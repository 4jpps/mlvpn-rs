//! End-to-end test of rekeying and session migration (`tunnel.rs`'s
//! `rekey_loop` and `handle_incoming`'s steady-state `HandshakeInit`
//! handling, backed by `crypto::SessionState`'s active/previous-session
//! overlap window -- see `ARCHITECTURE.md` §4).
//!
//! Configures both sides with a short `rekey_interval_secs` so a real
//! rekey happens well within the test's own timeout (rather than
//! waiting on the 120s default), pings across the tunnel once before
//! and once comfortably after that rekey should have happened, and
//! confirms the link is still reported `up` afterward. This is a
//! black-box, behavioral check -- like `veth_failover.rs`, it doesn't
//! scrape the daemons' logs for "session rekeyed" (both processes
//! share one inherited stdout with no per-process label, so a log line
//! alone wouldn't even prove which side produced it -- see the
//! `veth_failover` investigation this project's `CHANGELOG.md` and
//! git history document for exactly that trap). If rekeying or the
//! overlap window is broken -- the new session can't decrypt anything
//! (a `SessionState::decrypt` dispatch bug), the swap drops in-flight
//! traffic, or the daemon simply panics/hangs -- the second ping fails
//! or times out.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_rekey -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, unique_id, veth_link_addrs,
    write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair, CLIENT_TUNNEL_ADDR,
    SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

/// Short enough that at least one rekey is guaranteed well within this
/// test's own timeouts, long enough that the test isn't flaky against
/// scheduling jitter on a slow/virtualized runner.
const REKEY_INTERVAL_SECS: u64 = 2;

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn session_rekeys_periodically_and_data_keeps_flowing() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtrc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtrs{id}")).expect("create server netns");

    let vc0 = format!("mrc0{id}");
    let vs0 = format!("mrs0{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("rekey", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();

    let server_cfg = write_config(
        &tmp,
        "server",
        "mtrsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        Some(REKEY_INTERVAL_SECS),
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6200,
            local_addr: None,
            remote_addr: None,
        }],
        &server_ctl,
        None,
    )
    .expect("write server config");

    let client_cfg = write_config(
        &tmp,
        "client",
        "mtrcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        Some(REKEY_INTERVAL_SECS),
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6200,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6200")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let _client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up' before any rekey could even be attempted");

    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("baseline ping across the tunnel failed before any rekey");

    // `rekey_loop` (tunnel.rs) deliberately skips its first, immediate
    // tick so a rekey doesn't happen right on the heels of the initial
    // handshake -- the first real attempt fires ~REKEY_INTERVAL_SECS
    // after that. Wait past two full intervals so this isn't sensitive
    // to exact timing on a slow runner; by then either the client's own
    // rekey succeeded, or the server accepted a peer-initiated one, or
    // (if this feature is broken) something has already gone visibly
    // wrong in the daemon logs above this point.
    tokio::time::sleep(Duration::from_secs(REKEY_INTERVAL_SECS * 2 + 2)).await;

    // The actual point of this test: data must still flow after at
    // least one rekey has happened. A broken `SessionState::decrypt`
    // dispatch (wrong session picked, or the overlap window not
    // covering a packet that was genuinely in flight during the swap)
    // would make this fail or hang; a daemon that panicked during the
    // swap would make the whole process exit and this ping would fail
    // outright.
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after a rekey should have occurred");

    // And the control socket should still agree the link is healthy --
    // not just that one ICMP round trip happened to sneak through.
    poll_snapshot_until(&client_ctl, Duration::from_secs(5), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 not reported 'up' after the rekey window");
}
