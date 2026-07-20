//! End-to-end test of graceful shutdown (`tunnel.rs`'s local
//! SIGINT/SIGTERM handling, `broadcast_disconnect`, and
//! `handle_incoming`'s `PacketType::Disconnect` handling).
//!
//! As of the fix this file now covers, receiving the peer's own
//! `Disconnect` no longer tears this side down too -- it used to
//! (through v0.4.5), which meant a routine restart on *either* end (a
//! `.deb` upgrade, a manual `systemctl restart`) cascaded into a full
//! stop-then-cold-restart on the *other* end as well, even though
//! nothing was actually wrong with it. See `tunnel.rs`'s module doc
//! comment, "Graceful shutdown" section, for the full design.
//!
//! Two scenarios:
//! - `client_sigterm_disconnects_without_stopping_the_server`: SIGTERM
//!   the client (the same signal `systemctl stop` sends). The client
//!   itself should exit promptly (the local half of graceful
//!   shutdown), and the server should receive its `Disconnect` frame
//!   but keep running rather than exiting too (the peer-initiated half,
//!   now a no-op beyond logging for `Mode::Server`).
//! - `server_sigterm_triggers_fast_client_reconnect_without_restarting`:
//!   SIGTERM the server -- the more operationally important direction,
//!   since it's `Mode::Client` that has to actively do something
//!   (`rekey_loop`'s `reconnect` fast path) rather than just not
//!   exiting. The client should survive the server's `Disconnect`
//!   without exiting, and reconnect to a freshly restarted server well
//!   under the configured `rekey_interval_secs` once it's back up,
//!   with real traffic flowing again afterward.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_disconnect -- --ignored --nocapture
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

/// Short enough that this test's own reconnect-timing assertion
/// (well under `rekey_interval_secs`) stays meaningful without waiting
/// through a real production-sized interval, same reasoning as
/// `veth_daemon_health.rs`'s and `veth_rekey.rs`'s own constants.
/// Deliberately still much longer than how fast the reconnect should
/// actually happen (a couple of seconds) -- this is a ceiling on the
/// *fallback* periodic tick, not the expected reconnect time itself.
const REKEY_INTERVAL_SECS: u64 = 6;

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn client_sigterm_disconnects_without_stopping_the_server() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtdc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtds{id}")).expect("create server netns");

    let vc0 = format!("mdc0{id}");
    let vs0 = format!("mds0{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("disconnect", &id).expect("create scratch dir");

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
        "mtdsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6300,
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
        "mtdcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6300,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6300")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let mut server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let mut client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up' before shutdown could even be tested");

    // The client exits on its own signal -- the local half of graceful
    // shutdown, unchanged from before.
    client.terminate().expect("send SIGTERM to client");
    let client_status = client
        .wait_for_exit(Duration::from_secs(10))
        .expect("client did not exit promptly after SIGTERM");
    assert!(
        client_status.success(),
        "client should exit 0 on a graceful shutdown, got {client_status}"
    );

    // The point of this test: the server receives the client's
    // Disconnect but must *not* exit because of it anymore -- it
    // should still be running well after the client is long gone.
    let server_wait = server.wait_for_exit(Duration::from_secs(5));
    assert!(
        server_wait.is_err(),
        "server should NOT exit just because it received the client's Disconnect \
         (that cascading-shutdown behavior was removed -- see tunnel.rs's module doc \
         comment); instead it got: {server_wait:?}"
    );
}

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn server_sigterm_triggers_fast_client_reconnect_without_restarting() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtrc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtrs{id}")).expect("create server netns");

    let vc0 = format!("mtc0{id}");
    let vs0 = format!("mts0{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("disconnectrecon", &id).expect("create scratch dir");

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
            local_port: 6310,
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
            local_port: 6310,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6310")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let mut server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let mut client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up' before shutdown could even be tested");
    let session_id_before = snapshot.daemon.session_id;

    // Restart the server -- SIGTERM (same as `systemctl stop`), wait
    // for the old process to actually exit, then spawn a fresh one
    // from the same config, same as a real `.deb` upgrade's
    // stop-then-start would do.
    server.terminate().expect("send SIGTERM to server");
    let server_status = server
        .wait_for_exit(Duration::from_secs(10))
        .expect("server did not exit promptly after SIGTERM");
    assert!(
        server_status.success(),
        "server should exit 0 on a graceful shutdown, got {server_status}"
    );

    let server2 =
        MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn replacement server");

    // The point of this test: the client must not have exited just
    // because it received the old server's Disconnect.
    let client_wait = client.wait_for_exit(Duration::from_secs(1));
    assert!(
        client_wait.is_err(),
        "client should NOT exit just because it received the server's Disconnect \
         (that cascading-shutdown behavior was removed); instead it got: {client_wait:?}"
    );

    // It should reconnect to the replacement server well under
    // REKEY_INTERVAL_SECS -- if the fast path (handle_incoming's
    // Disconnect arm nudging rekey_loop immediately) were broken, this
    // would only recover on the next scheduled rekey tick instead.
    // Twice REKEY_INTERVAL_SECS plus headroom for the replacement
    // server's own startup/bind time is generous enough to not be
    // flaky while still meaningfully shorter than "waited for a
    // production-sized rekey_interval."
    let snapshot = poll_snapshot_until(
        &client_ctl,
        Duration::from_secs(REKEY_INTERVAL_SECS * 2 + 10),
        |s| link_is_up(s, "link0") && s.daemon.session_id != session_id_before,
    )
    .await
    .expect(
        "client never reconnected (new session_id, link0 back up) to the replacement \
         server within the expected window -- the Disconnect fast-reconnect path may be \
         broken",
    );
    assert_ne!(snapshot.daemon.session_id, session_id_before);

    // Real traffic should work again after reconnecting.
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after reconnecting to the replacement server");

    // Keep the replacement server alive until here so `_veth0`/`ns_*`
    // don't get torn down with it still bound.
    drop(server2);
}
