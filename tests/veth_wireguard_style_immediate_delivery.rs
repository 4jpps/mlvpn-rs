//! End-to-end test of the WireGuard-style settled-primary bypass path
//! (`handle_incoming`'s `PacketType::Data` arm in `tunnel.rs`,
//! `ReorderBuffer::note_delivered`) -- specifically the C1 regression
//! found in code review after that feature first shipped
//! (`.superpowers/sdd/2026-09-01-wireguard-style-immediate-delivery/`):
//! `Scheduler::primary` is driven purely by monitor/probe ticks, not by
//! Data-packet or session activity, so once bypass mode engages, the
//! *buffered* branch (the one that resets `peer_primary_link` on a
//! session-id change) is not guaranteed to run again for the rest of
//! the tunnel's lifetime. Left unfixed, a `follow_peer_primary` host's
//! adopted `peer_primary_link` would never get cleared across a rekey
//! while bypass mode is active.
//!
//! Configures the server with `scheduler.primary_link_mode` (decides
//! its own primary locally) and the client with
//! `scheduler.follow_peer_primary` (adopts whatever the server
//! advertises over `VersionInfo`) -- the exact two-sided topology this
//! feature is for. A single link on each side is enough: with only one
//! Up link, `primary_link_mode` settles on it immediately, and the
//! client's `follow_peer_primary` scheduler mirrors that choice, which
//! is exactly what puts the client's `handle_incoming` into the bypass
//! branch for its own inbound Data traffic (the server's *own* Data
//! never reordering also happens, but this test only asserts on the
//! client side, since that's the side actually maintaining
//! `peer_primary_link`).
//!
//! A short `rekey_interval_secs` forces at least one real rekey (a
//! `session_id` change) to happen well within this test's timeout,
//! matching `veth_rekey.rs`'s own approach. The fix under test
//! (`src/tunnel.rs`'s bypass branch) logs
//! `"cleared stale peer_primary_link in bypass mode after a session
//! change"` at `info` level, once, exactly when `note_delivered`
//! reports the session changed -- this test uses
//! `MlvpnProcess::spawn_with_log_capture` (the same tool
//! `veth_reorder_tuning.rs` uses for an analogous no-other-observable-
//! signal daemon decision) to confirm that line is actually emitted on
//! the client after the rekey, which is only possible if bypass mode
//! was genuinely active *and* the fix's reset path actually ran. Without
//! the fix, this line is never logged at all (the old code never reset
//! `peer_primary_link` from the bypass branch), so this test would have
//! caught the real regression the reviewer found.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_wireguard_style_immediate_delivery -- --ignored --nocapture
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

/// Same reasoning as `veth_rekey.rs`'s own constant: short enough that
/// at least one rekey is guaranteed well within this test's timeouts,
/// long enough not to be flaky on a slow/virtualized runner.
const REKEY_INTERVAL_SECS: u64 = 2;

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn peer_primary_link_is_cleared_across_a_rekey_while_bypass_mode_is_active() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mwsdc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mwsds{id}")).expect("create server netns");

    let vc0 = format!("mwdc0{id}");
    let vs0 = format!("mwds0{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("wgstyle", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();

    // Server: decides its own primary locally (only one link configured,
    // so it settles on it immediately once Up).
    let server_cfg = write_config(
        &tmp,
        "server",
        "mwsdsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        Some(REKEY_INTERVAL_SECS),
        SchedulerOverrides {
            primary_link_mode: true,
            ..Default::default()
        },
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

    // Client: adopts whatever the server advertises over VersionInfo,
    // rather than deciding locally.
    let client_cfg = write_config(
        &tmp,
        "client",
        "mwsdcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        Some(REKEY_INTERVAL_SECS),
        SchedulerOverrides {
            follow_peer_primary: true,
            ..Default::default()
        },
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

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, client_log) = MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg)
        .expect("spawn client with log capture");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up' before settling could even start");

    // Give the periodic VersionInfo exchange time to let the client
    // actually adopt the server's advertised primary and settle into
    // bypass mode -- `send_version_info`'s own periodic timer shares
    // the StatsShare/probe cadence, well under this window.
    ns_client
        .exec("ping", &["-c", "5", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("baseline ping across the tunnel failed before settling");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // `rekey_loop` skips its first, immediate tick (see `veth_rekey.rs`
    // for the same reasoning) -- wait past two full intervals so this
    // isn't sensitive to exact timing on a slow runner, then keep
    // traffic flowing across the rekey so `handle_incoming` actually
    // processes the post-rekey Data frames that trigger the fix.
    tokio::time::sleep(Duration::from_secs(REKEY_INTERVAL_SECS * 2 + 2)).await;
    ns_client
        .exec("ping", &["-c", "5", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after a rekey should have occurred");

    // The actual point of this test: the fix's own log line must have
    // fired on the client, proving `peer_primary_link` was genuinely
    // reset by the bypass branch itself (not merely by a coincidental
    // fresh VersionInfo overwrite) in direct response to the rekey's
    // session-id change while bypass mode was active.
    let saw_reset = client_log
        .wait_for_line_containing(
            "cleared stale peer_primary_link in bypass mode after a session change",
            Duration::from_secs(10),
        )
        .await;
    assert!(
        saw_reset,
        "client never logged clearing peer_primary_link after a rekey while bypass mode was \
         active -- this is the exact C1 regression (peer_primary_link latching forever across a \
         rekey once the bypass branch takes over) that this test exists to catch"
    );

    // And the tunnel must still be healthy afterward -- the fix must
    // not have broken ordinary delivery to achieve the reset.
    poll_snapshot_until(&client_ctl, Duration::from_secs(5), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 not reported 'up' after the rekey window");
}
