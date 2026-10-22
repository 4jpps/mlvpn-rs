//! End-to-end test of the daemon/host-level health added to the control
//! socket across several commits: `ipc::DaemonSnapshot` (session id/
//! uptime/rekey count, outbound queue depth/capacity/drops, TUN
//! interface sysfs counters, machine-wide `/proc` stats) and
//! `Snapshot::new_log_lines` (the live log ring streamed to
//! `mlvpn-tui`'s Logs tab -- see `logbuf.rs`).
//!
//! Modeled on `veth_link_control.rs` and `veth_rekey.rs`: real `mlvpnd`
//! processes in network namespaces connected by a veth pair, driven
//! through the real control socket rather than calling any of
//! `control.rs`'s internals directly.
//!
//! The `new_log_lines` delta assertion is the one part of this test
//! that can't go through `support::poll_snapshot_until` -- that helper
//! opens a brand new connection every time it's called, and each
//! connection gets its own independent cursor into the log ring (see
//! `logbuf::LogRing::entries_since`'s doc comment), so two calls to it
//! would each see a full replay rather than a delta. This test instead
//! holds one connection open across two consecutive reads to actually
//! exercise the "second read doesn't repeat the first read's lines"
//! guarantee the whole delta-streaming design depends on.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_daemon_health -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::time::Duration;
use support::{
    CLIENT_TUNNEL_ADDR, LinkSpec, MlvpnProcess, NetNs, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
    SchedulerOverrides, VethPair, create_scratch_dir, ensure_mlvpn_system_user,
    generate_test_keypair, link_is_up, poll_snapshot_until, require_ip_command, require_root,
    unique_id, veth_link_addrs, write_config,
};

/// Short enough that a real rekey is guaranteed well within this test's
/// own timeouts (same reasoning as `veth_rekey.rs`'s own constant), but
/// long enough that the very first two control-socket reads -- done
/// back to back, right after the link comes up, for the log-delta
/// assertion below -- land comfortably before `rekey_loop`'s first
/// tick and can't spuriously pick up a "session rekeyed" log line.
const REKEY_INTERVAL_SECS: u64 = 6;

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn daemon_snapshot_and_log_streaming_report_real_data() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mdhc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mdhs{id}")).expect("create server netns");

    let vc0 = format!("mdc0{id}");
    let vs0 = format!("mds0{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("daemonhealth", &id).expect("create scratch dir");

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
        "mdhsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        Some(REKEY_INTERVAL_SECS),
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6700,
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
        "mdhcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        Some(REKEY_INTERVAL_SECS),
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6700,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6700")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let _client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up' before daemon health could even be checked");

    // NOTE: this used to also sanity-check `session_uptime_ms`/
    // `rekey_count` here (a freshly established tunnel-wide Noise
    // session should read a small uptime and 0 rekeys). Those fields no
    // longer exist now that each link owns its own independent
    // WireGuard tunnel instead of one shared session (see
    // `src/wireguard.rs::WgTunnel`) -- a per-link replacement (e.g.
    // handshake age/count per link) would need new tracking state that
    // doesn't exist yet, left as a possible follow-up rather than
    // scope-creeping this fix.
    assert_eq!(snapshot.daemon.tun.iface, "mdhcli0");
    assert!(
        snapshot.daemon.outbound_queue_capacity > 0,
        "outbound_queue_capacity should reflect OUTBOUND_QUEUE_CAPACITY, not 0"
    );
    assert_eq!(
        snapshot.daemon.outbound_queue_dropped_total, 0,
        "nothing should have overflowed the outbound queue yet"
    );

    // --- Version exchange: `local_version` is always known immediately
    // (compiled in via `mlvpn::version()`); `peer_version` needs at least
    // one `VersionInfo` frame to have round-tripped over the wire
    // (piggybacked on the same 1s stats_tick as StatsShare -- see
    // `PacketType::VersionInfo`'s doc comment), so poll for it rather
    // than asserting on the very first snapshot.
    let local_version = mlvpn::version();
    assert_eq!(snapshot.daemon.local_version, local_version);
    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(10), |s| {
        s.daemon.peer_version.is_some()
    })
    .await
    .expect("peer_version never arrived via the periodic VersionInfo wire exchange");
    assert_eq!(
        snapshot.daemon.peer_version.as_deref(),
        Some(local_version.as_str()),
        "client and server in this test are the same build, so their versions must match"
    );

    // --- new_log_lines: delta, not a replay, on a single held-open
    // connection -- see this file's module doc comment for why
    // poll_snapshot_until can't be reused for this specific assertion.
    {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let stream = tokio::net::UnixStream::connect(&client_ctl)
            .await
            .expect("connect to client control socket for the log-delta check");
        let mut reader = BufReader::new(stream);

        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("timed out waiting for the first snapshot line")
            .expect("read first snapshot line");
        let first: mlvpn::ipc::Snapshot =
            serde_json::from_str(line.trim()).expect("parse first snapshot");
        assert!(
            !first.new_log_lines.is_empty(),
            "a brand new connection's first snapshot should replay everything already in \
             the daemon's log ring (startup, link-bind, tun-created, session-established, \
             link-up lines are all real INFO events that happened before this connection \
             was even opened)"
        );
        let first_seqs: std::collections::HashSet<u64> =
            first.new_log_lines.iter().map(|e| e.seq).collect();

        line.clear();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("timed out waiting for the second snapshot line")
            .expect("read second snapshot line");
        let second: mlvpn::ipc::Snapshot =
            serde_json::from_str(line.trim()).expect("parse second snapshot");
        assert!(
            second
                .new_log_lines
                .iter()
                .all(|e| !first_seqs.contains(&e.seq)),
            "the second snapshot on the same connection must never repeat a seq the first \
             snapshot already delivered -- that's the entire point of the per-connection \
             last_log_seq cursor in control::serve_client"
        );
    }

    // --- Tun interface byte counters: real kernel counters on the real
    // TUN device, driven by real ping traffic across the tunnel.
    ns_client
        .exec("ping", &["-c", "4", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed");

    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(10), |s| {
        s.daemon.tun.tx_bytes.unwrap_or(0) > 0 && s.daemon.tun.rx_bytes.unwrap_or(0) > 0
    })
    .await
    .expect("tun tx/rx byte counters never became positive after driving real ping traffic");
    assert!(snapshot.daemon.tun.tx_bytes.unwrap_or(0) > 0);
    assert!(snapshot.daemon.tun.rx_bytes.unwrap_or(0) > 0);

    // --- System stats: real /proc reads on whatever host/container
    // actually runs this test -- every field should come back Some on
    // any real Linux box.
    assert!(
        snapshot.daemon.system.load1.is_some(),
        "load1 should be readable from /proc/loadavg on any real Linux host"
    );
    assert!(
        snapshot.daemon.system.uptime_secs.is_some(),
        "uptime_secs should be readable from /proc/uptime on any real Linux host"
    );
    assert!(
        snapshot.daemon.system.mem_total_kb.is_some(),
        "mem_total_kb should be readable from /proc/meminfo on any real Linux host"
    );

    // --- Telemetry: health state, structured events, reorder/rate
    // counters. `poll_snapshot_until` opens a fresh connection, so the
    // first snapshot replays the whole event ring.
    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(15), |s| {
        s.daemon.telemetry.health == "HEALTHY"
    })
    .await
    .expect("telemetry health never reached HEALTHY with the only link up");
    assert!(
        snapshot.daemon.telemetry.tunnel_uptime_secs < 600,
        "tunnel_uptime_secs should be a small number for a freshly started tunnel"
    );
    assert_eq!(snapshot.daemon.telemetry.scheduler_mode, "weighted");
    assert!(
        snapshot
            .new_events
            .iter()
            .any(|e| e.kind == "LINK_UP" && e.link.as_deref() == Some("link0")),
        "expected a LINK_UP event for link0 in the replayed event ring, got: {:?}",
        snapshot
            .new_events
            .iter()
            .map(|e| e.kind.as_str())
            .collect::<Vec<_>>()
    );

    let ns_name = ns_client.name.clone();
    let pinger = std::thread::spawn(move || {
        let _ = std::process::Command::new("ip")
            .args([
                "netns", "exec", &ns_name, "ping", "-q", "-c", "60", "-i", "0.1",
            ])
            .arg(SERVER_TUNNEL_HOST)
            .output();
    });
    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(10), |s| {
        let r = &s.daemon.telemetry.rates;
        r.tx_pps > 0.0 && r.rx_pps > 0.0
    })
    .await
    .expect("telemetry rates never became positive while pinging across the tunnel");
    assert!(snapshot.daemon.telemetry.rates.tx_mbps > 0.0);
    let _ = pinger.join();
    assert!(
        snapshot.daemon.telemetry.process.rss_kb.unwrap_or(0) > 0,
        "process RSS should be readable from /proc/self/statm"
    );

    // NOTE: this section used to also assert `session_id`/`rekey_count`
    // changed here, same timing pattern as `veth_rekey.rs` (rekey_loop
    // skips its first, immediate tick, so the first real attempt fired
    // ~REKEY_INTERVAL_SECS after the initial handshake). Those
    // tunnel-wide fields no longer exist now that each link owns its
    // own independent WireGuard tunnel with its own internal rekeying
    // (see `src/wireguard.rs::WgTunnel`) instead of one shared Noise
    // session -- a per-link replacement would need new tracking state
    // that doesn't exist yet, left as a possible follow-up. Following
    // `veth_rekey.rs`'s own pattern instead: just wait past the rekey
    // window and confirm the link is still healthy and passing traffic,
    // which is what actually matters operationally.
    tokio::time::sleep(Duration::from_secs(REKEY_INTERVAL_SECS * 2 + 2)).await;

    poll_snapshot_until(&client_ctl, Duration::from_secs(10), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 not reported 'up' after the rekey window");

    // Data should still be flowing after all of the above.
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after the rekey/health checks above");
}
