//! End-to-end test of `scheduler.auto_tune_reorder_window`
//! (`tunnel::reorder_tuning_loop`, `tunnel::suggest_reorder_window_ms` --
//! see `ARCHITECTURE.md` §7).
//!
//! Uses `tc netem` to add a real, asymmetric RTT to link1 (link0 stays
//! near-zero latency, same as every other veth pair in this harness),
//! so the client's own live RTT spread across its two links is genuinely
//! large enough to push the auto-tuner's suggested window well past its
//! default 50ms. Confirms the daemon actually applies it by watching for
//! the `"auto-tuned reorder_window_ms"` log line
//! (`MlvpnProcess::spawn_with_log_capture` -- see that function's doc
//! comment for why this test needs real log capture instead of the
//! control socket: the tuned value isn't exposed there, only logged).
//!
//! **What this does not assert**: the exact resulting window value.
//! `suggest_reorder_window_ms`'s math (spread scaling, clamping,
//! symmetry) is covered precisely by `tunnel.rs`'s own unit tests
//! instead, which don't need real sockets or timing to get an exact
//! answer; this test's job is only to prove the whole path -- real RTT
//! measurement, real hysteresis check, real `ReorderBuffer::set_window`
//! call -- fires at all against a real daemon under real (if modest)
//! network conditions, and that the tunnel keeps working while it does.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user) -- plus `tc` specifically
//! (`require_tc_command`), which is sometimes packaged separately from
//! `ip`. Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_reorder_tuning -- --ignored --nocapture
//! ```
//!
//! Slower than this harness's other tests (tens of seconds, not one or
//! two): `reorder_tuning_loop` only re-evaluates every 30s
//! (`tunnel::REORDER_TUNING_INTERVAL`) by design -- this is tuning a
//! policy parameter from an already-smoothed EWMA, not reacting
//! per-packet, so there's no reason to check more often, but it does
//! mean this test has to wait through at least one of those ticks.
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::time::Duration;
use support::{
    CLIENT_TUNNEL_ADDR, LinkSpec, MlvpnProcess, NetNs, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
    SchedulerOverrides, VethPair, create_scratch_dir, ensure_mlvpn_system_user,
    generate_test_keypair, link_is_up, poll_snapshot_until, require_ip_command, require_root,
    require_tc_command, unique_id, veth_link_addrs, write_config,
};

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), and network namespaces -- see module doc comment"]
async fn auto_tune_reorder_window_reacts_to_real_rtt_spread() {
    require_root();
    require_ip_command();
    require_tc_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtrc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtrs{id}")).expect("create server netns");

    let vc0 = format!("mrtc0{id}");
    let vs0 = format!("mrts0{id}");
    let vc1 = format!("mrtc1{id}");
    let vs1 = format!("mrts1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1");

    // Add real, symmetric latency to link1 only -- link0 stays as
    // near-zero-latency as every other test's veth pairs. 75ms each way
    // gives a ~150ms round trip on link1 alone, versus link0's
    // sub-millisecond baseline: a spread easily large enough to push
    // suggest_reorder_window_ms's output (1.5x spread + 10ms headroom)
    // well past both the default 50ms window and this config's default
    // [10ms, 500ms] bounds' lower end, without threatening to clamp
    // against the upper end either.
    ns_client
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &vc1, "root", "netem", "delay", "75ms",
            ],
        )
        .expect("add netem delay to client's link1 veth");
    ns_server
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &vs1, "root", "netem", "delay", "75ms",
            ],
        )
        .expect("add netem delay to server's link1 veth");

    let tmp = create_scratch_dir("reordertune", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();
    let server_addr_1 = addr_s1.split('/').next().unwrap();

    let server_cfg = write_config(
        &tmp,
        "server",
        "mrtsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        // only the client needs auto_tune_reorder_window for this test
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6600,
                local_addr: None,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6601,
                local_addr: None,
                remote_addr: None,
            },
        ],
        &server_ctl,
        None,
    )
    .expect("write server config");

    let client_cfg = write_config(
        &tmp,
        "client",
        "mrtcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides {
            auto_tune_reorder_window: true,
            ..Default::default()
        },
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6600,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_0}:6600")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6601,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_1}:6601")),
            },
        ],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, client_logs) = MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg)
        .expect("spawn client with log capture");

    // The added netem delay pushes probe RTTs up but shouldn't come
    // close to ProbeTracker's timeout (4x probe_interval_ms, floored at
    // 500ms -- 800ms at the default 200ms probe_interval_ms), so both
    // links should still reach "up" via the normal hysteresis path,
    // just a little slower than the other, undelayed tests.
    poll_snapshot_until(&client_ctl, Duration::from_secs(30), |s| {
        link_is_up(s, "link0") && link_is_up(s, "link1")
    })
    .await
    .expect("both links never reached 'up' despite the added netem latency");

    // The actual point of this test: once both links have real RTT
    // samples, the ~150ms spread between them should be large enough to
    // clear the hysteresis threshold against the default 50ms window
    // the moment `reorder_tuning_loop` next ticks (every 30s -- see
    // this file's module doc comment for why that's not shorter).
    let saw_tuning = client_logs
        .wait_for_line_containing("auto-tuned reorder_window_ms", Duration::from_secs(50))
        .await;
    assert!(
        saw_tuning,
        "never saw an \"auto-tuned reorder_window_ms\" log line from the client within 50s; \
         either reorder_tuning_loop isn't firing, or the RTT spread wasn't large enough to \
         clear its hysteresis threshold"
    );

    // Traffic should still flow normally through and after a live
    // window change -- ReorderBuffer::set_window must not have
    // corrupted or stalled anything already in flight.
    ns_client
        .exec("ping", &["-c", "3", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after the reorder window was auto-tuned");
}

/// Companion to `auto_tune_reorder_window_reacts_to_real_rtt_spread` above:
/// that test proves the auto-tuner widens `reorder_window_ms` at all; this
/// one proves the exact bug Task 1 of this plan fixes doesn't come back --
/// that widening the window doesn't translate into added latency on real
/// Data traffic. Before the `ReorderBuffer` high-watermark fix, nearly
/// every real Data packet was held for up to the full (now-widened)
/// `reorder_window_ms` regardless of whether reordering was actually in
/// progress, confirmed live to add ~110ms of round-trip latency and
/// collapse real TCP throughput.
///
/// Reuses this file's harness setup verbatim through the "auto-tuned
/// reorder_window_ms" log line, then measures a real ping round trip
/// through the tunnel and parses its average RTT out of ping's own
/// summary line.
#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), and network namespaces -- see module doc comment"]
async fn real_data_traffic_is_not_delayed_by_a_widened_reorder_window() {
    require_root();
    require_ip_command();
    require_tc_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtlc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtls{id}")).expect("create server netns");

    let vc0 = format!("mltc0{id}");
    let vs0 = format!("mlts0{id}");
    let vc1 = format!("mltc1{id}");
    let vs1 = format!("mlts1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1");

    // Same asymmetric-latency setup as the sibling test above: 75ms each
    // way on link1 only, giving a real ~150ms spread against link0's
    // near-zero baseline -- enough to push suggest_reorder_window_ms's
    // output well past the default 50ms window.
    ns_client
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &vc1, "root", "netem", "delay", "75ms",
            ],
        )
        .expect("add netem delay to client's link1 veth");
    ns_server
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &vs1, "root", "netem", "delay", "75ms",
            ],
        )
        .expect("add netem delay to server's link1 veth");

    let tmp = create_scratch_dir("reordertune2", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();
    let server_addr_1 = addr_s1.split('/').next().unwrap();

    let server_cfg = write_config(
        &tmp,
        "server",
        "mltsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        // only the client needs auto_tune_reorder_window for this test
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6600,
                local_addr: None,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6601,
                local_addr: None,
                remote_addr: None,
            },
        ],
        &server_ctl,
        None,
    )
    .expect("write server config");

    let client_cfg = write_config(
        &tmp,
        "client",
        "mltcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides {
            auto_tune_reorder_window: true,
            ..Default::default()
        },
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6600,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_0}:6600")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6601,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_1}:6601")),
            },
        ],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, client_logs) = MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg)
        .expect("spawn client with log capture");

    poll_snapshot_until(&client_ctl, Duration::from_secs(30), |s| {
        link_is_up(s, "link0") && link_is_up(s, "link1")
    })
    .await
    .expect("both links never reached 'up' despite the added netem latency");

    let saw_tuning = client_logs
        .wait_for_line_containing("auto-tuned reorder_window_ms", Duration::from_secs(50))
        .await;
    assert!(
        saw_tuning,
        "never saw an \"auto-tuned reorder_window_ms\" log line from the client within 50s; \
         either reorder_tuning_loop isn't firing, or the RTT spread wasn't large enough to \
         clear its hysteresis threshold"
    );

    // With the window now widened (confirmed via the log line above), send
    // real traffic through the tunnel and measure its round-trip time.
    // Before this plan's Task 1 fix, a widened window directly translated
    // into added latency on nearly every Data packet (the exact bug this
    // test guards against) -- ping through the tunnel should complete in a
    // time comparable to the underlying links' own real latency, not
    // inflated by anywhere near the full (now-widened) reorder_window_ms.
    //
    // Run inside the client netns (like every other ping in this harness)
    // via `ip netns exec` directly rather than `NetNs::exec`, since that
    // helper only reports success/failure and this test needs ping's own
    // stdout to measure RTT.
    let ping_output = std::process::Command::new("ip")
        .args(["netns", "exec", &ns_client.name, "ping"])
        .args(["-c", "5", "-W", "2", SERVER_TUNNEL_HOST])
        .output()
        .expect("failed to run ping");
    let stdout = String::from_utf8_lossy(&ping_output.stdout);
    assert!(
        ping_output.status.success(),
        "ping through the tunnel failed: {stdout}"
    );

    // Parse the average RTT out of ping's own summary line
    // ("rtt min/avg/max/mdev = A/B/C/D ms").
    let avg_rtt_ms: f64 = stdout
        .lines()
        .find(|l| l.contains("rtt min/avg/max/mdev"))
        .and_then(|l| l.split('=').nth(1))
        .and_then(|nums| nums.split('/').nth(1))
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| panic!("could not parse average RTT from ping output: {stdout}"));

    // The widened window from this test's tc netem setup is well past
    // 50ms (that's the whole point of using netem here) -- if the old
    // contiguity bug were still present, nearly every ping packet
    // would be held for close to that full window in each direction.
    // A real, unaffected round trip should land far below that,
    // comfortably under 100ms even with the injected link delay.
    assert!(
        avg_rtt_ms < 100.0,
        "expected real ping RTT well under 100ms even with a widened \
         reorder window, got {avg_rtt_ms}ms -- possible regression of \
         the ReorderBuffer high-watermark fix"
    );
}
