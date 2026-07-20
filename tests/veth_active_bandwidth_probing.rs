//! End-to-end test of `scheduler.active_bandwidth_probing`
//! (`tunnel::active_bandwidth_prober`, which reuses
//! `tunnel::send_throughput_test_stream` and the `ThroughputTestData`/
//! `ThroughputTestResult` handling in `tunnel::handle_incoming`, and
//! `link::LinkStats::active_bandwidth_mbps` -- see `ARCHITECTURE.md` §5).
//!
//! Uses `tc qdisc ... tbf` to cap the client's link1 veth interface to a
//! known, low rate (link0 stays unshaped, same baseline every other test
//! in this harness uses), then confirms the client's own logged
//! `achieved_mbps` for link1 (`"active bandwidth probe result"`, the
//! only externally observable signal for this feature -- see
//! `veth_reorder_tuning.rs`'s module doc comment for why a handful of
//! this project's auto-tuning-adjacent features are asserted against
//! log output via `MlvpnProcess::spawn_with_log_capture` instead of the
//! control socket) actually reflects that cap, and comes in meaningfully
//! lower than link0's.
//!
//! **What this does not assert**: an exact achieved_mbps value. A
//! stream against a token-bucket shaper is inherently a little noisy
//! (initial burst credit, timer granularity), so this only checks that
//! link1's measured rate is capped to a sane ballpark and is clearly
//! lower than link0's unshaped measurement -- proving the whole path
//! (stream send, stream receive/accumulate, result reply, EWMA update,
//! log) fires and reacts to real network conditions, which is this
//! test's actual job.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user) -- plus `tc` specifically
//! (`require_tc_command`). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_active_bandwidth_probing -- --ignored --nocapture
//! ```
//!
//! Slow (tens of seconds): `active_bandwidth_probe_interval_secs` has a
//! validated 30s floor (see `config.rs::Config::validate` -- this sends
//! real injected traffic, not a single latency probe, so a shorter
//! interval would start to look like a self-inflicted flood), and this
//! test uses that floor directly rather than waiting the 300s config
//! default.
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, require_tc_command, unique_id,
    veth_link_addrs, write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair,
    CLIENT_TUNNEL_ADDR, SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

/// Pulls the `achieved_mbps=<value>` field back out of a captured log
/// line in the default `tracing_subscriber::fmt()` format (unquoted,
/// space-delimited `key=value` fields after the message/target).
fn parse_achieved_mbps(line: &str) -> f64 {
    let after = line
        .split("achieved_mbps=")
        .nth(1)
        .unwrap_or_else(|| panic!("no achieved_mbps field in line: {line}"));
    let value: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    value
        .parse()
        .unwrap_or_else(|e| panic!("could not parse achieved_mbps {value:?} in line {line}: {e}"))
}

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), and network namespaces -- see module doc comment"]
async fn active_bandwidth_probing_discovers_a_real_rate_cap() {
    require_root();
    require_ip_command();
    require_tc_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mbwc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mbws{id}")).expect("create server netns");

    let vc0 = format!("mbwc0{id}");
    let vs0 = format!("mbws0{id}");
    let vc1 = format!("mbwc1{id}");
    let vs1 = format!("mbws1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1");

    // Cap link1's egress rate on the client side only -- link0 stays
    // unshaped, same near-line-rate baseline every other veth pair in
    // this harness uses. `burst` is set just above the tunnel's packet
    // size so the token bucket can't front-load an outsized chunk of
    // the probe stream as one free burst credit; `latency` bounds how
    // long tbf will queue (rather than drop) a packet waiting for
    // tokens.
    ns_client
        .exec(
            "tc",
            &[
                "qdisc", "add", "dev", &vc1, "root", "tbf", "rate", "2mbit", "burst", "1600b",
                "latency", "400ms",
            ],
        )
        .expect("add tbf rate cap to client's link1 veth");

    let tmp = create_scratch_dir("bwprobe", &id).expect("create scratch dir");

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
        "mbwsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        // Only the client needs active_bandwidth_probing for this test
        // -- it's the one sending the bursts and logging results.
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
        "mbwcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides {
            active_bandwidth_probing: true,
            active_bandwidth_probe_interval_secs: Some(30),
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
    .expect("both links never reached 'up'");

    // active_bandwidth_prober's first tick fires immediately on task
    // spawn (tokio::time::Interval's well-known behavior: the first
    // `.tick()` completes right away rather than after one full
    // period), then every `active_bandwidth_probe_interval_secs`
    // (the 30s config floor used above) after that -- so this doesn't
    // actually need to wait out a full interval, but the timeout below
    // still gives it a generous margin regardless. Each probe now runs
    // for a real `active_bandwidth_probe_duration_secs` (default 2s,
    // not overridden here) rather than completing near-instantly, so
    // the margin also covers that plus the reply's own round trip.
    //
    // `tracing_subscriber`'s default formatter writes an event's
    // fields, in declaration order, right after its message --
    // `tracing::info!(link = %link.config.name, achieved_mbps = ...,
    // "active bandwidth probe result")` in `handle_incoming` -- and
    // the `%` sigil means Display formatting, not Debug, so the link
    // name appears *unquoted* (`link=link0`, not `link="link0"`). This
    // combined needle pins the result to the specific link it's about,
    // not just any bandwidth-probe-result line.
    let link0_line = client_logs
        .find_line_containing(
            "active bandwidth probe result link=link0",
            Duration::from_secs(60),
        )
        .await
        .expect("never saw an active bandwidth probe result for link0");
    let link1_line = client_logs
        .find_line_containing(
            "active bandwidth probe result link=link1",
            Duration::from_secs(30),
        )
        .await
        .expect("never saw an active bandwidth probe result for link1");

    let mbps0 = parse_achieved_mbps(&link0_line);
    let mbps1 = parse_achieved_mbps(&link1_line);

    assert!(
        mbps1 < 10.0,
        "link1's achieved_mbps ({mbps1}) should reflect the 2mbit tbf cap, not an unshaped rate"
    );
    assert!(
        mbps1 < mbps0,
        "shaped link1 ({mbps1} mbps) should measure lower than unshaped link0 ({mbps0} mbps)"
    );

    // Traffic should still flow normally alongside/after the probe
    // bursts -- the injected burst traffic must not have starved or
    // corrupted real Data frames.
    ns_client
        .exec("ping", &["-c", "3", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after active bandwidth probing ran");
}
