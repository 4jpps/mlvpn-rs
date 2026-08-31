//! End-to-end test of `scheduler.primary_link_mode`: with two Up
//! links, confirms all Data traffic rides one link (the primary), not
//! split via SWRR; confirms failover to the other link is immediate
//! when the primary goes down; confirms recovery does NOT immediately
//! switch back (hysteresis) until a sustained-margin window passes.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_primary_link_mode -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up, link_state,
    poll_snapshot_until, require_ip_command, require_root, unique_id, veth_link_addrs,
    write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair, CLIENT_TUNNEL_ADDR,
    SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

/// Reads `link0`'s and `link1`'s current `tx_bytes` out of a snapshot,
/// as `(link0_tx, link1_tx)`. Panics if either link is missing from the
/// snapshot -- both are always configured for this test, so that would
/// indicate a harness bug, not a real test outcome.
fn tx_bytes_pair(snapshot: &mlvpn::ipc::Snapshot) -> (u64, u64) {
    let get = |name: &str| {
        snapshot
            .links
            .iter()
            .find(|l| l.name == name)
            .unwrap_or_else(|| panic!("snapshot missing link '{name}'"))
            .tx_bytes
    };
    (get("link0"), get("link1"))
}

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn primary_link_mode_sends_all_traffic_on_one_link_and_fails_over_immediately() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtpc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtps{id}")).expect("create server netns");

    let vc0 = format!("mtpc0{id}");
    let vs0 = format!("mtps0{id}");
    let vc1 = format!("mtpc1{id}");
    let vs1 = format!("mtps1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1");

    let tmp = create_scratch_dir("primarylink", &id).expect("create scratch dir");

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
        "mtpsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides {
            primary_link_mode: true,
            ..Default::default()
        },
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6200,
                local_addr: None,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6201,
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
        "mtpcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides {
            primary_link_mode: true,
            ..Default::default()
        },
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6200,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_0}:6200")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6201,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_1}:6201")),
            },
        ],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let _client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    // Both links reachable this time -- wait for both to come up before
    // touching anything.
    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0") && link_is_up(s, "link1")
    })
    .await
    .expect("both links never reached 'up' before the primary-link test could even start");

    // Baseline tx_bytes for both links right after both are Up, before
    // any traffic is deliberately generated below.
    let before = poll_snapshot_until(&client_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("failed to fetch a baseline snapshot");
    let (before_l0, before_l1) = tx_bytes_pair(&before);

    // Generate a real burst of traffic across the tunnel, so there's
    // something for tx_bytes to actually measure.
    ns_client
        .exec("ping", &["-c", "10", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("baseline ping burst across the tunnel failed");

    let after = poll_snapshot_until(&client_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("failed to fetch a post-ping snapshot");
    let (after_l0, after_l1) = tx_bytes_pair(&after);
    let delta_l0 = after_l0.saturating_sub(before_l0);
    let delta_l1 = after_l1.saturating_sub(before_l1);

    // Exactly one of the two links should have carried the burst -- the
    // primary. The other should have stayed essentially flat (only its
    // own periodic Probe/StatsShare/VersionInfo traffic, not Data).
    let (primary_link, primary_delta, other_delta) = if delta_l0 >= delta_l1 {
        ("link0", delta_l0, delta_l1)
    } else {
        ("link1", delta_l1, delta_l0)
    };
    assert!(
        primary_delta > other_delta * 4,
        "expected the primary link ('{primary_link}') to carry nearly all Data traffic, \
         but link0 grew by {delta_l0} bytes and link1 grew by {delta_l1} bytes"
    );

    // Take the primary's client-side veth down. down_threshold defaults
    // to 5 consecutive missed probes at the default 200ms
    // probe_interval_ms (~1s), so this should show up well within the
    // timeout below even on a slow runner.
    let (primary_veth, other_link_name) = if primary_link == "link0" {
        (vc0.as_str(), "link1")
    } else {
        (vc1.as_str(), "link0")
    };
    ns_client
        .exec("ip", &["link", "set", primary_veth, "down"])
        .expect("bring primary link's veth down");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_state(s, primary_link) == Some("down")
    })
    .await
    .expect("primary link never transitioned to 'down' after its veth was taken down");

    // Failover must be immediate (no hysteresis on the way *down* --
    // `refresh_from_scores` re-selects the moment the current primary's
    // index drops out of the Up set), and it must be seamless from the
    // data plane's perspective, not just a state-string flip: send more
    // traffic and confirm the surviving link now carries it.
    let before_failover = poll_snapshot_until(&client_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("failed to fetch a pre-failover-traffic snapshot");
    let (before_failover_l0, before_failover_l1) = tx_bytes_pair(&before_failover);

    ns_client
        .exec("ping", &["-c", "10", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed while the primary link was down");

    let after_failover = poll_snapshot_until(&client_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("failed to fetch a post-failover-traffic snapshot");
    let (after_failover_l0, after_failover_l1) = tx_bytes_pair(&after_failover);
    let other_delta_failover = if other_link_name == "link0" {
        after_failover_l0.saturating_sub(before_failover_l0)
    } else {
        after_failover_l1.saturating_sub(before_failover_l1)
    };
    assert!(
        other_delta_failover > 0,
        "the surviving link ('{other_link_name}') never carried traffic after the \
         primary link failed over"
    );

    // Bring the original primary's veth back up. up_threshold defaults
    // to 3 consecutive successful probes, so recovery to plain 'up'
    // state should be faster than the initial down detection above --
    // this only covers the same quality-based hysteresis
    // `veth_failover.rs` already exercises, not re-tested here.
    ns_client
        .exec("ip", &["link", "set", primary_veth, "up"])
        .expect("bring the original primary link's veth back up");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, primary_link)
    })
    .await
    .expect("the original primary link never recovered to 'up' after its veth was brought back up");

    // The point of this test: even though the recovered link is Up
    // again, it must NOT immediately win primary status back and start
    // carrying traffic again -- `refresh_from_scores`'s
    // `PRIMARY_SWITCH_MARGIN`/candidate-streak hysteresis requires it to
    // out-score the current primary by a sustained margin across
    // `up_threshold` consecutive refreshes first. Send a few more probe
    // intervals' worth of traffic and confirm the recovered link's
    // tx_bytes stays flat.
    let before_recovery = poll_snapshot_until(&client_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("failed to fetch a pre-recovery-check snapshot");
    let (before_recovery_l0, before_recovery_l1) = tx_bytes_pair(&before_recovery);

    ns_client
        .exec("ping", &["-c", "10", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed right after the original primary recovered");

    let after_recovery = poll_snapshot_until(&client_ctl, Duration::from_secs(5), |_| true)
        .await
        .expect("failed to fetch a post-recovery-check snapshot");
    let (after_recovery_l0, after_recovery_l1) = tx_bytes_pair(&after_recovery);
    let recovered_delta = if primary_link == "link0" {
        after_recovery_l0.saturating_sub(before_recovery_l0)
    } else {
        after_recovery_l1.saturating_sub(before_recovery_l1)
    };
    assert_eq!(
        recovered_delta, 0,
        "the recovered link ('{primary_link}') carried Data traffic again immediately after \
         coming back Up, but hysteresis should have kept the failed-over link primary until \
         a sustained-margin window passed"
    );
}
