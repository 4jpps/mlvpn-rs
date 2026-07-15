//! End-to-end test of `scheduler.auto_tune_probe_interval`
//! (`tunnel::link_prober`, `tunnel::suggest_probe_interval_ms` -- see
//! `ARCHITECTURE.md` §5).
//!
//! Unlike `veth_reorder_tuning.rs`, this needs no artificial network
//! impairment: an ordinary, healthy veth link already gives
//! `link_prober` a long clean streak "for free," so the auto-tuner
//! should back its effective probe interval off from the default 200ms
//! floor within a few seconds of the link coming up (`PROBE_BACKOFF_STREAK`
//! consecutive hits, ~2s at 200ms/probe). Confirms it actually did by
//! watching for the `"auto-tuned probe_interval_ms"` log line
//! (`MlvpnProcess::spawn_with_log_capture` -- see
//! `veth_reorder_tuning.rs`'s module doc comment for why real log
//! capture is needed here instead of the control socket).
//!
//! **What this does not assert**: the exact resulting interval value or
//! the immediate-snap-back-to-floor-on-a-miss half of the design.
//! `suggest_probe_interval_ms`'s math (both halves) is covered
//! precisely by `tunnel.rs`'s own unit tests instead; this test's job
//! is only to prove the backoff half of the path fires at all against a
//! real daemon under real (if uneventful) network conditions.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_probe_interval_tuning -- --ignored --nocapture
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

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn auto_tune_probe_interval_backs_off_on_a_clean_streak() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtpc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtps{id}")).expect("create server netns");

    let vc0 = format!("mpc0{id}");
    let vs0 = format!("mps0{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("probetune", &id).expect("create scratch dir");

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
        "mptsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6800,
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
        "mptcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides {
            auto_tune_probe_interval: true,
            ..Default::default()
        },
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6800,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6800")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, client_logs) = MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg)
        .expect("spawn client with log capture");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up'");

    // The actual point of this test: a healthy link should back its
    // probe interval off after PROBE_BACKOFF_STREAK (10) consecutive
    // good probes -- roughly 2s of wall time at the default 200ms
    // floor, plus room for the up-threshold delay and general test
    // overhead.
    let saw_tuning = client_logs
        .wait_for_line_containing("auto-tuned probe_interval_ms", Duration::from_secs(15))
        .await;
    assert!(
        saw_tuning,
        "never saw an \"auto-tuned probe_interval_ms\" log line from the client within 15s; \
         either link_prober isn't backing off, or the streak never got the chance to build up"
    );

    // Traffic should still flow normally with a backed-off probe
    // interval in effect.
    ns_client
        .exec("ping", &["-c", "3", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after the probe interval was auto-tuned");
}
