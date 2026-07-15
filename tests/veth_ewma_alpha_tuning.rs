//! End-to-end test of `scheduler.auto_tune_ewma_alpha`
//! (`tunnel::link_prober`, `tunnel::suggest_ewma_alpha`,
//! `link::LinkStats::set_alpha` -- see `ARCHITECTURE.md` §5).
//!
//! Same shape as `veth_probe_interval_tuning.rs` and for the same
//! reason: an ordinary, healthy veth link already gives `link_prober` a
//! long clean streak "for free," so the auto-tuner should smooth a
//! link's alpha down from its configured starting value within a few
//! seconds of coming up (`EWMA_ALPHA_SMOOTHING_STREAK` consecutive
//! hits, ~2s at the default 200ms probe interval). Confirms it actually
//! did by watching for the `"auto-tuned ewma_alpha"` log line -- see
//! `veth_reorder_tuning.rs`'s module doc comment for why real log
//! capture (`MlvpnProcess::spawn_with_log_capture`) is needed here
//! instead of the control socket.
//!
//! **What this does not assert**: the exact resulting alpha value, or
//! the immediate-jump-to-max-on-a-miss half of the design.
//! `suggest_ewma_alpha`'s math (both halves) is covered precisely by
//! `tunnel.rs`'s own unit tests instead; this test's job is only to
//! prove the smoothing half of the path fires at all against a real
//! daemon under real (if uneventful) network conditions.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_ewma_alpha_tuning -- --ignored --nocapture
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
async fn auto_tune_ewma_alpha_smooths_on_a_clean_streak() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtec{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtes{id}")).expect("create server netns");

    let vc0 = format!("mec0{id}");
    let vs0 = format!("mes0{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("ewmatune", &id).expect("create scratch dir");

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
        "mewsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6900,
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
        "mewcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides {
            auto_tune_ewma_alpha: true,
            ..Default::default()
        },
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6900,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6900")),
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

    // The actual point of this test: a healthy link should smooth its
    // alpha down after EWMA_ALPHA_SMOOTHING_STREAK (10) consecutive
    // good probes -- roughly 2s of wall time at the default 200ms probe
    // interval, plus room for the up-threshold delay and general test
    // overhead.
    let saw_tuning = client_logs
        .wait_for_line_containing("auto-tuned ewma_alpha", Duration::from_secs(15))
        .await;
    assert!(
        saw_tuning,
        "never saw an \"auto-tuned ewma_alpha\" log line from the client within 15s; \
         either link_prober isn't smoothing, or the streak never got the chance to build up"
    );

    // Traffic should still flow normally with a re-tuned alpha in
    // effect.
    ns_client
        .exec("ping", &["-c", "3", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after ewma_alpha was auto-tuned");
}
