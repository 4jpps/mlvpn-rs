//! End-to-end test of the runtime command socket (`control::serve_commands`,
//! `ipc::Command::SetLinkEnabled`, `Link::admin_disabled` -- see
//! `ARCHITECTURE.md` §9).
//!
//! Drives this through the real `mlvpnd set-link` CLI subcommand rather
//! than talking JSON to the socket directly, so this exercises the whole
//! path an operator would actually use: CLI -> command socket ->
//! `Link::admin_disabled` -> `monitor::score()` forcing 0 ->
//! `scheduler::Scheduler` excluding the link from picking, all while the
//! link's real, probe-measured `state` keeps reporting the truth (it
//! never leaves "up" -- nothing about the underlying veth is touched).
//! The command socket is a Unix socket on the local filesystem, not a
//! network resource, so `mlvpnd set-link` is invoked directly (no `ip
//! netns exec` needed) even though the daemon it's talking to lives
//! inside a network namespace.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_link_control -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::process::Command;
use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up, link_score,
    link_state, poll_snapshot_until, require_ip_command, require_root, unique_id, veth_link_addrs,
    write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair, CLIENT_TUNNEL_ADDR,
    SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn set_link_enabled_pins_scheduling_without_changing_real_link_state() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mtlc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtls{id}")).expect("create server netns");

    let vc0 = format!("mlc0{id}");
    let vs0 = format!("mls0{id}");
    let vc1 = format!("mlc1{id}");
    let vs1 = format!("mls1{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);
    let (addr_c1, addr_s1) = veth_link_addrs(1);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair 0");
    let _veth1 = VethPair::create(&vc1, &ns_client, &addr_c1, &vs1, &ns_server, &addr_s1)
        .expect("create veth pair 1");

    let tmp = create_scratch_dir("linkctl", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");
    let client_cmd = tmp.join("client-command.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();
    let server_addr_1 = addr_s1.split('/').next().unwrap();

    let server_cfg = write_config(
        &tmp,
        "server",
        "mlcsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vs0,
                local_port: 6500,
                local_addr: None,
                remote_addr: None,
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vs1,
                local_port: 6501,
                local_addr: None,
                remote_addr: None,
            },
        ],
        &server_ctl,
        None, // server doesn't need a command socket for this test
    )
    .expect("write server config");

    // The client's command socket is deliberately enabled here (`Some`)
    // while the server's stays disabled above (`None`) -- this is the
    // only side under test, and leaving the server's off is itself a
    // small regression guard that `[command]` really does default/stay
    // off when not asked for.
    let client_cfg = write_config(
        &tmp,
        "client",
        "mlccli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[
            LinkSpec {
                name: "link0",
                bind_interface: &vc0,
                local_port: 6500,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_0}:6500")),
            },
            LinkSpec {
                name: "link1",
                bind_interface: &vc1,
                local_port: 6501,
                local_addr: None,
                remote_addr: Some(format!("{server_addr_1}:6501")),
            },
        ],
        &client_ctl,
        Some(&client_cmd),
    )
    .expect("write client config");

    let _server = MlvpnProcess::spawn(&ns_server.name, &server_cfg).expect("spawn server");
    let _client = MlvpnProcess::spawn(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0") && link_is_up(s, "link1")
    })
    .await
    .expect("both links never reached 'up' before the command test could even start");

    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(5), |s| {
        link_score(s, "link0").unwrap_or(0.0) > 0.0
    })
    .await
    .expect("link0 never showed a positive score before being disabled");
    assert!(link_score(&snapshot, "link0").unwrap_or(0.0) > 0.0);

    // The actual point of this test: disabling link0 via the command
    // socket should zero its score (excluding it from scheduling)
    // without ever marking it "down" -- the real probes on the wire
    // never stopped succeeding.
    let bin = env!("CARGO_BIN_EXE_mlvpnd");
    let status = Command::new(bin)
        .args(["set-link", "--config"])
        .arg(&client_cfg)
        .args(["link0", "disable"])
        .status()
        .expect("run mlvpnd set-link (disable)");
    assert!(status.success(), "mlvpnd set-link link0 disable failed");

    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(10), |s| {
        link_score(s, "link0") == Some(0.0)
    })
    .await
    .expect("link0's score never dropped to 0 after being disabled");
    assert_eq!(
        link_state(&snapshot, "link0"),
        Some("up"),
        "link0's real state should stay 'up' while merely admin-disabled -- \
         the underlying veth was never touched"
    );
    assert!(
        link_score(&snapshot, "link1").unwrap_or(0.0) > 0.0,
        "link1 should be unaffected by link0 being disabled"
    );

    // Traffic should still flow -- link1 alone should be carrying it.
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed while link0 was admin-disabled");

    // Re-enable and confirm it comes back into rotation.
    let status = Command::new(bin)
        .args(["set-link", "--config"])
        .arg(&client_cfg)
        .args(["link0", "enable"])
        .status()
        .expect("run mlvpnd set-link (enable)");
    assert!(status.success(), "mlvpnd set-link link0 enable failed");

    let snapshot = poll_snapshot_until(&client_ctl, Duration::from_secs(10), |s| {
        link_score(s, "link0").unwrap_or(0.0) > 0.0
    })
    .await
    .expect("link0's score never recovered after being re-enabled");
    assert_eq!(link_state(&snapshot, "link0"), Some("up"));

    // Asking to control a link that doesn't exist should fail cleanly
    // rather than silently succeeding or crashing the daemon.
    let status = Command::new(bin)
        .args(["set-link", "--config"])
        .arg(&client_cfg)
        .args(["not-a-real-link", "disable"])
        .status()
        .expect("run mlvpnd set-link against a bogus link name");
    assert!(
        !status.success(),
        "mlvpnd set-link should fail for an unknown link name"
    );

    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after link0 was re-enabled");
}
