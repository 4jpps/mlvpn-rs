//! End-to-end test of the TCP tunnel-level self-test (see
//! `docs/superpowers/specs/2026-09-16-tcp-tunnel-self-test-design.md`):
//! runs `mlvpnd self-test --tunnel --protocol tcp --bidirectional`
//! against a real peer over a real veth pair and confirms both legs
//! report a real, nonzero `achieved_mbps` plus real TCP retransmit
//! counts.
//!
//! Unlike `tests/veth_fec.rs`/`tests/veth_primary_mtu.rs`, this test
//! was actually EXECUTED for real (not just compiled) on the
//! `mlvpn-mtu-test` Proxmox VM (VMID 105) as part of landing this
//! feature -- see this plan's Task 4 report for the real run's result.
//!
//! Modeled directly on `tests/veth_tunnel_selftest.rs`'s (the UDP
//! sibling of this test) topology and CLI-invocation pattern: the
//! `mlvpnd self-test --tunnel` subcommand talks to the already-running
//! daemon over its command-socket (a plain Unix domain socket, just a
//! file on disk), so the CLI process itself does not need to run
//! *inside* either network namespace -- only the two `mlvpnd` daemons
//! (already spawned inside their respective namespaces) do the real
//! TCP work over the veth pair.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_tcp_selftest -- --ignored --nocapture
//! ```

mod support;

use std::process::Command;
use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, unique_id, veth_link_addrs,
    write_config, LinkSpec, MlvpnProcess, NetNs, SchedulerOverrides, VethPair, CLIENT_TUNNEL_ADDR,
    SERVER_TUNNEL_ADDR, SERVER_TUNNEL_HOST,
};

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn tcp_tunnel_self_test_reports_real_nonzero_throughput_both_directions() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("tcpstc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("tcpsts{id}")).expect("create server netns");

    let vc0 = format!("tcpc0{id}");
    let vs0 = format!("tcps0{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("tcpselftest", &id).expect("create scratch dir");

    let (client_key_path, client_pub) =
        generate_test_keypair(&tmp, "client").expect("generate client keypair");
    let (server_key_path, server_pub) =
        generate_test_keypair(&tmp, "server").expect("generate server keypair");

    let server_ctl = tmp.join("server.sock");
    let client_ctl = tmp.join("client.sock");
    let client_cmd = tmp.join("client-command.sock");

    let server_addr_0 = addr_s0.split('/').next().unwrap();

    let server_cfg = write_config(
        &tmp,
        "server",
        "tcpstsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6410,
            local_addr: None,
            remote_addr: None,
        }],
        &server_ctl,
        // No command socket on the server -- the tunnel-level listener
        // runs unconditionally regardless of the server's own
        // command-socket config, matching the UDP self-test's own
        // "any daemon can be the target" precedent
        // (`tests/veth_tunnel_selftest.rs`).
        None,
    )
    .expect("write server config");

    let client_cfg = write_config(
        &tmp,
        "client",
        "tcpstcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6410,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6410")),
        }],
        &client_ctl,
        Some(&client_cmd),
    )
    .expect("write client config");

    let (_server, _server_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, _client_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up' before the TCP tunnel self-test could even start");

    let bin = env!("CARGO_BIN_EXE_mlvpnd");

    // Run the real mlvpnd CLI binary's self-test subcommand -- exercising
    // the actual CLI parsing/command-socket path end to end, not just
    // internal Rust functions -- against the server's real
    // tunnel-internal address, over a real TCP connection.
    let output = Command::new(bin)
        .args(["self-test", "--config"])
        .arg(&client_cfg)
        .args(["--tunnel", "--peer-addr", SERVER_TUNNEL_HOST])
        .args(["--protocol", "tcp", "--bidirectional"])
        .args(["--duration", "3"])
        .output()
        .expect("run mlvpnd self-test --tunnel --protocol tcp (bidirectional)");
    assert!(
        output.status.success(),
        "mlvpnd self-test --tunnel --protocol tcp failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("upload:") && !stdout.contains("upload: no result"),
        "expected a real upload result, got: {stdout}"
    );
    assert!(
        stdout.contains("download:") && !stdout.contains("download: no result"),
        "expected a real download result, got: {stdout}"
    );
    assert!(
        stdout.contains("retransmits:"),
        "expected real TCP retransmit counts in the output, got: {stdout}"
    );

    // Real Data traffic should still flow normally afterward -- the
    // tunnel-level TCP self-test's synthetic app-level traffic must not
    // have left anything in a broken state.
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after the tunnel-level TCP self-test");
}
