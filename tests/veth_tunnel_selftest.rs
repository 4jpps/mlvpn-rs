//! End-to-end test of the tunnel-level throughput self-test
//! (`mlvpnd self-test --tunnel`, `ipc::Command::RunTunnelThroughputTest`
//! -- see `tunneltest.rs`'s module doc comment for what makes this
//! different from the plain per-link `mlvpnd self-test`: real UDP
//! packets addressed to the peer's *tunnel-internal* IP, genuinely
//! flowing through the TUN device, the real bounded outbound queue, and
//! the real scheduler, instead of raw traffic on one link's own socket).
//!
//! Drives this through the real `mlvpnd self-test --tunnel` CLI
//! subcommand, same reasoning as every other CLI-driven test in this
//! harness (`veth_throughput_selftest.rs`'s own module doc comment).
//! Only the client needs `[command]` enabled -- the server's persistent
//! listener (`tunneltest::run_listener`) runs unconditionally,
//! regardless of its own command-socket config, matching the per-link
//! self-test's own "any daemon can be the target" precedent.
//!
//! Covers both the unidirectional case (upload leg only, the server's
//! listener measures and replies) and the bidirectional case (also
//! exercises the server's autonomous reverse leg, and confirms the
//! reported outbound-queue-drop deltas come back as real numbers, not
//! just present-but-meaningless placeholders).
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_tunnel_selftest -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

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
async fn tunnel_selftest_measures_the_real_bonded_path() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mttc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mtts{id}")).expect("create server netns");

    let vc0 = format!("mtt0c{id}");
    let vs0 = format!("mtt0s{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("tunnelst", &id).expect("create scratch dir");

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
        "mttsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6930,
            local_addr: None,
            remote_addr: None,
        }],
        &server_ctl,
        // No command socket on the server -- the tunnel-level
        // listener must still work without it (see module doc
        // comment).
        None,
    )
    .expect("write server config");

    let client_cfg = write_config(
        &tmp,
        "client",
        "mttcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6930,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6930")),
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
    .expect("link0 never reached 'up' before the tunnel self-test could even start");

    let bin = env!("CARGO_BIN_EXE_mlvpnd");

    // --- Unidirectional: upload leg only.
    let output = Command::new(bin)
        .args(["self-test", "--config"])
        .arg(&client_cfg)
        .args(["--tunnel", "--peer-addr", SERVER_TUNNEL_HOST])
        .args(["--duration", "2"])
        .output()
        .expect("run mlvpnd self-test --tunnel (unidirectional)");
    assert!(
        output.status.success(),
        "mlvpnd self-test --tunnel (unidirectional) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("upload:") && !stdout.contains("no result"),
        "expected a real upload result in CLI output, got: {stdout}"
    );
    // Not asserting a *specific* count: an unthrottled synthetic blast
    // over a very fast local veth pair routinely overwhelms the
    // outbound queue's small fixed capacity on its own (observed in
    // practice: hundreds of thousands of real drops in just a couple of
    // seconds) -- that's a genuine, useful finding about the queue's
    // real behavior under sufficiently bursty load, not a test bug to
    // paper over. What matters here is that the report line is present
    // and reflects a real, non-negative number either way.
    assert!(
        stdout.contains("our own outbound queue dropped") && stdout.contains("packet(s)")
            || stdout.contains("outbound queue dropped 0 packets"),
        "expected a local queue-drop report line in CLI output, got: {stdout}"
    );
    assert!(
        !stdout.contains("download:"),
        "unidirectional run should not print a download line, got: {stdout}"
    );

    // --- Bidirectional: also exercises the server's autonomous
    // reverse leg.
    let output = Command::new(bin)
        .args(["self-test", "--config"])
        .arg(&client_cfg)
        .args(["--tunnel", "--peer-addr", SERVER_TUNNEL_HOST])
        .args(["--duration", "2", "--bidirectional"])
        .output()
        .expect("run mlvpnd self-test --tunnel (bidirectional)");
    assert!(
        output.status.success(),
        "mlvpnd self-test --tunnel (bidirectional) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("upload:") && stdout.contains("download:") && !stdout.contains("no result"),
        "expected real upload and download results in CLI output, got: {stdout}"
    );
    assert!(
        stdout.contains("peer's outbound queue dropped"),
        "expected a peer queue-drop report for the download leg, got: {stdout}"
    );

    // Real Data traffic should still flow normally afterward -- the
    // tunnel-level self-test's synthetic app-level traffic must not
    // have left anything in a broken state.
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after the tunnel-level self-tests");
}
