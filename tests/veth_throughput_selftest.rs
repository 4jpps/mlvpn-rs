//! End-to-end test of the on-demand throughput self-test
//! (`ipc::Command::RunThroughputTest`, `mlvpnd self-test` on the CLI --
//! see `tunnel::send_throughput_test_stream`/
//! `tunnel::send_throughput_test_reverse_request`/
//! `tunnel::ThroughputTestContext` and `control::apply_command`'s
//! handling of this command).
//!
//! Drives this through the real `mlvpnd self-test` CLI subcommand
//! rather than talking JSON to the command socket directly, so this
//! exercises the whole path an operator would actually use -- same
//! reasoning as `veth_link_control.rs`'s own module doc comment. The
//! command socket is a Unix socket on the local filesystem, not a
//! network resource, so `mlvpnd self-test` is invoked directly (no `ip
//! netns exec` needed) even though the daemon it's talking to lives
//! inside a network namespace.
//!
//! Covers both the unidirectional case (forward/upload leg only, the
//! peer measures and reports back over the wire) and the bidirectional
//! case (also exercises the autonomous peer-triggered reverse stream --
//! the server side needs no separate command invoked against it at
//! all, it just reacts to the `ThroughputTestReverseRequest` frame on
//! its own).
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_throughput_selftest -- --ignored --nocapture
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

/// Pulls the `achieved_mbps=<value>` field back out of a captured log
/// line -- same approach (and same reasoning) as
/// `veth_active_bandwidth_probing.rs`'s own helper of the same shape.
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

/// Short enough that this test stays fast (each direction actually
/// transmits for this long), long enough to produce a stable,
/// non-noise-dominated rate measurement over the veth pair.
const TEST_DURATION_SECS: &str = "2";

#[tokio::test]
#[ignore = "needs root, iproute2, and network namespaces -- see module doc comment"]
async fn throughput_selftest_measures_both_directions_over_a_real_link() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mstc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("msts{id}")).expect("create server netns");

    let vc0 = format!("mst0c{id}");
    let vs0 = format!("mst0s{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("throughputst", &id).expect("create scratch dir");

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
        "mtssrv0",
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
        None, // server never needs its own command socket for this --
              // the reverse leg is peer-triggered, not locally invoked.
    )
    .expect("write server config");

    let client_cfg = write_config(
        &tmp,
        "client",
        "mtscli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6900,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6900")),
        }],
        &client_ctl,
        Some(&client_cmd),
    )
    .expect("write client config");

    let (_server, server_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, client_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        link_is_up(s, "link0")
    })
    .await
    .expect("link0 never reached 'up' before the self-test could even start");

    let bin = env!("CARGO_BIN_EXE_mlvpnd");

    // --- Unidirectional: forward/upload leg only. The server measures
    // the stream it receives and reports back over the wire; only the
    // client-side CLI invocation is needed.
    let output = Command::new(bin)
        .args(["self-test", "--config"])
        .arg(&client_cfg)
        .args(["--duration", TEST_DURATION_SECS])
        .output()
        .expect("run mlvpnd self-test (unidirectional)");
    assert!(
        output.status.success(),
        "mlvpnd self-test (unidirectional) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("upload") && !stdout.contains("no result"),
        "expected a real upload result in CLI output, got: {stdout}"
    );

    // The server actually measured and logged a real, positive rate --
    // not just that the CLI printed *something* that looked plausible.
    let server_line = server_logs
        .find_line_containing(
            "throughput self-test stream received",
            Duration::from_secs(10),
        )
        .await
        .expect("server never logged a received throughput-test stream");
    let upload_mbps = parse_achieved_mbps(&server_line);
    assert!(
        upload_mbps > 0.0,
        "server's measured upload rate should be positive, got {upload_mbps}"
    );

    // --- Bidirectional: also exercises the autonomous peer-triggered
    // reverse stream -- the server does this entirely on its own, in
    // response to a ThroughputTestReverseRequest frame, with no CLI
    // invocation against the server side at all.
    let output = Command::new(bin)
        .args(["self-test", "--config"])
        .arg(&client_cfg)
        .args(["--duration", TEST_DURATION_SECS, "--bidirectional"])
        .output()
        .expect("run mlvpnd self-test (bidirectional)");
    assert!(
        output.status.success(),
        "mlvpnd self-test (bidirectional) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("upload") && stdout.contains("download") && !stdout.contains("no result"),
        "expected real upload and download results in CLI output, got: {stdout}"
    );

    // The client itself measured the reverse-direction stream locally
    // (delivered via ThroughputTestContext, not a wire reply) --
    // confirming the autonomous reverse leg actually ran and produced a
    // real number, not just that the CLI's own summary line looked
    // plausible.
    let client_line = client_logs
        .find_line_containing(
            "throughput self-test stream received",
            Duration::from_secs(TEST_DURATION_SECS.parse::<u64>().unwrap() + 10),
        )
        .await
        .expect("client never logged its own measurement of the reverse-direction stream");
    let download_mbps = parse_achieved_mbps(&client_line);
    assert!(
        download_mbps > 0.0,
        "client's measured download rate should be positive, got {download_mbps}"
    );

    // Real Data traffic should still flow normally afterward -- the
    // self-test's extra packet types/tasks must not have left anything
    // in a broken state.
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after the throughput self-tests");
}
