//! End-to-end test of the diagnostic-dump feature (`ipc::Command::DiagDump`,
//! `mlvpnd diag-dump` on the CLI, and the automatic loss-threshold watcher
//! `control::diagnostics_watch_loop` -- see `diag.rs` and
//! `config::DiagnosticsConfig`).
//!
//! Covers both halves:
//!
//! - **Manual**: `mlvpnd diag-dump` against a running daemon writes a
//!   text bundle containing the daemon-visible section (link/session/
//!   queue/tun/system state, rendered by `diag::format_dump`) plus a
//!   kernel-diagnostics section captured by the CLI process itself
//!   (`main.rs::capture_kernel_udp_diagnostics`) -- this test only
//!   asserts the `/proc/net/udp` sub-section, since `nstat`/`ss` aren't
//!   guaranteed to be installed wherever this test runs and that
//!   function already degrades gracefully when they're missing.
//! - **Automatic**: with `[diagnostics] auto_dump_enabled = true` and a
//!   low `loss_threshold_pct`, injecting real loss via `tc netem` on the
//!   client's veth interface should make the client's own locally
//!   measured probe loss exceed the threshold, and
//!   `diagnostics_watch_loop` should write a dump file to `dump_dir` on
//!   its own, with no CLI/command-socket invocation involved.
//!
//! See `tests/support/mod.rs`'s module doc comment for what this needs
//! (root, `iproute2` incl. `tc`, the `mlvpn` system user). Run with:
//!
//! ```text
//! sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked \
//!     --test veth_diag_dump -- --ignored --nocapture
//! ```
//!
//! (`sudo -E` alone isn't enough for a rustup-managed toolchain -- see
//! `veth_handshake_race.rs`'s module doc comment for why.)

mod support;

use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use support::{
    create_scratch_dir, ensure_mlvpn_system_user, generate_test_keypair, link_is_up,
    poll_snapshot_until, require_ip_command, require_root, require_tc_command,
    spawn_capturing_mock_server_on, unique_id, veth_link_addrs, write_config, LinkSpec,
    MlvpnProcess, NetNs, SchedulerOverrides, VethPair, CLIENT_TUNNEL_ADDR, SERVER_TUNNEL_ADDR,
    SERVER_TUNNEL_HOST,
};

/// Guards concurrent mutation of the process-global `MLVPN_DIAGNOSTICS_URL`
/// env var across tests in this file. Mirrors the `ENV_LOCK` pattern
/// `src/diagnostics.rs`'s own unit tests already established for this
/// exact env var (Task 3 hit this same race and fixed it the same way) --
/// this file's documented invocation doesn't pass `--test-threads=1`, and
/// other tests in this file spawn `mlvpnd` child processes concurrently,
/// so an unguarded `std::env::set_var`/`remove_var` pair here would
/// reintroduce that exact class of bug.
static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// RAII guard: holds `ENV_LOCK` and unsets `MLVPN_DIAGNOSTICS_URL` on
/// drop, so a panicking `.expect()`/`assert!` anywhere after `set` is
/// called still can't leak the mutation (or the lock) into whatever test
/// runs after this one -- normal Rust test-harness unwinding runs `Drop`
/// impls for a panicking test's still-live locals same as any other
/// early return.
struct DiagnosticsUrlGuard {
    _lock: MutexGuard<'static, ()>,
}

impl DiagnosticsUrlGuard {
    fn set(url: &str) -> Self {
        let lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        std::env::set_var("MLVPN_DIAGNOSTICS_URL", url);
        Self { _lock: lock }
    }
}

impl Drop for DiagnosticsUrlGuard {
    fn drop(&mut self) {
        std::env::remove_var("MLVPN_DIAGNOSTICS_URL");
    }
}

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), and network namespaces -- see module doc comment"]
async fn diag_dump_manual_command_writes_a_real_bundle() {
    require_root();
    require_ip_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mddc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mdds{id}")).expect("create server netns");

    let vc0 = format!("mdd0c{id}");
    let vs0 = format!("mdd0s{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    let tmp = create_scratch_dir("diagdump", &id).expect("create scratch dir");

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
        "mddsrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6910,
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
        "mddcli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6910,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6910")),
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
    .expect("link0 never reached 'up' before diag-dump could even run");

    let bin = env!("CARGO_BIN_EXE_mlvpnd");
    let output_path = tmp.join("manual-dump.txt");
    let output = Command::new(bin)
        .args(["diag-dump", "--config"])
        .arg(&client_cfg)
        .args(["--output"])
        .arg(&output_path)
        .output()
        .expect("run mlvpnd diag-dump");
    assert!(
        output.status.success(),
        "mlvpnd diag-dump failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let dump = std::fs::read_to_string(&output_path).expect("read diag-dump output file");
    assert!(
        dump.contains("=== mlvpn diagnostic dump ==="),
        "missing daemon-visible header, got:\n{dump}"
    );
    assert!(
        dump.contains("trigger: manual (mlvpnd diag-dump)"),
        "missing manual trigger line, got:\n{dump}"
    );
    assert!(
        dump.contains("link0: state="),
        "missing link0's section, got:\n{dump}"
    );
    assert!(
        dump.contains("--- Kernel UDP diagnostics"),
        "missing kernel-diagnostics section, got:\n{dump}"
    );
    assert!(
        dump.contains("$ /proc/net/udp"),
        "missing /proc/net/udp sub-section, got:\n{dump}"
    );

    // Real Data traffic should still flow normally afterward.
    ns_client
        .exec("ping", &["-c", "2", "-W", "2", SERVER_TUNNEL_HOST])
        .expect("ping across the tunnel failed after diag-dump");
}

#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), and network namespaces -- see module doc comment"]
async fn diag_dump_auto_watch_fires_on_real_loss() {
    require_root();
    require_ip_command();
    require_tc_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mdac{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mdas{id}")).expect("create server netns");

    let vc0 = format!("mda0c{id}");
    let vs0 = format!("mda0s{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    // Real, substantial loss on the client's own interface -- this is
    // what should push the client's locally-measured probe loss
    // (`LinkStats::loss_rate`, the same figure `local_loss_pct` reports)
    // past the low threshold configured below.
    ns_client
        .exec(
            "tc",
            &["qdisc", "add", "dev", &vc0, "root", "netem", "loss", "60%"],
        )
        .expect("add netem loss to client's veth");

    let tmp = create_scratch_dir("diagdumpauto", &id).expect("create scratch dir");
    let dump_dir = tmp.join("auto-dumps");

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
        "mdasrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6911,
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
        "mdacli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6911,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6911")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    // `write_config` has no `[diagnostics]` knob of its own (every other
    // integration test leaves this feature off) -- append the section
    // directly rather than growing that shared helper's already-long
    // parameter list for one test file's sake.
    let mut toml = std::fs::read_to_string(&client_cfg).expect("read client config back");
    toml.push_str(&format!(
        "[diagnostics]\nauto_dump_enabled = true\nloss_threshold_pct = 5.0\n\
         cooldown_secs = 1\ndump_dir = \"{}\"\n",
        dump_dir.display()
    ));
    std::fs::write(&client_cfg, toml).expect("append [diagnostics] to client config");

    let (_server, _server_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, _client_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg).expect("spawn client");

    // Don't wait for link0 to reach "up" here -- 60% loss may well keep
    // it flapping or Down; the diagnostic watcher checks
    // `local_loss_pct` regardless of `state` (probes, and the loss they
    // feed into `LinkStats::loss_rate`, run independent of the
    // scheduling state machine), so this test only needs the daemon to
    // be up and probing, not the link to be considered healthy.
    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        s.links.iter().any(|l| l.name == "link0")
    })
    .await
    .expect("client never produced a snapshot with link0 at all");

    // Poll the dump directory directly rather than the control socket --
    // this is a file the daemon writes to disk on its own, with no wire
    // or command-socket signal accompanying it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut found: Option<std::path::PathBuf> = None;
    while tokio::time::Instant::now() < deadline {
        if let Ok(entries) = std::fs::read_dir(&dump_dir) {
            if let Some(entry) = entries
                .filter_map(|e| e.ok())
                .find(|e| e.file_name().to_string_lossy().starts_with("mlvpn-diag-"))
            {
                found = Some(entry.path());
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let path = found.expect(
        "diagnostics_watch_loop never wrote an automatic dump file within 60s of real 60% loss",
    );
    let dump = std::fs::read_to_string(&path).expect("read automatic dump file");
    assert!(
        dump.contains("trigger: automatic: link 'link0' loss"),
        "missing automatic trigger line, got:\n{dump}"
    );
    assert!(
        dump.contains("exceeded threshold 5.0%"),
        "missing threshold detail in trigger line, got:\n{dump}"
    );
}

const HOST_VETH_HOST_IP: &str = "203.0.113.1";
const HOST_VETH_CLIENT_IP: &str = "203.0.113.2";

struct HostVeth {
    host_if: String,
}

impl HostVeth {
    fn create(host_if: &str, peer_if: &str, client_ns: &NetNs) -> std::io::Result<Self> {
        let run = |args: &[&str]| -> std::io::Result<()> {
            let st = std::process::Command::new("ip").args(args).status()?;
            if st.success() {
                Ok(())
            } else {
                Err(std::io::Error::other(format!("ip {args:?} failed")))
            }
        };
        run(&[
            "link", "add", host_if, "type", "veth", "peer", "name", peer_if,
        ])?;
        let this = Self {
            host_if: host_if.to_string(),
        };
        run(&["link", "set", peer_if, "netns", client_ns.name.as_str()])?;
        run(&[
            "addr",
            "add",
            &format!("{HOST_VETH_HOST_IP}/30"),
            "dev",
            host_if,
        ])?;
        run(&["link", "set", host_if, "up"])?;
        client_ns.exec(
            "ip",
            &[
                "addr",
                "add",
                &format!("{HOST_VETH_CLIENT_IP}/30"),
                "dev",
                peer_if,
            ],
        )?;
        client_ns.exec("ip", &["link", "set", peer_if, "up"])?;
        Ok(this)
    }
}

impl Drop for HostVeth {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["link", "del", self.host_if.as_str()])
            .status();
    }
}

/// Same real-loss setup as `diag_dump_auto_watch_fires_on_real_loss`, but
/// with `auto_submit_enabled = true` and `MLVPN_DIAGNOSTICS_URL` pointed
/// at a local mock server (see `support::spawn_capturing_mock_server`)
/// standing in for `jpps/software-support`. Confirms
/// `control::diagnostics_watch_loop` doesn't just write the local dump
/// file (already covered above) but also actually submits it, with
/// `trigger: "auto"` in the POST body -- the new behavior added in this
/// task (see `src/control.rs`'s call to
/// `diagnostics::submit_report_async` right after the local write).
#[tokio::test]
#[ignore = "needs root, iproute2 (incl. tc), and network namespaces -- see module doc comment"]
async fn diag_dump_auto_watch_submits_report_when_auto_submit_enabled() {
    require_root();
    require_ip_command();
    require_tc_command();
    ensure_mlvpn_system_user().expect("ensure mlvpn system user/group exists");

    let id = unique_id();
    let ns_client = NetNs::create(&format!("mdsc{id}")).expect("create client netns");
    let ns_server = NetNs::create(&format!("mdss{id}")).expect("create server netns");

    // The mock intake server lives in the host netns, but `mlvpnd` runs in
    // `ns_client` with its own loopback, so give the client a dedicated
    // veth to the host (no netem on it) and bind the mock to the host end.
    let host_if = format!("mdsh{id}");
    let host_peer = format!("mdsp{id}");
    let _host_veth = HostVeth::create(&host_if, &host_peer, &ns_client)
        .expect("create host<->client veth for the mock intake server");
    let (mock_url, mock_rx) = spawn_capturing_mock_server_on(
        HOST_VETH_HOST_IP,
        "HTTP/1.1 201 Created",
        r#"{"ticket_id":"test-ticket-1"}"#,
    );
    // `MlvpnProcess::spawn_with_log_capture` inherits the current
    // process's environment, so setting this before spawning the client
    // is enough for the child `mlvpnd` to pick it up via
    // `diagnostics::diagnostics_url`. `Drop` unsets it and releases
    // `ENV_LOCK` even if something below panics.
    let _diagnostics_url_guard = DiagnosticsUrlGuard::set(&mock_url);

    let vc0 = format!("mds0c{id}");
    let vs0 = format!("mds0s{id}");
    let (addr_c0, addr_s0) = veth_link_addrs(0);

    let _veth0 = VethPair::create(&vc0, &ns_client, &addr_c0, &vs0, &ns_server, &addr_s0)
        .expect("create veth pair");

    // Real, substantial loss on the client's own interface, same as the
    // plain automatic-dump test above, to push measured loss past the
    // low threshold configured below.
    ns_client
        .exec(
            "tc",
            &["qdisc", "add", "dev", &vc0, "root", "netem", "loss", "60%"],
        )
        .expect("add netem loss to client's veth");

    let tmp = create_scratch_dir("diagdumpsubmit", &id).expect("create scratch dir");
    let dump_dir = tmp.join("auto-dumps");

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
        "mdssrv0",
        SERVER_TUNNEL_ADDR,
        &server_key_path,
        &client_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vs0,
            local_port: 6912,
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
        "mdscli0",
        CLIENT_TUNNEL_ADDR,
        &client_key_path,
        &server_pub,
        None,
        SchedulerOverrides::default(),
        &[LinkSpec {
            name: "link0",
            bind_interface: &vc0,
            local_port: 6912,
            local_addr: None,
            remote_addr: Some(format!("{server_addr_0}:6912")),
        }],
        &client_ctl,
        None,
    )
    .expect("write client config");

    let mut toml = std::fs::read_to_string(&client_cfg).expect("read client config back");
    toml.push_str(&format!(
        "[diagnostics]\nauto_dump_enabled = true\nauto_submit_enabled = true\n\
         loss_threshold_pct = 5.0\ncooldown_secs = 1\ndump_dir = \"{}\"\n",
        dump_dir.display()
    ));
    std::fs::write(&client_cfg, toml).expect("append [diagnostics] to client config");

    let (_server, _server_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_server.name, &server_cfg).expect("spawn server");
    let (_client, _client_logs) =
        MlvpnProcess::spawn_with_log_capture(&ns_client.name, &client_cfg).expect("spawn client");

    poll_snapshot_until(&client_ctl, Duration::from_secs(20), |s| {
        s.links.iter().any(|l| l.name == "link0")
    })
    .await
    .expect("client never produced a snapshot with link0 at all");

    // Wait for the mock server to actually receive the automatic
    // submission's POST -- this is the new behavior under test, distinct
    // from the local dump file also covered by the sibling test above.
    let request = mock_rx
        .recv_timeout(Duration::from_secs(60))
        .expect("mock software-support server never received a POST within 60s of real 60% loss");

    assert!(
        request.starts_with("POST /api/v1/reports"),
        "expected a POST to /api/v1/reports, got request:\n{request}"
    );
    assert!(
        request.contains("\"trigger\":\"auto\""),
        "expected trigger:\"auto\" in the submitted body, got request:\n{request}"
    );
    assert!(
        request.contains("\"product\":\"mlvpn-rs\""),
        "expected product:\"mlvpn-rs\" in the submitted body, got request:\n{request}"
    );
}
