//! Shared helpers for the veth/network-namespace integration tests
//! (`tests/veth_*.rs`). Not a test target itself -- `tests/support/mod.rs`
//! (a subdirectory, not `tests/support.rs`) is the idiomatic way to keep
//! Cargo from treating this as its own (empty) integration test binary;
//! each real test file pulls it in with `mod support;`.
//!
//! **What these tests actually exercise, and what they need.** Every test
//! that uses this module spins up two real `mlvpnd` processes (client and
//! server) in their own Linux network namespaces, connected by one or more
//! veth pairs, and drives them exactly like two real hosts on separate
//! physical links would be -- real `SO_BINDTODEVICE` binds, a real Noise
//! handshake, real probing, and (via the control socket) real
//! `ipc::Snapshot` JSON identical to what `mlvpn-tui` consumes. This needs:
//!
//! - Root (network namespace and veth creation, `mlvpnd`'s own
//!   `CAP_NET_ADMIN`/`CAP_NET_RAW` privileged setup).
//! - `iproute2`'s `ip` command on `PATH`.
//! - The `mlvpn` system user/group to exist (created here if missing,
//!   mirroring `docs/installation.md`'s manual "Option B" setup steps
//!   exactly -- and, like that doc's packaging note, never removed again
//!   by teardown).
//!
//! None of that is available in a typical `cargo test` run, so every test
//! using this module is marked `#[ignore]` with an explanatory message;
//! see each test file's own doc comment for the exact command to run them
//! for real. This also means these tests are invisible to (and cannot
//! break) `cargo build`, `cargo test --lib`, or plain `cargo test` --
//! only `cargo test --test <name> -- --ignored` reaches them, and
//! `cargo clippy --all-targets` / `cargo fmt` (which do cover `tests/`)
//! only compile-check and format-check this code, never execute it.
//!
//! **What this does *not* cover yet**, deliberately out of scope for this
//! first pass: rebinding a link whose interface is deleted and recreated
//! with a new ifindex (`link::LinkHandle::reconnect`, see
//! `ARCHITECTURE.md` §6/§8) is not exercised here -- only the
//! already-existing quality-based up/down hysteresis (`veth_failover.rs`,
//! toggling a veth's admin state, which never changes its ifindex).
//! Testing an actual reconnect end-to-end needs either running the daemon
//! under the ambient-capabilities deployment model (so `CAP_NET_RAW`
//! survives startup) or accepting that the default model under test here
//! will legitimately hit `MlvpnError::CapabilityMissing` -- worth a
//! dedicated follow-up test, not bolted onto this one.
//!
//! `#![allow(dead_code)]`: each `tests/veth_*.rs` file compiles this
//! module independently as part of its own standalone test binary (see
//! above), so a helper used by only one of them looks like dead code
//! from every *other* one's perspective -- expected and harmless for a
//! shared support module, not something worth chasing per-file.

#![allow(dead_code)]

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use mlvpn::crypto::StaticKeypair;

/// Fixed addresses reused by every test: safe to hard-code because each
/// test's veths and tunnel devices live inside their own uniquely-named,
/// fully isolated network namespaces (see `unique_id`) -- there is no
/// shared routing table or interface namespace for these to collide in,
/// even when multiple tests run concurrently under the default
/// multi-threaded test runner.
pub const CLIENT_TUNNEL_ADDR: &str = "10.200.0.1/30";
pub const SERVER_TUNNEL_ADDR: &str = "10.200.0.2/30";
pub const CLIENT_TUNNEL_HOST: &str = "10.200.0.1";
pub const SERVER_TUNNEL_HOST: &str = "10.200.0.2";

/// RFC 5737 TEST-NET-2, sliced into /30s: veth pair `n` (0-indexed) uses
/// `198.51.100.{4n+1}` / `198.51.100.{4n+2}`.
pub fn veth_link_addrs(pair_index: u8) -> (String, String) {
    let base = pair_index * 4;
    (
        format!("198.51.100.{}/30", base + 1),
        format!("198.51.100.{}/30", base + 2),
    )
}

/// IPv6 analogue of `veth_link_addrs` above, for `veth_ipv6_link.rs`.
/// Uses a ULA prefix (`fd00::/8`, RFC 4193 -- privately assignable, like
/// TEST-NET-2 is for IPv4) sliced per veth pair the same way: pair `n`
/// (0-indexed) gets its own `/64`, with the pair's two ends at `::1` and
/// `::2` within it.
pub fn veth_link_addrs6(pair_index: u8) -> (String, String) {
    (
        format!("fd00:6c76:70{pair_index:02x}::1/64"),
        format!("fd00:6c76:70{pair_index:02x}::2/64"),
    )
}

/// Short, collision-resistant suffix for netns/interface names. Interface
/// names specifically (veth ends, the TUN device) are capped at
/// `IFNAMSIZ - 1 = 15` bytes by the kernel, so callers must budget their
/// own fixed prefix against this staying short: process id in hex (up to
/// 6 hex digits on a default-configured Linux `pid_max`) plus a 2-hex-digit
/// per-process counter is at most 8 characters.
/// Creates `$TMPDIR/mlvpn-test-<label>-<id>` and makes it world-writable.
///
/// Needed because of a real, worth-understanding interaction: this test
/// harness itself runs as root (it has to, for the netns/veth work), so
/// a plain `create_dir_all` here would leave the directory owned by
/// root with the default (non-group/other-writable) mode. `mlvpnd`,
/// though, binds its control socket *after* `privilege::drop_privileges`
/// has already taken it down to the unprivileged `mlvpn` user (see
/// `ARCHITECTURE.md` §2/§8) -- which then has no permission to create a
/// new file inside a root-owned, mode-0700-ish directory, and
/// `control::serve` fails closed (logs a warning, control socket simply
/// never comes up) rather than erroring the whole daemon. A real
/// deployment never hits this: systemd's `RuntimeDirectory=mlvpn` (see
/// `systemd/mlvpn.service`) creates `/run/mlvpn` already owned by the
/// `mlvpn` user before the daemon ever starts. World-writable is fine
/// for a disposable per-test scratch directory under `$TMPDIR`, torn
/// down (best-effort) once the test's `MlvpnProcess`es are dropped and
/// no longer need it -- see the note on `Drop for MlvpnProcess`.
pub fn create_scratch_dir(label: &str, id: &str) -> io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("mlvpn-test-{label}-{id}"));
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))?;
    Ok(dir)
}

pub fn unique_id() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed) & 0xff;
    format!("{:x}{:02x}", std::process::id(), n)
}

pub fn require_root() {
    if !nix::unistd::geteuid().is_root() {
        panic!(
            "this test needs root: it creates network namespaces and veth \
             interfaces, and exercises mlvpnd's own CAP_NET_ADMIN/CAP_NET_RAW \
             privileged setup. Re-run as: sudo env \"PATH=$PATH\" HOME=\"$HOME\" \
             cargo test --release --locked --test <name> -- --ignored --nocapture \
             (plain `sudo -E` isn't enough for a rustup-managed toolchain)"
        );
    }
}

pub fn require_ip_command() {
    let ok = Command::new("ip")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        panic!("this test needs the `ip` command (iproute2 package) on PATH");
    }
}

/// `tc` (traffic control) ships in the same `iproute2` package as `ip`
/// on most distributions, but is occasionally split into its own
/// package (e.g. `iproute2-tc` on some RPM-based distros), so this is
/// checked separately from `require_ip_command` rather than assumed.
/// Used by `veth_reorder_tuning.rs` to inject an artificial RTT
/// asymmetry (`netem delay`) between two otherwise-identical veth
/// links.
pub fn require_tc_command() {
    let ok = Command::new("tc")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        panic!("this test needs the `tc` command (iproute2, sometimes packaged separately as iproute2-tc) on PATH");
    }
}

/// Idempotent: creates the `mlvpn` system user/group if missing, mirroring
/// `docs/installation.md`'s manual "Option B" setup steps exactly (this is
/// exactly what a real deployment's packaging postinst script, or a
/// from-source install, does once). Deliberately never removed again --
/// same convention `docs/installation.md` notes for the `.rpm` package
/// ("system accounts outlive a plain uninstall").
pub fn ensure_mlvpn_system_user() -> io::Result<()> {
    // `.output()` (captured), not `.status()` (inherited): `getent`'s own
    // matched-entry line would otherwise print straight to the test's
    // stdout on every run where the account already exists, which is
    // noisy and easy to mistake for daemon output.
    let group_exists = Command::new("getent")
        .args(["group", "mlvpn"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !group_exists {
        run_ok("groupadd", &["--system", "mlvpn"])?;
    }
    let user_exists = Command::new("getent")
        .args(["passwd", "mlvpn"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !user_exists {
        run_ok(
            "useradd",
            &[
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "-g",
                "mlvpn",
                "mlvpn",
            ],
        )?;
    }
    Ok(())
}

fn run_ok(cmd: &str, args: &[&str]) -> io::Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "`{cmd} {}` exited with {status}",
            args.join(" ")
        )));
    }
    Ok(())
}

fn run_in_ns_ok(ns: &str, cmd: &str, args: &[&str]) -> io::Result<()> {
    let status = Command::new("ip")
        .args(["netns", "exec", ns, cmd])
        .args(args)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "`ip netns exec {ns} {cmd} {}` exited with {status}",
            args.join(" ")
        )));
    }
    Ok(())
}

/// A Linux network namespace, deleted on drop (best-effort: cleanup
/// running during an already-failing/panicking test must not itself
/// panic, so failures here are silently swallowed -- worst case is a
/// leftover namespace with a distinctive test-only name, harmless beyond
/// `ip netns list` noise until a manual `ip -all netns delete`).
pub struct NetNs {
    pub name: String,
}

impl NetNs {
    pub fn create(name: &str) -> io::Result<Self> {
        run_ok("ip", &["netns", "add", name])?;
        // Loopback isn't strictly needed by anything these tests do
        // (the control socket is a Unix socket, not TCP loopback), but
        // costs nothing and avoids surprises from code that assumes it.
        run_in_ns_ok(name, "ip", &["link", "set", "lo", "up"])?;
        Ok(Self {
            name: name.to_string(),
        })
    }

    pub fn exec(&self, cmd: &str, args: &[&str]) -> io::Result<()> {
        run_in_ns_ok(&self.name, cmd, args)
    }

    /// Like `exec`, but doesn't fail the caller if the command exits
    /// non-zero -- used for the "bring this link down/up" toggles in
    /// `veth_failover.rs`, where a transient error attempting to touch
    /// an interface that's mid-transition is not itself the thing under
    /// test.
    pub fn exec_best_effort(&self, cmd: &str, args: &[&str]) {
        let _ = Command::new("ip")
            .args(["netns", "exec", self.name.as_str(), cmd])
            .args(args)
            .status();
    }
}

impl Drop for NetNs {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", self.name.as_str()])
            .status();
    }
}

/// A veth pair with each end already moved into its target namespace,
/// addressed, and brought up. Deleting either end removes the whole pair
/// (the kernel tears down the peer automatically), so `Drop` only needs
/// to act on one side -- best-effort, same reasoning as `NetNs::drop`,
/// and largely redundant with it anyway (deleting a `NetNs` destroys
/// every interface still inside it).
pub struct VethPair {
    a_name: String,
    a_netns: String,
}

impl VethPair {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        a_name: &str,
        a_ns: &NetNs,
        a_cidr: &str,
        b_name: &str,
        b_ns: &NetNs,
        b_cidr: &str,
    ) -> io::Result<Self> {
        run_ok(
            "ip",
            &[
                "link", "add", a_name, "type", "veth", "peer", "name", b_name,
            ],
        )?;
        run_ok("ip", &["link", "set", a_name, "netns", a_ns.name.as_str()])?;
        run_ok("ip", &["link", "set", b_name, "netns", b_ns.name.as_str()])?;
        a_ns.exec("ip", &["addr", "add", a_cidr, "dev", a_name])?;
        a_ns.exec("ip", &["link", "set", a_name, "up"])?;
        b_ns.exec("ip", &["addr", "add", b_cidr, "dev", b_name])?;
        b_ns.exec("ip", &["link", "set", b_name, "up"])?;
        Ok(Self {
            a_name: a_name.to_string(),
            a_netns: a_ns.name.clone(),
        })
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args([
                "netns",
                "exec",
                self.a_netns.as_str(),
                "ip",
                "link",
                "del",
                self.a_name.as_str(),
            ])
            .status();
    }
}

/// One configured link entry for `write_config`. `remote_addr` is `None`
/// for a server-side link (the peer address is learned dynamically from
/// the first authenticated frame -- see `tunnel.rs`'s `handle_incoming`);
/// `config::Config::validate` requires it to be `Some` for every
/// client-side link. `local_addr` is normally `None` (SO_BINDTODEVICE
/// alone is enough); `veth_ipv6_link.rs` sets it on a server-side link
/// with no `remote_addr` to tell `link::socket_domain` that link is
/// IPv6, the same way an operator would (see that function's doc
/// comment).
pub struct LinkSpec<'a> {
    pub name: &'a str,
    pub bind_interface: &'a str,
    pub local_port: u16,
    pub local_addr: Option<&'a str>,
    pub remote_addr: Option<String>,
}

/// Generates a fresh Curve25519 keypair, writes the private half to
/// `dir/<label>.key` mode 0600 (matching what `config::check_permissions`
/// requires -- checked against the file's own mode bits only, not its
/// owner, so this is satisfiable from a plain tempdir regardless of which
/// uid the test runs as), and returns `(private_key_path,
/// public_key_base64)`. Split out from `write_config` specifically so a
/// caller can generate both sides' keypairs first and cross-reference
/// each one's public half into the *other* side's config -- `write_config`
/// alone can't do that, since each config needs a public key it doesn't
/// itself own.
pub fn generate_test_keypair(dir: &Path, label: &str) -> io::Result<(PathBuf, String)> {
    let keypair = StaticKeypair::generate()
        .map_err(|e| io::Error::other(format!("generating test keypair for {label}: {e}")))?;
    let key_path = dir.join(format!("{label}.key"));
    std::fs::write(&key_path, keypair.private_base64())?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    Ok((key_path, keypair.public_base64()))
}

/// Scheduler-level boolean toggles for `write_config`'s `[scheduler]`
/// table, grouped into one struct rather than a growing list of
/// positional bool parameters on `write_config` itself (this project
/// keeps adding opt-in `scheduler.auto_tune_*` flags, and each one used
/// to mean touching every existing test's call site). All default to
/// `false`, matching `config.rs`'s own defaults, so a test sets only
/// the one flag it actually cares about:
/// `SchedulerOverrides { redundant_mode: true, ..Default::default() }`.
#[derive(Default)]
pub struct SchedulerOverrides {
    /// Used by `veth_redundant.rs` to exercise `scheduler.redundant_mode`.
    pub redundant_mode: bool,
    /// Used by `veth_reorder_tuning.rs` to exercise
    /// `scheduler.auto_tune_reorder_window`.
    pub auto_tune_reorder_window: bool,
    /// Used by `veth_probe_interval_tuning.rs` to exercise
    /// `scheduler.auto_tune_probe_interval`.
    pub auto_tune_probe_interval: bool,
    /// Used by `veth_ewma_alpha_tuning.rs` to exercise
    /// `scheduler.auto_tune_ewma_alpha`.
    pub auto_tune_ewma_alpha: bool,
    /// Used by `veth_active_bandwidth_probing.rs` to exercise
    /// `scheduler.active_bandwidth_probing`.
    pub active_bandwidth_probing: bool,
    /// Overrides `scheduler.active_bandwidth_probe_interval_secs`
    /// (config.rs's own default is 300s, far too slow for a test) --
    /// `None` omits the field, leaving the config default in place.
    /// `Config::validate` enforces a 30s floor regardless.
    pub active_bandwidth_probe_interval_secs: Option<u64>,
}

/// Writes a minimal-but-complete `mlvpnd` TOML config to `dir`. The
/// config file itself is written mode 0600, same reasoning as
/// `generate_test_keypair`'s key file.
#[allow(clippy::too_many_arguments)]
pub fn write_config(
    dir: &Path,
    mode: &str,
    tunnel_name: &str,
    tunnel_address: &str,
    private_key_path: &Path,
    peer_public_key: &str,
    // `None` omits the field entirely, so `config.rs`'s own
    // `default_rekey_secs` (120s) applies -- `Some(n)` overrides it,
    // used by `veth_rekey.rs` to force a real rekey to happen well
    // within a test's own timeout rather than waiting two minutes.
    rekey_interval_secs: Option<u64>,
    scheduler: SchedulerOverrides,
    links: &[LinkSpec],
    control_socket_path: &Path,
    // `None` omits `[command]` entirely (config.rs's own default is
    // already `enabled = false`); `Some(path)` writes `enabled = true`
    // plus that socket path -- used by `veth_link_control.rs` to
    // exercise `control::serve_commands`.
    command_socket_path: Option<&Path>,
) -> io::Result<PathBuf> {
    let mut toml = String::new();
    toml.push_str(&format!("mode = \"{mode}\"\n\n"));
    toml.push_str("[tunnel]\n");
    toml.push_str(&format!("name = \"{tunnel_name}\"\n"));
    toml.push_str(&format!("address = \"{tunnel_address}\"\n\n"));
    toml.push_str("[crypto]\n");
    toml.push_str(&format!(
        "private_key_file = \"{}\"\n",
        private_key_path.display()
    ));
    toml.push_str(&format!("peer_public_key = \"{peer_public_key}\"\n"));
    if let Some(secs) = rekey_interval_secs {
        toml.push_str(&format!("rekey_interval_secs = {secs}\n"));
    }
    toml.push('\n');
    // All flags share one `[scheduler]` table -- TOML doesn't allow
    // re-declaring the same table twice, so this has to be one
    // conditional block rather than one per flag.
    if scheduler.redundant_mode
        || scheduler.auto_tune_reorder_window
        || scheduler.auto_tune_probe_interval
        || scheduler.auto_tune_ewma_alpha
        || scheduler.active_bandwidth_probing
        || scheduler.active_bandwidth_probe_interval_secs.is_some()
    {
        toml.push_str("[scheduler]\n");
        if scheduler.redundant_mode {
            toml.push_str("redundant_mode = true\n");
        }
        if scheduler.auto_tune_reorder_window {
            toml.push_str("auto_tune_reorder_window = true\n");
        }
        if scheduler.auto_tune_probe_interval {
            toml.push_str("auto_tune_probe_interval = true\n");
        }
        if scheduler.auto_tune_ewma_alpha {
            toml.push_str("auto_tune_ewma_alpha = true\n");
        }
        if scheduler.active_bandwidth_probing {
            toml.push_str("active_bandwidth_probing = true\n");
        }
        if let Some(secs) = scheduler.active_bandwidth_probe_interval_secs {
            toml.push_str(&format!("active_bandwidth_probe_interval_secs = {secs}\n"));
        }
        toml.push('\n');
    }
    toml.push_str("[control]\n");
    toml.push_str(&format!(
        "socket_path = \"{}\"\n\n",
        control_socket_path.display()
    ));
    if let Some(path) = command_socket_path {
        toml.push_str("[command]\n");
        toml.push_str("enabled = true\n");
        toml.push_str(&format!("socket_path = \"{}\"\n\n", path.display()));
    }
    for link in links {
        toml.push_str("[[links]]\n");
        toml.push_str(&format!("name = \"{}\"\n", link.name));
        toml.push_str(&format!("bind_interface = \"{}\"\n", link.bind_interface));
        toml.push_str(&format!("local_port = {}\n", link.local_port));
        if let Some(local) = link.local_addr {
            toml.push_str(&format!("local_addr = \"{local}\"\n"));
        }
        if let Some(remote) = &link.remote_addr {
            toml.push_str(&format!("remote_addr = \"{remote}\"\n"));
        }
        toml.push('\n');
    }

    let config_path = dir.join(format!("{tunnel_name}-{mode}.toml"));
    std::fs::write(&config_path, toml)?;
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
    Ok(config_path)
}

/// A running `mlvpnd run` process inside a network namespace. Killed
/// (`SIGKILL`, then reaped) on drop -- this is a test harness tearing
/// down after (or during, on failure) an assertion, where a graceful
/// stop isn't the point of most tests and shouldn't be able to make
/// cleanup itself hang. Tests that specifically exercise graceful
/// shutdown (`tests/veth_disconnect.rs`) use `terminate`/`wait_for_exit`
/// instead. Uses `env!("CARGO_BIN_EXE_mlvpnd")`, which Cargo resolves at
/// compile time to the real built binary and, as a side effect, makes
/// `cargo test` build it automatically before running these tests.
///
/// Relies on `ip netns exec`'s documented behavior of `setns()`-ing and
/// then directly `execve()`-ing the target command in place, rather than
/// forking a supervising child -- i.e. the PID this returns is the real
/// `mlvpnd` process throughout, not a wrapper around it, so killing it
/// here actually kills the daemon rather than just the `ip` invocation
/// that launched it.
pub struct MlvpnProcess {
    child: std::process::Child,
}

impl MlvpnProcess {
    pub fn spawn(ns: &str, config_path: &Path) -> io::Result<Self> {
        let bin = env!("CARGO_BIN_EXE_mlvpnd");
        let child = Command::new("ip")
            .args(["netns", "exec", ns, bin, "run", "--config"])
            .arg(config_path)
            // Inherited rather than piped-and-buffered-here: shows up
            // directly in `cargo test -- --nocapture` output, which is
            // both simpler and more robust than managing pipe-reading
            // threads in this harness ourselves.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self { child })
    }

    /// Like `spawn`, but pipes stdout through a `LogCapture` instead of
    /// inheriting it, so a test can assert a specific log line was
    /// actually emitted. Only worth the extra complexity for tests
    /// where a daemon decision has no other externally observable
    /// signal today -- e.g. `veth_reorder_tuning.rs`, confirming
    /// `tunnel::reorder_tuning_loop` actually re-tuned the window: that
    /// value isn't exposed over the control socket (see its doc comment
    /// in `tunnel.rs` for why simple `tracing::info!` logging was judged
    /// sufficient rather than extending `ipc::Snapshot`'s schema for
    /// it), so the log line *is* the only signal. Every other test still
    /// uses plain `spawn`'s inherited stdio, which is simpler and reads
    /// naturally under `--nocapture`.
    pub fn spawn_with_log_capture(ns: &str, config_path: &Path) -> io::Result<(Self, LogCapture)> {
        let bin = env!("CARGO_BIN_EXE_mlvpnd");
        let mut child = Command::new("ip")
            .args(["netns", "exec", ns, bin, "run", "--config"])
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .expect("stdout was requested as piped above");
        Ok((Self { child }, LogCapture::spawn(stdout)))
    }
}

/// Background-thread-backed capture of a spawned `mlvpnd`'s stdout
/// lines, for tests that need to assert a specific log line actually
/// appeared. See `MlvpnProcess::spawn_with_log_capture`'s doc comment
/// for when this is (and isn't) the right tool.
pub struct LogCapture {
    lines: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl LogCapture {
    fn spawn(stdout: std::process::ChildStdout) -> Self {
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = lines.clone();
        // A plain OS thread, not a tokio task: this reads a blocking
        // pipe (`std::process::ChildStdout`) for the whole life of the
        // child process, which would tie up a tokio worker thread for
        // that entire duration if spawned as an async task instead.
        std::thread::spawn(move || {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                // Still visible under `cargo test -- --nocapture`,
                // same as every other test's inherited-stdio daemon
                // output, just relayed through this thread instead of
                // the OS doing it directly.
                println!("{line}");
                writer.lock().unwrap().push(line);
            }
        });
        Self { lines }
    }

    /// Polls (every 200ms) until some captured line contains `needle`,
    /// or `timeout` elapses.
    pub async fn wait_for_line_containing(&self, needle: &str, timeout: Duration) -> bool {
        self.find_line_containing(needle, timeout).await.is_some()
    }

    /// Like `wait_for_line_containing`, but returns the actual matching
    /// line (the *last* one seen, if more than one matched by the
    /// deadline) instead of just whether one appeared -- used by
    /// `veth_active_bandwidth_probing.rs` to pull the logged
    /// `achieved_mbps` value back out for a numeric assertion, not just
    /// confirm the log line fired at all.
    pub async fn find_line_containing(&self, needle: &str, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(line) = self
                .lines
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|l| l.contains(needle))
            {
                return Some(line.clone());
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

impl MlvpnProcess {
    /// Sends `SIGTERM` (via the `kill` command rather than a `nix`
    /// dependency this test harness doesn't otherwise need -- consistent
    /// with `run_ok`/`run_in_ns_ok` already shelling out for everything
    /// else here), the same signal `systemctl stop` sends. Used to
    /// exercise the graceful-shutdown path (`tunnel::run`'s local
    /// SIGINT/SIGTERM handling, `tests/veth_disconnect.rs`) rather than
    /// `Drop`'s `SIGKILL`, which bypasses it entirely.
    pub fn terminate(&self) -> io::Result<()> {
        let pid = self.child.id().to_string();
        let status = Command::new("kill").args(["-TERM", &pid]).status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "`kill -TERM {pid}` exited with {status}"
            )));
        }
        Ok(())
    }

    /// Polls (blocking, via `try_wait`) until the process has actually
    /// exited or `timeout` elapses. Used to confirm a signaled shutdown
    /// completed promptly rather than hanging -- a `tunnel::run` that
    /// got stuck (e.g. failing to abort every spawned task) would leave
    /// the process running indefinitely instead of returning.
    pub fn wait_for_exit(&mut self, timeout: Duration) -> io::Result<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "process did not exit within {timeout:?}"
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for MlvpnProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Connects to `socket_path` (retrying until it exists) and reads
/// newline-delimited `ipc::Snapshot` JSON lines until `predicate` matches
/// one or `timeout` elapses. On timeout, the error message includes the
/// last snapshot actually seen (if any) to make a failing assertion
/// debuggable without needing `--nocapture` on the daemon's own logs.
pub async fn poll_snapshot_until<F>(
    socket_path: &Path,
    timeout: Duration,
    mut predicate: F,
) -> Result<mlvpn::ipc::Snapshot, String>
where
    F: FnMut(&mlvpn::ipc::Snapshot) -> bool,
{
    use tokio::io::AsyncBufReadExt;

    let deadline = Instant::now() + timeout;
    let mut last_snapshot: Option<mlvpn::ipc::Snapshot> = None;

    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "predicate never matched within {timeout:?}; last snapshot seen: {last_snapshot:?}"
            ));
        }

        let connect = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::UnixStream::connect(socket_path),
        )
        .await;
        let Ok(Ok(stream)) = connect else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let mut reader = tokio::io::BufReader::new(stream);

        loop {
            if Instant::now() >= deadline {
                return Err(format!(
                    "predicate never matched within {timeout:?}; last snapshot seen: {last_snapshot:?}"
                ));
            }
            let mut line = String::new();
            let read =
                tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line)).await;
            match read {
                Ok(Ok(0)) => break, // peer closed the stream; reconnect
                Ok(Ok(_)) => {
                    if let Ok(snapshot) = serde_json::from_str::<mlvpn::ipc::Snapshot>(line.trim())
                    {
                        if predicate(&snapshot) {
                            return Ok(snapshot);
                        }
                        last_snapshot = Some(snapshot);
                    }
                }
                Ok(Err(_)) => break, // read error; reconnect
                Err(_) => {}         // this read timed out; loop back and check the outer deadline
            }
        }
    }
}

/// True if `link.state == "up"`, for the common case of waiting on one
/// specific named link.
pub fn link_is_up(snapshot: &mlvpn::ipc::Snapshot, link_name: &str) -> bool {
    snapshot
        .links
        .iter()
        .any(|l| l.name == link_name && l.state == "up")
}

pub fn link_state<'a>(snapshot: &'a mlvpn::ipc::Snapshot, link_name: &str) -> Option<&'a str> {
    snapshot
        .links
        .iter()
        .find(|l| l.name == link_name)
        .map(|l| l.state.as_str())
}

/// The scheduler's own SWRR weight for `link_name` right now (see
/// `ipc::LinkSnapshot::score`'s doc comment) -- used by
/// `veth_link_control.rs` to confirm `admin_disabled` forces this to 0
/// without touching the link's real, probe-measured `state`.
pub fn link_score(snapshot: &mlvpn::ipc::Snapshot, link_name: &str) -> Option<f64> {
    snapshot
        .links
        .iter()
        .find(|l| l.name == link_name)
        .map(|l| l.score)
}
