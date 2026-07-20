use clap::{Parser, Subcommand, ValueEnum};
use mlvpn::config::{self, Config};
use mlvpn::error::{MlvpnError, Result};
use mlvpn::firewall;
use mlvpn::ipc::{Command as SocketCommand, CommandResult};
use mlvpn::logbuf::{LogRing, LogRingLayer};
use mlvpn::{crypto, link, privilege, tunnel};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "mlvpnd", version, about = "Multi-link VPN bonding daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon using the given configuration file.
    Run {
        #[arg(short, long, default_value = "/etc/mlvpn/mlvpn.toml")]
        config: PathBuf,
    },
    /// Generate a new Curve25519 static keypair and print both halves as
    /// base64. Save the private half to a 0600 file referenced by
    /// `crypto.private_key_file` in the config, and share the public half
    /// with the peer for their `crypto.peer_public_key`.
    Genkey {
        /// Write the private key to this file (mode 0600) instead of
        /// printing it to stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Detect the active firewall backend (firewalld, ufw, nftables, or
    /// iptables) and open inbound UDP access for every [[links]] port in
    /// the given config. Always try --dry-run first: this inspects and
    /// modifies live firewall state, unlike every other subcommand here.
    FirewallSetup {
        #[arg(short, long, default_value = "/etc/mlvpn/mlvpn.toml")]
        config: PathBuf,
        /// Print the commands this would run without executing them.
        #[arg(long)]
        dry_run: bool,
        /// Close the ports instead of opening them.
        #[arg(long)]
        remove: bool,
        /// Skip auto-detection and use this backend instead: firewalld,
        /// ufw, nftables, or iptables.
        #[arg(long)]
        backend: Option<String>,
    },
    /// Pin a link enabled or disabled on a *running* mlvpnd, without
    /// editing the config and restarting. Talks to the command socket
    /// (`[command]` in the config -- must have `enabled = true` there
    /// first; off by default, see `mlvpn.toml.example`).
    SetLink {
        #[arg(short, long, default_value = "/etc/mlvpn/mlvpn.toml")]
        config: PathBuf,
        /// Link name, matching a [[links]] `name` in the config.
        link: String,
        /// Enable or disable the link for scheduling. A disabled link's
        /// real quality stats keep updating (visible via the control
        /// socket) -- it's just excluded from picking, same as if it
        /// were probe-Down, until re-enabled.
        #[arg(value_enum)]
        state: LinkEnableState,
    },
    /// Run an on-demand throughput self-test against a running mlvpnd's
    /// peer, without needing a separate tool like iperf3. Talks to the
    /// command socket, same as `set-link` (`[command] enabled = true`
    /// required first). Sends a real, MTU-sized packet stream for
    /// `--duration` seconds and reports the achieved rate; add
    /// `--bidirectional` to also measure the reverse direction
    /// (sequentially, so this roughly doubles the total time). By
    /// default this tests each configured link's own raw capacity
    /// directly, bypassing the TUN device/outbound queue/scheduler
    /// entirely -- pass `--tunnel --peer-addr <IP>` instead to test the
    /// real bonded tunnel (real UDP through the TUN device, the actual
    /// outbound queue, and the real scheduler splitting traffic across
    /// links), which can also help diagnose queue/buffer issues the
    /// per-link mode can't see.
    SelfTest {
        #[arg(short, long, default_value = "/etc/mlvpn/mlvpn.toml")]
        config: PathBuf,
        /// Test only this link (matching a [[links]] `name`). Omit to
        /// test every configured link with a currently-known peer
        /// address, one at a time. Ignored when `--tunnel` is set.
        #[arg(short, long)]
        link: Option<String>,
        /// How long to run each direction's stream, in seconds.
        #[arg(short, long, default_value_t = 10)]
        duration: u32,
        /// Also measure the reverse direction (the peer sends to us) --
        /// runs after the forward direction completes, not
        /// concurrently, so this roughly doubles the total time per
        /// link tested.
        #[arg(short, long)]
        bidirectional: bool,
        /// Test the real bonded tunnel (TUN device/outbound queue/
        /// scheduler) instead of one link's own raw capacity -- requires
        /// `--peer-addr`. See this command's own doc comment.
        #[arg(short, long)]
        tunnel: bool,
        /// The peer's tunnel-internal address (e.g. "10.200.0.2", not a
        /// link's WAN address) -- required, and only meaningful, when
        /// `--tunnel` is set.
        #[arg(short, long)]
        peer_addr: Option<String>,
    },
    /// Capture a diagnostic dump for a running mlvpnd: every link's
    /// health, daemon/session state, and recent log lines (via the
    /// command socket, same `[command] enabled = true` requirement as
    /// `set-link`/`self-test`), plus -- run from this CLI process
    /// directly, not the sandboxed daemon -- kernel-level UDP
    /// diagnostics (`nstat -az`, `ss -lu -n -a`, `/proc/net/udp`).
    /// Meant to be run the moment loss is observed (e.g. mid-`iperf3`
    /// test) and the resulting file attached to a bug report.
    DiagDump {
        #[arg(short, long, default_value = "/etc/mlvpn/mlvpn.toml")]
        config: PathBuf,
        /// Write the dump to this file instead of an auto-named one
        /// (`mlvpn-diag-<tunnel>-<unix-seconds>.txt`) in the current
        /// directory.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum LinkEnableState {
    Enable,
    Disable,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Genkey { out } => genkey(out),
        Command::Run { config } => {
            let cfg = Config::load(&config)?;
            let log_ring = init_logging(&cfg.logging.level);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run(cfg, log_ring))
        }
        Command::FirewallSetup {
            config,
            dry_run,
            remove,
            backend,
        } => {
            let cfg = Config::load(&config)?;
            let action = if remove {
                firewall::Action::Remove
            } else {
                firewall::Action::Add
            };
            firewall::run(&cfg, dry_run, action, backend.as_deref())?;
            Ok(())
        }
        Command::SetLink {
            config,
            link,
            state,
        } => set_link(&config, &link, matches!(state, LinkEnableState::Enable)),
        Command::SelfTest {
            config,
            link,
            duration,
            bidirectional,
            tunnel,
            peer_addr,
        } => {
            if tunnel {
                let Some(peer_addr) = peer_addr else {
                    anyhow::bail!("--tunnel requires --peer-addr <the peer's tunnel-internal IP>");
                };
                run_tunnel_throughput_selftest(&config, &peer_addr, duration, bidirectional)
            } else {
                run_throughput_selftest(&config, link, duration, bidirectional)
            }
        }
        Command::DiagDump { config, output } => run_diag_dump(&config, output),
    }
}

/// Connects to `config_path`'s command socket and sends `cmd`, returning
/// the daemon's `CommandResult` reply. Shared by `set_link` and
/// `run_throughput_selftest` -- plain blocking `std` I/O rather than
/// spinning up a tokio runtime for it, since this is a one-shot
/// request/reply over an already-local Unix socket, not something that
/// benefits from async (true even for `RunThroughputTest`, whose reply
/// can take many seconds: `read_line` below just blocks for however
/// long that takes, no different in kind from any other slow blocking
/// call this CLI could make).
fn send_command(config_path: &Path, cmd: &SocketCommand) -> anyhow::Result<CommandResult> {
    let cfg = Config::load(config_path)?;
    if !cfg.command.enabled {
        anyhow::bail!(
            "[command] is not enabled in {}; set `[command] enabled = true` in the config and \
             restart mlvpnd before this will work",
            config_path.display()
        );
    }
    let path = cfg
        .command
        .socket_path
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/mlvpn/{}.command.sock", cfg.tunnel.name)));

    let mut stream = UnixStream::connect(&path).map_err(|e| {
        anyhow::anyhow!(
            "connecting to command socket {}: {e} (is mlvpnd running with [command] enabled?)",
            path.display()
        )
    })?;

    let mut line = serde_json::to_vec(cmd)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    // Half-close our write side so the server's read loop sees EOF after
    // this one line instead of waiting on a second line that never
    // comes -- matches `serve_command_client`'s "read exactly one line"
    // contract.
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut reply = String::new();
    BufReader::new(&stream).read_line(&mut reply)?;
    Ok(serde_json::from_str(reply.trim_end())?)
}

/// Send a `SetLinkEnabled` command to a running daemon's command socket
/// and print the result.
fn set_link(config_path: &Path, link: &str, enabled: bool) -> anyhow::Result<()> {
    let cmd = SocketCommand::SetLinkEnabled {
        link: link.to_string(),
        enabled,
    };
    let result = send_command(config_path, &cmd)?;

    if result.ok {
        println!(
            "ok: link '{link}' {}",
            if enabled { "enabled" } else { "disabled" }
        );
        Ok(())
    } else {
        anyhow::bail!(
            "mlvpnd rejected the command: {}",
            result
                .error
                .unwrap_or_else(|| "(no error detail)".to_string())
        );
    }
}

/// Send a `RunThroughputTest` command to a running daemon's command
/// socket and print each tested link's result. See `send_command`'s
/// doc comment for why this stays plain blocking I/O even though the
/// reply can take many seconds to arrive.
fn run_throughput_selftest(
    config_path: &Path,
    link: Option<String>,
    duration_secs: u32,
    bidirectional: bool,
) -> anyhow::Result<()> {
    println!(
        "running throughput self-test ({duration_secs}s per direction{}) -- this will take a \
         while...",
        if bidirectional { ", bidirectional" } else { "" }
    );
    let cmd = SocketCommand::RunThroughputTest {
        link,
        duration_secs,
        bidirectional,
    };
    let result = send_command(config_path, &cmd)?;

    if !result.ok {
        anyhow::bail!(
            "mlvpnd rejected the command: {}",
            result
                .error
                .unwrap_or_else(|| "(no error detail)".to_string())
        );
    }
    if result.throughput_results.is_empty() {
        println!("no links were tested");
        return Ok(());
    }
    for r in &result.throughput_results {
        let upload = r
            .upload_mbps
            .map(|v| format!("{v:.1} Mbps"))
            .unwrap_or_else(|| "no result (timed out or peer doesn't support this)".to_string());
        if bidirectional {
            let download = r
                .download_mbps
                .map(|v| format!("{v:.1} Mbps"))
                .unwrap_or_else(|| {
                    "no result (timed out or peer doesn't support this)".to_string()
                });
            println!("{}: upload {upload}, download {download}", r.link);
        } else {
            println!("{}: upload {upload}", r.link);
        }
    }
    Ok(())
}

/// Send a `RunTunnelThroughputTest` command to a running daemon's
/// command socket and print the result -- see `tunneltest.rs`'s module
/// doc comment for what makes this different from
/// `run_throughput_selftest` above (real UDP through the TUN device,
/// outbound queue, and scheduler, not one link's own raw socket).
fn run_tunnel_throughput_selftest(
    config_path: &Path,
    peer_addr: &str,
    duration_secs: u32,
    bidirectional: bool,
) -> anyhow::Result<()> {
    println!(
        "running tunnel-level self-test against {peer_addr} ({duration_secs}s per direction{}) \
         -- this will take a while...",
        if bidirectional { ", bidirectional" } else { "" }
    );
    let cmd = SocketCommand::RunTunnelThroughputTest {
        peer_addr: peer_addr.to_string(),
        duration_secs,
        bidirectional,
    };
    let result = send_command(config_path, &cmd)?;

    if !result.ok {
        anyhow::bail!(
            "mlvpnd rejected the command: {}",
            result
                .error
                .unwrap_or_else(|| "(no error detail)".to_string())
        );
    }
    let Some(tt) = result.tunnel_test_result else {
        anyhow::bail!("mlvpnd accepted the command but returned no result");
    };

    let no_result = || "no result (timed out or peer doesn't support this)".to_string();
    let upload = tt
        .upload_mbps
        .map(|v| format!("{v:.1} Mbps"))
        .unwrap_or_else(no_result);
    println!("upload: {upload}");
    if tt.local_outbound_queue_dropped_delta > 0 {
        println!(
            "  our own outbound queue dropped {} packet(s) during this leg",
            tt.local_outbound_queue_dropped_delta
        );
    } else {
        println!("  our own outbound queue dropped 0 packets during this leg");
    }

    if bidirectional {
        let download = tt
            .download_mbps
            .map(|v| format!("{v:.1} Mbps"))
            .unwrap_or_else(no_result);
        println!("download: {download}");
        match tt.peer_outbound_queue_dropped_delta {
            Some(0) => println!("  peer's outbound queue dropped 0 packets during this leg"),
            Some(n) => println!("  peer's outbound queue dropped {n} packet(s) during this leg"),
            None => println!("  peer's outbound queue drop count unavailable (no result)"),
        }
    }
    Ok(())
}

/// Sends `Command::DiagDump` and writes the combined dump (the daemon's
/// own text, plus this CLI process's own kernel-level UDP diagnostics --
/// see `capture_kernel_udp_diagnostics`) to `output`, or an auto-named
/// file in the current directory when `output` is `None`.
fn run_diag_dump(config_path: &Path, output: Option<PathBuf>) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;
    let result = send_command(config_path, &SocketCommand::DiagDump)?;

    if !result.ok {
        anyhow::bail!(
            "mlvpnd rejected the command: {}",
            result
                .error
                .unwrap_or_else(|| "(no error detail)".to_string())
        );
    }
    let daemon_dump = result
        .diag_dump
        .unwrap_or_else(|| "(daemon returned no dump text)".to_string());
    let kernel_dump = capture_kernel_udp_diagnostics();

    let path = output.unwrap_or_else(|| {
        let unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        PathBuf::from(format!("mlvpn-diag-{}-{unix_secs}.txt", cfg.tunnel.name))
    });
    std::fs::write(&path, format!("{daemon_dump}\n{kernel_dump}"))?;
    println!("wrote diagnostic dump to {}", path.display());
    Ok(())
}

/// Captures kernel-level UDP diagnostics from *this* CLI process --
/// running as whatever account/privileges invoked `mlvpnd diag-dump`,
/// not the (systemd-sandboxed by default) daemon -- rather than having
/// the daemon shell out to external tools on its own. Mirrors the
/// specific commands recommended for chasing this project's own
/// still-open real-world loss investigation: `nstat -az` (filtered to
/// UDP-related lines, same reasoning as the `| grep -i udp` in that
/// recommendation, just done in Rust instead of depending on `grep`
/// being on `PATH` too), `ss -lu -n -a` (UDP socket receive-queue
/// depth), and `/proc/net/udp`'s own drops column. Every source degrades
/// gracefully (a missing binary or unreadable file becomes a note in
/// the output, not a hard failure) since this is best-effort diagnostic
/// context, not something the dump should fail over.
fn capture_kernel_udp_diagnostics() -> String {
    let mut out = String::new();
    out.push_str("--- Kernel UDP diagnostics (captured here, not by the daemon) ---\n\n");
    out.push_str(&run_and_capture_filtered("nstat", &["-az"], Some("udp")));
    out.push_str(&run_and_capture_filtered("ss", &["-lu", "-n", "-a"], None));
    out.push_str("$ /proc/net/udp\n");
    match std::fs::read_to_string("/proc/net/udp") {
        Ok(s) => out.push_str(&s),
        Err(e) => out.push_str(&format!("(could not read /proc/net/udp: {e})\n")),
    }
    out.push('\n');
    out
}

/// Runs `cmd args...` and captures stdout+stderr, optionally keeping
/// only lines whose lowercased form contains `needle` (plus the output's
/// first line, so column headers survive the filter too). `None` keeps
/// every line unfiltered.
fn run_and_capture_filtered(cmd: &str, args: &[&str], needle: Option<&str>) -> String {
    let mut out = format!("$ {cmd} {}\n", args.join(" "));
    match std::process::Command::new(cmd).args(args).output() {
        Ok(o) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            match needle {
                Some(needle) => {
                    for (i, line) in combined.lines().enumerate() {
                        if i == 0 || line.to_lowercase().contains(needle) {
                            out.push_str(line);
                            out.push('\n');
                        }
                    }
                }
                None => out.push_str(&combined),
            }
        }
        Err(e) => out.push_str(&format!(
            "(could not run {cmd}: {e} -- is it installed and on PATH?)\n"
        )),
    }
    out.push('\n');
    out
}

/// Builds the process-wide `tracing` subscriber as a `Registry` of two
/// composed layers rather than the single `tracing_subscriber::fmt()`
/// call this used to be: the existing fmt/journald output (`fmt_layer`,
/// filtered by the operator's own `[logging].level`/`RUST_LOG`), plus a
/// new `LogRingLayer` (`ring_layer`, independently filtered to INFO+
/// regardless of the operator's own filter -- see its doc comment) that
/// feeds the in-memory ring `mlvpn-tui`'s Logs tab streams from over the
/// control socket. Returns the `Arc<LogRing>` so the caller can thread
/// it into `tunnel::run`.
fn init_logging(level: &str) -> Arc<LogRing> {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    // `with_ansi(false)`: mlvpnd is a background daemon whose stdout/stderr
    // normally lands in journald or a log file, not an interactive
    // terminal -- `tracing_subscriber::fmt()`'s ANSI color coding defaults
    // to *on* unconditionally (it doesn't auto-detect a non-tty writer),
    // so without this every log line carries embedded color escape codes
    // that pollute journal/file output invisibly (a real terminal renders
    // them away, so this goes unnoticed until something reads the raw
    // bytes). Concretely surfaced by `tests/support/mod.rs`'s
    // `LogCapture`: it re-prints each captured line via `println!` (which
    // renders the escapes away again under `--nocapture`, so the test's
    // own terminal output looks completely normal), but stores the *raw*
    // string -- including the invisible escape sequences -- for
    // `wait_for_line_containing`/`find_line_containing` to search.
    // tracing_subscriber colors field keys/values distinctly from the
    // message text, so a needle spanning a `key=value` pair (as
    // `tests/veth_active_bandwidth_probing.rs`'s does) can straddle an
    // embedded escape sequence and silently never match, even though the
    // exact same text is plainly visible on screen. Existing log-based
    // tests happened to only search the plain message text and never hit
    // this.
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_filter(filter);

    let log_ring = Arc::new(LogRing::new());
    let ring_layer = LogRingLayer::new(log_ring.clone());

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(ring_layer)
        .init();

    log_ring
}

fn genkey(out: Option<PathBuf>) -> anyhow::Result<()> {
    let kp = crypto::StaticKeypair::generate()?;
    match out {
        Some(path) => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(kp.private_base64().as_bytes())?;
            println!("private key written to {}", path.display());
            println!("public key (share with peer): {}", kp.public_base64());
        }
        None => {
            println!("private key: {}", kp.private_base64());
            println!("public key:  {}", kp.public_base64());
            eprintln!(
                "\nwarning: private key printed to stdout; prefer --out to write it \
                 straight to a 0600 file instead of letting it touch your shell history \
                 or terminal scrollback."
            );
        }
    }
    Ok(())
}

async fn run(cfg: Config, log_ring: Arc<LogRing>) -> anyhow::Result<()> {
    tracing::info!(mode = ?cfg.mode, tunnel = %cfg.tunnel.name, "starting mlvpnd");

    // --- Privileged setup phase -------------------------------------
    // Links are bound *before* the TUN device is created (deliberately
    // reversed from the more obvious ordering) so we can query each
    // bind_interface's real kernel MTU first and pick a safe effective
    // tunnel MTU -- see effective_tunnel_mtu() below -- before the TUN
    // device is ever built with a fixed value. Both still happen before
    // privileges are dropped, since both need CAP_NET_RAW/root-level
    // access on the systems that require it.
    let mut links = Vec::with_capacity(cfg.links.len());
    for (i, link_cfg) in cfg.links.iter().enumerate() {
        let id =
            u8::try_from(i).map_err(|_| MlvpnError::Config("too many links (max 255)".into()))?;
        let link = link::Link::bind(id, link_cfg.clone(), cfg.scheduler.ewma_alpha).await?;
        tracing::info!(
            link = %link_cfg.name,
            interface = %link_cfg.bind_interface,
            port = link_cfg.local_port,
            physical_mtu = ?link.physical_mtu,
            "link bound"
        );
        links.push(link);
    }

    let effective_mtu = effective_tunnel_mtu(&cfg.tunnel, &links);
    let tun = open_tun(&cfg.tunnel, effective_mtu)?;

    let local_private = crypto::StaticKeypair::load_private(&cfg.crypto.private_key_file)?;
    let peer_public = crypto::decode_public_key(&cfg.crypto.peer_public_key)?;

    // --- Drop privileges before touching the network further ---------
    privilege::drop_privileges(&privilege::DropTarget::default())?;
    privilege::assert_unprivileged()?;

    // The control socket exposes live link/traffic stats to `mlvpn-tui`
    // (and anything else that wants to read newline-delimited JSON off a
    // Unix socket -- see `control.rs`). `None` disables it entirely.
    let control_socket = if cfg.control.enabled {
        Some(
            cfg.control
                .socket_path
                .clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(format!("/run/mlvpn/{}.sock", cfg.tunnel.name))),
        )
    } else {
        None
    };

    // Off by default -- see `config::CommandConfig::enabled`'s doc
    // comment for why this one doesn't default on the way
    // `control_socket` above does. Default path deliberately uses a
    // different filename (`.command.sock` vs `.sock`) so the two are
    // never confusable at a glance even though they share a directory.
    let command_socket = if cfg.command.enabled {
        Some(
            cfg.command
                .socket_path
                .clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(format!("/run/mlvpn/{}.command.sock", cfg.tunnel.name))
                }),
        )
    } else {
        None
    };

    // Off by default -- see `config::DiagnosticsConfig::auto_dump_enabled`'s
    // doc comment. `dump_dir` defaults to `/var/log/mlvpn`, matching
    // where most other services on the system log to (and already
    // writable under the shipped systemd unit's `LogsDirectory=mlvpn`
    // -- unlike `/run/mlvpn`, this persists across restarts/reboots,
    // which matters for evidence of a loss event caught automatically).
    let diagnostics_watch = if cfg.diagnostics.auto_dump_enabled {
        Some(tunnel::DiagnosticsWatchParams {
            loss_threshold_pct: cfg.diagnostics.loss_threshold_pct,
            cooldown: std::time::Duration::from_secs(cfg.diagnostics.cooldown_secs),
            dump_dir: cfg
                .diagnostics
                .dump_dir
                .clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/log/mlvpn")),
        })
    } else {
        None
    };

    // Same string `open_tun` above already parsed to build the TUN
    // device itself -- see `TunnelParams::tunnel_local_addr`'s doc
    // comment for why the tunnel-level self-test listener needs it.
    let (tunnel_local_addr_str, _) = parse_cidr(&cfg.tunnel.address)?;
    let tunnel_local_addr: std::net::IpAddr = tunnel_local_addr_str.parse().map_err(|e| {
        MlvpnError::Config(format!(
            "tunnel.address '{}' has an unparseable address: {e}",
            cfg.tunnel.address
        ))
    })?;

    let params = tunnel::TunnelParams {
        mode: cfg.mode,
        mtu: effective_mtu,
        clamp_mss: cfg.tunnel.clamp_mss,
        scheduler_cfg: cfg.scheduler.clone(),
        local_private,
        peer_public,
        rekey_interval: std::time::Duration::from_secs(cfg.crypto.rekey_interval_secs),
        tunnel_name: cfg.tunnel.name.clone(),
        control_socket,
        command_socket,
        diagnostics_watch,
        tunnel_local_addr,
    };

    // `tunnel::run` races SIGINT/SIGTERM against the tunnel's own tasks
    // internally (rather than this caller racing a bare `ctrl_c()`
    // against it from outside), specifically so it can send a
    // best-effort `Disconnect` frame to the peer before exiting -- that
    // needs access to the live links/session, which only exists inside
    // `tunnel::run` itself. See `tunnel.rs`'s `Shutdown` doc comment.
    tunnel::run(tun, links, params, log_ring)
        .await
        .map_err(anyhow::Error::from)
}

/// Picks the MTU actually used for the TUN device and outgoing packet
/// sizing: the smaller of the configured `tunnel.mtu` and a safe value
/// derived from every bonded link's real physical interface MTU (see
/// `link::Link::physical_mtu`, populated via `SIOCGIFMTU` at bind time).
/// This turns the previously advisory-only startup warning (still in
/// `config.rs`'s `validate()`, checked against a generic 1500-byte
/// assumption before any link exists to ask) into a real, self-correcting
/// default: a configured `tunnel.mtu` that would actually fragment
/// against this deployment's hardware gets clamped down automatically
/// instead of just logging a warning and fragmenting anyway. Links
/// whose physical MTU couldn't be determined (non-Linux, insufficient
/// permissions, a transient ioctl failure) simply don't participate in
/// the minimum -- if *no* link's MTU is known, this falls back to
/// trusting the configured value outright rather than refusing to
/// start.
///
/// `outer_overhead` deliberately assumes the *larger* of the two
/// possible outer-transport combinations (IPv6/UDP, 48 bytes) rather
/// than IPv4/UDP (28 bytes): which one a given link actually dials over
/// depends on `remote_addr`'s address family per-link, and this
/// function has no per-link visibility into that -- one tunnel-wide MTU
/// is picked for all of them. Assuming the larger overhead errs toward
/// "possibly slightly conservative" rather than "possibly still
/// fragments on an IPv6 link," which is the correct direction to be
/// wrong in given the user asked for this to auto-adjust for
/// *throughput*, not just raw MTU size: a black-holed PMTUD stall costs
/// far more throughput than a few bytes of headroom ever would.
fn effective_tunnel_mtu(cfg: &config::TunnelConfig, links: &[link::Link]) -> u16 {
    let outer_overhead = mlvpn::protocol::HEADER_LEN as u32 + mlvpn::crypto::TAG_LEN as u32 + 48;

    let Some(detected_min) = links.iter().filter_map(|l| l.physical_mtu).min() else {
        return cfg.mtu;
    };

    let safe_mtu = detected_min
        .saturating_sub(outer_overhead)
        .min(u16::MAX as u32) as u16;

    if cfg.mtu > safe_mtu {
        // Never clamp below the config-time floor already enforced in
        // config.rs's validate() (>= 576, the IPv6 minimum-MTU
        // guarantee) -- an unusually small detected physical MTU should
        // surface as a visible problem, not silently produce a tunnel
        // MTU so small it can't carry a minimum-size IPv6 packet at
        // all.
        let clamped = safe_mtu.max(576);
        tracing::warn!(
            configured = cfg.mtu,
            detected_min_physical_mtu = detected_min,
            clamped_to = clamped,
            "tunnel.mtu exceeds what the bonded links' physical interfaces can carry \
             without fragmentation; auto-clamping down for this run (edit tunnel.mtu \
             in the config to make this permanent and silence this warning)"
        );
        clamped
    } else {
        cfg.mtu
    }
}

fn open_tun(cfg: &config::TunnelConfig, mtu: u16) -> Result<tun_rs::AsyncDevice> {
    let (addr, prefix) = parse_cidr(&cfg.address)?;
    let mut builder = tun_rs::DeviceBuilder::new()
        .name(cfg.name.as_str())
        .ipv4(addr.as_str(), prefix, None)
        .mtu(mtu);

    if let Some(address6) = &cfg.address6 {
        let (addr6, prefix6) = parse_cidr(address6)?;
        builder = builder.ipv6(addr6.as_str(), prefix6);
    }

    let dev = builder
        .build_async()
        .map_err(|e| MlvpnError::Tun(format!("creating device '{}': {e}", cfg.name)))?;
    tracing::info!(
        name = %cfg.name,
        address = %cfg.address,
        address6 = ?cfg.address6,
        mtu,
        "tun device created"
    );
    Ok(dev)
}

fn parse_cidr(s: &str) -> Result<(String, u8)> {
    let (addr, prefix) = s.split_once('/').ok_or_else(|| {
        MlvpnError::Config(format!(
            "tunnel.address '{s}' must be in CIDR form, e.g. 10.0.0.1/30"
        ))
    })?;
    let prefix: u8 = prefix.parse().map_err(|_| {
        MlvpnError::Config(format!("invalid prefix length in tunnel.address '{s}'"))
    })?;
    Ok((addr.to_string(), prefix))
}
