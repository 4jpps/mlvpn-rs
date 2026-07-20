//! Local monitoring control socket.
//!
//! `mlvpnd` listens on a Unix domain socket (path from `[control]` in the
//! config; default `/run/mlvpn/<tunnel.name>.sock`) and streams one
//! newline-delimited JSON `ipc::Snapshot` roughly twice a second to every
//! connected client for as long as that client stays connected.
//! `mlvpn-tui` is the reference client (`src/bin/mlvpn-tui.rs`), but the
//! format is plain enough to consume with `socat -u UNIX-CONNECT:<path> -
//! | jq` for ad-hoc debugging.
//!
//! Security: this socket exposes live topology (bind interfaces, learned
//! peer IP:port per link) and traffic statistics -- never key material,
//! and there is no write/command side, so a reader can only observe, never
//! redirect traffic or exfiltrate secrets. Even so, the socket file is
//! created mode 0600 so only the daemon's own runtime user (or root) can
//! connect; anyone who can already read it can already read `/proc` for
//! the same process, so this isn't adding new exposure, just convenience.
//!
//! **Command socket.** `serve_commands` (below) is a second, separate
//! Unix socket -- different path, off by default (`[command].enabled`)
//! -- for runtime link control (currently: pin a link enabled/disabled,
//! see `ipc::Command`). Kept as its own socket rather than a write mode
//! bolted onto the one above specifically so a client authorized only to
//! *read* the monitoring socket (e.g. a `mlvpn-tui` running under a
//! monitoring-only account) never incidentally gains the ability to
//! redirect live traffic. Same 0600-via-umask creation as `serve`: mode
//! 0600 is a real boundary here, not security-by-obscurity -- the kernel
//! checks it (effectively `SO_PEERCRED`-equivalent: only the owning
//! uid/root can `connect()` at all) before a client ever gets a byte in
//! or out, the same guarantee any other 0600 Unix socket or file
//! provides.

use crate::crypto::{random_session_id, SessionState};
use crate::diag;
use crate::ipc::{
    Command, CommandResult, DaemonSnapshot, LinkSnapshot, Snapshot, SystemSnapshot,
    ThroughputTestLinkResult, TunSnapshot, TunnelTestCommandResult,
};
use crate::link::{self, LinkState, Links};
use crate::logbuf::LogRing;
use crate::peerstats::PeerStatsTable;
use crate::procstats;
use crate::sysfs_net;
use crate::tunnel::{
    send_throughput_test_reverse_request, send_throughput_test_stream, DiagnosticsWatchParams,
    OutboundFrame, PeerVersion, SessionMeta, ThroughputTestContext,
};
use crate::tunneltest;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio::time::interval;

const SNAPSHOT_INTERVAL_MS: u64 = 500;

/// Bind the control socket and serve snapshots to whoever connects until
/// the process exits. Any setup failure (can't create the runtime
/// directory, can't bind, path already in use by something else) is
/// logged and treated as "monitoring unavailable" rather than a fatal
/// daemon error -- a stats socket is a convenience feature, not something
/// that should be able to take the tunnel down.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    path: PathBuf,
    links: Links,
    peer_stats: Arc<PeerStatsTable>,
    tunnel_name: String,
    mode: String,
    session_meta: Arc<SessionMeta>,
    outbound_tx: mpsc::Sender<OutboundFrame>,
    outbound_dropped_total: Arc<AtomicU64>,
    log_ring: Arc<LogRing>,
    peer_version: PeerVersion,
) {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                error = %e,
                path = %parent.display(),
                "failed to create control socket directory; mlvpn-tui will be unavailable"
            );
            return;
        }
        // Defense in depth for manual/non-systemd runs, where this
        // directory doesn't already exist with a restrictive mode via
        // `RuntimeDirectory=` (see systemd/mlvpn.service). Harmless
        // no-op when it does.
        if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750)) {
            tracing::debug!(
                error = %e,
                path = %parent.display(),
                "could not set control socket directory permissions (likely already correct)"
            );
        }
    }

    // A stale socket file left behind by an unclean previous shutdown
    // would otherwise make bind() fail with AddrInUse even though nothing
    // is actually listening on it anymore.
    let _ = std::fs::remove_file(&path);

    // Create the socket file with a restrictive mode *atomically* at
    // creation time by tightening the process umask around just this
    // call, rather than binding first and `chmod`-ing after. The latter
    // leaves a real (if brief) window where the socket exists at
    // whatever the ambient umask allows -- group/world-connectable
    // unless the umask already happens to be restrictive. The shipped
    // systemd unit sets `UMask=0077` so that window wouldn't matter
    // there, but `control::serve` is also reachable from a manual,
    // non-systemd run where nothing else guarantees that.
    let listener = {
        // SAFETY: `umask(2)` is an unconditional syscall with no
        // preconditions beyond "no other thread relies on the umask
        // being unchanged for the duration" -- there is no such
        // concurrent dependency here, and we restore the prior value
        // immediately after `bind()` returns.
        let previous_umask = unsafe { libc::umask(0o177) };
        let result = UnixListener::bind(&path);
        unsafe {
            libc::umask(previous_umask);
        }
        match result {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "failed to bind control socket; mlvpn-tui will be unavailable"
                );
                return;
            }
        }
    };

    // Belt and suspenders: explicitly (re-)assert 0600 even though the
    // umask above should already have produced exactly that, in case
    // some platform/backend doesn't fully honor umask for AF_UNIX socket
    // creation.
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(error = %e, "failed to restrict control socket permissions to 0600");
    }

    tracing::info!(path = %path.display(), "control socket listening (for mlvpn-tui)");

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "control socket accept failed");
                continue;
            }
        };
        let links = links.clone();
        let peer_stats = peer_stats.clone();
        let tunnel_name = tunnel_name.clone();
        let mode = mode.clone();
        let session_meta = session_meta.clone();
        let outbound_tx = outbound_tx.clone();
        let outbound_dropped_total = outbound_dropped_total.clone();
        let log_ring = log_ring.clone();
        let peer_version = peer_version.clone();
        tokio::spawn(async move {
            serve_client(
                stream,
                links,
                peer_stats,
                tunnel_name,
                mode,
                session_meta,
                outbound_tx,
                outbound_dropped_total,
                log_ring,
                peer_version,
            )
            .await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_client(
    mut stream: UnixStream,
    links: Links,
    peer_stats: Arc<PeerStatsTable>,
    tunnel_name: String,
    mode: String,
    session_meta: Arc<SessionMeta>,
    outbound_tx: mpsc::Sender<OutboundFrame>,
    outbound_dropped_total: Arc<AtomicU64>,
    log_ring: Arc<LogRing>,
    peer_version: PeerVersion,
) {
    let mut tick = interval(Duration::from_millis(SNAPSHOT_INTERVAL_MS));
    // Per-connection cursor into `log_ring` -- each connected client
    // gets its own independent view of "what have I already sent",
    // starting at 0 (see `LogRing::new`'s doc comment for why real
    // `seq`s start at 1, making 0 mean "nothing sent yet" rather than
    // needing an `Option<u64>` here).
    let mut last_log_seq = 0u64;
    loop {
        tick.tick().await;
        let (snapshot, new_last_log_seq) = build_snapshot(
            &links,
            &peer_stats,
            &tunnel_name,
            &mode,
            &session_meta,
            &outbound_tx,
            &outbound_dropped_total,
            &log_ring,
            last_log_seq,
            &peer_version,
        )
        .await;
        last_log_seq = new_last_log_seq;
        let Ok(mut line) = serde_json::to_vec(&snapshot) else {
            continue;
        };
        line.push(b'\n');
        if stream.write_all(&line).await.is_err() {
            return; // client disconnected
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn build_snapshot(
    links: &Links,
    peer_stats: &Arc<PeerStatsTable>,
    tunnel_name: &str,
    mode: &str,
    session_meta: &SessionMeta,
    outbound_tx: &mpsc::Sender<OutboundFrame>,
    outbound_dropped_total: &AtomicU64,
    log_ring: &LogRing,
    last_log_seq: u64,
    peer_version: &PeerVersion,
) -> (Snapshot, u64) {
    let snap = link::snapshot_links(links).await;
    let link_snapshots = snap
        .iter()
        .enumerate()
        .map(|(idx, link)| {
            let peer = peer_stats.get(idx as u8);
            LinkSnapshot {
                name: link.config.name.clone(),
                bind_interface: link.config.bind_interface.clone(),
                local_port: link.config.local_port,
                remote_addr: link.remote.map(|a| a.to_string()),
                state: link.state.as_str().to_string(),
                score: crate::monitor::score(link),
                state_duration_ms: link.state_since.elapsed().as_millis() as u64,
                tx_bytes: link.stats.tx_bytes,
                rx_bytes: link.stats.rx_bytes,
                tx_packets: link.stats.tx_packets,
                rx_packets: link.stats.rx_packets,
                local_rtt_ms: link.stats.rtt_ms.get(),
                local_jitter_ms: link.stats.jitter_ms.get(),
                local_loss_pct: link.stats.loss_rate.get().map(|v| v * 100.0),
                local_rx_throughput_mbps: link.stats.rx_throughput_mbps.get(),
                local_tx_throughput_mbps: link.stats.tx_throughput_mbps.get(),
                local_active_bandwidth_mbps: link.stats.active_bandwidth_mbps.get(),
                local_consecutive_hits: link.stats.consecutive_hits,
                local_consecutive_misses: link.stats.consecutive_misses,
                peer_name: peer.as_ref().map(|p| p.name.clone()),
                peer_state: peer
                    .as_ref()
                    .map(|p| LinkState::from_wire(p.state).as_str().to_string()),
                peer_rtt_ms: peer.as_ref().map(|p| p.rtt_ms),
                peer_jitter_ms: peer.as_ref().map(|p| p.jitter_ms),
                peer_loss_pct: peer.as_ref().map(|p| p.loss_pct),
                peer_throughput_mbps: peer.as_ref().map(|p| p.throughput_mbps),
                peer_stats_age_ms: peer
                    .as_ref()
                    .map(|p| p.received_at.elapsed().as_millis() as u64),
            }
        })
        .collect();

    let (session_id, rekey_count, session_uptime_ms) = session_meta.snapshot();

    // `max_capacity` is fixed (OUTBOUND_QUEUE_CAPACITY) for the channel's
    // whole lifetime; `capacity` is the number of currently-free slots,
    // so `max_capacity - capacity` is the current queue depth. Reading
    // both off a cloned `Sender` never contends with `tun_reader`'s
    // `try_send` -- these are lock-free atomic loads internal to the
    // channel, not a new lock on the hot path.
    let outbound_queue_capacity = outbound_tx.max_capacity();
    let outbound_queue_len = outbound_queue_capacity - outbound_tx.capacity();

    // `tunnel_name` is the same string the TUN device itself was
    // created with (see `main.rs::open_tun`), so no separate iface
    // field needs threading through just for this sysfs lookup.
    let tun_stats = sysfs_net::read_tun_stats(tunnel_name);
    let system_stats = procstats::read_system_stats();

    let new_log_lines = log_ring.entries_since(last_log_seq);
    let new_last_log_seq = new_log_lines.last().map(|e| e.seq).unwrap_or(last_log_seq);

    let snapshot = Snapshot {
        tunnel_name: tunnel_name.to_string(),
        mode: mode.to_string(),
        unix_ts_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        links: link_snapshots,
        daemon: DaemonSnapshot {
            session_id,
            session_uptime_ms,
            rekey_count,
            outbound_queue_len: outbound_queue_len as u64,
            outbound_queue_capacity: outbound_queue_capacity as u64,
            outbound_queue_dropped_total: outbound_dropped_total.load(Ordering::Relaxed),
            tun: TunSnapshot {
                iface: tunnel_name.to_string(),
                rx_bytes: tun_stats.rx_bytes,
                tx_bytes: tun_stats.tx_bytes,
                rx_errors: tun_stats.rx_errors,
                tx_errors: tun_stats.tx_errors,
                rx_dropped: tun_stats.rx_dropped,
                tx_dropped: tun_stats.tx_dropped,
            },
            system: SystemSnapshot {
                load1: system_stats.load1,
                load5: system_stats.load5,
                load15: system_stats.load15,
                mem_total_kb: system_stats.mem_total_kb,
                mem_available_kb: system_stats.mem_available_kb,
                uptime_secs: system_stats.uptime_secs,
            },
            local_version: crate::VERSION.to_string(),
            peer_version: peer_version.lock().unwrap().clone(),
        },
        new_log_lines,
    };

    (snapshot, new_last_log_seq)
}

/// Bundles the pieces `apply_command`'s `Command::DiagDump` handler
/// needs to build a fresh `ipc::Snapshot` on demand -- the same data
/// `build_snapshot` already assembles for the read-only monitoring
/// socket. Grouped into one struct (rather than adding another five
/// positional parameters to `serve_commands`/`serve_command_client`/
/// `apply_command`, on top of the throughput-test ones already there)
/// specifically because none of it is otherwise needed by the command
/// socket's other, link/session-only commands -- `SetLinkEnabled` and
/// `RunThroughputTest` never touch this.
#[derive(Clone)]
pub(crate) struct DiagContext {
    pub(crate) peer_stats: Arc<PeerStatsTable>,
    pub(crate) tunnel_name: String,
    pub(crate) mode: String,
    pub(crate) session_meta: Arc<SessionMeta>,
    pub(crate) outbound_tx: mpsc::Sender<OutboundFrame>,
    pub(crate) outbound_dropped_total: Arc<AtomicU64>,
    pub(crate) log_ring: Arc<LogRing>,
    pub(crate) peer_version: PeerVersion,
}

/// Bind the command socket and serve `ipc::Command` requests until the
/// process exits. Setup (directory creation, umask-tightened bind,
/// belt-and-suspenders 0600 re-assertion) exactly mirrors `serve` above
/// -- see its comments for why each step exists. The protocol differs:
/// this is request/reply rather than a streaming push, so each
/// connection is expected to send exactly one JSON `Command` line and
/// gets exactly one JSON `CommandResult` line back before the
/// connection closes. As with `serve`, any setup failure is logged and
/// treated as "runtime link control unavailable" rather than a fatal
/// daemon error -- this is an operator convenience, not something that
/// should be able to take the tunnel down.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_commands(
    path: PathBuf,
    links: Links,
    session: Arc<AsyncMutex<SessionState>>,
    throughput_test_ctx: Arc<ThroughputTestContext>,
    tunnel_test_ctx: Arc<tunneltest::TunnelTestContext>,
    mtu: usize,
    diag_ctx: DiagContext,
) {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                error = %e,
                path = %parent.display(),
                "failed to create command socket directory; runtime link control will be unavailable"
            );
            return;
        }
        if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750)) {
            tracing::debug!(
                error = %e,
                path = %parent.display(),
                "could not set command socket directory permissions (likely already correct)"
            );
        }
    }

    let _ = std::fs::remove_file(&path);

    let listener = {
        // SAFETY: same reasoning as the umask block in `serve` above.
        let previous_umask = unsafe { libc::umask(0o177) };
        let result = UnixListener::bind(&path);
        unsafe {
            libc::umask(previous_umask);
        }
        match result {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "failed to bind command socket; runtime link control will be unavailable"
                );
                return;
            }
        }
    };

    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(error = %e, "failed to restrict command socket permissions to 0600");
    }

    tracing::info!(path = %path.display(), "command socket listening (runtime link control)");

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "command socket accept failed");
                continue;
            }
        };
        let links = links.clone();
        let session = session.clone();
        let throughput_test_ctx = throughput_test_ctx.clone();
        let tunnel_test_ctx = tunnel_test_ctx.clone();
        let diag_ctx = diag_ctx.clone();
        tokio::spawn(async move {
            serve_command_client(
                stream,
                links,
                session,
                throughput_test_ctx,
                tunnel_test_ctx,
                mtu,
                diag_ctx,
            )
            .await;
        });
    }
}

/// Handle one command-socket connection: read exactly one JSON line,
/// apply it, write exactly one JSON `CommandResult` line back. Silently
/// returns (rather than logging) on a client that connects and
/// disconnects without sending anything, or one that disappears before
/// the reply is written -- a raced/impatient client is not a server-side
/// problem worth a warning.
#[allow(clippy::too_many_arguments)]
async fn serve_command_client(
    stream: UnixStream,
    links: Links,
    session: Arc<AsyncMutex<SessionState>>,
    throughput_test_ctx: Arc<ThroughputTestContext>,
    tunnel_test_ctx: Arc<tunneltest::TunnelTestContext>,
    mtu: usize,
    diag_ctx: DiagContext,
) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    let line = match lines.next_line().await {
        Ok(Some(l)) => l,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, "command socket read failed");
            return;
        }
    };

    let result = match serde_json::from_str::<Command>(&line) {
        Ok(cmd) => {
            apply_command(
                cmd,
                &links,
                &session,
                &throughput_test_ctx,
                &tunnel_test_ctx,
                mtu,
                &diag_ctx,
            )
            .await
        }
        Err(e) => CommandResult {
            ok: false,
            error: Some(format!("invalid command: {e}")),
            throughput_results: Vec::new(),
            diag_dump: None,
            tunnel_test_result: None,
            peer_version: diag_ctx.peer_version.lock().unwrap().clone(),
        },
    };

    let Ok(mut out) = serde_json::to_vec(&result) else {
        return;
    };
    out.push(b'\n');
    let _ = writer.write_all(&out).await;
}

/// Apply one already-parsed `Command` and report the outcome. Split out
/// from `serve_command_client` so the actual link-mutation logic is
/// testable/readable independent of the socket I/O around it.
#[allow(clippy::too_many_arguments)]
async fn apply_command(
    cmd: Command,
    links: &Links,
    session: &Arc<AsyncMutex<SessionState>>,
    throughput_test_ctx: &Arc<ThroughputTestContext>,
    tunnel_test_ctx: &Arc<tunneltest::TunnelTestContext>,
    mtu: usize,
    diag_ctx: &DiagContext,
) -> CommandResult {
    match cmd {
        Command::SetLinkEnabled { link, enabled } => {
            // Each link's name lives inside its own per-link mutex now
            // (see `Links`' doc comment), so finding one by name means
            // locking candidates one at a time rather than a single
            // `iter_mut().find(...)` over a whole-vec guard -- fine here,
            // this is the rarely-used command socket, not the packet hot
            // path, and each lock is held only long enough to check one
            // link's name (or, on a match, flip `admin_disabled`).
            let mut found = false;
            for l in links.iter() {
                let mut guard = l.lock().await;
                if guard.config.name == link {
                    guard.admin_disabled = !enabled;
                    found = true;
                    break;
                }
            }
            if found {
                tracing::info!(
                    link = %link,
                    enabled,
                    "link admin_disabled set via command socket"
                );
                CommandResult {
                    ok: true,
                    error: None,
                    throughput_results: Vec::new(),
                    diag_dump: None,
                    tunnel_test_result: None,
                    peer_version: diag_ctx.peer_version.lock().unwrap().clone(),
                }
            } else {
                CommandResult {
                    ok: false,
                    error: Some(format!("no such link '{link}'")),
                    throughput_results: Vec::new(),
                    diag_dump: None,
                    tunnel_test_result: None,
                    peer_version: diag_ctx.peer_version.lock().unwrap().clone(),
                }
            }
        }
        Command::RunThroughputTest {
            link,
            duration_secs,
            bidirectional,
        } => {
            run_throughput_test_command(
                links,
                session,
                throughput_test_ctx,
                mtu,
                link,
                duration_secs,
                bidirectional,
                &diag_ctx.peer_version,
            )
            .await
        }
        Command::DiagDump => run_diag_dump_command(links, diag_ctx).await,
        Command::RunTunnelThroughputTest {
            peer_addr,
            duration_secs,
            bidirectional,
        } => {
            run_tunnel_throughput_test_command(
                &peer_addr,
                duration_secs,
                bidirectional,
                mtu,
                &diag_ctx.outbound_dropped_total,
                tunnel_test_ctx,
                &diag_ctx.peer_version,
            )
            .await
        }
    }
}

/// Implements `Command::RunTunnelThroughputTest`: parses `peer_addr`
/// (the peer's tunnel-internal address, e.g. `"10.200.0.2"`) and hands
/// off to `tunneltest::run_test` -- see that module's doc comment for
/// why this is a genuinely different mechanism from
/// `run_throughput_test_command` above (real UDP through the TUN
/// device/outbound queue/scheduler, not a link's own raw socket).
async fn run_tunnel_throughput_test_command(
    peer_addr: &str,
    duration_secs: u32,
    bidirectional: bool,
    mtu: usize,
    outbound_dropped_total: &Arc<AtomicU64>,
    tunnel_test_ctx: &Arc<tunneltest::TunnelTestContext>,
    peer_version: &PeerVersion,
) -> CommandResult {
    let peer_addr = match peer_addr.parse::<std::net::IpAddr>() {
        Ok(addr) => addr,
        Err(e) => {
            return CommandResult {
                ok: false,
                error: Some(format!("invalid peer_addr '{peer_addr}': {e}")),
                throughput_results: Vec::new(),
                diag_dump: None,
                tunnel_test_result: None,
                peer_version: peer_version.lock().unwrap().clone(),
            };
        }
    };

    let outcome = tunneltest::run_test(
        peer_addr,
        duration_secs,
        bidirectional,
        mtu,
        outbound_dropped_total,
        tunnel_test_ctx,
    )
    .await;

    tracing::info!(
        %peer_addr,
        upload_mbps = ?outcome.upload_mbps,
        download_mbps = ?outcome.download_mbps,
        local_queue_drops = outcome.local_queue_drops,
        peer_queue_drops = ?outcome.peer_queue_drops,
        "tunnel-level throughput self-test complete"
    );

    CommandResult {
        ok: true,
        error: None,
        throughput_results: Vec::new(),
        diag_dump: None,
        tunnel_test_result: Some(TunnelTestCommandResult {
            upload_mbps: outcome.upload_mbps,
            download_mbps: outcome.download_mbps,
            local_outbound_queue_dropped_delta: outcome.local_queue_drops,
            peer_outbound_queue_dropped_delta: outcome.peer_queue_drops,
        }),
        // Read *after* the test, not before: if the peer's own
        // `VersionInfo` broadcast happens to land during the test
        // (same session, independent timer), this reports the freshest
        // value available rather than a slightly-stale one -- doesn't
        // matter in practice (the version isn't expected to change
        // mid-test), but there's no reason to prefer the stale read.
        peer_version: peer_version.lock().unwrap().clone(),
    }
}

/// Implements `Command::DiagDump`: builds a fresh `ipc::Snapshot` (same
/// assembly `build_snapshot` does for the monitoring socket) with the
/// log cursor forced to `0` so the dump's log section carries everything
/// currently in `LogRing`, not just a recent delta, then renders it via
/// `diag::format_dump`. Always succeeds (there is no failure mode here
/// short of a bug -- unlike `RunThroughputTest`, nothing here waits on
/// the peer or can time out).
async fn run_diag_dump_command(links: &Links, diag_ctx: &DiagContext) -> CommandResult {
    let (snapshot, _) = build_snapshot(
        links,
        &diag_ctx.peer_stats,
        &diag_ctx.tunnel_name,
        &diag_ctx.mode,
        &diag_ctx.session_meta,
        &diag_ctx.outbound_tx,
        &diag_ctx.outbound_dropped_total,
        &diag_ctx.log_ring,
        0,
        &diag_ctx.peer_version,
    )
    .await;
    let text = diag::format_dump(&snapshot, "manual (mlvpnd diag-dump)");
    tracing::info!("diagnostic dump captured via command socket");
    CommandResult {
        ok: true,
        error: None,
        throughput_results: Vec::new(),
        diag_dump: Some(text),
        tunnel_test_result: None,
        peer_version: diag_ctx.peer_version.lock().unwrap().clone(),
    }
}

/// How often `diagnostics_watch_loop` re-checks every link's loss
/// against `DiagnosticsWatchParams::loss_threshold_pct`. Frequent enough
/// to catch a loss event not long after it starts (loss itself is a
/// windowed EWMA already smoothed over multiple probes, so there is no
/// benefit to checking faster than that smoothing resolves), infrequent
/// enough to be negligible overhead on top of the periodic
/// `procstats`/`sysfs_net` reads `build_snapshot` already does for every
/// connected monitoring client.
const DIAGNOSTICS_WATCH_INTERVAL_SECS: u64 = 5;

/// Watches every link's own locally-measured loss (`LinkSnapshot::local_loss_pct`,
/// the same figure `mlvpn-tui`'s Links tab shows) and writes a text
/// diagnostic dump to `watch.dump_dir` the moment one crosses
/// `watch.loss_threshold_pct` -- the automatic counterpart to
/// `Command::DiagDump`'s on-demand capture, meant to catch a transient
/// loss event's evidence even if no one is watching live at the moment
/// it happens. `watch.cooldown` rate-limits repeat dumps so a
/// persistently lossy link doesn't fill the directory with near-
/// duplicate captures -- each dump already reflects that moment fully,
/// repeating it every few seconds adds nothing. Deliberately does not
/// shell out to `nstat`/`ss` the way `mlvpnd diag-dump`'s CLI side does
/// -- see `diag.rs`'s module doc comment for why that split exists.
pub(crate) async fn diagnostics_watch_loop(
    watch: DiagnosticsWatchParams,
    links: Links,
    diag_ctx: DiagContext,
) {
    let mut tick = interval(Duration::from_secs(DIAGNOSTICS_WATCH_INTERVAL_SECS));
    let mut last_dump_at: Option<Instant> = None;
    loop {
        tick.tick().await;

        if let Some(last) = last_dump_at {
            if last.elapsed() < watch.cooldown {
                continue;
            }
        }

        let (snapshot, _) = build_snapshot(
            &links,
            &diag_ctx.peer_stats,
            &diag_ctx.tunnel_name,
            &diag_ctx.mode,
            &diag_ctx.session_meta,
            &diag_ctx.outbound_tx,
            &diag_ctx.outbound_dropped_total,
            &diag_ctx.log_ring,
            0,
            &diag_ctx.peer_version,
        )
        .await;

        let Some((link_name, loss_pct)) =
            diag::worst_loss_link(&snapshot, watch.loss_threshold_pct)
        else {
            continue;
        };

        let trigger = format!(
            "automatic: link '{link_name}' loss {loss_pct:.1}% exceeded threshold {:.1}%",
            watch.loss_threshold_pct
        );
        let text = diag::format_dump(&snapshot, &trigger);
        match write_dump_file(&watch.dump_dir, &diag_ctx.tunnel_name, &text) {
            Ok(path) => {
                tracing::warn!(
                    link = %link_name,
                    loss_pct,
                    threshold_pct = watch.loss_threshold_pct,
                    path = %path.display(),
                    "loss threshold exceeded; wrote automatic diagnostic dump"
                );
                last_dump_at = Some(Instant::now());
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    dir = %watch.dump_dir.display(),
                    "loss threshold exceeded but failed to write diagnostic dump"
                );
            }
        }
    }
}

/// Writes `text` to a new, uniquely-named file under `dir` (created if
/// missing) and returns the path written. Mode 0600 for the same reason
/// every other file this daemon creates on its own is restricted --
/// a dump includes learned peer IP:port and recent log lines, which
/// while not secret material, are still only this process's own
/// business to hand out.
fn write_dump_file(dir: &Path, tunnel_name: &str, text: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let unix_ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let path = dir.join(format!("mlvpn-diag-{tunnel_name}-{unix_ts_ms}.txt"));
    std::fs::write(&path, text)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

/// Extra time to wait, beyond a leg's own `duration_secs`, for its
/// result to actually arrive/complete -- covers final-packet round-trip
/// time plus normal network jitter. Generous since a throughput test is
/// already a multi-second, deliberately-invoked operation; a few extra
/// seconds of patience here is cheap insurance against a slow/lossy
/// link producing a spurious `None` result instead of the number a
/// slightly slower round trip still would have produced.
const THROUGHPUT_TEST_RESULT_GRACE: Duration = Duration::from_secs(5);

/// Implements `Command::RunThroughputTest`: runs the forward/upload leg
/// against one named link, or every configured link with a
/// currently-known peer address in turn if `link` is `None`, and --
/// when `bidirectional` -- the reverse/download leg for each too. Both
/// legs of a given link's test run strictly sequentially (see
/// `tunnel::ThroughputTestContext`'s doc comment for why), and so does
/// every targeted link's own test, one after another, never
/// concurrently.
#[allow(clippy::too_many_arguments)]
async fn run_throughput_test_command(
    links: &Links,
    session: &Arc<AsyncMutex<SessionState>>,
    throughput_test_ctx: &Arc<ThroughputTestContext>,
    mtu: usize,
    link: Option<String>,
    duration_secs: u32,
    bidirectional: bool,
    peer_version: &PeerVersion,
) -> CommandResult {
    // Snapshot (name, id, remote, socket) for every candidate link up
    // front, before running any test -- avoids holding a link's own
    // lock for the whole multi-second test duration, and means a link
    // that disappears or reconnects mid-run doesn't take the others
    // down with it.
    let mut targets: Vec<(String, u8, SocketAddr, Arc<UdpSocket>)> = Vec::new();
    for l in links.iter() {
        let guard = l.lock().await;
        if let Some(name) = &link {
            if guard.config.name != *name {
                continue;
            }
        }
        let Some(remote) = guard.remote else {
            continue;
        };
        let socket = guard.handle().current_socket().await;
        targets.push((guard.config.name.clone(), guard.id, remote, socket));
    }

    if targets.is_empty() {
        return CommandResult {
            ok: false,
            error: Some(match link {
                Some(name) => {
                    format!("no such link '{name}', or it has no known peer address yet")
                }
                None => "no configured link has a known peer address yet".to_string(),
            }),
            throughput_results: Vec::new(),
            diag_dump: None,
            tunnel_test_result: None,
            peer_version: peer_version.lock().unwrap().clone(),
        };
    }

    let mut results = Vec::with_capacity(targets.len());
    for (link_name, link_id, remote, socket) in targets {
        // Marks operator intent in the log tail as early as possible --
        // before either leg sends a single packet -- so a diagnostic
        // dump (`mlvpnd diag-dump`) covering this window makes it clear
        // a self-test was deliberately invoked against this link, not
        // just that a stream happened to start (see
        // `tunnel::send_throughput_test_stream`'s own start-of-stream
        // log for the per-leg detail).
        tracing::info!(
            link = %link_name,
            duration_secs,
            bidirectional,
            "starting throughput self-test"
        );
        let upload_mbps = run_throughput_test_leg_upload(
            &socket,
            remote,
            link_id,
            session,
            throughput_test_ctx,
            mtu,
            duration_secs,
        )
        .await;

        let download_mbps = if bidirectional {
            run_throughput_test_leg_download(
                &socket,
                remote,
                link_id,
                session,
                throughput_test_ctx,
                duration_secs,
            )
            .await
        } else {
            None
        };

        tracing::info!(
            link = %link_name,
            ?upload_mbps,
            ?download_mbps,
            "throughput self-test complete"
        );

        results.push(ThroughputTestLinkResult {
            link: link_name,
            upload_mbps,
            download_mbps,
        });
    }

    CommandResult {
        ok: true,
        error: None,
        throughput_results: results,
        diag_dump: None,
        tunnel_test_result: None,
        peer_version: peer_version.lock().unwrap().clone(),
    }
}

/// Forward/upload leg: sends a `duration_secs` stream to the peer, then
/// waits (with `THROUGHPUT_TEST_RESULT_GRACE`'s extra timeout) for
/// their `ThroughputTestResult` reply. `None` if the send itself failed
/// or no reply arrived in time -- e.g. an old peer that predates this
/// feature and silently drops the unrecognized packet type.
#[allow(clippy::too_many_arguments)]
async fn run_throughput_test_leg_upload(
    socket: &Arc<UdpSocket>,
    remote: SocketAddr,
    link_id: u8,
    session: &Arc<AsyncMutex<SessionState>>,
    throughput_test_ctx: &Arc<ThroughputTestContext>,
    mtu: usize,
    duration_secs: u32,
) -> Option<f64> {
    let test_id = random_session_id();
    let mut rx = throughput_test_ctx.register_wait(test_id);
    if let Err(e) = send_throughput_test_stream(
        socket.clone(),
        remote,
        link_id,
        session.clone(),
        test_id,
        Duration::from_secs(duration_secs as u64),
        mtu,
    )
    .await
    {
        tracing::warn!(error = %e, "throughput self-test upload stream failed to send");
        return None;
    }
    match tokio::time::timeout(THROUGHPUT_TEST_RESULT_GRACE, rx.recv()).await {
        Ok(Some(mbps)) => Some(mbps),
        _ => None,
    }
}

/// Reverse/download leg: asks the peer to send a `duration_secs` stream
/// back to us, then waits (`duration_secs` plus
/// `THROUGHPUT_TEST_RESULT_GRACE`) for our own receive side to finish
/// measuring it -- delivered locally via `ThroughputTestContext`, not
/// over the wire (there's nothing the *peer* needs to be told about a
/// result *we* computed from data *they* sent).
async fn run_throughput_test_leg_download(
    socket: &Arc<UdpSocket>,
    remote: SocketAddr,
    link_id: u8,
    session: &Arc<AsyncMutex<SessionState>>,
    throughput_test_ctx: &Arc<ThroughputTestContext>,
    duration_secs: u32,
) -> Option<f64> {
    let test_id = random_session_id();
    let mut rx = throughput_test_ctx.register_wait(test_id);
    if let Err(e) = send_throughput_test_reverse_request(
        socket,
        remote,
        link_id,
        session,
        test_id,
        duration_secs,
    )
    .await
    {
        tracing::warn!(error = %e, "throughput self-test reverse request failed to send");
        return None;
    }
    let wait = Duration::from_secs(duration_secs as u64) + THROUGHPUT_TEST_RESULT_GRACE;
    match tokio::time::timeout(wait, rx.recv()).await {
        Ok(Some(mbps)) => Some(mbps),
        _ => None,
    }
}
