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

use crate::ipc::{Command, CommandResult, LinkSnapshot, Snapshot};
use crate::link::{Link, LinkState};
use crate::peerstats::PeerStatsTable;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::interval;

const SNAPSHOT_INTERVAL_MS: u64 = 500;

/// Bind the control socket and serve snapshots to whoever connects until
/// the process exits. Any setup failure (can't create the runtime
/// directory, can't bind, path already in use by something else) is
/// logged and treated as "monitoring unavailable" rather than a fatal
/// daemon error -- a stats socket is a convenience feature, not something
/// that should be able to take the tunnel down.
pub async fn serve(
    path: PathBuf,
    links: Arc<AsyncMutex<Vec<Link>>>,
    peer_stats: Arc<PeerStatsTable>,
    tunnel_name: String,
    mode: String,
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
        tokio::spawn(async move {
            serve_client(stream, links, peer_stats, tunnel_name, mode).await;
        });
    }
}

async fn serve_client(
    mut stream: UnixStream,
    links: Arc<AsyncMutex<Vec<Link>>>,
    peer_stats: Arc<PeerStatsTable>,
    tunnel_name: String,
    mode: String,
) {
    let mut tick = interval(Duration::from_millis(SNAPSHOT_INTERVAL_MS));
    loop {
        tick.tick().await;
        let snapshot = build_snapshot(&links, &peer_stats, &tunnel_name, &mode).await;
        let Ok(mut line) = serde_json::to_vec(&snapshot) else {
            continue;
        };
        line.push(b'\n');
        if stream.write_all(&line).await.is_err() {
            return; // client disconnected
        }
    }
}

async fn build_snapshot(
    links: &Arc<AsyncMutex<Vec<Link>>>,
    peer_stats: &Arc<PeerStatsTable>,
    tunnel_name: &str,
    mode: &str,
) -> Snapshot {
    let links_guard = links.lock().await;
    let link_snapshots = links_guard
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
                local_rtt_ms: link.stats.rtt_ms.get(),
                local_jitter_ms: link.stats.jitter_ms.get(),
                local_loss_pct: link.stats.loss_rate.get().map(|v| v * 100.0),
                local_throughput_mbps: link.stats.throughput_mbps.get(),
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

    Snapshot {
        tunnel_name: tunnel_name.to_string(),
        mode: mode.to_string(),
        unix_ts_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        links: link_snapshots,
    }
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
pub async fn serve_commands(path: PathBuf, links: Arc<AsyncMutex<Vec<Link>>>) {
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
        tokio::spawn(async move {
            serve_command_client(stream, links).await;
        });
    }
}

/// Handle one command-socket connection: read exactly one JSON line,
/// apply it, write exactly one JSON `CommandResult` line back. Silently
/// returns (rather than logging) on a client that connects and
/// disconnects without sending anything, or one that disappears before
/// the reply is written -- a raced/impatient client is not a server-side
/// problem worth a warning.
async fn serve_command_client(stream: UnixStream, links: Arc<AsyncMutex<Vec<Link>>>) {
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
        Ok(cmd) => apply_command(cmd, &links).await,
        Err(e) => CommandResult {
            ok: false,
            error: Some(format!("invalid command: {e}")),
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
async fn apply_command(cmd: Command, links: &Arc<AsyncMutex<Vec<Link>>>) -> CommandResult {
    match cmd {
        Command::SetLinkEnabled { link, enabled } => {
            let mut links_guard = links.lock().await;
            match links_guard.iter_mut().find(|l| l.config.name == link) {
                Some(l) => {
                    l.admin_disabled = !enabled;
                    tracing::info!(
                        link = %link,
                        enabled,
                        "link admin_disabled set via command socket"
                    );
                    CommandResult {
                        ok: true,
                        error: None,
                    }
                }
                None => CommandResult {
                    ok: false,
                    error: Some(format!("no such link '{link}'")),
                },
            }
        }
    }
}
