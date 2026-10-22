//! `mlvpn-tui`: a live monitoring view over an `mlvpnd` tunnel.
//!
//! Connects to the daemon's local control socket (see `control.rs` in the
//! `mlvpn` lib crate) and renders a continuously-updating terminal UI
//! built around one question: *is the tunnel healthy right now?* A health
//! banner (HEALTHY / DEGRADED / FAILOVER / DOWN / STARTING / DISCONNECTED,
//! symbol plus color) is always on screen, with six views below it:
//! **Overview**, **Links** (compact table, Enter for a per-link detail
//! panel), **Traffic** (rates as bars and sparklines), **Reliability**
//! (FEC, reorder buffer, drops and errors), **System** (host, daemon
//! process, TUN, queue, version/MTU agreement) and **Debug** (connection
//! details, structured events, log tail). Layouts shrink for small
//! terminals.
//!
//! Deliberately does not use tokio: the only I/O here is one blocking
//! Unix-socket read loop (run on its own OS thread) feeding a shared
//! `Mutex<SharedState>`, while the main thread runs crossterm/ratatui's
//! inherently synchronous event-poll-and-draw loop.

mod chrome;
mod model;
mod theme;
mod views;

use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use mlvpn::ipc::Snapshot;
use model::{SharedState, Tab, Ui};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::{self, BufRead, BufReader, Stdout};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "mlvpn-tui",
    version,
    about = "Live monitoring view for an mlvpnd tunnel"
)]
struct Cli {
    /// Path to the mlvpnd control socket. If omitted, auto-detects a
    /// single `*.sock` file under /run/mlvpn/ and uses that.
    #[arg(short, long)]
    socket: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let hostname = local_hostname();
    let socket_source = resolve_socket_source(cli.socket)?;

    let state = Arc::new(Mutex::new(SharedState::new(match &socket_source {
        SocketSource::Fixed(p) => Some(p.clone()),
        SocketSource::AutoDetect => None,
    })));

    {
        let state = state.clone();
        thread::spawn(move || reader_thread(socket_source, state));
    }

    let mut terminal = setup_terminal()?;
    let result = run_app(&mut terminal, &state, &hostname);
    restore_terminal(&mut terminal)?;
    result
}

/// This machine's own hostname, shown in the header so a snapshot pasted
/// or screenshotted out of context (e.g. into a bug report, or a chat
/// with someone helping debug a two-host tunnel) is unambiguous about
/// which end of the tunnel it came from -- `tunnel_name` alone doesn't
/// help when, as is typical, both ends share the same tunnel name, and
/// `mode` (client/server) requires the reader to already know which
/// role runs on which host. Best-effort: a host that can't report its
/// own hostname (extremely unusual) gets a placeholder rather than
/// failing the whole tool over a cosmetic header detail.
fn local_hostname() -> String {
    let mut buf = vec![0u8; 256];
    // SAFETY: `buf` is a valid buffer of `buf.len()` bytes; POSIX
    // `gethostname` writes a name into it (NUL-terminated if it fits,
    // silently truncated otherwise per POSIX.1-2001) and never writes
    // past the given length.
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if ret != 0 {
        return "(unknown host)".to_string();
    }
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul]).into_owned()
}

/// Name of the systemd unit this tool knows how to check/start for the
/// "no control socket yet" recovery flow in `resolve_socket_source`
/// below -- matches `systemd/mlvpn.service`'s install location
/// (`/etc/systemd/system/mlvpn.service`). This project ships exactly
/// one, non-templated unit (one tunnel per host, by convention), so a
/// single hardcoded name is enough; a host running `mlvpnd` some other
/// way (manually, a different init system) just falls through to
/// `ServiceStatus::Unknown` and gets the original plain error.
const MLVPN_SYSTEMD_UNIT: &str = "mlvpn.service";

/// Where `reader_thread` should look for the control socket.
enum SocketSource {
    Fixed(PathBuf),
    /// The control socket's exact path isn't known yet -- keep
    /// rescanning `/run/mlvpn` for it (see `reader_thread`). Reached
    /// only after `resolve_socket_source` has already established
    /// there's a reasonable chance one will actually show up (the
    /// service is active, or the operator just asked to start it).
    AutoDetect,
}

enum AutoDetectOutcome {
    Found(PathBuf),
    NoneFound,
    Ambiguous(Vec<PathBuf>),
}

/// Scans `/run/mlvpn` for exactly one monitoring control socket. Used
/// both by `resolve_socket_source`'s first attempt and by
/// `reader_thread` on every retry while in `SocketSource::AutoDetect`
/// mode.
fn scan_auto_socket_dir() -> AutoDetectOutcome {
    let dir = Path::new("/run/mlvpn");
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // The command socket (`<tunnel>.command.sock`, only present
            // when `[command] enabled = true`) speaks a completely
            // different protocol -- one JSON `Command` in, one JSON
            // `CommandResult` back, for `mlvpnd set-link` (see
            // `control.rs::serve_commands`) -- not the streaming
            // `Snapshot` this tool reads off the plain `.sock` file.
            // Checking `path.extension() == Some("sock")` alone matched
            // both (the extension of `mlvpnrs0.command.sock` is also
            // just `sock`), so auto-detection broke the moment a config
            // turned the command socket on. Explicitly exclude it here
            // rather than trying to connect and letting it fail, so a
            // single control socket still auto-detects cleanly with
            // the command socket enabled alongside it.
            if name.ends_with(".command.sock") {
                continue;
            }
            if name.ends_with(".sock") {
                found.push(path);
            }
        }
    }
    match found.len() {
        1 => AutoDetectOutcome::Found(found.remove(0)),
        0 => AutoDetectOutcome::NoneFound,
        _ => AutoDetectOutcome::Ambiguous(found),
    }
}

/// If the peer's `mlvpnd` predates `[control]` support, the daemon
/// simply isn't running, or -- the common case this recovers from --
/// it's running but still establishing its very first connection to
/// the peer, there is nothing to connect to *yet*. `control::serve`
/// isn't spawned until after that initial handshake succeeds (see
/// `tunnel::run`), so the socket genuinely doesn't exist on a freshly
/// (re)started daemon that's waiting on an unreachable peer -- that's
/// not an error condition, just something to wait out.
///
/// Rather than failing immediately the moment no socket is found, this
/// checks whether `mlvpn.service` is actually running: if so, hands
/// back `SocketSource::AutoDetect` and lets `reader_thread` keep
/// rescanning `/run/mlvpn` in the background while the TUI itself
/// already renders (see that variant's own doc comment) -- no need to
/// block startup on it. If the service isn't running at all, offers to
/// start it right here (a plain stdin prompt, before the terminal
/// switches to raw/alternate-screen mode) instead of just erroring
/// out. Only truly gives up -- the original plain error -- when
/// systemd itself can't be queried (non-systemd host, `mlvpnd` run
/// some other way) or the operator declines to start it.
fn resolve_socket_source(explicit: Option<String>) -> anyhow::Result<SocketSource> {
    if let Some(p) = explicit {
        return Ok(SocketSource::Fixed(PathBuf::from(p)));
    }

    match scan_auto_socket_dir() {
        AutoDetectOutcome::Found(path) => Ok(SocketSource::Fixed(path)),
        AutoDetectOutcome::Ambiguous(found) => anyhow::bail!(
            "multiple control sockets found under /run/mlvpn: {found:?} -- pass --socket to \
             pick one"
        ),
        AutoDetectOutcome::NoneFound => match systemd_service_status(MLVPN_SYSTEMD_UNIT) {
            ServiceStatus::Active => {
                println!(
                    "{MLVPN_SYSTEMD_UNIT} is running but hasn't created a control socket yet -- \
                     probably still waiting for the remote end to connect. Watching \
                     /run/mlvpn for it to appear (Ctrl+C to give up)..."
                );
                Ok(SocketSource::AutoDetect)
            }
            ServiceStatus::InactiveOrFailed => {
                print!(
                    "No control socket found under /run/mlvpn, and {MLVPN_SYSTEMD_UNIT} isn't \
                     running. Start it now? [y/N] "
                );
                let _ = io::Write::flush(&mut io::stdout());
                let mut answer = String::new();
                io::stdin().read_line(&mut answer)?;
                if answer.trim().eq_ignore_ascii_case("y") {
                    start_service(MLVPN_SYSTEMD_UNIT)?;
                    println!(
                        "Started {MLVPN_SYSTEMD_UNIT} -- watching /run/mlvpn for its control \
                         socket to appear..."
                    );
                    Ok(SocketSource::AutoDetect)
                } else {
                    anyhow::bail!(
                        "no control socket found under /run/mlvpn; pass --socket explicitly, \
                         or start {MLVPN_SYSTEMD_UNIT} yourself first"
                    );
                }
            }
            ServiceStatus::Unknown => anyhow::bail!(
                "no control socket found under /run/mlvpn; pass --socket explicitly, or check \
                 that mlvpnd is running with [control] enabled (the default)"
            ),
        },
    }
}

enum ServiceStatus {
    Active,
    InactiveOrFailed,
    /// Couldn't tell -- no `systemctl` on `PATH`, this isn't a systemd
    /// host, or the query itself failed for some other reason. Treated
    /// as "can't help here", falling back to the original plain error
    /// rather than guessing.
    Unknown,
}

fn systemd_service_status(unit: &str) -> ServiceStatus {
    match std::process::Command::new("systemctl")
        .args(["is-active", unit])
        .output()
    {
        Ok(out) => match String::from_utf8_lossy(&out.stdout).trim() {
            "active" | "activating" | "reloading" => ServiceStatus::Active,
            "inactive" | "failed" | "deactivating" => ServiceStatus::InactiveOrFailed,
            _ => ServiceStatus::Unknown,
        },
        Err(_) => ServiceStatus::Unknown,
    }
}

/// Runs `systemctl start <unit>`, via `sudo` if we're not already root
/// -- this whole recovery flow happens before the terminal switches to
/// raw/alternate-screen mode, so an interactive `sudo` password prompt
/// here behaves exactly like it would from any other plain shell
/// command.
fn start_service(unit: &str) -> anyhow::Result<()> {
    // SAFETY: geteuid() takes no arguments and has no failure mode.
    let is_root = unsafe { libc::geteuid() } == 0;
    let status = if is_root {
        std::process::Command::new("systemctl")
            .args(["start", unit])
            .status()?
    } else {
        std::process::Command::new("sudo")
            .args(["systemctl", "start", unit])
            .status()?
    };
    if !status.success() {
        anyhow::bail!("systemctl start {unit} failed");
    }
    Ok(())
}

/// Runs forever on its own thread: connect, stream newline-delimited JSON
/// snapshots into `state` for as long as the connection lasts, and
/// reconnect on any error or EOF (the daemon may not have started yet, or
/// may restart mid-session -- neither should crash the viewer).
///
/// In `SocketSource::AutoDetect` mode, also re-scans `/run/mlvpn` on
/// every retry until exactly one control socket shows up. Once found, the
/// source is pinned to `Fixed`.
///
/// Each new connection replays the daemon's whole log and event rings, so
/// `on_connect` clears what the previous connection accumulated.
fn reader_thread(mut source: SocketSource, state: Arc<Mutex<SharedState>>) {
    loop {
        let path = match &source {
            SocketSource::Fixed(p) => p.clone(),
            SocketSource::AutoDetect => match scan_auto_socket_dir() {
                AutoDetectOutcome::Found(p) => {
                    state.lock().unwrap().socket_path = Some(p.clone());
                    source = SocketSource::Fixed(p.clone());
                    p
                }
                AutoDetectOutcome::NoneFound | AutoDetectOutcome::Ambiguous(_) => {
                    state.lock().unwrap().connected = false;
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            },
        };

        if let Ok(stream) = UnixStream::connect(&path) {
            state.lock().unwrap().on_connect();
            for line in BufReader::new(stream).lines() {
                let Ok(text) = line else { break };
                if let Ok(snapshot) = serde_json::from_str::<Snapshot>(&text) {
                    state.lock().unwrap().ingest(snapshot);
                }
            }
        }
        state.lock().unwrap().connected = false;
        thread::sleep(Duration::from_secs(2));
    }
}

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &Arc<Mutex<SharedState>>,
    hostname: &str,
) -> anyhow::Result<()> {
    let mut ui = Ui::default();

    loop {
        {
            let s = state.lock().unwrap();
            let link_count = s.snapshot.as_ref().map_or(0, |snap| snap.links.len());
            ui.link_selected = ui.link_selected.min(link_count.saturating_sub(1));
            terminal.draw(|f| chrome::draw(f, &s, &ui, hostname))?;
        }

        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let ctrl_c =
                key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
            if ctrl_c || key.code == KeyCode::Char('q') {
                return Ok(());
            }
            if key.code == KeyCode::Esc {
                if ui.link_detail {
                    ui.link_detail = false;
                    continue;
                }
                return Ok(());
            }
            let link_count = state
                .lock()
                .unwrap()
                .snapshot
                .as_ref()
                .map_or(0, |snap| snap.links.len());
            handle_key(&mut ui, key.code, link_count);
        }
    }
}

/// Everything except quitting, split out so it can be unit tested.
fn handle_key(ui: &mut Ui, code: KeyCode, link_count: usize) {
    match code {
        KeyCode::Tab => ui.tab = ui.tab.next(),
        KeyCode::BackTab => ui.tab = ui.tab.prev(),
        KeyCode::Char(c) => {
            if let Some(t) = Tab::from_digit(c) {
                ui.tab = t;
            }
        }
        KeyCode::Up if ui.tab == Tab::Links => {
            ui.link_selected = ui.link_selected.saturating_sub(1)
        }
        KeyCode::Down if ui.tab == Tab::Links => {
            ui.link_selected = (ui.link_selected + 1).min(link_count.saturating_sub(1))
        }
        KeyCode::Enter if ui.tab == Tab::Links => ui.link_detail = !ui.link_detail,
        KeyCode::Up if ui.tab == Tab::Debug => ui.log_scroll = ui.log_scroll.saturating_add(1),
        KeyCode::Down if ui.tab == Tab::Debug => ui.log_scroll = ui.log_scroll.saturating_sub(1),
        KeyCode::PageUp if ui.tab == Tab::Debug => ui.log_scroll = ui.log_scroll.saturating_add(10),
        KeyCode::PageDown if ui.tab == Tab::Debug => {
            ui.log_scroll = ui.log_scroll.saturating_sub(10)
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_and_tab_switch_views() {
        let mut ui = Ui::default();
        handle_key(&mut ui, KeyCode::Char('4'), 0);
        assert_eq!(ui.tab, Tab::Reliability);
        handle_key(&mut ui, KeyCode::Tab, 0);
        assert_eq!(ui.tab, Tab::System);
        handle_key(&mut ui, KeyCode::BackTab, 0);
        handle_key(&mut ui, KeyCode::BackTab, 0);
        assert_eq!(ui.tab, Tab::Traffic);
        handle_key(&mut ui, KeyCode::Char('9'), 0);
        assert_eq!(ui.tab, Tab::Traffic);
    }

    #[test]
    fn link_selection_is_clamped_and_enter_toggles_detail() {
        let mut ui = Ui::default();
        handle_key(&mut ui, KeyCode::Char('2'), 3);
        handle_key(&mut ui, KeyCode::Up, 3);
        assert_eq!(ui.link_selected, 0);
        for _ in 0..10 {
            handle_key(&mut ui, KeyCode::Down, 3);
        }
        assert_eq!(ui.link_selected, 2);
        handle_key(&mut ui, KeyCode::Enter, 3);
        assert!(ui.link_detail);
        handle_key(&mut ui, KeyCode::Enter, 3);
        assert!(!ui.link_detail);
    }

    #[test]
    fn log_scroll_only_on_debug_and_floors_at_zero() {
        let mut ui = Ui::default();
        handle_key(&mut ui, KeyCode::PageUp, 0);
        assert_eq!(ui.log_scroll, 0);
        handle_key(&mut ui, KeyCode::Char('6'), 0);
        handle_key(&mut ui, KeyCode::PageUp, 0);
        assert_eq!(ui.log_scroll, 10);
        handle_key(&mut ui, KeyCode::Down, 0);
        assert_eq!(ui.log_scroll, 9);
        for _ in 0..20 {
            handle_key(&mut ui, KeyCode::Down, 0);
        }
        assert_eq!(ui.log_scroll, 0);
    }
}
