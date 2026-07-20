//! `mlvpn-tui`: a live monitoring view over an `mlvpnd` tunnel.
//!
//! Connects to the daemon's local control socket (see `control.rs` in the
//! `mlvpn` lib crate) and renders a continuously-updating, tabbed view:
//! **Overview** (the default tab at startup -- condensed Links/Daemon/Logs
//! panes stacked in one screen, for an at-a-glance/screenshot-friendly
//! view without switching tabs), **Links** (every bonded link's state,
//! the peer address it's talking to, and both this side's own measured
//! RTT/jitter/loss/throughput *and* the peer's self-reported view of the
//! same link, received over the wire via `StatsShare` frames -- see
//! `protocol.rs`), **Daemon** (session/rekey state, the outbound queue,
//! the TUN device's own kernel counters, and machine-wide load/memory/
//! uptime), and **Logs** (a live tail of the daemon's own log output,
//! streamed incrementally rather than requiring a separate
//! `journalctl -f` window).
//!
//! Deliberately does not use tokio: the only I/O here is one blocking
//! Unix-socket read loop (run on its own OS thread) feeding a shared
//! `Mutex<SharedState>`, while the main thread runs crossterm/ratatui's
//! inherently synchronous event-poll-and-draw loop. Pulling in an async
//! runtime for that would add a dependency and a layer of indirection
//! without buying anything.

use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use mlvpn::ipc::{DaemonSnapshot, LinkSnapshot, LogEntry, Snapshot, TunSnapshot};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Tabs},
    Frame, Terminal,
};
use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Stdout};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Semantic color constants, used consistently across every tab instead
// of scattered inline `Color::Green` literals -- link/peer-staleness
// state, queue-fill thresholds, error/drop counters, log levels, and
// tab/section highlighting all read off these same five names.
const COLOR_GOOD: Color = Color::Green;
const COLOR_WARN: Color = Color::Yellow;
const COLOR_BAD: Color = Color::Red;
const COLOR_MUTED: Color = Color::DarkGray;
const COLOR_ACCENT: Color = Color::Cyan;

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

/// Which of the four tabs is currently on screen -- pure UI-input
/// state local to `run_app`'s loop, not shared with `reader_thread`, so
/// it deliberately doesn't live on `SharedState`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Links,
    Daemon,
    Logs,
}

impl Tab {
    const ALL: [Tab; 4] = [Tab::Overview, Tab::Links, Tab::Daemon, Tab::Logs];

    fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Links => "Links",
            Tab::Daemon => "Daemon",
            Tab::Logs => "Logs",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap()
    }

    fn next(self) -> Tab {
        Tab::ALL[(self.index() + 1) % Tab::ALL.len()]
    }

    fn prev(self) -> Tab {
        Tab::ALL[(self.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }
}

/// How many recent log lines to keep client-side. Independent of (and
/// larger than) the daemon's own `logbuf::LOG_RING_CAPACITY` -- this
/// just bounds local memory use for a long-running `mlvpn-tui` session;
/// the daemon's ring is what actually limits how far back history can
/// go after a fresh connection.
const TUI_LOG_CAPACITY: usize = 2000;

struct SharedState {
    snapshot: Option<Snapshot>,
    connected: bool,
    last_update: Option<Instant>,
    /// Accumulated from every `Snapshot::new_log_lines` delta seen so
    /// far -- see `reader_thread`. Oldest-first, capped at
    /// `TUI_LOG_CAPACITY`.
    logs: VecDeque<LogEntry>,
    /// `None` while auto-detecting and no control socket has been found
    /// yet (see `SocketSource::AutoDetect`); `Some` once known, either
    /// because `--socket` was given explicitly or auto-detection found
    /// it. Purely for header/footer display -- `reader_thread` tracks
    /// its own working copy independently.
    socket_path: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let hostname = local_hostname();
    let socket_source = resolve_socket_source(cli.socket)?;

    let state = Arc::new(Mutex::new(SharedState {
        snapshot: None,
        connected: false,
        last_update: None,
        logs: VecDeque::new(),
        socket_path: match &socket_source {
            SocketSource::Fixed(p) => Some(p.clone()),
            SocketSource::AutoDetect => None,
        },
    }));

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
/// every retry until exactly one control socket shows up -- see
/// `resolve_socket_source`'s doc comment for why this mode exists at
/// all (a freshly started `mlvpnd` waiting on an unreachable peer
/// doesn't create the socket until its initial handshake succeeds).
/// Once found, that path is written to `state.socket_path` (purely for
/// the header/footer to display) and the local `source` is pinned to
/// `Fixed` from then on -- no need to keep rescanning a directory for a
/// daemon that's already shown up once.
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
                    // Ambiguous here would mean a second tunnel's socket
                    // appeared after startup -- not this tool's problem
                    // to resolve interactively mid-session; just keep
                    // waiting for exactly one, same as "not found yet".
                    state.lock().unwrap().connected = false;
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            },
        };

        match UnixStream::connect(&path) {
            Ok(stream) => {
                state.lock().unwrap().connected = true;
                let reader = BufReader::new(stream);
                for line in reader.lines() {
                    match line {
                        Ok(text) => {
                            if let Ok(snapshot) = serde_json::from_str::<Snapshot>(&text) {
                                let mut s = state.lock().unwrap();
                                for entry in &snapshot.new_log_lines {
                                    if s.logs.len() == TUI_LOG_CAPACITY {
                                        s.logs.pop_front();
                                    }
                                    s.logs.push_back(entry.clone());
                                }
                                s.snapshot = Some(snapshot);
                                s.last_update = Some(Instant::now());
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
            Err(_) => {
                // Socket doesn't exist yet or connection was refused;
                // fall through to the retry sleep below.
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
    // Overview first: a screenshot-friendly, at-a-glance combination of
    // every other tab's panes is the most useful thing to see the
    // instant this tool starts up, before an operator has decided which
    // single tab they actually want to drill into.
    let mut active_tab = Tab::Overview;
    // Lines scrolled up from the bottom of the Logs tab -- 0 means
    // "pinned to the newest line" (standard tail -f auto-follow: as
    // long as this stays 0, `draw_logs_tab` always shows whatever's
    // most recent, no extra "am I following" bit needed). Only
    // meaningful on `Tab::Logs`; harmless if stale while another tab
    // is active.
    let mut log_scroll: usize = 0;

    loop {
        {
            let s = state.lock().unwrap();
            terminal.draw(|f| draw(f, &s, hostname, active_tab, log_scroll))?;
        }

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                let quit = matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL));
                if quit {
                    return Ok(());
                }
                match key.code {
                    KeyCode::Tab => active_tab = active_tab.next(),
                    KeyCode::BackTab => active_tab = active_tab.prev(),
                    KeyCode::Char('1') => active_tab = Tab::Overview,
                    KeyCode::Char('2') => active_tab = Tab::Links,
                    KeyCode::Char('3') => active_tab = Tab::Daemon,
                    KeyCode::Char('4') => active_tab = Tab::Logs,
                    KeyCode::Up if active_tab == Tab::Logs => {
                        log_scroll = log_scroll.saturating_add(1);
                    }
                    KeyCode::Down if active_tab == Tab::Logs => {
                        log_scroll = log_scroll.saturating_sub(1);
                    }
                    KeyCode::PageUp if active_tab == Tab::Logs => {
                        log_scroll = log_scroll.saturating_add(10);
                    }
                    KeyCode::PageDown if active_tab == Tab::Logs => {
                        log_scroll = log_scroll.saturating_sub(10);
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw(f: &mut Frame, state: &SharedState, hostname: &str, active_tab: Tab, log_scroll: usize) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_tabs_header(f, chunks[0], state, hostname, active_tab);
    match active_tab {
        Tab::Overview => draw_overview_tab(f, chunks[1], state),
        Tab::Links => draw_links_tab(f, chunks[1], state),
        Tab::Daemon => draw_daemon_tab(f, chunks[1], state),
        Tab::Logs => draw_logs_tab(f, chunks[1], state, log_scroll),
    }
    draw_footer(f, chunks[2], state, active_tab);
}

fn draw_tabs_header(
    f: &mut Frame,
    area: Rect,
    state: &SharedState,
    hostname: &str,
    active_tab: Tab,
) {
    let (title, style) = match (&state.snapshot, &state.socket_path) {
        (Some(snap), Some(path)) => (
            format!(
                " {}  --  tunnel '{}' ({})  --  {} ",
                hostname,
                snap.tunnel_name,
                snap.mode,
                path.display()
            ),
            Style::default()
                .fg(COLOR_ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        (_, Some(path)) => (
            format!(
                " {}  --  waiting for data from {}... ",
                hostname,
                path.display()
            ),
            Style::default().fg(COLOR_WARN),
        ),
        (_, None) => (
            format!(
                " {}  --  waiting for mlvpnd's control socket under /run/mlvpn... ",
                hostname
            ),
            Style::default().fg(COLOR_WARN),
        ),
    };

    let titles = Tab::ALL.iter().map(|t| t.title());
    let tabs = Tabs::new(titles)
        .select(active_tab.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(Span::styled(title, style))),
        )
        .highlight_style(
            Style::default()
                .fg(COLOR_ACCENT)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(" | ");
    f.render_widget(tabs, area);
}

/// The default tab at startup: condensed panes from every other tab
/// stacked into one screen -- the full Links table on top (unchanged,
/// just reused directly), the four Daemon panels arranged as a 2x2
/// grid in the middle, and a following Logs tail at the bottom. Meant
/// to be screenshot-friendly on its own, without needing to switch
/// tabs to see the whole picture at a glance. The embedded Logs pane
/// always follows the tail (no scrolling here -- switch to the real
/// Logs tab for that).
fn draw_overview_tab(f: &mut Frame, area: Rect, state: &SharedState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(45),
            Constraint::Length(10),
            Constraint::Min(3),
        ])
        .split(area);

    draw_links_tab(f, rows[0], state);

    let Some(snap) = &state.snapshot else {
        let block = Block::default().borders(Borders::ALL).title(" Daemon ");
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "waiting for data...",
                Style::default().fg(COLOR_MUTED),
            )))
            .block(block),
            rows[1],
        );
        f.render_widget(
            Block::default().borders(Borders::ALL).title(" Logs "),
            rows[2],
        );
        return;
    };
    let daemon = &snap.daemon;

    let daemon_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Length(5)])
        .split(rows[1]);
    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(daemon_rows[0]);
    let bottom_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(daemon_rows[1]);

    draw_session_panel(f, top_cols[0], daemon);
    draw_outbound_queue_panel(f, top_cols[1], daemon);
    draw_tun_panel(f, bottom_cols[0], &daemon.tun);
    draw_system_panel(f, bottom_cols[1], daemon);

    draw_logs_tab(f, rows[2], state, 0);
}

fn draw_links_tab(f: &mut Frame, area: Rect, state: &SharedState) {
    let header = Row::new(vec![
        Cell::from("Link"),
        Cell::from("State"),
        Cell::from("Up For"),
        Cell::from("Peer Addr"),
        Cell::from("Score"),
        Cell::from("Tx / Rx (total)"),
        Cell::from("Local (this side's own measurement)"),
        Cell::from("Peer (their self-reported measurement)"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .bottom_margin(1);

    let rows: Vec<Row> = match &state.snapshot {
        Some(snap) => snap.links.iter().map(link_row).collect(),
        None => Vec::new(),
    };

    let widths = [
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(8),
        Constraint::Length(21),
        Constraint::Length(6),
        Constraint::Length(18),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
    ];

    let title = match &state.snapshot {
        Some(snap) => {
            let (agg_rx, agg_tx) = aggregate_throughput(&snap.links);
            format!(" Links -- tunnel aggregate: rx {agg_rx:.1} Mbps / tx {agg_tx:.1} Mbps (up links only) ")
        }
        None => " Links ".to_string(),
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .column_spacing(1);

    f.render_widget(table, area);
}

/// Sums each up link's real-time local rx/tx throughput EWMAs --
/// `local_rx_throughput_mbps`/`local_tx_throughput_mbps`, both
/// windowed real-time rates re-sampled every ~1s, not the cumulative
/// `tx_bytes`/`rx_bytes` totals -- into one "how much is the whole
/// bonded tunnel actually moving right now" figure. Computed client-side
/// from data every snapshot already carries rather than adding a
/// daemon-side aggregate field, since mlvpn-tui already has everything
/// it needs. Down/probing links are excluded: a link that isn't
/// currently carrying scheduled traffic shouldn't count toward "what
/// the tunnel is doing right now" even if its EWMA hasn't yet decayed
/// to zero.
fn aggregate_throughput(links: &[LinkSnapshot]) -> (f64, f64) {
    links
        .iter()
        .filter(|l| l.state == "up")
        .fold((0.0, 0.0), |(rx, tx), l| {
            (
                rx + l.local_rx_throughput_mbps.unwrap_or(0.0),
                tx + l.local_tx_throughput_mbps.unwrap_or(0.0),
            )
        })
}

fn link_row(l: &LinkSnapshot) -> Row<'static> {
    let state_style = state_style(&l.state);
    let peer_stale = l.peer_stats_age_ms.map(|a| a > 5000).unwrap_or(true);

    let local_line = local_measurement_line(
        l.local_rtt_ms,
        l.local_jitter_ms,
        l.local_loss_pct,
        l.local_rx_throughput_mbps,
        l.local_tx_throughput_mbps,
    );

    let peer_line = if l.peer_rtt_ms.is_none() && l.peer_name.is_none() {
        Line::from(Span::styled(
            "(no StatsShare received yet)",
            Style::default().fg(COLOR_MUTED),
        ))
    } else {
        let age = l
            .peer_stats_age_ms
            .map(|a| format!(" [{:.1}s ago]", a as f64 / 1000.0))
            .unwrap_or_default();
        measurement_line(
            l.peer_rtt_ms,
            l.peer_jitter_ms,
            l.peer_loss_pct,
            l.peer_throughput_mbps,
            &age,
            peer_stale,
        )
    };

    let tx_rx_text = format!("{} / {}", fmt_bytes(l.tx_bytes), fmt_bytes(l.rx_bytes));

    Row::new(vec![
        Cell::from(l.name.clone()),
        Cell::from(l.state.clone()).style(state_style),
        Cell::from(fmt_duration_ms(l.state_duration_ms)),
        Cell::from(l.remote_addr.clone().unwrap_or_else(|| "-".to_string())),
        Cell::from(format!("{:.2}", l.score)).style(score_style(l.score)),
        Cell::from(tx_rx_text),
        Cell::from(local_line),
        Cell::from(peer_line),
    ])
}

/// Builds one "rtt X  jit Y  loss Z  N Mbps[ age]" line with the loss
/// percentage colored by severity (see `loss_style`) -- RTT/jitter/
/// throughput stay plain since none of them has as clear-cut a
/// universal good/bad threshold as loss does. `muted`, when set,
/// overrides every span (including the loss one) to `COLOR_MUTED`
/// uniformly instead -- used for stale peer-reported data, where
/// individual-field coloring would overstate confidence in numbers
/// that might be well out of date.
///
/// Peer-only: the wire protocol's `StatsShare` frame (`protocol.rs`)
/// carries a single receive-side throughput figure, not a separate
/// tx/rx pair the way this process's own `LinkSnapshot` fields do --
/// see `local_measurement_line` below for the local (both-directions)
/// counterpart.
fn measurement_line(
    rtt_ms: Option<f64>,
    jitter_ms: Option<f64>,
    loss_pct: Option<f64>,
    throughput_mbps: Option<f64>,
    suffix: &str,
    muted: bool,
) -> Line<'static> {
    let base = if muted {
        Style::default().fg(COLOR_MUTED)
    } else {
        Style::default()
    };
    let loss_span_style = if muted { base } else { loss_style(loss_pct) };
    Line::from(vec![
        Span::styled(
            format!("rtt {}  jit {}  loss ", fmt_ms(rtt_ms), fmt_ms(jitter_ms)),
            base,
        ),
        Span::styled(fmt_pct(loss_pct), loss_span_style),
        Span::styled(format!("  {}{suffix}", fmt_mbps(throughput_mbps)), base),
    ])
}

/// Local counterpart to `measurement_line`, showing both directions'
/// real-time throughput (`local_rx_throughput_mbps`/
/// `local_tx_throughput_mbps` -- windowed EWMAs re-sampled every ~1s,
/// not the cumulative `Tx / Rx (total)` column) side by side, since a
/// link's send/receive rates are often meaningfully asymmetric and this
/// process always has both. No `muted`/`suffix` parameters -- unlike
/// peer data, local measurements are never stale (there's no wire hop
/// for them to arrive late over) and there's no "age" to report.
fn local_measurement_line(
    rtt_ms: Option<f64>,
    jitter_ms: Option<f64>,
    loss_pct: Option<f64>,
    rx_mbps: Option<f64>,
    tx_mbps: Option<f64>,
) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!(
            "rtt {}  jit {}  loss ",
            fmt_ms(rtt_ms),
            fmt_ms(jitter_ms)
        )),
        Span::styled(fmt_pct(loss_pct), loss_style(loss_pct)),
        Span::raw(format!(
            "  rx {}  tx {}",
            fmt_mbps(rx_mbps),
            fmt_mbps(tx_mbps)
        )),
    ])
}

/// Green above 0.5 (this link is carrying a healthy share of traffic),
/// yellow above 0 (up and eligible, but a small share -- e.g. a
/// low-`weight` or bandwidth-capped link, or one just coming back into
/// rotation), muted at exactly 0 (down, admin-disabled, or otherwise
/// excluded from scheduling -- see `ipc::LinkSnapshot::score`'s doc
/// comment).
fn score_style(score: f64) -> Style {
    if score <= 0.0 {
        Style::default().fg(COLOR_MUTED)
    } else if score < 0.5 {
        Style::default().fg(COLOR_WARN)
    } else {
        Style::default().fg(COLOR_GOOD)
    }
}

/// Green at exactly 0% loss, yellow under 5%, red at 5% or above --
/// `None` (no measurement yet) reads as muted, not a false "good".
fn loss_style(pct: Option<f64>) -> Style {
    match pct {
        None => Style::default().fg(COLOR_MUTED),
        Some(p) if p <= 0.0 => Style::default().fg(COLOR_GOOD),
        Some(p) if p < 5.0 => Style::default().fg(COLOR_WARN),
        Some(_) => Style::default().fg(COLOR_BAD),
    }
}

fn draw_daemon_tab(f: &mut Frame, area: Rect, state: &SharedState) {
    let Some(snap) = &state.snapshot else {
        let block = Block::default().borders(Borders::ALL).title(" Daemon ");
        let para = Paragraph::new(Line::from(Span::styled(
            "waiting for data...",
            Style::default().fg(COLOR_MUTED),
        )))
        .block(block);
        f.render_widget(para, area);
        return;
    };
    let daemon = &snap.daemon;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(area);

    draw_session_panel(f, chunks[0], daemon);
    draw_outbound_queue_panel(f, chunks[1], daemon);
    draw_tun_panel(f, chunks[2], &daemon.tun);
    draw_system_panel(f, chunks[3], daemon);
}

fn draw_session_panel(f: &mut Frame, area: Rect, daemon: &DaemonSnapshot) {
    let session_line = Line::from(vec![
        Span::raw("Session ID: "),
        Span::styled(
            format!("{:08x}", daemon.session_id),
            Style::default().fg(COLOR_ACCENT),
        ),
        Span::raw("   Uptime: "),
        Span::raw(fmt_duration_ms(daemon.session_uptime_ms)),
        Span::raw("   Rekeys: "),
        Span::raw(daemon.rekey_count.to_string()),
    ]);

    // Peer version comes from the periodic authenticated `VersionInfo`
    // wire exchange (`PacketType::VersionInfo`), independent of
    // whatever self-test or diag-dump command may or may not have run
    // -- see that packet type's doc comment. `None` just means no
    // session has delivered one yet (e.g. right after startup).
    let version_line = match &daemon.peer_version {
        Some(peer) if *peer == daemon.local_version => Line::from(vec![
            Span::raw("Version: "),
            Span::raw(daemon.local_version.clone()),
            Span::styled(" (peer matches)", Style::default().fg(COLOR_MUTED)),
        ]),
        Some(peer) => Line::from(vec![
            Span::raw("Version: "),
            Span::raw(daemon.local_version.clone()),
            Span::raw("   Peer: "),
            Span::styled(format!("{peer} (MISMATCH)"), Style::default().fg(COLOR_BAD)),
        ]),
        None => Line::from(vec![
            Span::raw("Version: "),
            Span::raw(daemon.local_version.clone()),
            Span::styled("   Peer: unknown", Style::default().fg(COLOR_MUTED)),
        ]),
    };

    let block = Block::default().borders(Borders::ALL).title(" Session ");
    f.render_widget(
        Paragraph::new(vec![session_line, version_line]).block(block),
        area,
    );
}

/// A `Gauge` colored by fill ratio (good/warn/bad thresholds match the
/// same semantics as `state_style`'s link coloring) plus the lifetime
/// drop count -- see `outbound_queue_drop_reporter`'s doc comment in
/// `tunnel.rs` for why that counter is monotonic rather than windowed.
fn draw_outbound_queue_panel(f: &mut Frame, area: Rect, daemon: &DaemonSnapshot) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Outbound Queue ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(inner);

    let ratio = if daemon.outbound_queue_capacity > 0 {
        (daemon.outbound_queue_len as f64 / daemon.outbound_queue_capacity as f64).min(1.0)
    } else {
        0.0
    };
    let gauge_color = if ratio > 0.75 {
        COLOR_BAD
    } else if ratio > 0.25 {
        COLOR_WARN
    } else {
        COLOR_GOOD
    };
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(gauge_color))
        .ratio(ratio)
        .label(format!(
            "{} / {}",
            daemon.outbound_queue_len, daemon.outbound_queue_capacity
        ));
    f.render_widget(gauge, rows[0]);

    let dropped_style = if daemon.outbound_queue_dropped_total > 0 {
        Style::default().fg(COLOR_BAD)
    } else {
        Style::default().fg(COLOR_MUTED)
    };
    let dropped_line = Line::from(vec![
        Span::raw("Dropped (lifetime): "),
        Span::styled(
            daemon.outbound_queue_dropped_total.to_string(),
            dropped_style,
        ),
    ]);
    f.render_widget(Paragraph::new(dropped_line), rows[1]);
}

fn draw_tun_panel(f: &mut Frame, area: Rect, tun: &TunSnapshot) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tun Interface ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let errors = tun.rx_errors.unwrap_or(0) + tun.tx_errors.unwrap_or(0);
    let dropped = tun.rx_dropped.unwrap_or(0) + tun.tx_dropped.unwrap_or(0);
    let errors_style = if errors > 0 || dropped > 0 {
        Style::default().fg(COLOR_BAD)
    } else {
        Style::default().fg(COLOR_MUTED)
    };

    let lines = vec![
        Line::from(format!("Interface: {}", tun.iface)),
        Line::from(format!(
            "Rx {}   Tx {}",
            fmt_bytes_opt(tun.rx_bytes),
            fmt_bytes_opt(tun.tx_bytes),
        )),
        Line::from(Span::styled(
            format!(
                "Errors: rx {} tx {}   Dropped: rx {} tx {}",
                fmt_opt_u64(tun.rx_errors),
                fmt_opt_u64(tun.tx_errors),
                fmt_opt_u64(tun.rx_dropped),
                fmt_opt_u64(tun.tx_dropped),
            ),
            errors_style,
        )),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_system_panel(f: &mut Frame, area: Rect, daemon: &DaemonSnapshot) {
    let sys = &daemon.system;
    let block = Block::default().borders(Borders::ALL).title(" System ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mem_line = match (sys.mem_total_kb, sys.mem_available_kb) {
        (Some(total), Some(avail)) if total > 0 => {
            let used = total.saturating_sub(avail);
            let pct = used as f64 / total as f64 * 100.0;
            Line::from(vec![
                Span::raw(format!(
                    "Mem: {} / {} (",
                    fmt_bytes(used * 1024),
                    fmt_bytes(total * 1024),
                )),
                Span::styled(format!("{pct:.0}%"), mem_pct_style(pct)),
                Span::raw(" used)"),
            ])
        }
        _ => Line::from("Mem: --"),
    };

    let uptime_line = match sys.uptime_secs {
        Some(secs) => format!("Uptime: {}", fmt_duration_ms(secs.saturating_mul(1000))),
        None => "Uptime: --".to_string(),
    };

    let lines = vec![
        Line::from(format!(
            "Load: {} {} {}",
            fmt_load(sys.load1),
            fmt_load(sys.load5),
            fmt_load(sys.load15),
        )),
        mem_line,
        Line::from(uptime_line),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

/// Green under 70% used, yellow 70-90%, red at 90% or above.
fn mem_pct_style(pct: f64) -> Style {
    if pct >= 90.0 {
        Style::default().fg(COLOR_BAD)
    } else if pct >= 70.0 {
        Style::default().fg(COLOR_WARN)
    } else {
        Style::default().fg(COLOR_GOOD)
    }
}

/// Renders a fixed window of `state.logs`, most-recent-at-bottom.
/// Deliberately not a stateful `ratatui::widgets::ListState` scroll --
/// `log_scroll` (lines back from the newest entry) is plain, and the
/// visible slice is recomputed from it every frame, so "pinned to the
/// bottom" falls out for free whenever `log_scroll == 0`: as new
/// entries arrive, the end of the slice always tracks `state.logs`'s
/// current length rather than a remembered index into a list that just
/// grew underneath it.
fn draw_logs_tab(f: &mut Frame, area: Rect, state: &SharedState, log_scroll: usize) {
    let following = log_scroll == 0;
    let title = if following {
        " Logs ".to_string()
    } else {
        format!(" Logs (scrolled up {log_scroll} -- Down/PageDown to catch up) ")
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let visible = inner.height as usize;
    let total = state.logs.len();
    let end = total.saturating_sub(log_scroll.min(total));
    let start = end.saturating_sub(visible);

    let items: Vec<ListItem> = state
        .logs
        .range(start..end)
        .map(|entry| ListItem::new(log_entry_line(entry)))
        .collect();
    f.render_widget(List::new(items), inner);
}

fn log_entry_line(entry: &LogEntry) -> Line<'static> {
    let level_style = match entry.level.as_str() {
        "ERROR" => Style::default().fg(COLOR_BAD).add_modifier(Modifier::BOLD),
        "WARN" => Style::default().fg(COLOR_WARN),
        _ => Style::default(),
    };
    let target = entry.target.as_deref().unwrap_or("-");
    Line::from(vec![
        Span::styled(
            fmt_log_timestamp(entry.unix_ts_ms),
            Style::default().fg(COLOR_MUTED),
        ),
        Span::raw(" "),
        Span::styled(format!("{:5}", entry.level), level_style),
        Span::raw(" "),
        Span::styled(
            format!("{:24}", truncate(target, 24)),
            Style::default().fg(COLOR_MUTED),
        ),
        Span::raw(" "),
        Span::raw(entry.message.clone()),
    ])
}

/// Truncates on char boundaries (module-path targets are always ASCII
/// in practice, but this avoids ever panicking on a byte-index mid
/// multi-byte character regardless) and appends an ellipsis when it
/// actually cut something off.
fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// `HH:MM:SS`, UTC (matching `tracing_subscriber::fmt`'s own default
/// timestamp format for the primary log output) -- computed by hand
/// rather than pulling in a `chrono`/`time` dependency just for this.
fn fmt_log_timestamp(unix_ts_ms: u64) -> String {
    let secs = unix_ts_ms / 1000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn draw_footer(f: &mut Frame, area: Rect, state: &SharedState, active_tab: Tab) {
    let status = if state.connected {
        match state.last_update {
            Some(t) if t.elapsed() < Duration::from_secs(3) => {
                Span::styled("connected", Style::default().fg(COLOR_GOOD))
            }
            Some(_) => Span::styled("connected, no recent data", Style::default().fg(COLOR_WARN)),
            None => Span::styled(
                "connected, waiting for first snapshot",
                Style::default().fg(COLOR_WARN),
            ),
        }
    } else if state.socket_path.is_none() {
        Span::styled(
            "waiting for mlvpnd's control socket to appear...",
            Style::default().fg(COLOR_WARN),
        )
    } else {
        Span::styled(
            "disconnected -- retrying...",
            Style::default().fg(COLOR_BAD),
        )
    };

    let keys = match active_tab {
        Tab::Logs => {
            "q/Esc: quit   Tab/Shift+Tab or 1/2/3/4: switch tab   Up/Down/PgUp/PgDn: scroll   "
        }
        _ => "q/Esc: quit   Tab/Shift+Tab or 1/2/3/4: switch tab   ",
    };

    let line = Line::from(vec![Span::raw(keys), Span::raw("status: "), status]);
    f.render_widget(Paragraph::new(line), area);
}

fn state_style(s: &str) -> Style {
    match s {
        "up" => Style::default().fg(COLOR_GOOD).add_modifier(Modifier::BOLD),
        "down" => Style::default().fg(COLOR_BAD).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(COLOR_WARN),
    }
}

fn fmt_ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}ms"))
        .unwrap_or_else(|| "-".to_string())
}

fn fmt_pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".to_string())
}

fn fmt_mbps(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}Mbps"))
        .unwrap_or_else(|| "-".to_string())
}

/// Formats a byte count with a binary-prefix unit (`KB` = 1024 bytes,
/// etc.) -- used for both per-link cumulative counters (this tab) and
/// the TUN interface's own kernel counters (the Daemon tab).
fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes}B")
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

/// `fmt_bytes` for the `Option<u64>` sysfs counters on the Daemon tab
/// (`TunSnapshot`'s fields) -- `None` reads as "unknown" (the sysfs
/// read failed or the interface is gone), never as zero traffic.
fn fmt_bytes_opt(v: Option<u64>) -> String {
    v.map(fmt_bytes).unwrap_or_else(|| "-".to_string())
}

fn fmt_opt_u64(v: Option<u64>) -> String {
    v.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string())
}

fn fmt_load(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "-".to_string())
}

/// Formats a millisecond duration as a compact "how long" string --
/// used for `state_duration_ms` here and reused for session uptime on
/// the Daemon tab. Always already-elapsed (never a raw timestamp), so
/// this never needs to know "now".
fn fmt_duration_ms(ms: u64) -> String {
    let total_secs = ms / 1000;
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}
