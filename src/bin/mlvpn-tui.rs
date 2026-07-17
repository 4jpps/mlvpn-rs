//! `mlvpn-tui`: a live monitoring view over an `mlvpnd` tunnel.
//!
//! Connects to the daemon's local control socket (see `control.rs` in the
//! `mlvpn` lib crate) and renders a continuously-updating table of every
//! bonded link: state, the peer address it's talking to, and both this
//! side's own measured RTT/jitter/loss/throughput *and* the peer's
//! self-reported view of the same link (received over the wire via
//! `StatsShare` frames -- see `protocol.rs`). Showing both sides at once
//! is the point: without it you'd need to SSH into both ends and compare
//! `mlvpnd` logs by hand to see the full picture of a link's health.
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
use mlvpn::ipc::{LinkSnapshot, Snapshot};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame, Terminal,
};
use std::io::{self, BufRead, BufReader, Stdout};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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

struct SharedState {
    snapshot: Option<Snapshot>,
    connected: bool,
    last_update: Option<Instant>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let socket_path = resolve_socket_path(cli.socket)?;
    let hostname = local_hostname();

    let state = Arc::new(Mutex::new(SharedState {
        snapshot: None,
        connected: false,
        last_update: None,
    }));

    {
        let state = state.clone();
        let socket_path = socket_path.clone();
        thread::spawn(move || reader_thread(socket_path, state));
    }

    let mut terminal = setup_terminal()?;
    let result = run_app(&mut terminal, &state, &socket_path, &hostname);
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

/// If the peer's `mlvpnd` predates `[control]` support, or the daemon
/// simply isn't running, there is nothing for this tool to connect to;
/// fail with a clear message up front rather than guessing.
fn resolve_socket_path(explicit: Option<String>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(PathBuf::from(p));
    }
    let dir = Path::new("/run/mlvpn");
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("sock") {
                found.push(path);
            }
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => anyhow::bail!(
            "no control socket found under {}; pass --socket explicitly, or check that mlvpnd \
             is running with [control] enabled (the default)",
            dir.display()
        ),
        _ => anyhow::bail!(
            "multiple control sockets found under {}: {found:?} -- pass --socket to pick one",
            dir.display()
        ),
    }
}

/// Runs forever on its own thread: connect, stream newline-delimited JSON
/// snapshots into `state` for as long as the connection lasts, and
/// reconnect on any error or EOF (the daemon may not have started yet, or
/// may restart mid-session -- neither should crash the viewer).
fn reader_thread(socket_path: PathBuf, state: Arc<Mutex<SharedState>>) {
    loop {
        match UnixStream::connect(&socket_path) {
            Ok(stream) => {
                state.lock().unwrap().connected = true;
                let reader = BufReader::new(stream);
                for line in reader.lines() {
                    match line {
                        Ok(text) => {
                            if let Ok(snapshot) = serde_json::from_str::<Snapshot>(&text) {
                                let mut s = state.lock().unwrap();
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
    socket_path: &Path,
    hostname: &str,
) -> anyhow::Result<()> {
    loop {
        {
            let s = state.lock().unwrap();
            terminal.draw(|f| draw(f, &s, socket_path, hostname))?;
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
            }
        }
    }
}

fn draw(f: &mut Frame, state: &SharedState, socket_path: &Path, hostname: &str) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(f, chunks[0], state, socket_path, hostname);
    draw_table(f, chunks[1], state);
    draw_footer(f, chunks[2], state);
}

fn draw_header(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    state: &SharedState,
    socket_path: &Path,
    hostname: &str,
) {
    let (title, style) = match &state.snapshot {
        Some(snap) => (
            format!(
                "mlvpn-tui  --  {}  --  tunnel '{}' ({})  --  {}",
                hostname,
                snap.tunnel_name,
                snap.mode,
                socket_path.display()
            ),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        None => (
            format!(
                "mlvpn-tui  --  {}  --  waiting for data from {}...",
                hostname,
                socket_path.display()
            ),
            Style::default().fg(Color::Yellow),
        ),
    };
    let block = Block::default().borders(Borders::ALL);
    let para = Paragraph::new(Line::from(Span::styled(title, style))).block(block);
    f.render_widget(para, area);
}

fn draw_table(f: &mut Frame, area: ratatui::layout::Rect, state: &SharedState) {
    let header = Row::new(vec![
        Cell::from("Link"),
        Cell::from("State"),
        Cell::from("Peer Addr"),
        Cell::from("Score"),
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
        Constraint::Length(12),
        Constraint::Length(9),
        Constraint::Length(21),
        Constraint::Length(7),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Links "))
        .column_spacing(1);

    f.render_widget(table, area);
}

fn link_row(l: &LinkSnapshot) -> Row<'static> {
    let state_style = state_style(&l.state);
    let peer_stale = l.peer_stats_age_ms.map(|a| a > 5000).unwrap_or(true);
    let peer_style = if peer_stale {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    };

    let local_text = format!(
        "rtt {}  jit {}  loss {}  {}",
        fmt_ms(l.local_rtt_ms),
        fmt_ms(l.local_jitter_ms),
        fmt_pct(l.local_loss_pct),
        fmt_mbps(l.local_throughput_mbps),
    );

    let peer_text = if l.peer_rtt_ms.is_none() && l.peer_name.is_none() {
        "(no StatsShare received yet)".to_string()
    } else {
        let age = l
            .peer_stats_age_ms
            .map(|a| format!(" [{:.1}s ago]", a as f64 / 1000.0))
            .unwrap_or_default();
        format!(
            "rtt {}  jit {}  loss {}  {}{age}",
            fmt_ms(l.peer_rtt_ms),
            fmt_ms(l.peer_jitter_ms),
            fmt_pct(l.peer_loss_pct),
            fmt_mbps(l.peer_throughput_mbps),
        )
    };

    Row::new(vec![
        Cell::from(l.name.clone()),
        Cell::from(l.state.clone()).style(state_style),
        Cell::from(l.remote_addr.clone().unwrap_or_else(|| "-".to_string())),
        Cell::from(format!("{:.2}", l.score)),
        Cell::from(local_text),
        Cell::from(peer_text).style(peer_style),
    ])
}

fn draw_footer(f: &mut Frame, area: ratatui::layout::Rect, state: &SharedState) {
    let status = if state.connected {
        match state.last_update {
            Some(t) if t.elapsed() < Duration::from_secs(3) => {
                Span::styled("connected", Style::default().fg(Color::Green))
            }
            Some(_) => Span::styled(
                "connected, no recent data",
                Style::default().fg(Color::Yellow),
            ),
            None => Span::styled(
                "connected, waiting for first snapshot",
                Style::default().fg(Color::Yellow),
            ),
        }
    } else {
        Span::styled(
            "disconnected -- retrying...",
            Style::default().fg(Color::Red),
        )
    };

    let line = Line::from(vec![
        Span::raw("q/Esc: quit   "),
        Span::raw("status: "),
        status,
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn state_style(s: &str) -> Style {
    match s {
        "up" => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        "down" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(Color::Yellow),
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
