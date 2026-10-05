//! Debug: connection details, the structured event list, and a
//! scrollable tail of the daemon's own log.

use super::{panel, Density};
use crate::model::{SharedState, Ui};
use crate::theme::*;
use mlvpn::ipc::LogEntry;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph},
    Frame,
};

pub fn draw(f: &mut Frame, area: Rect, state: &SharedState, ui: &Ui, density: Density) {
    if density == Density::Compact {
        return logs(f, area, state, ui, density);
    }
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Percentage(30),
            Constraint::Min(3),
        ])
        .split(area);
    f.render_widget(
        Paragraph::new(connection_lines(state)).block(panel("Connection")),
        parts[0],
    );
    super::overview::events(f, parts[1], state, density);
    logs(f, parts[2], state, ui, density);
}

fn connection_lines(state: &SharedState) -> Vec<Line<'static>> {
    let socket = state
        .socket_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(searching under /run/mlvpn)".into());
    let age = state
        .last_update
        .map(|t| format!("{:.1}s ago", t.elapsed().as_secs_f64()))
        .unwrap_or_else(|| "never".into());
    let tunnel = state
        .snapshot
        .as_ref()
        .map(|s| format!("'{}' ({})", s.tunnel_name, s.mode))
        .unwrap_or_else(|| "-".into());
    vec![
        kv("Socket", socket, Style::default()),
        kv(
            "Connection",
            if state.connected {
                "open".into()
            } else {
                "closed, retrying".into()
            },
            Style::default().fg(if state.connected {
                COLOR_GOOD
            } else {
                COLOR_BAD
            }),
        ),
        kv("Last snapshot", age, Style::default()),
        kv("Tunnel", tunnel, Style::default()),
        kv(
            "Buffered",
            format!(
                "{} events, {} log lines",
                state.events.len(),
                state.logs.len()
            ),
            muted(),
        ),
    ]
}

fn logs(f: &mut Frame, area: Rect, state: &SharedState, ui: &Ui, density: Density) {
    let title = if ui.log_scroll == 0 {
        "Logs".to_string()
    } else {
        format!(
            "Logs (scrolled up {} -- Down/PgDn to follow)",
            ui.log_scroll
        )
    };
    let visible = if density == Density::Compact {
        area.height as usize
    } else {
        area.height.saturating_sub(2) as usize
    };
    let total = state.logs.len();
    let end = total.saturating_sub(ui.log_scroll.min(total));
    let start = end.saturating_sub(visible);
    let items: Vec<ListItem> = state
        .logs
        .range(start..end)
        .map(|e| ListItem::new(log_line(e)))
        .collect();
    let list = List::new(items);
    f.render_widget(
        if density == Density::Compact {
            list
        } else {
            list.block(panel(&title))
        },
        area,
    );
}

fn log_line(e: &LogEntry) -> Line<'static> {
    let level = match e.level.as_str() {
        "ERROR" => bold(COLOR_BAD),
        "WARN" => Style::default().fg(COLOR_WARN),
        _ => Style::default(),
    };
    Line::from(vec![
        Span::styled(fmt_log_timestamp(e.unix_ts_ms), muted()),
        Span::raw(" "),
        Span::styled(format!("{:5}", e.level), level),
        Span::raw(" "),
        Span::styled(
            format!("{:24}", truncate(e.target.as_deref().unwrap_or("-"), 24)),
            muted(),
        ),
        Span::raw(" "),
        Span::raw(e.message.clone()),
    ])
}
