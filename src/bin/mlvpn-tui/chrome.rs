//! Screen chrome: health banner, tab bar, footer, and the body area.

use crate::model::{Health, SharedState, Tab, Ui};
use crate::theme::*;
use crate::views::{self, Density};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn draw(f: &mut Frame, state: &SharedState, ui: &Ui, hostname: &str) {
    let area = f.area();
    let density = Density::for_area(area);
    let compact = density == Density::Compact;

    let banner_h = if compact { 1 } else { 3 };
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_h),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    banner(f, parts[0], state, hostname, compact);
    tab_bar(f, parts[1], ui.tab, compact);
    views::draw_body(f, parts[2], state, ui, density);
    footer(f, parts[3], state, ui, compact);
}

fn banner(f: &mut Frame, area: Rect, state: &SharedState, hostname: &str, compact: bool) {
    let (health, reason) = state.health();
    let style = Style::default()
        .fg(health.color())
        .add_modifier(Modifier::BOLD);

    let mut spans = vec![
        Span::styled(format!("{} {}", health.symbol(), health.label()), style),
        Span::raw(format!(" - {reason}")),
    ];
    if !compact {
        let ctx = match &state.snapshot {
            Some(s) => {
                let secs = s.daemon.telemetry.tunnel_uptime_secs;
                let up = if secs > 0 {
                    format!(" · up {}", fmt_duration_secs(secs))
                } else {
                    String::new()
                };
                format!(
                    "   {hostname} · tunnel '{}' ({}){up}",
                    s.tunnel_name, s.mode
                )
            }
            None => format!("   {hostname}"),
        };
        spans.push(Span::styled(ctx, muted()));
    }

    if compact {
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    } else {
        let border = Style::default().fg(if health == Health::Healthy {
            COLOR_MUTED
        } else {
            health.color()
        });
        f.render_widget(
            Paragraph::new(Line::from(spans))
                .block(Block::default().borders(Borders::ALL).border_style(border)),
            area,
        );
    }
}

fn tab_bar(f: &mut Frame, area: Rect, active: Tab, compact: bool) {
    let mut spans = Vec::new();
    for (i, t) in Tab::ALL.iter().enumerate() {
        let title = if compact { t.short_title() } else { t.title() };
        let label = format!(" {} {} ", i + 1, title);
        let style = if *t == active {
            Style::default()
                .fg(COLOR_ACCENT)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            muted()
        };
        spans.push(Span::styled(label, style));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn footer(f: &mut Frame, area: Rect, state: &SharedState, ui: &Ui, compact: bool) {
    let hints = match ui.tab {
        Tab::Links => "↑↓ select · Enter detail · Tab/1-6 views · q quit",
        Tab::Debug => "↑↓/PgUp/PgDn scroll logs · Tab/1-6 views · q quit",
        _ => "Tab/Shift-Tab or 1-6 switch views · q quit",
    };
    let hints = if compact { "Tab/1-6 · q quit" } else { hints };

    let conn = if state.connected {
        match state.last_update {
            Some(t) => format!("live ({:.1}s)", t.elapsed().as_secs_f64()),
            None => "connected".to_string(),
        }
    } else {
        "disconnected".to_string()
    };
    let conn_style = if state.is_fresh() {
        Style::default().fg(COLOR_GOOD)
    } else {
        Style::default().fg(COLOR_BAD)
    };
    let sock = match (&state.socket_path, compact) {
        (Some(p), false) => format!("  {}", p.display()),
        _ => String::new(),
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(hints, muted()),
            Span::raw("  "),
            Span::styled(conn, conn_style),
            Span::styled(sock, muted()),
        ])),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Health;
    use mlvpn::ipc::{EventRecord, LinkSnapshot, LogEntry, Snapshot};
    use ratatui::{backend::TestBackend, Terminal};

    fn link(name: &str, state: &str, score: f64) -> LinkSnapshot {
        LinkSnapshot {
            name: name.into(),
            state: state.into(),
            score,
            local_rtt_ms: Some(12.5),
            local_loss_pct: Some(0.4),
            local_tx_throughput_mbps: Some(42.0),
            local_rx_throughput_mbps: Some(7.0),
            ..Default::default()
        }
    }

    fn snapshot(health: &str) -> Snapshot {
        let mut s = Snapshot {
            tunnel_name: "t0".into(),
            mode: "client".into(),
            unix_ts_ms: 1_700_000_000_000,
            links: vec![
                link("wan1", "up", 0.9),
                link("a-very-long-link-name-indeed", "down", 0.0),
                link("lte", "probing", 0.4),
            ],
            daemon: Default::default(),
            new_log_lines: vec![LogEntry {
                seq: 1,
                unix_ts_ms: 1_700_000_000_000,
                level: "WARN".into(),
                target: Some("mlvpn::link".into()),
                message: "something happened".into(),
            }],
            new_events: vec![EventRecord {
                seq: 1,
                unix_ts_ms: 1_700_000_000_000,
                severity: "warn".into(),
                kind: "LINK_DOWN".into(),
                link: Some("wan1".into()),
                message: "link wan1 went down".into(),
                fields: Default::default(),
            }],
        };
        s.daemon.telemetry.health = health.into();
        s.daemon.telemetry.health_reason = "test reason".into();
        s.daemon.outbound_queue_capacity = 100;
        s.daemon.outbound_queue_len = 30;
        s
    }

    fn render(state: &SharedState, ui: &Ui, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| draw(f, state, ui, "host")).unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn every_view_renders_at_every_size_without_panicking() {
        let sizes = [
            (120, 40),
            (80, 24),
            (79, 19),
            (60, 12),
            (40, 10),
            (20, 5),
            (10, 3),
            (1, 1),
        ];
        for with_snapshot in [false, true] {
            for connected in [false, true] {
                for tab in Tab::ALL {
                    for detail in [false, true] {
                        let mut state = SharedState::new(None);
                        if with_snapshot {
                            state.on_connect();
                            state.ingest(snapshot("DEGRADED"));
                        }
                        state.connected = connected;
                        let ui = Ui {
                            tab,
                            link_selected: 1,
                            link_detail: detail,
                            log_scroll: 3,
                        };
                        for (w, h) in sizes {
                            render(&state, &ui, w, h);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn banner_shows_health_state_and_reason() {
        let mut state = SharedState::new(None);
        state.on_connect();
        state.ingest(snapshot("DEGRADED"));
        let out = render(&state, &Ui::default(), 120, 40);
        assert!(out.contains("DEGRADED"), "{out}");
        assert!(out.contains("test reason"), "{out}");
        assert!(out.contains("tunnel 't0'"), "{out}");
    }

    #[test]
    fn disconnected_overrides_last_snapshot_in_banner() {
        let mut state = SharedState::new(None);
        state.on_connect();
        state.ingest(snapshot("HEALTHY"));
        state.connected = false;
        assert_eq!(state.health().0, Health::Disconnected);
        let out = render(&state, &Ui::default(), 120, 40);
        assert!(out.contains("DISCONNECTED"), "{out}");
    }

    #[test]
    fn compact_layout_keeps_banner_and_links_on_screen() {
        let mut state = SharedState::new(None);
        state.on_connect();
        state.ingest(snapshot("FAILOVER"));
        let out = render(&state, &Ui::default(), 60, 12);
        assert!(out.contains("FAILOVER"), "{out}");
        assert!(out.contains("wan1"), "{out}");
    }

    #[test]
    fn tab_bar_lists_all_six_views() {
        let state = SharedState::new(None);
        let out = render(&state, &Ui::default(), 120, 30);
        for t in Tab::ALL {
            assert!(out.contains(t.title()), "missing {}: {out}", t.title());
        }
    }
}
