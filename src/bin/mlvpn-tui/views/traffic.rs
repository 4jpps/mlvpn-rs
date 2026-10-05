//! Traffic: tunnel and per-link rates as bars plus a rolling sparkline.

use super::{panel, Density};
use crate::model::{bar, spark, tunnel_rates, SharedState};
use crate::theme::*;
use mlvpn::ipc::Snapshot;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn draw(f: &mut Frame, area: Rect, state: &SharedState, snap: &Snapshot, density: Density) {
    let compact = density == Density::Compact;
    let (tx, rx) = tunnel_rates(snap);
    let tx_hist = state.history.tunnel_tx.values();
    let rx_hist = state.history.tunnel_rx.values();

    // One shared scale so Tx and Rx bars are comparable.
    let scale = tx_hist
        .iter()
        .chain(rx_hist.iter())
        .copied()
        .fold(tx.max(rx), f64::max)
        .max(1.0);

    let inner_w = if compact {
        area.width
    } else {
        area.width.saturating_sub(2)
    } as usize;
    // label(3) + rate(12) + spaces; remaining split bar:spark.
    let room = inner_w.saturating_sub(3 + 1 + 12 + 2);
    let bar_w = (room / 2).clamp(0, 30);
    let spark_w = room.saturating_sub(bar_w).min(60);

    let tunnel = vec![
        rate_line("Tx", tx, scale, bar_w, spark_w, &tx_hist, COLOR_ACCENT),
        rate_line("Rx", rx, scale, bar_w, spark_w, &rx_hist, COLOR_GOOD),
    ];

    let link_count = snap.links.len() as u16;
    let tunnel_h = if compact { 2 } else { 4 };
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(tunnel_h),
            Constraint::Min(link_count.max(1)),
        ])
        .split(area);
    f.render_widget(
        if compact {
            Paragraph::new(tunnel)
        } else {
            Paragraph::new(tunnel).block(panel("Tunnel (last minute)"))
        },
        parts[0],
    );

    let total_tx: f64 = snap
        .links
        .iter()
        .filter(|l| l.state == "up")
        .map(|l| l.local_tx_throughput_mbps.unwrap_or(0.0))
        .sum();
    let link_scale = snap
        .links
        .iter()
        .flat_map(|l| {
            [
                l.local_tx_throughput_mbps.unwrap_or(0.0),
                l.local_rx_throughput_mbps.unwrap_or(0.0),
            ]
        })
        .fold(1.0, f64::max);

    let name_w = snap
        .links
        .iter()
        .map(|l| l.name.chars().count())
        .max()
        .unwrap_or(4)
        .clamp(4, 14);
    // symbol+name, two "Tx/Rx <rate>" cells, and the "tx share NNN%" tail.
    let lroom = inner_w.saturating_sub(name_w + 2 + 2 * (3 + 12) + 13);
    let lbar = if compact {
        0
    } else {
        (lroom / 2).saturating_sub(1).min(20)
    };

    let mut lines: Vec<Line> = Vec::new();
    for l in &snap.links {
        let ltx = l.local_tx_throughput_mbps.unwrap_or(0.0);
        let lrx = l.local_rx_throughput_mbps.unwrap_or(0.0);
        let share = if l.state == "up" && total_tx > 0.0 {
            format!("{:>3.0}%", ltx / total_tx * 100.0)
        } else {
            "  - ".to_string()
        };
        let mut spans = vec![
            Span::styled(
                format!("{} ", state_symbol(&l.state)),
                state_style(&l.state),
            ),
            Span::raw(format!("{:<name_w$} ", truncate(&l.name, name_w))),
            Span::styled("Tx ", muted()),
            Span::raw(format!("{:>11} ", fmt_rate(ltx))),
        ];
        if lbar > 0 {
            spans.push(Span::styled(
                format!("{} ", bar(ltx / link_scale, lbar)),
                Style::default().fg(COLOR_ACCENT),
            ));
        }
        spans.push(Span::styled("Rx ", muted()));
        spans.push(Span::raw(format!("{:>11} ", fmt_rate(lrx))));
        if lbar > 0 {
            spans.push(Span::styled(
                format!("{} ", bar(lrx / link_scale, lbar)),
                Style::default().fg(COLOR_GOOD),
            ));
        }
        spans.push(Span::styled(format!("tx share {share}"), muted()));
        lines.push(Line::from(spans));

        if !compact {
            if let Some(h) = state.history.link_total.get(&l.name) {
                let w = inner_w.saturating_sub(name_w + 4).min(60);
                lines.push(Line::from(vec![
                    Span::raw(" ".repeat(name_w + 3)),
                    Span::styled(spark(&h.values(), w, 0.0), muted()),
                ]));
            }
        }
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled("no links", muted())));
    }
    f.render_widget(
        if compact {
            Paragraph::new(lines)
        } else {
            Paragraph::new(lines).block(panel("Links"))
        },
        parts[1],
    );
}

fn rate_line(
    label: &str,
    now: f64,
    scale: f64,
    bar_w: usize,
    spark_w: usize,
    hist: &[f64],
    color: ratatui::style::Color,
) -> Line<'static> {
    let mut spans = vec![
        Span::styled(format!("{label} "), bold(color)),
        Span::raw(format!("{:>11} ", fmt_rate(now))),
    ];
    if bar_w > 0 {
        spans.push(Span::styled(
            format!("{} ", bar(now / scale, bar_w)),
            Style::default().fg(color),
        ));
    }
    if spark_w > 0 {
        spans.push(Span::styled(spark(hist, spark_w, scale), muted()));
    }
    Line::from(spans)
}
