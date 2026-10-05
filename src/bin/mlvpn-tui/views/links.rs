//! Links: a compact one-row-per-link table, with an Enter-toggled
//! drill-down holding every counter for the selected link.

use super::{panel, Density};
use crate::model::Ui;
use crate::theme::*;
use mlvpn::ipc::{LinkSnapshot, Snapshot};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Cell, Paragraph, Row, Table},
    Frame,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Col {
    Link,
    State,
    Role,
    UpFor,
    Rtt,
    Jitter,
    Loss,
    Rx,
    Tx,
    Score,
    Flags,
}

fn columns(width: u16) -> Vec<Col> {
    if width >= 110 {
        vec![
            Col::Link,
            Col::State,
            Col::Role,
            Col::UpFor,
            Col::Rtt,
            Col::Jitter,
            Col::Loss,
            Col::Rx,
            Col::Tx,
            Col::Score,
            Col::Flags,
        ]
    } else if width >= 80 {
        vec![
            Col::Link,
            Col::State,
            Col::Role,
            Col::Rtt,
            Col::Loss,
            Col::Rx,
            Col::Tx,
            Col::Flags,
        ]
    } else if width >= 50 {
        vec![
            Col::Link,
            Col::State,
            Col::Rtt,
            Col::Loss,
            Col::Tx,
            Col::Flags,
        ]
    } else {
        vec![Col::Link, Col::State, Col::Loss]
    }
}

fn header(c: Col) -> &'static str {
    match c {
        Col::Link => "Link",
        Col::State => "State",
        Col::Role => "Role",
        Col::UpFor => "For",
        Col::Rtt => "RTT",
        Col::Jitter => "Jitter",
        Col::Loss => "Loss",
        Col::Rx => "Rx",
        Col::Tx => "Tx",
        Col::Score => "Score",
        Col::Flags => "Flags",
    }
}

fn width_of(c: Col) -> Constraint {
    match c {
        Col::Link => Constraint::Min(8),
        Col::State => Constraint::Length(9),
        Col::Role => Constraint::Length(8),
        Col::UpFor => Constraint::Length(7),
        Col::Rtt | Col::Jitter => Constraint::Length(8),
        Col::Loss => Constraint::Length(6),
        Col::Rx | Col::Tx => Constraint::Length(11),
        Col::Score => Constraint::Length(5),
        Col::Flags => Constraint::Length(10),
    }
}

fn role(l: &LinkSnapshot, any_primary: bool) -> (&'static str, Style) {
    if l.is_primary {
        ("Primary", bold(COLOR_GOOD))
    } else if any_primary {
        ("Failover", muted())
    } else if l.state == "up" {
        ("Bonded", Style::default().fg(COLOR_ACCENT))
    } else {
        ("", Style::default())
    }
}

/// Short problem tokens: DEG (congestion-degraded), QF (tx queue full
/// seen), ERR (send failures or WireGuard rejects/substitutions).
fn flags(l: &LinkSnapshot) -> (String, Style) {
    let mut out = Vec::new();
    let mut style = Style::default().fg(COLOR_WARN);
    if l.degraded {
        out.push("DEG");
    }
    if l.tx_queue_full_total > 0 {
        out.push("QF");
    }
    if l.tx_send_failed_total > 0 || l.wg_rejected_total > 0 || l.wg_substituted_total > 0 {
        out.push("ERR");
        style = Style::default().fg(COLOR_BAD);
    }
    if out.is_empty() {
        ("-".to_string(), muted())
    } else {
        (out.join(" "), style)
    }
}

fn cell(c: Col, l: &LinkSnapshot, any_primary: bool) -> Cell<'static> {
    match c {
        Col::Link => Cell::from(l.name.clone()),
        Col::State => Cell::from(format!("{} {}", state_symbol(&l.state), l.state))
            .style(state_style(&l.state)),
        Col::Role => {
            let (t, s) = role(l, any_primary);
            Cell::from(t).style(s)
        }
        Col::UpFor => Cell::from(fmt_duration_ms(l.state_duration_ms)),
        Col::Rtt => Cell::from(fmt_ms(l.local_rtt_ms)),
        Col::Jitter => Cell::from(fmt_ms(l.local_jitter_ms)),
        Col::Loss => Cell::from(fmt_pct(l.local_loss_pct)).style(loss_style(l.local_loss_pct)),
        Col::Rx => Cell::from(fmt_mbps(l.local_rx_throughput_mbps)),
        Col::Tx => Cell::from(fmt_mbps(l.local_tx_throughput_mbps)),
        Col::Score => Cell::from(format!("{:.2}", l.score)).style(score_style(l.score)),
        Col::Flags => {
            let (t, s) = flags(l);
            Cell::from(t).style(s)
        }
    }
}

/// The compact table, shared with the Overview. `selected` highlights one
/// row (reverse video) when `Some`.
pub fn render_table(
    f: &mut Frame,
    area: Rect,
    snap: &Snapshot,
    selected: Option<usize>,
    title: &str,
    density: Density,
) {
    let cols = columns(area.width);
    let any_primary = snap.links.iter().any(|l| l.is_primary);
    let rows: Vec<Row> = snap
        .links
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let row = Row::new(cols.iter().map(|c| cell(*c, l, any_primary)));
            if selected == Some(i) {
                row.style(Style::default().add_modifier(Modifier::REVERSED))
            } else {
                row
            }
        })
        .collect();
    let header = Row::new(cols.iter().map(|c| header(*c))).style(muted());
    let table = Table::new(rows, cols.iter().map(|c| width_of(*c)).collect::<Vec<_>>())
        .header(header)
        .column_spacing(1);
    let table = if density == Density::Compact {
        table
    } else {
        table.block(panel(title))
    };
    f.render_widget(table, area);
}

/// Rows the table needs: links + header (+ borders when Normal).
pub fn table_height(snap: &Snapshot, density: Density) -> u16 {
    let rows = snap.links.len() as u16 + 1;
    if density == Density::Normal {
        rows + 2
    } else {
        rows
    }
}

pub fn draw(f: &mut Frame, area: Rect, snap: &Snapshot, ui: &Ui, density: Density) {
    if snap.links.is_empty() {
        return super::waiting(f, area, "Links");
    }
    let sel = ui.link_selected.min(snap.links.len() - 1);
    let table_h = table_height(snap, density);

    if !ui.link_detail {
        return render_table(f, area, snap, Some(sel), "Links", density);
    }
    // Not enough room for both: show just the detail.
    if area.height < table_h + 12 {
        return render_detail(f, area, &snap.links[sel]);
    }
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(table_h), Constraint::Min(0)])
        .split(area);
    render_table(f, parts[0], snap, Some(sel), "Links", density);
    render_detail(f, parts[1], &snap.links[sel]);
}

fn render_detail(f: &mut Frame, area: Rect, l: &LinkSnapshot) {
    let (role_text, _) = role(l, false);
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled(
            format!("{} {}", state_symbol(&l.state), l.state),
            state_style(&l.state),
        ),
        Span::raw(format!(
            " for {}   iface {}   local port {}   remote {}",
            fmt_duration_ms(l.state_duration_ms),
            l.bind_interface,
            l.local_port,
            l.remote_addr.as_deref().unwrap_or("-")
        )),
    ]));
    lines.push(Line::from(format!(
        "role {}   score {:.2}   congestion share x{:.2}{}",
        if l.is_primary { "Primary" } else { role_text },
        l.score,
        l.congestion_factor,
        if l.degraded { "   DEGRADED" } else { "" }
    )));
    lines.push(Line::raw(""));

    lines.push(section("This side"));
    lines.push(Line::from(vec![
        Span::raw(format!(
            "rtt {}  jitter {}  loss ",
            fmt_ms(l.local_rtt_ms),
            fmt_ms(l.local_jitter_ms)
        )),
        Span::styled(fmt_pct(l.local_loss_pct), loss_style(l.local_loss_pct)),
        Span::raw(format!(
            "   rx {}  tx {}",
            fmt_mbps(l.local_rx_throughput_mbps),
            fmt_mbps(l.local_tx_throughput_mbps)
        )),
    ]));
    lines.push(Line::from(match l.local_active_bandwidth_mbps {
        None => Span::styled("probe: off, or no result yet", muted()),
        Some(a) => Span::raw(format!(
            "probe: {} (confirmed ceiling {})",
            fmt_mbps(Some(a)),
            fmt_mbps(l.local_confirmed_ceiling_mbps)
        )),
    }));

    lines.push(section("Peer's view"));
    if l.peer_rtt_ms.is_none() && l.peer_name.is_none() {
        lines.push(Line::from(Span::styled(
            "(no StatsShare received yet)",
            muted(),
        )));
    } else {
        let stale = l.peer_stats_age_ms.map(|a| a > 5000).unwrap_or(true);
        let base = if stale { muted() } else { Style::default() };
        let age = l
            .peer_stats_age_ms
            .map(|a| format!("   [{:.1}s ago]", a as f64 / 1000.0))
            .unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled(
                format!(
                    "rtt {}  jitter {}  loss ",
                    fmt_ms(l.peer_rtt_ms),
                    fmt_ms(l.peer_jitter_ms)
                ),
                base,
            ),
            Span::styled(
                fmt_pct(l.peer_loss_pct),
                if stale {
                    base
                } else {
                    loss_style(l.peer_loss_pct)
                },
            ),
            Span::styled(
                format!("   {}{age}", fmt_mbps(l.peer_throughput_mbps)),
                base,
            ),
        ]));
    }

    lines.push(section("Totals"));
    lines.push(Line::from(format!(
        "tx {} ({} pkts)   rx {} ({} pkts)",
        fmt_bytes(l.tx_bytes),
        l.tx_packets,
        fmt_bytes(l.rx_bytes),
        l.rx_packets
    )));

    lines.push(section("Send queue"));
    lines.push(Line::from(format!(
        "depth {}   delay {} (max {})   send wait {}",
        l.tx_queue_depth,
        fmt_us_as_ms(l.tx_queue_delay_us),
        fmt_us_as_ms(l.tx_queue_delay_max_us),
        fmt_us_as_ms(l.tx_send_wait_us),
    )));

    lines.push(section("Errors"));
    lines.push(Line::from(vec![
        counter("queue full", l.tx_queue_full_total, COLOR_WARN),
        Span::raw("   "),
        counter("send failed", l.tx_send_failed_total, COLOR_BAD),
        Span::raw("   "),
        counter("rerouted away", l.tx_rerouted_total, COLOR_WARN),
    ]));
    lines.push(Line::from(vec![
        counter("wg rejected", l.wg_rejected_total, COLOR_BAD),
        Span::raw("   "),
        counter("wg substituted", l.wg_substituted_total, COLOR_BAD),
    ]));

    f.render_widget(
        Paragraph::new(Text::from(lines)).block(panel(&format!("Link {}", l.name))),
        area,
    );
}

fn section(name: &str) -> Line<'static> {
    Line::from(Span::styled(
        name.to_string(),
        Style::default()
            .fg(COLOR_ACCENT)
            .add_modifier(Modifier::BOLD),
    ))
}

fn counter(label: &str, v: u64, nonzero: Color) -> Span<'static> {
    Span::styled(format!("{label} {v}"), counter_style(v, nonzero))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_sets_shrink_with_width() {
        let w = columns(120).len();
        let m = columns(90).len();
        let n = columns(60).len();
        let t = columns(30).len();
        assert!(w > m && m > n && n > t);
        for width in [30, 60, 90, 120] {
            let c = columns(width);
            assert_eq!(c[0], Col::Link, "link name always leads");
            assert!(c.contains(&Col::State));
        }
    }

    #[test]
    fn flags_escalate_to_err() {
        let mut l = LinkSnapshot::default();
        assert_eq!(flags(&l).0, "-");
        l.degraded = true;
        assert_eq!(flags(&l).0, "DEG");
        l.tx_queue_full_total = 3;
        assert_eq!(flags(&l).0, "DEG QF");
        l.wg_rejected_total = 1;
        assert_eq!(flags(&l).0, "DEG QF ERR");
        assert_eq!(flags(&l).1.fg, Some(COLOR_BAD));
    }
}
