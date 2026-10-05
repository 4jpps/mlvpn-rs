//! Reliability: FEC, reorder buffer, and every drop/error counter, with
//! nonzero values highlighted so a clean tunnel reads as a quiet screen.

use super::{overview::fec_summary, panel, Density};
use crate::theme::*;
use mlvpn::ipc::Snapshot;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

fn count(label: &str, v: u64, nonzero: Color) -> Line<'static> {
    kv(label, v.to_string(), counter_style(v, nonzero))
}

fn fec_lines(snap: &Snapshot) -> Vec<Line<'static>> {
    let d = &snap.daemon;
    vec![
        kv("Mode", fec_summary(snap), Style::default()),
        count("Groups sent", d.fec_groups_sent_total, COLOR_ACCENT),
        Line::from(vec![
            Span::styled("Parity sent: ", muted()),
            Span::raw(format!(
                "P {}   Q {}",
                d.fec_parity_p_sent_total, d.fec_parity_q_sent_total
            )),
        ]),
        count("Recovered (rx)", d.fec_recovered_total, COLOR_GOOD),
        count("Unrecoverable", d.fec_unrecoverable_total, COLOR_BAD),
    ]
}

fn reorder_lines(snap: &Snapshot) -> Vec<Line<'static>> {
    let r = &snap.daemon.telemetry.reorder;
    vec![
        kv("Window", format!("{} ms", r.window_ms), Style::default()),
        kv(
            "Depth now / peak",
            format!("{} / {}", r.depth, r.max_depth),
            Style::default(),
        ),
        kv(
            "Wait recent / max",
            format!(
                "{} / {}",
                fmt_us_as_ms(r.wait_recent_us),
                fmt_us_as_ms(r.wait_max_us)
            ),
            Style::default(),
        ),
        count("Late frames", r.late_total, COLOR_WARN),
        count("Duplicates", r.duplicate_total, COLOR_WARN),
        count("Timed out", r.timeout_total, COLOR_WARN),
    ]
}

fn drop_lines(snap: &Snapshot) -> Vec<Line<'static>> {
    let d = &snap.daemon;
    let t = &d.telemetry;
    let sum = |f: fn(&mlvpn::ipc::LinkSnapshot) -> u64| snap.links.iter().map(f).sum::<u64>();
    let tun_drops = d.tun.rx_dropped.unwrap_or(0) + d.tun.tx_dropped.unwrap_or(0);
    let tun_errs = d.tun.rx_errors.unwrap_or(0) + d.tun.tx_errors.unwrap_or(0);
    vec![
        count(
            "Outbound queue drops",
            d.outbound_queue_dropped_total,
            COLOR_BAD,
        ),
        count("Rx pipeline drops", t.rx_pipeline_dropped_total, COLOR_BAD),
        count("TUN drops", tun_drops, COLOR_BAD),
        count("TUN errors", tun_errs, COLOR_BAD),
        count(
            "Link tx queue full",
            sum(|l| l.tx_queue_full_total),
            COLOR_WARN,
        ),
        count(
            "Link send failures",
            sum(|l| l.tx_send_failed_total),
            COLOR_BAD,
        ),
        count("WireGuard rejected", d.wg_rejected_total, COLOR_BAD),
        count("WireGuard substituted", d.wg_substituted_total, COLOR_BAD),
        count("Rerouted frames", t.reroutes_total, COLOR_WARN),
    ]
}

pub fn draw(f: &mut Frame, area: Rect, snap: &Snapshot, density: Density) {
    let fec = fec_lines(snap);
    let reorder = reorder_lines(snap);
    let drops = drop_lines(snap);

    if density == Density::Compact {
        let mut lines = Vec::new();
        for (title, body) in [
            ("FEC", fec),
            ("Reorder", reorder),
            ("Drops and errors", drops),
        ] {
            lines.push(Line::from(Span::styled(title, bold(COLOR_ACCENT))));
            lines.extend(body);
        }
        f.render_widget(Paragraph::new(lines), area);
        return;
    }

    let drops_h = drops.len() as u16 + 2;
    let top_h = fec.len().max(reorder.len()) as u16 + 2;
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(top_h), Constraint::Min(drops_h)])
        .split(area);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(parts[0]);
    f.render_widget(Paragraph::new(fec).block(panel("FEC")), top[0]);
    f.render_widget(
        Paragraph::new(reorder).block(panel("Reorder buffer")),
        top[1],
    );
    f.render_widget(
        Paragraph::new(drops).block(panel("Drops and errors")),
        parts[1],
    );
}
