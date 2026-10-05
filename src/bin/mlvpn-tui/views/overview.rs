//! Overview: the at-a-glance screen -- links, tunnel and reliability
//! summaries, and the most recent events.

use super::{links, panel, Density};
use crate::model::{tunnel_rates, SharedState};
use crate::theme::*;
use mlvpn::ipc::Snapshot;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph},
    Frame,
};

pub fn draw(f: &mut Frame, area: Rect, state: &SharedState, snap: &Snapshot, density: Density) {
    let links_h = links::table_height(snap, density)
        .min(area.height / 2)
        .max(3);

    if density == Density::Compact {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(links_h), Constraint::Min(0)])
            .split(area);
        links::render_table(f, parts[0], snap, None, "Links", density);
        events(f, parts[1], state, density);
        return;
    }

    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(links_h),
            Constraint::Length(8),
            Constraint::Min(3),
        ])
        .split(area);
    links::render_table(f, parts[0], snap, None, "Links", density);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(parts[1]);
    f.render_widget(
        Paragraph::new(tunnel_lines(snap)).block(panel("Tunnel")),
        mid[0],
    );
    f.render_widget(
        Paragraph::new(reliability_lines(snap)).block(panel("Reliability")),
        mid[1],
    );
    events(f, parts[2], state, density);
}

fn tunnel_lines(snap: &Snapshot) -> Vec<Line<'static>> {
    let t = &snap.daemon.telemetry;
    let (tx, rx) = tunnel_rates(snap);
    let up = snap.links.iter().filter(|l| l.state == "up").count();
    let mode = if t.scheduler_mode.is_empty() {
        "-".to_string()
    } else {
        t.scheduler_mode.clone()
    };
    let uptime = if t.health.is_empty() {
        "-".to_string()
    } else {
        fmt_duration_secs(t.tunnel_uptime_secs)
    };
    vec![
        kv(
            "Links up",
            format!("{up} of {}", snap.links.len()),
            Style::default(),
        ),
        kv("Scheduler", mode, Style::default()),
        kv(
            "Tx / Rx",
            format!("{} / {}", fmt_rate(tx), fmt_rate(rx)),
            Style::default(),
        ),
        kv(
            "MTU",
            snap.daemon.local_tunnel_mtu.to_string(),
            Style::default(),
        ),
        kv("Uptime", uptime, Style::default()),
        kv(
            "Version",
            snap.daemon.local_version.clone(),
            Style::default(),
        ),
    ]
}

pub fn fec_summary(snap: &Snapshot) -> String {
    let fec = &snap.daemon.telemetry.fec;
    if !fec.enabled {
        return "off".to_string();
    }
    let kind = if fec.parity >= 2 { "P+Q" } else { "XOR" };
    format!("{kind} 1-in-{} ({})", fec.group_size, fec.placement)
}

fn reliability_lines(snap: &Snapshot) -> Vec<Line<'static>> {
    let d = &snap.daemon;
    let t = &d.telemetry;
    let drops = d.outbound_queue_dropped_total + t.rx_pipeline_dropped_total;
    vec![
        kv("FEC", fec_summary(snap), Style::default()),
        kv(
            "FEC recovered",
            d.fec_recovered_total.to_string(),
            counter_style(d.fec_recovered_total, COLOR_GOOD),
        ),
        kv(
            "FEC unrecoverable",
            d.fec_unrecoverable_total.to_string(),
            counter_style(d.fec_unrecoverable_total, COLOR_BAD),
        ),
        kv(
            "Reorder depth",
            format!("{} (peak {})", t.reorder.depth, t.reorder.max_depth),
            Style::default(),
        ),
        kv(
            "Late frames",
            t.reorder.late_total.to_string(),
            counter_style(t.reorder.late_total, COLOR_WARN),
        ),
        kv("Drops", drops.to_string(), counter_style(drops, COLOR_BAD)),
    ]
}

pub fn events(f: &mut Frame, area: Rect, state: &SharedState, density: Density) {
    let block = panel("Recent events");
    let visible = if density == Density::Compact {
        area.height as usize
    } else {
        area.height.saturating_sub(2) as usize
    };
    let items: Vec<ListItem> = if state.events.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "no events yet",
            muted(),
        )))]
    } else {
        state
            .events
            .iter()
            .rev()
            .take(visible)
            .map(|e| ListItem::new(event_line(e)))
            .collect()
    };
    let list = List::new(items);
    f.render_widget(
        if density == Density::Compact {
            list
        } else {
            list.block(block)
        },
        area,
    );
}
