//! System: host load/memory, the daemon process, TUN counters, the
//! outbound queue, and version/MTU agreement with the peer.

use super::{panel, Density};
use crate::model::bar;
use crate::theme::*;
use mlvpn::ipc::{DaemonSnapshot, Snapshot};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

fn host_lines(d: &DaemonSnapshot) -> Vec<Line<'static>> {
    let s = &d.system;
    let mem = match (s.mem_total_kb, s.mem_available_kb) {
        (Some(total), Some(avail)) if total > 0 => {
            let used = total.saturating_sub(avail);
            let pct = used as f64 / total as f64 * 100.0;
            Line::from(vec![
                Span::styled("Memory: ", muted()),
                Span::raw(format!(
                    "{} / {} ",
                    fmt_bytes(used * 1024),
                    fmt_bytes(total * 1024)
                )),
                Span::styled(format!("{pct:.0}% "), pct_used_style(pct)),
                Span::styled(bar(pct / 100.0, 10), pct_used_style(pct)),
            ])
        }
        _ => kv("Memory", "-".into(), muted()),
    };
    vec![
        kv(
            "Load",
            format!(
                "{} {} {}",
                fmt_load(s.load1),
                fmt_load(s.load5),
                fmt_load(s.load15)
            ),
            Style::default(),
        ),
        mem,
        kv(
            "Uptime",
            s.uptime_secs
                .map(fmt_duration_secs)
                .unwrap_or_else(|| "-".into()),
            Style::default(),
        ),
    ]
}

fn process_lines(d: &DaemonSnapshot) -> Vec<Line<'static>> {
    let p = &d.telemetry.process;
    vec![
        kv("CPU", fmt_pct(p.cpu_pct), Style::default()),
        kv(
            "Resident memory",
            fmt_bytes_opt(p.rss_kb.map(|k| k * 1024)),
            Style::default(),
        ),
        kv("Threads", fmt_opt_u64(p.threads), Style::default()),
        kv("Open files", fmt_opt_u64(p.open_fds), Style::default()),
    ]
}

fn tun_lines(d: &DaemonSnapshot) -> Vec<Line<'static>> {
    let t = &d.tun;
    let bad = t.rx_errors.unwrap_or(0)
        + t.tx_errors.unwrap_or(0)
        + t.rx_dropped.unwrap_or(0)
        + t.tx_dropped.unwrap_or(0);
    vec![
        kv("Interface", t.iface.clone(), Style::default()),
        kv(
            "Rx / Tx",
            format!(
                "{} / {}",
                fmt_bytes_opt(t.rx_bytes),
                fmt_bytes_opt(t.tx_bytes)
            ),
            Style::default(),
        ),
        kv(
            "Errors rx/tx",
            format!(
                "{} / {}",
                fmt_opt_u64(t.rx_errors),
                fmt_opt_u64(t.tx_errors)
            ),
            counter_style(bad, COLOR_BAD),
        ),
        kv(
            "Dropped rx/tx",
            format!(
                "{} / {}",
                fmt_opt_u64(t.rx_dropped),
                fmt_opt_u64(t.tx_dropped)
            ),
            counter_style(bad, COLOR_BAD),
        ),
    ]
}

fn queue_lines(d: &DaemonSnapshot) -> Vec<Line<'static>> {
    let ratio = if d.outbound_queue_capacity > 0 {
        d.outbound_queue_len as f64 / d.outbound_queue_capacity as f64
    } else {
        0.0
    };
    let style = if ratio > 0.75 {
        Style::default().fg(COLOR_BAD)
    } else if ratio > 0.25 {
        Style::default().fg(COLOR_WARN)
    } else {
        Style::default().fg(COLOR_GOOD)
    };
    vec![
        Line::from(vec![
            Span::styled("Fill: ", muted()),
            Span::styled(bar(ratio, 12), style),
            Span::raw(format!(
                " {} / {}",
                d.outbound_queue_len, d.outbound_queue_capacity
            )),
        ]),
        kv(
            "Dropped (lifetime)",
            d.outbound_queue_dropped_total.to_string(),
            counter_style(d.outbound_queue_dropped_total, COLOR_BAD),
        ),
    ]
}

fn version_line(d: &DaemonSnapshot) -> Line<'static> {
    let mut spans = vec![
        Span::styled("Version: ", muted()),
        Span::raw(d.local_version.clone()),
    ];
    match &d.peer_version {
        Some(p) if *p == d.local_version => spans.push(Span::styled(" (peer matches)", muted())),
        Some(p) => {
            spans.push(Span::raw("   Peer: "));
            spans.push(Span::styled(
                format!("{p} (MISMATCH)"),
                Style::default().fg(COLOR_BAD),
            ));
        }
        None => spans.push(Span::styled("   Peer: unknown", muted())),
    }
    Line::from(spans)
}

/// The peer's *capability* MTU above ours is normal (negotiation takes
/// the minimum); only a peer *applied* MTU different from ours, or a
/// capability below ours, means negotiation has not converged.
fn mtu_line(d: &DaemonSnapshot) -> Line<'static> {
    let mut spans = vec![
        Span::styled("Tunnel MTU: ", muted()),
        Span::raw(d.local_tunnel_mtu.to_string()),
    ];
    match (d.peer_applied_tunnel_mtu, d.peer_tunnel_mtu) {
        (Some(applied), _) if applied == d.local_tunnel_mtu => {
            spans.push(Span::styled(" (peer matches)", muted()))
        }
        (Some(applied), _) => {
            spans.push(Span::raw("   Peer applied: "));
            spans.push(Span::styled(
                format!("{applied} (not converged)"),
                Style::default().fg(COLOR_BAD),
            ));
        }
        (None, Some(cap)) if cap < d.local_tunnel_mtu => {
            spans.push(Span::raw("   Peer capability: "));
            spans.push(Span::styled(
                format!("{cap} (not converged)"),
                Style::default().fg(COLOR_BAD),
            ));
        }
        (None, Some(cap)) => {
            spans.push(Span::styled(format!("   Peer capability: {cap}"), muted()))
        }
        (None, None) => spans.push(Span::styled("   Peer: unknown", muted())),
    }
    Line::from(spans)
}

pub fn draw(f: &mut Frame, area: Rect, snap: &Snapshot, density: Density) {
    let d = &snap.daemon;
    let mut host = host_lines(d);
    let mut process = process_lines(d);
    let mut tun = tun_lines(d);
    let mut queue = queue_lines(d);
    queue.push(version_line(d));
    queue.push(mtu_line(d));

    if density == Density::Compact {
        let mut lines = Vec::new();
        for (title, body) in [
            ("Host", &mut host),
            ("Daemon process", &mut process),
            ("TUN", &mut tun),
            ("Queue and session", &mut queue),
        ] {
            lines.push(Line::from(Span::styled(title, bold(COLOR_ACCENT))));
            lines.append(body);
        }
        f.render_widget(Paragraph::new(lines), area);
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(6)])
        .split(area);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);
    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    f.render_widget(Paragraph::new(host).block(panel("Host")), top[0]);
    f.render_widget(
        Paragraph::new(process).block(panel("Daemon process")),
        top[1],
    );
    f.render_widget(Paragraph::new(tun).block(panel("TUN interface")), bottom[0]);
    f.render_widget(
        Paragraph::new(queue).block(panel("Outbound queue and session")),
        bottom[1],
    );
}
