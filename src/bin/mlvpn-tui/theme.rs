//! Colors, styles and small text formatters shared by every view.
//!
//! Everything that carries meaning uses a symbol or word as well as a
//! color, so the display still reads correctly on a monochrome terminal
//! or for a color-blind operator.

use mlvpn::ipc::EventRecord;
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

pub const COLOR_GOOD: Color = Color::Green;
pub const COLOR_WARN: Color = Color::Yellow;
pub const COLOR_BAD: Color = Color::Red;
pub const COLOR_MUTED: Color = Color::DarkGray;
pub const COLOR_ACCENT: Color = Color::Cyan;

pub fn muted() -> Style {
    Style::default().fg(COLOR_MUTED)
}

pub fn bold(color: Color) -> Style {
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

/// Link state as a symbol plus word: `● up`, `… probing`, `× down`.
pub fn state_symbol(state: &str) -> &'static str {
    match state {
        "up" => "●",
        "down" => "×",
        _ => "…",
    }
}

pub fn state_style(s: &str) -> Style {
    match s {
        "up" => bold(COLOR_GOOD),
        "down" => bold(COLOR_BAD),
        _ => Style::default().fg(COLOR_WARN),
    }
}

/// Green above 0.5, yellow above 0, muted at exactly 0 (excluded from
/// scheduling -- see `ipc::LinkSnapshot::score`).
pub fn score_style(score: f64) -> Style {
    if score <= 0.0 {
        muted()
    } else if score < 0.5 {
        Style::default().fg(COLOR_WARN)
    } else {
        Style::default().fg(COLOR_GOOD)
    }
}

/// Green at 0% loss, yellow under 5%, red at 5% or above; `None` (no
/// measurement yet) is muted rather than a false "good".
pub fn loss_style(pct: Option<f64>) -> Style {
    match pct {
        None => muted(),
        Some(p) if p <= 0.0 => Style::default().fg(COLOR_GOOD),
        Some(p) if p < 5.0 => Style::default().fg(COLOR_WARN),
        Some(_) => Style::default().fg(COLOR_BAD),
    }
}

/// Green under 70% used, yellow 70-90%, red at 90% or above.
pub fn pct_used_style(pct: f64) -> Style {
    if pct >= 90.0 {
        Style::default().fg(COLOR_BAD)
    } else if pct >= 70.0 {
        Style::default().fg(COLOR_WARN)
    } else {
        Style::default().fg(COLOR_GOOD)
    }
}

/// Muted at zero, `bad` (red by default) once nonzero -- for counters
/// where any occurrence is worth noticing.
pub fn counter_style(v: u64, nonzero: Color) -> Style {
    if v > 0 {
        Style::default().fg(nonzero)
    } else {
        muted()
    }
}

pub fn event_style(severity: &str) -> Style {
    match severity {
        "error" => bold(COLOR_BAD),
        "warn" => Style::default().fg(COLOR_WARN),
        _ => Style::default(),
    }
}

pub fn event_symbol(severity: &str) -> &'static str {
    match severity {
        "error" => "×",
        "warn" => "!",
        _ => "·",
    }
}

/// One event as a single line: `HH:MM:SS ! KIND link  message`.
pub fn event_line(e: &EventRecord) -> Line<'static> {
    let style = event_style(&e.severity);
    let mut spans = vec![
        Span::styled(fmt_log_timestamp(e.unix_ts_ms), muted()),
        Span::raw(" "),
        Span::styled(event_symbol(&e.severity), style),
        Span::raw(" "),
        Span::styled(format!("{:<20}", e.kind), style),
    ];
    if let Some(link) = &e.link {
        spans.push(Span::styled(
            format!(" {link}"),
            Style::default().fg(COLOR_ACCENT),
        ));
    }
    spans.push(Span::raw(format!("  {}", e.message)));
    Line::from(spans)
}

/// `label: value` with a muted label.
pub fn kv(label: &str, value: String, style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), muted()),
        Span::styled(value, style),
    ])
}

pub fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// `HH:MM:SS` UTC, matching the daemon's own log timestamps.
pub fn fmt_log_timestamp(unix_ts_ms: u64) -> String {
    let secs = unix_ts_ms / 1000;
    format!(
        "{:02}:{:02}:{:02}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

pub fn fmt_ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}ms"))
        .unwrap_or_else(|| "-".to_string())
}

pub fn fmt_pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".to_string())
}

pub fn fmt_mbps(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}Mbps"))
        .unwrap_or_else(|| "-".to_string())
}

pub fn fmt_rate(mbps: f64) -> String {
    if mbps >= 100.0 {
        format!("{mbps:.0} Mbps")
    } else if mbps >= 1.0 {
        format!("{mbps:.1} Mbps")
    } else {
        format!("{:.0} kbps", mbps * 1000.0)
    }
}

pub fn fmt_us_as_ms(us: u64) -> String {
    format!("{:.1} ms", us as f64 / 1000.0)
}

/// Binary-prefix byte count (`KB` = 1024 bytes).
pub fn fmt_bytes(bytes: u64) -> String {
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

pub fn fmt_bytes_opt(v: Option<u64>) -> String {
    v.map(fmt_bytes).unwrap_or_else(|| "-".to_string())
}

pub fn fmt_opt_u64(v: Option<u64>) -> String {
    v.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string())
}

pub fn fmt_load(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "-".to_string())
}

pub fn fmt_duration_ms(ms: u64) -> String {
    fmt_duration_secs(ms / 1000)
}

pub fn fmt_duration_secs(total_secs: u64) -> String {
    let d = total_secs / 86_400;
    let h = (total_secs % 86_400) / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    if d > 0 {
        format!("{d}d{h:02}h")
    } else if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_compact() {
        assert_eq!(fmt_duration_secs(7), "7s");
        assert_eq!(fmt_duration_secs(125), "2m05s");
        assert_eq!(fmt_duration_secs(3 * 3600 + 120), "3h02m");
        assert_eq!(fmt_duration_secs(2 * 86_400 + 5 * 3600), "2d05h");
    }

    #[test]
    fn rates_pick_a_sensible_unit() {
        assert_eq!(fmt_rate(0.25), "250 kbps");
        assert_eq!(fmt_rate(12.34), "12.3 Mbps");
        assert_eq!(fmt_rate(412.6), "413 Mbps");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("héllo", 10), "héllo");
        assert_eq!(truncate("héllo wörld", 6), "héllo…");
    }

    #[test]
    fn state_has_symbol_as_well_as_color() {
        assert_eq!(state_symbol("up"), "●");
        assert_eq!(state_symbol("down"), "×");
        assert_eq!(state_symbol("probing"), "…");
    }
}
