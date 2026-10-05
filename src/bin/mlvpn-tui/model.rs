//! Client-side state: the shared snapshot/log/event/history store the
//! reader thread feeds, UI-only navigation state, the overall health
//! indicator, and pure text-graph helpers.

use mlvpn::ipc::{EventRecord, LinkSnapshot, LogEntry, Snapshot};
use ratatui::style::Color;
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Recent log lines kept client-side; independent of the daemon's own ring.
pub const LOG_CAPACITY: usize = 2000;
pub const EVENT_CAPACITY: usize = 500;
/// Samples of rate history per series. Snapshots arrive every 500 ms, so
/// this is one minute.
pub const HISTORY_SAMPLES: usize = 120;
/// No snapshot for this long and the display says DISCONNECTED even if the
/// socket is technically still open.
pub const STALE_AFTER: Duration = Duration::from_secs(3);

/// The one prominent state shown in the header. Symbols as well as colors,
/// so it reads on a monochrome terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Degraded,
    Failover,
    Down,
    Starting,
    /// Client-side only: the daemon's control socket is gone or stale.
    Disconnected,
}

impl Health {
    pub fn label(self) -> &'static str {
        match self {
            Health::Healthy => "HEALTHY",
            Health::Degraded => "DEGRADED",
            Health::Failover => "FAILOVER",
            Health::Down => "DOWN",
            Health::Starting => "STARTING",
            Health::Disconnected => "DISCONNECTED",
        }
    }

    pub fn symbol(self) -> &'static str {
        match self {
            Health::Healthy => "●",
            Health::Degraded => "!",
            Health::Failover => "↻",
            Health::Down => "×",
            Health::Starting => "…",
            Health::Disconnected => "○",
        }
    }

    pub fn color(self) -> Color {
        match self {
            Health::Healthy => Color::Green,
            Health::Degraded | Health::Failover => Color::Yellow,
            Health::Down => Color::Red,
            Health::Starting => Color::Cyan,
            Health::Disconnected => Color::DarkGray,
        }
    }

    pub fn parse(s: &str) -> Option<Health> {
        match s {
            "HEALTHY" => Some(Health::Healthy),
            "DEGRADED" => Some(Health::Degraded),
            "FAILOVER" => Some(Health::Failover),
            "DOWN" => Some(Health::Down),
            "STARTING" => Some(Health::Starting),
            _ => None,
        }
    }
}

/// Health for a daemon that predates `telemetry.health` (empty string):
/// a coarse derivation from the per-link data alone.
pub fn fallback_health(links: &[LinkSnapshot]) -> (Health, String) {
    let up = links.iter().filter(|l| l.state == "up").count();
    if up == 0 {
        if links.iter().any(|l| l.state == "probing") {
            return (Health::Starting, "no link up yet, probing".to_string());
        }
        return (Health::Down, "no link is up".to_string());
    }
    let degraded = links
        .iter()
        .any(|l| l.state != "up" || l.degraded || l.local_loss_pct.is_some_and(|p| p >= 5.0));
    if degraded {
        (
            Health::Degraded,
            format!("{up} of {} links healthy", links.len()),
        )
    } else {
        (Health::Healthy, format!("{up} of {} links up", links.len()))
    }
}

/// Mutable view state that never leaves the main thread.
pub struct Ui {
    pub tab: Tab,
    pub link_selected: usize,
    pub link_detail: bool,
    /// Lines scrolled up from the newest log line; 0 follows the tail.
    pub log_scroll: usize,
}

impl Default for Ui {
    fn default() -> Self {
        Ui {
            tab: Tab::Overview,
            link_selected: 0,
            link_detail: false,
            log_scroll: 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Overview,
    Links,
    Traffic,
    Reliability,
    System,
    Debug,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Overview,
        Tab::Links,
        Tab::Traffic,
        Tab::Reliability,
        Tab::System,
        Tab::Debug,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Links => "Links",
            Tab::Traffic => "Traffic",
            Tab::Reliability => "Reliability",
            Tab::System => "System",
            Tab::Debug => "Debug",
        }
    }

    pub fn short_title(self) -> &'static str {
        match self {
            Tab::Overview => "Ovw",
            Tab::Links => "Lnk",
            Tab::Traffic => "Trf",
            Tab::Reliability => "Rel",
            Tab::System => "Sys",
            Tab::Debug => "Dbg",
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap()
    }

    pub fn next(self) -> Tab {
        Tab::ALL[(self.index() + 1) % Tab::ALL.len()]
    }

    pub fn prev(self) -> Tab {
        Tab::ALL[(self.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }

    pub fn from_digit(c: char) -> Option<Tab> {
        c.to_digit(10)
            .and_then(|d| (d as usize).checked_sub(1))
            .and_then(|i| Tab::ALL.get(i).copied())
    }
}

/// A fixed-capacity rolling series of samples, oldest first.
#[derive(Default)]
pub struct Series(VecDeque<f64>);

impl Series {
    pub fn push(&mut self, v: f64) {
        if self.0.len() == HISTORY_SAMPLES {
            self.0.pop_front();
        }
        self.0.push_back(v);
    }

    pub fn values(&self) -> Vec<f64> {
        self.0.iter().copied().collect()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Default)]
pub struct History {
    pub tunnel_tx: Series,
    pub tunnel_rx: Series,
    /// Per-link combined tx+rx Mbps.
    pub link_total: BTreeMap<String, Series>,
}

pub struct SharedState {
    pub snapshot: Option<Snapshot>,
    pub connected: bool,
    pub last_update: Option<Instant>,
    pub logs: VecDeque<LogEntry>,
    pub events: VecDeque<EventRecord>,
    pub history: History,
    /// `None` while auto-detecting and no socket has been found yet.
    pub socket_path: Option<PathBuf>,
}

impl SharedState {
    pub fn new(socket_path: Option<PathBuf>) -> Self {
        SharedState {
            snapshot: None,
            connected: false,
            last_update: None,
            logs: VecDeque::new(),
            events: VecDeque::new(),
            history: History::default(),
            socket_path,
        }
    }

    /// A fresh connection replays the daemon's whole log and event rings
    /// (per-connection cursors start at zero), so drop what was
    /// accumulated from the previous connection to avoid duplicates.
    pub fn on_connect(&mut self) {
        self.connected = true;
        self.logs.clear();
        self.events.clear();
        self.history = History::default();
    }

    pub fn ingest(&mut self, snapshot: Snapshot) {
        for entry in &snapshot.new_log_lines {
            if self.logs.len() == LOG_CAPACITY {
                self.logs.pop_front();
            }
            self.logs.push_back(entry.clone());
        }
        for ev in &snapshot.new_events {
            if self.events.len() == EVENT_CAPACITY {
                self.events.pop_front();
            }
            self.events.push_back(ev.clone());
        }

        let (tx, rx) = tunnel_rates(&snapshot);
        self.history.tunnel_tx.push(tx);
        self.history.tunnel_rx.push(rx);
        for l in &snapshot.links {
            let total = l.local_tx_throughput_mbps.unwrap_or(0.0)
                + l.local_rx_throughput_mbps.unwrap_or(0.0);
            self.history
                .link_total
                .entry(l.name.clone())
                .or_default()
                .push(total);
        }

        self.snapshot = Some(snapshot);
        self.last_update = Some(Instant::now());
    }

    pub fn is_fresh(&self) -> bool {
        self.connected && self.last_update.is_some_and(|t| t.elapsed() < STALE_AFTER)
    }

    /// The overall indicator and a short reason. DISCONNECTED takes
    /// precedence over anything the last snapshot said.
    pub fn health(&self) -> (Health, String) {
        let Some(snap) = &self.snapshot else {
            return if self.connected {
                (Health::Starting, "waiting for first snapshot".to_string())
            } else {
                (
                    Health::Disconnected,
                    "not connected to the daemon".to_string(),
                )
            };
        };
        if !self.is_fresh() {
            return (
                Health::Disconnected,
                "no recent data from the daemon".to_string(),
            );
        }
        let t = &snap.daemon.telemetry;
        match Health::parse(&t.health) {
            Some(h) => (h, t.health_reason.clone()),
            None => fallback_health(&snap.links),
        }
    }
}

/// Tunnel tx/rx Mbps: the daemon's own TUN-rate sample when it provides
/// one, else the sum of per-link throughput.
pub fn tunnel_rates(snap: &Snapshot) -> (f64, f64) {
    if !snap.daemon.telemetry.health.is_empty() {
        let r = &snap.daemon.telemetry.rates;
        return (r.tx_mbps, r.rx_mbps);
    }
    snap.links
        .iter()
        .filter(|l| l.state == "up")
        .fold((0.0, 0.0), |(tx, rx), l| {
            (
                tx + l.local_tx_throughput_mbps.unwrap_or(0.0),
                rx + l.local_rx_throughput_mbps.unwrap_or(0.0),
            )
        })
}

const SPARK: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Renders the last `width` samples as block characters scaled to
/// `max` (or the series' own peak when `max` is 0). Shorter series are
/// left-padded with spaces so the newest sample is always rightmost.
pub fn spark(values: &[f64], width: usize, max: f64) -> String {
    if width == 0 {
        return String::new();
    }
    let tail = &values[values.len().saturating_sub(width)..];
    let peak = if max > 0.0 {
        max
    } else {
        tail.iter().copied().fold(0.0, f64::max)
    };
    let mut out = " ".repeat(width - tail.len());
    for &v in tail {
        let level = if peak <= 0.0 || v <= 0.0 {
            0
        } else {
            ((v / peak).min(1.0) * (SPARK.len() - 1) as f64).round() as usize
        };
        out.push(SPARK[level]);
    }
    out
}

/// A horizontal bar of exactly `width` cells filled to `ratio` (0..=1).
pub fn bar(ratio: f64, width: usize) -> String {
    let ratio = if ratio.is_finite() {
        ratio.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let filled = (ratio * width as f64).round() as usize;
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlvpn::ipc::{DaemonSnapshot, TelemetrySnapshot};

    fn link(name: &str, state: &str) -> LinkSnapshot {
        LinkSnapshot {
            name: name.into(),
            state: state.into(),
            score: 1.0,
            ..Default::default()
        }
    }

    fn snapshot(links: Vec<LinkSnapshot>, health: &str) -> Snapshot {
        let daemon = DaemonSnapshot {
            telemetry: TelemetrySnapshot {
                health: health.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        Snapshot {
            tunnel_name: "t0".into(),
            mode: "client".into(),
            unix_ts_ms: 0,
            links,
            daemon,
            new_log_lines: vec![],
            new_events: vec![],
        }
    }

    #[test]
    fn health_parse_round_trips_every_daemon_state() {
        for h in [
            Health::Healthy,
            Health::Degraded,
            Health::Failover,
            Health::Down,
            Health::Starting,
        ] {
            assert_eq!(Health::parse(h.label()), Some(h));
        }
        assert_eq!(Health::parse(""), None);
        assert_eq!(Health::parse("DISCONNECTED"), None);
    }

    #[test]
    fn every_health_has_a_distinct_symbol() {
        let all = [
            Health::Healthy,
            Health::Degraded,
            Health::Failover,
            Health::Down,
            Health::Starting,
            Health::Disconnected,
        ];
        let mut syms: Vec<_> = all.iter().map(|h| h.symbol()).collect();
        syms.sort();
        syms.dedup();
        assert_eq!(syms.len(), all.len());
    }

    #[test]
    fn fallback_health_ladder() {
        assert_eq!(fallback_health(&[link("a", "down")]).0, Health::Down);
        assert_eq!(fallback_health(&[link("a", "probing")]).0, Health::Starting);
        assert_eq!(
            fallback_health(&[link("a", "up"), link("b", "down")]).0,
            Health::Degraded
        );
        assert_eq!(
            fallback_health(&[link("a", "up"), link("b", "up")]).0,
            Health::Healthy
        );
    }

    #[test]
    fn tab_navigation_wraps_and_digits_map() {
        assert_eq!(Tab::Debug.next(), Tab::Overview);
        assert_eq!(Tab::Overview.prev(), Tab::Debug);
        assert_eq!(Tab::from_digit('1'), Some(Tab::Overview));
        assert_eq!(Tab::from_digit('6'), Some(Tab::Debug));
        assert_eq!(Tab::from_digit('7'), None);
        assert_eq!(Tab::from_digit('0'), None);
    }

    #[test]
    fn spark_scales_pads_and_handles_flat_series() {
        assert_eq!(spark(&[], 4, 0.0), "    ");
        assert_eq!(spark(&[0.0, 0.0], 3, 0.0), " ▁▁");
        assert_eq!(spark(&[0.0, 5.0, 10.0], 3, 0.0), "▁▅█");
        assert_eq!(spark(&[1.0, 2.0, 3.0, 10.0], 2, 10.0).chars().count(), 2);
        assert_eq!(spark(&[20.0], 1, 10.0), "█");
        assert_eq!(spark(&[1.0], 0, 0.0), "");
    }

    #[test]
    fn bar_is_exact_width_and_clamped() {
        assert_eq!(bar(0.0, 4), "░░░░");
        assert_eq!(bar(0.5, 4), "██░░");
        assert_eq!(bar(1.0, 4), "████");
        assert_eq!(bar(7.0, 4), "████");
        assert_eq!(bar(-1.0, 4), "░░░░");
        assert_eq!(bar(f64::NAN, 4), "░░░░");
        assert_eq!(bar(0.5, 0), "");
    }

    #[test]
    fn series_is_capped() {
        let mut s = Series::default();
        for i in 0..(HISTORY_SAMPLES + 10) {
            s.push(i as f64);
        }
        assert_eq!(s.len(), HISTORY_SAMPLES);
        assert_eq!(s.values()[0], 10.0);
    }

    #[test]
    fn health_prefers_disconnected_then_daemon_value_then_fallback() {
        let mut st = SharedState::new(None);
        assert_eq!(st.health().0, Health::Disconnected);
        st.on_connect();
        assert_eq!(st.health().0, Health::Starting);

        st.ingest(snapshot(vec![link("a", "up")], "FAILOVER"));
        assert_eq!(st.health().0, Health::Failover);

        st.ingest(snapshot(vec![link("a", "up")], ""));
        assert_eq!(st.health().0, Health::Healthy);

        st.connected = false;
        assert_eq!(st.health().0, Health::Disconnected);

        st.connected = true;
        st.last_update = Some(Instant::now() - STALE_AFTER - Duration::from_secs(1));
        assert_eq!(st.health().0, Health::Disconnected);
    }

    #[test]
    fn on_connect_drops_replayed_state() {
        let mut st = SharedState::new(None);
        let mut s = snapshot(vec![link("a", "up")], "HEALTHY");
        s.new_events.push(EventRecord {
            seq: 1,
            unix_ts_ms: 0,
            severity: "info".into(),
            kind: "LINK_UP".into(),
            link: Some("a".into()),
            message: "up".into(),
            fields: Default::default(),
        });
        st.ingest(s);
        assert_eq!(st.events.len(), 1);
        assert_eq!(st.history.tunnel_tx.len(), 1);
        st.on_connect();
        assert!(st.events.is_empty());
        assert_eq!(st.history.tunnel_tx.len(), 0);
    }
}
