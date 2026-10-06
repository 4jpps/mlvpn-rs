//! Derived tunnel telemetry: the one place that turns raw counters into
//! the answers every monitoring consumer (mlvpn-tui, the read-only web
//! API) wants -- overall health, rates, reorder-buffer state, process
//! resource use, structured events.
//!
//! A single background task (`run`) samples the daemon twice a second,
//! feeds `events::EventDetector`, and caches the result as an
//! `ipc::TelemetrySnapshot`. Control-socket clients just copy the cache,
//! so N connected clients cost no more than one and always agree.
//!
//! Nothing here sits on the packet path. The only hot-path-adjacent
//! piece is `RxPipelineStats`, plain atomics that `tunnel::rx_pipeline`
//! publishes into from its existing 10 ms flush tick.

use crate::config::{FecParityPlacement, SchedulerConfig};
use crate::events::{EventDetector, EventRing, LinkObs, Obs};
use crate::ipc::{
    FecConfigSnapshot, ProcessSnapshot, RateSnapshot, ReorderSnapshot, TelemetrySnapshot,
};
use crate::link::{self, LinkState, Links};
use crate::procstats;
use crate::scheduler::Scheduler;
use crate::sysfs_net;
use crate::tunnel::LiveMtu;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::interval;

const SAMPLE_INTERVAL: Duration = Duration::from_millis(500);
/// Rates and CPU are recomputed over at least this long a window; at
/// the 500 ms sample cadence a shorter window is mostly quantization
/// noise at low packet rates.
const RATE_WINDOW: Duration = Duration::from_millis(1000);
/// A link that has not come up within this long of daemon start is
/// reported as down rather than still starting.
const STARTUP_GRACE_SECS: u64 = 30;
/// How long FAILOVER / recent-loss states linger after the triggering
/// transition, so a brief blip is still visible at a glance.
const HEALTH_HOLD_MS: u64 = 10_000;
const LOSSY_LINK_PCT: f64 = 5.0;

/// Receive-pipeline numbers published by `tunnel::rx_pipeline`.
#[derive(Debug, Default)]
pub struct RxPipelineStats {
    pub window_ms: AtomicU64,
    pub depth: AtomicU64,
    pub max_depth: AtomicU64,
    pub wait_recent_us: AtomicU64,
    pub wait_max_us: AtomicU64,
    pub late_total: AtomicU64,
    pub duplicate_total: AtomicU64,
    pub timeout_total: AtomicU64,
    /// Lifetime frames dropped because the pipeline channel was full.
    pub dropped_total: AtomicU64,
    pub busy_ns_total: AtomicU64,
    pub max_backlog: AtomicU64,
}

impl RxPipelineStats {
    pub fn reorder_snapshot(&self) -> ReorderSnapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        ReorderSnapshot {
            window_ms: g(&self.window_ms),
            depth: g(&self.depth),
            max_depth: g(&self.max_depth),
            wait_recent_us: g(&self.wait_recent_us),
            wait_max_us: g(&self.wait_max_us),
            late_total: g(&self.late_total),
            duplicate_total: g(&self.duplicate_total),
            timeout_total: g(&self.timeout_total),
        }
    }
}

/// Configuration facts that never change while the daemon runs.
#[derive(Debug, Clone)]
pub struct StaticConfig {
    pub fec: FecConfigSnapshot,
    pub scheduler_mode: &'static str,
}

impl StaticConfig {
    pub fn from_scheduler(cfg: &SchedulerConfig) -> Self {
        let scheduler_mode = if cfg.follow_peer_primary {
            "follow-peer"
        } else if cfg.primary_link_mode {
            "primary"
        } else if cfg.redundant_mode {
            "redundant"
        } else {
            "weighted"
        };
        let placement = match cfg.fec_parity_placement {
            FecParityPlacement::Scheduler => "scheduler",
            FecParityPlacement::Dominant => "dominant",
            FecParityPlacement::Diverse => "diverse",
        };
        Self {
            fec: FecConfigSnapshot {
                enabled: cfg.fec_enabled,
                group_size: cfg.fec_group_size,
                parity: cfg.fec_parity,
                placement: placement.to_string(),
            },
            scheduler_mode,
        }
    }
}

/// Shared handle: the event ring plus the cached derived snapshot.
pub struct Telemetry {
    pub events: EventRing,
    pub rx: Arc<RxPipelineStats>,
    cached: Mutex<TelemetrySnapshot>,
}

impl Telemetry {
    pub fn new(rx: Arc<RxPipelineStats>) -> Self {
        Self {
            events: EventRing::new(),
            rx,
            cached: Mutex::new(TelemetrySnapshot {
                health: Health::Starting.as_str().to_string(),
                health_reason: "daemon starting".to_string(),
                ..Default::default()
            }),
        }
    }

    pub fn current(&self) -> TelemetrySnapshot {
        self.cached.lock().unwrap().clone()
    }

    fn store(&self, snap: TelemetrySnapshot) {
        *self.cached.lock().unwrap() = snap;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Starting,
    Healthy,
    Degraded,
    Failover,
    Down,
}

impl Health {
    pub fn as_str(self) -> &'static str {
        match self {
            Health::Starting => "STARTING",
            Health::Healthy => "HEALTHY",
            Health::Degraded => "DEGRADED",
            Health::Failover => "FAILOVER",
            Health::Down => "DOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LinkHealth {
    pub name: String,
    pub state: LinkState,
    /// Up but shedding traffic because of congestion.
    pub congested: bool,
    pub loss_pct: Option<f64>,
}

#[derive(Debug)]
pub struct HealthInput<'a> {
    pub uptime_secs: u64,
    pub links: &'a [LinkHealth],
    /// Name of the link traffic was recently moved away from, if any.
    pub failed_over_from: Option<&'a str>,
    pub recent_loss: bool,
}

/// The single definition of overall tunnel health. Ordered from most to
/// least severe so the headline is always the worst applicable state.
pub fn derive_health(i: &HealthInput) -> (Health, String) {
    let total = i.links.len();
    let up = i.links.iter().filter(|l| l.state == LinkState::Up).count();
    let probing = i
        .links
        .iter()
        .filter(|l| l.state == LinkState::Probing)
        .count();

    if total == 0 {
        return (Health::Starting, "no links configured yet".to_string());
    }
    if up == 0 {
        if probing > 0 && i.uptime_secs < STARTUP_GRACE_SECS {
            return (Health::Starting, "waiting for the first link".to_string());
        }
        return (Health::Down, "no link is up".to_string());
    }
    if let Some(name) = i.failed_over_from {
        return (
            Health::Failover,
            format!("traffic moved off link {name}; {up} of {total} links carrying it"),
        );
    }
    let not_up: Vec<&str> = i
        .links
        .iter()
        .filter(|l| l.state != LinkState::Up)
        .map(|l| l.name.as_str())
        .collect();
    if !not_up.is_empty() {
        return (
            Health::Degraded,
            format!("link {} is not up ({up} of {total} up)", not_up.join(", ")),
        );
    }
    if let Some(l) = i.links.iter().find(|l| l.congested) {
        return (
            Health::Degraded,
            format!("link {} is congested and shedding traffic", l.name),
        );
    }
    if let Some(l) = i
        .links
        .iter()
        .find(|l| l.loss_pct.is_some_and(|p| p >= LOSSY_LINK_PCT))
    {
        return (
            Health::Degraded,
            format!("link {} loss is {:.1}%", l.name, l.loss_pct.unwrap_or(0.0)),
        );
    }
    if i.recent_loss {
        return (
            Health::Degraded,
            "packets were recently dropped".to_string(),
        );
    }
    (Health::Healthy, format!("all {total} links up"))
}

/// Notices when traffic is pushed off a link that was carrying it.
#[derive(Debug, Default)]
pub struct FailoverTracker {
    prev_up: Vec<bool>,
    prev_primary: Option<usize>,
    last: Option<(u64, String)>,
}

impl FailoverTracker {
    /// `primary_mode`: only a drop of the *current primary* counts as a
    /// failover (a non-primary link dying moves no traffic). Otherwise
    /// any Up -> not-Up transition with a survivor does.
    pub fn update(
        &mut self,
        now_ms: u64,
        links: &[LinkHealth],
        primary: Option<usize>,
        primary_mode: bool,
    ) {
        let any_up = links.iter().any(|l| l.state == LinkState::Up);
        if any_up {
            for (idx, l) in links.iter().enumerate() {
                let was_up = self.prev_up.get(idx).copied().unwrap_or(false);
                if was_up && l.state != LinkState::Up {
                    let carried = !primary_mode || self.prev_primary == Some(idx);
                    if carried {
                        self.last = Some((now_ms, l.name.clone()));
                    }
                }
            }
        }
        self.prev_up = links.iter().map(|l| l.state == LinkState::Up).collect();
        self.prev_primary = primary;
    }

    pub fn active(&self, now_ms: u64) -> Option<&str> {
        match &self.last {
            Some((t, name)) if now_ms.saturating_sub(*t) < HEALTH_HOLD_MS => Some(name),
            _ => None,
        }
    }
}

/// Counter deltas -> rates. A counter that went backwards (interface
/// recreated) yields zero for that interval rather than a huge value.
pub fn rate_between(prev: u64, cur: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        return 0.0;
    }
    cur.saturating_sub(prev) as f64 / secs
}

#[derive(Clone, Copy)]
struct TunSample {
    at: Instant,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    cpu_ticks: Option<u64>,
}

#[derive(Default)]
struct Sampler {
    last: Option<TunSample>,
    rates: RateSnapshot,
    cpu_pct: Option<f64>,
}

impl Sampler {
    fn update(&mut self, tun: &sysfs_net::TunIfaceStats, cpu_ticks: Option<u64>) {
        let cur = TunSample {
            at: Instant::now(),
            rx_bytes: tun.rx_bytes.unwrap_or(0),
            tx_bytes: tun.tx_bytes.unwrap_or(0),
            rx_packets: tun.rx_packets.unwrap_or(0),
            tx_packets: tun.tx_packets.unwrap_or(0),
            cpu_ticks,
        };
        match self.last {
            None => self.last = Some(cur),
            Some(prev) => {
                let dt = cur.at.duration_since(prev.at);
                if dt < RATE_WINDOW {
                    return;
                }
                let secs = dt.as_secs_f64();
                self.rates = RateSnapshot {
                    tx_pps: rate_between(prev.tx_packets, cur.tx_packets, secs),
                    rx_pps: rate_between(prev.rx_packets, cur.rx_packets, secs),
                    tx_mbps: rate_between(prev.tx_bytes, cur.tx_bytes, secs) * 8.0 / 1e6,
                    rx_mbps: rate_between(prev.rx_bytes, cur.rx_bytes, secs) * 8.0 / 1e6,
                };
                self.cpu_pct = match (prev.cpu_ticks, cur.cpu_ticks) {
                    (Some(a), Some(b)) => Some(
                        rate_between(a, b, secs) / procstats::clock_ticks_per_sec() as f64 * 100.0,
                    ),
                    _ => None,
                };
                self.last = Some(cur);
            }
        }
    }
}

/// Everything `run` needs to observe the daemon.
pub struct WatchInputs {
    pub links: Links,
    pub scheduler: Arc<Mutex<Scheduler>>,
    pub tunnel_name: String,
    pub outbound_dropped_total: Arc<AtomicU64>,
    pub fec_recovered_total: Arc<AtomicU64>,
    pub fec_unrecoverable_total: Arc<AtomicU64>,
    pub mtu: LiveMtu,
    pub cfg: StaticConfig,
}

/// Sample the daemon forever: detect events, derive health, refresh the
/// cached `TelemetrySnapshot`.
pub async fn run(telemetry: Arc<Telemetry>, inputs: WatchInputs) {
    let started = Instant::now();
    let t0_ms = unix_ms();
    let mut detector = EventDetector::new();
    let mut failover = FailoverTracker::default();
    let mut sampler = Sampler::default();
    let mut last_loss_ms: Option<u64> = None;
    let mut tick = interval(SAMPLE_INTERVAL);
    let primary_mode = matches!(inputs.cfg.scheduler_mode, "primary" | "follow-peer");

    loop {
        tick.tick().await;
        let now_ms = unix_ms();
        let snap = link::snapshot_links(&inputs.links).await;
        let primary_idx = inputs.scheduler.lock().unwrap().primary();

        let mut link_obs = Vec::with_capacity(snap.len());
        let mut link_health = Vec::with_capacity(snap.len());
        let mut reroutes_total = 0u64;
        for l in snap.iter() {
            let congestion =
                l.stats.tx_counters.congestion_milli.load(Ordering::Relaxed) as f64 / 1000.0;
            let congested =
                l.state == LinkState::Up && congestion < crate::congestion::DEGRADED_BELOW;
            let loss_pct = l.stats.loss_rate.get().map(|v| v * 100.0);
            let rerouted = l.stats.tx_counters.rerouted_away.load(Ordering::Relaxed);
            reroutes_total += rerouted;
            link_obs.push(LinkObs {
                name: l.config.name.clone(),
                state: l.state,
                congested,
                loss_pct,
                queue_full: l.stats.tx_counters.queue_full.load(Ordering::Relaxed),
                send_failed: l.stats.tx_counters.send_failed.load(Ordering::Relaxed),
                rerouted,
                wg_rejected: l.wg_rejected_count(),
                handshake_age_ms: l.wg_handshake_age_ms(),
            });
            link_health.push(LinkHealth {
                name: l.config.name.clone(),
                state: l.state,
                congested,
                loss_pct,
            });
        }
        drop(snap);

        let tun = sysfs_net::read_tun_stats(&inputs.tunnel_name);
        let rx = &telemetry.rx;
        let reorder = rx.reorder_snapshot();
        let obs = Obs {
            now_ms,
            links: link_obs,
            fec_recovered: inputs.fec_recovered_total.load(Ordering::Relaxed),
            fec_unrecoverable: inputs.fec_unrecoverable_total.load(Ordering::Relaxed),
            outbound_dropped: inputs.outbound_dropped_total.load(Ordering::Relaxed),
            tun_dropped: tun.rx_dropped.unwrap_or(0) + tun.tx_dropped.unwrap_or(0),
            // Redundant mode deliberately sends every frame down every
            // link, so late duplicates are its normal state, not a warning.
            reorder_timeouts: if inputs.cfg.scheduler_mode == "redundant" {
                0
            } else {
                reorder.timeout_total
            },
            mtu: inputs.mtu.load(Ordering::Relaxed),
        };
        for ev in detector.observe(&obs) {
            if ev.kind.is_loss() {
                last_loss_ms = Some(now_ms);
            }
            telemetry.events.push(ev);
        }

        failover.update(now_ms, &link_health, primary_idx, primary_mode);
        let process = procstats::read_process_stats();
        sampler.update(&tun, process.cpu_ticks);

        let recent_loss = last_loss_ms.is_some_and(|t| now_ms.saturating_sub(t) < HEALTH_HOLD_MS);
        let uptime_secs = started.elapsed().as_secs();
        let (health, reason) = derive_health(&HealthInput {
            uptime_secs,
            links: &link_health,
            failed_over_from: failover.active(now_ms),
            recent_loss,
        });

        telemetry.store(TelemetrySnapshot {
            health: health.as_str().to_string(),
            health_reason: reason,
            tunnel_uptime_secs: uptime_secs.max(now_ms.saturating_sub(t0_ms) / 1000),
            scheduler_mode: inputs.cfg.scheduler_mode.to_string(),
            fec: inputs.cfg.fec.clone(),
            reorder,
            rates: sampler.rates.clone(),
            reroutes_total,
            rx_pipeline_dropped_total: rx.dropped_total.load(Ordering::Relaxed),
            rx_pipeline_busy_ns_total: rx.busy_ns_total.load(Ordering::Relaxed),
            rx_pipeline_max_backlog: rx.max_backlog.load(Ordering::Relaxed),
            process: ProcessSnapshot {
                cpu_pct: sampler.cpu_pct,
                rss_kb: process.rss_kb,
                threads: process.threads,
                open_fds: process.open_fds,
            },
        });
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lh(name: &str, state: LinkState) -> LinkHealth {
        LinkHealth {
            name: name.to_string(),
            state,
            congested: false,
            loss_pct: None,
        }
    }

    fn input<'a>(uptime: u64, links: &'a [LinkHealth]) -> HealthInput<'a> {
        HealthInput {
            uptime_secs: uptime,
            links,
            failed_over_from: None,
            recent_loss: false,
        }
    }

    #[test]
    fn health_is_starting_until_grace_then_down() {
        let links = [lh("a", LinkState::Probing), lh("b", LinkState::Probing)];
        assert_eq!(derive_health(&input(5, &links)).0, Health::Starting);
        assert_eq!(derive_health(&input(60, &links)).0, Health::Down);
        let down = [lh("a", LinkState::Down)];
        assert_eq!(derive_health(&input(5, &down)).0, Health::Down);
    }

    #[test]
    fn health_ladder_picks_the_worst_applicable_state() {
        let all_up = [lh("a", LinkState::Up), lh("b", LinkState::Up)];
        assert_eq!(derive_health(&input(60, &all_up)).0, Health::Healthy);

        let mut i = input(60, &all_up);
        i.recent_loss = true;
        assert_eq!(derive_health(&i).0, Health::Degraded);

        let one_down = [lh("a", LinkState::Up), lh("b", LinkState::Down)];
        let (h, why) = derive_health(&input(60, &one_down));
        assert_eq!(h, Health::Degraded);
        assert!(why.contains('b'));

        let mut i = input(60, &one_down);
        i.failed_over_from = Some("b");
        assert_eq!(derive_health(&i).0, Health::Failover);

        let none_up = [lh("a", LinkState::Down), lh("b", LinkState::Down)];
        let mut i = input(60, &none_up);
        i.failed_over_from = Some("b");
        assert_eq!(derive_health(&i).0, Health::Down);
    }

    #[test]
    fn congestion_and_loss_degrade_an_otherwise_up_tunnel() {
        let mut links = [lh("a", LinkState::Up), lh("b", LinkState::Up)];
        links[1].congested = true;
        assert_eq!(derive_health(&input(60, &links)).0, Health::Degraded);
        links[1].congested = false;
        links[0].loss_pct = Some(7.5);
        let (h, why) = derive_health(&input(60, &links));
        assert_eq!(h, Health::Degraded);
        assert!(why.contains("7.5"));
        links[0].loss_pct = Some(1.0);
        assert_eq!(derive_health(&input(60, &links)).0, Health::Healthy);
    }

    #[test]
    fn failover_tracker_weighted_mode_counts_any_drop_with_a_survivor() {
        let mut t = FailoverTracker::default();
        let up = [lh("a", LinkState::Up), lh("b", LinkState::Up)];
        t.update(0, &up, None, false);
        assert!(t.active(0).is_none());
        let b_down = [lh("a", LinkState::Up), lh("b", LinkState::Down)];
        t.update(1000, &b_down, None, false);
        assert_eq!(t.active(1000), Some("b"));
        assert_eq!(t.active(1000 + HEALTH_HOLD_MS - 1), Some("b"));
        assert!(t.active(1000 + HEALTH_HOLD_MS).is_none());
    }

    #[test]
    fn failover_tracker_primary_mode_ignores_a_non_primary_drop() {
        let mut t = FailoverTracker::default();
        let up = [lh("a", LinkState::Up), lh("b", LinkState::Up)];
        t.update(0, &up, Some(0), true);
        let b_down = [lh("a", LinkState::Up), lh("b", LinkState::Down)];
        t.update(1000, &b_down, Some(0), true);
        assert!(t.active(1000).is_none(), "standby dying moves no traffic");

        let mut t = FailoverTracker::default();
        t.update(0, &up, Some(0), true);
        let a_down = [lh("a", LinkState::Down), lh("b", LinkState::Up)];
        t.update(1000, &a_down, Some(1), true);
        assert_eq!(t.active(1000), Some("a"));
    }

    #[test]
    fn failover_tracker_needs_a_survivor() {
        let mut t = FailoverTracker::default();
        let up = [lh("a", LinkState::Up)];
        t.update(0, &up, None, false);
        t.update(1000, &[lh("a", LinkState::Down)], None, false);
        assert!(t.active(1000).is_none());
    }

    #[test]
    fn rate_between_handles_reset_and_zero_interval() {
        assert_eq!(rate_between(100, 1100, 2.0), 500.0);
        assert_eq!(rate_between(1000, 10, 1.0), 0.0);
        assert_eq!(rate_between(0, 10, 0.0), 0.0);
    }

    #[test]
    fn static_config_picks_scheduler_mode_with_follow_peer_first() {
        let mut cfg = SchedulerConfig::default();
        assert_eq!(
            StaticConfig::from_scheduler(&cfg).scheduler_mode,
            "weighted"
        );
        cfg.redundant_mode = true;
        assert_eq!(
            StaticConfig::from_scheduler(&cfg).scheduler_mode,
            "redundant"
        );
        cfg.redundant_mode = false;
        cfg.primary_link_mode = true;
        assert_eq!(StaticConfig::from_scheduler(&cfg).scheduler_mode, "primary");
        cfg.follow_peer_primary = true;
        assert_eq!(
            StaticConfig::from_scheduler(&cfg).scheduler_mode,
            "follow-peer"
        );
    }

    #[test]
    fn fresh_telemetry_reports_starting() {
        let t = Telemetry::new(Arc::new(RxPipelineStats::default()));
        assert_eq!(t.current().health, "STARTING");
    }
}
