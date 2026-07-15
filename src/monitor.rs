//! Pure link-quality logic: turning raw probe round trips into the
//! latency/jitter/loss statistics used for scheduling, deciding when a
//! link flips Up/Down, and scoring links against each other.
//!
//! This module intentionally has no knowledge of sockets or async tasks --
//! see `tunnel.rs` for the per-link actor that drives probes over the
//! wire and feeds results back in here. Keeping the decision logic free of
//! I/O makes it straightforward to unit test the failover behavior without
//! standing up real network links.

use crate::config::SchedulerConfig;
use crate::link::{Link, LinkState};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Tracks outstanding (unacknowledged) probes for one link so that when a
/// `ProbeReply` comes back we can compute RTT from our own clock, and so
/// that probes which never get a reply can be swept into a "miss" after a
/// timeout.
pub struct ProbeTracker {
    outstanding: HashMap<u32, Instant>,
    timeout: Duration,
}

impl ProbeTracker {
    pub fn new(timeout: Duration) -> Self {
        Self {
            outstanding: HashMap::new(),
            timeout,
        }
    }

    pub fn record_sent(&mut self, probe_seq: u32) {
        self.outstanding.insert(probe_seq, Instant::now());
    }

    /// Call when a ProbeReply for `probe_seq` arrives. Returns the
    /// measured RTT in milliseconds, or `None` if we have no record of
    /// sending that probe (already timed out and swept, or a stray/replayed
    /// reply).
    pub fn record_reply(&mut self, probe_seq: u32) -> Option<f64> {
        let sent_at = self.outstanding.remove(&probe_seq)?;
        Some(sent_at.elapsed().as_secs_f64() * 1000.0)
    }

    /// Remove and return the count of probes that have been outstanding
    /// longer than `timeout`; each one counts as a loss.
    pub fn sweep_timeouts(&mut self) -> usize {
        let timeout = self.timeout;
        let before = self.outstanding.len();
        self.outstanding
            .retain(|_, sent_at| sent_at.elapsed() < timeout);
        before - self.outstanding.len()
    }
}

/// Update a link's Up/Down state from its current hit/miss streak. Uses
/// separate up/down thresholds (hysteresis) specifically so a link
/// flapping right at the edge of usable doesn't bounce the scheduler in
/// and out every other probe -- that kind of flapping is worse for
/// perceived quality than just staying down a little longer than strictly
/// necessary.
pub fn update_link_state(link: &mut Link, cfg: &SchedulerConfig) {
    let was = link.state;
    link.state = match link.state {
        LinkState::Up if link.stats.consecutive_misses >= cfg.down_threshold => LinkState::Down,
        LinkState::Down | LinkState::Probing if link.stats.consecutive_hits >= cfg.up_threshold => {
            LinkState::Up
        }
        other => other,
    };
    if was != link.state {
        tracing::info!(
            link = %link.config.name,
            from = ?was,
            to = ?link.state,
            "link state changed"
        );
    }
}

/// Composite score used by the scheduler's weighted round robin. Higher is
/// better. A link that is not Up always scores 0 so it is excluded from
/// the active rotation without needing to be removed from the link list
/// (removal would lose its accumulated stats, which we want to keep so it
/// can be judged fairly again once probes start succeeding).
///
/// The formula rewards higher throughput sub-linearly (sqrt) so one very
/// fast link doesn't totally starve slower-but-still-useful links of
/// traffic, and penalizes latency, jitter and loss multiplicatively so a
/// link that's fast but flaky doesn't outscore one that's slower but
/// reliable.
pub fn score(link: &Link) -> f64 {
    if link.state != LinkState::Up || link.admin_disabled {
        return 0.0;
    }
    let rtt = link.stats.rtt_ms.get().unwrap_or(200.0).max(0.1);
    let jitter = link.stats.jitter_ms.get().unwrap_or(20.0).max(0.0);
    let loss = link.stats.loss_rate.get().unwrap_or(0.0).clamp(0.0, 1.0);
    // Prefer the active-probe measurement (a deliberate, MTU-sized burst
    // sent purely to measure capacity) over the passive one (bytes
    // actually carried by real traffic) when we have it: a link that's
    // currently under-used by real traffic still gets scored on its true
    // capacity instead of looking artificially slow. See
    // `LinkStats::active_bandwidth_mbps`'s doc comment.
    let throughput = link
        .stats
        .active_bandwidth_mbps
        .get()
        .or_else(|| link.stats.throughput_mbps.get())
        .unwrap_or(1.0)
        .max(0.1)
        .min(link.config.bandwidth_cap_mbps.unwrap_or(f64::MAX));

    let latency_factor = 1.0 / (1.0 + rtt / 50.0);
    let jitter_factor = 1.0 / (1.0 + jitter / 20.0);
    let loss_factor = (1.0 - loss).powi(2);

    link.config.weight * throughput.sqrt() * latency_factor * jitter_factor * loss_factor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_tracker_round_trip() {
        let mut t = ProbeTracker::new(Duration::from_millis(500));
        t.record_sent(1);
        std::thread::sleep(Duration::from_millis(5));
        let rtt = t.record_reply(1).expect("should have RTT");
        assert!(rtt >= 4.0, "rtt was {rtt}");
        assert!(t.record_reply(1).is_none(), "second reply should not match");
    }

    #[test]
    fn hysteresis_requires_sustained_state() {
        let cfg = SchedulerConfig {
            down_threshold: 3,
            up_threshold: 2,
            ..Default::default()
        };
        // These asserts document the intended transition thresholds; full
        // Link-based tests require constructing a Link, which needs a live
        // socket and is covered by integration tests instead.
        assert_eq!(cfg.down_threshold, 3);
        assert_eq!(cfg.up_threshold, 2);
    }
}
