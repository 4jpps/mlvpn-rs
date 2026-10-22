//! Per-link congestion tracking for the scheduler (Phase 4).
//!
//! Each link's TX worker publishes queue-delay / send-failure counters
//! (`link::TxCounters`). Every tick the scheduler feeds interval deltas of
//! those counters through a `CongestionTracker`, which maintains a
//! `factor` in `[MIN_FACTOR, 1.0]` that scales the link's SWRR weight.
//!
//! Asymmetric on purpose: the factor drops immediately when a link
//! congests (queue delay is the earliest honest signal) but recovers
//! gradually, after a short hold-down, so a link that just stopped being
//! congested is not instantly handed its full share back and re-congested.

use std::time::{Duration, Instant};

use crate::link::{TxCounters, mono_us};
use std::sync::atomic::Ordering;

/// Weight multiplier floor: a congested link still keeps a trickle of
/// traffic (and a non-zero SWRR weight) so its recovery stays observable.
pub const MIN_FACTOR: f64 = 0.1;
/// Upper bound on the factor while any queue-full event occurred in the
/// last window.
pub const QUEUE_FULL_CAP: f64 = 0.3;
/// Upper bound while any send failure occurred in the last window.
pub const SEND_FAILED_CAP: f64 = 0.25;
/// Factor gained per second of recovery.
pub const RECOVERY_PER_SEC: f64 = 0.15;
/// After a drop, no recovery for this long.
pub const HOLD_DOWN: Duration = Duration::from_secs(1);
/// Windows shorter than this are skipped (too few samples to trust).
pub const MIN_WINDOW: Duration = Duration::from_millis(50);
/// A link whose factor is below this is reported as degraded.
pub const DEGRADED_BELOW: f64 = 0.7;

/// Map an average queue delay to the factor the link could safely carry.
/// Thresholds per the improvement plan: <1 ms excellent, 1-5 ms normal,
/// 5-20 ms congested, >20 ms severe; piecewise-linear between anchors so
/// the factor moves smoothly rather than in steps.
pub fn delay_target(delay_us: u64) -> f64 {
    const ANCHORS: [(f64, f64); 5] = [
        (1_000.0, 1.0),
        (5_000.0, 0.8),
        (20_000.0, 0.3),
        (60_000.0, MIN_FACTOR),
        (f64::MAX, MIN_FACTOR),
    ];
    let d = delay_us as f64;
    if d <= ANCHORS[0].0 {
        return 1.0;
    }
    for w in ANCHORS.windows(2) {
        let (x0, y0) = w[0];
        let (x1, y1) = w[1];
        if d <= x1 {
            return y0 + (y1 - y0) * (d - x0) / (x1 - x0);
        }
    }
    MIN_FACTOR
}

/// One step of the asymmetric filter: drop to `target` immediately, rise
/// toward it at `RECOVERY_PER_SEC` unless `held` (still inside the
/// post-drop hold-down).
pub fn next_factor(current: f64, target: f64, dt_secs: f64, held: bool) -> f64 {
    let target = target.clamp(MIN_FACTOR, 1.0);
    if target < current {
        target
    } else if held {
        current
    } else {
        (current + RECOVERY_PER_SEC * dt_secs).min(target)
    }
}

/// A point-in-time read of one link's `TxCounters`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CounterSnapshot {
    pub delay_sum_us: u64,
    pub delay_samples: u64,
    pub send_wait_sum_us: u64,
    pub send_wait_samples: u64,
    pub queue_full: u64,
    pub send_failed: u64,
    /// Time since the worker last made progress, but only while packets
    /// are queued -- an idle link has no stall.
    pub stall_us: u64,
}

impl CounterSnapshot {
    pub fn read(c: &TxCounters) -> Self {
        let last = c.last_progress_us.load(Ordering::Relaxed);
        let stall_us = if last != 0 && c.depth.load(Ordering::Relaxed) > 0 {
            mono_us().saturating_sub(last)
        } else {
            0
        };
        Self {
            delay_sum_us: c.queue_delay_sum_us.load(Ordering::Relaxed),
            delay_samples: c.queue_delay_samples.load(Ordering::Relaxed),
            send_wait_sum_us: c.send_wait_sum_us.load(Ordering::Relaxed),
            send_wait_samples: c.send_wait_samples.load(Ordering::Relaxed),
            queue_full: c.queue_full.load(Ordering::Relaxed),
            send_failed: c.send_failed.load(Ordering::Relaxed),
            stall_us,
        }
    }
}

fn mean_delta(sum: u64, prev_sum: u64, n: u64, prev_n: u64) -> u64 {
    sum.wrapping_sub(prev_sum)
        .checked_div(n.wrapping_sub(prev_n))
        .unwrap_or(0)
}

#[derive(Debug)]
pub struct CongestionTracker {
    factor: f64,
    last_update: Option<Instant>,
    last_drop: Option<Instant>,
    prev: CounterSnapshot,
    delay_recent_us: u64,
    send_wait_recent_us: u64,
}

impl Default for CongestionTracker {
    fn default() -> Self {
        Self {
            factor: 1.0,
            last_update: None,
            last_drop: None,
            prev: CounterSnapshot::default(),
            delay_recent_us: 0,
            send_wait_recent_us: 0,
        }
    }
}

impl CongestionTracker {
    pub fn factor(&self) -> f64 {
        self.factor
    }

    pub fn delay_recent_us(&self) -> u64 {
        self.delay_recent_us
    }

    pub fn send_wait_recent_us(&self) -> u64 {
        self.send_wait_recent_us
    }

    /// Fold in the counters as of `now`; returns the (possibly updated)
    /// factor. Idle windows (no samples, nothing queued) read as zero
    /// delay, so an idle link recovers rather than staying penalized.
    pub fn update(&mut self, now: Instant, cur: CounterSnapshot) -> f64 {
        let Some(last) = self.last_update else {
            self.prev = cur;
            self.last_update = Some(now);
            return self.factor;
        };
        let dt = now.saturating_duration_since(last);
        if dt < MIN_WINDOW {
            return self.factor;
        }
        let avg_delay = mean_delta(
            cur.delay_sum_us,
            self.prev.delay_sum_us,
            cur.delay_samples,
            self.prev.delay_samples,
        );
        self.send_wait_recent_us = mean_delta(
            cur.send_wait_sum_us,
            self.prev.send_wait_sum_us,
            cur.send_wait_samples,
            self.prev.send_wait_samples,
        );
        self.delay_recent_us = avg_delay.max(cur.stall_us);
        let mut target = delay_target(self.delay_recent_us);
        if cur.queue_full != self.prev.queue_full {
            target = target.min(QUEUE_FULL_CAP);
        }
        if cur.send_failed != self.prev.send_failed {
            target = target.min(SEND_FAILED_CAP);
        }
        let held = self
            .last_drop
            .is_some_and(|t| now.saturating_duration_since(t) < HOLD_DOWN);
        let next = next_factor(self.factor, target, dt.as_secs_f64(), held);
        if next < self.factor {
            self.last_drop = Some(now);
        }
        self.factor = next;
        self.prev = cur;
        self.last_update = Some(now);
        self.factor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(delay_sum_us: u64, delay_samples: u64) -> CounterSnapshot {
        CounterSnapshot {
            delay_sum_us,
            delay_samples,
            ..Default::default()
        }
    }

    #[test]
    fn delay_target_follows_plan_thresholds() {
        assert_eq!(delay_target(0), 1.0);
        assert_eq!(delay_target(999), 1.0);
        assert!((delay_target(5_000) - 0.8).abs() < 1e-9);
        assert!((delay_target(20_000) - 0.3).abs() < 1e-9);
        assert!((delay_target(60_000) - MIN_FACTOR).abs() < 1e-9);
        assert_eq!(delay_target(5_000_000), MIN_FACTOR);
        let mut prev = 1.0;
        for d in (0..100_000).step_by(500) {
            let t = delay_target(d);
            assert!(t <= prev + 1e-12, "non-monotonic at {d}");
            prev = t;
        }
    }

    #[test]
    fn factor_drops_immediately_and_recovers_gradually() {
        assert_eq!(next_factor(1.0, 0.2, 0.1, false), 0.2);
        let up = next_factor(0.2, 1.0, 1.0, false);
        assert!((up - (0.2 + RECOVERY_PER_SEC)).abs() < 1e-9);
        assert_eq!(next_factor(0.2, 1.0, 5.0, true), 0.2, "held: no recovery");
        assert_eq!(next_factor(0.9, 1.0, 5.0, false), 1.0, "capped at target");
    }

    #[test]
    fn tracker_reacts_then_recovers_after_hold_down() {
        let t0 = Instant::now();
        let mut tr = CongestionTracker::default();
        tr.update(t0, snap(0, 0));
        // 100 samples averaging 30 ms: severe.
        let f = tr.update(t0 + Duration::from_millis(100), snap(3_000_000, 100));
        assert!((f - 0.25).abs() < 1e-9, "factor {f}");
        assert_eq!(tr.delay_recent_us(), 30_000);
        // Idle windows read as zero delay but the hold-down blocks recovery.
        let f2 = tr.update(t0 + Duration::from_millis(600), snap(3_000_000, 100));
        assert_eq!(f2, f);
        assert_eq!(tr.delay_recent_us(), 0);
        // Past hold-down: gradual, not instant.
        let f3 = tr.update(t0 + Duration::from_millis(2100), snap(3_000_000, 100));
        assert!(f3 > f && f3 < 1.0, "factor {f3}");
        // Eventually fully recovered.
        let mut now = t0 + Duration::from_millis(2100);
        for _ in 0..100 {
            now += Duration::from_millis(100);
            tr.update(now, snap(3_000_000, 100));
        }
        assert_eq!(tr.factor(), 1.0);
    }

    #[test]
    fn queue_full_and_send_failure_cap_the_target() {
        let t0 = Instant::now();
        let mut tr = CongestionTracker::default();
        tr.update(t0, CounterSnapshot::default());
        let f = tr.update(
            t0 + Duration::from_millis(100),
            CounterSnapshot {
                queue_full: 1,
                ..Default::default()
            },
        );
        assert!((f - QUEUE_FULL_CAP).abs() < 1e-9);
        let f = tr.update(
            t0 + Duration::from_millis(200),
            CounterSnapshot {
                queue_full: 1,
                send_failed: 1,
                ..Default::default()
            },
        );
        assert!((f - SEND_FAILED_CAP).abs() < 1e-9);
    }

    #[test]
    fn stalled_worker_counts_as_delay_even_without_new_samples() {
        let t0 = Instant::now();
        let mut tr = CongestionTracker::default();
        tr.update(t0, CounterSnapshot::default());
        let f = tr.update(
            t0 + Duration::from_millis(100),
            CounterSnapshot {
                stall_us: 500_000,
                ..Default::default()
            },
        );
        assert_eq!(f, MIN_FACTOR);
    }

    #[test]
    fn short_windows_are_ignored() {
        let t0 = Instant::now();
        let mut tr = CongestionTracker::default();
        tr.update(t0, snap(0, 0));
        let f = tr.update(t0 + Duration::from_millis(10), snap(9_000_000, 10));
        assert_eq!(f, 1.0);
    }

    #[test]
    fn steady_moderate_delay_does_not_oscillate() {
        let t0 = Instant::now();
        let mut tr = CongestionTracker::default();
        tr.update(t0, snap(0, 0));
        let (mut sum, mut n) = (0u64, 0u64);
        let mut now = t0;
        let mut factors = Vec::new();
        for _ in 0..100 {
            now += Duration::from_millis(100);
            sum += 3_000 * 50;
            n += 50;
            factors.push(tr.update(now, snap(sum, n)));
        }
        // 3 ms is "normal": settles at delay_target(3000) and stays.
        let target = delay_target(3_000);
        for f in &factors[1..] {
            assert!((f - target).abs() < 1e-9, "factor {f} vs {target}");
        }
    }
}
