//! Per-link delivery feedback for the scheduler.
//!
//! A link whose probes succeed can still be a bad data path: a policed or
//! throttled link answers tiny probes fine while silently discarding most
//! of a bulk flow. This tracker compares what we *offered* a link (local
//! `tx_throughput_mbps`) with what the peer says it *received* on it
//! (`StatsShare` throughput, which we already receive once a second) and
//! derives a `factor` in `[MIN_FACTOR, 1.0]` that scales the link's SWRR
//! weight. Offered and delivered are both EWMAs sampled the same way on
//! each side, and the delivered/offered ratio is direction-specific by
//! construction: it only ever describes our own transmissions.
//!
//! State machine: `Normal` -> congestion detected (cut `factor` by the
//! delivered/offered ratio at once, so the offered rate lands just under
//! what the link delivered) -> `HoldDown` (no increase, hold time doubles
//! on every relapse) -> `Recovering` (slow multiplicative increase while
//! deliveries stay clean) -> `Normal` once back at 1.0.

use std::time::{Duration, Instant};

/// Floor for the factor. Low enough that a link policed to ~1 Mbps next to
/// a 500 Mbps one can be steered down to roughly its own capacity.
pub const MIN_FACTOR: f64 = 0.001;
/// Offered load below this is too little to judge a link by.
pub const MIN_OFFERED_MBPS: f64 = 0.25;
/// Deliveries below this fraction of the offered rate count as bad.
pub const BAD_RATIO: f64 = 0.85;
/// A first window this bad cuts immediately instead of waiting for a
/// second confirming window.
pub const SEVERE_RATIO: f64 = 0.3;
/// Minimum absolute shortfall (Mbps) for a window to count as bad.
pub const MIN_SHORTFALL_MBPS: f64 = 0.1;
/// Landing margin: after a cut the offered rate targets this fraction of
/// the delivered rate rather than exactly it.
pub const CUT_MARGIN: f64 = 0.9;
/// Evidence windows ignored after a cut, while the offered/delivered EWMAs
/// still reflect the pre-cut rate.
pub const SETTLE_WINDOWS: u32 = 3;
/// First hold-down after a cut, doubled on each relapse up to `HOLD_MAX`.
pub const HOLD_BASE: Duration = Duration::from_secs(5);
pub const HOLD_MAX: Duration = Duration::from_secs(60);
/// Multiplicative increase per second while recovering.
pub const RECOVER_PER_SEC: f64 = 0.10;
/// Clean evidence windows required before each recovery increase.
pub const CLEAN_WINDOWS_TO_GROW: u32 = 2;
/// Peer stats older than this are not evidence.
pub const STALE_AFTER: Duration = Duration::from_secs(3);
/// Time at full health after which the relapse hold-down resets.
pub const RESET_AFTER: Duration = Duration::from_secs(60);
/// A link's `tx_throughput_mbps` EWMA only moves while it sends; a sample
/// older than this means the link is idle, not that it offers its last rate.
pub const IDLE_AFTER: Duration = Duration::from_millis(2500);
/// A link below this factor is reported as degraded.
pub const DEGRADED_BELOW: f64 = 0.7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Normal,
    HoldDown,
    Recovering,
}

#[derive(Clone, Copy, Debug)]
pub struct DeliverySample {
    pub offered_mbps: f64,
    pub delivered_mbps: f64,
    /// When the peer's stats frame arrived; identifies a fresh window.
    pub stamp: Instant,
}

#[derive(Debug)]
pub struct DeliveryTracker {
    factor: f64,
    phase: Phase,
    last_stamp: Option<Instant>,
    last_tick: Option<Instant>,
    bad_windows: u32,
    clean_windows: u32,
    settle_left: u32,
    hold_until: Option<Instant>,
    hold: Duration,
    healthy_since: Option<Instant>,
}

impl Default for DeliveryTracker {
    fn default() -> Self {
        Self {
            factor: 1.0,
            phase: Phase::Normal,
            last_stamp: None,
            last_tick: None,
            bad_windows: 0,
            clean_windows: 0,
            settle_left: 0,
            hold_until: None,
            hold: HOLD_BASE,
            healthy_since: None,
        }
    }
}

impl DeliveryTracker {
    pub fn factor(&self) -> f64 {
        self.factor
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Fold one observation in. `sample` is `None` when the peer's stats
    /// are missing, the link is idle, or the peer reports the link down.
    pub fn observe(&mut self, now: Instant, sample: Option<DeliverySample>) -> f64 {
        let dt = self
            .last_tick
            .map_or(0.0, |t| now.saturating_duration_since(t).as_secs_f64());
        self.last_tick = Some(now);

        if self.phase == Phase::HoldDown && self.hold_until.is_none_or(|t| now >= t) {
            self.phase = Phase::Recovering;
        }

        let fresh = sample.filter(|s| {
            self.last_stamp != Some(s.stamp) && now.saturating_duration_since(s.stamp) < STALE_AFTER
        });
        match fresh {
            Some(s) => {
                self.last_stamp = Some(s.stamp);
                self.evaluate_window(now, s);
            }
            None if sample.is_none() => {
                self.bad_windows = 0;
            }
            None => {}
        }

        if self.phase == Phase::Recovering && self.settle_left == 0 {
            let idle = sample.is_none();
            if idle || self.clean_windows >= CLEAN_WINDOWS_TO_GROW {
                self.factor = (self.factor * (1.0 + RECOVER_PER_SEC * dt)).min(1.0);
                if self.factor >= 1.0 {
                    self.phase = Phase::Normal;
                    self.healthy_since = Some(now);
                }
            }
        }

        if self.phase == Phase::Normal
            && self
                .healthy_since
                .is_some_and(|t| now.saturating_duration_since(t) >= RESET_AFTER)
        {
            self.hold = HOLD_BASE;
        }
        self.factor
    }

    fn evaluate_window(&mut self, now: Instant, s: DeliverySample) {
        if self.settle_left > 0 {
            self.settle_left -= 1;
            return;
        }
        let loaded = s.offered_mbps >= MIN_OFFERED_MBPS;
        let ratio = if loaded {
            (s.delivered_mbps / s.offered_mbps).clamp(0.0, 1.0)
        } else {
            1.0
        };
        let bad =
            loaded && ratio < BAD_RATIO && s.offered_mbps - s.delivered_mbps >= MIN_SHORTFALL_MBPS;
        if bad {
            self.bad_windows += 1;
            self.clean_windows = 0;
        } else {
            self.bad_windows = 0;
            self.clean_windows += 1;
        }

        if bad && (self.bad_windows >= 2 || ratio < SEVERE_RATIO) {
            self.cut(now, ratio);
        }
    }

    fn cut(&mut self, now: Instant, ratio: f64) {
        if self.phase == Phase::Recovering {
            self.hold = (self.hold * 2).min(HOLD_MAX);
        }
        self.factor = (self.factor * ratio * CUT_MARGIN).clamp(MIN_FACTOR, 1.0);
        self.phase = Phase::HoldDown;
        self.hold_until = Some(now + self.hold);
        self.settle_left = SETTLE_WINDOWS;
        self.bad_windows = 0;
        self.clean_windows = 0;
        self.healthy_since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sim {
        tr: DeliveryTracker,
        t0: Instant,
        now: Instant,
    }

    impl Sim {
        fn new() -> Self {
            let t0 = Instant::now();
            Self {
                tr: DeliveryTracker::default(),
                t0,
                now: t0,
            }
        }

        fn second(&mut self, offered: f64, delivered: f64) -> f64 {
            self.now += Duration::from_secs(1);
            self.tr.observe(
                self.now,
                Some(DeliverySample {
                    offered_mbps: offered,
                    delivered_mbps: delivered,
                    stamp: self.now,
                }),
            )
        }

        fn idle_second(&mut self) -> f64 {
            self.now += Duration::from_secs(1);
            self.tr.observe(self.now, None)
        }

        fn elapsed(&self) -> u64 {
            (self.now - self.t0).as_secs()
        }
    }

    /// Link policed to `cap` Mbps next to a total of `total` Mbps offered
    /// across links: offered = factor-share of total, delivered = min.
    fn policed(tr_factor: f64, total: f64, cap: f64) -> (f64, f64) {
        let offered = tr_factor * total / (1.0 + tr_factor);
        (offered, offered.min(cap))
    }

    #[test]
    fn healthy_link_is_never_touched() {
        let mut s = Sim::new();
        for _ in 0..120 {
            assert_eq!(s.second(200.0, 199.0), 1.0);
        }
        assert_eq!(s.tr.phase(), Phase::Normal);
    }

    #[test]
    fn idle_or_trickle_links_are_not_judged() {
        let mut s = Sim::new();
        for _ in 0..30 {
            assert_eq!(s.second(0.05, 0.0), 1.0);
        }
        for _ in 0..30 {
            assert_eq!(s.idle_second(), 1.0);
        }
    }

    #[test]
    fn severe_loss_cuts_in_one_window() {
        let mut s = Sim::new();
        let f = s.second(20.0, 1.0);
        assert!((f - 0.05 * CUT_MARGIN).abs() < 1e-9, "factor {f}");
        assert_eq!(s.tr.phase(), Phase::HoldDown);
    }

    #[test]
    fn moderate_loss_needs_two_windows() {
        let mut s = Sim::new();
        assert_eq!(s.second(10.0, 6.0), 1.0);
        let f = s.second(10.0, 6.0);
        assert!((f - 0.6 * CUT_MARGIN).abs() < 1e-9, "factor {f}");
    }

    #[test]
    fn one_bad_window_amid_clean_ones_is_noise() {
        let mut s = Sim::new();
        for _ in 0..10 {
            s.second(50.0, 50.0);
            assert_eq!(s.second(50.0, 40.0), 1.0);
        }
    }

    #[test]
    fn settle_windows_block_over_cutting_on_lagging_ewmas() {
        let mut s = Sim::new();
        let f = s.second(20.0, 1.0);
        for _ in 0..SETTLE_WINDOWS {
            assert_eq!(s.second(20.0, 1.0), f, "stale evidence must not re-cut");
        }
    }

    #[test]
    fn hold_down_blocks_recovery() {
        let mut s = Sim::new();
        let f = s.second(20.0, 1.0);
        for _ in 0..4 {
            assert_eq!(s.second(1.0, 1.0), f);
        }
    }

    #[test]
    fn policed_link_converges_near_capacity_and_stays_small() {
        // 1 Mbps policed link against 400 Mbps carried by the healthy one.
        let mut s = Sim::new();
        let mut f = 1.0;
        let mut over_windows = 0;
        let mut samples = 0;
        for _ in 0..600 {
            let (o, d) = policed(f, 400.0, 1.0);
            f = s.second(o, d);
            if s.elapsed() > 120 {
                samples += 1;
                if o > 1.0 * 1.05 {
                    over_windows += 1;
                }
            }
        }
        let (o, _) = policed(f, 400.0, 1.0);
        assert!(o < 3.0, "offered {o} Mbps to a 1 Mbps link");
        assert!(
            over_windows * 4 < samples,
            "oversubscribed {over_windows}/{samples} windows"
        );
    }

    #[test]
    fn relapse_doubles_hold_down_up_to_the_cap() {
        let mut s = Sim::new();
        s.second(20.0, 1.0);
        let mut holds = Vec::new();
        for _ in 0..6 {
            // Wait out the hold-down, recover, then relapse.
            let mut guard = 0;
            while s.tr.phase() == Phase::HoldDown {
                s.second(1.0, 1.0);
                guard += 1;
                assert!(guard < 200);
            }
            guard = 0;
            let before = s.now;
            while s.tr.phase() == Phase::Recovering && s.tr.factor() < 0.9 {
                let (o, d) = policed(s.tr.factor(), 400.0, 1.0);
                s.second(o, d);
                if s.tr.phase() == Phase::HoldDown {
                    holds.push(s.tr.hold);
                    break;
                }
                guard += 1;
                assert!(guard < 400);
            }
            let _ = before;
        }
        assert!(holds.windows(2).all(|w| w[1] >= w[0]), "{holds:?}");
        assert!(holds.iter().all(|h| *h <= HOLD_MAX));
        assert!(holds.last().copied() >= Some(HOLD_BASE * 4), "{holds:?}");
    }

    #[test]
    fn a_link_that_stops_being_limited_recovers_fully() {
        let mut s = Sim::new();
        s.second(20.0, 1.0);
        for _ in 0..400 {
            s.second(5.0, 5.0);
        }
        assert_eq!(s.tr.factor(), 1.0);
        assert_eq!(s.tr.phase(), Phase::Normal);
    }

    #[test]
    fn stale_or_repeated_stamps_are_not_new_evidence() {
        let mut s = Sim::new();
        let stamp = s.now;
        let sample = DeliverySample {
            offered_mbps: 20.0,
            delivered_mbps: 1.0,
            stamp,
        };
        s.now += Duration::from_millis(500);
        let f = s.tr.observe(s.now, Some(sample));
        assert!(f < 1.0);
        // Same stamp again: ignored (no second cut even after settle).
        for _ in 0..10 {
            s.now += Duration::from_millis(250);
            assert_eq!(s.tr.observe(s.now, Some(sample)), f);
        }
        // A stamp older than STALE_AFTER is not evidence either.
        let mut s2 = Sim::new();
        s2.now += Duration::from_secs(10);
        let old = DeliverySample {
            offered_mbps: 20.0,
            delivered_mbps: 1.0,
            stamp: s2.t0,
        };
        assert_eq!(s2.tr.observe(s2.now, Some(old)), 1.0);
    }

    #[test]
    fn factor_never_leaves_its_bounds() {
        let mut s = Sim::new();
        for i in 0..2000 {
            let f = if i % 7 < 3 {
                s.second(100.0, 0.0)
            } else {
                s.second(100.0, 100.0)
            };
            assert!((MIN_FACTOR..=1.0).contains(&f), "factor {f}");
        }
    }
}
