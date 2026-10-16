//! Decision logic for automatic loss reports (`control::diagnostics_watch_loop`).
//!
//! Everything here is pure and clock-injected so it can be table-tested.
//! The trigger reads *raw* probe outcomes over a sliding window rather than
//! the scheduler's loss EWMA: with `auto_tune_ewma_alpha` a single missed
//! probe jumps alpha to 0.5, so one miss on a healthy link reads ~52% and
//! the EWMA falls back under 10% after ~4 hits, which both false-alarms on
//! blips and hides chronic 12-30% loss. The EWMA itself is left untouched.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const PROBE_HISTORY: Duration = Duration::from_secs(120);
const PROBE_HISTORY_MAX_SAMPLES: usize = 8192;
const DOWN_HISTORY: Duration = Duration::from_secs(3600);
const DOWN_HISTORY_MAX_SAMPLES: usize = 256;

/// Recent probe outcomes (hit = true) for one link, newest last.
#[derive(Debug, Clone, Default)]
pub struct ProbeWindow {
    samples: VecDeque<(Instant, bool)>,
}

impl ProbeWindow {
    pub fn record(&mut self, now: Instant, hit: bool) {
        self.samples.push_back((now, hit));
        while let Some(&(t, _)) = self.samples.front() {
            if now.saturating_duration_since(t) > PROBE_HISTORY
                || self.samples.len() > PROBE_HISTORY_MAX_SAMPLES
            {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Raw loss percentage over the last `window`, or `None` with fewer
    /// than `min_probes` probes in it (too little data to call).
    pub fn loss_pct(&self, now: Instant, window: Duration, min_probes: usize) -> Option<f64> {
        let (mut total, mut missed) = (0usize, 0usize);
        for &(t, hit) in self.samples.iter().rev() {
            if now.saturating_duration_since(t) > window {
                break;
            }
            total += 1;
            if !hit {
                missed += 1;
            }
        }
        if total < min_probes.max(1) {
            return None;
        }
        Some(missed as f64 * 100.0 / total as f64)
    }
}

/// When a link last went Up -> Down, for the flap trigger.
#[derive(Debug, Clone, Default)]
pub struct DownTransitions {
    times: VecDeque<Instant>,
}

impl DownTransitions {
    pub fn record(&mut self, now: Instant) {
        self.times.push_back(now);
        while let Some(&t) = self.times.front() {
            if now.saturating_duration_since(t) > DOWN_HISTORY
                || self.times.len() > DOWN_HISTORY_MAX_SAMPLES
            {
                self.times.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn count_within(&self, now: Instant, window: Duration) -> u32 {
        self.times
            .iter()
            .filter(|&&t| now.saturating_duration_since(t) <= window)
            .count() as u32
    }
}

#[derive(Debug, Clone)]
pub struct TriggerCfg {
    pub threshold_pct: f64,
    pub window: Duration,
    pub min_probes: usize,
    /// Down transitions within `flap_window` that open an event; 0 disables.
    pub flap_downs: u32,
    pub flap_window: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Reason {
    Loss(f64),
    Flap(u32),
}

impl Reason {
    pub fn describe(&self, cfg: &TriggerCfg) -> String {
        match self {
            Reason::Loss(p) => format!(
                "raw probe loss {p:.1}% over last {}s exceeded threshold {:.1}%",
                cfg.window.as_secs(),
                cfg.threshold_pct
            ),
            Reason::Flap(n) => format!(
                "{n} Down transitions in the last {}s",
                cfg.flap_window.as_secs()
            ),
        }
    }
}

/// Is this link currently in a reportable state? Loss takes precedence
/// over flapping.
pub fn evaluate(
    probes: &ProbeWindow,
    downs: &DownTransitions,
    now: Instant,
    cfg: &TriggerCfg,
) -> Option<Reason> {
    if let Some(p) = probes.loss_pct(now, cfg.window, cfg.min_probes) {
        if p > cfg.threshold_pct {
            return Some(Reason::Loss(p));
        }
    }
    if cfg.flap_downs > 0 {
        let n = downs.count_within(now, cfg.flap_window);
        if n >= cfg.flap_downs {
            return Some(Reason::Flap(n));
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct TrackerCfg {
    /// Continuous clear time that ends an event.
    pub clear: Duration,
    /// Minimum gap between ticket submissions for one ongoing event.
    pub reminder: Duration,
    /// A link opening within this long of another open event rides on that
    /// event's ticket instead of filing its own.
    pub join: Duration,
    /// Minimum gap between local dump files while an event continues.
    pub dump_cooldown: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpKind {
    Opened,
    Reminder,
    Ongoing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Quiet,
    Dump { submit: bool, kind: DumpKind },
    Ended,
}

#[derive(Debug, Clone)]
struct Event {
    opened_at: Instant,
    last_dump: Instant,
    last_submit: Instant,
    clear_since: Option<Instant>,
}

/// Per-link event state machine: one ticket when an event opens, one
/// reminder per `reminder`, event ends after `clear` of continuous quiet.
/// A link that re-opens an event within `reminder` of its last ticket (loss
/// hovering around the threshold) is dumped locally but not ticketed again.
#[derive(Debug)]
pub struct EventTracker {
    cfg: TrackerCfg,
    events: HashMap<String, Event>,
    last_submit: HashMap<String, Instant>,
    dirty: bool,
}

/// What survives a daemon restart: when each open event last filed a
/// ticket, as unix seconds (monotonic instants don't persist).
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PersistedEvents {
    pub last_submit_unix: HashMap<String, u64>,
}

impl EventTracker {
    pub fn new(cfg: TrackerCfg) -> Self {
        Self {
            cfg,
            events: HashMap::new(),
            last_submit: HashMap::new(),
            dirty: false,
        }
    }

    pub fn observe(&mut self, now: Instant, link: &str, reason: Option<&Reason>) -> Outcome {
        match (reason, self.events.contains_key(link)) {
            (Some(_), false) => {
                let rides = self
                    .events
                    .values()
                    .any(|e| now.saturating_duration_since(e.opened_at) < self.cfg.join);
                let recent = self
                    .last_submit
                    .get(link)
                    .copied()
                    .filter(|&at| now.saturating_duration_since(at) < self.cfg.reminder);
                let submit = !rides && recent.is_none();
                if submit || rides {
                    self.last_submit.insert(link.to_string(), now);
                }
                self.events.insert(
                    link.to_string(),
                    Event {
                        opened_at: now,
                        last_dump: now,
                        last_submit: self.last_submit.get(link).copied().unwrap_or(now),
                        clear_since: None,
                    },
                );
                self.dirty = true;
                Outcome::Dump {
                    submit,
                    kind: DumpKind::Opened,
                }
            }
            (Some(_), true) => {
                let ev = self.events.get_mut(link).expect("checked above");
                ev.clear_since = None;
                if now.saturating_duration_since(ev.last_submit) >= self.cfg.reminder {
                    ev.last_submit = now;
                    ev.last_dump = now;
                    self.last_submit.insert(link.to_string(), now);
                    self.dirty = true;
                    Outcome::Dump {
                        submit: true,
                        kind: DumpKind::Reminder,
                    }
                } else if now.saturating_duration_since(ev.last_dump) >= self.cfg.dump_cooldown {
                    ev.last_dump = now;
                    Outcome::Dump {
                        submit: false,
                        kind: DumpKind::Ongoing,
                    }
                } else {
                    Outcome::Quiet
                }
            }
            (None, true) => {
                let ev = self.events.get_mut(link).expect("checked above");
                let since = *ev.clear_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= self.cfg.clear {
                    self.events.remove(link);
                    self.dirty = true;
                    Outcome::Ended
                } else {
                    Outcome::Quiet
                }
            }
            (None, false) => Outcome::Quiet,
        }
    }

    /// `Some` when the open-event set or a submit time changed since the last call.
    pub fn take_dirty_state(&mut self, now: Instant, now_unix: u64) -> Option<PersistedEvents> {
        if !std::mem::take(&mut self.dirty) {
            return None;
        }
        let last_submit_unix = self
            .last_submit
            .iter()
            .filter(|(_, &at)| now.saturating_duration_since(at) < self.cfg.reminder)
            .map(|(k, &at)| {
                let age = now.saturating_duration_since(at).as_secs();
                (k.clone(), now_unix.saturating_sub(age))
            })
            .collect();
        Some(PersistedEvents { last_submit_unix })
    }

    /// Re-adopt events that were open before a restart so they don't
    /// re-ticket; entries older than the reminder interval are dropped
    /// (the next exceedance is allowed to file a fresh ticket).
    pub fn restore(&mut self, now: Instant, now_unix: u64, persisted: PersistedEvents) {
        for (link, submitted_unix) in persisted.last_submit_unix {
            let age = Duration::from_secs(now_unix.saturating_sub(submitted_unix));
            if age >= self.cfg.reminder {
                continue;
            }
            let at = now.checked_sub(age).unwrap_or(now);
            self.last_submit.insert(link.clone(), at);
            self.events.insert(
                link,
                Event {
                    opened_at: at,
                    last_dump: now,
                    last_submit: at,
                    clear_since: None,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trig() -> TriggerCfg {
        TriggerCfg {
            threshold_pct: 10.0,
            window: Duration::from_secs(60),
            min_probes: 20,
            flap_downs: 3,
            flap_window: Duration::from_secs(600),
        }
    }

    fn trk() -> TrackerCfg {
        TrackerCfg {
            clear: Duration::from_secs(60),
            reminder: Duration::from_secs(3600),
            join: Duration::from_secs(60),
            dump_cooldown: Duration::from_secs(300),
        }
    }

    /// One probe per second for `secs` seconds starting at `t0 + start`;
    /// `miss(i)` decides whether probe `i` (0-based within this run) is lost.
    fn feed(w: &mut ProbeWindow, t0: Instant, start: u64, secs: u64, miss: impl Fn(u64) -> bool) {
        for i in 0..secs {
            w.record(t0 + Duration::from_secs(start + i), !miss(i));
        }
    }

    fn eval(w: &ProbeWindow, t0: Instant, at: u64) -> Option<Reason> {
        evaluate(
            w,
            &DownTransitions::default(),
            t0 + Duration::from_secs(at),
            &trig(),
        )
    }

    #[test]
    fn single_miss_on_healthy_link_is_quiet() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::default();
        feed(&mut w, t0, 0, 60, |i| i == 30);
        assert_eq!(eval(&w, t0, 59), None);
    }

    #[test]
    fn three_consecutive_misses_in_a_minute_is_quiet() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::default();
        feed(&mut w, t0, 0, 60, |i| (30..33).contains(&i));
        assert_eq!(eval(&w, t0, 59), None);
    }

    #[test]
    fn chronic_12_percent_fires() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::default();
        feed(&mut w, t0, 0, 120, |i| i % 8 == 0);
        assert!(matches!(eval(&w, t0, 119), Some(Reason::Loss(p)) if p > 10.0 && p < 14.0));
    }

    #[test]
    fn chronic_30_percent_fires() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::default();
        feed(&mut w, t0, 0, 120, |i| i % 10 < 3);
        assert!(matches!(eval(&w, t0, 119), Some(Reason::Loss(p)) if (28.0..=32.0).contains(&p)));
    }

    #[test]
    fn full_outage_fires_at_100_percent() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::default();
        feed(&mut w, t0, 0, 60, |_| true);
        assert_eq!(eval(&w, t0, 59), Some(Reason::Loss(100.0)));
    }

    #[test]
    fn too_few_probes_never_fires_even_at_total_loss() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::default();
        feed(&mut w, t0, 0, 5, |_| true);
        assert_eq!(eval(&w, t0, 4), None);
    }

    #[test]
    fn recovery_decays_below_threshold_within_the_window() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::default();
        feed(&mut w, t0, 0, 60, |_| true);
        feed(&mut w, t0, 60, 60, |_| false);
        assert_eq!(eval(&w, t0, 119), None);
        assert!(eval(&w, t0, 70).is_some());
    }

    #[test]
    fn slower_probe_interval_still_judged_by_ratio() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::default();
        // 0.5 probes/s for 2 minutes with every 4th lost = 25%
        for i in 0..60u64 {
            w.record(t0 + Duration::from_secs(i * 2), i % 4 != 0);
        }
        assert!(matches!(eval(&w, t0, 118), Some(Reason::Loss(p)) if p > 20.0));
    }

    #[test]
    fn flap_trigger_opens_on_three_downs_in_ten_minutes() {
        let t0 = Instant::now();
        let w = ProbeWindow::default();
        let mut d = DownTransitions::default();
        d.record(t0);
        d.record(t0 + Duration::from_secs(120));
        let at = t0 + Duration::from_secs(300);
        assert_eq!(evaluate(&w, &d, at, &trig()), None);
        d.record(t0 + Duration::from_secs(240));
        assert_eq!(evaluate(&w, &d, at, &trig()), Some(Reason::Flap(3)));
        let later = t0 + Duration::from_secs(900);
        assert_eq!(evaluate(&w, &d, later, &trig()), None);
    }

    #[test]
    fn flap_trigger_can_be_disabled() {
        let t0 = Instant::now();
        let mut d = DownTransitions::default();
        for i in 0..10 {
            d.record(t0 + Duration::from_secs(i));
        }
        let mut cfg = trig();
        cfg.flap_downs = 0;
        let at = t0 + Duration::from_secs(10);
        assert_eq!(evaluate(&ProbeWindow::default(), &d, at, &cfg), None);
    }

    fn loss() -> Reason {
        Reason::Loss(50.0)
    }

    #[test]
    fn tracker_submits_once_then_reminds_hourly() {
        let t0 = Instant::now();
        let mut t = EventTracker::new(trk());
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert_eq!(
            t.observe(at(0), "a", Some(&loss())),
            Outcome::Dump {
                submit: true,
                kind: DumpKind::Opened
            }
        );
        assert_eq!(t.observe(at(5), "a", Some(&loss())), Outcome::Quiet);
        assert_eq!(
            t.observe(at(300), "a", Some(&loss())),
            Outcome::Dump {
                submit: false,
                kind: DumpKind::Ongoing
            }
        );
        assert_eq!(
            t.observe(at(3600), "a", Some(&loss())),
            Outcome::Dump {
                submit: true,
                kind: DumpKind::Reminder
            }
        );
    }

    #[test]
    fn event_ends_only_after_a_full_clear_period() {
        let t0 = Instant::now();
        let mut t = EventTracker::new(trk());
        let at = |s: u64| t0 + Duration::from_secs(s);
        t.observe(at(0), "a", Some(&loss()));
        assert_eq!(t.observe(at(10), "a", None), Outcome::Quiet);
        assert_eq!(t.observe(at(40), "a", None), Outcome::Quiet);
        // flaps back before the clear period elapses: same event, no new ticket
        assert_eq!(t.observe(at(50), "a", Some(&loss())), Outcome::Quiet);
        assert_eq!(t.observe(at(60), "a", None), Outcome::Quiet);
        assert_eq!(t.observe(at(120), "a", None), Outcome::Ended);
        // re-opens within the reminder interval of the last ticket: dumped, not ticketed
        assert_eq!(
            t.observe(at(130), "a", Some(&loss())),
            Outcome::Dump {
                submit: false,
                kind: DumpKind::Opened
            }
        );
    }

    #[test]
    fn reopening_event_files_one_ticket_per_reminder_interval() {
        let t0 = Instant::now();
        let mut t = EventTracker::new(trk());
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut submits = 0;
        // loss hovers at the threshold: opens, clears for 2 min, reopens, for 50 min
        for cycle in 0..10u64 {
            let base = cycle * 300;
            if let Outcome::Dump { submit, .. } = t.observe(at(base), "a", Some(&loss())) {
                submits += usize::from(submit);
            }
            t.observe(at(base + 60), "a", None);
            t.observe(at(base + 130), "a", None);
        }
        assert_eq!(submits, 1);
        // an hour after the ticket a new event files again
        assert_eq!(
            t.observe(at(3700), "a", Some(&loss())),
            Outcome::Dump {
                submit: true,
                kind: DumpKind::Opened
            }
        );
    }

    #[test]
    fn second_link_within_join_window_rides_on_first_ticket() {
        let t0 = Instant::now();
        let mut t = EventTracker::new(trk());
        let at = |s: u64| t0 + Duration::from_secs(s);
        t.observe(at(0), "a", Some(&loss()));
        assert_eq!(
            t.observe(at(30), "b", Some(&loss())),
            Outcome::Dump {
                submit: false,
                kind: DumpKind::Opened
            }
        );
        assert_eq!(
            t.observe(at(200), "c", Some(&loss())),
            Outcome::Dump {
                submit: true,
                kind: DumpKind::Opened
            }
        );
    }

    #[test]
    fn restart_does_not_reticket_an_ongoing_event() {
        let t0 = Instant::now();
        let mut t = EventTracker::new(trk());
        t.observe(t0, "a", Some(&loss()));
        let now = t0 + Duration::from_secs(600);
        let saved = t
            .take_dirty_state(now, 1_000_000)
            .expect("dirty after open");
        assert_eq!(saved.last_submit_unix["a"], 1_000_000 - 600);
        assert!(t.take_dirty_state(now, 1_000_000).is_none());

        let mut fresh = EventTracker::new(trk());
        fresh.restore(now, 1_000_000, saved);
        let out = fresh.observe(now + Duration::from_secs(5), "a", Some(&loss()));
        assert_eq!(out, Outcome::Quiet);
    }

    #[test]
    fn stale_persisted_event_is_forgotten() {
        let now = Instant::now();
        let mut p = PersistedEvents::default();
        p.last_submit_unix.insert("a".into(), 1_000_000 - 7200);
        let mut t = EventTracker::new(trk());
        t.restore(now, 1_000_000, p);
        assert_eq!(
            t.observe(now, "a", Some(&loss())),
            Outcome::Dump {
                submit: true,
                kind: DumpKind::Opened
            }
        );
    }

    /// Replays the shape of the 48 real auto-tickets from 2026-10-07..13:
    /// ~11 single/double-miss blips, one ~56 min outage (was 12 tickets)
    /// and one ~107 min outage (was 25), through the real trigger + tracker.
    fn simulate(secs: u64, miss: impl Fn(u64) -> bool) -> (usize, usize) {
        let t0 = Instant::now();
        let mut w = ProbeWindow::default();
        let d = DownTransitions::default();
        let mut tr = EventTracker::new(trk());
        let (mut submits, mut dumps) = (0, 0);
        for s in 0..secs {
            w.record(t0 + Duration::from_secs(s), !miss(s));
            if s % 5 == 0 {
                let now = t0 + Duration::from_secs(s);
                let r = evaluate(&w, &d, now, &trig());
                if let Outcome::Dump { submit, .. } = tr.observe(now, "a", r.as_ref()) {
                    dumps += 1;
                    submits += usize::from(submit);
                }
            }
        }
        (submits, dumps)
    }

    #[test]
    fn replay_blips_file_no_tickets() {
        // an hour on a ~5% link with scattered 1-3 probe blips
        let (submits, dumps) = simulate(3600, |s| matches!(s % 300, 117..=119) || s % 997 == 500);
        assert_eq!((submits, dumps), (0, 0));
    }

    #[test]
    fn replay_56_minute_outage_files_one_ticket() {
        let (submits, _) = simulate(3600 + 120, |s| (60..60 + 56 * 60).contains(&s));
        assert_eq!(submits, 1);
    }

    #[test]
    fn replay_107_minute_outage_files_one_ticket_plus_one_hourly_reminder() {
        let (submits, _) = simulate(3 * 3600, |s| (60..60 + 107 * 60).contains(&s));
        assert_eq!(submits, 2);
    }
}
