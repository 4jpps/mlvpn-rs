//! Decision logic for automatic loss reports (`control::diagnostics_watch_loop`).
//!
//! Everything here is pure and clock-injected so it can be table-tested.
//! The trigger reads *raw* probe outcomes over a sliding window rather than
//! the scheduler's loss EWMA: with `auto_tune_ewma_alpha` a single missed
//! probe jumps alpha to 0.5, so one miss on a healthy link reads ~52%.
//! The EWMA itself is left untouched.
//!
//! Three event classes, strongest first: `Outage` (link not Up for longer
//! than `outage_after`), `Flap` (repeated Up->Down), and `Degraded` (a
//! long window of probes with both an absolute miss count and a loss
//! percentage over the open thresholds, holding for `CONFIRM`). One event
//! per link at a time, one ticket per event, no periodic reminders;
//! degraded events are additionally rate-limited per link.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const PROBE_HISTORY: Duration = Duration::from_secs(330);
const PROBE_HISTORY_MAX_SAMPLES: usize = 16384;
const DOWN_HISTORY: Duration = Duration::from_secs(3600);
const DOWN_HISTORY_MAX_SAMPLES: usize = 256;

/// A degraded condition has to hold this long before an event opens
/// (the "two consecutive evaluations" rule, with evaluations 30 s apart).
const CONFIRM: Duration = Duration::from_secs(30);
/// A new Outage/Flap event within this long of the link's last ticket is
/// dumped locally but not ticketed again (a restart mid-outage, or a link
/// bouncing in and out of the same trouble).
const RETICKET_GAP: Duration = Duration::from_secs(1800);
/// How long the previous event is remembered for the "age of previous
/// event" line in the next ticket.
const PREVIOUS_EVENT_MEMORY: Duration = Duration::from_secs(7 * 24 * 3600);

/// Recent probe outcomes (hit = true) for one link, newest last.
#[derive(Debug, Clone, Default)]
pub struct ProbeWindow {
    samples: VecDeque<(Instant, bool)>,
    /// First sample since the window was created or last cleared; the
    /// window's age for warm-up purposes.
    epoch: Option<Instant>,
}

impl ProbeWindow {
    pub fn record(&mut self, now: Instant, hit: bool) {
        self.epoch.get_or_insert(now);
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

    /// Forget everything: called when a link comes Up so the misses
    /// accumulated while it was Down (or still handshaking) never count
    /// toward a degradation verdict.
    pub fn clear(&mut self) {
        self.samples.clear();
        self.epoch = None;
    }

    /// `(probes, misses)` within the last `window`.
    pub fn counts(&self, now: Instant, window: Duration) -> (usize, usize) {
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
        (total, missed)
    }

    /// Time since the first sample after the last clear.
    pub fn age(&self, now: Instant) -> Option<Duration> {
        self.epoch.map(|e| now.saturating_duration_since(e))
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
    /// Probe window the degradation verdict is computed over.
    pub window: Duration,
    /// Fewer probes than this in the window means too little data to call.
    pub min_probes: usize,
    /// Degradation opens at this many misses in the window...
    pub open_misses: usize,
    /// ...and at least this loss percentage.
    pub open_pct: f64,
    /// An open event is calm while window loss is below this.
    pub close_pct: f64,
    /// Continuous calm that ends an event.
    pub clear: Duration,
    /// Link not Up for longer than this is an outage.
    pub outage_after: Duration,
    /// No degradation verdict until the window is this old (after
    /// process start or link-up).
    pub warmup: Duration,
    /// Down transitions within `flap_window` that open a flap; 0 disables.
    pub flap_downs: u32,
    pub flap_window: Duration,
}

#[derive(Debug, Clone)]
pub struct TrackerCfg {
    /// Minimum gap between local dump files while an event continues.
    pub dump_cooldown: Duration,
    /// A link opening within this long of another open event rides on
    /// that event's ticket instead of filing its own.
    pub join: Duration,
    /// At most one Degraded ticket per link per this long.
    pub degraded_ticket_gap: Duration,
}

/// Event class, ordered by severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    Degraded,
    Flap,
    Outage,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::Degraded => "DEGRADED",
            Class::Flap => "FLAP",
            Class::Outage => "OUTAGE",
        }
    }
}

/// Everything the trigger needs to know about one link at one instant.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkObs {
    /// How long the link has been not-Up, `None` while Up.
    pub down_for: Option<Duration>,
    pub recent_downs: u32,
    pub total: usize,
    pub missed: usize,
    pub window_age: Option<Duration>,
}

impl LinkObs {
    pub fn gather(
        probes: &ProbeWindow,
        downs: &DownTransitions,
        down_for: Option<Duration>,
        now: Instant,
        cfg: &TriggerCfg,
    ) -> Self {
        let (total, missed) = probes.counts(now, cfg.window);
        Self {
            down_for,
            recent_downs: downs.count_within(now, cfg.flap_window),
            total,
            missed,
            window_age: probes.age(now),
        }
    }

    pub fn loss_pct(&self) -> Option<f64> {
        (self.total > 0).then(|| self.missed as f64 * 100.0 / self.total as f64)
    }
}

struct Conditions {
    outage: bool,
    flap: bool,
    hot: bool,
    calm: bool,
}

fn conditions(obs: &LinkObs, cfg: &TriggerCfg) -> Conditions {
    let outage = obs.down_for.is_some_and(|d| d > cfg.outage_after);
    let flap = cfg.flap_downs > 0 && obs.recent_downs >= cfg.flap_downs;
    let warm = obs.window_age.is_some_and(|a| a >= cfg.warmup);
    let enough = obs.total >= cfg.min_probes;
    let pct = obs.loss_pct().unwrap_or(0.0);
    // A link that isn't Up has no meaningful loss percentage; the outage
    // class owns that case.
    let hot = obs.down_for.is_none()
        && warm
        && enough
        && obs.missed >= cfg.open_misses
        && pct >= cfg.open_pct;
    let calm = !outage && !flap && !(enough && pct >= cfg.close_pct);
    Conditions {
        outage,
        flap,
        hot,
        calm,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpKind {
    Opened,
    Escalated,
    Ongoing,
}

/// The previous event on a link, for the next ticket's context line.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PrevSummary {
    pub ended_ago: Duration,
    pub duration: Duration,
    pub peak_loss_pct: f64,
    pub class: Class,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EventInfo {
    pub id: String,
    pub class: Class,
    pub age: Duration,
    pub peak_loss_pct: f64,
    /// Degraded events held back by the per-link rate limit since the
    /// last Degraded ticket on this link.
    pub suppressed_degraded: u32,
    pub previous: Option<PrevSummary>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Quiet,
    Dump {
        submit: bool,
        kind: DumpKind,
        event: EventInfo,
    },
    Ended {
        id: String,
        class: Class,
        duration: Duration,
        peak_loss_pct: f64,
    },
}

#[derive(Debug, Clone)]
struct Event {
    id: String,
    class: Class,
    opened_at: Instant,
    peak_loss_pct: f64,
    calm_since: Option<Instant>,
    last_dump: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Prev {
    ended_at: Instant,
    duration: Duration,
    peak_loss_pct: f64,
    class: Class,
}

#[derive(Debug, Default)]
struct LinkTrack {
    event: Option<Event>,
    hot_since: Option<Instant>,
    last_submit: Option<Instant>,
    last_degraded_submit: Option<Instant>,
    suppressed_degraded: u32,
    prev: Option<Prev>,
}

/// Per-link event state machine.
#[derive(Debug)]
pub struct EventTracker {
    trig: TriggerCfg,
    cfg: TrackerCfg,
    links: HashMap<String, LinkTrack>,
    dirty: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PersistedPrev {
    pub ended_unix: u64,
    pub duration_secs: u64,
    pub peak_loss_pct: f64,
    pub class: String,
}

/// What survives a daemon restart (monotonic instants don't persist, so
/// everything is unix seconds): when each link last filed a ticket, when
/// it last filed a Degraded one, and its previous event.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PersistedEvents {
    #[serde(default)]
    pub last_submit_unix: HashMap<String, u64>,
    #[serde(default)]
    pub last_degraded_unix: HashMap<String, u64>,
    #[serde(default)]
    pub previous: HashMap<String, PersistedPrev>,
}

fn class_from_label(s: &str) -> Option<Class> {
    [Class::Degraded, Class::Flap, Class::Outage]
        .into_iter()
        .find(|c| c.label() == s)
}

impl EventTracker {
    pub fn new(trig: TriggerCfg, cfg: TrackerCfg) -> Self {
        Self {
            trig,
            cfg,
            links: HashMap::new(),
            dirty: false,
        }
    }

    pub fn observe(&mut self, now: Instant, now_unix: u64, link: &str, obs: &LinkObs) -> Outcome {
        let cond = conditions(obs, &self.trig);
        let others_recently_opened = self.links.iter().any(|(name, t)| {
            name != link
                && t.event
                    .as_ref()
                    .is_some_and(|e| now.saturating_duration_since(e.opened_at) < self.cfg.join)
        });
        let st = self.links.entry(link.to_string()).or_default();

        if cond.hot {
            st.hot_since.get_or_insert(now);
        } else {
            st.hot_since = None;
        }
        let confirmed_hot = st
            .hot_since
            .is_some_and(|t| now.saturating_duration_since(t) >= CONFIRM);
        let active = if cond.outage {
            Some(Class::Outage)
        } else if cond.flap {
            Some(Class::Flap)
        } else if confirmed_hot {
            Some(Class::Degraded)
        } else {
            None
        };

        let pct = if cond.outage {
            100.0
        } else {
            obs.loss_pct().unwrap_or(0.0)
        };

        if let Some(ev) = st.event.as_mut() {
            ev.peak_loss_pct = ev.peak_loss_pct.max(pct);
            if cond.calm {
                let since = *ev.calm_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= self.trig.clear {
                    let ev = st.event.take().expect("checked above");
                    let duration = now.saturating_duration_since(ev.opened_at);
                    st.prev = Some(Prev {
                        ended_at: now,
                        duration,
                        peak_loss_pct: ev.peak_loss_pct,
                        class: ev.class,
                    });
                    self.dirty = true;
                    return Outcome::Ended {
                        id: ev.id,
                        class: ev.class,
                        duration,
                        peak_loss_pct: ev.peak_loss_pct,
                    };
                }
                return Self::ongoing(st, now, &self.cfg, false);
            }
            ev.calm_since = None;
            if let Some(class) = active.filter(|&c| c > ev.class) {
                ev.class = class;
                ev.last_dump = now;
                st.last_submit = Some(now);
                self.dirty = true;
                return Outcome::Dump {
                    submit: true,
                    kind: DumpKind::Escalated,
                    event: Self::info(st, now),
                };
            }
            return Self::ongoing(st, now, &self.cfg, true);
        }

        let Some(class) = active else {
            return Outcome::Quiet;
        };

        let within = |t: Option<Instant>, gap: Duration| {
            t.is_some_and(|t| now.saturating_duration_since(t) < gap)
        };
        let recently_ticketed = within(st.last_submit, RETICKET_GAP);
        let degraded_limited = class == Class::Degraded
            && within(st.last_degraded_submit, self.cfg.degraded_ticket_gap);
        let submit = !others_recently_opened && !recently_ticketed && !degraded_limited;
        if !submit && !others_recently_opened && class == Class::Degraded {
            st.suppressed_degraded += 1;
        }
        let reported_suppressed = st.suppressed_degraded;
        if submit || others_recently_opened {
            st.last_submit = Some(now);
            if class == Class::Degraded {
                st.last_degraded_submit = Some(now);
                st.suppressed_degraded = 0;
            }
            self.dirty = true;
        }
        st.event = Some(Event {
            id: format!("{link}-{now_unix:x}"),
            class,
            opened_at: now,
            peak_loss_pct: pct,
            calm_since: None,
            last_dump: now,
        });
        let mut event = Self::info(st, now);
        event.suppressed_degraded = reported_suppressed;
        Outcome::Dump {
            submit,
            kind: DumpKind::Opened,
            event,
        }
    }

    fn ongoing(st: &mut LinkTrack, now: Instant, cfg: &TrackerCfg, bump_dump: bool) -> Outcome {
        let ev = st.event.as_mut().expect("event is open");
        if bump_dump && now.saturating_duration_since(ev.last_dump) >= cfg.dump_cooldown {
            ev.last_dump = now;
            return Outcome::Dump {
                submit: false,
                kind: DumpKind::Ongoing,
                event: Self::info(st, now),
            };
        }
        Outcome::Quiet
    }

    fn info(st: &LinkTrack, now: Instant) -> EventInfo {
        let ev = st.event.as_ref().expect("event is open");
        EventInfo {
            id: ev.id.clone(),
            class: ev.class,
            age: now.saturating_duration_since(ev.opened_at),
            peak_loss_pct: ev.peak_loss_pct,
            suppressed_degraded: st.suppressed_degraded,
            previous: st.prev.map(|p| PrevSummary {
                ended_ago: now.saturating_duration_since(p.ended_at),
                duration: p.duration,
                peak_loss_pct: p.peak_loss_pct,
                class: p.class,
            }),
        }
    }

    /// `Some` when a ticket time or a previous event changed since the last call.
    pub fn take_dirty_state(&mut self, now: Instant, now_unix: u64) -> Option<PersistedEvents> {
        if !std::mem::take(&mut self.dirty) {
            return None;
        }
        let to_unix =
            |at: Instant| now_unix.saturating_sub(now.saturating_duration_since(at).as_secs());
        let mut out = PersistedEvents::default();
        for (name, st) in &self.links {
            if let Some(at) = st.last_submit {
                out.last_submit_unix.insert(name.clone(), to_unix(at));
            }
            if let Some(at) = st.last_degraded_submit {
                out.last_degraded_unix.insert(name.clone(), to_unix(at));
            }
            if let Some(p) = st.prev {
                out.previous.insert(
                    name.clone(),
                    PersistedPrev {
                        ended_unix: to_unix(p.ended_at),
                        duration_secs: p.duration.as_secs(),
                        peak_loss_pct: p.peak_loss_pct,
                        class: p.class.label().to_string(),
                    },
                );
            }
        }
        Some(out)
    }

    /// Re-adopt ticket times and previous events from before a restart so
    /// an outage that spans one doesn't re-ticket. Open events themselves
    /// are not restored: the conditions re-evaluate from a fresh window.
    pub fn restore(&mut self, now: Instant, now_unix: u64, persisted: PersistedEvents) {
        let ago = |unix: u64| {
            let age = Duration::from_secs(now_unix.saturating_sub(unix));
            now.checked_sub(age).map(|at| (at, age))
        };
        for (link, unix) in persisted.last_submit_unix {
            if let Some((at, age)) = ago(unix).filter(|(_, a)| *a < RETICKET_GAP) {
                let _ = age;
                self.links.entry(link).or_default().last_submit = Some(at);
            }
        }
        for (link, unix) in persisted.last_degraded_unix {
            if let Some((at, age)) = ago(unix).filter(|(_, a)| *a < self.cfg.degraded_ticket_gap) {
                let _ = age;
                self.links.entry(link).or_default().last_degraded_submit = Some(at);
            }
        }
        for (link, p) in persisted.previous {
            let Some(class) = class_from_label(&p.class) else {
                continue;
            };
            if let Some((at, _)) = ago(p.ended_unix).filter(|(_, a)| *a < PREVIOUS_EVENT_MEMORY) {
                self.links.entry(link).or_default().prev = Some(Prev {
                    ended_at: at,
                    duration: Duration::from_secs(p.duration_secs),
                    peak_loss_pct: p.peak_loss_pct,
                    class,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trig() -> TriggerCfg {
        TriggerCfg {
            window: Duration::from_secs(300),
            min_probes: 100,
            open_misses: 8,
            open_pct: 12.0,
            close_pct: 5.0,
            clear: Duration::from_secs(300),
            outage_after: Duration::from_secs(60),
            warmup: Duration::from_secs(120),
            flap_downs: 3,
            flap_window: Duration::from_secs(600),
        }
    }

    fn trk() -> TrackerCfg {
        TrackerCfg {
            dump_cooldown: Duration::from_secs(300),
            join: Duration::from_secs(60),
            degraded_ticket_gap: Duration::from_secs(6 * 3600),
        }
    }

    fn obs(total: usize, missed: usize, age: u64) -> LinkObs {
        LinkObs {
            down_for: None,
            recent_downs: 0,
            total,
            missed,
            window_age: Some(Duration::from_secs(age)),
        }
    }

    fn down(secs: u64) -> LinkObs {
        LinkObs {
            down_for: Some(Duration::from_secs(secs)),
            recent_downs: 1,
            total: 0,
            missed: 0,
            window_age: None,
        }
    }

    /// One probe per second on one link, evaluated every 5 s. `miss(s)` is
    /// whether the probe at second `s` is lost, `down_at(s)` how long the
    /// link has been not-Up at `s`. Returns (tickets, dumps, ends).
    struct Sim {
        t0: Instant,
        w: ProbeWindow,
        d: DownTransitions,
        tr: EventTracker,
        tickets: usize,
        dumps: usize,
        ends: usize,
    }

    impl Sim {
        fn new() -> Self {
            Self {
                t0: Instant::now(),
                w: ProbeWindow::default(),
                d: DownTransitions::default(),
                tr: EventTracker::new(trig(), trk()),
                tickets: 0,
                dumps: 0,
                ends: 0,
            }
        }

        fn at(&self, s: u64) -> Instant {
            self.t0 + Duration::from_secs(s)
        }

        fn run(
            &mut self,
            from: u64,
            to: u64,
            miss: impl Fn(u64) -> bool,
            down_at: impl Fn(u64) -> Option<u64>,
        ) {
            for s in from..to {
                self.w.record(self.at(s), !miss(s));
                if s % 5 == 0 {
                    let o = LinkObs::gather(
                        &self.w,
                        &self.d,
                        down_at(s).map(Duration::from_secs),
                        self.at(s),
                        &trig(),
                    );
                    match self.tr.observe(self.at(s), 1_000_000 + s, "a", &o) {
                        Outcome::Dump { submit, .. } => {
                            self.dumps += 1;
                            self.tickets += usize::from(submit);
                        }
                        Outcome::Ended { .. } => self.ends += 1,
                        Outcome::Quiet => {}
                    }
                }
            }
        }
    }

    // --- the six real tickets of 2026-10-16 -------------------------------

    #[test]
    fn real_ticket_chronic_ten_percent_with_hits_13_misses_0_is_quiet() {
        // 10.2-10.8% over a long window (31-32 misses in 300), one probe per second.
        for missed in [31, 32, 31, 32, 32, 31] {
            let mut sim = Sim::new();
            sim.run(0, 900, |s| (s * missed) % 300 < missed, |_| None);
            assert_eq!((sim.tickets, sim.dumps), (0, 0), "missed={missed}");
        }
    }

    #[test]
    fn real_ticket_restart_at_22_to_25_percent_after_54s_is_quiet() {
        for missed in [12, 13] {
            let o = obs(54, missed, 54);
            assert!(!conditions(&o, &trig()).hot, "missed={missed}");
        }
        // even with the full window's probe count, warm-up still blocks it
        let o = obs(110, 26, 54);
        assert!(!conditions(&o, &trig()).hot);
    }

    // --- degradation ------------------------------------------------------

    #[test]
    fn single_miss_and_short_bursts_are_quiet() {
        let mut sim = Sim::new();
        sim.run(
            0,
            3600,
            |s| s == 500 || matches!(s % 600, 300..=302),
            |_| None,
        );
        assert_eq!((sim.tickets, sim.dumps), (0, 0));
    }

    #[test]
    fn chronic_fifteen_percent_opens_once_after_confirmation() {
        let mut sim = Sim::new();
        sim.run(0, 1200, |s| s % 20 < 3, |_| None);
        assert_eq!(sim.tickets, 1);
    }

    #[test]
    fn degradation_needs_both_miss_count_and_percent() {
        let t = trig();
        assert!(!conditions(&obs(100, 7, 300), &t).hot);
        assert!(!conditions(&obs(300, 30, 300), &t).hot);
        assert!(conditions(&obs(300, 36, 300), &t).hot);
        assert!(!conditions(&obs(99, 20, 300), &t).hot);
    }

    #[test]
    fn degradation_must_hold_before_opening() {
        let t0 = Instant::now();
        let mut tr = EventTracker::new(trig(), trk());
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert_eq!(
            tr.observe(at(0), 1000, "a", &obs(300, 45, 300)),
            Outcome::Quiet
        );
        // the condition drops away before CONFIRM: strike resets
        assert_eq!(
            tr.observe(at(20), 1020, "a", &obs(300, 5, 300)),
            Outcome::Quiet
        );
        assert_eq!(
            tr.observe(at(40), 1040, "a", &obs(300, 45, 300)),
            Outcome::Quiet
        );
        assert!(matches!(
            tr.observe(at(70), 1070, "a", &obs(300, 45, 300)),
            Outcome::Dump {
                submit: true,
                kind: DumpKind::Opened,
                ..
            }
        ));
    }

    #[test]
    fn warmup_blocks_degradation_after_link_up() {
        let mut sim = Sim::new();
        // 40% loss from the first sample, but the window is younger than 120 s
        sim.run(0, 110, |s| s % 5 < 2, |_| None);
        assert_eq!(sim.dumps, 0);
        // once warm (and 100+ probes are in), it opens
        sim.run(110, 200, |s| s % 5 < 2, |_| None);
        assert_eq!(sim.tickets, 1);
    }

    #[test]
    fn clearing_the_window_restarts_warmup() {
        let mut sim = Sim::new();
        sim.run(0, 400, |_| false, |_| None);
        sim.w.clear();
        sim.run(400, 480, |s| s % 5 < 2, |_| None);
        assert_eq!(sim.dumps, 0);
    }

    #[test]
    fn degraded_event_closes_only_after_five_calm_minutes() {
        let mut sim = Sim::new();
        sim.run(0, 600, |s| s % 20 < 3, |_| None);
        assert_eq!(sim.tickets, 1);
        // loss between close and open thresholds (~8%) keeps it open
        sim.run(600, 1500, |s| s % 12 == 0, |_| None);
        assert_eq!(sim.ends, 0);
        // clean link: window drains under 5%, then 300 s of calm
        sim.run(1500, 2400, |_| false, |_| None);
        assert_eq!(sim.ends, 1);
    }

    #[test]
    fn second_degraded_event_within_six_hours_is_suppressed_and_counted() {
        let t0 = Instant::now();
        let mut tr = EventTracker::new(trig(), trk());
        let at = |s: u64| t0 + Duration::from_secs(s);
        let hot = obs(300, 45, 300);
        let calm = obs(300, 0, 300);
        let open = |tr: &mut EventTracker, s: u64| {
            tr.observe(at(s), 1000 + s, "a", &hot);
            tr.observe(at(s + 30), 1030 + s, "a", &hot)
        };
        assert!(matches!(
            open(&mut tr, 0),
            Outcome::Dump { submit: true, .. }
        ));
        tr.observe(at(100), 1100, "a", &calm);
        assert!(matches!(
            tr.observe(at(400), 1400, "a", &calm),
            Outcome::Ended { .. }
        ));
        // 40 minutes later: past the 30-minute re-ticket gap, inside 6 hours
        match open(&mut tr, 2800) {
            Outcome::Dump { submit, event, .. } => {
                assert!(!submit);
                assert_eq!(event.suppressed_degraded, 1);
                assert_eq!(
                    event.previous.expect("previous event").class,
                    Class::Degraded
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        tr.observe(at(3000), 3000, "a", &calm);
        tr.observe(at(3400), 3400, "a", &calm);
        // after the six-hour gap a new one is ticketed again
        assert!(matches!(
            open(&mut tr, 7 * 3600),
            Outcome::Dump { submit: true, .. }
        ));
    }

    // --- outage and flap --------------------------------------------------

    #[test]
    fn outage_needs_more_than_sixty_seconds_down() {
        let t0 = Instant::now();
        let mut tr = EventTracker::new(trig(), trk());
        assert_eq!(tr.observe(t0, 1000, "a", &down(45)), Outcome::Quiet);
        assert_eq!(tr.observe(t0, 1000, "a", &down(60)), Outcome::Quiet);
        assert!(matches!(
            tr.observe(t0, 1000, "a", &down(61)),
            Outcome::Dump { submit: true, kind: DumpKind::Opened, event, .. } if event.class == Class::Outage
        ));
    }

    #[test]
    fn long_outages_file_exactly_one_ticket_each_and_no_reminders() {
        for mins in [56u64, 107] {
            let mut sim = Sim::new();
            let end = 120 + mins * 60;
            sim.run(0, 120, |_| false, |_| None);
            sim.run(120, end, |_| true, |s| Some(s - 120));
            assert_eq!(sim.tickets, 1, "{mins} min outage");
            sim.w.clear();
            sim.run(end, end + 900, |_| false, |_| None);
            assert_eq!(sim.ends, 1, "{mins} min outage");
        }
    }

    #[test]
    fn flap_opens_on_three_downs_in_ten_minutes() {
        let t0 = Instant::now();
        let mut tr = EventTracker::new(trig(), trk());
        let mut o = obs(0, 0, 10);
        o.recent_downs = 2;
        assert_eq!(tr.observe(t0, 1000, "a", &o), Outcome::Quiet);
        o.recent_downs = 3;
        assert!(matches!(
            tr.observe(t0, 1000, "a", &o),
            Outcome::Dump { submit: true, event, .. } if event.class == Class::Flap
        ));
    }

    #[test]
    fn flap_trigger_can_be_disabled() {
        let t0 = Instant::now();
        let mut cfg = trig();
        cfg.flap_downs = 0;
        let mut tr = EventTracker::new(cfg, trk());
        let mut o = obs(0, 0, 10);
        o.recent_downs = 10;
        assert_eq!(tr.observe(t0, 1000, "a", &o), Outcome::Quiet);
    }

    #[test]
    fn degraded_escalating_to_outage_files_a_second_ticket() {
        let t0 = Instant::now();
        let mut tr = EventTracker::new(trig(), trk());
        let at = |s: u64| t0 + Duration::from_secs(s);
        let hot = obs(300, 45, 300);
        tr.observe(at(0), 1000, "a", &hot);
        assert!(matches!(
            tr.observe(at(30), 1030, "a", &hot),
            Outcome::Dump {
                submit: true,
                kind: DumpKind::Opened,
                ..
            }
        ));
        match tr.observe(at(60), 1060, "a", &down(90)) {
            Outcome::Dump {
                submit,
                kind,
                event,
            } => {
                assert!(submit);
                assert_eq!(kind, DumpKind::Escalated);
                assert_eq!(event.class, Class::Outage);
                assert!((event.peak_loss_pct - 100.0).abs() < f64::EPSILON);
            }
            other => panic!("unexpected {other:?}"),
        }
        // staying in the same class does not ticket again
        assert!(!matches!(
            tr.observe(at(65), 1065, "a", &down(95)),
            Outcome::Dump { submit: true, .. }
        ));
    }

    // --- joining, persistence, local dumps --------------------------------

    #[test]
    fn second_link_within_join_window_rides_on_first_ticket() {
        let t0 = Instant::now();
        let mut tr = EventTracker::new(trig(), trk());
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert!(matches!(
            tr.observe(at(0), 1000, "a", &down(90)),
            Outcome::Dump { submit: true, .. }
        ));
        assert!(matches!(
            tr.observe(at(30), 1030, "b", &down(90)),
            Outcome::Dump {
                submit: false,
                kind: DumpKind::Opened,
                ..
            }
        ));
    }

    #[test]
    fn restart_mid_outage_does_not_reticket() {
        let t0 = Instant::now();
        let mut tr = EventTracker::new(trig(), trk());
        tr.observe(t0, 1_000_000, "a", &down(90));
        let now = t0 + Duration::from_secs(600);
        let saved = tr
            .take_dirty_state(now, 1_000_600)
            .expect("dirty after ticket");
        assert_eq!(saved.last_submit_unix["a"], 1_000_000);
        assert!(tr.take_dirty_state(now, 1_000_600).is_none());

        let mut fresh = EventTracker::new(trig(), trk());
        fresh.restore(now, 1_000_600, saved);
        assert!(matches!(
            fresh.observe(now, 1_000_600, "a", &down(90)),
            Outcome::Dump {
                submit: false,
                kind: DumpKind::Opened,
                ..
            }
        ));
    }

    #[test]
    fn stale_persisted_ticket_times_are_forgotten() {
        let now = Instant::now();
        let mut p = PersistedEvents::default();
        p.last_submit_unix.insert("a".into(), 1_000_000 - 7200);
        let mut tr = EventTracker::new(trig(), trk());
        tr.restore(now, 1_000_000, p);
        assert!(matches!(
            tr.observe(now, 1_000_000, "a", &down(90)),
            Outcome::Dump { submit: true, .. }
        ));
    }

    #[test]
    fn previous_event_survives_a_restart() {
        let t0 = Instant::now();
        let mut tr = EventTracker::new(trig(), trk());
        let at = |s: u64| t0 + Duration::from_secs(s);
        tr.observe(at(0), 1000, "a", &down(90));
        tr.observe(at(100), 1100, "a", &obs(300, 0, 300));
        assert!(matches!(
            tr.observe(at(400), 1400, "a", &obs(300, 0, 300)),
            Outcome::Ended { .. }
        ));
        let saved = tr.take_dirty_state(at(400), 1400).unwrap();
        let mut fresh = EventTracker::new(trig(), trk());
        fresh.restore(at(500), 1500, saved);
        let Outcome::Dump { event, .. } = fresh.observe(at(5000), 6000, "a", &down(90)) else {
            panic!("expected a dump");
        };
        let prev = event.previous.expect("previous event");
        assert_eq!(prev.class, Class::Outage);
        assert_eq!(prev.duration, Duration::from_secs(400));
    }

    #[test]
    fn old_state_file_without_new_fields_still_loads() {
        let p: PersistedEvents = serde_json::from_str(r#"{"last_submit_unix":{"a":5}}"#).unwrap();
        assert_eq!(p.last_submit_unix["a"], 5);
        assert!(p.last_degraded_unix.is_empty() && p.previous.is_empty());
    }

    #[test]
    fn ongoing_event_dumps_locally_at_the_cooldown_without_a_ticket() {
        let t0 = Instant::now();
        let mut tr = EventTracker::new(trig(), trk());
        let at = |s: u64| t0 + Duration::from_secs(s);
        tr.observe(at(0), 1000, "a", &down(90));
        assert_eq!(tr.observe(at(5), 1005, "a", &down(95)), Outcome::Quiet);
        assert!(matches!(
            tr.observe(at(300), 1300, "a", &down(390)),
            Outcome::Dump {
                submit: false,
                kind: DumpKind::Ongoing,
                ..
            }
        ));
        // hours later, still no reminder ticket
        assert!(!matches!(
            tr.observe(at(3 * 3600), 1000 + 3 * 3600, "a", &down(3 * 3600)),
            Outcome::Dump { submit: true, .. }
        ));
    }
}
