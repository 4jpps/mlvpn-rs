//! Outgoing packet scheduling across bonded links.
//!
//! Uses smooth weighted round robin (SWRR) -- the same algorithm nginx
//! uses for weighted upstream balancing -- to spread traffic across all
//! currently-Up links roughly in proportion to their `monitor::score()`,
//! while avoiding the bursty back-to-back selection a naive
//! highest-weight-wins approach would produce.
//!
//! Zero-downtime requirement: `select()` only returns `None` when there
//! are no links at all (a configuration error caught at startup). If every
//! link is currently marked Down by the probe monitor, `select()` still
//! returns the least-bad one instead of refusing to send: a probe-Down
//! link is a *quality* judgment, not proof the underlying interface is
//! physically gone. This is what "no downtime unless all bound interfaces
//! go offline" means in practice here -- we keep attempting transmission
//! on whatever we have, so the moment any path actually starts working
//! again (probes succeeding or not), traffic flows without operator
//! intervention. True silence only happens if every interface really is
//! unreachable, which is indistinguishable from "all links down" from
//! inside the process.

use crate::config::SchedulerConfig;
use crate::congestion::{CongestionTracker, CounterSnapshot};
use crate::link::{Link, LinkScore, LinkState, TxCounters};
use crate::monitor;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How far ahead (as a fraction, 0.2 = 20%) a candidate link's score
/// must be over the current primary's before it even starts being
/// tracked as a switch candidate -- see `Scheduler::refresh_from_scores`
/// for the full hysteresis this feeds into.
const PRIMARY_SWITCH_MARGIN: f64 = 0.2;

struct SwrrEntry {
    link_index: usize,
    /// `monitor::score` as of the last `refresh()`.
    base_weight: f64,
    /// `base_weight` scaled by the link's congestion factor -- what SWRR
    /// actually uses. Re-derived on every `update_congestion` tick.
    effective_weight: f64,
    current_weight: f64,
    /// Copied out of `LinkConfig` once, here in `refresh()` (which only
    /// runs at probe-interval frequency), specifically so the per-packet
    /// `select()`/`swrr_pick_under_cap` path never needs to touch a
    /// `Link`/`LinkConfig` at all -- see `select`'s doc comment.
    bandwidth_cap_mbps: Option<f64>,
}

/// Per-link byte counter backing `bandwidth_cap_mbps` enforcement,
/// keyed by `link_index` in `Scheduler::rate_limits`. Deliberately kept
/// outside `entries` and never touched by `refresh()`: `entries` is
/// fully rebuilt on every `refresh()` call (probe-interval frequency,
/// a few hundred ms), but a rate limiter's window needs to survive well
/// past that -- rebuilding it that often would reset the byte count
/// long before a real one-second window elapses, letting a capped link
/// burst far past its configured ceiling.
struct RateLimitState {
    window_start: Instant,
    bytes_in_window: u64,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            bytes_in_window: 0,
        }
    }

    /// True if sending `additional_bytes` right now would keep this
    /// link at or under `cap_mbps` for the current one-second window.
    /// A fixed window, not a true sliding one or a smooth token bucket
    /// -- deliberately the simplest thing that enforces the cap
    /// correctly on average, consistent with this project's existing
    /// preference for simple, well-understood algorithms (EWMA, SWRR)
    /// over more precise but more complex ones. Worst case is a brief
    /// burst up to roughly double the cap right at a window boundary,
    /// never an unbounded one.
    fn under_cap(&mut self, cap_mbps: f64, additional_bytes: u64) -> bool {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            self.window_start = Instant::now();
            self.bytes_in_window = 0;
        }
        let budget_bytes = (cap_mbps * 1_000_000.0 / 8.0) as u64;
        self.bytes_in_window + additional_bytes <= budget_bytes
    }

    fn record(&mut self, bytes: u64) {
        self.bytes_in_window += bytes;
    }
}

/// How long a link that just reported a full per-link TX queue
/// (`note_queue_full`) is skipped by the SWRR pick, so the scheduler
/// steers new traffic toward links that can take it instead of
/// re-offering packets to a link whose socket send path is backed up.
/// Short on purpose: a stalled link that recovers gets traffic back
/// within a fraction of a second, and a link that is still full is simply
/// re-penalized by the next overflow.
const QUEUE_FULL_PENALTY: Duration = Duration::from_millis(200);
/// Same idea for a send failure (socket error / no remote); a little
/// longer because a failing link is less likely to be healthy again in
/// 200 ms than one that merely had a burst.
const SEND_FAILED_PENALTY: Duration = Duration::from_millis(500);

pub struct Scheduler {
    entries: Vec<SwrrEntry>,
    rate_limits: HashMap<usize, RateLimitState>,
    /// Links recently reported queue-full, with when the penalty lapses.
    /// Almost always empty, so the hot path only pays an `is_empty()`.
    penalized: Vec<(usize, Instant)>,
    /// Per-link congestion state, indexed by link index. Lives outside
    /// `entries` because `refresh()` rebuilds those from scratch while the
    /// factor has to persist (and recover gradually) across rebuilds.
    congestion: Vec<CongestionTracker>,
    /// Current primary link's index, when `scheduler.primary_link_mode`
    /// is on. `None` before the first `refresh()`, or if every link is
    /// currently Down. See `refresh_from_scores`'s doc comment for
    /// the full selection/hysteresis logic.
    primary: Option<usize>,
    /// A link that has been beating the current primary's score by
    /// `PRIMARY_SWITCH_MARGIN` for `count` consecutive refreshes in a
    /// row, tracked so a switch only happens once that streak reaches
    /// `SchedulerConfig::up_threshold` -- prevents flapping between two
    /// close-scoring links on ordinary measurement noise. Reset to
    /// `None` the moment a different link becomes the best candidate,
    /// or the current candidate's margin lapses.
    candidate: Option<(usize, u32)>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            rate_limits: HashMap::new(),
            penalized: Vec::new(),
            congestion: Vec::new(),
            primary: None,
            candidate: None,
        }
    }

    /// This scheduler's currently-selected primary link, as a local
    /// `Links`-array index -- `None` when not in `primary_link_mode` (or
    /// `follow_peer_primary`), or when no link is currently Up. Used by
    /// `tunnel::send_version_info` to advertise this host's choice to the
    /// peer over the wire (as a link name, resolved by the caller -- see
    /// `VersionInfoPayload::primary_link_name`).
    pub fn primary(&self) -> Option<usize> {
        self.primary
    }

    /// A link's bounded TX queue was full when the dispatcher tried to
    /// hand it a packet (`tunnel::dispatch`): deprioritize it in the SWRR
    /// pick for `QUEUE_FULL_PENALTY`. Never removes the link outright --
    /// if every candidate is penalized the pick proceeds as normal, and
    /// `primary` selection is untouched (a primary stays primary; the
    /// dispatcher decides separately whether it may spill).
    pub fn note_queue_full(&mut self, idx: usize) {
        self.penalize(idx, QUEUE_FULL_PENALTY);
    }

    /// A link's TX worker failed to put a packet on the wire. Same
    /// short-lived deprioritization as `note_queue_full`; because it only
    /// lasts `SEND_FAILED_PENALTY` past the *last* failure, one transient
    /// socket error costs a fraction of a second of reduced share and
    /// never takes the link out (link state stays with the probes).
    pub fn note_send_failed(&mut self, idx: usize) {
        self.penalize(idx, SEND_FAILED_PENALTY);
    }

    fn penalize(&mut self, idx: usize, dur: Duration) {
        let until = Instant::now() + dur;
        match self.penalized.iter_mut().find(|(i, _)| *i == idx) {
            Some(entry) => entry.1 = entry.1.max(until),
            None => self.penalized.push((idx, until)),
        }
    }

    /// Current congestion factor for link `idx` (1.0 when unknown).
    pub fn congestion_factor(&self, idx: usize) -> f64 {
        self.congestion.get(idx).map_or(1.0, |t| t.factor())
    }

    /// Fold each link's TX counters into its congestion factor and
    /// re-scale the SWRR weights; also publishes the recent delay / send
    /// wait / factor back onto the counters for diagnostics. Cheap (atomic
    /// loads), run on its own short tick rather than per probe so a
    /// congested link is noticed within ~100 ms. `counters` is in `Links`
    /// order. Primary-link selection deliberately ignores the factor.
    pub fn update_congestion(&mut self, counters: &[Arc<TxCounters>]) {
        let now = Instant::now();
        if self.congestion.len() < counters.len() {
            self.congestion
                .resize_with(counters.len(), CongestionTracker::default);
        }
        for (i, c) in counters.iter().enumerate() {
            let t = &mut self.congestion[i];
            t.update(now, CounterSnapshot::read(c));
            c.queue_delay_recent_us
                .store(t.delay_recent_us(), Ordering::Relaxed);
            c.send_wait_recent_us
                .store(t.send_wait_recent_us(), Ordering::Relaxed);
            c.congestion_milli
                .store((t.factor() * 1000.0).round() as u32, Ordering::Relaxed);
        }
        for e in &mut self.entries {
            e.effective_weight = e.base_weight
                * self
                    .congestion
                    .get(e.link_index)
                    .map_or(1.0, |t| t.factor());
        }
    }

    /// Recompute per-link scores and rebuild the SWRR weight table, then
    /// (if `cfg.primary_link_mode` is on) update primary-link selection.
    /// Call this after every monitor tick (probe result, timeout sweep,
    /// or state change) so scheduling reacts promptly to changing
    /// conditions.
    pub fn refresh(
        &mut self,
        links: &[Link],
        cfg: &SchedulerConfig,
        peer_primary_index: Option<usize>,
    ) {
        let up_indices: Vec<(usize, f64)> = links
            .iter()
            .enumerate()
            .map(|(i, l)| (i, monitor::score(l)))
            .filter(|(_, w)| *w > 0.0)
            .collect();
        self.refresh_from_scores(&up_indices, cfg, peer_primary_index);
        // Rebuild rather than patch in place: link membership and scores
        // both change over time, and this runs at probe-interval
        // frequency (hundreds of ms), not per-packet, so the allocation
        // cost is not on the data path.
        self.entries = up_indices
            .into_iter()
            .map(|(i, w)| SwrrEntry {
                link_index: i,
                base_weight: w,
                effective_weight: w * self.congestion_factor(i),
                current_weight: 0.0,
                bandwidth_cap_mbps: links[i].config.bandwidth_cap_mbps,
            })
            .collect();
    }

    /// The scored-pairs half of `refresh()`, factored out so the
    /// primary-selection hysteresis is unit-testable with fake scores
    /// and no real `Link`/socket -- see this module's `primary_link_mode`
    /// tests. `up_indices` is exactly what `refresh()` already computed
    /// (every currently-Up link's `(link_index, monitor::score())`) --
    /// a link with score 0.0 (Down) has already been filtered out
    /// before this is called, which is what makes a hard failure show
    /// up here as "the current primary's index is simply absent from
    /// `up_indices`," not as a zero score to compare against.
    fn refresh_from_scores(
        &mut self,
        up_indices: &[(usize, f64)],
        cfg: &SchedulerConfig,
        peer_primary_index: Option<usize>,
    ) {
        if cfg.follow_peer_primary {
            // No hysteresis here -- the peer already did that work on its
            // own side (if it's running primary_link_mode). Just mirror
            // its choice, or fall back to ordinary scheduling if the peer
            // hasn't chosen one yet, or chose one that isn't Up on this
            // side (e.g. this side's own view of that link's health
            // differs from the peer's -- possible with asymmetric loss).
            self.primary =
                peer_primary_index.filter(|idx| up_indices.iter().any(|(i, _)| i == idx));
            self.candidate = None;
            return;
        }

        if !cfg.primary_link_mode {
            self.primary = None;
            self.candidate = None;
            return;
        }

        let primary_score = self
            .primary
            .and_then(|idx| up_indices.iter().find(|(i, _)| *i == idx).map(|(_, s)| *s));

        let Some(primary_score) = primary_score else {
            // No current primary, or it just went Down -- immediate
            // (re)selection, no hysteresis. Picks the best of whatever
            // is currently Up; None if nothing is.
            self.primary = up_indices
                .iter()
                .max_by(|(_, a), (_, b)| a.total_cmp(b))
                .map(|(i, _)| *i);
            self.candidate = None;
            return;
        };

        let best_other = up_indices
            .iter()
            .filter(|(i, _)| Some(*i) != self.primary)
            .max_by(|(_, a), (_, b)| a.total_cmp(b));

        let Some((other_idx, other_score)) = best_other else {
            self.candidate = None;
            return;
        };

        if *other_score > primary_score * (1.0 + PRIMARY_SWITCH_MARGIN) {
            match &mut self.candidate {
                Some((idx, count)) if *idx == *other_idx => {
                    *count += 1;
                    if *count >= cfg.up_threshold {
                        self.primary = Some(*other_idx);
                        self.candidate = None;
                    }
                }
                _ => {
                    self.candidate = Some((*other_idx, 1));
                }
            }
        } else {
            self.candidate = None;
        }
    }

    /// Pick the link to send the next packet on, returning its index into
    /// whatever `Links` collection the caller is working with (not a
    /// reference into `links` -- see below for why). `frame_len` is the
    /// size (in bytes) of the frame about to be sent on whichever link is
    /// returned -- needed to enforce each link's `bandwidth_cap_mbps`, if
    /// configured (see `swrr_pick_under_cap`).
    ///
    /// Deliberately takes `&[LinkScore]` (a cheap, `Copy`-only snapshot --
    /// see `link::snapshot_scores`) rather than `&[Link]`, and returns
    /// `Option<usize>` rather than `Option<&Link>`: this is called once
    /// per outgoing packet (`tunnel::pick_link`), and the normal
    /// (non-fallback) path below doesn't actually need anything from
    /// `Link` at all -- `refresh()` already cached each candidate's
    /// `bandwidth_cap_mbps` in its own `SwrrEntry` above, so
    /// `swrr_pick_under_cap` needs no `Link`/`LinkScore` access either.
    /// A real 200 Mbps UDP test showed a flat ~65% loss ceiling traced to
    /// this call site cloning every link's full `Link` (heap-allocating
    /// `LinkConfig`'s `String` fields) on every packet just to discard
    /// all but one -- returning an index instead of a reference is what
    /// lets the caller resolve only the *winning* link's remote
    /// address/socket handle, locking it just once, instead of every
    /// link being locked-and-cloned up front regardless of which one
    /// wins.
    pub fn select(&mut self, links: &[LinkScore], frame_len: usize) -> Option<usize> {
        if links.is_empty() {
            return None;
        }

        if let Some(primary) = self.primary {
            return Some(primary);
        }

        if !self.entries.is_empty() {
            return Some(self.swrr_pick_under_cap(frame_len));
        }

        // Fallback: nothing is currently Up. Pick whichever configured
        // link looks least-bad, so we keep attempting delivery instead of
        // stalling the tunnel. See module docs for rationale. Rare enough
        // (every link Down) that reading `LinkScore` for every link here
        // costs nothing worth avoiding.
        links
            .iter()
            .min_by(|a, b| {
                let a_key = (a.consecutive_misses, a.rtt_ms.unwrap_or(f64::MAX) as i64);
                let b_key = (b.consecutive_misses, b.rtt_ms.unwrap_or(f64::MAX) as i64);
                a_key.cmp(&b_key)
            })
            .map(|l| l.link_index)
    }

    /// Lock-free-for-links fast path for the hot per-packet send call
    /// (`tunnel::pick_link`). `select`'s own `self.primary`/
    /// `self.entries` branches never actually read the `links:
    /// &[LinkScore]` slice they're handed -- both are populated entirely
    /// by the last periodic `refresh()`, not by anything live at send
    /// time. Only `select`'s final fallback branch (every link Down)
    /// needs a fresh scan. Before this existed, every single outgoing
    /// packet paid for `link::snapshot_scores` -- an async lock
    /// acquisition on *every configured link* -- purely to satisfy an
    /// `is_empty()` guard and a branch that, in the two common cases,
    /// never even reads the result. Confirmed live in production via
    /// `strace -f -c` on a loaded tunnel: ~75% of `mlvpnd`'s wall-clock
    /// time was spent in `futex` (async-lock contention) rather than
    /// the `sendto` doing the actual work, capping real throughput far
    /// below the link's measured capacity.
    ///
    /// `link_count`: `links.len()` on the caller's already-in-scope
    /// `Links` `Vec` -- just its length, no locking, since this
    /// mirrors `select`'s own `links.is_empty()` guard without needing
    /// the expensive per-link snapshot that guard's real slice would
    /// otherwise require.
    ///
    /// Returns `None` exactly when the caller must fall back to the
    /// slower `link::snapshot_scores` + `select` path: no configured
    /// links at all, or nothing cached from the last `refresh()` (no
    /// primary, no SWRR entries) -- i.e. the same rare "every link is
    /// Down" case `select`'s own fallback branch handles.
    pub fn select_fast(&mut self, link_count: usize, frame_len: usize) -> Option<usize> {
        if link_count == 0 {
            return None;
        }
        if let Some(primary) = self.primary {
            return Some(primary);
        }
        if !self.entries.is_empty() {
            return Some(self.swrr_pick_under_cap(frame_len));
        }
        None
    }

    fn swrr_pick(&mut self) -> usize {
        let total: f64 = self.entries.iter().map(|e| e.effective_weight).sum();
        for e in self.entries.iter_mut() {
            e.current_weight += e.effective_weight;
        }
        let winner = self
            .entries
            .iter_mut()
            // total_cmp, not partial_cmp().unwrap(): never panics, even
            // in a hypothetical future where a score computation
            // produces NaN/infinity. current_weight is a running sum of
            // monitor::score() outputs, which are already clamped away
            // from NaN today, but a scheduling hot path is exactly the
            // kind of code that should be panic-free by construction
            // rather than "we don't think it's reachable right now."
            .max_by(|a, b| a.current_weight.total_cmp(&b.current_weight))
            .expect("entries is non-empty (checked by caller)");
        winner.current_weight -= total;
        winner.link_index
    }

    /// Like `swrr_pick`, but skips any link currently at or over its
    /// configured `bandwidth_cap_mbps` (links with no cap configured are
    /// never excluded). Only entries actually competing for this pick
    /// have their `current_weight` advanced -- a capped link's weight
    /// deliberately does *not* keep accumulating while it's excluded,
    /// so it doesn't come back from being throttled with an unfairly
    /// large backlog that would otherwise cause a burst the moment it's
    /// back under cap. Falls back to the plain, cap-ignoring
    /// `swrr_pick` if literally every entry is currently over its cap --
    /// respecting a cap is a best-effort shaping policy, never a reason
    /// to drop a packet outright (see the module doc comment's
    /// zero-downtime rationale).
    fn swrr_pick_under_cap(&mut self, frame_len: usize) -> usize {
        // First pass, read-only: which entries are under their cap right
        // now. Kept as its own pass (rather than checked inline in the
        // weight-update loop below) so it's obvious this never mutates
        // `entries`, only `rate_limits`. Reads `bandwidth_cap_mbps` off
        // the entry itself (cached by `refresh()`), not `links` -- this
        // function no longer takes a `links` parameter at all, since
        // nothing here needs one anymore.
        let mut eligible: Vec<usize> = Vec::with_capacity(self.entries.len());
        for pos in 0..self.entries.len() {
            let idx = self.entries[pos].link_index;
            let under_cap = match self.entries[pos].bandwidth_cap_mbps {
                None => true,
                Some(cap_mbps) => {
                    let state = self
                        .rate_limits
                        .entry(idx)
                        .or_insert_with(RateLimitState::new);
                    state.under_cap(cap_mbps, frame_len as u64)
                }
            };
            if under_cap {
                eligible.push(pos);
            }
        }

        if !self.penalized.is_empty() {
            let now = Instant::now();
            self.penalized.retain(|(_, until)| *until > now);
            if !self.penalized.is_empty() {
                let penalized = &self.penalized;
                let entries = &self.entries;
                let unpenalized: Vec<usize> = eligible
                    .iter()
                    .copied()
                    .filter(|&pos| !penalized.iter().any(|(i, _)| *i == entries[pos].link_index))
                    .collect();
                if !unpenalized.is_empty() {
                    eligible = unpenalized;
                }
            }
        }

        if eligible.is_empty() {
            let idx = self.swrr_pick();
            if let Some(state) = self.rate_limits.get_mut(&idx) {
                state.record(frame_len as u64);
            }
            return idx;
        }

        let total: f64 = eligible
            .iter()
            .map(|&pos| self.entries[pos].effective_weight)
            .sum();
        for &pos in &eligible {
            self.entries[pos].current_weight += self.entries[pos].effective_weight;
        }
        let winner_pos = *eligible
            .iter()
            .max_by(|&&a, &&b| {
                self.entries[a]
                    .current_weight
                    .total_cmp(&self.entries[b].current_weight)
            })
            .expect("eligible is non-empty (checked above)");
        self.entries[winner_pos].current_weight -= total;
        let idx = self.entries[winner_pos].link_index;

        if let Some(state) = self.rate_limits.get_mut(&idx) {
            state.record(frame_len as u64);
        }
        idx
    }

    /// True only when every configured link is marked Down. Used purely
    /// for logging/metrics ("aggregate degraded") -- it does not gate
    /// `select()`, which always keeps trying (see module docs).
    pub fn all_down(&self, links: &[Link]) -> bool {
        links.iter().all(|l| l.state == LinkState::Down)
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SWRR should, over many picks, distribute roughly proportionally to
    /// weight without ever picking the same link twice in a row when a
    /// second link has comparable weight (the classic nginx SWRR
    /// smoothness property).
    #[test]
    fn swrr_distributes_proportionally() {
        let mut entries = [
            SwrrEntry {
                link_index: 0,
                effective_weight: 3.0,
                base_weight: 3.0,
                current_weight: 0.0,
                bandwidth_cap_mbps: None,
            },
            SwrrEntry {
                link_index: 1,
                effective_weight: 1.0,
                base_weight: 1.0,
                current_weight: 0.0,
                bandwidth_cap_mbps: None,
            },
        ];
        let mut counts = [0usize; 2];
        let total: f64 = entries.iter().map(|e| e.effective_weight).sum();
        for _ in 0..400 {
            for e in entries.iter_mut() {
                e.current_weight += e.effective_weight;
            }
            let (idx, winner) = entries
                .iter_mut()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.current_weight.total_cmp(&b.current_weight))
                .unwrap();
            counts[idx] += 1;
            winner.current_weight -= total;
        }
        // Expect roughly 3:1 -- allow generous tolerance since this is a
        // deterministic but non-uniform sequence, not a random sample.
        let ratio = counts[0] as f64 / counts[1] as f64;
        assert!(
            (2.5..3.5).contains(&ratio),
            "ratio was {ratio}, counts {counts:?}"
        );
    }

    fn two_entry_scheduler() -> Scheduler {
        let mut s = Scheduler::new();
        s.entries = (0..2)
            .map(|i| SwrrEntry {
                link_index: i,
                effective_weight: 1.0,
                base_weight: 1.0,
                current_weight: 0.0,
                bandwidth_cap_mbps: None,
            })
            .collect();
        s
    }

    #[test]
    fn queue_full_penalty_steers_picks_to_other_links() {
        let mut s = two_entry_scheduler();
        s.note_queue_full(1);
        for _ in 0..50 {
            assert_eq!(s.select_fast(2, 100), Some(0));
        }
    }

    #[test]
    fn queue_full_penalty_never_empties_the_pick_set() {
        let mut s = two_entry_scheduler();
        s.note_queue_full(0);
        s.note_queue_full(1);
        let mut seen = [false; 2];
        for _ in 0..20 {
            seen[s.select_fast(2, 100).unwrap()] = true;
        }
        assert!(seen[0] && seen[1], "all-penalized must fall back to SWRR");
    }

    fn counters_pair() -> Vec<Arc<TxCounters>> {
        vec![Arc::new(TxCounters::new()), Arc::new(TxCounters::new())]
    }

    /// Pretend link `i`'s worker saw `n` batches each `delay_us` old.
    fn add_delay(c: &TxCounters, delay_us: u64, n: u64) {
        c.queue_delay_sum_us
            .fetch_add(delay_us * n, Ordering::Relaxed);
        c.queue_delay_samples.fetch_add(n, Ordering::Relaxed);
    }

    #[test]
    fn congested_link_loses_share_but_keeps_a_trickle() {
        let mut s = two_entry_scheduler();
        let counters = counters_pair();
        s.update_congestion(&counters);
        std::thread::sleep(Duration::from_millis(60));
        add_delay(&counters[1], 40_000, 20);
        s.update_congestion(&counters);

        assert!(
            s.congestion_factor(1) <= 0.2 + 1e-9,
            "{}",
            s.congestion_factor(1)
        );
        assert_eq!(s.congestion_factor(0), 1.0);
        assert!(s.entries[1].effective_weight <= s.entries[0].effective_weight * 0.2 + 1e-9);
        assert_eq!(s.entries[1].base_weight, 1.0, "base weight is preserved");
        let mut picks = [0usize; 2];
        for _ in 0..1000 {
            picks[s.select_fast(2, 100).unwrap()] += 1;
        }
        assert!(picks[0] >= picks[1] * 4, "picks {picks:?}");
        assert!(picks[1] > 0, "congested link keeps a trickle: {picks:?}");
        assert!(counters[1].congestion_milli.load(Ordering::Relaxed) <= 200);
        assert_eq!(
            counters[1].queue_delay_recent_us.load(Ordering::Relaxed),
            40_000
        );
    }

    #[test]
    fn congestion_factor_survives_refresh_style_entry_rebuild() {
        let mut s = two_entry_scheduler();
        let counters = counters_pair();
        s.update_congestion(&counters);
        std::thread::sleep(Duration::from_millis(60));
        add_delay(&counters[0], 30_000, 10);
        s.update_congestion(&counters);
        let f = s.congestion_factor(0);
        assert!(f < 0.3);
        // `refresh()` rebuilds `entries` from monitor scores; the factor
        // lives in `congestion` and is re-applied from there.
        s.entries.clear();
        assert_eq!(s.congestion_factor(0), f);
    }

    #[test]
    fn send_failure_penalty_lapses_and_never_extends_backwards() {
        let mut s = two_entry_scheduler();
        s.note_send_failed(1);
        for _ in 0..50 {
            assert_eq!(s.select_fast(2, 100), Some(0));
        }
        let until = s.penalized[0].1;
        s.note_queue_full(1);
        assert!(
            s.penalized[0].1 >= until,
            "a shorter penalty must not shorten a longer one"
        );
        s.penalized[0].1 = Instant::now() - Duration::from_millis(1);
        let mut seen = [false; 2];
        for _ in 0..20 {
            seen[s.select_fast(2, 100).unwrap()] = true;
        }
        assert!(seen[1]);
    }

    #[test]
    fn queue_full_penalty_lapses() {
        let mut s = two_entry_scheduler();
        s.penalized
            .push((1, Instant::now() - Duration::from_millis(1)));
        let mut seen = [false; 2];
        for _ in 0..20 {
            seen[s.select_fast(2, 100).unwrap()] = true;
        }
        assert!(seen[1], "an expired penalty must not exclude the link");
        assert!(s.penalized.is_empty());
    }

    #[test]
    fn primary_link_mode_off_never_sets_a_primary() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            primary_link_mode: false,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 3.0)], &cfg, None);
        assert_eq!(sched.primary, None);
    }

    #[test]
    fn primary_link_mode_picks_highest_scoring_link_first() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            primary_link_mode: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 3.0)], &cfg, None);
        assert_eq!(sched.primary, Some(0));
    }

    #[test]
    fn candidate_below_margin_never_switches() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            primary_link_mode: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 3.0)], &cfg, None);
        assert_eq!(sched.primary, Some(0));
        // Link 1 improves to 5.5 -- only ~10% ahead of link 0's 5.0, well
        // under the 20% margin. Run many refreshes; should never switch.
        for _ in 0..10 {
            sched.refresh_from_scores(&[(0, 5.0), (1, 5.5)], &cfg, None);
        }
        assert_eq!(sched.primary, Some(0));
    }

    #[test]
    fn candidate_above_margin_needs_sustained_cycles_to_switch() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            primary_link_mode: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 1.0)], &cfg, None);
        assert_eq!(sched.primary, Some(0));
        // Link 1 jumps to 7.0 -- 40% ahead of link 0's 5.0, over the 20%
        // margin. Should NOT switch on the first or second favorable
        // refresh (up_threshold is 3).
        sched.refresh_from_scores(&[(0, 5.0), (1, 7.0)], &cfg, None);
        assert_eq!(
            sched.primary,
            Some(0),
            "1st favorable refresh: no switch yet"
        );
        sched.refresh_from_scores(&[(0, 5.0), (1, 7.0)], &cfg, None);
        assert_eq!(
            sched.primary,
            Some(0),
            "2nd favorable refresh: no switch yet"
        );
        // 3rd consecutive favorable refresh (== up_threshold): switches.
        sched.refresh_from_scores(&[(0, 5.0), (1, 7.0)], &cfg, None);
        assert_eq!(sched.primary, Some(1), "3rd favorable refresh: switches");
    }

    #[test]
    fn candidate_streak_resets_if_it_drops_below_margin_mid_streak() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            primary_link_mode: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 1.0)], &cfg, None);
        sched.refresh_from_scores(&[(0, 5.0), (1, 7.0)], &cfg, None); // 1st favorable
        sched.refresh_from_scores(&[(0, 5.0), (1, 5.1)], &cfg, None); // drops back under margin
        sched.refresh_from_scores(&[(0, 5.0), (1, 7.0)], &cfg, None); // 1st favorable again (streak reset)
        sched.refresh_from_scores(&[(0, 5.0), (1, 7.0)], &cfg, None); // 2nd
        assert_eq!(
            sched.primary,
            Some(0),
            "streak should have reset, not reached 3 yet"
        );
    }

    #[test]
    fn primary_going_down_switches_immediately_regardless_of_margin() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            primary_link_mode: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 1.0)], &cfg, None);
        assert_eq!(sched.primary, Some(0));
        // Link 0 drops out entirely (Down -- score 0.0 links are already
        // filtered out of the up_indices list before this point in the
        // real refresh(), so simulate that by omitting it here).
        sched.refresh_from_scores(&[(1, 1.0)], &cfg, None);
        assert_eq!(
            sched.primary,
            Some(1),
            "hard failure must switch immediately, even though link 1's \
             score never beat link 0's by the 20% margin"
        );
    }

    #[test]
    fn select_returns_primary_when_primary_link_mode_is_on() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            primary_link_mode: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 3.0)], &cfg, None);
        let scores = [
            LinkScore {
                link_index: 0,
                state: LinkState::Up,
                admin_disabled: false,
                weight: 1.0,
                bandwidth_cap_mbps: None,
                rtt_ms: Some(10.0),
                jitter_ms: Some(1.0),
                loss_rate: Some(0.0),
                rx_throughput_mbps: None,
                active_bandwidth_mbps: None,
                consecutive_misses: 0,
            },
            LinkScore {
                link_index: 1,
                state: LinkState::Up,
                admin_disabled: false,
                weight: 1.0,
                bandwidth_cap_mbps: None,
                rtt_ms: Some(10.0),
                jitter_ms: Some(1.0),
                loss_rate: Some(0.0),
                rx_throughput_mbps: None,
                active_bandwidth_mbps: None,
                consecutive_misses: 0,
            },
        ];
        // Called many times -- every single pick must be link 0 (the
        // primary), never SWRR-style alternation.
        for _ in 0..20 {
            assert_eq!(sched.select(&scores, 1000), Some(0));
        }
    }

    #[test]
    fn select_fast_returns_primary_without_needing_any_scores() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            primary_link_mode: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 3.0)], &cfg, None);
        assert_eq!(sched.select_fast(2, 1000), Some(0));
    }

    #[test]
    fn select_fast_returns_swrr_pick_when_entries_are_populated() {
        // `entries` is built by `refresh()` (from a real `&[Link]`), not
        // `refresh_from_scores` -- populate it directly the same way
        // `refresh()` does, to test `select_fast`'s SWRR branch without
        // needing real `Link`/socket objects.
        let mut sched = Scheduler::new();
        sched.entries.push(SwrrEntry {
            link_index: 0,
            effective_weight: 5.0,
            base_weight: 5.0,
            current_weight: 0.0,
            bandwidth_cap_mbps: None,
        });
        sched.entries.push(SwrrEntry {
            link_index: 1,
            effective_weight: 3.0,
            base_weight: 3.0,
            current_weight: 0.0,
            bandwidth_cap_mbps: None,
        });
        // Off primary_link_mode/follow_peer_primary -> select_fast's
        // SWRR branch fires. A real pick must come back, not None
        // (which would wrongly force the caller into the expensive
        // snapshot_scores fallback for every packet).
        assert!(sched.select_fast(2, 1000).is_some());
    }

    #[test]
    fn select_fast_returns_none_when_nothing_is_cached_yet() {
        // Fresh scheduler: no primary, no SWRR entries (refresh has
        // never run). Caller must fall back to the full snapshot_scores
        // + select path -- this is the only case that's allowed to.
        let mut sched = Scheduler::new();
        assert_eq!(sched.select_fast(2, 1000), None);
    }

    #[test]
    fn select_fast_returns_none_when_there_are_no_configured_links() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            primary_link_mode: true,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0)], &cfg, None);
        assert_eq!(sched.select_fast(0, 1000), None);
    }

    #[test]
    fn select_fast_agrees_with_select_across_primary_swrr_and_empty_states() {
        // select_fast must never return a different link than select
        // would for the same state -- it's purely a faster path to the
        // exact same answer, never a different one.
        let scores = [
            LinkScore {
                link_index: 0,
                state: LinkState::Up,
                admin_disabled: false,
                weight: 1.0,
                bandwidth_cap_mbps: None,
                rtt_ms: Some(10.0),
                jitter_ms: Some(1.0),
                loss_rate: Some(0.0),
                rx_throughput_mbps: None,
                active_bandwidth_mbps: None,
                consecutive_misses: 0,
            },
            LinkScore {
                link_index: 1,
                state: LinkState::Up,
                admin_disabled: false,
                weight: 1.0,
                bandwidth_cap_mbps: None,
                rtt_ms: Some(10.0),
                jitter_ms: Some(1.0),
                loss_rate: Some(0.0),
                rx_throughput_mbps: None,
                active_bandwidth_mbps: None,
                consecutive_misses: 0,
            },
        ];

        // Primary state.
        let mut sched = Scheduler::new();
        let primary_cfg = SchedulerConfig {
            primary_link_mode: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 3.0)], &primary_cfg, None);
        assert_eq!(
            sched.select_fast(2, 1000),
            sched.select(&scores, 1000),
            "primary state"
        );

        // SWRR state: two independently-built schedulers in the same
        // starting state must pick identically, call for call --
        // select_fast is a faster route to the same SWRR algorithm,
        // not a different one. `entries` built directly the same way
        // `refresh()` does (see `select_fast_returns_swrr_pick_when_
        // entries_are_populated`'s comment for why).
        let build_swrr = || {
            let mut s = Scheduler::new();
            s.entries.push(SwrrEntry {
                link_index: 0,
                effective_weight: 5.0,
                base_weight: 5.0,
                current_weight: 0.0,
                bandwidth_cap_mbps: None,
            });
            s.entries.push(SwrrEntry {
                link_index: 1,
                effective_weight: 3.0,
                base_weight: 3.0,
                current_weight: 0.0,
                bandwidth_cap_mbps: None,
            });
            s
        };
        let mut via_fast = build_swrr();
        let mut via_select = build_swrr();
        for _ in 0..10 {
            assert_eq!(
                via_fast.select_fast(2, 1000),
                via_select.select(&scores, 1000),
                "swrr state"
            );
        }

        // Empty state: neither primary nor entries populated.
        let mut sched = Scheduler::new();
        assert_eq!(sched.select_fast(2, 1000), None);
        assert_eq!(
            sched.select(&scores, 1000),
            Some(0),
            "select's own live-scan fallback still resolves a pick -- \
             select_fast's None here is the documented \"caller must \
             fall back\" signal, not a functional disagreement"
        );
    }

    #[test]
    fn follow_peer_primary_adopts_peer_choice_when_link_is_up() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            follow_peer_primary: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 3.0)], &cfg, Some(1));
        assert_eq!(sched.primary, Some(1));
    }

    #[test]
    fn follow_peer_primary_falls_back_to_normal_scheduling_when_peer_has_no_primary_yet() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            follow_peer_primary: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        sched.refresh_from_scores(&[(0, 5.0), (1, 3.0)], &cfg, None);
        assert_eq!(sched.primary, None);
    }

    #[test]
    fn follow_peer_primary_falls_back_when_peer_choice_is_not_up_locally() {
        let mut sched = Scheduler::new();
        let cfg = SchedulerConfig {
            follow_peer_primary: true,
            up_threshold: 3,
            ..SchedulerConfig::default()
        };
        // Peer advertised link index 2, but it's absent from up_indices
        // (not Up on this side).
        sched.refresh_from_scores(&[(0, 5.0), (1, 3.0)], &cfg, Some(2));
        assert_eq!(sched.primary, None);
    }

    /// `swrr_pick_under_cap`/`select` need a real `Link` (a live socket)
    /// to exercise end-to-end -- covered by the integration tests
    /// instead (same reasoning `monitor.rs`'s own tests document). This
    /// covers the actual enforcement math in isolation.
    #[test]
    fn rate_limit_state_enforces_budget_and_resets_after_a_window() {
        let mut state = RateLimitState::new();
        // 8 Mbps == 1,000,000 bytes/sec budget.
        let cap_mbps = 8.0;

        assert!(
            state.under_cap(cap_mbps, 500_000),
            "half the budget should fit"
        );
        state.record(500_000);
        assert!(
            state.under_cap(cap_mbps, 500_000),
            "exactly the remaining budget should still fit"
        );
        state.record(500_000);
        assert!(
            !state.under_cap(cap_mbps, 1),
            "budget is fully spent for this window; even one more byte should be rejected"
        );

        // Force the window to roll over rather than sleeping a real
        // second in a unit test.
        state.window_start = Instant::now() - Duration::from_secs(2);
        assert!(
            state.under_cap(cap_mbps, 999_999),
            "a new window should have a fresh budget"
        );
    }
}
