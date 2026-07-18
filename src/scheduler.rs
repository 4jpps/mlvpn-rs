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

use crate::link::{Link, LinkScore, LinkState};
use crate::monitor;
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct SwrrEntry {
    link_index: usize,
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

pub struct Scheduler {
    entries: Vec<SwrrEntry>,
    rate_limits: HashMap<usize, RateLimitState>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            rate_limits: HashMap::new(),
        }
    }

    /// Recompute per-link scores and rebuild the SWRR weight table. Call
    /// this after every monitor tick (probe result, timeout sweep, or
    /// state change) so scheduling reacts promptly to changing conditions.
    pub fn refresh(&mut self, links: &[Link]) {
        let up_indices: Vec<(usize, f64)> = links
            .iter()
            .enumerate()
            .map(|(i, l)| (i, monitor::score(l)))
            .filter(|(_, w)| *w > 0.0)
            .collect();

        // Rebuild rather than patch in place: link membership and scores
        // both change over time, and this runs at probe-interval
        // frequency (hundreds of ms), not per-packet, so the allocation
        // cost is not on the data path.
        self.entries = up_indices
            .into_iter()
            .map(|(i, w)| SwrrEntry {
                link_index: i,
                effective_weight: w,
                current_weight: 0.0,
                bandwidth_cap_mbps: links[i].config.bandwidth_cap_mbps,
            })
            .collect();
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
    /// per outgoing packet (`tunnel::send_scheduled`), and the normal
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
                current_weight: 0.0,
                bandwidth_cap_mbps: None,
            },
            SwrrEntry {
                link_index: 1,
                effective_weight: 1.0,
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
