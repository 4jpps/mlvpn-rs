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

use crate::link::{Link, LinkState};
use crate::monitor;

struct SwrrEntry {
    link_index: usize,
    effective_weight: f64,
    current_weight: f64,
}

pub struct Scheduler {
    entries: Vec<SwrrEntry>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
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
            })
            .collect();
    }

    /// Pick the link to send the next packet on. `links` is passed again
    /// here (not cached) so the fallback path can inspect live state
    /// without the scheduler needing its own copy of link stats.
    pub fn select<'a>(&mut self, links: &'a [Link]) -> Option<&'a Link> {
        if links.is_empty() {
            return None;
        }

        if !self.entries.is_empty() {
            return Some(&links[self.swrr_pick()]);
        }

        // Fallback: nothing is currently Up. Pick whichever configured
        // link looks least-bad, so we keep attempting delivery instead of
        // stalling the tunnel. See module docs for rationale.
        let best = links
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| {
                let a_key = (
                    a.stats.consecutive_misses,
                    a.stats.rtt_ms.get().unwrap_or(f64::MAX) as i64,
                );
                let b_key = (
                    b.stats.consecutive_misses,
                    b.stats.rtt_ms.get().unwrap_or(f64::MAX) as i64,
                );
                a_key.cmp(&b_key)
            })
            .map(|(i, _)| i)?;
        Some(&links[best])
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
            },
            SwrrEntry {
                link_index: 1,
                effective_weight: 1.0,
                current_weight: 0.0,
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
}
