//! In-memory table of the most recent `StatsShare` received from the peer
//! for each of *our own* link indices (see `protocol::StatsPayload`'s doc
//! comment for why keying by our own receiving link, rather than
//! anything the sender includes, is the correct and simplest choice).
//!
//! Written by `tunnel.rs::handle_incoming` on every `StatsShare` frame,
//! read by `control.rs` when it builds an `ipc::Snapshot` for a connected
//! monitoring client. This module has no async/socket knowledge of its
//! own, matching the same "keep I/O and pure state separate" split as
//! `monitor.rs`.

use crate::protocol::StatsPayload;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct PeerLinkStats {
    pub name: String,
    pub rtt_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    pub throughput_mbps: f64,
    /// Wire-encoded `link::LinkState` -- kept as the raw byte here so this
    /// module doesn't need to depend on `link.rs`; callers decode with
    /// `link::LinkState::from_wire`.
    pub state: u8,
    pub received_at: Instant,
}

/// A plain blocking `std::sync::Mutex`, not `tokio::sync::Mutex`: every
/// access here is a quick, non-awaiting map read/write, so there is
/// nothing to gain from an async mutex and a small amount of overhead to
/// lose.
#[derive(Default)]
pub struct PeerStatsTable(Mutex<HashMap<u8, PeerLinkStats>>);

impl PeerStatsTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&self, local_idx: u8, payload: &StatsPayload) {
        let mut map = self.0.lock().unwrap();
        map.insert(
            local_idx,
            PeerLinkStats {
                name: payload.name_str(),
                rtt_ms: payload.rtt_ms as f64,
                jitter_ms: payload.jitter_ms as f64,
                loss_pct: payload.loss_pct as f64,
                throughput_mbps: payload.throughput_mbps as f64,
                state: payload.state,
                received_at: Instant::now(),
            },
        );
    }

    pub fn get(&self, local_idx: u8) -> Option<PeerLinkStats> {
        self.0.lock().unwrap().get(&local_idx).cloned()
    }
}
