//! Shared JSON schema for the daemon's local monitoring control socket.
//!
//! `mlvpnd` streams one `Snapshot` per line (newline-delimited JSON) to
//! every client connected to its control socket -- see `control.rs` for
//! the server side. `mlvpn-tui` (`src/bin/mlvpn-tui.rs`) is the reference
//! consumer, but the format is intentionally plain JSON so ad-hoc
//! debugging with `socat -u UNIX-CONNECT:<path> - | jq` also works
//! without any special tooling.
//!
//! These types carry no secrets -- no keys, no plaintext tunnel payloads --
//! only link identity (interface names, learned peer IP:port) and
//! aggregate statistics. See `control.rs`'s module doc comment for the
//! access-control reasoning around that.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub tunnel_name: String,
    /// "server" or "client".
    pub mode: String,
    pub unix_ts_ms: u64,
    pub links: Vec<LinkSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSnapshot {
    pub name: String,
    pub bind_interface: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    /// "probing" | "up" | "down".
    pub state: String,
    /// This process's own SWRR weight for the link right now (0 when not
    /// Up); mirrors what the scheduler is actually doing with traffic.
    pub score: f64,

    // Locally measured -- this process's own view of the link.
    pub local_rtt_ms: Option<f64>,
    pub local_jitter_ms: Option<f64>,
    pub local_loss_pct: Option<f64>,
    pub local_throughput_mbps: Option<f64>,

    // Peer-reported -- their view of the same physical link, received
    // over the wire via a `StatsShare` frame (see `protocol.rs`). `None`
    // until at least one such frame has arrived on this link.
    pub peer_name: Option<String>,
    pub peer_state: Option<String>,
    pub peer_rtt_ms: Option<f64>,
    pub peer_jitter_ms: Option<f64>,
    pub peer_loss_pct: Option<f64>,
    pub peer_throughput_mbps: Option<f64>,
    /// How long ago (in ms) the peer's stats were received. Lets a viewer
    /// visually flag a peer-stats column as stale if this grows large
    /// (e.g. an old mlvpnd on the other end that predates StatsShare, or
    /// the return path being down while the forward path still works).
    pub peer_stats_age_ms: Option<u64>,
}
