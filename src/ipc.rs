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
//!
//! `Command`/`CommandResult` are the analogous schema for the separate,
//! opt-in *command* socket (`control.rs::serve_commands`) -- one JSON
//! `Command` per connection, answered with exactly one `CommandResult`
//! before the connection closes. Kept in their own types (not folded
//! into `Snapshot`) so the read-only monitoring socket's wire format
//! stays completely unchanged by this addition.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub tunnel_name: String,
    /// "server" or "client".
    pub mode: String,
    pub unix_ts_ms: u64,
    pub links: Vec<LinkSnapshot>,
    pub daemon: DaemonSnapshot,
}

/// Daemon/host-level health, as opposed to `LinkSnapshot`'s
/// per-bonded-link view -- session identity, the outbound queue, the
/// TUN device's own kernel counters, and machine-wide system stats.
/// Always present (not `Option`) since the daemon itself is always
/// running by the time anything is connected to read this; individual
/// fields inside `tun`/`system` are `Option` where the underlying
/// read (sysfs/`/proc`) can fail independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonSnapshot {
    /// The active Noise transport session's id right now.
    pub session_id: u32,
    /// How long (ms) the *current* session has been active -- resets
    /// to 0 on every rekey, successful or peer-initiated alike.
    pub session_uptime_ms: u64,
    /// Total rekeys since this process started (not since the tunnel
    /// was first configured -- a daemon restart resets this to 0).
    pub rekey_count: u32,
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
    /// How long (ms) the link has held its *current* `state` --
    /// meaningful for every state, not just "up": "down for 42s" is
    /// exactly as useful as "up for 3h" (see `Link::state_since`'s doc
    /// comment). Already-elapsed, like `peer_stats_age_ms` below, so
    /// the viewer never has to do its own clock math.
    pub state_duration_ms: u64,

    /// Lifetime totals -- only ever grow, unlike the throughput EWMAs
    /// above which are windowed. See `LinkStats::record_tx`/`record_rx`.
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,

    // Locally measured -- this process's own view of the link.
    pub local_rtt_ms: Option<f64>,
    pub local_jitter_ms: Option<f64>,
    pub local_loss_pct: Option<f64>,
    pub local_throughput_mbps: Option<f64>,
    /// Throughput from an explicit active bandwidth probe burst, as
    /// opposed to `local_throughput_mbps` (real-traffic-derived).
    /// `None` until the first probe completes, or forever if
    /// `scheduler.active_bandwidth_probing` is off. See
    /// `LinkStats::active_bandwidth_mbps`'s doc comment.
    pub local_active_bandwidth_mbps: Option<f64>,
    /// Consecutive successful/missed probes right now -- one of these
    /// two is always 0 (a hit resets the miss streak and vice versa).
    /// Shows a link's short-term probe health at a glance, e.g. "3
    /// misses in a row" ahead of a state transition actually firing.
    pub local_consecutive_hits: u32,
    pub local_consecutive_misses: u32,

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

/// A request sent over the command socket. `#[serde(tag = "command")]`
/// gives each variant a plain `{"command": "set_link_enabled", ...}`
/// shape on the wire rather than the more awkward externally-tagged
/// default, so it reads naturally from `socat`/`jq` the same way
/// `Snapshot` already does. Currently one variant; more can be added
/// without breaking existing callers as long as `command` stays the
/// discriminant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// Pin `link` (matched against `LinkConfig::name`) enabled/disabled
    /// for scheduling, independent of its real probe-measured state --
    /// see `Link::admin_disabled`'s doc comment.
    SetLinkEnabled { link: String, enabled: bool },
}

/// Reply to exactly one `Command`, written back once before the
/// connection is closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub ok: bool,
    /// `None` when `ok` is true. Set when `ok` is false, e.g. "no such
    /// link" or a malformed request.
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `LinkSnapshot` is rebuilt fresh every 500ms and re-serialized --
    /// the cheapest place to catch a field getting dropped or renamed
    /// between `control::build_snapshot` and `mlvpn-tui`'s `Snapshot`
    /// deserialize is right here, not in an integration test.
    #[test]
    fn link_snapshot_round_trips_with_active_bandwidth_and_streak_fields() {
        let snap = LinkSnapshot {
            name: "lte0".to_string(),
            bind_interface: "wwan0".to_string(),
            local_port: 51000,
            remote_addr: Some("198.51.100.1:51000".to_string()),
            state: "up".to_string(),
            score: 1.5,
            state_duration_ms: 12_345,
            tx_bytes: 1_000_000,
            rx_bytes: 2_000_000,
            tx_packets: 700,
            rx_packets: 1400,
            local_rtt_ms: Some(42.0),
            local_jitter_ms: Some(1.5),
            local_loss_pct: Some(0.0),
            local_throughput_mbps: Some(93.4),
            local_active_bandwidth_mbps: Some(193.4),
            local_consecutive_hits: 12,
            local_consecutive_misses: 0,
            peer_name: None,
            peer_state: None,
            peer_rtt_ms: None,
            peer_jitter_ms: None,
            peer_loss_pct: None,
            peer_throughput_mbps: None,
            peer_stats_age_ms: None,
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let back: LinkSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.local_active_bandwidth_mbps, Some(193.4));
        assert_eq!(back.local_consecutive_hits, 12);
        assert_eq!(back.local_consecutive_misses, 0);
        assert_eq!(back.state_duration_ms, 12_345);
        assert_eq!(back.tx_bytes, 1_000_000);
        assert_eq!(back.rx_bytes, 2_000_000);
        assert_eq!(back.tx_packets, 700);
        assert_eq!(back.rx_packets, 1400);
    }

    /// `serve_commands` reads one line of JSON per connection and a CLI
    /// client writes it -- if the shape drifts between a serialize on
    /// one side and a deserialize on the other, this is the cheapest
    /// place to catch it, well before either process is involved.
    #[test]
    fn command_json_round_trips() {
        let cmd = Command::SetLinkEnabled {
            link: "lte0".to_string(),
            enabled: false,
        };
        let json = serde_json::to_string(&cmd).expect("serialize");
        assert_eq!(
            json,
            r#"{"command":"set_link_enabled","link":"lte0","enabled":false}"#
        );
        let back: Command = serde_json::from_str(&json).expect("deserialize");
        let Command::SetLinkEnabled { link, enabled } = back;
        assert_eq!(link, "lte0");
        assert!(!enabled);
    }

    #[test]
    fn command_result_round_trips_both_variants() {
        let ok = CommandResult {
            ok: true,
            error: None,
        };
        let ok_back: CommandResult =
            serde_json::from_str(&serde_json::to_string(&ok).unwrap()).unwrap();
        assert!(ok_back.ok);
        assert!(ok_back.error.is_none());

        let err = CommandResult {
            ok: false,
            error: Some("no such link 'bogus'".to_string()),
        };
        let err_back: CommandResult =
            serde_json::from_str(&serde_json::to_string(&err).unwrap()).unwrap();
        assert!(!err_back.ok);
        assert_eq!(err_back.error.as_deref(), Some("no such link 'bogus'"));
    }
}
