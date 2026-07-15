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
