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
    /// Log lines produced since the connected client's last poll --
    /// almost always empty on a quiet tunnel. See `logbuf::LogRing` for
    /// the ring buffer this is drained from and `control::serve_client`
    /// for the per-connection `last_log_seq` cursor that makes this a
    /// delta rather than the whole ring resent every tick.
    pub new_log_lines: Vec<LogEntry>,
}

/// One captured log line, INFO-severity or higher (see
/// `logbuf::LogRingLayer`'s doc comment for why DEBUG/TRACE never reach
/// this ring regardless of the operator's own configured log level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Monotonically increasing within one daemon process's lifetime,
    /// never reused -- the cursor `new_log_lines` delta streaming is
    /// built on. Resets to 0 on a daemon restart, same as `rekey_count`.
    pub seq: u64,
    pub unix_ts_ms: u64,
    /// "ERROR" | "WARN" | "INFO" (`tracing::Level::as_str()`'s own
    /// formatting, uppercase).
    pub level: String,
    /// The event's `tracing` target (typically a module path like
    /// `mlvpn::tunnel`) -- `Option` for forward compatibility even
    /// though `tracing::Event::metadata().target()` is always
    /// populated in practice.
    pub target: Option<String>,
    pub message: String,
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
    /// Frames currently buffered between `tun_reader` and
    /// `outbound_sender`, waiting to be sent -- 0 on a healthy tunnel
    /// keeping up with the TUN device's read rate.
    pub outbound_queue_len: u64,
    /// Fixed capacity of that same queue (`OUTBOUND_QUEUE_CAPACITY`);
    /// included alongside `outbound_queue_len` so a viewer can show a
    /// fill ratio without hardcoding the constant.
    pub outbound_queue_capacity: u64,
    /// Lifetime count of packets dropped because the outbound queue was
    /// full when `tun_reader` tried to enqueue them -- monotonic, never
    /// reset, same "only ever grows" convention as `LinkSnapshot`'s
    /// `tx_bytes`/`rx_bytes`. See `outbound_queue_drop_reporter`'s doc
    /// comment for why this counter and its periodic log line are now
    /// independent of each other.
    pub outbound_queue_dropped_total: u64,
    /// The TUN device's own kernel-tracked counters -- see
    /// `sysfs_net::read_tun_stats`.
    pub tun: TunSnapshot,
    /// Machine-wide health -- see `procstats::read_system_stats`.
    pub system: SystemSnapshot,
}

/// Host-wide load/memory/uptime, independent of anything tunnel- or
/// link-specific -- context for whether a problem elsewhere in the
/// snapshot is actually a symptom of the host itself being under load
/// or low on memory. Every field is `Option` since `/proc/loadavg`,
/// `/proc/meminfo`, and `/proc/uptime` are read and parsed
/// independently and any one of them can fail on its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub load1: Option<f64>,
    pub load5: Option<f64>,
    pub load15: Option<f64>,
    pub mem_total_kb: Option<u64>,
    pub mem_available_kb: Option<u64>,
    pub uptime_secs: Option<u64>,
}

/// `/sys/class/net/<iface>/statistics/*` counters for the TUN device,
/// independent of and a cross-check against the per-link
/// `LinkSnapshot` tx/rx counters above (those only count bytes this
/// process handed to a link's socket; these are the kernel's own view
/// of the TUN device as a whole). Every counter is `Option` since the
/// sysfs read can fail independently of everything else in a
/// `Snapshot` (e.g. the interface was renamed or torn down).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunSnapshot {
    /// The TUN interface name this data was read for -- same string as
    /// `Snapshot::tunnel_name`, included here too so a viewer never has
    /// to cross-reference the two.
    pub iface: String,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub rx_errors: Option<u64>,
    pub tx_errors: Option<u64>,
    pub rx_dropped: Option<u64>,
    pub tx_dropped: Option<u64>,
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
    /// Real-time (windowed-EWMA, re-sampled every ~1s -- not cumulative,
    /// see `tx_bytes`/`rx_bytes` above for that) receive-side throughput,
    /// from bytes actually received on this link. `local_tx_throughput_mbps`
    /// below is the send-side counterpart; the two are tracked
    /// independently since a link's send/receive rates are often
    /// asymmetric. Named `local_rx_throughput_mbps` (not just
    /// `local_throughput_mbps`, its name before both directions were
    /// exposed) so its rx-only-ness is explicit in the wire schema
    /// itself, not just in a doc comment.
    pub local_rx_throughput_mbps: Option<f64>,
    pub local_tx_throughput_mbps: Option<f64>,
    /// Throughput from an explicit active bandwidth probe burst, as
    /// opposed to `local_rx_throughput_mbps` (real-traffic-derived).
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
/// `Snapshot` already does.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// Pin `link` (matched against `LinkConfig::name`) enabled/disabled
    /// for scheduling, independent of its real probe-measured state --
    /// see `Link::admin_disabled`'s doc comment.
    SetLinkEnabled { link: String, enabled: bool },
    /// Runs an on-demand throughput self-test (`mlvpnd selftest` on the
    /// CLI) -- see `tunnel::send_throughput_test_stream`,
    /// `control::apply_command`'s handling of this variant. `link`
    /// selects one named link to test; `None` tests every configured
    /// link with a `remote_addr`, one at a time. Blocks the command
    /// connection for roughly `duration_secs` per link tested
    /// (doubled if `bidirectional`, since the two legs run
    /// sequentially, not concurrently) -- there is no async
    /// "start and poll later" variant of this command.
    RunThroughputTest {
        link: Option<String>,
        duration_secs: u32,
        bidirectional: bool,
    },
    /// Captures a text diagnostic dump of every link's health, daemon
    /// state, and recent log lines right now (`mlvpnd diag-dump` on the
    /// CLI) -- see `diag::format_dump` and `control::apply_command`'s
    /// handling of this variant. Distinct from the *automatic* dump
    /// `control::diagnostics_watch_loop` can also produce on its own
    /// (see `config::DiagnosticsConfig`): this is always the operator
    /// asking for one right now, unconditionally.
    DiagDump,
}

/// One link's result from a completed `Command::RunThroughputTest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputTestLinkResult {
    pub link: String,
    /// Mbps this side measured *sending* to the peer (the forward/
    /// upload leg) -- `None` if that leg failed or timed out waiting
    /// for the peer's `ThroughputTestResult` (e.g. an old peer that
    /// predates this feature, silently dropping the unrecognized
    /// packet type).
    pub upload_mbps: Option<f64>,
    /// Mbps this side measured *receiving* from the peer (the reverse/
    /// download leg) -- only attempted when `bidirectional` was
    /// requested; `None` either because it wasn't requested or because
    /// the peer's reverse stream never arrived/completed in time.
    pub download_mbps: Option<f64>,
}

/// Reply to exactly one `Command`, written back once before the
/// connection is closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub ok: bool,
    /// `None` when `ok` is true. Set when `ok` is false, e.g. "no such
    /// link" or a malformed request.
    pub error: Option<String>,
    /// Populated only by `Command::RunThroughputTest` -- one entry per
    /// link actually tested, in the order tested. Empty for every other
    /// command (including a `RunThroughputTest` that failed before
    /// testing anything -- see `error` in that case).
    #[serde(default)]
    pub throughput_results: Vec<ThroughputTestLinkResult>,
    /// Populated only by `Command::DiagDump` -- the formatted text
    /// bundle from `diag::format_dump`. `None` for every other command,
    /// and for a `DiagDump` that failed before it could be assembled
    /// (see `error` in that case).
    #[serde(default)]
    pub diag_dump: Option<String>,
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
            local_rx_throughput_mbps: Some(93.4),
            local_tx_throughput_mbps: Some(12.1),
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
        assert_eq!(back.local_rx_throughput_mbps, Some(93.4));
        assert_eq!(back.local_tx_throughput_mbps, Some(12.1));
        assert_eq!(back.local_active_bandwidth_mbps, Some(193.4));
        assert_eq!(back.local_consecutive_hits, 12);
        assert_eq!(back.local_consecutive_misses, 0);
        assert_eq!(back.state_duration_ms, 12_345);
        assert_eq!(back.tx_bytes, 1_000_000);
        assert_eq!(back.rx_bytes, 2_000_000);
        assert_eq!(back.tx_packets, 700);
        assert_eq!(back.rx_packets, 1400);
    }

    /// `DaemonSnapshot` picks up new fields far less often than
    /// `LinkSnapshot`, but the same drop/rename risk exists between
    /// `control::build_snapshot` and `mlvpn-tui`'s deserialize -- worth
    /// the same cheap round-trip coverage.
    #[test]
    fn daemon_snapshot_round_trips_with_outbound_queue_and_tun_fields() {
        let snap = DaemonSnapshot {
            session_id: 42,
            session_uptime_ms: 5_000,
            rekey_count: 3,
            outbound_queue_len: 12,
            outbound_queue_capacity: 256,
            outbound_queue_dropped_total: 7,
            tun: TunSnapshot {
                iface: "mlvpn0".to_string(),
                rx_bytes: Some(1_000),
                tx_bytes: Some(2_000),
                rx_errors: Some(0),
                tx_errors: None,
                rx_dropped: Some(0),
                tx_dropped: None,
            },
            system: SystemSnapshot {
                load1: Some(0.52),
                load5: Some(0.58),
                load15: None,
                mem_total_kb: Some(16_384_000),
                mem_available_kb: Some(8_192_000),
                uptime_secs: Some(12_345),
            },
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let back: DaemonSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.session_id, 42);
        assert_eq!(back.session_uptime_ms, 5_000);
        assert_eq!(back.rekey_count, 3);
        assert_eq!(back.outbound_queue_len, 12);
        assert_eq!(back.outbound_queue_capacity, 256);
        assert_eq!(back.outbound_queue_dropped_total, 7);
        assert_eq!(back.tun.iface, "mlvpn0");
        assert_eq!(back.tun.rx_bytes, Some(1_000));
        assert_eq!(back.tun.tx_errors, None);
        assert_eq!(back.system.load1, Some(0.52));
        assert_eq!(back.system.load15, None);
        assert_eq!(back.system.mem_available_kb, Some(8_192_000));
    }

    /// `new_log_lines` is the delta-streaming mechanism the Logs tab
    /// depends on entirely -- if a `LogEntry` field silently drops or
    /// renames across the wire, this is the cheapest place to catch it.
    #[test]
    fn log_entry_round_trips() {
        let entry = LogEntry {
            seq: 17,
            unix_ts_ms: 1_700_000_000_000,
            level: "WARN".to_string(),
            target: Some("mlvpn::tunnel".to_string()),
            message: "outbound queue overflowed".to_string(),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let back: LogEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.seq, 17);
        assert_eq!(back.level, "WARN");
        assert_eq!(back.target.as_deref(), Some("mlvpn::tunnel"));
        assert_eq!(back.message, "outbound queue overflowed");
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
        let Command::SetLinkEnabled { link, enabled } = back else {
            panic!("expected SetLinkEnabled, got {back:?}");
        };
        assert_eq!(link, "lte0");
        assert!(!enabled);
    }

    #[test]
    fn run_throughput_test_command_json_round_trips() {
        let cmd = Command::RunThroughputTest {
            link: Some("lte0".to_string()),
            duration_secs: 10,
            bidirectional: true,
        };
        let json = serde_json::to_string(&cmd).expect("serialize");
        let back: Command = serde_json::from_str(&json).expect("deserialize");
        let Command::RunThroughputTest {
            link,
            duration_secs,
            bidirectional,
        } = back
        else {
            panic!("expected RunThroughputTest, got {back:?}");
        };
        assert_eq!(link.as_deref(), Some("lte0"));
        assert_eq!(duration_secs, 10);
        assert!(bidirectional);
    }

    #[test]
    fn command_result_round_trips_both_variants() {
        let ok = CommandResult {
            ok: true,
            error: None,
            throughput_results: vec![ThroughputTestLinkResult {
                link: "lte0".to_string(),
                upload_mbps: Some(94.2),
                download_mbps: None,
            }],
            diag_dump: None,
        };
        let ok_back: CommandResult =
            serde_json::from_str(&serde_json::to_string(&ok).unwrap()).unwrap();
        assert!(ok_back.ok);
        assert!(ok_back.error.is_none());
        assert_eq!(ok_back.throughput_results.len(), 1);
        assert_eq!(ok_back.throughput_results[0].link, "lte0");
        assert_eq!(ok_back.throughput_results[0].upload_mbps, Some(94.2));
        assert_eq!(ok_back.throughput_results[0].download_mbps, None);
        assert!(ok_back.diag_dump.is_none());

        let err = CommandResult {
            ok: false,
            error: Some("no such link 'bogus'".to_string()),
            throughput_results: Vec::new(),
            diag_dump: None,
        };
        let err_back: CommandResult =
            serde_json::from_str(&serde_json::to_string(&err).unwrap()).unwrap();
        assert!(!err_back.ok);
        assert_eq!(err_back.error.as_deref(), Some("no such link 'bogus'"));
        assert!(err_back.throughput_results.is_empty());
        assert!(err_back.diag_dump.is_none());
    }

    #[test]
    fn diag_dump_command_json_round_trips() {
        let cmd = Command::DiagDump;
        let json = serde_json::to_string(&cmd).expect("serialize");
        assert_eq!(json, r#"{"command":"diag_dump"}"#);
        let back: Command = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(back, Command::DiagDump));
    }

    #[test]
    fn command_result_diag_dump_round_trips() {
        let result = CommandResult {
            ok: true,
            error: None,
            throughput_results: Vec::new(),
            diag_dump: Some("=== mlvpn diagnostic dump ===\n...".to_string()),
        };
        let back: CommandResult =
            serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
        assert!(back.ok);
        assert_eq!(
            back.diag_dump.as_deref(),
            Some("=== mlvpn diagnostic dump ===\n...")
        );
    }
}
