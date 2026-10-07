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
    /// Structured events (`events::EventRing`) produced since the
    /// connected client's last poll -- same per-connection cursor
    /// delta as `new_log_lines`, but typed and bounded to the
    /// operationally interesting transitions rather than free text.
    #[serde(default)]
    pub new_events: Vec<EventRecord>,
}

/// One structured daemon event. `kind` and `severity` are strings (not
/// enums) so a newer daemon's unknown kinds still deserialize in an older
/// client; `events::EventKind` is the authoritative list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    /// Monotonic within one daemon process, starting at 1 -- the cursor
    /// for delta streaming (see `LogEntry::seq`).
    pub seq: u64,
    pub unix_ts_ms: u64,
    /// "info" | "warn" | "error"
    pub severity: String,
    /// SCREAMING_SNAKE_CASE, e.g. "LINK_DOWN".
    pub kind: String,
    /// Link name when the event concerns one link.
    #[serde(default)]
    pub link: Option<String>,
    pub message: String,
    /// Small machine-readable details (counts, old/new values).
    #[serde(default)]
    pub fields: std::collections::BTreeMap<String, String>,
}

/// Derived tunnel-level telemetry the daemon computes once so every
/// consumer (TUI, web) shows the same answer. All-default (empty
/// `health`) from an older daemon.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetrySnapshot {
    /// "STARTING" | "HEALTHY" | "DEGRADED" | "FAILOVER" | "DOWN"
    pub health: String,
    pub health_reason: String,
    pub tunnel_uptime_secs: u64,
    /// "weighted" | "primary" | "follow-peer" | "redundant"
    pub scheduler_mode: String,
    pub fec: FecConfigSnapshot,
    pub reorder: ReorderSnapshot,
    pub rates: RateSnapshot,
    /// Sum of every link's `tx_rerouted_total`.
    pub reroutes_total: u64,
    /// Lifetime frames dropped because the receive pipeline's channel
    /// was full.
    pub rx_pipeline_dropped_total: u64,
    /// Lifetime nanoseconds the receive pipeline task spent processing
    /// batches (excludes time parked waiting for events).
    pub rx_pipeline_busy_ns_total: u64,
    /// Highest receive-pipeline channel backlog observed at the start of
    /// a batch (capacity is `RX_PIPELINE_CAPACITY`).
    pub rx_pipeline_max_backlog: u64,
    pub process: ProcessSnapshot,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FecConfigSnapshot {
    pub enabled: bool,
    pub group_size: u8,
    pub parity: u8,
    pub placement: String,
}

/// Receive-side reorder buffer state. `late_total` counts frames that
/// arrived at or below the delivered high-watermark (genuine cross-link
/// reordering); `timeout_total` those of them released only because they
/// aged out of the window; `duplicate_total` a seq arriving again while
/// its first copy was still buffered.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReorderSnapshot {
    pub window_ms: u64,
    pub depth: u64,
    pub max_depth: u64,
    pub wait_recent_us: u64,
    pub wait_max_us: u64,
    pub late_total: u64,
    pub duplicate_total: u64,
    pub timeout_total: u64,
}

/// Tunnel (TUN device) throughput over the last sampling interval.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RateSnapshot {
    pub tx_pps: f64,
    pub rx_pps: f64,
    pub tx_mbps: f64,
    pub rx_mbps: f64,
}

/// The daemon process itself, as opposed to `SystemSnapshot`'s host view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessSnapshot {
    pub cpu_pct: Option<f64>,
    pub rss_kb: Option<u64>,
    pub threads: Option<u64>,
    pub open_fds: Option<u64>,
}

/// One captured log line, INFO-severity or higher (see
/// `logbuf::LogRingLayer`'s doc comment for why DEBUG/TRACE never reach
/// this ring regardless of the operator's own configured log level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Monotonically increasing within one daemon process's lifetime,
    /// never reused -- the cursor `new_log_lines` delta streaming is
    /// built on. Resets to 0 on a daemon restart.
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaemonSnapshot {
    // NOTE: `session_id`/`session_uptime_ms`/`rekey_count` were removed
    // here -- they described the old tunnel-wide shared Noise transport
    // session, which no longer exists now that each link owns its own
    // independent WireGuard tunnel (see `src/wireguard.rs::WgTunnel`).
    // A per-link replacement (e.g. handshake count/age per link) would
    // need new tracking state inside `WgTunnel`/`Link` that doesn't
    // exist yet -- left as a possible follow-up, not done here.
    /// Frames currently buffered between `tun_reader` and
    /// `outbound_sender`, waiting to be sent -- 0 on a healthy tunnel
    /// keeping up with the TUN device's read rate.
    pub outbound_queue_len: u64,
    /// Fixed capacity of that same queue (`OUTBOUND_QUEUE_CAPACITY`);
    /// included alongside `outbound_queue_len` so a viewer can show a
    /// fill ratio without hardcoding the constant.
    pub outbound_queue_capacity: u64,
    /// Lifetime count of packets dropped on the TX path, despite the
    /// name: (1) the outbound queue was full when `tun_reader` tried to
    /// enqueue (the send path as a whole is behind), plus (2) every
    /// `TxDispatcher` drop -- all per-link TX queues full, no-spill
    /// `primary_link_mode`/`follow_peer_primary` overflow, and a failed
    /// reroute. Under a fast TCP sender (e.g. BBR) this tracks the sender's
    /// own TCP retransmits, so it is local backpressure, not path loss.
    /// Monotonic, never
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
    /// This daemon's own `mlvpnd` version (`env!("CARGO_PKG_VERSION")`).
    pub local_version: String,
    /// The peer's own last-reported version, learned from the
    /// periodic authenticated `PacketType::VersionInfo` wire exchange
    /// (see that variant's doc comment in `protocol.rs`) -- `None`
    /// until the first one arrives after a session establishes, e.g.
    /// briefly after startup or a fresh rekey. Lets `mlvpn-tui` and
    /// `mlvpnd self-test`'s CLI output flag a version mismatch between
    /// the two ends without needing to SSH to the peer and check by
    /// hand.
    pub peer_version: Option<String>,
    /// This side's own live tunnel MTU (`tunnel::LiveMtu`, from the
    /// v0.5.0 adaptive-MTU feature) -- previously not exposed to
    /// mlvpn-tui at all (neither side's MTU was, despite this
    /// project's own design docs assuming local MTU already was).
    pub local_tunnel_mtu: u16,
    /// The peer's own raw, pre-negotiation local link capability
    /// (`protocol::VersionInfoPayload::tunnel_mtu`), from the periodic
    /// authenticated `VersionInfo` wire exchange (same source/reasoning
    /// as `peer_version`). `None` until the first `VersionInfo`
    /// arrives. Will legitimately differ from `local_tunnel_mtu`
    /// whenever the peer's link happens to support more headroom than
    /// this side's own -- that is NOT itself a problem; see
    /// `peer_applied_tunnel_mtu` below for the field that actually
    /// indicates whether negotiation has converged.
    #[serde(default)]
    pub peer_tunnel_mtu: Option<u16>,
    /// The peer's own actual, already-negotiated live tunnel MTU
    /// (`protocol::VersionInfoPayload::live_tunnel_mtu` --
    /// what's really applied to the peer's TUN device right now).
    /// `None` until the first `VersionInfo` carrying this field
    /// arrives (added alongside this field, 2026-09-17 -- an older
    /// peer's `VersionInfo` predates it, same convention as
    /// `peer_tunnel_mtu` predating a pre-0.6.0 peer). Once both sides
    /// have exchanged at least one `VersionInfo` post-negotiation,
    /// this should equal `local_tunnel_mtu` -- a real, persistent
    /// difference (not just momentarily stale right after a restart)
    /// indicates negotiation hasn't converged, unlike a difference
    /// against `peer_tunnel_mtu` (raw capability), which is often
    /// completely normal. See `mlvpn-tui`'s Session panel, which is
    /// what surfaced the need for this distinction in the first place:
    /// a real asymmetric-but-fully-converged pairing (home-bgp:
    /// capability 1285, cloud-bgp: capability 1305, both correctly
    /// negotiated down to a shared applied MTU of 1285) showed as a
    /// false "MISMATCH" before this field existed to tell the two
    /// cases apart.
    #[serde(default)]
    pub peer_applied_tunnel_mtu: Option<u16>,
    /// Sum of every link's `LinkSnapshot::wg_rejected_total` -- see that
    /// field's doc comment. Added alongside the per-link counters
    /// 2026-09-14 while investigating real TCP-level loss (~15%
    /// retransmission under load) that every pre-existing counter
    /// (`outbound_queue_dropped_total`, `tun.rx_dropped`/`tx_dropped`)
    /// failed to explain.
    #[serde(default)]
    pub wg_rejected_total: u64,
    /// Sum of every link's `LinkSnapshot::wg_substituted_total` -- see
    /// that field's doc comment. Added the same night as
    /// `wg_rejected_total` after that counter stayed at zero through two
    /// real loss-reproducing load tests, ruling out receive-side
    /// rejection and motivating a look at the send side instead.
    #[serde(default)]
    pub wg_substituted_total: u64,
    /// Lifetime count of Data frames successfully reconstructed by
    /// single-erasure FEC (`fec.rs`) -- only ever nonzero when
    /// `scheduler.fec_enabled` is true. See
    /// `docs/superpowers/specs/2026-09-15-single-erasure-fec-design.md`.
    #[serde(default)]
    pub fec_recovered_total: u64,
    /// Lifetime count of FEC groups FEC could not help with: on the
    /// receive side, 2+ members missing, or exactly one missing whose
    /// group-mates can no longer be XORed back together (their
    /// plaintexts aged out before the parity frame landed) -- the
    /// disclosed limit of single-erasure parity, see the design doc's
    /// own "Known, accepted limitation" section. Also incremented on the
    /// *send* side for a group whose parity frame would have exceeded
    /// the live tunnel MTU and was therefore skipped rather than
    /// fragmented (only reachable if the live MTU shrinks mid-group).
    /// Real loss reaching TCP corresponds to this counter, not
    /// `fec_recovered_total`.
    #[serde(default)]
    pub fec_unrecoverable_total: u64,
    /// Sender side: FEC groups whose parity was queued, and the P / Q
    /// parity frames queued for them. A group skipped because it held a
    /// member that never reached the wire (or an oversized parity frame)
    /// is *not* counted here -- it bumps `fec_unrecoverable_total`.
    #[serde(default)]
    pub fec_groups_sent_total: u64,
    #[serde(default)]
    pub fec_parity_p_sent_total: u64,
    #[serde(default)]
    pub fec_parity_q_sent_total: u64,
    #[serde(default)]
    pub telemetry: TelemetrySnapshot,
}

/// Host-wide load/memory/uptime, independent of anything tunnel- or
/// link-specific -- context for whether a problem elsewhere in the
/// snapshot is actually a symptom of the host itself being under load
/// or low on memory. Every field is `Option` since `/proc/loadavg`,
/// `/proc/meminfo`, and `/proc/uptime` are read and parsed
/// independently and any one of them can fail on its own.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

fn default_congestion_factor() -> f64 {
    1.0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinkSnapshot {
    pub name: String,
    pub bind_interface: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    /// "probing" | "up" | "down".
    pub state: String,
    /// True for the single link `Scheduler::primary()` currently returns,
    /// when `scheduler.primary_link_mode`/`follow_peer_primary` is on.
    /// Always `false` for every link under plain SWRR (no concept of a
    /// single primary there -- see `Scheduler::primary`'s own doc
    /// comment). Lets a viewer show which link is actually carrying
    /// traffic without cross-referencing byte counters by hand.
    #[serde(default)]
    pub is_primary: bool,
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
    /// This link's `LinkStats::confirmed_ceiling_mbps` -- the rate
    /// `adaptive_bandwidth_ramp` last fully converged on, as opposed to
    /// `local_active_bandwidth_mbps` above (the smoothed EWMA of every
    /// probe/verification result, ramp or single-step alike). `None`
    /// until the first full ramp completes, or always if
    /// `scheduler.active_bandwidth_probing` is off.
    #[serde(default)]
    pub local_confirmed_ceiling_mbps: Option<f64>,
    /// Consecutive successful/missed probes right now -- one of these
    /// two is always 0 (a hit resets the miss streak and vice versa).
    /// Shows a link's short-term probe health at a glance, e.g. "3
    /// misses in a row" ahead of a state transition actually firing.
    pub local_consecutive_hits: u32,
    pub local_consecutive_misses: u32,
    /// This link's own lifetime count of datagrams its `WgTunnel`
    /// (`src/wireguard.rs`) rejected outright -- bad MAC, replay-window
    /// miss, garbled/oversized data. Previously invisible to every
    /// existing counter (`outbound_queue_dropped_total`, the TUN
    /// device's `rx_dropped`/`tx_dropped`): the rejection happens inside
    /// boringtun, before a frame is ever handed to those layers. Added
    /// 2026-09-14 -- see `WgTunnel::rejected_total`'s doc comment.
    #[serde(default)]
    pub wg_rejected_total: u64,
    /// This link's own lifetime count of `WgTunnel::encapsulate` calls
    /// whose real plaintext was silently substituted with a handshake
    /// datagram instead of actually being sent -- boringtun's own
    /// `TunnResult::WriteToNetwork` covers both a genuine data send and
    /// this substitution identically, so `wg_send`'s caller (including
    /// `LinkStats::record_tx`) sees a completely normal successful send
    /// either way. See `WgTunnel::substituted_total`'s doc comment for
    /// the full boringtun-source-level explanation. Added 2026-09-15.
    #[serde(default)]
    pub wg_substituted_total: u64,
    /// Lifetime count of times this link's bounded TX queue was full when
    /// the dispatcher tried to hand it a packet -- the link's socket send
    /// path was not keeping up. See `link::TxCounters`.
    #[serde(default)]
    pub tx_queue_full_total: u64,
    /// Lifetime count of packets this link's TX worker failed to put on
    /// the wire (socket error or no remote address).
    #[serde(default)]
    pub tx_send_failed_total: u64,
    /// Lifetime count of packets redirected to another link because this
    /// one could not take them (queue full, or send failure).
    #[serde(default)]
    pub tx_rerouted_total: u64,
    /// Packets currently queued for (or being sent by) this link's TX
    /// worker.
    #[serde(default)]
    pub tx_queue_depth: u32,
    /// Recent average time the oldest packet of each TX batch waited in
    /// this link's queue, microseconds (0 when idle). The primary
    /// congestion signal the scheduler acts on.
    #[serde(default)]
    pub tx_queue_delay_us: u64,
    /// Lifetime peak of the same measurement.
    #[serde(default)]
    pub tx_queue_delay_max_us: u64,
    /// Recent average per-packet time spent inside this link's socket
    /// send, microseconds.
    #[serde(default)]
    pub tx_send_wait_us: u64,
    /// Scheduler weight multiplier in `[0.1, 1.0]`: 1.0 healthy, lower
    /// while the link's queue delay / send failures say it is congested.
    #[serde(default = "default_congestion_factor")]
    pub congestion_factor: f64,
    /// Scheduler weight multiplier from delivery feedback (what the peer
    /// reports receiving vs. what we offered this link): 1.0 healthy,
    /// down to 0.001 for a link that drops most of a bulk flow even
    /// though its probes succeed.
    #[serde(default = "default_congestion_factor")]
    pub delivery_factor: f64,
    /// The link is Up but congested enough (`congestion_factor` below
    /// 0.7) that the scheduler is steering traffic away from it. A
    /// derived overlay on `state`, not a separate state.
    #[serde(default)]
    pub degraded: bool,

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

/// Which wire protocol `Command::RunTunnelThroughputTest` uses --
/// `Tcp` (the default) gives numbers directly comparable to `iperf3`
/// since it reacts to real loss the way TCP does; `Udp` preserves the
/// original raw, unpaced-by-loss measurement, useful as a diagnostic
/// comparison point (the gap between the two shows how much real loss
/// is hurting real traffic). See
/// docs/superpowers/specs/2026-09-16-tcp-tunnel-self-test-design.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
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
    /// Runs an on-demand *tunnel-level* throughput self-test
    /// (`mlvpnd self-test --tunnel` on the CLI) -- unlike
    /// `RunThroughputTest` above (raw UDP directly on one link's own
    /// socket, bypassing the TUN device/outbound queue/scheduler
    /// entirely), this sends real UDP packets to `peer_addr` (the
    /// peer's tunnel-internal address, e.g. `"10.200.0.2"`) that
    /// genuinely transit the whole real pipeline -- see
    /// `tunneltest.rs`'s module doc comment. Blocks the command
    /// connection for roughly `duration_secs` (doubled, sequentially,
    /// if `bidirectional`) plus a grace period.
    RunTunnelThroughputTest {
        peer_addr: String,
        duration_secs: u32,
        bidirectional: bool,
        #[serde(default)]
        protocol: Protocol,
    },
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
    /// One `(target_mbps, achieved_mbps)` pair per step of the upload
    /// leg's `adaptive_bandwidth_ramp` -- lets `mlvpnd self-test`'s CLI
    /// output show exactly where a real throughput ceiling sits (e.g.
    /// an ISP policer cliff), not just the final backed-off number.
    /// Empty if the upload leg failed before any step ran.
    #[serde(default)]
    pub upload_steps: Vec<(f64, Option<f64>)>,
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
    /// Populated only by `Command::RunTunnelThroughputTest`. `None` for
    /// every other command, and for one that failed before running
    /// (see `error` in that case).
    #[serde(default)]
    pub tunnel_test_result: Option<TunnelTestCommandResult>,
    /// The peer's own last-reported version at the time this command
    /// was answered -- same source as `DaemonSnapshot::peer_version`
    /// (the periodic `VersionInfo` wire exchange), included on every
    /// command reply since it's cheap and lets a self-test command's
    /// CLI output flag a version mismatch even when the test itself
    /// timed out with no result. `None` if no `VersionInfo` has been
    /// received from the peer yet.
    #[serde(default)]
    pub peer_version: Option<String>,
}

/// Result of a completed `Command::RunTunnelThroughputTest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelTestCommandResult {
    /// Mbps the peer measured receiving our upload stream. `None` if
    /// that leg never produced a result in time (e.g. real loss severe
    /// enough that even the redundant "done" copies never arrived).
    pub upload_mbps: Option<f64>,
    /// Mbps we measured receiving the peer's autonomous reverse stream
    /// -- only attempted when `bidirectional` was requested.
    pub download_mbps: Option<f64>,
    /// This side's own `outbound_queue_dropped_total` delta observed
    /// while sending the upload leg -- direct evidence of whether the
    /// real outbound queue dropped anything during this test, not an
    /// inference from external loss measurements. Always present (0 if
    /// nothing dropped), unlike the peer-side figure below, since this
    /// side always knows it regardless of whether the upload leg
    /// otherwise succeeded.
    pub local_outbound_queue_dropped_delta: u64,
    /// The *peer's* own `outbound_queue_dropped_total` delta while it
    /// sent the reverse leg back to us -- `None` unless `bidirectional`
    /// was requested and that leg actually completed (this figure rides
    /// on the reverse stream itself, so it's unavailable if that leg
    /// never arrived).
    pub peer_outbound_queue_dropped_delta: Option<u64>,
    /// TCP-only (`None` for a UDP-protocol test). See `TunnelTestOutcome`.
    #[serde(default)]
    pub upload_retransmits: Option<u32>,
    /// TCP-only (`None` for a UDP-protocol test). See `TunnelTestOutcome`.
    #[serde(default)]
    pub download_retransmits: Option<u32>,
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
            is_primary: true,
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
            local_confirmed_ceiling_mbps: Some(180.0),
            local_consecutive_hits: 12,
            local_consecutive_misses: 0,
            wg_rejected_total: 3,
            wg_substituted_total: 2,
            tx_queue_full_total: 0,
            tx_send_failed_total: 0,
            tx_rerouted_total: 0,
            tx_queue_depth: 0,
            tx_queue_delay_us: 0,
            tx_queue_delay_max_us: 0,
            tx_send_wait_us: 0,
            congestion_factor: 1.0,
            delivery_factor: 1.0,
            degraded: false,
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
        assert_eq!(back.local_confirmed_ceiling_mbps, Some(180.0));
        assert_eq!(back.local_consecutive_hits, 12);
        assert_eq!(back.local_consecutive_misses, 0);
        assert_eq!(back.state_duration_ms, 12_345);
        assert_eq!(back.tx_bytes, 1_000_000);
        assert_eq!(back.rx_bytes, 2_000_000);
        assert_eq!(back.tx_packets, 700);
        assert_eq!(back.rx_packets, 1400);
        assert_eq!(back.wg_rejected_total, 3);
        assert_eq!(back.wg_substituted_total, 2);
    }

    /// `DaemonSnapshot` picks up new fields far less often than
    /// `LinkSnapshot`, but the same drop/rename risk exists between
    /// `control::build_snapshot` and `mlvpn-tui`'s deserialize -- worth
    /// the same cheap round-trip coverage.
    #[test]
    fn daemon_snapshot_round_trips_with_outbound_queue_and_tun_fields() {
        let snap = DaemonSnapshot {
            outbound_queue_len: 12,
            outbound_queue_capacity: 256,
            outbound_queue_dropped_total: 7,
            wg_rejected_total: 4,
            wg_substituted_total: 5,
            fec_recovered_total: 9,
            fec_unrecoverable_total: 2,
            fec_groups_sent_total: 7,
            fec_parity_p_sent_total: 7,
            fec_parity_q_sent_total: 5,
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
            local_version: "0.4.5".to_string(),
            peer_version: Some("0.4.5".to_string()),
            local_tunnel_mtu: 1420,
            peer_tunnel_mtu: Some(1420),
            peer_applied_tunnel_mtu: Some(1420),
            telemetry: TelemetrySnapshot {
                health: "DEGRADED".to_string(),
                reroutes_total: 3,
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let back: DaemonSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.outbound_queue_len, 12);
        assert_eq!(back.outbound_queue_capacity, 256);
        assert_eq!(back.outbound_queue_dropped_total, 7);
        assert_eq!(back.wg_rejected_total, 4);
        assert_eq!(back.wg_substituted_total, 5);
        assert_eq!(back.fec_recovered_total, 9);
        assert_eq!(back.fec_unrecoverable_total, 2);
        assert_eq!(back.fec_groups_sent_total, 7);
        assert_eq!(back.fec_parity_q_sent_total, 5);
        assert_eq!(back.tun.iface, "mlvpn0");
        assert_eq!(back.tun.rx_bytes, Some(1_000));
        assert_eq!(back.tun.tx_errors, None);
        assert_eq!(back.system.load1, Some(0.52));
        assert_eq!(back.system.load15, None);
        assert_eq!(back.system.mem_available_kb, Some(8_192_000));
        assert_eq!(back.local_version, "0.4.5");
        assert_eq!(back.peer_version, Some("0.4.5".to_string()));
        assert_eq!(back.telemetry.health, "DEGRADED");
        assert_eq!(back.telemetry.reroutes_total, 3);
        assert_eq!(back.local_tunnel_mtu, 1420);
        assert_eq!(back.peer_tunnel_mtu, Some(1420));
    }

    #[test]
    fn daemon_snapshot_peer_version_defaults_to_none_when_absent_from_the_wire() {
        // A daemon that hasn't yet received a `VersionInfo` frame from
        // the peer (e.g. right after startup, before the first
        // `stats_tick`) has to serialize `peer_version: None` cleanly,
        // not omit the field -- unlike `CommandResult`'s newer fields,
        // `DaemonSnapshot` is always freshly constructed server-side, so
        // there's no `#[serde(default)]` backward-compat concern here,
        // just confirming `Option::None` itself round-trips.
        let json = r#"{"outbound_queue_len":0,"outbound_queue_capacity":256,
            "outbound_queue_dropped_total":0,
            "tun":{"iface":"mlvpn0","rx_bytes":null,"tx_bytes":null,
                "rx_errors":null,"tx_errors":null,"rx_dropped":null,"tx_dropped":null},
            "system":{"load1":null,"load5":null,"load15":null,
                "mem_total_kb":null,"mem_available_kb":null,"uptime_secs":null},
            "local_version":"0.4.5","peer_version":null,"local_tunnel_mtu":1420}"#;
        let snap: DaemonSnapshot = serde_json::from_str(json).expect("deserialize");
        assert_eq!(snap.peer_version, None);
        assert_eq!(snap.peer_tunnel_mtu, None);
    }

    /// `peer_tunnel_mtu` is `#[serde(default)]` (unlike `peer_version`
    /// above, which is a plain required field on `DaemonSnapshot`) so
    /// that an older daemon binary's already-serialized snapshot (from
    /// before this field existed) still deserializes cleanly on a newer
    /// `mlvpn-tui` -- confirms the field can be entirely *absent* from
    /// the JSON, not just present-and-null.
    #[test]
    fn daemon_snapshot_peer_tunnel_mtu_defaults_to_none_when_absent_from_the_wire() {
        let json = r#"{"outbound_queue_len":0,"outbound_queue_capacity":256,
            "outbound_queue_dropped_total":0,
            "tun":{"iface":"mlvpn0","rx_bytes":null,"tx_bytes":null,
                "rx_errors":null,"tx_errors":null,"rx_dropped":null,"tx_dropped":null},
            "system":{"load1":null,"load5":null,"load15":null,
                "mem_total_kb":null,"mem_available_kb":null,"uptime_secs":null},
            "local_version":"0.4.5","peer_version":null,"local_tunnel_mtu":1420}"#;
        let snap: DaemonSnapshot = serde_json::from_str(json).expect("deserialize");
        assert_eq!(snap.peer_tunnel_mtu, None);
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
                upload_steps: vec![(2.0, Some(1.9)), (4.0, Some(3.8))],
            }],
            diag_dump: None,
            tunnel_test_result: None,
            peer_version: None,
        };
        let ok_back: CommandResult =
            serde_json::from_str(&serde_json::to_string(&ok).unwrap()).unwrap();
        assert!(ok_back.ok);
        assert!(ok_back.error.is_none());
        assert_eq!(ok_back.throughput_results.len(), 1);
        assert_eq!(ok_back.throughput_results[0].link, "lte0");
        assert_eq!(ok_back.throughput_results[0].upload_mbps, Some(94.2));
        assert_eq!(ok_back.throughput_results[0].download_mbps, None);
        assert_eq!(
            ok_back.throughput_results[0].upload_steps,
            vec![(2.0, Some(1.9)), (4.0, Some(3.8))]
        );
        assert!(ok_back.diag_dump.is_none());

        let err = CommandResult {
            ok: false,
            error: Some("no such link 'bogus'".to_string()),
            throughput_results: Vec::new(),
            diag_dump: None,
            tunnel_test_result: None,
            peer_version: None,
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
            tunnel_test_result: None,
            peer_version: None,
        };
        let back: CommandResult =
            serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
        assert!(back.ok);
        assert_eq!(
            back.diag_dump.as_deref(),
            Some("=== mlvpn diagnostic dump ===\n...")
        );
    }

    #[test]
    fn run_tunnel_throughput_test_command_json_round_trips() {
        let cmd = Command::RunTunnelThroughputTest {
            peer_addr: "10.200.0.2".to_string(),
            duration_secs: 10,
            bidirectional: true,
            protocol: Protocol::Tcp,
        };
        let json = serde_json::to_string(&cmd).expect("serialize");
        let back: Command = serde_json::from_str(&json).expect("deserialize");
        let Command::RunTunnelThroughputTest {
            peer_addr,
            duration_secs,
            bidirectional,
            protocol,
        } = back
        else {
            panic!("expected RunTunnelThroughputTest, got {back:?}");
        };
        assert_eq!(peer_addr, "10.200.0.2");
        assert_eq!(duration_secs, 10);
        assert!(bidirectional);
        assert_eq!(protocol, Protocol::Tcp);
    }

    /// Forward-compatibility guard: an older CLI's request (predating
    /// the `protocol` field) must still deserialize against a newer
    /// daemon, defaulting to `Protocol::Tcp` via `#[serde(default)]` --
    /// same established pattern as `peer_tunnel_mtu` elsewhere in this
    /// file.
    #[test]
    fn run_tunnel_throughput_test_command_protocol_defaults_to_tcp_when_absent_from_the_wire() {
        let json = serde_json::json!({
            "command": "run_tunnel_throughput_test",
            "peer_addr": "10.200.0.2",
            "duration_secs": 10,
            "bidirectional": false,
        })
        .to_string();
        let back: Command = serde_json::from_str(&json).expect("deserialize");
        let Command::RunTunnelThroughputTest { protocol, .. } = back else {
            panic!("expected RunTunnelThroughputTest, got {back:?}");
        };
        assert_eq!(protocol, Protocol::Tcp);
    }

    #[test]
    fn command_result_tunnel_test_result_round_trips() {
        let result = CommandResult {
            ok: true,
            error: None,
            throughput_results: Vec::new(),
            diag_dump: None,
            tunnel_test_result: Some(TunnelTestCommandResult {
                upload_mbps: Some(412.3),
                download_mbps: Some(388.9),
                local_outbound_queue_dropped_delta: 0,
                peer_outbound_queue_dropped_delta: Some(3),
                upload_retransmits: Some(12),
                download_retransmits: Some(7),
            }),
            peer_version: None,
        };
        let back: CommandResult =
            serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
        let tt = back.tunnel_test_result.expect("tunnel_test_result");
        assert_eq!(tt.upload_mbps, Some(412.3));
        assert_eq!(tt.download_mbps, Some(388.9));
        assert_eq!(tt.local_outbound_queue_dropped_delta, 0);
        assert_eq!(tt.peer_outbound_queue_dropped_delta, Some(3));
    }

    #[test]
    fn command_result_peer_version_round_trips() {
        let result = CommandResult {
            ok: true,
            error: None,
            throughput_results: Vec::new(),
            diag_dump: None,
            tunnel_test_result: None,
            peer_version: Some("0.4.4".to_string()),
        };
        let back: CommandResult =
            serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
        assert_eq!(back.peer_version.as_deref(), Some("0.4.4"));
    }

    /// Mirrors `daemon_snapshot_peer_version_defaults_to_none_when_absent_from_the_wire`:
    /// `peer_version` is `#[serde(default)]` on `CommandResult` (unlike
    /// `DaemonSnapshot`'s copy, which has no backward-compat need since
    /// it's always freshly constructed server-side) specifically so an
    /// older daemon's reply -- missing this field entirely -- still
    /// deserializes on a newer `mlvpnd`/`mlvpn-tui` CLI instead of
    /// failing the whole command round trip.
    #[test]
    fn command_result_peer_version_defaults_to_none_when_absent_from_the_wire() {
        let json = r#"{"ok":true,"error":null,"throughput_results":[],"diag_dump":null}"#;
        let back: CommandResult = serde_json::from_str(json).expect("deserialize");
        assert_eq!(back.peer_version, None);
        assert!(back.tunnel_test_result.is_none());
    }
}
