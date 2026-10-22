//! Ties together the TUN device, the bonded links, the scheduler and the
//! crypto session into the running data path.
//!
//! Task layout (all spawned on the shared tokio runtime):
//!
//! - one `tun_reader` task: reads plaintext IP packets from the TUN
//!   device and encrypts them, then hands each one off (a bounded,
//!   non-blocking `try_send`, see `OUTBOUND_QUEUE_CAPACITY`'s doc
//!   comment) to...
//! - one `outbound_sender` task: asks the `Scheduler` which link to use
//!   for each queued frame and `try_send`s it onto that link's own
//!   bounded queue (`TxDispatcher`), never blocking. Split from
//!   `tun_reader` specifically so a slow send side can never stall
//!   draining the TUN device -- a full queue drops the packet and counts
//!   it instead, logged by...
//! - one `link_tx_worker` task per link: drains that link's queue,
//!   encrypts and does the actual `send_to`. A stalled socket therefore
//!   only backs up its own queue (counted in `TxCounters::queue_full`);
//!   other links keep transmitting. A packet that finds its link's queue
//!   full spills to the freest other link, or is dropped under
//!   `primary_link_mode`/`follow_peer_primary`. FEC traffic (Data
//!   members and parity shares) goes through the same queues; see
//!   `FecGate` for how group parity still excludes frames that never
//!   reached the wire.
//! - one `outbound_queue_drop_reporter` task: silent on a healthy
//!   tunnel, periodically logs (and resets) the outbound queue's drop
//!   counter otherwise. The original C `MLVPN`'s equivalent mechanism
//!   (`freebuffer_t`, a fixed-size packet-object pool that returns
//!   `NULL` once exhausted) inspired this -- see `OUTBOUND_QUEUE_CAPACITY`'s
//!   doc comment for the real bug (silent, kernel-level TUN-queue
//!   overflow, invisible from inside this process) this exists to catch
//!   sooner next time.
//! - two tasks per link: `link_receiver` owns that link's UDP socket and
//!   demultiplexes incoming frames by `PacketType` (Data goes to the
//!   reorder buffer and then the TUN device; Probe/ProbeReply feed the
//!   latency monitor; StatsShare feeds `peerstats::PeerStatsTable`);
//!   `link_prober` independently emits Probe frames on a timer, emits
//!   StatsShare frames on a slower timer, and sweeps timed-out probes into
//!   losses. These are deliberately *separate* tasks rather than one task
//!   `select!`-ing between "receive" and "probe timer" branches: under
//!   sustained high receive volume, a biased or even fairly-randomized
//!   `select!` can keep preferring the always-ready receive branch and
//!   starve the timer branches, which for this daemon means probes
//!   silently stop firing on the busiest links -- precisely the ones whose
//!   quality most needs fresh measurement. Giving the prober its own task
//!   with its own timer removes that failure mode entirely instead of
//!   just making it statistically rare.
//! - one `rx_pipeline` task: the single owner of the reorder buffer and
//!   the FEC recovery buffer. Link receivers only decrypt and hand frames
//!   over a bounded channel (`RxEvent`), so neither structure sits behind
//!   a lock on the hot path. It also releases packets that have waited
//!   past `reorder_window_ms` (a permanently missing packet degrades to
//!   out-of-order delivery instead of stalling the tunnel forever) and
//!   expires stale FEC groups.
//! - one `reorder_tuning_loop` task (no-op unless
//!   `scheduler.auto_tune_reorder_window` is set): periodically re-tunes
//!   `reorder_window_ms` itself from the live RTT spread across Up
//!   links, instead of leaving it fixed at its configured value for the
//!   tunnel's whole lifetime. See `ARCHITECTURE.md` §7.
//! - one optional `control::serve` task: accepts connections on the local
//!   monitoring Unix socket and streams live link/traffic stats to
//!   whoever connects (`mlvpn-tui`, or anything else speaking the
//!   newline-delimited-JSON protocol in `ipc.rs`). Disabled by setting
//!   `[control] enabled = false` in the config.
//! - one optional `control::serve_commands` task: a separate, off-by-default
//!   Unix socket (`[command] enabled = true` to turn it on) accepting
//!   one JSON `ipc::Command` per connection to mutate live link state at
//!   runtime -- currently just pinning a link enabled/disabled
//!   (`Link::admin_disabled`) without editing the config and
//!   restarting. See `control.rs`'s module doc comment for why this is
//!   a separate socket from the read-only one above.
//! - one optional `control::diagnostics_watch_loop` task (`[diagnostics]
//!   auto_dump_enabled = true` to turn it on, off by default): watches
//!   every link's locally-measured loss and writes a text diagnostic
//!   dump to disk when one is degraded, flapping or down, so a
//!   transient loss event's evidence gets captured even if no one is
//!   watching live. See `diag.rs` and `config::DiagnosticsConfig`.
//!
//! **Graceful shutdown.** `run()`'s tail waits on a local SIGINT/SIGTERM,
//! then sends a best-effort `Disconnect` to the peer on every link
//! (`broadcast_disconnect`) before aborting every spawned task and
//! returning cleanly, rather than the process only ever ending via
//! signal or panic. Receiving the peer's own `Disconnect`
//! (`handle_incoming`) deliberately does *not* trigger the same
//! teardown on this side anymore -- it used to (through v0.4.5's
//! `Shutdown`/`ShutdownReason::PeerInitiated`), which meant a routine
//! restart on *either* end (a `.deb` upgrade, a manual
//! `systemctl restart`) cascaded into a full stop-then-cold-restart on
//! the *other* end too, even though nothing was actually wrong with it.
//! Now a received `Disconnect` just means "the peer is shutting down or
//! restarting" -- purely informational (logged), since neither role
//! needs to *do* anything about it anymore: each link's own WireGuard
//! session re-handshakes lazily on its own the next time either side
//! sends real traffic (see this module's own doc comment on the
//! per-link transport), the same way real WireGuard recovers from a
//! peer restart without any explicit reconnect signal. This side's own
//! tasks (TUN reader, outbound queue, control sockets, other links)
//! keep running the whole time regardless -- no process exit, no
//! `systemd` `RestartSec` gap, no cold-boot re-bind of every socket.
//!
//! Locking discipline: `links: link::Links` (`Arc<Vec<AsyncMutex<Link>>>`)
//! gives each link its own independent lock over its metadata (stats,
//! state, the learned remote address) -- *not* one lock shared across the
//! whole collection. An earlier version of this module used
//! `Arc<AsyncMutex<Vec<Link>>>`, a single mutex guarding every link at
//! once; real two-link deployment testing (see `CHANGELOG.md`) found that
//! this forced both links' `link_receiver` tasks to serialize against
//! each other on every packet's metadata update (recording bytes,
//! learning a peer address), even though the two links touch completely
//! disjoint data -- measured as bonded throughput coming in at roughly
//! half of either link's solo throughput, worse than not bonding at all.
//! Per-link locks remove that cross-link contention entirely: locking
//! `links[0]` never blocks anything waiting on `links[1]`. Any call site
//! that genuinely needs to look at *every* link at once (a control-socket
//! snapshot, `Scheduler::refresh`, the rare all-links-Down fallback) uses
//! `link::snapshot_links`, which locks each link only long enough to
//! clone it, rather than holding a single lock across the whole read.
//!
//! That full clone is still too expensive for a true per-packet hot path,
//! though: fixing the lock contention above wasn't enough on its own --
//! a real two-link deployment test pushing 200 Mbps of small UDP
//! datagrams (~19k packets/sec) found a hard, flat ~65% loss ceiling
//! traced to the old inline send path calling `snapshot_links` (cloning every
//! link's full `Link`, including heap-allocating every `LinkConfig`
//! `String` field) on *every outgoing packet*, just to let the scheduler
//! pick one and throw the rest away. `pick_link` now calls
//! `link::snapshot_scores` instead -- a `Copy`-only snapshot with no
//! `String`/heap data at all -- and `Scheduler::select` returns just the
//! winning index, so only that *one* link ever gets locked-and-cloned
//! for its remote address/socket handle, not every candidate up front.

//!
//! Every task that performs socket I/O first takes a `link::LinkHandle`
//! (see that module) out from under a short-lived lock, reads the
//! handle's *current* socket (`LinkHandle::current_socket`, its own
//! separate, per-link `RwLock` -- see below), and only then awaits
//! `send_to`/`recv_from` on that owned clone, never across a `Link`
//! mutex guard. Holding an async mutex across a network read/write that
//! can block indefinitely would serialize every link behind whichever one
//! is slowest to receive -- exactly the kind of head-of-line blocking a
//! multi-link bonding daemon exists to avoid.
//!
//! **Per-link WireGuard transport (replaces the old shared Noise
//! session).** There is no longer one tunnel-wide crypto session, no
//! app-level handshake, and no app-driven rekeying in this module at
//! all: each configured link owns its own independent `wireguard::WgTunnel`
//! (built at `Link::bind` time from that link's own
//! `private_key_file`/`peer_public_key`, see `link.rs`), which handles
//! its own handshake, rekey, keepalive, and replay window entirely
//! internally via `boringtun`. Every send goes through that link's own
//! `LinkHandle::wg_send` (encrypts + transmits) and every receive
//! through `LinkHandle::wg_recv` (receives + decrypts, looping
//! internally past any handshake/keepalive traffic so callers only ever
//! see a genuine decrypted mlvpn frame). Because encryption is now tied
//! to *which link* a frame goes out on, a frame can no longer be
//! encrypted once, tunnel-wide, before a link is chosen the way the old
//! shared-session design did -- `TxDispatcher` below
//! pick the link first, then build and encrypt that specific frame via
//! the chosen link's own `wg_send`.
//!
//! `protocol::Header.seq` is still a single, tunnel-wide monotonic
//! counter (`next_send_seq` below, a plain `AtomicU64` -- previously
//! this lived on the old shared `crypto::Session`), shared across every
//! packet type on every link, exactly as before: `ReorderBuffer` still
//! uses it to detect genuine cross-link reordering. This is unrelated to
//! -- and does not need to agree with -- any per-link WireGuard-internal
//! nonce/counter, which is now entirely private to that link's own
//! `WgTunnel`/`boringtun::Tunn`.
//!
//! There is no explicit "wait for the handshake" step anywhere in this
//! module's startup sequence, on either `Mode::Client` or `Mode::Server`
//! -- `run()` spawns every link's tasks immediately. This mirrors real
//! WireGuard's own lazy, connectionless handshake model rather than
//! reintroducing a new tunnel-wide readiness gate: a link's very first
//! `wg_send` call (a `Probe`, fired unconditionally on `link_prober`'s
//! own timer, or real Data traffic) queues the plaintext internally and
//! emits a handshake-initiation datagram instead of delivering it
//! immediately (see `wireguard::WgTunnel::encapsulate`'s doc comment);
//! `link_prober` also drives boringtun's own internal retry/keepalive
//! timers by calling `LinkHandle::wg_tick` (`link.rs`) once per probe
//! interval, so a handshake that needs retrying (a lost init/response,
//! a peer that's briefly unreachable) recovers on its own without any
//! bespoke retry loop in this module. Each link therefore comes up
//! independently, on its own schedule -- exactly the same per-link
//! Up/Down tolerance `scheduler.rs`/`monitor.rs` already had to handle
//! for ordinary link-quality reasons, reused here rather than inventing
//! a second "is the whole tunnel up yet" concept.
//!
//! **Dual-stack address-family race.** A link whose `remote_addr` hostname
//! resolves to both IPv4 and IPv6 races its real WireGuard handshake
//! initiation against both addresses once, at the top of `run`
//! (`Link::resolve_alternate`), before any per-link task snapshots the
//! link's remote, and keeps whichever family answers. If neither answers
//! within `ALTERNATE_RACE_DEADLINE` the primary is kept and ordinary lazy
//! handshake retries continue against it (so a peer that is down at
//! startup can leave a link on a wrong-family guess until restart).
//!
//! **Self-healing reconnection.** `link_receiver` and `link_prober` each
//! track consecutive I/O failures on the socket they're currently using
//! (via `link::LinkHandle::current_socket`, re-read fresh before every
//! call rather than cached) -- but only failures that
//! `link::is_interface_gone_error` classifies as "the interface itself
//! is gone" (`ENODEV`/`ENXIO`) count toward that streak. Past
//! `RECONNECT_FAILURE_THRESHOLD` of those in a row, `attempt_reconnect`
//! below calls `LinkHandle::reconnect` to rebind the link's socket from
//! scratch, with exponential backoff between attempts if that keeps
//! failing. Most transient loss (a route flapping, an interface briefly
//! admin-down, `ENETDOWN`/`ENETUNREACH`) never reaches this path at all
//! -- it's deliberately never counted, so the existing socket is left
//! alone to just start working again on its own the moment the route
//! returns, exactly as `link.rs`'s module doc comment promises; this
//! exists only for the harder case of the bound interface being fully
//! removed and recreated with a new ifindex. See `link.rs`'s module doc
//! comment for the full rationale and `LinkHandle::reconnect`'s doc
//! comment for the one deployment-model caveat.

use crate::config;
use crate::config::{Mode, SchedulerConfig};
use crate::control;
use crate::crypto;
use crate::delivery::{self, DeliverySample};
use crate::error::{MlvpnError, Result};
use crate::fec;
use crate::link::{self, Link, LinkHandle, LinkScore, LinkState, Links, is_interface_gone_error};
use crate::monitor::{self, ProbeTracker};
use crate::peerstats::PeerStatsTable;
use crate::protocol::{
    HEADER_LEN, Header, PacketType, ProbePayload, StatsPayload, ThroughputTestDataPayload,
    ThroughputTestResultPayload, ThroughputTestReverseRequestPayload, VersionInfoPayload,
};
use crate::scheduler::{PrimaryFlag, Scheduler};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::time::interval;
use tun_rs::AsyncDevice;

/// How often each link reports its own stats to the peer via a
/// `StatsShare` frame. Not performance-sensitive (this only feeds a
/// monitoring display), so a fixed constant rather than another config
/// knob -- 1s is frequent enough to feel "live" in `mlvpn-tui` without
/// adding meaningful traffic overhead.
const STATS_SHARE_INTERVAL_MS: u64 = 1000;

/// Consecutive socket I/O failures (on send *or* receive) a link's
/// prober/receiver task tolerates before attempting a from-scratch
/// reconnect (`link::LinkHandle::reconnect`). Deliberately not 1 -- a
/// single transient error (a momentarily full send buffer, one lost
/// route lookup during a routing table update) shouldn't trigger a
/// privileged rebind attempt; only a sustained run of failures spanning
/// several probe intervals indicates the socket itself, not just one
/// packet, is the problem. At the default 200ms `probe_interval_ms`
/// this is roughly a one-second detection window.
const RECONNECT_FAILURE_THRESHOLD: u32 = 5;

/// Initial delay before retrying a failed reconnect attempt, doubling
/// (capped at `RECONNECT_BACKOFF_MAX_MS`) on each further failure and
/// resetting back to this value the moment one succeeds. Keeps a link
/// whose interface is genuinely gone from hammering `bind()` in a tight
/// loop, while still reconnecting promptly once it's usable again.
const RECONNECT_BACKOFF_INITIAL_MS: u64 = 500;
const RECONNECT_BACKOFF_MAX_MS: u64 = 30_000;

/// Attempt one reconnect of `handle`'s socket, logging the outcome and
/// sleeping for the current backoff duration regardless of result (so
/// the caller's loop never needs its own separate delay after calling
/// this). Called by both `link_receiver` and `link_prober` once their
/// own consecutive-failure counter crosses `RECONNECT_FAILURE_THRESHOLD`
/// -- see the module doc comment.
async fn attempt_reconnect(handle: &LinkHandle, link_name: &str, backoff_ms: &mut u64) {
    match handle.reconnect().await {
        Ok(()) => {
            tracing::info!(link = %link_name, "link socket reconnected");
            *backoff_ms = RECONNECT_BACKOFF_INITIAL_MS;
        }
        Err(MlvpnError::CapabilityMissing(detail)) => {
            // No amount of retrying fixes this on its own -- see
            // LinkHandle::reconnect's doc comment. Still retry (an
            // operator could restart the daemon under the ambient-
            // capabilities deployment model without changing this
            // build), but at the slowest cadence, with a message that
            // explains why once per attempt rather than leaving the
            // operator to guess from a bare "permission denied".
            tracing::error!(
                link = %link_name,
                error = %detail,
                "cannot reconnect this link's socket: self-healing reconnection after an \
                 interface is removed/recreated requires CAP_NET_RAW to still be held at \
                 runtime, which only the 'never be root' deployment model guarantees \
                 (systemd AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW, see \
                 systemd/mlvpn.service) -- the default 'start as root, drop after setup' \
                 model clears every capability permanently after startup. This link will \
                 keep retrying but cannot succeed until the daemon is restarted under that \
                 model."
            );
            *backoff_ms = RECONNECT_BACKOFF_MAX_MS;
        }
        Err(e) => {
            tracing::warn!(
                link = %link_name,
                error = %e,
                backoff_ms = *backoff_ms,
                "link reconnect attempt failed, backing off"
            );
            *backoff_ms = (*backoff_ms * 2).min(RECONNECT_BACKOFF_MAX_MS);
        }
    }
    tokio::time::sleep(Duration::from_millis(*backoff_ms)).await;
}

/// The tunnel's *current* MTU, shared between every task that needs to
/// size a packet.
///
/// Seeded at startup from `control::effective_tunnel_mtu` and then kept
/// current by `control::mtu_monitor_loop`, which resizes the live TUN
/// device whenever the detected physical link capacity changes. Every
/// consumer loads it fresh at the moment it sizes a packet rather than
/// caching it, so a live resize takes effect immediately instead of
/// leaving that task pinned to whatever the value happened to be when
/// the daemon started.
pub type LiveMtu = std::sync::Arc<std::sync::atomic::AtomicU16>;

pub struct TunnelParams {
    pub mode: Mode,
    /// The tunnel MTU as computed once at startup. This is only the
    /// *seed* for the shared `LiveMtu` built in `run`; nothing should
    /// read it after that point, because it does not track the live
    /// resizes `control::mtu_monitor_loop` performs.
    pub mtu: u16,
    /// Whether to rewrite the MSS option of TCP SYN/SYN-ACK segments
    /// read off the TUN device so they fit the *live* tunnel MTU (see
    /// `LiveMtu`, not the `mtu` field above). See `mss.rs`.
    pub clamp_mss: bool,
    pub scheduler_cfg: SchedulerConfig,
    /// Used to label snapshots served over the control socket and to
    /// compute its default path (`/run/mlvpn/<tunnel_name>.sock`).
    pub tunnel_name: String,
    /// `None` disables the monitoring control socket entirely.
    pub control_socket: Option<PathBuf>,
    /// `None` disables the runtime command socket entirely (the default
    /// -- see `config::CommandConfig::enabled`'s doc comment for why
    /// this one, unlike `control_socket`, is opt-in).
    pub command_socket: Option<PathBuf>,
    /// `None` (the default) disables the automatic loss-threshold
    /// diagnostic-dump watcher entirely -- see
    /// `config::DiagnosticsConfig::auto_dump_enabled`'s doc comment.
    pub diagnostics_watch: Option<DiagnosticsWatchParams>,
    /// This tunnel's own local IP (parsed from `tunnel.address`, the
    /// same string `main.rs::open_tun` already parses to build the TUN
    /// device) -- used only to bind the tunnel-level throughput
    /// self-test's persistent listener (`tunneltest::run_listener`) to
    /// the TUN device's own address rather than every interface. See
    /// `tunneltest.rs`'s module doc comment.
    pub tunnel_local_addr: std::net::IpAddr,
    /// The tunnel-specific config, threaded through only for
    /// `control::mtu_monitor_loop`'s periodic recomputation -- every
    /// other tunnel-level field on this struct is already flattened
    /// from it for direct use elsewhere in `tunnel::run`.
    pub tunnel_cfg: config::TunnelConfig,
    /// Every configured link's `bind_interface` name, for
    /// `control::mtu_monitor_loop` to re-query physical MTUs from
    /// directly -- see that function's doc comment for why it can't
    /// use `Link.physical_mtu` instead.
    pub bind_interfaces: Vec<String>,
    /// The one thread allowed to issue `SIOCSIFMTU`, handed to
    /// `control::mtu_monitor_loop` in place of it calling
    /// `link::set_interface_mtu` itself. Created in `main` immediately
    /// after the privilege drop, because Linux capabilities are
    /// per-thread and no tokio worker (all spawned pre-drop) holds
    /// `CAP_NET_ADMIN` -- see `link::MtuResizer`'s doc comment.
    pub mtu_resizer: crate::link::MtuResizer,
}

/// Config for `control::diagnostics_watch_loop`, threaded from
/// `config::DiagnosticsConfig` -- see that type's doc comment for what
/// each field means and why the feature exists.
#[derive(Clone)]
pub struct DiagnosticsWatchParams {
    pub degraded_open_pct: f64,
    pub degraded_open_misses: usize,
    pub degraded_close_pct: f64,
    pub cooldown: Duration,
    pub window: Duration,
    pub min_probes: usize,
    pub clear: Duration,
    pub outage: Duration,
    pub warmup: Duration,
    pub degraded_ticket_gap: Duration,
    pub flap_downs: u32,
    pub max_dump_files: usize,
    pub dump_dir: PathBuf,
    pub auto_submit: bool,
}

/// Global, tunnel-lifetime monotonic sequence counter used to tag every
/// outgoing frame's `Header.seq` field, independent of any per-link
/// WireGuard session -- see this module's doc comment. Previously this
/// counter lived on the old shared `crypto::Session`
/// (`Session::next_send_seq`); now that encryption is per-link
/// (`wireguard::WgTunnel`), there is no longer a single shared session
/// to own it, so it lives here as a plain, process-wide atomic instead.
/// Safe as a `static` (rather than a field threaded through every
/// function that sends a frame) because exactly one `run()` invocation
/// is ever active in a given `mlvpnd` process.
static SEND_SEQ: AtomicU64 = AtomicU64::new(0);

/// Allocate the next `Header.seq` value for an outgoing frame. See
/// `SEND_SEQ`'s doc comment.
fn next_send_seq() -> u64 {
    SEND_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Correlates an in-flight `ipc::Command::RunThroughputTest` with its
/// eventual result. A result can arrive by either of two paths, both
/// delivered through this same registry (see `handle_incoming`'s
/// `ThroughputTestData`/`ThroughputTestResult` arms):
///
/// - A remote `ThroughputTestResult` frame: the peer measured a stream
///   *we* sent them (the forward/upload leg).
/// - A local measurement: we just finished receiving a stream the peer
///   sent back to us after we asked them to (`ThroughputTestReverseRequest`
///   -- the reverse/download leg of a bidirectional test). There's
///   nothing to send *over the wire* for this case; the result is ready
///   the instant `handle_incoming` finishes computing it.
///
/// Keyed by `test_id`, not single-slot: originally only
/// `control::apply_command` ever awaited a throughput test (its own
/// legs, and every targeted link's own test if more than one, strictly
/// sequentially -- so a single-slot registry was correct then). Now
/// `active_bandwidth_prober` also registers waits here, one independent
/// task per link, on its own periodic timer -- entirely possible for
/// two links' probes (or a probe and a manually-triggered
/// `mlvpnd self-test`) to be in flight at the same moment, which a
/// single-slot registry would silently break (a second registration
/// would overwrite the first's slot, permanently orphaning its result).
pub(crate) struct ThroughputTestContext {
    waiters: std::sync::Mutex<std::collections::HashMap<u32, mpsc::UnboundedSender<f64>>>,
}

impl ThroughputTestContext {
    pub(crate) fn new() -> Self {
        Self {
            waiters: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Registers interest in a result for `test_id`, returning the
    /// receiving half. Called once per leg (or per probe), before that
    /// leg's stream (or reverse-request) goes out, so there's somewhere
    /// to route the eventual result from the moment it could possibly
    /// arrive. Opportunistically prunes any previously-registered entry
    /// whose receiver has already been dropped (a caller that gave up
    /// waiting, e.g. via a `tokio::time::timeout`, without ever getting a
    /// result) -- otherwise a `test_id` whose result genuinely never
    /// arrives would leak its entry in the map forever.
    pub(crate) fn register_wait(&self, test_id: u32) -> mpsc::UnboundedReceiver<f64> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut waiters = self.waiters.lock().unwrap();
        waiters.retain(|_, tx| !tx.is_closed());
        waiters.insert(test_id, tx);
        rx
    }

    /// Forwards `achieved_mbps` to the waiter registered for `test_id`,
    /// if any -- removed on delivery, since a `test_id` is only ever
    /// used once. Anything with no matching registration (a stray late
    /// result from a leg that already timed out and gave up, or plain
    /// noise) is silently ignored.
    fn forward_result(&self, test_id: u32, achieved_mbps: f64) {
        if let Some(tx) = self.waiters.lock().unwrap().remove(&test_id) {
            let _ = tx.send(achieved_mbps);
        }
    }
}

/// Tunnel-wide storage for the peer's most recently received `mlvpnd`
/// version (`PacketType::VersionInfo`) -- see that variant's doc
/// comment. A bare `Option<String>` behind a `std::sync::Mutex`
/// (touched only on receipt, at the same slow cadence as `StatsShare`)
/// rather than anything per-link: unlike link stats, the daemon's own
/// version isn't a per-link property, so there's exactly one value to
/// track regardless of how many links are configured.
pub(crate) type PeerVersion = Arc<std::sync::Mutex<Option<String>>>;

/// Tunnel-wide storage for the peer's most recently received live tunnel
/// MTU, piggybacked on the same `PacketType::VersionInfo` exchange as
/// `PeerVersion` above -- same shape, same reasoning: `None` until the
/// first `VersionInfo` arrives, `std::sync::Mutex` since it's touched
/// only on receipt at that same slow cadence.
pub(crate) type PeerMtu = Arc<std::sync::Mutex<Option<u16>>>;

/// Tunnel-wide storage for the peer's most recently reported *applied*
/// live tunnel MTU (`VersionInfoPayload::live_tunnel_mtu`) -- same
/// shape/reasoning as `PeerMtu` above, but this is the peer's own
/// already-negotiated value (what's really on their TUN device right
/// now), not their pre-negotiation capability. Lets a receiver confirm
/// real convergence (this side's own `live_mtu` should equal this,
/// once both sides have exchanged at least one `VersionInfo` post-
/// negotiation) separately from `PeerMtu`, which will legitimately
/// differ from `live_mtu` whenever the peer's link happens to support
/// more headroom than this side's own -- see `mlvpn-tui`'s Session
/// panel, which is what first surfaced the need for this distinction
/// (a real asymmetric-but-healthy pairing on home-bgp/cloud-bgp showed
/// as a false "MISMATCH" before this field existed to tell the two
/// cases apart).
pub(crate) type PeerLiveMtu = Arc<std::sync::Mutex<Option<u16>>>;

/// Tunnel-wide storage for the peer's most recently advertised primary
/// link, piggybacked on the same `PacketType::VersionInfo` exchange as
/// `PeerVersion`/`PeerMtu` above. Holds the peer's advertised primary
/// link's *name* (`LinkConfig::name`) -- deliberately NOT a wire
/// `link_id`/local `Links`-array index. `link_id` is assigned per-host
/// from each host's own `[[link]]` config order (see `main.rs`), so it
/// is not a namespace shared between peers: two hosts can easily
/// configure their links in a different order, in which case indexing
/// this host's own `Links` array by the peer's numeric id would
/// silently resolve to the wrong physical link. Resolving this to a
/// local link always means matching `Link.config.name` against the
/// stored name here -- never indexing directly.
///
/// `None` when the peer hasn't advertised a primary at all (either it
/// isn't running `scheduler.primary_link_mode`, or it is but hasn't
/// picked one yet). Each link's own WireGuard session now rekeys
/// entirely internally (`boringtun`), invisibly to this module, so
/// there is no longer an app-level "session changed" event to reset
/// this on -- it simply reflects whatever the peer's most recent
/// `VersionInfo` said.
///
/// Consumed by `Scheduler::refresh` when this host has
/// `scheduler.follow_peer_primary` set -- see that config field's doc
/// comment.
pub(crate) type PeerPrimaryLink = Arc<std::sync::Mutex<Option<String>>>;

/// Resolves `peer_primary_link`'s advertised link name to a LOCAL
/// `Links`-array index by matching `Link.config.name`, for
/// `Scheduler::refresh`'s `peer_primary_index` argument. Returns `None`
/// when the peer hasn't advertised a primary, or advertised a name that
/// doesn't match any link configured on this host -- both cases already
/// fall back to ordinary SWRR selection in
/// `Scheduler::refresh_from_scores`.
fn resolve_peer_primary_index(snap: &[Link], peer_primary_link: &PeerPrimaryLink) -> Option<usize> {
    let name = peer_primary_link.lock().unwrap().clone()?;
    snap.iter().position(|l| l.config.name == name)
}

/// How long startup waits for a dual-stack link's address-family race.
const ALTERNATE_RACE_DEADLINE: Duration = Duration::from_secs(10);

pub async fn run(
    tun: AsyncDevice,
    links: Vec<Link>,
    params: TunnelParams,
    log_ring: Arc<crate::logbuf::LogRing>,
) -> Result<()> {
    let tun = Arc::new(tun);
    let links: Links = Arc::new(links.into_iter().map(AsyncMutex::new).collect());
    {
        let races: Vec<_> = (0..links.len())
            .map(|idx| {
                let links = links.clone();
                tokio::spawn(async move {
                    links[idx]
                        .lock()
                        .await
                        .resolve_alternate(ALTERNATE_RACE_DEADLINE)
                        .await;
                })
            })
            .collect();
        for race in races {
            let _ = race.await;
        }
    }
    let scheduler = Arc::new(std::sync::Mutex::new(Scheduler::new()));
    // Wrapped once, here, so every task below can cheaply clone a handle
    // to the full params instead of each needing its own hand-picked
    // subset of fields threaded through as separate arguments.
    let params = Arc::new(params);

    // No app-level handshake to wait for here anymore -- see the module
    // doc comment: each link independently drives its own WireGuard
    // handshake (via `wg_send`/`wg_recv`/`wg_tick`, all in `link.rs`)
    // once its tasks are spawned below, lazily, the same way real
    // WireGuard does. `run()` never blocks tunnel startup on any of them
    // completing.
    tracing::info!("tunnel starting; each link will handshake independently");

    let (rx_pipeline_tx_chan, rx_pipeline_rx) = mpsc::channel::<RxEvent>(RX_PIPELINE_CAPACITY);
    let rx_pipeline_dropped = Arc::new(AtomicU64::new(0));
    let rx_stats = Arc::new(crate::telemetry::RxPipelineStats::default());
    let telemetry = Arc::new(crate::telemetry::Telemetry::new(rx_stats.clone()));
    let rx_pipeline_tx = RxPipelineTx {
        tx: rx_pipeline_tx_chan,
        dropped: rx_pipeline_dropped.clone(),
    };

    // Shared across both links (a FEC group's members can arrive on
    // either physical link), same reasoning as `reorder` above. Its own
    // retention is deliberately NOT derived from `reorder_window_ms`:
    // see `fec::PAYLOAD_TTL`'s doc comment for why those are unrelated
    // timescales. Built unconditionally (it is empty and never touched
    // when FEC is disabled) so nothing downstream needs an Option.
    let fec_recovery = fec::FecRecoveryBuffer::new(
        params.scheduler_cfg.fec_group_size,
        params.scheduler_cfg.fec_parity,
    );
    let fec_recovered_total = Arc::new(AtomicU64::new(0));
    let fec_unrecoverable_total = Arc::new(AtomicU64::new(0));
    let fec_send_stats = Arc::new(crate::fec::FecSendStats::default());

    // One ProbeTracker per link, shared between that link's receiver and
    // prober tasks: the prober records when a probe was sent
    // (`record_sent`) and the receiver records when its reply comes back
    // (`record_reply`) -- both need to see the same outstanding-probes
    // table for RTT to ever be computed at all, which is why this is
    // built once here and handed to *both* tasks below rather than each
    // task getting its own independent tracker.
    let trackers: Vec<Arc<AsyncMutex<ProbeTracker>>> = {
        let snap = link::snapshot_links(&links).await;
        snap.iter()
            .map(|l| {
                // The tracker's timeout is built once, for the whole
                // session, but `probe_interval_ms` itself can grow at
                // runtime if `auto_tune_probe_interval` is on (see
                // `link_prober`/`suggest_probe_interval_ms`) -- so this
                // has to be generous enough to cover the *ceiling* that
                // interval could ever back off to, not just its
                // starting value, or a probe sent at a backed-off
                // cadence would spuriously time out well before the
                // next one even fires.
                let longest_possible_interval_ms = if params.scheduler_cfg.auto_tune_probe_interval
                {
                    l.config
                        .probe_interval_ms
                        .max(params.scheduler_cfg.probe_interval_max_ms)
                } else {
                    l.config.probe_interval_ms
                };
                let timeout_ms = longest_possible_interval_ms.saturating_mul(4).max(500);
                Arc::new(AsyncMutex::new(ProbeTracker::new(Duration::from_millis(
                    timeout_ms,
                ))))
            })
            .collect()
    };

    // Most recent StatsShare received from the peer, per local link index.
    // Written by `handle_incoming` (in every `link_receiver` task), read
    // by `control::serve` when it builds a snapshot for a connected
    // monitoring client.
    let peer_stats = Arc::new(PeerStatsTable::new());

    // The peer's own last-reported `mlvpnd` version -- see
    // `PeerVersion`'s doc comment.
    let peer_version: PeerVersion = Arc::new(std::sync::Mutex::new(None));

    // The peer's own last-reported live tunnel MTU -- see `PeerMtu`'s
    // doc comment.
    let peer_mtu: PeerMtu = Arc::new(std::sync::Mutex::new(None));

    // The peer's own last-reported *applied* live tunnel MTU -- see
    // `PeerLiveMtu`'s doc comment.
    let peer_live_mtu: PeerLiveMtu = Arc::new(std::sync::Mutex::new(None));

    // The peer's own last-advertised primary link -- see
    // `PeerPrimaryLink`'s doc comment.
    let peer_primary_link: PeerPrimaryLink = Arc::new(std::sync::Mutex::new(None));

    // One per link, tracking a possibly-in-progress incoming
    // `ThroughputTestData` stream -- see `ThroughputTestReceiveState`'s
    // doc comment. `throughput_test_ctx` is the shared registry both
    // `control::serve_commands`'s `Command::RunThroughputTest` handler
    // and `active_bandwidth_prober` (below) wait on for a result, from
    // either direction -- see `ThroughputTestContext`'s doc comment.
    let throughput_test_states: Vec<Arc<AsyncMutex<ThroughputTestReceiveState>>> = (0..trackers
        .len())
        .map(|_| Arc::new(AsyncMutex::new(ThroughputTestReceiveState::new())))
        .collect();
    let throughput_test_ctx = Arc::new(ThroughputTestContext::new());

    // Shared between `control::serve_commands`'s
    // `Command::RunTunnelThroughputTest` handler (which registers a
    // wait before sending the upload leg) and
    // `tunneltest::run_listener` (which delivers a result into it when
    // an incoming stream turns out to be this daemon's own reverse leg
    // completing, rather than someone else testing it fresh) -- see
    // `tunneltest::TunnelTestContext`'s doc comment.
    let tunnel_test_ctx = Arc::new(crate::tunneltest::TunnelTestContext::new());

    let mut handles = Vec::new();

    // Shared live tunnel MTU: seeded with the startup-time
    // `effective_tunnel_mtu` result, kept current afterward by
    // `control::mtu_monitor_loop` and read fresh on every packet by
    // `tun_reader`'s MSS-clamping.
    let live_mtu: LiveMtu = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(params.mtu));

    // This side's own live LOCAL LINK CAPABILITY -- what effective_tunnel_mtu
    // computes from this side's currently-selected primary link (or bonded
    // min), BEFORE the peer's advertised value is folded in via
    // negotiate_tunnel_mtu. Advertised to the peer via VersionInfo in place
    // of live_mtu itself, so peer negotiation cannot create a monotonic
    // ratchet -- see docs/superpowers/specs/2026-09-16-primary-aware-peer-mtu-design.md
    // §2 and the final-review finding that motivated this. live_mtu (above)
    // remains "what the TUN device is actually set to right now"; this is
    // "what this side could support if the peer had no lower value at all."
    let local_capability_mtu: LiveMtu =
        std::sync::Arc::new(std::sync::atomic::AtomicU16::new(params.mtu));

    // Bounded outbound queue between tun_reader (producer) and
    // outbound_sender (consumer) -- see OUTBOUND_QUEUE_CAPACITY's doc
    // comment. Built here, ahead of the control-socket spawn below, so
    // control::serve can be handed a clone of outbound_tx (to read
    // .capacity()/.max_capacity()) and outbound_dropped_total.
    let (outbound_tx, outbound_rx) = mpsc::channel::<OutboundFrame>(OUTBOUND_QUEUE_CAPACITY);
    let outbound_dropped_total = Arc::new(AtomicU64::new(0));

    for (idx, (tracker, throughput_test_state)) in trackers
        .iter()
        .zip(throughput_test_states.iter())
        .enumerate()
    {
        let tracker = tracker.clone();
        {
            let links = links.clone();
            let scheduler = scheduler.clone();
            let rx_pipeline_tx = rx_pipeline_tx.clone();
            let cfg = params.scheduler_cfg.clone();
            let tracker = tracker.clone();
            let peer_stats = peer_stats.clone();
            let mtu = live_mtu.clone();
            let throughput_test_state = throughput_test_state.clone();
            let throughput_test_ctx = throughput_test_ctx.clone();
            let peer_version = peer_version.clone();
            let peer_mtu = peer_mtu.clone();
            let peer_live_mtu = peer_live_mtu.clone();
            let peer_primary_link = peer_primary_link.clone();
            handles.push(tokio::spawn(async move {
                // link_receiver never returns under normal operation --
                // see its doc comment: socket errors are retried/
                // reconnected in place rather than propagated. This
                // task only ends via panic (a bug) or the process
                // exiting.
                link_receiver(
                    idx,
                    links,
                    scheduler,
                    rx_pipeline_tx,
                    cfg,
                    tracker,
                    peer_stats,
                    mtu,
                    throughput_test_state,
                    throughput_test_ctx,
                    peer_version,
                    peer_mtu,
                    peer_live_mtu,
                    peer_primary_link,
                )
                .await;
            }));
        }
        {
            let links = links.clone();
            let scheduler = scheduler.clone();
            let cfg = params.scheduler_cfg.clone();
            let local_capability_mtu = local_capability_mtu.clone();
            let live_mtu = live_mtu.clone();
            let peer_primary_link = peer_primary_link.clone();
            handles.push(tokio::spawn(async move {
                link_prober(
                    idx,
                    links,
                    scheduler,
                    cfg,
                    local_capability_mtu,
                    live_mtu,
                    tracker,
                    peer_primary_link,
                )
                .await;
            }));
        }
        {
            let links = links.clone();
            let cfg = params.scheduler_cfg.clone();
            let mtu = live_mtu.clone();
            let throughput_test_ctx = throughput_test_ctx.clone();
            handles.push(tokio::spawn(async move {
                // No-op and returns immediately unless
                // active_bandwidth_probing is on -- see the function's
                // own doc comment, same "spawn unconditionally, check
                // inside" pattern as reorder_tuning_loop below.
                active_bandwidth_prober(idx, links, cfg, mtu, throughput_test_ctx).await;
            }));
        }
    }

    {
        let inputs = crate::telemetry::WatchInputs {
            links: links.clone(),
            scheduler: scheduler.clone(),
            tunnel_name: params.tunnel_name.clone(),
            outbound_dropped_total: outbound_dropped_total.clone(),
            fec_recovered_total: fec_recovered_total.clone(),
            fec_unrecoverable_total: fec_unrecoverable_total.clone(),
            mtu: live_mtu.clone(),
            cfg: crate::telemetry::StaticConfig::from_scheduler(&params.scheduler_cfg),
        };
        let telemetry = telemetry.clone();
        handles.push(tokio::spawn(async move {
            crate::telemetry::run(telemetry, inputs).await;
        }));
    }

    if let Some(path) = params.control_socket.clone() {
        let links = links.clone();
        let peer_stats = peer_stats.clone();
        let tunnel_name = params.tunnel_name.clone();
        let mode = params.mode.as_str().to_string();
        let outbound_tx = outbound_tx.clone();
        let outbound_dropped_total = outbound_dropped_total.clone();
        let log_ring = log_ring.clone();
        let peer_version = peer_version.clone();
        let peer_mtu = peer_mtu.clone();
        let peer_live_mtu = peer_live_mtu.clone();
        let mtu = live_mtu.clone();
        let scheduler = scheduler.clone();
        let fec_recovered_total = fec_recovered_total.clone();
        let fec_unrecoverable_total = fec_unrecoverable_total.clone();
        let fec_send_stats = fec_send_stats.clone();
        let telemetry = telemetry.clone();
        handles.push(tokio::spawn(async move {
            control::serve(
                path,
                links,
                peer_stats,
                tunnel_name,
                mode,
                outbound_tx,
                outbound_dropped_total,
                log_ring,
                peer_version,
                mtu,
                peer_mtu,
                peer_live_mtu,
                scheduler,
                fec_recovered_total,
                fec_unrecoverable_total,
                fec_send_stats,
                telemetry,
            )
            .await;
        }));
    }

    if let Some(path) = params.command_socket.clone() {
        let links = links.clone();
        let throughput_test_ctx = throughput_test_ctx.clone();
        let tunnel_test_ctx_for_commands = tunnel_test_ctx.clone();
        let mtu = live_mtu.clone();
        let diag_ctx = control::DiagContext {
            peer_stats: peer_stats.clone(),
            tunnel_name: params.tunnel_name.clone(),
            mode: params.mode.as_str().to_string(),
            outbound_tx: outbound_tx.clone(),
            outbound_dropped_total: outbound_dropped_total.clone(),
            log_ring: log_ring.clone(),
            peer_version: peer_version.clone(),
            mtu: live_mtu.clone(),
            peer_mtu: peer_mtu.clone(),
            peer_live_mtu: peer_live_mtu.clone(),
            scheduler: scheduler.clone(),
            fec_recovered_total: fec_recovered_total.clone(),
            fec_unrecoverable_total: fec_unrecoverable_total.clone(),
            fec_send_stats: fec_send_stats.clone(),
            telemetry: telemetry.clone(),
        };
        handles.push(tokio::spawn(async move {
            // NOTE(task 5): same `SessionMeta`/`session` removal as
            // above -- `control::DiagContext.session_meta` and
            // `control::serve_commands`'s `session` parameter are both
            // stale now; left for Task 6.
            control::serve_commands(
                path,
                links,
                throughput_test_ctx,
                tunnel_test_ctx_for_commands,
                mtu,
                diag_ctx,
            )
            .await;
        }));
    }

    // The tunnel-level self-test's persistent listener -- see
    // `tunneltest.rs`'s module doc comment. Deliberately *not* gated on
    // `[command] enabled`: matching the existing per-link self-test's
    // own precedent, any daemon can be the *target* of a test regardless
    // of its own command-socket config (`handle_incoming` already
    // processes an incoming `ThroughputTestData` stream unconditionally)
    // -- only the *initiating* side needs `[command] enabled`, to accept
    // the CLI's command-socket connection in the first place. Requiring
    // it here too would mean a server that never intends to run its own
    // self-test commands still couldn't be *tested by* a client that
    // does.
    {
        let tunnel_local_addr = params.tunnel_local_addr;
        let outbound_dropped_total = outbound_dropped_total.clone();
        let tunnel_test_ctx = tunnel_test_ctx.clone();
        let mtu = live_mtu.clone();
        handles.push(tokio::spawn(async move {
            crate::tunneltest::run_listener(
                tunnel_local_addr,
                outbound_dropped_total,
                tunnel_test_ctx,
                mtu,
            )
            .await;
        }));
    }

    // The TCP counterpart to the UDP listener spawned just above -- see
    // `tunneltest::run_tcp_listener`'s own doc comment. Same
    // not-gated-on-`[command] enabled` reasoning applies here too.
    {
        let tunnel_local_addr = params.tunnel_local_addr;
        let tunnel_test_ctx = tunnel_test_ctx.clone();
        handles.push(tokio::spawn(async move {
            crate::tunneltest::run_tcp_listener(tunnel_local_addr, tunnel_test_ctx).await;
        }));
    }

    if let Some(watch) = params.diagnostics_watch.clone() {
        let links = links.clone();
        let diag_ctx = control::DiagContext {
            peer_stats: peer_stats.clone(),
            tunnel_name: params.tunnel_name.clone(),
            mode: params.mode.as_str().to_string(),
            outbound_tx: outbound_tx.clone(),
            outbound_dropped_total: outbound_dropped_total.clone(),
            log_ring: log_ring.clone(),
            peer_version: peer_version.clone(),
            mtu: live_mtu.clone(),
            peer_mtu: peer_mtu.clone(),
            peer_live_mtu: peer_live_mtu.clone(),
            scheduler: scheduler.clone(),
            fec_recovered_total: fec_recovered_total.clone(),
            fec_unrecoverable_total: fec_unrecoverable_total.clone(),
            fec_send_stats: fec_send_stats.clone(),
            telemetry: telemetry.clone(),
        };
        handles.push(tokio::spawn(async move {
            control::diagnostics_watch_loop(watch, links, diag_ctx).await;
        }));
    }

    {
        let tunnel_cfg = params.tunnel_cfg.clone();
        let tun_ifname = params.tunnel_name.clone();
        let bind_interfaces = params.bind_interfaces.clone();
        let live_mtu = live_mtu.clone();
        let local_capability_mtu = local_capability_mtu.clone();
        let mtu_resizer = params.mtu_resizer.clone();
        let fec_reservation = fec::mtu_reservation_bytes(&params.scheduler_cfg);
        let scheduler = scheduler.clone();
        let peer_mtu = peer_mtu.clone();
        handles.push(tokio::spawn(async move {
            control::mtu_monitor_loop(
                tunnel_cfg,
                tun_ifname,
                bind_interfaces,
                live_mtu,
                local_capability_mtu,
                mtu_resizer,
                fec_reservation,
                scheduler,
                peer_mtu,
            )
            .await;
        }));
    }

    {
        let redundant_mode = params.scheduler_cfg.redundant_mode;
        let fec_enabled = params.scheduler_cfg.fec_enabled;

        // Per-link TX workers: every frame -- Data, FEC parity, redundant
        // copies -- reaches the wire through them, so no mode (FEC
        // included) can bring back head-of-line blocking on a stalled
        // socket.
        let dispatcher = {
            let mut senders = Vec::with_capacity(links.len());
            let mut receivers = Vec::with_capacity(links.len());
            for l in links.iter() {
                let (tx, rx) = mpsc::channel::<TxJob>(LINK_TX_QUEUE_CAPACITY);
                senders.push(LinkTx {
                    tx,
                    counters: l.lock().await.stats.tx_counters.clone(),
                });
                receivers.push(rx);
            }
            let dispatcher = TxDispatcher {
                links: links.clone(),
                queues: Arc::new(senders),
                scheduler: scheduler.clone(),
                allow_spill: !(params.scheduler_cfg.primary_link_mode
                    || params.scheduler_cfg.follow_peer_primary),
                dropped_total: outbound_dropped_total.clone(),
            };
            for (idx, rx) in receivers.into_iter().enumerate() {
                let d = dispatcher.clone();
                handles.push(tokio::spawn(async move {
                    link_tx_worker(idx, rx, d).await;
                }));
            }
            let counters: Vec<Arc<link::TxCounters>> = dispatcher
                .queues
                .iter()
                .map(|q| q.counters.clone())
                .collect();
            let sched = scheduler.clone();
            let congestion_counters = counters.clone();
            handles.push(tokio::spawn(async move {
                congestion_loop(sched, congestion_counters).await;
            }));
            let sched = scheduler.clone();
            let delivery_links = links.clone();
            let delivery_peer_stats = peer_stats.clone();
            handles.push(tokio::spawn(async move {
                delivery_loop(sched, delivery_links, delivery_peer_stats, counters).await;
            }));
            dispatcher
        };

        let fec_group_size = params.scheduler_cfg.fec_group_size;
        let fec_parity = params.scheduler_cfg.fec_parity;
        let fec_placement = params.scheduler_cfg.fec_parity_placement;
        let live_mtu = live_mtu.clone();
        let fec_unrecoverable_total = fec_unrecoverable_total.clone();
        let fec_send_stats = fec_send_stats.clone();
        handles.push(tokio::spawn(async move {
            outbound_sender(
                outbound_rx,
                redundant_mode,
                fec_enabled,
                fec_group_size,
                fec_parity,
                fec_placement,
                live_mtu,
                fec_unrecoverable_total,
                fec_send_stats,
                dispatcher,
            )
            .await;
        }));
    }

    {
        let dropped_total = outbound_dropped_total.clone();
        handles.push(tokio::spawn(async move {
            outbound_queue_drop_reporter(dropped_total).await;
        }));
    }

    {
        let tun = tun.clone();
        let mtu = live_mtu.clone();
        let clamp_mss = params.clamp_mss;
        let tx = outbound_tx.clone();
        let dropped_total = outbound_dropped_total.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = tun_reader(tun, mtu, clamp_mss, tx, dropped_total).await {
                tracing::error!(error = %e, "tun reader exited");
            }
        }));
    }

    {
        let tun = tun.clone();
        let scheduler = scheduler.clone();
        let reorder_window_ms = params.scheduler_cfg.reorder_window_ms;
        let fec_enabled = params.scheduler_cfg.fec_enabled;
        let fec_recovered_total = fec_recovered_total.clone();
        let fec_unrecoverable_total = fec_unrecoverable_total.clone();
        handles.push(tokio::spawn(async move {
            rx_pipeline(
                rx_pipeline_rx,
                tun,
                scheduler,
                reorder_window_ms,
                fec_recovery,
                fec_enabled,
                fec_recovered_total,
                fec_unrecoverable_total,
                rx_pipeline_dropped,
                rx_stats,
            )
            .await;
        }));
    }

    {
        let links = links.clone();
        let rx_pipeline_tx = rx_pipeline_tx.clone();
        let cfg = params.scheduler_cfg.clone();
        let scheduler = scheduler.clone();
        handles.push(tokio::spawn(async move {
            reorder_tuning_loop(links, rx_pipeline_tx, cfg, scheduler).await;
        }));
    }

    // None of the tasks above normally return on their own (they're all
    // infinite loops or `select!` loops), so without this, `run()`
    // would never return short of the whole process being killed out
    // from under it. Only a local signal unblocks this anymore -- see
    // the module doc comment's "Graceful shutdown" section for why a
    // peer's own `Disconnect` no longer does (that used to race this
    // same select via a shared `Shutdown` signal, up through v0.4.5).
    let mut sigterm = signal(SignalKind::terminate()).map_err(MlvpnError::Io)?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }

    tracing::info!("shutting down: notifying peer");
    broadcast_disconnect(&links).await;

    for h in handles {
        h.abort();
    }

    Ok(())
}

/// Best-effort notification that this side is shutting down on
/// purpose, sent on every link with a learned/configured remote
/// address. "Best-effort": a send failure here just means the peer
/// falls back to noticing via the probe timeout it would have hit
/// anyway -- a clean shutdown should never block on this succeeding,
/// which is also why this doesn't retry.
async fn broadcast_disconnect(links: &Links) {
    let targets: Vec<(LinkHandle, u8)> = {
        let snap = link::snapshot_links(links).await;
        snap.iter()
            .filter(|link| link.remote.is_some())
            .map(|link| (link.handle(), link.id))
            .collect()
    };

    // Disconnect carries no payload -- it's the frame type itself that's
    // the whole signal.
    let seq = next_send_seq();

    for (handle, link_id) in targets {
        let mut frame = Vec::with_capacity(HEADER_LEN);
        Header {
            ptype: PacketType::Disconnect,
            link_id,
            seq,
        }
        .encode(&mut frame);
        let _ = handle.wg_send(&frame).await;
    }
}

/// Capacity of the bounded channel between `tun_reader` (producer: reads
/// the TUN device, clamps MSS, encrypts) and `outbound_sender` (consumer:
/// asks the `Scheduler` for a link and hands the frame to that link's TX
/// worker, or, in the FEC path, does the socket I/O inline).
///
/// Loosely modeled on the original C `MLVPN`'s `freebuffer_t`
/// (`src/buffer.c` upstream): a fixed-size pool of packet slots that
/// returns `NULL` once exhausted rather than growing or blocking, with
/// the caller logging and dropping the packet at that point instead of
/// silently stalling. This channel is the same idea reimplemented as a
/// bounded `tokio::sync::mpsc` channel instead of a hand-rolled free
/// list (Rust's ownership model already gives per-packet allocation
/// lifetime management for free, so there's no need to pool packet
/// objects the way the C version did) -- see `tun_reader`'s `try_send`
/// and `outbound_queue_drop_reporter` for the drop-and-log side of it.
///
/// This exists specifically because of a real, hard-to-diagnose bug: the
/// per-packet overhead the old inline send path used to have (cloning every
/// configured link's full `Link` just to pick one, see this module's
/// module doc comment) made the *combined* read-encrypt-select-send
/// pipeline unable to keep up with a high packet rate, and the resulting
/// drops happened silently in the *kernel's* TUN receive queue --
/// entirely invisible to `mlvpnd`, discoverable only by comparing
/// external `iperf3` throughput numbers against what the links should
/// support. Splitting the pipeline at this exact boundary means any
/// future regression that makes the send side too slow again shows up
/// immediately as a logged warning here instead of requiring that same
/// external-throughput detective work.
///
/// Deliberately bounded, not unbounded: an unbounded channel would just
/// relocate the "silently drops packets no one notices" failure mode
/// from the kernel's TUN queue into an ever-growing userspace `Vec`,
/// trading a *diagnosable* problem for an out-of-memory one. Sized to
/// absorb a brief stall (a scheduling hiccup, a momentarily slow
/// syscall) without dropping anything, while staying small enough that
/// a *sustained* backlog -- the send side genuinely unable to keep up --
/// overflows and gets logged within a fraction of a second rather than
/// being silently absorbed for minutes.
const OUTBOUND_QUEUE_CAPACITY: usize = 256;

/// How often `outbound_queue_drop_reporter` checks for and logs outbound
/// queue drops. A dedicated timer task rather than a `tokio::select!`
/// inside `outbound_sender`'s own receive loop, deliberately -- see this
/// module's doc comment on why `link_receiver`/`link_prober` are kept
/// as separate tasks instead of one task racing a receive branch against
/// a timer branch: under sustained high packet rate, a biased or even
/// fairly-randomized `select!` can keep preferring the always-ready
/// receive branch and starve the timer branch, which here would mean
/// drops happening under exactly the sustained-overload condition this
/// mechanism exists to surface, but the report itself never firing.
const OUTBOUND_QUEUE_DROP_REPORT_INTERVAL: Duration = Duration::from_secs(2);

/// One plaintext IP packet read off the TUN device, ready to hand to a
/// link's socket -- what `tun_reader` pushes onto the outbound queue and
/// `outbound_sender` pulls back off. Unlike the old shared-session
/// design, this is deliberately *not* pre-encrypted: encryption now
/// happens per-link (`wireguard::WgTunnel`, via `LinkHandle::wg_send`),
/// so which link's key material applies is only known once
/// the dispatcher has actually picked a link -- see
/// this module's doc comment.
pub(crate) struct OutboundFrame {
    plaintext: Vec<u8>,
}

async fn tun_reader(
    tun: Arc<AsyncDevice>,
    mtu: LiveMtu,
    clamp_mss: bool,
    tx: mpsc::Sender<OutboundFrame>,
    dropped_total: Arc<AtomicU64>,
) -> Result<()> {
    // Sized once at the theoretical maximum (`u16::MAX`, since `mtu` is
    // itself a `u16`) rather than from the startup MTU value: unlike a
    // per-link physical MTU, the live tunnel MTU is NOT monotonically
    // non-increasing after startup -- `effective_tunnel_mtu`'s own `None`
    // branch explicitly uses the full detected-safe value "including
    // upward" (that's the actual fix for the throughput regression this
    // whole feature exists for), and `mtu_monitor_loop` resizes upward
    // just as readily as downward, e.g. when a link reconnects on
    // different hardware with a higher physical MTU. A buffer sized from
    // the startup value would silently truncate (or panic via the
    // `buf[..n]` slice, if `tun.recv` ever reported `n` beyond the
    // buffer's length) any packet larger than that after a live upward
    // resize. One `u16::MAX`-sized allocation for this task's entire
    // lifetime is negligible cost -- not worth reallocating on every
    // resize just to save well under 64KB of memory.
    let mut buf = vec![0u8; u16::MAX as usize + 64];
    loop {
        let n = tun.recv(&mut buf).await.map_err(MlvpnError::Io)?;
        let mut plaintext = buf[..n].to_vec();

        // Only touches TCP SYN/SYN-ACK segments carrying an MSS option
        // larger than what `mtu` can carry -- see mss.rs for why this
        // matters more than relying on Path MTU Discovery alone, and for
        // the IPv4/IPv6 parsing and checksum recompute this performs.
        // Loaded fresh on every packet (rather than once outside the
        // loop) so a live resize from `mtu_monitor_loop` takes effect
        // immediately, not only after this task restarts.
        if clamp_mss {
            crate::mss::clamp_if_tcp_syn(
                &mut plaintext,
                mtu.load(std::sync::atomic::Ordering::Relaxed),
            );
        }

        // `try_send`, never `.send().await`: this loop's whole job is to
        // keep draining the kernel's TUN queue as fast as packets arrive
        // there, so blocking it on a full outbound queue would defeat
        // the point -- see `OUTBOUND_QUEUE_CAPACITY`'s doc comment. A
        // full queue means the send side is genuinely falling behind;
        // drop this packet and count it rather than stall reading the
        // next one, same drop-rather-than-block policy the original C
        // MLVPN's `freebuffer_t` used.
        if let Err(TrySendError::Full(_)) = tx.try_send(OutboundFrame { plaintext }) {
            dropped_total.fetch_add(1, Ordering::Relaxed);
        }
        // TrySendError::Closed would mean outbound_sender's receiver was
        // dropped -- only happens during shutdown, when this task is
        // about to be aborted anyway; nothing useful to do about it here.
    }
}

/// Capacity of each link's own bounded TX queue (`LinkTx`). Small on
/// purpose: it only has to absorb the burstiness between the dispatcher
/// and one link's socket, and every queued packet is latency a stalled
/// link adds before its backlog is noticed. A link whose queue fills is
/// by definition not keeping up, which is exactly the signal the
/// dispatcher acts on (penalize + spill) instead of letting that link's
/// slow `send_to` hold up every other link.
const LINK_TX_QUEUE_CAPACITY: usize = 128;

/// Most packets a link's TX worker pulls off its queue per wakeup (one
/// link lock to resolve the handle and one to record stats per batch,
/// instead of two per packet).
const TX_WORKER_BATCH: usize = 32;

/// One frame handed to a link's TX worker. `seq` is allocated by the
/// dispatcher (not the worker) so a packet rerouted to another link keeps
/// its sequence number, and redundant mode can send the *same* seq on
/// every link.
struct TxJob {
    /// `Data`, or a FEC parity share (`FecParity` / `FecParityQ`).
    ptype: PacketType,
    seq: u64,
    plaintext: Vec<u8>,
    /// Already redirected once after a send failure -- a second failure
    /// drops the packet rather than bouncing it between links forever.
    rerouted: bool,
    /// When this job was last handed to a link's queue (stamped by
    /// `try_enqueue` / `send_reserved`); the worker turns it into the
    /// link's queue delay.
    enqueued: Instant,
    /// Present on a Data frame that was folded into a FEC group: how the
    /// worker reports back whether the frame genuinely reached the wire.
    member: Option<FecMember>,
}

impl TxJob {
    fn new(ptype: PacketType, seq: u64, plaintext: Vec<u8>) -> Self {
        Self {
            ptype,
            seq,
            plaintext,
            rerouted: false,
            enqueued: Instant::now(),
            member: None,
        }
    }
}

/// Bounded hand-off from the TX workers back to the FEC owner
/// (`outbound_sender`) for groups whose members have all been resolved.
const FEC_READY_CAPACITY: usize = 256;

/// Gate on one open FEC group. The FEC owner folds a frame into the group
/// the moment a TX queue accepts it, but whether that frame actually
/// reaches the wire is only known later, on the link's worker: a frame
/// can be dropped after acceptance (send error and a failed reroute), or
/// substituted by a WireGuard handshake datagram (every handshake/rekey).
/// Such a frame is a *phantom member* -- one the receiver can never
/// observe. It permanently burns a share of the group's erasure budget,
/// and a group whose only missing member is a phantom would
/// "reconstruct" and inject a datagram that was never sent (seen live as
/// a fabricated IPv6 Router Solicitation).
///
/// So a group's parity is released only once every member is resolved,
/// and only if none was a phantom; a group with a phantom is skipped (the
/// real members still travel unprotected, counted in
/// `fec_unrecoverable_total`). Resolution is tracked with one counter:
/// the owner holds a "seal" token from the group's creation, each member
/// holds one, and whoever drops the last token releases the group --
/// usually the worker that sent the final member, so parity follows its
/// members onto the wire without the owner ever waiting on a socket.
struct FecGate {
    outstanding: AtomicU32,
    phantom: std::sync::atomic::AtomicBool,
    group: std::sync::Mutex<Option<fec::FecGroup>>,
    ready: mpsc::Sender<fec::FecGroup>,
    unrecoverable: Arc<AtomicU64>,
}

impl FecGate {
    fn new(ready: mpsc::Sender<fec::FecGroup>, unrecoverable: Arc<AtomicU64>) -> Arc<Self> {
        Arc::new(Self {
            outstanding: AtomicU32::new(1),
            phantom: std::sync::atomic::AtomicBool::new(false),
            group: std::sync::Mutex::new(None),
            ready,
            unrecoverable,
        })
    }

    /// Register one more member. Must be called before the member's job is
    /// queued (and before the group is sealed).
    fn join(self: &Arc<Self>) -> FecMember {
        self.outstanding.fetch_add(1, Ordering::Relaxed);
        FecMember {
            gate: self.clone(),
            carried: false,
        }
    }

    /// The group is complete: store its parity and drop the owner's seal
    /// token. If every member is already resolved this releases the parity
    /// immediately.
    fn seal(&self, group: fec::FecGroup) {
        *self.group.lock().unwrap() = Some(group);
        self.release();
    }

    fn release(&self) {
        if self.outstanding.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.emit();
        }
    }

    fn emit(&self) {
        let Some(group) = self.group.lock().unwrap().take() else {
            return;
        };
        if self.phantom.load(Ordering::Acquire) {
            self.unrecoverable.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                "skipping FEC parity for a group with a member that never reached the wire"
            );
            return;
        }
        if self.ready.try_send(group).is_err() {
            self.unrecoverable.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A FEC group member's claim on its gate. A member counts as having
/// reached the wire only if `mark_carried` was called before it dropped;
/// any other way of disappearing (dropped queue, failed reroute,
/// substituted by a handshake, shutdown) makes the group's parity unsafe.
struct FecMember {
    gate: Arc<FecGate>,
    carried: bool,
}

impl FecMember {
    fn mark_carried(&mut self) {
        self.carried = true;
    }
}

impl Drop for FecMember {
    fn drop(&mut self) {
        if !self.carried {
            self.gate.phantom.store(true, Ordering::Release);
        }
        self.gate.release();
    }
}

/// Enqueue `job` on `q` with the depth / enqueue-time accounting the
/// congestion tracker relies on. `depth` is raised *before* the attempt so
/// the worker's decrement can never underflow it, and undone on failure.
fn try_enqueue(q: &LinkTx, mut job: TxJob) -> std::result::Result<(), TrySendError<TxJob>> {
    job.enqueued = Instant::now();
    q.counters.depth.fetch_add(1, Ordering::Relaxed);
    q.tx.try_send(job).inspect_err(|_| {
        q.counters.depth.fetch_sub(1, Ordering::Relaxed);
    })
}

/// How often the scheduler re-reads every link's TX counters to update
/// congestion factors. Short enough to catch a stalling link within a few
/// RTTs, long enough that each window holds many worker-batch samples.
const CONGESTION_TICK: Duration = Duration::from_millis(100);

async fn congestion_loop(
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    counters: Vec<Arc<link::TxCounters>>,
) {
    let mut tick = tokio::time::interval(CONGESTION_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        scheduler.lock().unwrap().update_congestion(&counters);
    }
}

/// How often the scheduler looks for fresh peer stats to judge each link's
/// delivery by. The peer reports once a second, so most ticks find nothing
/// new; this only bounds how late a fresh report is noticed.
const DELIVERY_TICK: Duration = Duration::from_millis(250);

/// Compare what we offer each link with what the peer reports receiving on
/// it (`delivery.rs`). Both sides are byte-counter deltas between two
/// consecutive peer reports, not throughput EWMAs: the EWMAs lag and sit on
/// unaligned windows, which made a healthy ramping link look lossy.
async fn delivery_loop(
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    links: Links,
    peer_stats: Arc<PeerStatsTable>,
    counters: Vec<Arc<link::TxCounters>>,
) {
    let mut tick = tokio::time::interval(DELIVERY_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut samples: Vec<Option<DeliverySample>> = Vec::with_capacity(links.len());
    let mut windows: Vec<delivery::ReportWindow> =
        (0..links.len()).map(|_| Default::default()).collect();
    loop {
        tick.tick().await;
        samples.clear();
        for (idx, l) in links.iter().enumerate() {
            let (idle, up) = {
                let g = l.lock().await;
                (
                    g.stats.last_tx_throughput_sample.elapsed() > delivery::IDLE_AFTER,
                    g.state == LinkState::Up,
                )
            };
            let peer = peer_stats
                .get(idx as u8)
                .filter(|p| up && !idle && LinkState::from_wire(p.state) == LinkState::Up);
            let sample = match peer.and_then(|p| p.rx_bytes.map(|rx| (p, rx))) {
                Some((p, rx)) => windows[idx].observe(delivery::Report {
                    stamp: p.received_at,
                    peer_rx_bytes: rx,
                    local_tx_bytes: p.local_tx_bytes,
                }),
                None => {
                    windows[idx].reset();
                    None
                }
            };
            samples.push(sample);
        }
        scheduler
            .lock()
            .unwrap()
            .update_delivery(Instant::now(), &samples, &counters);
    }
}

/// A link's TX queue sender plus its lock-free health counters.
struct LinkTx {
    tx: mpsc::Sender<TxJob>,
    counters: Arc<link::TxCounters>,
}

/// Links in `Links` order: `TxQueues[i]` feeds link `i`'s worker.
type TxQueues = Arc<Vec<LinkTx>>;

const SPILL_MIN_DELIVERY_PPM: u32 = 500_000;

/// Links to try, best first, when a packet cannot go to `from`: every
/// other link with free queue room, most free slots first (ties broken by
/// index for determinism). Pure so the spill policy is unit-testable
/// without sockets; link *usability* (Up, enabled, has a remote) is
/// checked separately by the caller because it needs the link locks.
/// A link whose delivery feedback has collapsed (`delivery_ppm` below
/// `SPILL_MIN_DELIVERY_PPM`) is never a spill target: the peer is not
/// receiving what it is sent, so spilling onto it just feeds the policer.
fn spill_candidates(free: &[usize], delivery_ppm: &[u32], from: usize) -> Vec<usize> {
    let mut c: Vec<usize> = (0..free.len())
        .filter(|&i| {
            i != from
                && free[i] > 0
                && delivery_ppm.get(i).copied().unwrap_or(1_000_000) >= SPILL_MIN_DELIVERY_PPM
        })
        .collect();
    c.sort_by(|&a, &b| free[b].cmp(&free[a]).then(a.cmp(&b)));
    c
}

/// Choose the link for one frame: `Scheduler::select_fast` first (zero
/// link locking), falling back to a full `link::snapshot_scores` scan
/// only when nothing is cached yet. See `select_fast`'s doc comment: the
/// unconditional scan used to be the dominant cost in the send path.
async fn pick_link(
    links: &Links,
    scheduler: &Arc<std::sync::Mutex<Scheduler>>,
    frame_len: usize,
) -> Option<usize> {
    let fast = scheduler
        .lock()
        .unwrap()
        .select_fast(links.len(), frame_len);
    match fast {
        Some(idx) => Some(idx),
        None => {
            let scores = link::snapshot_scores(links).await;
            let mut sched = scheduler.lock().unwrap();
            sched.select(&scores, frame_len)
        }
    }
}

/// Hands Data frames to per-link TX workers without ever blocking: the
/// failure-isolation half of the send path. A link whose socket send is
/// stalled only backs up *its own* bounded queue; the dispatcher
/// (`outbound_sender`) keeps running because it only ever `try_send`s.
#[derive(Clone)]
struct TxDispatcher {
    links: Links,
    queues: TxQueues,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    /// Whether a packet that finds its chosen link's queue full may be
    /// redirected to another link. False under `primary_link_mode` /
    /// `follow_peer_primary`: those modes mean "use this link and nothing
    /// else", and a transient burst on the primary must not leak traffic
    /// onto a (possibly metered) backup -- the packet is dropped and
    /// counted instead, same as an overflowing outbound queue.
    allow_spill: bool,
    dropped_total: Arc<AtomicU64>,
}

impl TxDispatcher {
    fn drop_job(&self) {
        self.dropped_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Reserve a slot on the queue of the link this frame should use,
    /// without blocking: `forced` pins the choice when that link is Up,
    /// enabled and has a remote (FEC parity placement), otherwise the
    /// scheduler picks. A full queue spills to the freest other link
    /// (unless `allow_spill` is off, which drops instead).
    ///
    /// Returns the accepting link's index and a permit that makes the
    /// matching `send_reserved` infallible. Because the link is known
    /// *before* the frame is handed over, the FEC owner can fold the
    /// frame into its group (needing the plaintext and the carrying
    /// link) and only then queue it.
    async fn reserve(
        &self,
        forced: Option<usize>,
        frame_len: usize,
    ) -> Option<(usize, mpsc::Permit<'_, TxJob>)> {
        let mut chosen = None;
        if let Some(f) = forced
            && let Some(l) = self.links.get(f)
        {
            let g = l.lock().await;
            if g.state == LinkState::Up && !g.admin_disabled && g.remote.is_some() {
                chosen = Some(f);
            }
        }
        if chosen.is_none() {
            chosen = pick_link(&self.links, &self.scheduler, frame_len).await;
        }
        let Some(idx) = chosen else {
            tracing::warn!("no link available to send on; dropping packet");
            return None;
        };
        let Some(q) = self.queues.get(idx) else {
            tracing::warn!("no link available to send on; dropping packet");
            return None;
        };
        match q.tx.try_reserve() {
            Ok(permit) => Some((idx, permit)),
            Err(TrySendError::Full(())) => {
                q.counters.queue_full.fetch_add(1, Ordering::Relaxed);
                self.scheduler.lock().unwrap().note_queue_full(idx);
                if self.allow_spill {
                    self.spill_reserve(idx).await
                } else {
                    self.drop_job();
                    None
                }
            }
            // Only possible once the worker is gone (shutdown).
            Err(TrySendError::Closed(())) => self.spill_reserve(idx).await,
        }
    }

    /// Consume a reservation: stamp the enqueue time, raise the queue's
    /// depth (before the worker can ever decrement it) and hand over.
    fn send_reserved(q: &LinkTx, permit: mpsc::Permit<'_, TxJob>, mut job: TxJob) {
        job.enqueued = Instant::now();
        q.counters.depth.fetch_add(1, Ordering::Relaxed);
        permit.send(job);
    }

    /// Queue one frame without blocking (see `reserve`). A frame that
    /// finds no room anywhere is dropped and counted.
    async fn dispatch(&self, job: TxJob, forced: Option<usize>) {
        let frame_len = HEADER_LEN + job.plaintext.len();
        if let Some((idx, permit)) = self.reserve(forced, frame_len).await {
            Self::send_reserved(&self.queues[idx], permit, job);
        }
    }

    /// A worker could not put `job` on the wire (socket error, or the
    /// link has no remote yet): give it one more chance on another link.
    /// A job that cannot be placed is dropped here -- for a FEC member
    /// that drop is what marks the group's parity unsafe.
    async fn reroute(&self, from: usize, mut job: TxJob) {
        if job.rerouted {
            self.drop_job();
            return;
        }
        job.rerouted = true;
        if let Some((idx, permit)) = self.spill_reserve(from).await {
            Self::send_reserved(&self.queues[idx], permit, job);
        }
    }

    /// Reserve a slot on the usable link with the most free queue room
    /// other than `from`, or count a drop if there is none.
    async fn spill_reserve(&self, from: usize) -> Option<(usize, mpsc::Permit<'_, TxJob>)> {
        let free: Vec<usize> = self.queues.iter().map(|q| q.tx.capacity()).collect();
        let delivery: Vec<u32> = self
            .queues
            .iter()
            .map(|q| q.counters.delivery_ppm.load(Ordering::Relaxed))
            .collect();
        for cand in spill_candidates(&free, &delivery, from) {
            {
                let g = self.links[cand].lock().await;
                if g.state == LinkState::Down || g.admin_disabled || g.remote.is_none() {
                    continue;
                }
            }
            if let Ok(permit) = self.queues[cand].tx.try_reserve() {
                self.queues[from]
                    .counters
                    .rerouted_away
                    .fetch_add(1, Ordering::Relaxed);
                return Some((cand, permit));
            }
        }
        self.drop_job();
        None
    }

    /// Redundancy mode (`scheduler.redundant_mode`): send the same frame
    /// on every currently-Up link instead of picking one via `Scheduler`,
    /// trading bandwidth for the lowest chance of losing this packet.
    /// Falls back to every link with a known remote (regardless of state)
    /// if none are Up. Deliberately bypasses `bandwidth_cap_mbps`: this
    /// mode is opt-in specifically to prioritize reliability, and quietly
    /// skipping a capped link would undermine its one guarantee. A blunt
    /// whole-tunnel toggle (no per-flow classification) -- only worth
    /// enabling for a small, latency-critical tunnel.
    ///
    /// A copy that finds its link's queue
    /// full is simply not sent -- the other copies still carry the packet,
    /// and spilling would only duplicate a copy onto a link that already
    /// has one.
    async fn send_redundant(&self, plaintext: Vec<u8>) {
        let mut up = Vec::new();
        let mut any = Vec::new();
        for (i, l) in self.links.iter().enumerate() {
            let g = l.lock().await;
            if g.remote.is_some() {
                any.push(i);
                if g.state == LinkState::Up {
                    up.push(i);
                }
            }
        }
        let targets = if up.is_empty() { any } else { up };
        if targets.is_empty() {
            tracing::warn!("redundant mode: no link available to send on; dropping packet");
            return;
        }
        // Every copy carries the SAME seq -- `ReorderBuffer`'s
        // high-watermark logic treats every copy after the first as "not
        // forward progress" and discards it via the stale-duplicate path.
        let seq = next_send_seq();
        for idx in targets {
            let q = &self.queues[idx];
            let mut job = TxJob::new(PacketType::Data, seq, plaintext.clone());
            job.rerouted = true;
            if let Err(TrySendError::Full(_)) = try_enqueue(q, job) {
                q.counters.queue_full.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// One link's TX worker: drains its bounded queue and does the
/// encrypt + `send_to` for that link only. A slow or stalled socket
/// blocks just this task; every other link's worker and the dispatcher
/// keep running (Phase 2 of the improvement plan -- previously a single
/// `outbound_sender` did every link's `send_to` inline, so one stalled
/// link stalled them all).
async fn link_tx_worker(idx: usize, mut rx: mpsc::Receiver<TxJob>, d: TxDispatcher) {
    let counters = d.queues[idx].counters.clone();
    let mut batch: Vec<TxJob> = Vec::with_capacity(TX_WORKER_BATCH);
    let send_mode = d.links[idx].lock().await.config.tx_send_mode;
    match send_mode {
        crate::config::TxSendMode::Sendto => {}
        crate::config::TxSendMode::Sendmmsg => {
            tracing::info!(link = idx, "TX send mode: sendmmsg (batched)");
        }
        crate::config::TxSendMode::SendmmsgGso => {
            tracing::info!(link = idx, "TX send mode: sendmmsg_gso (batched, UDP GSO)");
        }
    }
    let mut mmsg = mmsg_tx::State::new(send_mode);
    loop {
        if rx.recv_many(&mut batch, TX_WORKER_BATCH).await == 0 {
            return;
        }
        // Resolved once per batch, still on every batch rather than once
        // for the task's lifetime, so a reconnect that swaps this link's
        // socket or remote is picked up within one batch.
        let target = {
            let g = d.links[idx].lock().await;
            g.remote.map(|_| (g.id, g.handle(), g.config.name.clone()))
        };
        // FIFO queue: the first job of the batch is the oldest, so its
        // age is the delay the worst-served packet just experienced.
        let batch_len = batch.len() as u32;
        let queue_delay_us = batch[0].enqueued.elapsed().as_micros() as u64;
        counters
            .queue_delay_sum_us
            .fetch_add(queue_delay_us, Ordering::Relaxed);
        counters.queue_delay_samples.fetch_add(1, Ordering::Relaxed);
        counters
            .queue_delay_max_us
            .fetch_max(queue_delay_us, Ordering::Relaxed);
        counters
            .last_progress_us
            .store(link::mono_us(), Ordering::Relaxed);
        let send_started = Instant::now();
        let mut bytes = 0u64;
        let mut pkts = 0u64;
        // Drains `batch` in `sendmmsg` mode; otherwise leaves it untouched
        // and the per-packet loop below sends it.
        {
            let (b, p) = mmsg_tx::send_batch(&d, idx, &target, &mut batch, &mut mmsg).await;
            bytes += b;
            pkts += p;
        }
        for mut job in batch.drain(..) {
            let Some((link_id, handle, name)) = &target else {
                counters.send_failed.fetch_add(1, Ordering::Relaxed);
                d.scheduler.lock().unwrap().note_send_failed(idx);
                d.reroute(idx, job).await;
                continue;
            };
            let header = Header {
                ptype: job.ptype,
                link_id: *link_id,
                seq: job.seq,
            }
            .to_bytes();
            match handle
                .wg_send_parts(&[&header, job.plaintext.as_slice()])
                .await
            {
                // `record_tx` keeps its "bytes this link put on the wire"
                // semantics, so a substituted handshake datagram still
                // counts; only a FEC member cares whether the datagram
                // actually carried its frame.
                Ok(carried) => {
                    bytes += (HEADER_LEN + job.plaintext.len()) as u64;
                    pkts += 1;
                    if carried && let Some(m) = job.member.as_mut() {
                        m.mark_carried();
                    }
                }
                Err(e) => {
                    tracing::debug!(link = %name, error = %e, "send failed");
                    counters.send_failed.fetch_add(1, Ordering::Relaxed);
                    d.scheduler.lock().unwrap().note_send_failed(idx);
                    d.reroute(idx, job).await;
                }
            }
        }
        if let Some(per_packet_us) = (send_started.elapsed().as_micros() as u64).checked_div(pkts) {
            counters
                .send_wait_sum_us
                .fetch_add(per_packet_us, Ordering::Relaxed);
            counters.send_wait_samples.fetch_add(1, Ordering::Relaxed);
            d.links[idx].lock().await.stats.record_tx_many(bytes, pkts);
        }
        counters.depth.fetch_sub(batch_len, Ordering::Relaxed);
        counters
            .last_progress_us
            .store(link::mono_us(), Ordering::Relaxed);
    }
}

/// `tx_send_mode = "sendmmsg"`: one `sendmmsg(2)` per worker batch instead of
/// one `sendto(2)` per packet. The per-packet path in `link_tx_worker` stays
/// the default and is also the fallback if the kernel refuses `sendmmsg`.
mod mmsg_tx {
    use super::*;

    pub(super) struct State {
        /// Cleared for good if the kernel reports `sendmmsg` unsupported.
        active: bool,
        /// Cleared for good if the kernel/NIC rejects a UDP GSO message.
        gso: bool,
        gso_runs: u64,
        gso_segments: u64,
        calls: u64,
        partial: u64,
        pkts: u64,
        batches: u64,
        last_log: Option<Instant>,
    }

    impl State {
        pub(super) fn new(mode: crate::config::TxSendMode) -> Self {
            Self {
                active: mode != crate::config::TxSendMode::Sendto,
                gso: mode == crate::config::TxSendMode::SendmmsgGso,
                gso_runs: 0,
                gso_segments: 0,
                calls: 0,
                partial: 0,
                pkts: 0,
                batches: 0,
                last_log: None,
            }
        }
    }

    /// Returns `(bytes, packets)` put on the wire. When this link is not in
    /// `sendmmsg` mode (or has fallen back) it returns `(0, 0)` without
    /// touching `batch`, and the caller's per-packet loop sends it.
    pub(super) async fn send_batch(
        d: &TxDispatcher,
        idx: usize,
        target: &Option<(u8, LinkHandle, String)>,
        batch: &mut Vec<TxJob>,
        st: &mut State,
    ) -> (u64, u64) {
        if !st.active {
            return (0, 0);
        }
        let Some((link_id, handle, name)) = target else {
            return (0, 0);
        };
        let headers: Vec<_> = batch
            .iter()
            .map(|job| {
                Header {
                    ptype: job.ptype,
                    link_id: *link_id,
                    seq: job.seq,
                }
                .to_bytes()
            })
            .collect();
        let (results, stats) = {
            let frames: Vec<[&[u8]; 2]> = batch
                .iter()
                .zip(headers.iter())
                .map(|(job, h)| [&h[..], job.plaintext.as_slice()])
                .collect();
            handle.wg_send_batch(&frames, st.gso).await
        };
        let counters = &d.queues[idx].counters;
        let (mut bytes, mut pkts) = (0u64, 0u64);
        let mut unsupported = false;
        for (mut job, res) in batch.drain(..).zip(results) {
            match res {
                Ok(carried) => {
                    bytes += (HEADER_LEN + job.plaintext.len()) as u64;
                    pkts += 1;
                    if carried && let Some(m) = job.member.as_mut() {
                        m.mark_carried();
                    }
                }
                Err(e) => {
                    if matches!(&e, MlvpnError::Io(io) if io.raw_os_error() == Some(libc::ENOSYS)) {
                        unsupported = true;
                    }
                    tracing::debug!(link = %name, error = %e, "send failed");
                    counters.send_failed.fetch_add(1, Ordering::Relaxed);
                    d.scheduler.lock().unwrap().note_send_failed(idx);
                    d.reroute(idx, job).await;
                }
            }
        }
        if unsupported {
            tracing::warn!(link = %name, "sendmmsg(2) not supported here; falling back to per-packet sendto");
            st.active = false;
            return (bytes, pkts);
        }
        if stats.gso_disabled && st.gso {
            tracing::warn!(link = %name, "UDP GSO rejected by the kernel; continuing with plain sendmmsg");
            st.gso = false;
        }
        st.calls += stats.calls;
        st.partial += stats.partial;
        st.gso_runs += stats.gso_runs;
        st.gso_segments += stats.gso_segments;
        st.pkts += pkts;
        st.batches += 1;
        let now = Instant::now();
        let last = *st.last_log.get_or_insert(now);
        if now.duration_since(last) >= Duration::from_secs(10) {
            tracing::debug!(
                link = %name,
                batches = st.batches,
                sendmmsg_calls = st.calls,
                partial_calls = st.partial,
                gso_runs = st.gso_runs,
                gso_segments = st.gso_segments,
                packets = st.pkts,
                pkts_per_call = format!("{:.2}", st.pkts as f64 / st.calls.max(1) as f64),
                "sendmmsg TX stats (last 10s)"
            );
            st.calls = 0;
            st.partial = 0;
            st.gso_runs = 0;
            st.gso_segments = 0;
            st.pkts = 0;
            st.batches = 0;
            st.last_log = Some(now);
        }
        (bytes, pkts)
    }
}

/// FEC state owned by `outbound_sender`: the group accumulator plus the
/// gate on the group currently being filled.
struct FecTx {
    sender: fec::FecSender,
    gate: Arc<FecGate>,
    ready: mpsc::Sender<fec::FecGroup>,
    unrecoverable: Arc<AtomicU64>,
}

/// Pulls frames off the outbound queue and hands them to the per-link TX
/// workers -- the other half of `tun_reader`'s split, see
/// `OUTBOUND_QUEUE_CAPACITY`'s doc comment for why this is a separate
/// task rather than `tun_reader` sending directly. This loop never waits
/// on a socket, in any mode: every send (Data, FEC parity, redundant
/// copies) is a non-blocking queue hand-off, so one stalled link cannot
/// stall the rest. Returns once `tx` (held by `tun_reader`) is dropped,
/// i.e. only during shutdown.
///
/// With FEC on (and not `redundant_mode`) this task is also the single
/// owner of the FEC group accumulator. A frame joins the group on the
/// link whose queue accepted it, and the group's parity is released by
/// its `FecGate` once every member has been resolved on a worker -- see
/// `FecGate` for how that keeps phantom members out of parity -- then
/// queued here like any other frame, so parity follows its members onto
/// the wire.
#[allow(clippy::too_many_arguments)]
async fn outbound_sender(
    mut rx: mpsc::Receiver<OutboundFrame>,
    redundant_mode: bool,
    fec_enabled: bool,
    fec_group_size: u8,
    fec_parity: u8,
    fec_placement: crate::config::FecParityPlacement,
    mtu: LiveMtu,
    fec_unrecoverable_total: Arc<AtomicU64>,
    fec_send_stats: Arc<fec::FecSendStats>,
    d: TxDispatcher,
) {
    let (ready_tx, mut ready_rx) = mpsc::channel::<fec::FecGroup>(FEC_READY_CAPACITY);
    // Redundant mode already sends every frame on every link; FEC adds
    // nothing there, so it keeps ignoring FEC exactly as before.
    let mut fec_tx = (fec_enabled && !redundant_mode).then(|| FecTx {
        sender: fec::FecSender::new(fec_group_size, fec_parity),
        gate: FecGate::new(ready_tx.clone(), fec_unrecoverable_total.clone()),
        ready: ready_tx.clone(),
        unrecoverable: fec_unrecoverable_total.clone(),
    });
    // What a parity frame is allowed to cost beyond the tunnel MTU: the
    // exact same number of bytes `control::effective_tunnel_mtu` already
    // reserved out of the tunnel MTU for this group size, so a parity
    // frame covering full-MTU members lands on the wire at the same
    // total size a Data frame did before FEC was enabled.
    let parity_headroom = if fec_enabled {
        crate::fec::parity_frame_overhead_bytes(fec_group_size) as usize
    } else {
        0
    };
    loop {
        tokio::select! {
            biased;
            Some(group) = ready_rx.recv() => {
                send_fec_parity(
                    &d,
                    group,
                    fec_placement,
                    parity_headroom,
                    &mtu,
                    &fec_unrecoverable_total,
                    &fec_send_stats,
                )
                .await;
            }
            frame = rx.recv() => {
                let Some(frame) = frame else { return };
                if redundant_mode {
                    d.send_redundant(frame.plaintext).await;
                    continue;
                }
                let Some(fec_tx) = fec_tx.as_mut() else {
                    d.dispatch(TxJob::new(PacketType::Data, next_send_seq(), frame.plaintext), None)
                        .await;
                    continue;
                };
                // A frame may join a FEC group only once a queue has
                // accepted it: one that is dropped here (no link, every
                // queue full) never existed as far as the receiver is
                // concerned. Whether an accepted frame then reaches the
                // wire is the gate's job.
                let frame_len = HEADER_LEN + frame.plaintext.len();
                let Some((link_idx, permit)) = d.reserve(None, frame_len).await else {
                    continue;
                };
                let seq = next_send_seq();
                let member = fec_tx.gate.join();
                if let Some(group) = fec_tx.sender.accumulate(seq, &frame.plaintext, link_idx) {
                    let next = FecGate::new(fec_tx.ready.clone(), fec_tx.unrecoverable.clone());
                    std::mem::replace(&mut fec_tx.gate, next).seal(group);
                }
                let mut job = TxJob::new(PacketType::Data, seq, frame.plaintext);
                job.member = Some(member);
                TxDispatcher::send_reserved(&d.queues[link_idx], permit, job);
            }
        }
    }
}

/// Queue the parity shares (P, then Q when configured) of a completed
/// group, honoring the configured placement.
async fn send_fec_parity(
    d: &TxDispatcher,
    group: fec::FecGroup,
    placement: crate::config::FecParityPlacement,
    parity_headroom: usize,
    mtu: &LiveMtu,
    fec_unrecoverable_total: &AtomicU64,
    stats: &fec::FecSendStats,
) {
    let parity_bytes = group.p.encode();
    // Belt-and-braces against the MTU reservation being momentarily
    // wrong: `mtu_monitor_loop` can *shrink* the live tunnel MTU (a link
    // reconnecting on smaller hardware) after a group has already
    // accumulated members sized for the old, larger one. Sending an
    // oversized parity frame is strictly worse than sending none at all
    // -- it either gets fragmented (needing *both* fragments to survive,
    // making it less likely to arrive than the data it protects) or
    // fails outright -- so drop it and count the group as one FEC could
    // not help with. The Q share is exactly as wide as P, so one check
    // covers both.
    let budget = mtu.load(Ordering::Relaxed) as usize + parity_headroom;
    if parity_bytes.len() > budget {
        fec_unrecoverable_total.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            parity_bytes = parity_bytes.len(),
            budget,
            "skipping an oversized FEC parity frame (tunnel MTU shrank mid-group)"
        );
        return;
    }
    let forced = if placement == crate::config::FecParityPlacement::Scheduler {
        None
    } else {
        let mut usable = Vec::with_capacity(d.links.len());
        for l in d.links.iter() {
            let g = l.lock().await;
            usable.push(g.state == LinkState::Up && !g.admin_disabled && g.remote.is_some());
        }
        crate::fec::choose_parity_link(placement, &group.member_links, &usable)
    };
    stats.groups.fetch_add(1, Ordering::Relaxed);
    stats.parity_p.fetch_add(1, Ordering::Relaxed);
    if group.q.is_some() {
        stats.parity_q.fetch_add(1, Ordering::Relaxed);
    }
    // A parity frame is not itself a group member: one that is dropped or
    // substituted just means the receiver never sees it and the group
    // times out as unrecoverable -- already the correct behavior, so
    // there is nothing to gate.
    d.dispatch(
        TxJob::new(PacketType::FecParity, next_send_seq(), parity_bytes),
        forced,
    )
    .await;
    if let Some(q) = group.q {
        d.dispatch(
            TxJob::new(PacketType::FecParityQ, next_send_seq(), q.encode()),
            forced,
        )
        .await;
    }
}

/// Periodically logs the outbound queue's drop counter -- silent when
/// nothing new was dropped since the last check, so this produces zero
/// log output on a healthy tunnel. See `OUTBOUND_QUEUE_CAPACITY`'s doc
/// comment for the bug this mechanism exists to make visible next time,
/// instead of only discoverable by comparing external `iperf3` numbers
/// against what the links should support.
///
/// `dropped_total` itself is monotonic (never reset) -- it's also
/// exposed to monitoring clients via `control::build_snapshot` as
/// `DaemonSnapshot::outbound_queue_dropped_total`, a lifetime counter
/// mirroring the per-link `tx_bytes`/`rx_bytes` convention (see
/// `LinkStats::record_tx`/`record_rx`). Only this reporter's own
/// `last_reported` local tracks where the previous window ended, so it
/// can still log a windowed delta count without needing to zero the
/// shared counter out from under a concurrently-polling monitoring
/// client.
async fn outbound_queue_drop_reporter(dropped_total: Arc<AtomicU64>) {
    let mut tick = interval(OUTBOUND_QUEUE_DROP_REPORT_INTERVAL);
    let mut last_reported = 0u64;
    loop {
        tick.tick().await;
        let total = dropped_total.load(Ordering::Relaxed);
        let n = total.saturating_sub(last_reported);
        last_reported = total;
        if n > 0 {
            tracing::warn!(
                dropped_packets = n,
                window_secs = OUTBOUND_QUEUE_DROP_REPORT_INTERVAL.as_secs(),
                queue_capacity = OUTBOUND_QUEUE_CAPACITY,
                "outbound queue overflowed: the send path (link scheduling/socket I/O) is \
                 falling behind the rate packets arrive from the TUN device, so packets were \
                 dropped here rather than stalling the TUN read loop. If this persists, see \
                 docs/performance-tuning.md."
            );
        }
    }
}

/// Owns one link's receive side: read frames off the socket and dispatch
/// them. Nothing else runs on this task, so a busy link can never delay
/// its own (or any other link's) probe timer -- see the module doc
/// comment for why that separation matters.
///
/// Never returns under normal operation: a `recv_from` error is logged
/// and retried on the same socket for the first few consecutive
/// failures (most are transient -- see `link.rs`'s module doc comment),
/// then triggers a reconnect attempt (`attempt_reconnect`) once they
/// cross `RECONNECT_FAILURE_THRESHOLD`. This deliberately replaces the
/// previous behavior of propagating the error and letting the task
/// (and this link's receive side, permanently) exit.
#[allow(clippy::too_many_arguments)]
async fn link_receiver(
    idx: usize,
    links: Links,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    rx_pipeline: RxPipelineTx,
    cfg: SchedulerConfig,
    tracker: Arc<AsyncMutex<ProbeTracker>>,
    peer_stats: Arc<PeerStatsTable>,
    mtu: LiveMtu,
    throughput_test_state: Arc<AsyncMutex<ThroughputTestReceiveState>>,
    throughput_test_ctx: Arc<ThroughputTestContext>,
    peer_version: PeerVersion,
    peer_mtu: PeerMtu,
    peer_live_mtu: PeerLiveMtu,
    peer_primary_link: PeerPrimaryLink,
) {
    let (handle, link_id, link_name) = {
        let link = links[idx].lock().await;
        (link.handle(), link.id, link.config.name.clone())
    };

    let mut consecutive_failures = 0u32;
    let mut backoff_ms = RECONNECT_BACKOFF_INITIAL_MS;
    // Owned once for this task's lifetime: the raw-datagram scratch and the
    // decrypted-frame buffer `wg_recv_into` fills on every packet. Sized to
    // hold any legitimate UDP datagram (see `wg_recv_into`).
    let mut recv_buf = vec![0u8; u16::MAX as usize + 64];
    let mut frame: Vec<u8> = Vec::with_capacity(2048);
    loop {
        // `wg_recv_into` loops internally past any handshake/keepalive
        // traffic on this link's socket -- what comes back here is
        // always either a genuine decrypted mlvpn frame plus the
        // datagram's source address, or a real error (a socket I/O
        // failure, or a malformed/oversized datagram that
        // `wireguard::WgTunnel::decapsulate` rejected outright).
        match handle.wg_recv_into(&mut recv_buf, &mut frame).await {
            Ok(from) => {
                consecutive_failures = 0;
                handle_incoming(
                    idx,
                    link_id,
                    &frame,
                    from,
                    &links,
                    &scheduler,
                    &rx_pipeline,
                    &cfg,
                    &tracker,
                    &peer_stats,
                    &mtu,
                    &throughput_test_state,
                    &throughput_test_ctx,
                    &peer_version,
                    &peer_mtu,
                    &peer_live_mtu,
                    &peer_primary_link,
                )
                .await;
            }
            Err(MlvpnError::Io(e)) if is_interface_gone_error(&e) => {
                consecutive_failures += 1;
                tracing::debug!(
                    link = %link_name,
                    error = %e,
                    consecutive_failures,
                    "link receive error (interface appears gone)"
                );
                if consecutive_failures >= RECONNECT_FAILURE_THRESHOLD {
                    attempt_reconnect(&handle, &link_name, &mut backoff_ms).await;
                    consecutive_failures = 0;
                } else {
                    // Brief pause so a socket that's failing every call
                    // (rather than just occasionally) doesn't spin the
                    // task in a tight CPU-burning loop while it waits
                    // to cross the reconnect threshold.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            Err(MlvpnError::Io(e)) => {
                // Not classified as "interface gone" -- e.g. ENETDOWN
                // from an interface that's merely administratively down,
                // or a momentary route lookup failure. Deliberately not
                // counted toward the reconnect threshold at all: this
                // socket is expected to start working again on its own
                // the moment the underlying route returns (see
                // link.rs's module doc comment and
                // is_interface_gone_error's doc comment), so reconnecting
                // here would just rebind to the same still-unusable
                // interface for no benefit.
                tracing::debug!(
                    link = %link_name,
                    error = %e,
                    "link receive error (transient, not reconnecting)"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => {
                // A malformed/oversized/garbled datagram rejected by
                // `WgTunnel::decapsulate` before it ever became a real
                // frame -- not a socket problem, so it neither resets
                // nor increments the reconnect-failure counter, and
                // there's nothing to hand to `handle_incoming`. Anyone
                // can send arbitrary garbage at this socket; rejecting
                // it here and continuing is the correct response.
                tracing::debug!(
                    link = %link_name,
                    error = %e,
                    "link receive error (malformed datagram, ignoring)"
                );
            }
        }
    }
}

/// Owns one link's probing side: periodically sends authenticated `Probe`
/// frames, sweeps ones that never got a reply into recorded losses, and
/// (for link index 0 only) reports the aggregate all-links-down state.
/// Runs as a task fully independent of `link_receiver` -- see the module
/// doc comment. Shares `tracker` with that link's `link_receiver` (see
/// `run()`, where both tasks are handed the same `Arc`).
#[allow(clippy::too_many_arguments)]
async fn link_prober(
    idx: usize,
    links: Links,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    cfg: SchedulerConfig,
    local_capability_mtu: LiveMtu,
    live_mtu: LiveMtu,
    tracker: Arc<AsyncMutex<ProbeTracker>>,
    peer_primary_link: PeerPrimaryLink,
) {
    let (handle, link_id, probe_interval_ms, link_name) = {
        let link = links[idx].lock().await;
        (
            link.handle(),
            link.id,
            link.effective_probe_interval_ms,
            link.config.name.clone(),
        )
    };

    let probe_seq_counter = AtomicU32::new(0);
    let mut probe_tick = interval(Duration::from_millis(probe_interval_ms));
    let mut sweep_tick = interval(Duration::from_millis(probe_interval_ms));
    let mut stats_tick = interval(Duration::from_millis(STATS_SHARE_INTERVAL_MS));
    // Only meaningful/used by the idx == 0 prober.
    let mut all_down_reported = false;
    // Probe sends are this task's steady heartbeat -- it runs
    // unconditionally on a timer whether or not there's any user
    // traffic, which makes it the most reliable place to notice a
    // socket that can no longer send at all. See the module doc
    // comment for the reconnect design this feeds.
    let mut probe_send_failures = 0u32;
    let mut backoff_ms = RECONNECT_BACKOFF_INITIAL_MS;

    loop {
        tokio::select! {
            _ = probe_tick.tick() => {
                // Drives boringtun's own internal handshake-retry/
                // keepalive timers -- see `LinkHandle::wg_tick`'s doc
                // comment and this module's own doc comment for why no
                // separate handshake-retry loop exists anywhere else.
                // Best-effort: a failure here doesn't affect probe
                // sending below, which has its own error handling.
                let _ = handle.wg_tick().await;

                let sent = {
                    let mut t = tracker.lock().await;
                    send_probe(link_id, &links, idx, &probe_seq_counter, &mut t).await
                };
                match sent {
                    ProbeSendOutcome::Sent => probe_send_failures = 0,
                    ProbeSendOutcome::InterfaceGone => {
                        probe_send_failures += 1;
                        // A probe that never left the socket can never
                        // get a reply and time out normally through
                        // `sweep_tick`/`ProbeTracker` -- see
                        // `record_send_failure_as_miss`'s doc comment.
                        // Feed the quality hysteresis directly instead
                        // of leaving it to notice only via whatever
                        // probes happened to already be in flight.
                        record_send_failure_as_miss(&links, idx, &cfg, &scheduler, &peer_primary_link).await;
                        if probe_send_failures >= RECONNECT_FAILURE_THRESHOLD {
                            attempt_reconnect(&handle, &link_name, &mut backoff_ms).await;
                            probe_send_failures = 0;
                        }
                    }
                    ProbeSendOutcome::TransientFailure => {
                        // Doesn't count toward the reconnect-failure
                        // counter (see `ProbeSendOutcome`'s doc comment
                        // -- this is expected to clear up on its own),
                        // but it's still a real, present-tense delivery
                        // failure the quality hysteresis needs to know
                        // about, for the same reason as the
                        // `InterfaceGone` arm above.
                        record_send_failure_as_miss(&links, idx, &cfg, &scheduler, &peer_primary_link).await;
                    }
                    // Not a failure at all (no remote learned yet, or a
                    // non-socket encrypt failure) -- doesn't touch
                    // hysteresis or the reconnect-failure counter.
                    ProbeSendOutcome::Skipped => {}
                }
            }

            // A third independent timer branch, same rationale as the
            // probe/sweep split described in the module doc comment: this
            // only feeds a monitoring display, so it must never be able
            // to delay (or be delayed by) probing, which is what actually
            // drives scheduling decisions.
            _ = stats_tick.tick() => {
                send_stats_share(link_id, &links, idx).await;
                send_version_info(
                    link_id,
                    &links,
                    idx,
                    &local_capability_mtu,
                    &live_mtu,
                    &scheduler,
                )
                .await;
            }

            _ = sweep_tick.tick() => {
                let misses = {
                    let mut t = tracker.lock().await;
                    t.sweep_timeouts()
                };
                if misses > 0 {
                    {
                        let mut link = links[idx].lock().await;
                        for _ in 0..misses {
                            link.stats.record_miss();
                        }
                        monitor::update_link_state(&mut link, &cfg);
                    }
                    let snap = link::snapshot_links(&links).await;
                    let peer_primary_index = resolve_peer_primary_index(&snap, &peer_primary_link);
                    let mut sched = scheduler.lock().unwrap();
                    sched.refresh(&snap, &cfg, peer_primary_index);
                }

                // Only one of the N probers needs to report the aggregate
                // state, and only on the edge (not every tick while it
                // stays down), or this would spam the log once per link
                // per probe interval. Runs every sweep tick regardless of
                // whether *this* link had a miss, since a different
                // link's state is what may have changed.
                if idx == 0 {
                    let snap = link::snapshot_links(&links).await;
                    let sched = scheduler.lock().unwrap();
                    let now_all_down = sched.all_down(&snap);
                    if now_all_down && !all_down_reported {
                        tracing::warn!(
                            "all links are currently down; still attempting delivery on the \
                             least-bad link (see scheduler.rs) rather than stalling the tunnel"
                        );
                    } else if !now_all_down && all_down_reported {
                        tracing::info!("at least one link is back up; aggregate no longer down");
                    }
                    all_down_reported = now_all_down;
                }

                if cfg.auto_tune_probe_interval {
                    let new_interval_ms = {
                        let mut link = links[idx].lock().await;
                        let suggested = suggest_probe_interval_ms(
                            link.config.probe_interval_ms,
                            cfg.probe_interval_max_ms,
                            link.effective_probe_interval_ms,
                            link.stats.consecutive_hits,
                            link.stats.consecutive_misses,
                        );
                        if suggested == link.effective_probe_interval_ms {
                            None
                        } else {
                            link.effective_probe_interval_ms = suggested;
                            Some(suggested)
                        }
                    };
                    // `tokio::time::Interval` has no "change the period"
                    // operation -- recreating it is the standard way to
                    // do that. This resets its phase, which is fine
                    // here: a probe/sweep timer's phase relative to
                    // wall-clock time was never meaningful to begin
                    // with, only its period is.
                    if let Some(new_ms) = new_interval_ms {
                        tracing::info!(
                            link = %link_name,
                            new_probe_interval_ms = new_ms,
                            "auto-tuned probe_interval_ms"
                        );
                        probe_tick = interval(Duration::from_millis(new_ms));
                        sweep_tick = interval(Duration::from_millis(new_ms));
                    }
                }

                if cfg.auto_tune_ewma_alpha {
                    let mut link = links[idx].lock().await;
                    let suggested = suggest_ewma_alpha(
                        cfg.ewma_alpha_min,
                        cfg.ewma_alpha_max,
                        link.effective_ewma_alpha,
                        link.stats.consecutive_hits,
                        link.stats.consecutive_misses,
                    );
                    // Direct float comparison is fine here: `suggested`
                    // is either exactly `link.effective_ewma_alpha`
                    // unchanged (the common case, most ticks) or one of
                    // a small set of values `suggest_ewma_alpha` itself
                    // computes deterministically from it -- there's no
                    // accumulated floating-point drift to worry about
                    // the way there might be after many independent
                    // arithmetic paths converging on "the same" value.
                    if suggested != link.effective_ewma_alpha {
                        link.effective_ewma_alpha = suggested;
                        link.stats.set_alpha(suggested);
                        tracing::info!(
                            link = %link_name,
                            new_ewma_alpha = suggested,
                            "auto-tuned ewma_alpha"
                        );
                    }
                }
            }
        }
    }
}

/// How many consecutive successful probes a link needs before
/// `suggest_ewma_alpha` smooths its alpha another step toward the
/// floor. Shares `PROBE_BACKOFF_STREAK`'s reasoning (a couple of good
/// probes right after trouble shouldn't immediately start relaxing
/// again) but is deliberately its own constant, not a reused one --
/// these two tunables are conceptually independent, and nothing
/// requires they ever move in lockstep even though they happen to share
/// a value today.
const EWMA_ALPHA_SMOOTHING_STREAK: u32 = 10;

/// Fixed step applied at each `EWMA_ALPHA_SMOOTHING_STREAK` milestone --
/// linear rather than multiplicative (unlike
/// `PROBE_BACKOFF_FACTOR`'s ×1.5) because alpha lives in the narrow,
/// fixed `(0, 1]` range rather than an open-ended milliseconds scale,
/// where a multiplicative step would either be too timid near the top
/// of the range or overshoot near the bottom.
const EWMA_ALPHA_STEP: f64 = 0.02;

/// Pure suggestion function, factored out of `link_prober` the same way
/// `suggest_reorder_window_ms`/`suggest_probe_interval_ms` were -- see
/// either for why. Unlike those two, this one is bidirectional: any
/// miss at all (`consecutive_misses > 0`) jumps straight to `max_alpha`
/// (fastest possible reaction the instant a link looks even slightly
/// less reliable), while a long clean streak gradually smooths back
/// down toward `min_alpha` instead, `EWMA_ALPHA_STEP` at a time every
/// `EWMA_ALPHA_SMOOTHING_STREAK` hits. `current_alpha` is always
/// clamped into `[min_alpha, max_alpha]` regardless of which branch is
/// taken, so a config change to the bounds themselves self-corrects on
/// the very next tick rather than needing a miss first.
fn suggest_ewma_alpha(
    min_alpha: f64,
    max_alpha: f64,
    current_alpha: f64,
    consecutive_hits: u32,
    consecutive_misses: u32,
) -> f64 {
    if consecutive_misses > 0 {
        return max_alpha;
    }
    if consecutive_hits > 0 && consecutive_hits.is_multiple_of(EWMA_ALPHA_SMOOTHING_STREAK) {
        return (current_alpha - EWMA_ALPHA_STEP).clamp(min_alpha, max_alpha);
    }
    current_alpha.clamp(min_alpha, max_alpha)
}

/// How many consecutive successful probes a link needs before
/// `suggest_probe_interval_ms` backs its effective interval off another
/// step toward the ceiling. Deliberately not 1 -- a couple of good
/// probes right after a miss shouldn't immediately start relaxing
/// again; there should be a real, sustained clean streak first.
const PROBE_BACKOFF_STREAK: u32 = 10;

/// Multiplicative step applied at each `PROBE_BACKOFF_STREAK` milestone.
/// 1.5x roughly doubles the interval every two milestones -- gradual
/// enough that a link which starts flapping again after backing off
/// doesn't first have to "spend down" a huge interval before hysteresis
/// reacts (see the immediate-snap-to-floor behavior on any miss below).
const PROBE_BACKOFF_FACTOR: f64 = 1.5;

/// Pure suggestion function, factored out of `link_prober` the same way
/// `suggest_reorder_window_ms` was factored out of `reorder_tuning_loop`
/// -- so the actual backoff/reset math is unit-testable without a live
/// `Link`/socket. `floor_ms` is always the operator-configured
/// `[[links]] probe_interval_ms` for this link (auto-tuning only ever
/// backs off *from* it, never below); `max_ms` is
/// `scheduler.probe_interval_max_ms`; `current_ms` is the interval
/// currently in effect.
///
/// Any miss at all in the current streak (`consecutive_misses > 0`)
/// snaps straight back to `floor_ms` -- a link that's shown even one
/// bit of trouble needs the fastest hysteresis reaction available, not
/// a relaxed one. Otherwise, every `PROBE_BACKOFF_STREAK` consecutive
/// hits, backs off by `PROBE_BACKOFF_FACTOR`, clamped to
/// `[floor_ms, max_ms]`.
fn suggest_probe_interval_ms(
    floor_ms: u64,
    max_ms: u64,
    current_ms: u64,
    consecutive_hits: u32,
    consecutive_misses: u32,
) -> u64 {
    if consecutive_misses > 0 {
        return floor_ms;
    }
    if consecutive_hits > 0 && consecutive_hits.is_multiple_of(PROBE_BACKOFF_STREAK) {
        let backed_off = (current_ms as f64 * PROBE_BACKOFF_FACTOR) as u64;
        return backed_off.clamp(floor_ms, max_ms);
    }
    current_ms.clamp(floor_ms, max_ms)
}

/// One per link, same one-per-link pattern as `trackers` in `run()`,
/// tracking a possibly-in-progress incoming `ThroughputTestData` stream
/// -- shared by both `ipc::Command::RunThroughputTest` (`mlvpnd
/// self-test`) and the periodic `active_bandwidth_prober`, since both
/// send the exact same wire packet type. Time-bounded rather than
/// packet-count-bounded (the sender doesn't know its own final packet
/// count ahead of time -- it's stopping on a duration timer, not after N
/// packets), so this watches `ThroughputTestDataPayload::done`.
/// `last_completed_test_id` guards against the sender's redundant
/// final-packet copies being misread as a fresh one-packet stream.
struct ThroughputTestReceiveState {
    test_id: Option<u32>,
    first_seen: Instant,
    /// When the most recent *non-final* packet of the current stream
    /// arrived, if any yet have. Used instead of "whenever the `done`
    /// packet happened to arrive" to compute `elapsed_secs` -- see the
    /// `ThroughputTestData` handling arm for why: the sender retries a
    /// lost `done` packet up to twice, `THROUGHPUT_TEST_DONE_RETRY_DELAY`
    /// apart, so if the original `done` is lost, whichever retry copy
    /// finally gets through arrives up to ~500ms late relative to when
    /// the stream's real data actually stopped flowing. On a short
    /// (e.g. 1-second) ramp step, that inflates the measured duration by
    /// 25-50%, comfortably enough to make an otherwise-healthy step look
    /// like it failed.
    last_data_at: Option<Instant>,
    bytes_seen: u64,
    last_completed_test_id: Option<u32>,
}

impl ThroughputTestReceiveState {
    fn new() -> Self {
        Self {
            test_id: None,
            first_seen: Instant::now(),
            last_data_at: None,
            bytes_seen: 0,
            last_completed_test_id: None,
        }
    }
}

/// Pure throughput calculation shared by `handle_incoming`'s
/// `ThroughputTestData` handling (used by both `mlvpnd self-test` and
/// the periodic `active_bandwidth_prober` below) and its own unit tests:
/// bytes carried by a completed stream, divided by how long it took to
/// arrive. `elapsed_secs` is clamped to a small positive floor so a
/// (practically impossible, but not unrepresentable) zero-duration
/// stream can't divide by zero or report an infinite/nonsensical rate.
///
/// The floor used to be `0.001` (1ms), which sounded conservative but
/// wasn't: back when `active_bandwidth_prober` sent a small fixed-count
/// packet burst rather than today's duration-bounded stream, a ~28KB
/// burst only needed to sustain ~229 Mbps to be delivered in under a
/// millisecond, which any modern broadband link can do. Once a burst
/// legitimately completed that fast, `Instant::elapsed()` measured it
/// correctly but this clamp overrode the real (smaller) duration with
/// 1ms, silently ceiling `achieved_mbps` at ~229 regardless of how much
/// faster the link actually was -- observed in production as the exact
/// same `achieved_mbps` value recurring over and over for a fast link,
/// which looked like a link-identity mixup but was actually this clamp.
/// Because `active_bandwidth_mbps` feeds `monitor::score()`'s
/// `throughput.sqrt()` scheduler weight, a link stuck reporting a fake
/// ~229 Mbps ceiling gets systematically underweighted relative to its
/// true capacity. `Instant` has nanosecond resolution, so the floor only
/// needs to guard against a literal zero/negative duration -- 1
/// microsecond is plenty, and still lets `achieved_mbps` run up into the
/// tens-of-Gbps range before clamping, far outside what any real stream
/// could plausibly produce.
fn compute_achieved_mbps(bytes: u64, elapsed_secs: f64) -> f64 {
    let elapsed_secs = elapsed_secs.max(0.000_001);
    (bytes as f64 * 8.0) / elapsed_secs / 1_000_000.0
}

/// Pure elapsed-time calculation for `ThroughputTestData`'s receive
/// side, extracted out of the `handle_incoming` match arm specifically
/// so it's unit-testable without a real socket.
///
/// Measures to `last_data_at` (the last *non-final* packet of this
/// stream actually received) rather than to `done_arrived_at` (when the
/// `done`-flagged packet that triggered this calculation showed up).
/// This matters because the sender retries a lost `done` packet up to
/// twice, `THROUGHPUT_TEST_DONE_RETRY_DELAY` apart: if the original
/// `done` is lost, whichever retry copy finally gets through can arrive
/// up to ~500ms after the stream's real data actually stopped flowing.
/// On a short (e.g. 1-second) ramp step that inflates the measured
/// duration by 25-50% -- enough to cross `RAMP_SUCCESS_THRESHOLD` and
/// make an otherwise-healthy step look like it failed, specifically on
/// the lossy links where accurate measurement matters most.
///
/// Falls back to `done_arrived_at` only for a degenerate stream whose
/// very first packet is already flagged `done` (no earlier non-final
/// packet exists to measure to).
fn receive_elapsed_secs(
    first_seen: Instant,
    last_data_at: Option<Instant>,
    done_arrived_at: Instant,
) -> f64 {
    last_data_at
        .unwrap_or(done_arrived_at)
        .duration_since(first_seen)
        .as_secs_f64()
}

/// One step of an `adaptive_bandwidth_ramp`: the rate attempted and
/// what the receiver actually measured for it. `clean` is
/// `achieved_mbps >= RAMP_SUCCESS_THRESHOLD * target_mbps` -- see the
/// module-level doc on `adaptive_bandwidth_ramp` for why 90%.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RampStep {
    pub target_mbps: f64,
    pub achieved_mbps: Option<f64>,
    // Genuinely only read by this module's own `ramp_*` tests today --
    // `adaptive_bandwidth_ramp` itself only needs the local `clean`
    // (used to decide whether to keep doubling or back off), not this
    // stored copy, and neither current caller (`control.rs`'s CLI path,
    // `active_bandwidth_prober`) reads it back off `RampResult::steps`.
    // Kept as real per-step state (not decoration left over from an
    // earlier plan) since it's exactly what a future CLI/diagnostics
    // display of "which step(s) failed and why" would need -- narrowly
    // allowed here rather than treated as the same stale dead code the
    // blanket allows on this whole module were.
    #[allow(dead_code)]
    pub clean: bool,
}

/// Full trace of a completed `adaptive_bandwidth_ramp`, plus its final
/// converged rate. `steps` is kept (not just the final number) so
/// `mlvpnd self-test`'s CLI output can show exactly where a real
/// ISP-policer cliff sits, not just an opaque average.
#[derive(Debug, Clone)]
pub(crate) struct RampResult {
    pub steps: Vec<RampStep>,
    pub confirmed_mbps: f64,
}

const RAMP_START_MBPS: f64 = 2.0;
const RAMP_DOUBLING_FACTOR: f64 = 2.0;
const RAMP_MAX_STEPS: usize = 12;
const RAMP_SUCCESS_THRESHOLD: f64 = 0.9;
const RAMP_BACKOFF_FACTOR: f64 = 0.8;

/// Discovers a link's real achievable throughput by pacing successive
/// short bursts at doubling rates (2, 4, 8, 16... Mbps) until one
/// isn't delivered cleanly, then backing off to a safety margin below
/// that cliff -- see
/// `docs/superpowers/specs/2026-08-28-adaptive-bandwidth-pacing-design.md`
/// for the full rationale (in short: an unpaced/too-fast probe gets
/// silently hard-dropped by an ISP's policer well before it can
/// measure the link's real ceiling, with zero local evidence of any
/// loss at all).
///
/// `run_step` performs exactly one step: send a paced stream at the
/// given `target_mbps` and return the receiver's measured
/// `achieved_mbps` for it (`None` on failure/timeout). Generic over
/// this so the state machine itself is fully unit-testable without a
/// real socket -- see this module's `ramp_*` tests. Real callers
/// (`run_throughput_test_leg_upload` for a manual `mlvpnd self-test`,
/// `active_bandwidth_prober` for a background re-ramp) supply a
/// closure that calls `send_throughput_test_stream` at 1-second
/// duration and awaits its `ThroughputTestResult`.
pub(crate) async fn adaptive_bandwidth_ramp<F, Fut>(mut run_step: F) -> RampResult
where
    F: FnMut(f64) -> Fut,
    Fut: std::future::Future<Output = Option<f64>>,
{
    let mut steps = Vec::with_capacity(RAMP_MAX_STEPS);
    let mut target = RAMP_START_MBPS;
    let mut last_clean: Option<f64> = None;

    for _ in 0..RAMP_MAX_STEPS {
        let achieved = run_step(target).await;
        let clean = achieved
            .map(|a| a >= RAMP_SUCCESS_THRESHOLD * target)
            .unwrap_or(false);
        steps.push(RampStep {
            target_mbps: target,
            achieved_mbps: achieved,
            clean,
        });

        if !clean {
            let backoff_base = last_clean.or(achieved).unwrap_or(target);
            return RampResult {
                steps,
                confirmed_mbps: backoff_base * RAMP_BACKOFF_FACTOR,
            };
        }

        last_clean = achieved;
        target *= RAMP_DOUBLING_FACTOR;
    }

    // Every step up to the safety cap stayed clean -- a genuinely very
    // fast link. Report the last step's achieved rate as-is; there is
    // no discovered cliff to back off from.
    let confirmed_mbps = steps
        .last()
        .and_then(|s| s.achieved_mbps)
        .unwrap_or(RAMP_START_MBPS);
    RampResult {
        steps,
        confirmed_mbps,
    }
}

/// True if this tick should discard the cached `confirmed_ceiling_mbps`
/// and run a full `adaptive_bandwidth_ramp`, rather than one cheap
/// single-step verification at the cached rate. See
/// `config::SchedulerConfig::active_bandwidth_reramp_interval_secs`'s
/// doc comment for the reasoning behind the two trigger conditions.
fn should_full_ramp(stats: &link::LinkStats, reramp_interval: Duration) -> bool {
    let Some(last_ramp_at) = stats.last_ramp_at else {
        return true; // never ramped this link before
    };
    if stats.confirmed_ceiling_mbps.is_none() {
        return true;
    }
    if stats.consecutive_verify_misses >= 2 {
        return true;
    }
    last_ramp_at.elapsed() >= reramp_interval
}

/// True if a just-completed full ramp's result is still safe to commit
/// for a link, given the link's state as captured *before* the ramp
/// started (`state_since_before_ramp`) and its state *now*
/// (`current_state`/`current_state_since`).
///
/// A full ramp holds no lock for its ~1-20 second duration, so the link
/// can go Down and back Up entirely within that window --
/// `monitor::update_link_state`'s reset on that transition already
/// cleared any cached ceiling for exactly this reason. If the ramp then
/// blindly writes back its pre-outage measurement, it silently
/// reinstates the stale-cache bug that reset exists to prevent. This is
/// a cheap approximation of "no bounce happened mid-ramp": the link must
/// still be `Up`, and its `state_since` must be unchanged from before
/// the ramp started (a changed `state_since` means at least one
/// transition happened while the ramp was running, even if the link
/// happens to be back to `Up` by the time we check).
fn ramp_result_still_valid(
    current_state: LinkState,
    current_state_since: Instant,
    state_since_before_ramp: Instant,
) -> bool {
    current_state == LinkState::Up && current_state_since == state_since_before_ramp
}

/// Sender side of `scheduler.active_bandwidth_probing` (off by default):
/// periodically sends a real throughput-measurement stream down this
/// link and lets the receiver's `ThroughputTestData` handling in
/// `handle_incoming` measure and report back the achieved throughput.
/// Spawned unconditionally per link in `run()` (same pattern as
/// `reorder_tuning_loop`) but returns immediately as a no-op unless the
/// feature is actually enabled, so the common (disabled) case costs
/// nothing beyond one parked task.
///
/// Deliberately its own task rather than folded into `link_prober`:
/// `link_prober`'s timing is latency-sensitive (its own probe cadence
/// directly feeds the Up/Down hysteresis), and a multi-second stream --
/// even a short one -- risks momentarily delaying the next scheduled
/// latency probe if they shared a task.
///
/// Reuses `send_throughput_test_stream`/`ThroughputTestContext` --
/// exactly the mechanism `mlvpnd self-test` uses -- rather than a
/// separate fixed-packet-count burst mechanism (removed, along with the
/// `BandwidthProbeBurst`/`BandwidthProbeResult` wire types it used).
/// That old approach completed a fast link's burst in well under one
/// round trip, which measured local send-side overhead more than the
/// path's real sustained capacity -- the faster the link, the worse
/// that got (a real-world 688 Mbps link measured at just 56.7 Mbps by
/// the old 20-packet burst is what prompted this change; see
/// `config::SchedulerConfig::active_bandwidth_probe_duration_secs`'s
/// doc comment for the bandwidth-delay-product math behind why). A
/// duration-based stream naturally scales instead: a fast link moves
/// more bytes in the same window, a slow link moves fewer, and both
/// produce an accurate `achieved_mbps`.
///
/// Best-effort throughout: a send failure, or a result that never
/// arrives within `ACTIVE_BANDWIDTH_PROBE_RESULT_GRACE` of the stream's
/// own duration, just means no result for that attempt -- the next
/// scheduled probe tries again, so there's no separate retry logic here.
async fn active_bandwidth_prober(
    idx: usize,
    links: Links,
    cfg: SchedulerConfig,
    mtu: LiveMtu,
    throughput_test_ctx: Arc<ThroughputTestContext>,
) {
    if !cfg.active_bandwidth_probing {
        return;
    }

    let link_id = links[idx].lock().await.id;

    let mut tick = interval(Duration::from_secs(
        cfg.active_bandwidth_probe_interval_secs,
    ));

    loop {
        tick.tick().await;

        // A fresh handle from the live `Link` every tick, not one
        // captured once at task startup -- see `send_probe`'s comment
        // for why a stale captured `LinkHandle.remote` would otherwise
        // never observe a remote address learned later. Skipped
        // entirely if there's no remote to send to yet (e.g. right at
        // startup, or a link that's never come up).
        let handle = {
            let link = links[idx].lock().await;
            if link.remote.is_none() {
                continue;
            }
            link.handle()
        };

        let reramp_interval = Duration::from_secs(cfg.active_bandwidth_reramp_interval_secs);
        let full_ramp = {
            let link = links[idx].lock().await;
            should_full_ramp(&link.stats, reramp_interval)
        };

        // Shared per-step runner: sends a paced 1-second stream at
        // `target_mbps` and waits for the peer's result, same shape
        // Task 3's CLI upload leg uses.
        let run_step = |target_mbps: f64| {
            let handle = handle.clone();
            let mtu = mtu.clone();
            let throughput_test_ctx = throughput_test_ctx.clone();
            async move {
                let test_id = crypto::random_session_id();
                let mut rx = throughput_test_ctx.register_wait(test_id);
                if send_throughput_test_stream(
                    handle,
                    link_id,
                    test_id,
                    Duration::from_secs(1),
                    mtu,
                    target_mbps,
                )
                .await
                .is_err()
                {
                    return None;
                }
                match tokio::time::timeout(
                    Duration::from_secs(1) + ACTIVE_BANDWIDTH_PROBE_RESULT_GRACE,
                    rx.recv(),
                )
                .await
                {
                    Ok(Some(mbps)) => Some(mbps),
                    _ => None,
                }
            }
        };

        if full_ramp {
            let state_since_before_ramp = links[idx].lock().await.state_since;
            let result = adaptive_bandwidth_ramp(run_step).await;
            let got_real_measurement = result.steps.iter().any(|s| s.achieved_mbps.is_some());
            if !got_real_measurement {
                // Every step failed/timed out -- e.g. an old peer that
                // ignores `ThroughputTestData`, or a temporarily
                // unreachable one. `result.confirmed_mbps` in this case
                // is a fabricated fallback number
                // (`RAMP_START_MBPS * RAMP_BACKOFF_FACTOR`), not a real
                // measurement -- committing it would both override
                // `monitor::score()`'s real-traffic EWMA fallback
                // permanently and get cached into `confirmed_ceiling_mbps`,
                // self-perpetuating via the cheap verification tick.
                // Mirror `control.rs`'s CLI-path guard: skip committing
                // anything and let the next scheduled tick retry.
                let link_name = links[idx].lock().await.config.name.clone();
                tracing::warn!(
                    link = %link_name,
                    steps = result.steps.len(),
                    "active bandwidth ramp got no real measurement from any step, discarding"
                );
                continue;
            }
            if let Some(link) = links.get(idx) {
                let mut link = link.lock().await;
                // The link may have bounced Down and back Up while this
                // ramp was in flight (it holds no lock for its ~1-20s
                // duration). `monitor::update_link_state`'s reset on that
                // transition would have cleared the cache already -- if
                // we blindly write the ramp's pre-outage measurement back
                // now, we silently reinstate the exact stale-cache bug
                // that reset was fixed for. Cheap approximation: discard
                // if the link isn't still Up, or if its `state_since` has
                // moved since before the ramp started (i.e. it bounced).
                if !ramp_result_still_valid(link.state, link.state_since, state_since_before_ramp) {
                    tracing::warn!(
                        link = %link.config.name,
                        "link state changed mid-ramp, discarding ramp result"
                    );
                    continue;
                }
                link.stats
                    .active_bandwidth_mbps
                    .update(result.confirmed_mbps);
                link.stats.confirmed_ceiling_mbps = Some(result.confirmed_mbps);
                link.stats.last_ramp_at = Some(Instant::now());
                link.stats.consecutive_verify_misses = 0;
                tracing::info!(
                    link = %link.config.name,
                    confirmed_mbps = result.confirmed_mbps,
                    steps = result.steps.len(),
                    "active bandwidth ramp complete"
                );
            }
        } else {
            let cached = {
                let link = links[idx].lock().await;
                link.stats.confirmed_ceiling_mbps
            };
            let Some(cached_mbps) = cached else {
                continue; // shouldn't happen (should_full_ramp guards this), skip defensively
            };
            let achieved = run_step(cached_mbps).await;
            let clean = achieved
                .map(|a| a >= RAMP_SUCCESS_THRESHOLD * cached_mbps)
                .unwrap_or(false);
            if let Some(link) = links.get(idx) {
                let mut link = link.lock().await;
                if let Some(achieved_mbps) = achieved {
                    link.stats.active_bandwidth_mbps.update(achieved_mbps);
                }
                link.stats.consecutive_verify_misses = if clean {
                    0
                } else {
                    link.stats.consecutive_verify_misses + 1
                };
                tracing::info!(
                    link = %link.config.name,
                    cached_mbps,
                    ?achieved,
                    clean,
                    "active bandwidth verification tick"
                );
            }
        }
    }
}

/// Extra time to wait, beyond the probe stream's own duration, for the
/// peer's measured result to come back -- same reasoning as
/// `control::THROUGHPUT_TEST_RESULT_GRACE`, just local to this module
/// since `active_bandwidth_prober` runs entirely within `tunnel.rs`.
const ACTIVE_BANDWIDTH_PROBE_RESULT_GRACE: Duration = Duration::from_secs(5);

/// Reverse/download leg's last-resort pacing target when this link has
/// neither a cached `confirmed_ceiling_mbps` (active bandwidth probing
/// is off -- the default -- or this is the very first test against a
/// freshly-started link) nor an operator-configured
/// `LinkConfig::bandwidth_cap_mbps` to fall back to. Conservative enough
/// not to trigger the same off-host policing this whole feature exists
/// to avoid, on essentially any real-world link.
///
/// This used to be the *only* fallback, which meant every deployment
/// running with the (default-off) `active_bandwidth_probing` disabled
/// paced its reverse leg at exactly this number forever, silently, with
/// `mlvpnd self-test --bidirectional` reporting it as if it were a real
/// measurement. See `ThroughputTestReverseRequest`'s handler for the
/// full three-tier priority order this is now the last resort of.
const REVERSE_LEG_FALLBACK_MBPS: f64 = 20.0;

/// Sends a continuous, MTU-padded `ThroughputTestData` stream to
/// `remote` for `duration`, then a couple of redundant final ("done")
/// packets as insurance against losing exactly the last one.
///
/// Used by three callers, all sharing this one implementation rather
/// than each maintaining their own: the on-demand `mlvpnd self-test`'s
/// forward/upload leg (`control::apply_command`'s
/// `Command::RunThroughputTest` handler calls this directly), its
/// reverse/download leg (`handle_incoming`'s `ThroughputTestReverseRequest`
/// arm spawns this in response to a peer's request, entirely
/// autonomously -- no local command-socket trigger involved on that
/// side), and the periodic `active_bandwidth_prober` (off by default).
///
/// Deliberately does *not* batch every packet's encrypt under one lock
/// acquisition the way `active_bandwidth_prober`'s old fixed-packet-count
/// burst mechanism used to (removed -- see that function's doc comment
/// for why a short burst was the wrong tool for measuring a fast link's
/// real capacity in the first place): a multi-second stream is
/// specifically trying to measure "how fast can this link actually go
/// under realistic conditions," which means competing fairly with real
/// Data traffic for the shared session lock is exactly correct, not a
/// bug to route around. Holding the lock for the entire stream's
/// duration would instead starve `tun_reader` (and therefore all real
/// traffic on every link, not just this one) for the whole window --
/// acceptable for a handful of packets over a few milliseconds, not for
/// a stream that can run for seconds.
///
/// Pause between each redundant final ("done") packet -- see the loop
/// below for why this needs to be a real pause, not just back-to-back
/// insurance copies. Small relative to the `THROUGHPUT_TEST_RESULT_GRACE`/
/// `ACTIVE_BANDWIDTH_PROBE_RESULT_GRACE` a caller waits beyond the
/// stream's own duration for a result (two of these add well under a
/// second total), but meaningful relative to how fast a shaper actually
/// drains once this function's own sending stops adding to its queue.
const THROUGHPUT_TEST_DONE_RETRY_DELAY: Duration = Duration::from_millis(250);

/// How much wall-clock time should have elapsed, since a stream started,
/// once `bytes_sent` bytes of it have gone out, in order for the
/// stream's average send rate to converge on `target_mbps` -- see
/// `docs/superpowers/specs/2026-08-28-adaptive-bandwidth-pacing-design.md`.
/// Used by `send_throughput_test_stream`'s drift-corrected pacing loop
/// below: rather than sleeping a fixed delay after every packet (which
/// would compound scheduling/encrypt/syscall overhead into a real rate
/// slower than `target_mbps`), the loop computes where it *should* be by
/// now given bytes actually sent so far, and only sleeps the remaining
/// gap. Extracted out of the loop (rather than duplicating this formula
/// inline) so it's independently unit-testable and can't silently drift
/// out of sync with what the loop actually does.
///
/// `bytes_sent` here is `payload_len`-sized units -- the plaintext
/// length passed to `encode_padded`, *before* encryption -- not the
/// real on-wire size, which is `HEADER_LEN + ciphertext.len()` (larger,
/// since the AEAD ciphertext carries an authentication tag on top of the
/// plaintext). Pacing is therefore against the plaintext size, not the
/// true wire size.
fn target_elapsed_for_bytes(bytes_sent: u64, target_mbps: f64) -> Duration {
    let bits = bytes_sent as f64 * 8.0;
    let secs = bits / (target_mbps.max(0.001) * 1_000_000.0);
    Duration::from_secs_f64(secs.max(0.0))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_throughput_test_stream(
    handle: LinkHandle,
    link_id: u8,
    test_id: u32,
    duration: Duration,
    mtu: LiveMtu,
    target_mbps: f64,
) -> Result<()> {
    // Logged here (not just on completion) specifically so a diagnostic
    // dump's log tail (`diag.rs`, `mlvpnd diag-dump`) makes it obvious a
    // deliberate self-test -- not organic traffic -- was saturating this
    // link during whatever time window it covers. A self-test is a
    // common, intentional way to *induce* real loss for testing, and
    // without this line a loss event captured mid-test looks
    // indistinguishable from an unexplained one.
    tracing::info!(
        link_id,
        test_id,
        duration_secs = duration.as_secs(),
        "throughput self-test stream starting"
    );

    let deadline = Instant::now() + duration;

    async fn send_one(
        handle: &LinkHandle,
        link_id: u8,
        test_id: u32,
        done: bool,
        payload_len: usize,
    ) -> Result<()> {
        let payload = ThroughputTestDataPayload { test_id, done }.encode_padded(payload_len);
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        Header {
            ptype: PacketType::ThroughputTestData,
            link_id,
            seq: next_send_seq(),
        }
        .encode(&mut out);
        out.extend_from_slice(&payload);
        // Best-effort, same as active_bandwidth_prober's burst: a single
        // dropped packet mid-stream just means a slightly smaller
        // bytes_seen on the receiver, not a fatal error for the whole
        // test.
        let _ = handle.wg_send(&out).await;
        Ok(())
    }

    let stream_start = Instant::now();
    let mut bytes_sent: u64 = 0;

    loop {
        // Re-read the live MTU on every packet rather than sizing the
        // whole stream once up front: a self-test or bandwidth probe
        // running across an `mtu_monitor_loop` resize should follow the
        // link down (or up) mid-stream, not keep emitting packets sized
        // for an MTU the link no longer has -- which is exactly when
        // they would start fragmenting and skew the measurement.
        let payload_len = (mtu.load(std::sync::atomic::Ordering::Relaxed) as usize)
            .max(ThroughputTestDataPayload::HEADER_LEN);
        let done = Instant::now() >= deadline;
        send_one(&handle, link_id, test_id, done, payload_len).await?;
        bytes_sent += payload_len as u64;

        if done {
            for _ in 0..2 {
                // A real, if brief, pause -- not just insurance against a
                // one-off dropped packet. This loop has been sending as
                // fast as it can for the entire stream duration, which on
                // a heavily bandwidth-constrained or already-congested
                // link means any downstream queue (a shaper, a
                // bottleneck hop) is likely still full at the exact
                // moment the main loop stops. Sending all the redundant
                // copies back-to-back right then just re-rolls the same
                // bad odds instantly -- none of them get a materially
                // better chance than the first. Pausing between copies
                // gives the queue a real window to drain (at whatever
                // the link's actual rate is) before the next attempt,
                // which is what actually improves the odds. Confirmed
                // necessary, not just theoretical: a real veth test
                // shaped to 2mbit lost every unspaced copy of the final
                // packet, and production logs showed the same "no
                // result" pattern on a real, heavily loss-laden link.
                tokio::time::sleep(THROUGHPUT_TEST_DONE_RETRY_DELAY).await;
                let _ = send_one(&handle, link_id, test_id, true, payload_len).await;
            }
            return Ok(());
        }

        // Drift-corrected pacing: see `target_elapsed_for_bytes`'s doc
        // comment. Sleep only the remaining gap -- zero if we're already
        // behind schedule.
        let target_elapsed = target_elapsed_for_bytes(bytes_sent, target_mbps);
        let actual_elapsed = stream_start.elapsed();
        if target_elapsed > actual_elapsed {
            tokio::time::sleep(target_elapsed - actual_elapsed).await;
        }
    }
}

/// Sends one `ThroughputTestReverseRequest` frame, asking the peer to
/// start sending `ThroughputTestData` back to us for the reverse leg of
/// a bidirectional throughput test. Called once by
/// `control::apply_command`'s `Command::RunThroughputTest` handler,
/// before it starts waiting (via a `ThroughputTestContext` registration
/// made just ahead of this call) for that reverse stream to arrive and
/// complete.
pub(crate) async fn send_throughput_test_reverse_request(
    handle: &LinkHandle,
    link_id: u8,
    test_id: u32,
    duration_secs: u32,
) -> Result<()> {
    let payload = ThroughputTestReverseRequestPayload {
        test_id,
        duration_secs,
    }
    .encode();
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    Header {
        ptype: PacketType::ThroughputTestReverseRequest,
        link_id,
        seq: next_send_seq(),
    }
    .encode(&mut out);
    out.extend_from_slice(&payload);
    // Discard `wg_send`'s "did this frame really reach the wire" bool:
    // this function's own `Result<()>` contract is unchanged, and the
    // throughput-test protocol already tolerates a lost request (the
    // caller times out waiting for the reverse stream and reports no
    // result) rather than needing per-frame delivery confirmation.
    handle.wg_send(&out).await.map(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming(
    idx: usize,
    link_id: u8,
    frame: &[u8],
    from: SocketAddr,
    links: &Links,
    scheduler: &Arc<std::sync::Mutex<Scheduler>>,
    rx_pipeline: &RxPipelineTx,
    cfg: &SchedulerConfig,
    tracker: &Arc<AsyncMutex<ProbeTracker>>,
    peer_stats: &Arc<PeerStatsTable>,
    mtu: &LiveMtu,
    throughput_test_state: &Arc<AsyncMutex<ThroughputTestReceiveState>>,
    throughput_test_ctx: &Arc<ThroughputTestContext>,
    peer_version: &PeerVersion,
    peer_mtu: &PeerMtu,
    peer_live_mtu: &PeerLiveMtu,
    peer_primary_link: &PeerPrimaryLink,
) {
    // `frame` is already the plaintext output of `LinkHandle::wg_recv`
    // (this link's own `WgTunnel` already authenticated and decrypted
    // it) -- unlike the old shared-session design, there is no decrypt
    // step here at all, and no `HandshakeInit`/`HandshakeResp` arms:
    // WireGuard's handshake happens entirely inside `wireguard.rs`/
    // `link.rs`, below this layer, so a genuine mlvpn frame reaching
    // this function is authentication enough on its own.
    let Ok((hdr, plaintext)) = Header::decode(frame) else {
        return;
    };
    // Borrowed from `frame` (the receive loop's reusable buffer), not
    // copied: only the branch that must outlive this call
    // (`ReorderBuffer::insert`) takes an owned copy, and only when it
    // actually buffers.
    if matches!(
        hdr.ptype,
        PacketType::HandshakeInit | PacketType::HandshakeResp
    ) {
        // `PacketType` still declares these two variants (protocol.rs is
        // outside this task's scope), but nothing on this side ever
        // constructs one anymore -- a peer that somehow still sends one
        // (an old build, a forged frame) has nothing meaningful to do
        // here now that the real WireGuard handshake lives entirely
        // below this layer.
        tracing::debug!(%from, ptype = ?hdr.ptype, "ignoring legacy app-level handshake frame");
        return;
    }

    // Only now, having verified the frame is authentic, do we trust its
    // source address enough to (re-)learn it as this link's peer address.
    // This is what lets a server-side link start life with no configured
    // `remote_addr` and still become usable the moment the client's first
    // authenticated frame arrives on it, and lets either side recover
    // automatically if a link's source address changes mid-session (e.g.
    // mobile roaming, NAT rebinding) -- without letting an unauthenticated
    // spoofed packet redirect where we send subsequent traffic.
    let mut local_tx_bytes = 0;
    if let Some(l) = links.get(idx) {
        // Merged into one lock acquisition rather than two adjacent ones
        // (the remote-address check below, plus a Data-only record_rx
        // that used to re-lock the same link right after) -- confirmed
        // live via `strace -f -c` that per-packet lock acquisitions
        // dominate mlvpnd's wall-clock time (see `pick_link`'s
        // select_fast for the sibling fix on the send side); this halves
        // the lock count on the hottest part of the receive path too.
        let mut link = l.lock().await;
        if link.remote != Some(from) {
            tracing::debug!(link = %link.config.name, %from, "learned/updated peer address");
            link.remote = Some(from);
        }
        if hdr.ptype == PacketType::Data {
            link.stats.record_rx(frame.len() as u64);
        }
        local_tx_bytes = link.stats.tx_bytes;
    }

    match hdr.ptype {
        PacketType::Data => {
            // FEC observation, the duplicate guard, reordering and TUN
            // delivery all live in the single `rx_pipeline` owner, so the
            // receiving link's task only has to hand the frame over.
            rx_pipeline.deliver(RxEvent::Data {
                seq: hdr.seq,
                plaintext: plaintext.to_vec(),
            });
        }
        PacketType::FecParity | PacketType::FecParityQ => {
            if !cfg.fec_enabled {
                // A peer with FEC on talking to a receiver with it off:
                // nothing is being observed to reconstruct against, and
                // running the machinery anyway would report every group
                // as unrecoverable. Drop it like any other unwanted frame.
                return;
            }
            let Ok(parity) = crate::protocol::FecParityPayload::decode(plaintext) else {
                tracing::debug!("malformed FecParity payload, ignoring");
                return;
            };
            let kind = if hdr.ptype == PacketType::FecParityQ {
                fec::ParityKind::Q
            } else {
                fec::ParityKind::P
            };
            rx_pipeline.deliver(RxEvent::Parity(kind, parity));
        }
        PacketType::Probe => {
            // Echo the decrypted probe payload straight back, so the
            // original sender can match it against their
            // outstanding-probe table by `probe_seq` and compute RTT
            // from their own clock. Sent through a fresh `LinkHandle`
            // (this link's own `WgTunnel` encrypts it) rather than the
            // raw socket -- see `send_probe`'s comment on why a fresh
            // handle, not the caller's possibly-stale one, is used here.
            let Some(link_mutex) = links.get(idx) else {
                return;
            };
            let handle = link_mutex.lock().await.handle();
            let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len());
            Header {
                ptype: PacketType::ProbeReply,
                link_id,
                seq: next_send_seq(),
            }
            .encode(&mut out);
            out.extend_from_slice(plaintext);
            let _ = handle.wg_send(&out).await;
        }
        PacketType::ProbeReply => {
            let Ok(probe) = ProbePayload::decode(plaintext) else {
                return;
            };
            let rtt_ms = {
                let mut t = tracker.lock().await;
                t.record_reply(probe.probe_seq)
            };
            if let Some(rtt_ms) = rtt_ms {
                if let Some(l) = links.get(idx) {
                    let mut link = l.lock().await;
                    link.stats.record_rtt(rtt_ms);
                    monitor::update_link_state(&mut link, cfg);
                }
                let snap = link::snapshot_links(links).await;
                let peer_primary_index = resolve_peer_primary_index(&snap, peer_primary_link);
                let mut sched = scheduler.lock().unwrap();
                sched.refresh(&snap, cfg, peer_primary_index);
            }
        }
        PacketType::StatsShare => {
            if let Ok(payload) = StatsPayload::decode(plaintext) {
                // Keyed by our own idx (the link we received this on),
                // not anything the sender included -- see StatsPayload's
                // doc comment for why that's the correct choice here.
                peer_stats.update(idx as u8, &payload, local_tx_bytes);
            }
        }
        PacketType::VersionInfo => match VersionInfoPayload::decode(plaintext) {
            Ok(payload) => {
                *peer_version.lock().unwrap() = Some(payload.version_str());
                *peer_mtu.lock().unwrap() = Some(payload.tunnel_mtu);
                // `0` means the peer predates this field -- same
                // "not a real MTU, treat as unknown" convention as
                // `tunnel_mtu`'s own zero-sentinel (see
                // `negotiate_tunnel_mtu`'s doc comment).
                *peer_live_mtu.lock().unwrap() =
                    (payload.live_tunnel_mtu != 0).then_some(payload.live_tunnel_mtu);
                *peer_primary_link.lock().unwrap() = payload.primary_link_name_str();
            }
            Err(e) => {
                tracing::debug!(error = %e, %from, "failed to decode VersionInfo payload");
            }
        },
        PacketType::ThroughputTestData => {
            let Ok(data) = ThroughputTestDataPayload::decode(plaintext) else {
                return;
            };
            let mut state = throughput_test_state.lock().await;
            // Guards against a redundant copy of an already-completed
            // stream's final packet(s) being misread as the start of a
            // fresh one -- see `ThroughputTestReceiveState`'s doc
            // comment.
            if state.last_completed_test_id == Some(data.test_id) {
                return;
            }
            if state.test_id != Some(data.test_id) {
                state.test_id = Some(data.test_id);
                state.first_seen = Instant::now();
                state.last_data_at = None;
                state.bytes_seen = 0;
                // Same reasoning as `send_throughput_test_stream`'s own
                // start-of-stream log: marks the receive side's log tail
                // too, so a diagnostic dump covering this window shows
                // both "we started sending a self-test stream" and "we
                // started receiving one," bracketing exactly when
                // deliberate self-test load was on this link.
                tracing::info!(
                    link_id,
                    test_id = data.test_id,
                    %from,
                    "throughput self-test stream receiving"
                );
            }
            state.bytes_seen += frame.len() as u64;
            if !data.done {
                state.last_data_at = Some(Instant::now());
            }
            if data.done {
                let elapsed_secs =
                    receive_elapsed_secs(state.first_seen, state.last_data_at, Instant::now());
                let achieved_mbps = compute_achieved_mbps(state.bytes_seen, elapsed_secs);
                state.test_id = None;
                state.last_completed_test_id = Some(data.test_id);
                drop(state);

                // Always reply to whoever actually sent this stream --
                // that's the normal case, a peer running
                // Command::RunThroughputTest against us and waiting for
                // this exact reply.
                let result_payload = ThroughputTestResultPayload {
                    test_id: data.test_id,
                    achieved_mbps: achieved_mbps as f32,
                };
                if let Some(link_mutex) = links.get(idx) {
                    let handle = link_mutex.lock().await.handle();
                    let reply_plaintext = result_payload.encode();
                    let mut out = Vec::with_capacity(HEADER_LEN + reply_plaintext.len());
                    Header {
                        ptype: PacketType::ThroughputTestResult,
                        link_id,
                        seq: next_send_seq(),
                    }
                    .encode(&mut out);
                    out.extend_from_slice(&reply_plaintext);
                    let _ = handle.wg_send(&out).await;
                }

                // Also deliver locally: if *we* are the one waiting on
                // this exact test_id (the reverse leg of our own
                // bidirectional test -- see `ThroughputTestContext`'s
                // doc comment), this is how that result actually
                // reaches the waiting command handler. A no-op if
                // nothing's registered for it.
                throughput_test_ctx.forward_result(data.test_id, achieved_mbps);

                tracing::info!(
                    link_id,
                    achieved_mbps,
                    "throughput self-test stream received"
                );
            }
        }
        PacketType::ThroughputTestResult => {
            let Ok(result) = ThroughputTestResultPayload::decode(plaintext) else {
                return;
            };
            // The peer measuring a stream *we* sent them -- deliver to
            // whichever local command invocation is waiting on this
            // test_id. A no-op if nothing's registered (e.g. this
            // arrived after the waiting command already timed out and
            // gave up).
            throughput_test_ctx.forward_result(result.test_id, result.achieved_mbps as f64);
        }
        PacketType::ThroughputTestReverseRequest => {
            let Ok(req) = ThroughputTestReverseRequestPayload::decode(plaintext) else {
                return;
            };
            let target_mbps = {
                // `idx` (this link's own index into `links`) and `links`
                // are both already parameters of the enclosing
                // `handle_incoming` function -- no need to search by id.
                //
                // Three-tier priority: a real `confirmed_ceiling_mbps`
                // measurement beats everything; absent that, the
                // operator's own `bandwidth_cap_mbps` (already
                // documented as exactly this -- a manual ceiling on the
                // scheduler's throughput assumption for this link) is a
                // far better guess than the fixed 20 Mbps last resort,
                // which otherwise silently applies to every default
                // (active_bandwidth_probing-disabled) deployment
                // forever. Reading it here doesn't violate the "leave
                // bandwidth_cap_mbps untouched" constraint elsewhere in
                // this feature -- that's about not writing to it.
                let link = links[idx].lock().await;
                link.stats
                    .confirmed_ceiling_mbps
                    .or(link.config.bandwidth_cap_mbps)
                    .unwrap_or(REVERSE_LEG_FALLBACK_MBPS)
            };
            // Autonomously start sending a stream back, without any
            // local command-socket trigger -- this is what makes a
            // bidirectional throughput test work without needing the
            // operator to separately run a command on *both* ends.
            let Some(link_mutex) = links.get(idx) else {
                return;
            };
            let handle = link_mutex.lock().await.handle();
            let mtu = mtu.clone();
            let duration = Duration::from_secs(req.duration_secs as u64);
            tokio::spawn(async move {
                if let Err(e) = send_throughput_test_stream(
                    handle,
                    link_id,
                    req.test_id,
                    duration,
                    mtu,
                    target_mbps,
                )
                .await
                {
                    tracing::warn!(
                        error = %e,
                        "throughput self-test reverse-direction stream failed to send"
                    );
                }
            });
        }
        PacketType::Keepalive => {
            // No action beyond having been received -- the socket read
            // itself is enough to keep NAT bindings alive.
        }
        PacketType::Disconnect => {
            // `frame` already round-tripped through this link's own
            // authenticated `WgTunnel` (`LinkHandle::wg_recv`) -- a
            // forged Disconnect can't reach here without holding that
            // link's WireGuard keys, so this is a trustworthy signal
            // that the peer is shutting down or restarting. Does *not*
            // shut this side down too (see the module doc comment's
            // "Graceful shutdown" section) -- the peer's own link will
            // simply re-handshake on its own the next time it sends
            // anything, exactly like real WireGuard's lazy reconnection
            // model. There is no app-level rekey/reconnect nudge needed
            // anymore on either role.
            tracing::info!(%from, "peer sent Disconnect");
        }
        PacketType::HandshakeInit | PacketType::HandshakeResp => {
            unreachable!("filtered out above")
        }
    }
}

/// Record one probe as missed outside the normal sweep-timeout path.
///
/// `sweep_tick`/`ProbeTracker` only ever learns about a loss for a probe
/// that was successfully handed to the socket (`tracker.record_sent`,
/// called from `send_probe`'s success path only) and then never got a
/// reply within the timeout. A probe that fails to *send* in the first
/// place never enters that tracking at all, so on its own it can never
/// become a swept miss later -- meaning a link whose socket can no
/// longer send *at all* (as opposed to sending fine but never getting
/// replies, which sweep already covers) would previously stop
/// accumulating `consecutive_misses` the moment whatever probes were
/// already in flight when sending broke had all been swept, however few
/// that happened to be -- often fewer than `down_threshold`, so the link
/// would report `up` forever with its last real stats frozen in place.
/// This is exactly what the `veth_failover` integration test caught:
/// bringing a veth down stops the *client's* sends outright (immediate
/// `ENETDOWN`), while the *server's* sends keep succeeding (its own
/// interface is fine) and time out normally -- so only the server side
/// ever reached `down_threshold` the old way. Called from `link_prober`
/// for both `ProbeSendOutcome::InterfaceGone` and `TransientFailure`:
/// whether or not the failure justifies a reconnect attempt is a
/// separate question (see `ProbeSendOutcome`'s doc comment) from whether
/// it represents a real, present-tense delivery failure the quality
/// hysteresis needs to know about -- it always does.
async fn record_send_failure_as_miss(
    links: &Links,
    idx: usize,
    cfg: &SchedulerConfig,
    scheduler: &Arc<std::sync::Mutex<Scheduler>>,
    peer_primary_link: &PeerPrimaryLink,
) {
    {
        let mut link = links[idx].lock().await;
        link.stats.record_miss();
        monitor::update_link_state(&mut link, cfg);
    }
    let snap = link::snapshot_links(links).await;
    let peer_primary_index = resolve_peer_primary_index(&snap, peer_primary_link);
    let mut sched = scheduler.lock().unwrap();
    sched.refresh(&snap, cfg, peer_primary_index);
}

/// Outcome of one `send_probe` attempt. Deliberately more granular than a
/// plain success/failure bool so `link_prober` only counts the failure
/// kind that actually justifies a reconnect toward
/// `RECONNECT_FAILURE_THRESHOLD` -- see `link::is_interface_gone_error`'s
/// doc comment for the ENODEV/ENETDOWN distinction this is built on.
enum ProbeSendOutcome {
    /// Sent successfully -- resets the reconnect-failure counter.
    Sent,
    /// Nothing to send yet (no remote learned on this link), or the send
    /// was skipped for a reason unrelated to the socket/interface (e.g.
    /// payload encryption failed). Not a failure, so it neither resets
    /// nor increments the counter.
    Skipped,
    /// The interface itself appears gone (ENODEV/ENXIO) -- counts
    /// toward the reconnect threshold.
    InterfaceGone,
    /// Some other, presumably transient, send failure (e.g. ENETDOWN
    /// from an administratively-down interface, or a momentary route
    /// lookup failure). The existing socket is expected to recover on
    /// its own once the underlying route returns, so this deliberately
    /// does *not* count toward the reconnect threshold either.
    TransientFailure,
}

/// Sends one `Probe` frame on `socket`. See `ProbeSendOutcome` for what
/// each result means to the caller.
async fn send_probe(
    link_id: u8,
    links: &Links,
    idx: usize,
    probe_seq_counter: &AtomicU32,
    tracker: &mut ProbeTracker,
) -> ProbeSendOutcome {
    // A fresh handle from the live `Link`, not one captured once at task
    // startup -- `remote` is a plain (non-shared) field on `LinkHandle`,
    // so a stale captured copy would never observe a remote address
    // learned later (e.g. a server-mode link whose peer address is only
    // known once the client's first authenticated frame arrives). See
    // `pick_link`'s own comment for the same reasoning.
    let handle = links[idx].lock().await.handle();

    let probe_seq = probe_seq_counter.fetch_add(1, Ordering::Relaxed);
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let payload = ProbePayload {
        probe_seq,
        send_ts_ns: now_ns,
    }
    .encode();

    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    Header {
        ptype: PacketType::Probe,
        link_id,
        seq: next_send_seq(),
    }
    .encode(&mut frame);
    frame.extend_from_slice(&payload);

    match handle.wg_send(&frame).await {
        // A Probe belongs to no FEC group, and the probe tracker's own
        // loss accounting already treats an unanswered probe as lost --
        // which is exactly what a substituted (handshake) send produces,
        // so no separate handling is needed for `wg_send`'s new bool.
        Ok(_carried) => {
            tracker.record_sent(probe_seq);
            ProbeSendOutcome::Sent
        }
        Err(MlvpnError::Io(e)) if is_interface_gone_error(&e) => ProbeSendOutcome::InterfaceGone,
        Err(MlvpnError::Io(e)) => {
            tracing::debug!(
                link_id,
                error = %e,
                "probe send error (transient, not reconnecting)"
            );
            ProbeSendOutcome::TransientFailure
        }
        // Not a socket problem (e.g. no remote learned yet) -- see
        // `ProbeSendOutcome::Skipped`'s doc comment.
        Err(_) => ProbeSendOutcome::Skipped,
    }
}

/// Send this link's current locally-measured stats to the peer, so their
/// `mlvpn-tui` can show a full-duplex view instead of only what they
/// measure themselves. See `PacketType::StatsShare` and `StatsPayload`'s
/// doc comments in `protocol.rs` for the wire format and design
/// rationale.
async fn send_stats_share(link_id: u8, links: &Links, idx: usize) {
    let (handle, payload) = {
        let link = links[idx].lock().await;
        if link.remote.is_none() {
            return;
        }
        let payload = StatsPayload {
            name: StatsPayload::encode_name(&link.config.name),
            rtt_ms: link.stats.rtt_ms.get().unwrap_or(0.0) as f32,
            jitter_ms: link.stats.jitter_ms.get().unwrap_or(0.0) as f32,
            loss_pct: (link.stats.loss_rate.get().unwrap_or(0.0) * 100.0) as f32,
            throughput_mbps: link.stats.rx_throughput_mbps.get().unwrap_or(0.0) as f32,
            state: link.state.to_wire(),
            rx_bytes: Some(link.stats.rx_bytes),
        };
        (link.handle(), payload)
    };

    let plaintext = payload.encode();
    let mut frame = Vec::with_capacity(HEADER_LEN + plaintext.len());
    Header {
        ptype: PacketType::StatsShare,
        link_id,
        seq: next_send_seq(),
    }
    .encode(&mut frame);
    frame.extend_from_slice(&plaintext);

    let _ = handle.wg_send(&frame).await;
}

/// Send our own `mlvpnd` version to the peer -- see `PacketType::VersionInfo`'s
/// doc comment for why. Piggybacked on the same per-link timer as
/// `send_stats_share` rather than a dedicated interval: it's small,
/// tunnel-wide (not really per-link) information, but sending it once
/// per link per tick costs nothing extra worth a new timer, and gives
/// the same multi-link redundancy `StatsShare` already gets for free.
async fn send_version_info(
    link_id: u8,
    links: &Links,
    idx: usize,
    local_capability_mtu: &LiveMtu,
    live_mtu: &LiveMtu,
    scheduler: &Arc<std::sync::Mutex<Scheduler>>,
) {
    let handle = {
        let link = links[idx].lock().await;
        if link.remote.is_none() {
            return;
        }
        link.handle()
    };

    // The scheduler's `primary()` is a LOCAL `Links`-array index -- not a
    // value the peer can meaningfully interpret, since `link_id`
    // numbering is per-host (see `PeerPrimaryLink`'s doc comment). Advertise
    // the primary link's *name* instead, which both sides can agree on.
    let primary_link_name = {
        let primary_idx = scheduler.lock().unwrap().primary();
        match primary_idx {
            Some(idx) => match links.get(idx) {
                Some(l) => l.lock().await.config.name.clone(),
                None => String::new(),
            },
            None => String::new(),
        }
    };

    let payload = VersionInfoPayload {
        version: VersionInfoPayload::encode_version(&crate::version()),
        tunnel_mtu: local_capability_mtu.load(std::sync::atomic::Ordering::Relaxed),
        live_tunnel_mtu: live_mtu.load(std::sync::atomic::Ordering::Relaxed),
        primary_link_name: VersionInfoPayload::encode_link_name(&primary_link_name),
    };
    let plaintext = payload.encode();
    let mut frame = Vec::with_capacity(HEADER_LEN + plaintext.len());
    Header {
        ptype: PacketType::VersionInfo,
        link_id,
        seq: next_send_seq(),
    }
    .encode(&mut frame);
    frame.extend_from_slice(&plaintext);

    let _ = handle.wg_send(&frame).await;
}

/// The high-watermark is stored as `seq + 1` (0 = nothing delivered yet) so
/// "advance to at least `seq`" is a single `fetch_max`. `seq` comes from
/// `next_send_seq`, a counter that cannot realistically reach `u64::MAX`.
fn advance_watermark(wm: &AtomicU64, seq: u64) {
    wm.fetch_max(seq.saturating_add(1), Ordering::Relaxed);
}

fn watermark_value(wm: &AtomicU64) -> Option<u64> {
    wm.load(Ordering::Relaxed).checked_sub(1)
}

/// Sorts decrypted Data payloads by global session sequence number and
/// releases them to the TUN device as soon as the `rx_pipeline` drains
/// its channel batch. It never holds a frame back waiting for a missing
/// predecessor: a held frame stalls everything behind it (head-of-line
/// blocking), which measured as a 4.6x bonded TCP download loss when
/// cross-link skew made some frame arrive tens of milliseconds late.
/// Ordering is therefore best-effort within one batch; a frame that
/// arrives after a higher seq was already delivered is counted as `late`
/// and delivered anyway.
struct ReorderBuffer {
    window: Duration,
    /// Highest Data-frame `hdr.seq` delivered so far, or `None` before
    /// the very first frame. A frame whose `seq` exceeds this can never
    /// be "late" relative to anything already delivered -- see
    /// `drain_ready`'s doc comment for the full reasoning behind this
    /// model replacing the old "must equal next_expected" one.
    ///
    /// No longer has a session-boundary reset (removed in task 5, along
    /// with the rest of the shared Noise session): `seq` is now issued
    /// by `next_send_seq`, a single tunnel-lifetime `AtomicU64` that
    /// never resets, and each link's own WireGuard session rekeys
    /// entirely internally (invisibly to this module) -- there is no
    /// longer an app-level discontinuity in `seq` for this buffer to
    /// guard against the way the old per-rekey `crypto::Session::next_send_seq`
    /// restarting near zero required.
    high_watermark: AtomicU64,
    pending: BTreeMap<u64, (tokio::time::Instant, Vec<u8>)>,
    counters: ReorderCounters,
}

/// Lifetime reorder-buffer observations, plain integers because the
/// buffer is owned by the single `rx_pipeline` task; `publish` copies
/// them into the shared `RxPipelineStats` on the pipeline's flush tick.
#[derive(Default)]
struct ReorderCounters {
    /// Frames inserted at or below the delivered watermark (genuine
    /// cross-link reordering).
    late: u64,
    /// A seq inserted again while its first copy was still buffered.
    duplicate: u64,
    /// Always 0 since late frames are delivered immediately; kept so the
    /// telemetry schema does not change.
    timeout: u64,
    /// EWMA (alpha 1/8) and lifetime peak of how long a buffered frame
    /// waited before delivery, in microseconds.
    wait_recent_us: u64,
    wait_max_us: u64,
    max_depth: u64,
}

impl ReorderBuffer {
    fn new(window_ms: u64) -> Self {
        Self {
            window: Duration::from_millis(window_ms),
            high_watermark: AtomicU64::new(0),
            pending: BTreeMap::new(),
            counters: ReorderCounters::default(),
        }
    }

    fn publish(&self, stats: &crate::telemetry::RxPipelineStats) {
        let c = &self.counters;
        stats
            .window_ms
            .store(self.window.as_millis() as u64, Ordering::Relaxed);
        stats
            .depth
            .store(self.pending.len() as u64, Ordering::Relaxed);
        stats.max_depth.store(c.max_depth, Ordering::Relaxed);
        stats
            .wait_recent_us
            .store(c.wait_recent_us, Ordering::Relaxed);
        stats.wait_max_us.store(c.wait_max_us, Ordering::Relaxed);
        stats.late_total.store(c.late, Ordering::Relaxed);
        stats.duplicate_total.store(c.duplicate, Ordering::Relaxed);
        stats.timeout_total.store(c.timeout, Ordering::Relaxed);
    }

    /// Bypass-mode counterpart to `insert`+`drain_ready`: used when
    /// `Scheduler::primary()` is settled on a single active link (see
    /// `handle_incoming`'s `PacketType::Data` arm), where every packet
    /// is delivered to `tun` immediately, matching WireGuard's own
    /// architecture for single-path tunnels -- no time-based buffering
    /// at all, since there's no cross-link reordering to protect
    /// against with only one active link.
    ///
    /// Advances `high_watermark` the same way `drain_ready` does for a
    /// forward-progress frame, WITHOUT touching `pending` -- keeps the
    /// watermark accurate for whenever buffered mode resumes (the
    /// primary goes Down, falling back to multi-link delivery).
    fn note_delivered(&self, seq: u64) {
        advance_watermark(&self.high_watermark, seq);
    }

    #[cfg(test)]
    fn window_ms(&self) -> u64 {
        self.window.as_millis() as u64
    }

    /// Highest Data `seq` delivered so far, or `None` before any.
    fn watermark(&self) -> Option<u64> {
        watermark_value(&self.high_watermark)
    }

    /// Replace the window in effect from this point on. Deliberately
    /// does not touch `pending` or `high_watermark` -- a packet already
    /// sitting in the buffer keeps whichever deadline it was inserted
    /// with (`drain_ready` compares each entry's own `sent_at` against
    /// `self.window` freshly on every call, so a change here applies to
    /// every future comparison immediately, old and new entries alike;
    /// there is no separately stored per-entry deadline to reconcile).
    fn set_window(&mut self, window_ms: u64) {
        self.window = Duration::from_millis(window_ms);
    }

    fn insert(&mut self, seq: u64, payload: Vec<u8>) {
        if self.watermark().is_some_and(|wm| seq <= wm) {
            self.counters.late += 1;
        }
        if self
            .pending
            .insert(seq, (tokio::time::Instant::now(), payload))
            .is_some()
        {
            self.counters.duplicate += 1;
        }
        self.counters.max_depth = self.counters.max_depth.max(self.pending.len() as u64);
    }

    /// Drain every pending frame in ascending seq order.
    ///
    /// `hdr.seq` is shared by every packet type sent over the session
    /// (Data, Probe, StatsShare, ...), so Data seqs are never contiguous
    /// and "wait for the next integer" can never be satisfied. Beyond
    /// that, holding a below-watermark frame for `window` blocks every
    /// frame behind it, so nothing is held: the sort only repairs
    /// reordering that happened inside one batch of `RX_PIPELINE_BATCH`
    /// events. `window` is retained for config/telemetry compatibility
    /// but no longer delays delivery.
    fn drain_ready(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let now = tokio::time::Instant::now();

        while let Some((&seq, _)) = self.pending.iter().next() {
            let (sent_at, payload) = self.pending.remove(&seq).unwrap();
            let waited_us = now.duration_since(sent_at).as_micros() as u64;
            let c = &mut self.counters;
            c.wait_recent_us = c.wait_recent_us - c.wait_recent_us / 8 + waited_us / 8;
            c.wait_max_us = c.wait_max_us.max(waited_us);
            out.push(payload);
            self.note_delivered(seq);
        }
        out
    }
}

/// Capacity of the bounded channel from every `link_receiver` to the
/// single `rx_pipeline` owner. Sized (8192, up from 1024) so a bonded
/// download burst never overflows it while the owner is busy writing to
/// the TUN device -- 1024 dropped packets at ~500 Mbps; a full channel drops the
/// packet and counts it (see `RxPipelineTx::deliver`) rather than
/// blocking a receiver, which would also stall that link's probe and
/// control-frame handling.
const RX_PIPELINE_CAPACITY: usize = 8192;

/// Max events `rx_pipeline` takes from its channel per wakeup.
const RX_PIPELINE_BATCH: usize = 64;

/// How often `rx_pipeline` flushes aged-out reorder-buffer stragglers.
const REORDER_FLUSH_INTERVAL: Duration = Duration::from_millis(10);

/// How often `rx_pipeline` runs `FecRecoveryBuffer`'s maintenance pass
/// (ageing out retained plaintexts, rotating seen-seq generations).
/// Much slower than the reorder flush: nothing is waiting on it and the
/// timescales it manages are seconds.
const FEC_EXPIRY_INTERVAL: Duration = Duration::from_millis(250);

/// How often `rx_pipeline` reports (and resets) its overflow counter.
const RX_PIPELINE_DROP_REPORT_INTERVAL: Duration = Duration::from_secs(2);

/// What a `link_receiver` hands to the `rx_pipeline` owner. Only frames
/// that need FEC/reorder/TUN-delivery state go through here; probes,
/// stats and every other control frame are still handled inline by the
/// receiving link's own task.
enum RxEvent {
    Data { seq: u64, plaintext: Vec<u8> },
    Parity(fec::ParityKind, crate::protocol::FecParityPayload),
    SetReorderWindow(u64),
}

/// Producer half of the receive pipeline, cloned into every
/// `link_receiver`.
#[derive(Clone)]
struct RxPipelineTx {
    tx: mpsc::Sender<RxEvent>,
    dropped: Arc<AtomicU64>,
}

impl RxPipelineTx {
    /// Non-blocking hand-off. A full channel means the TUN write side is
    /// slower than the combined links' receive rate; dropping here is the
    /// same outcome the kernel's socket receive buffer would have had,
    /// but it keeps this link's task free to answer probes.
    fn deliver(&self, ev: RxEvent) {
        if self.tx.try_send(ev).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Where the receive pipeline writes delivered packets. The TUN device in
/// production; a plain channel in unit tests, which can't open a TUN.
trait RxSink: Send + Sync + 'static {
    fn send(&self, pkt: &[u8]) -> impl std::future::Future<Output = ()> + Send;
}

impl RxSink for AsyncDevice {
    async fn send(&self, pkt: &[u8]) {
        let _ = AsyncDevice::send(self, pkt).await;
    }
}

/// The single owner of all receive-side delivery state: the
/// `ReorderBuffer`, the `FecRecoveryBuffer`, and the only writer of
/// received packets to the TUN device. Every link's receiver task feeds
/// it through one bounded channel, so none of this state needs a lock
/// and a recovered or reordered frame can never be delivered
/// concurrently with another link's frame.
///
/// Also performs the periodic maintenance that used to be separate
/// tasks: flushing reorder stragglers (`REORDER_FLUSH_INTERVAL`) and
/// expiring FEC state (`FEC_EXPIRY_INTERVAL`, only when FEC is enabled).
/// Returns only when every sender is dropped, i.e. during shutdown.
#[allow(clippy::too_many_arguments)]
async fn rx_pipeline<S: RxSink>(
    mut rx: mpsc::Receiver<RxEvent>,
    tun: Arc<S>,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    reorder_window_ms: u64,
    mut fec_recovery: fec::FecRecoveryBuffer,
    fec_enabled: bool,
    fec_recovered_total: Arc<AtomicU64>,
    fec_unrecoverable_total: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    stats: Arc<crate::telemetry::RxPipelineStats>,
) {
    let primary = scheduler.lock().unwrap().primary_flag();
    let mut reorder = ReorderBuffer::new(reorder_window_ms);
    let mut flush_tick = interval(REORDER_FLUSH_INTERVAL);
    let mut fec_tick = interval(FEC_EXPIRY_INTERVAL);
    let mut report_tick = interval(RX_PIPELINE_DROP_REPORT_INTERVAL);
    let mut batch: Vec<RxEvent> = Vec::with_capacity(RX_PIPELINE_BATCH);
    loop {
        tokio::select! {
            n = rx.recv_many(&mut batch, RX_PIPELINE_BATCH) => {
                if n == 0 {
                    return;
                }
                let batch_start = Instant::now();
                stats.max_backlog.fetch_max((rx.len() + n) as u64, Ordering::Relaxed);
                for ev in batch.drain(..) {
                    match ev {
                        RxEvent::Data { seq, plaintext } => {
                            // `observe_data`'s `false` means FEC already
                            // reconstructed and delivered this seq (its
                            // parity frame beat the real copy through a
                            // slower link); delivering it again would put
                            // a byte-identical duplicate IP packet into
                            // the TUN device.
                            if fec_enabled && !fec_recovery.observe_data(seq, &plaintext) {
                                continue;
                            }
                            rx_deliver(&*tun, &primary, &mut reorder, seq, plaintext).await;
                            // A late member can complete a parked
                            // two-erasure group (`fec_parity = 2`).
                            if fec_enabled && fec_recovery.has_late_recoveries() {
                                for (seq, plaintext) in fec_recovery.take_late_recoveries() {
                                    fec_recovered_total.fetch_add(1, Ordering::Relaxed);
                                    rx_deliver(&*tun, &primary, &mut reorder, seq, plaintext).await;
                                }
                            }
                        }
                        RxEvent::Parity(kind, parity) => match fec_recovery.try_recover(kind, &parity) {
                            fec::RecoveryOutcome::Recovered(frames) => {
                                for (seq, plaintext) in frames {
                                    fec_recovered_total.fetch_add(1, Ordering::Relaxed);
                                    rx_deliver(&*tun, &primary, &mut reorder, seq, plaintext).await;
                                }
                            }
                            fec::RecoveryOutcome::Unrecoverable => {
                                fec_unrecoverable_total.fetch_add(1, Ordering::Relaxed);
                            }
                            fec::RecoveryOutcome::AlreadyComplete
                            | fec::RecoveryOutcome::Pending => {}
                        },
                        RxEvent::SetReorderWindow(ms) => reorder.set_window(ms),
                    }
                }
                stats
                    .busy_ns_total
                    .fetch_add(batch_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
            _ = flush_tick.tick() => {
                // Flushes entries that would otherwise sit until they age
                // out with no new packet arriving to trigger the inline
                // `insert` + `drain_ready` in `rx_deliver`.
                for pkt in reorder.drain_ready() {
                    tun.send(&pkt).await;
                }
                reorder.publish(&stats);
            }
            _ = fec_tick.tick(), if fec_enabled => {
                let given_up = fec_recovery.tick(Instant::now());
                if given_up > 0 {
                    fec_unrecoverable_total.fetch_add(given_up, Ordering::Relaxed);
                }
            }
            _ = report_tick.tick() => {
                let n = dropped.swap(0, Ordering::Relaxed);
                if n > 0 {
                    stats.dropped_total.fetch_add(n, Ordering::Relaxed);
                    tracing::warn!(
                        dropped_packets = n,
                        window_secs = RX_PIPELINE_DROP_REPORT_INTERVAL.as_secs(),
                        queue_capacity = RX_PIPELINE_CAPACITY,
                        "receive pipeline overflowed: writing received packets to the TUN device is falling behind the links' receive rate, so packets were dropped here"
                    );
                }
            }
        }
    }
}

/// Delivers one Data frame (real or FEC-recovered) to the TUN device:
/// immediately when a single link is the settled primary (no cross-link
/// reordering is possible, matching WireGuard's own single-path
/// architecture -- see `ReorderBuffer::note_delivered`), otherwise via
/// the reorder buffer. The primary check is read once per packet, not
/// cached, so a mid-stream transition is picked up on the very next one.
async fn rx_deliver<S: RxSink>(
    tun: &S,
    primary: &PrimaryFlag,
    reorder: &mut ReorderBuffer,
    seq: u64,
    plaintext: Vec<u8>,
) {
    if primary.is_set() {
        reorder.note_delivered(seq);
        tun.send(&plaintext).await;
    } else {
        reorder.insert(seq, plaintext);
        for pkt in reorder.drain_ready() {
            tun.send(&pkt).await;
        }
    }
}

/// How often `reorder_tuning_loop` re-evaluates the reorder window.
/// Deliberately much slower than the probe interval or the pipeline's
/// own 10ms flush tick -- this is tuning a *policy* parameter from an EWMA
/// that already smooths out single-sample noise, not reacting to
/// individual packets, so there is nothing to gain from checking more
/// often than a link's characteristics could plausibly have drifted.
const REORDER_TUNING_INTERVAL: Duration = Duration::from_secs(30);

/// Pure suggestion function, factored out of `reorder_tuning_loop` so
/// the actual math is unit-testable without a live `Link`/socket (the
/// same reasoning `scheduler.rs`'s `RateLimitState` tests document).
/// `rtts` is each currently-Up link's EWMA RTT in milliseconds. Returns
/// `None` if there are fewer than two samples -- with zero or one Up
/// link there is no *spread* to react to, so the window is left exactly
/// where it is rather than collapsing to some default.
///
/// The suggested value is 1.5x the spread between the fastest and
/// slowest Up link, plus a fixed 10ms of headroom, clamped to
/// `[min_ms, max_ms]`. 1.5x plus headroom is deliberately generous
/// rather than tight: the cost of the window being a little too wide is
/// a little extra worst-case latency on a packet that needed to wait
/// for a genuinely lost peer anyway (bounded by `max_ms` regardless),
/// while the cost of it being too narrow is out-of-order delivery on
/// every packet that arrives on the slower link even under perfectly
/// normal conditions -- an asymmetric cost that favors erring wide.
/// Multiplier applied to cross-link RTT spread when computing a
/// suggested `reorder_window_ms` -- see `suggest_reorder_window_ms`'s
/// doc comment for the full reasoning. Unchanged from this project's
/// original reorder-window design.
const REORDER_WINDOW_SPREAD_MULTIPLIER: f64 = 1.5;

/// Multiplier applied to a link's own `jitter_ms` when computing a
/// suggested `reorder_window_ms`. Deliberately mirrors TCP's own RTO
/// formula (Jacobson/Karels: `RTO = SRTT + 4*RTTVAR`) -- `jitter_ms` is
/// structurally the same quantity RTTVAR is (an EWMA of consecutive-
/// sample deltas), and this feature exists specifically to stop
/// tripping TCP's own RTO estimate with tunnel-induced latency
/// variance, so borrowing TCP's own well-established multiplier is a
/// principled choice rather than an arbitrary one.
const REORDER_WINDOW_JITTER_MULTIPLIER: f64 = 4.0;

/// Fixed headroom added on top of the spread/jitter terms regardless
/// of how small either is -- guarantees a small amount of buffering
/// even when both links are perfectly stable, since a real network
/// path is never perfectly jitter-free in practice.
const REORDER_WINDOW_FLOOR_MS: f64 = 10.0;

fn suggest_reorder_window_ms(
    scores: &[LinkScore],
    primary_idx: Option<usize>,
    min_ms: u64,
    max_ms: u64,
) -> Option<u64> {
    let up: Vec<&LinkScore> = scores.iter().filter(|s| s.state == LinkState::Up).collect();
    if up.is_empty() {
        return None;
    }

    // A settled primary is only meaningful if it's actually in the
    // current Up-links snapshot -- a stale/rare-transient index (the
    // primary just went Down, not yet reselected) falls through to the
    // multi-link branch below rather than being trusted.
    let settled_primary = primary_idx.and_then(|idx| up.iter().find(|s| s.link_index == idx));

    let (spread_term, jitter_term) = if let Some(primary) = settled_primary {
        // Settled single-link delivery: no cross-link skew is possible,
        // only this one link's own timing variance matters.
        let jitter = primary.jitter_ms.unwrap_or(0.0);
        (0.0, jitter * REORDER_WINDOW_JITTER_MULTIPLIER)
    } else {
        // Multi-link delivery is genuinely possible right now (plain
        // SWRR, redundant_mode, or a primary/follow mode with no
        // primary settled yet).
        let rtts: Vec<f64> = up.iter().filter_map(|s| s.rtt_ms).collect();
        let spread = if rtts.len() >= 2 {
            let min_rtt = rtts.iter().cloned().fold(f64::MAX, f64::min);
            let max_rtt = rtts.iter().cloned().fold(f64::MIN, f64::max);
            max_rtt - min_rtt
        } else {
            0.0
        };
        let worst_jitter = up
            .iter()
            .filter_map(|s| s.jitter_ms)
            .fold(0.0_f64, f64::max);
        (
            spread * REORDER_WINDOW_SPREAD_MULTIPLIER,
            worst_jitter * REORDER_WINDOW_JITTER_MULTIPLIER,
        )
    };

    let suggested = spread_term + jitter_term + REORDER_WINDOW_FLOOR_MS;
    Some(suggested.clamp(min_ms as f64, max_ms as f64).round() as u64)
}

/// No-op unless `scheduler.auto_tune_reorder_window` is enabled (see
/// that field's doc comment in `config.rs`) -- returns immediately in
/// that case rather than the caller needing to conditionally spawn this
/// task at all. Periodically recomputes a suggested `reorder_window_ms`
/// (`suggest_reorder_window_ms`) and applies it only if it clears a
/// hysteresis threshold against the value currently in effect, so a
/// single noisy sample can't chase the window back and forth every
/// tick -- the same principle as the existing Up/Down hysteresis in
/// `monitor.rs`. The suggestion itself is scheduling-mode-aware: with a
/// settled `Scheduler::primary()` (`primary_link_mode`/
/// `follow_peer_primary`), it's driven entirely by that one link's own
/// jitter, not RTT spread across every Up link -- see
/// `suggest_reorder_window_ms`'s own doc comment for the full reasoning.
/// See `ARCHITECTURE.md` §7 for the original design this extends.
async fn reorder_tuning_loop(
    links: Links,
    rx_pipeline: RxPipelineTx,
    cfg: SchedulerConfig,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
) {
    if !cfg.auto_tune_reorder_window {
        return;
    }

    // This loop is the only thing that ever changes the window, so it
    // tracks the value in effect locally instead of asking the pipeline.
    let mut current = cfg.reorder_window_ms;

    let mut tick = interval(REORDER_TUNING_INTERVAL);
    loop {
        tick.tick().await;

        let scores = link::snapshot_scores(&links).await;
        let primary_idx = scheduler.lock().unwrap().primary();

        let Some(suggested) = suggest_reorder_window_ms(
            &scores,
            primary_idx,
            cfg.reorder_window_min_ms,
            cfg.reorder_window_max_ms,
        ) else {
            continue;
        };

        // Hysteresis: only move if the suggestion differs from the
        // current value by more than 20% of it (minimum 10ms, so a
        // small current window still has a meaningful floor to clear).
        let threshold = ((current as f64) * 0.2).max(10.0) as u64;
        if current.abs_diff(suggested) > threshold {
            tracing::info!(
                previous_ms = current,
                new_ms = suggested,
                "auto-tuned reorder_window_ms"
            );
            // Control message, not a droppable packet: wait for room.
            if rx_pipeline
                .tx
                .send(RxEvent::SetReorderWindow(suggested))
                .await
                .is_err()
            {
                return;
            }
            current = suggested;
        }
    }
}

#[cfg(test)]
mod fec_gate_tests {
    use super::*;

    fn group() -> fec::FecGroup {
        let mut sender = fec::FecSender::new(2, 1);
        assert!(sender.accumulate(1, b"aa", 0).is_none());
        sender
            .accumulate(2, b"bb", 1)
            .expect("2nd member completes a 2-group")
    }

    fn gate(cap: usize) -> (Arc<FecGate>, mpsc::Receiver<fec::FecGroup>, Arc<AtomicU64>) {
        let (tx, rx) = mpsc::channel(cap);
        let unrecoverable = Arc::new(AtomicU64::new(0));
        (FecGate::new(tx, unrecoverable.clone()), rx, unrecoverable)
    }

    fn carried(g: &Arc<FecGate>) -> FecMember {
        let mut m = g.join();
        m.mark_carried();
        m
    }

    #[test]
    fn parity_is_released_once_every_member_reached_the_wire() {
        let (g, mut rx, unrec) = gate(4);
        let a = carried(&g);
        let b = carried(&g);
        g.seal(group());
        // Sealed but members still outstanding: nothing yet.
        assert!(rx.try_recv().is_err());
        drop(a);
        assert!(rx.try_recv().is_err());
        drop(b);
        assert!(
            rx.try_recv().is_ok(),
            "last resolved member releases the group"
        );
        assert!(rx.try_recv().is_err(), "released exactly once");
        assert_eq!(unrec.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn members_resolving_before_the_seal_wait_for_it() {
        let (g, mut rx, _) = gate(4);
        drop(carried(&g));
        drop(carried(&g));
        assert!(
            rx.try_recv().is_err(),
            "the group is not complete until the owner seals it"
        );
        g.seal(group());
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn a_member_that_never_reached_the_wire_suppresses_parity() {
        // Dropped after queue acceptance, or substituted by a handshake
        // datagram: either way `mark_carried` is never called.
        let (g, mut rx, unrec) = gate(4);
        drop(carried(&g));
        drop(g.join());
        g.seal(group());
        assert!(
            rx.try_recv().is_err(),
            "a phantom member must poison the group"
        );
        assert_eq!(unrec.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_full_ready_queue_counts_the_group_as_unrecoverable() {
        let (tx, _rx) = mpsc::channel(1);
        let unrec = Arc::new(AtomicU64::new(0));
        let g1 = FecGate::new(tx.clone(), unrec.clone());
        g1.seal(group());
        let g2 = FecGate::new(tx, unrec.clone());
        g2.seal(group());
        assert_eq!(unrec.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_member_moved_to_another_thread_still_releases_the_group() {
        let (g, mut rx, _) = gate(4);
        let m = carried(&g);
        g.seal(group());
        std::thread::spawn(move || drop(m)).join().unwrap();
        assert!(rx.try_recv().is_ok());
    }
}

#[cfg(test)]
mod spill_candidate_tests {
    use super::*;

    #[test]
    fn spill_prefers_most_free_slots_and_skips_origin_and_full_queues() {
        // link 0 is the origin, link 1 is full, 2 has the most room.
        assert_eq!(
            spill_candidates(&[10, 0, 100, 50], &[1_000_000; 4], 0),
            vec![2, 3]
        );
    }

    #[test]
    fn spill_breaks_ties_by_index() {
        assert_eq!(
            spill_candidates(&[5, 9, 9, 9], &[1_000_000; 4], 0),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn spill_skips_links_with_collapsed_delivery() {
        assert_eq!(
            spill_candidates(&[10, 100, 50], &[1_000_000, 1_000, 900_000], 0),
            vec![2]
        );
    }

    #[test]
    fn spill_has_no_candidate_when_everything_else_is_full() {
        assert!(spill_candidates(&[128, 0, 0], &[1_000_000; 3], 0).is_empty());
        assert!(spill_candidates(&[128], &[1_000_000], 0).is_empty());
    }

    fn job() -> TxJob {
        TxJob::new(PacketType::Data, 1, vec![0; 10])
    }

    #[test]
    fn try_enqueue_tracks_depth_and_undoes_it_when_the_queue_is_full() {
        let (tx, _rx) = mpsc::channel::<TxJob>(2);
        let q = LinkTx {
            tx,
            counters: Arc::new(link::TxCounters::new()),
        };
        assert!(try_enqueue(&q, job()).is_ok());
        assert!(try_enqueue(&q, job()).is_ok());
        assert_eq!(q.counters.depth.load(Ordering::Relaxed), 2);
        assert!(matches!(try_enqueue(&q, job()), Err(TrySendError::Full(_))));
        assert_eq!(
            q.counters.depth.load(Ordering::Relaxed),
            2,
            "a rejected enqueue must not count as queued"
        );
    }
}

#[cfg(test)]
mod reorder_tuning_tests {
    use super::*;

    /// `ReorderBuffer::set_window`/`window_ms` need a real `Link` to
    /// exercise via `reorder_tuning_loop` itself -- covered by the
    /// integration tests instead (same reasoning `scheduler.rs`'s own
    /// tests document for `swrr_pick_under_cap`). This covers the
    /// buffer's own mutator/getter pair in isolation.
    #[test]
    fn reorder_buffer_window_is_readable_and_settable() {
        let mut rb = ReorderBuffer::new(50);
        assert_eq!(rb.window_ms(), 50);
        rb.set_window(120);
        assert_eq!(rb.window_ms(), 120);
    }

    #[test]
    fn note_delivered_advances_watermark_without_touching_pending() {
        let mut buf = ReorderBuffer::new(50);
        buf.insert(10, vec![10]);
        assert_eq!(buf.drain_ready(), vec![vec![10]]);
        assert_eq!(buf.watermark(), Some(10));

        buf.note_delivered(100);
        assert_eq!(buf.watermark(), Some(100));
        assert!(buf.pending.is_empty());
    }

    #[test]
    fn note_delivered_advances_watermark_monotonically() {
        let buf = ReorderBuffer::new(50);
        buf.note_delivered(10);
        buf.note_delivered(50);
        buf.note_delivered(20);
        assert_eq!(buf.watermark(), Some(50));
    }

    #[test]
    fn bypass_then_resume_keeps_watermark_and_delivers_late_frames() {
        let mut buf = ReorderBuffer::new(50);
        buf.insert(10, vec![10]);
        assert_eq!(buf.drain_ready(), vec![vec![10]]);

        buf.note_delivered(500);

        buf.insert(200, vec![200]);
        assert_eq!(buf.drain_ready(), vec![vec![200]]);
        assert_eq!(buf.watermark(), Some(500));
        assert_eq!(buf.counters.late, 1);

        buf.insert(600, vec![88]);
        assert_eq!(buf.drain_ready(), vec![vec![88]]);
        assert_eq!(buf.watermark(), Some(600));
    }

    #[test]
    fn reorder_buffer_delivers_non_contiguous_seqs_immediately() {
        // The actual regression this fix targets: real Data frames never
        // arrive with contiguous sequence numbers, because every other
        // packet type (probes, stats, self-tests) shares the same counter.
        // A large, irregular gap between each Data frame's seq must never
        // cause a wait -- every one of these must come back out of
        // drain_ready() on the very first call after insert(), with no
        // sleep/staleness needed.
        let mut buf = ReorderBuffer::new(50);
        for seq in [7u64, 19, 20, 1000, 1001, 5_000_000] {
            buf.insert(seq, vec![seq as u8]);
            let delivered = buf.drain_ready();
            assert_eq!(
                delivered,
                vec![vec![seq as u8]],
                "seq {seq} should deliver immediately despite the gap from the previous seq"
            );
        }
    }

    #[test]
    fn reorder_buffer_first_frame_of_session_delivers_immediately_regardless_of_seq() {
        // ReorderBuffer::new's old hardcoded `next_expected: 0` meant a
        // session's very first Data frame (whose real seq is essentially
        // never 0, since the handshake and any probes already consumed
        // sequence numbers) was itself misjudged as "not next" and forced
        // through the stale-timeout path. The very first frame, at any
        // seq value, must always take the fast path.
        let mut buf = ReorderBuffer::new(50);
        buf.insert(42_000, vec![1, 2, 3]);
        assert_eq!(buf.drain_ready(), vec![vec![1, 2, 3]]);
    }

    #[test]
    fn reorder_buffer_delivers_late_frames_immediately_and_counts_them() {
        let mut buf = ReorderBuffer::new(50);
        buf.insert(10, vec![10]);
        assert_eq!(buf.drain_ready(), vec![vec![10]]);

        buf.insert(5, vec![5]);
        assert_eq!(buf.drain_ready(), vec![vec![5]]);
        assert_eq!(buf.counters.late, 1);
        assert_eq!(buf.watermark(), Some(10));
        assert!(buf.pending.is_empty());
    }

    #[test]
    fn reorder_buffer_sorts_one_batch_by_seq() {
        let mut buf = ReorderBuffer::new(50);
        buf.insert(100, vec![100]);
        assert_eq!(buf.drain_ready(), vec![vec![100]]);

        buf.insert(99, vec![99]);
        buf.insert(98, vec![98]);
        buf.insert(101, vec![101]);
        assert_eq!(buf.drain_ready(), vec![vec![98], vec![99], vec![101]]);
    }

    fn score(link_index: usize, rtt_ms: f64, jitter_ms: f64) -> LinkScore {
        LinkScore {
            link_index,
            state: LinkState::Up,
            admin_disabled: false,
            weight: 1.0,
            bandwidth_cap_mbps: None,
            rtt_ms: Some(rtt_ms),
            jitter_ms: Some(jitter_ms),
            loss_rate: Some(0.0),
            rx_throughput_mbps: None,
            active_bandwidth_mbps: None,
            consecutive_misses: 0,
        }
    }

    #[test]
    fn suggest_reorder_window_needs_at_least_one_sample() {
        assert_eq!(suggest_reorder_window_ms(&[], None, 10, 500), None);
    }

    #[test]
    fn suggest_reorder_window_no_primary_combines_spread_and_worst_jitter() {
        // No settled primary -> multi-link branch. Spread = 30-10 = 20,
        // spread_term = 20 * 1.5 = 30. Worst jitter = 8 (link 1's),
        // jitter_term = 8 * 4.0 = 32. suggested = 30 + 32 + 10 = 72.
        let scores = [score(0, 10.0, 2.0), score(1, 30.0, 8.0)];
        let suggested = suggest_reorder_window_ms(&scores, None, 10, 500)
            .expect("multiple Up links should always produce a suggestion");
        assert_eq!(suggested, 72);
    }

    #[test]
    fn suggest_reorder_window_no_primary_is_symmetric_in_sample_order() {
        let a =
            suggest_reorder_window_ms(&[score(0, 10.0, 2.0), score(1, 30.0, 8.0)], None, 10, 500);
        let b =
            suggest_reorder_window_ms(&[score(1, 30.0, 8.0), score(0, 10.0, 2.0)], None, 10, 500);
        assert_eq!(a, b);
    }

    #[test]
    fn suggest_reorder_window_settled_primary_uses_only_that_links_jitter() {
        // Link 1 is the settled primary with jitter 5 -> jitter_term =
        // 5 * 4.0 = 20, suggested = 0 (no spread) + 20 + 10 = 30. Link
        // 0's wildly different rtt/jitter (a stand-in for e.g. an idle
        // T-Mobile backup) must have zero effect on the result -- this
        // is the exact regression this whole feature exists to fix.
        let scores = [score(0, 250.0, 90.0), score(1, 15.0, 5.0)];
        let suggested = suggest_reorder_window_ms(&scores, Some(1), 10, 500)
            .expect("a settled primary with a jitter sample should always produce a suggestion");
        assert_eq!(suggested, 30);
    }

    #[test]
    fn suggest_reorder_window_settled_primary_missing_jitter_sample_contributes_zero() {
        // Primary link has no jitter sample yet (e.g. just came Up) --
        // must not panic, contributes 0.0, so suggested = floor only.
        let mut only_link = score(0, 15.0, 0.0);
        only_link.jitter_ms = None;
        let suggested = suggest_reorder_window_ms(&[only_link], Some(0), 10, 500).expect(
            "a settled primary should always produce a suggestion even with no jitter sample yet",
        );
        assert_eq!(suggested, 10); // floor only
    }

    #[test]
    fn suggest_reorder_window_primary_not_in_snapshot_falls_back_to_multi_link() {
        // Scheduler says index 5 is primary, but the current Up-links
        // snapshot doesn't contain that index (a rare transient -- the
        // primary just went Down and hasn't been reselected yet). Must
        // fall back to the multi-link branch, not panic.
        let scores = [score(0, 10.0, 2.0), score(1, 30.0, 8.0)];
        let with_stale_primary = suggest_reorder_window_ms(&scores, Some(5), 10, 500);
        let with_no_primary = suggest_reorder_window_ms(&scores, None, 10, 500);
        assert_eq!(with_stale_primary, with_no_primary);
    }

    #[test]
    fn suggest_reorder_window_clamps_to_configured_bounds() {
        // A huge spread should clamp to max_ms, not run away unbounded.
        let scores = [score(0, 5.0, 0.0), score(1, 5000.0, 0.0)];
        let suggested = suggest_reorder_window_ms(&scores, None, 10, 500)
            .expect("multiple Up links should always produce a suggestion");
        assert_eq!(suggested, 500);

        // Even a zero spread/jitter still gets the fixed 10ms floor, but
        // never drops below min_ms.
        let scores = [score(0, 15.0, 0.0), score(1, 15.0, 0.0)];
        let suggested = suggest_reorder_window_ms(&scores, None, 10, 500)
            .expect("multiple Up links should always produce a suggestion");
        assert_eq!(suggested, 10); // (0 * 1.5) + (0 * 4.0) + 10 = 10, and 10 is already the floor
    }
}

#[cfg(test)]
mod probe_interval_tuning_tests {
    use super::*;

    #[test]
    fn any_miss_snaps_straight_back_to_the_floor() {
        // Even a link that had backed all the way off to the ceiling
        // should snap straight back the instant it shows one miss.
        assert_eq!(suggest_probe_interval_ms(200, 2000, 2000, 0, 1), 200);
        assert_eq!(suggest_probe_interval_ms(200, 2000, 850, 3, 1), 200);
    }

    #[test]
    fn stays_put_below_the_backoff_streak_threshold() {
        // 9 consecutive hits: one short of PROBE_BACKOFF_STREAK (10),
        // so nothing should change yet.
        assert_eq!(suggest_probe_interval_ms(200, 2000, 200, 9, 0), 200);
    }

    #[test]
    fn backs_off_by_the_configured_factor_at_the_streak_milestone() {
        // 200 * 1.5 = 300.
        assert_eq!(suggest_probe_interval_ms(200, 2000, 200, 10, 0), 300);
        // Continuing to back off from a non-floor current value works
        // the same way: 300 * 1.5 = 450.
        assert_eq!(suggest_probe_interval_ms(200, 2000, 300, 20, 0), 450);
    }

    #[test]
    fn never_backs_off_past_the_configured_ceiling() {
        // Already at a value where one more step would overshoot 2000.
        assert_eq!(suggest_probe_interval_ms(200, 2000, 1900, 30, 0), 2000);
        // And once truly at the ceiling, further streak milestones keep
        // it pinned there rather than continuing to grow.
        assert_eq!(suggest_probe_interval_ms(200, 2000, 2000, 40, 0), 2000);
    }

    #[test]
    fn never_suggests_below_the_floor_even_if_current_somehow_was() {
        // Defensive: current_ms below floor_ms shouldn't be possible in
        // practice (nothing else in this module ever sets it there),
        // but the clamp should still hold if it somehow happened.
        assert_eq!(suggest_probe_interval_ms(200, 2000, 100, 5, 0), 200);
    }
}

#[cfg(test)]
mod ewma_alpha_tuning_tests {
    use super::*;

    #[test]
    fn any_miss_jumps_straight_to_the_max() {
        assert_eq!(suggest_ewma_alpha(0.05, 0.5, 0.05, 0, 1), 0.5);
        assert_eq!(suggest_ewma_alpha(0.05, 0.5, 0.2, 7, 1), 0.5);
    }

    #[test]
    fn stays_put_below_the_smoothing_streak_threshold() {
        assert_eq!(suggest_ewma_alpha(0.05, 0.5, 0.2, 9, 0), 0.2);
    }

    #[test]
    fn smooths_down_by_the_configured_step_at_the_streak_milestone() {
        let suggested = suggest_ewma_alpha(0.05, 0.5, 0.2, 10, 0);
        assert!((suggested - 0.18).abs() < 1e-9, "suggested was {suggested}");
    }

    #[test]
    fn never_smooths_below_the_configured_min() {
        // Already right at the point where one more step would
        // undershoot 0.05.
        let suggested = suggest_ewma_alpha(0.05, 0.5, 0.06, 10, 0);
        assert!((suggested - 0.05).abs() < 1e-9, "suggested was {suggested}");
        // And once truly at the floor, further milestones keep it
        // pinned there rather than continuing to shrink.
        let suggested = suggest_ewma_alpha(0.05, 0.5, 0.05, 20, 0);
        assert!((suggested - 0.05).abs() < 1e-9, "suggested was {suggested}");
    }

    #[test]
    fn a_config_change_to_the_bounds_self_corrects_immediately() {
        // current_alpha outside the (new, tighter) bounds should clamp
        // back in on the very next call, no miss required first.
        assert_eq!(suggest_ewma_alpha(0.1, 0.3, 0.5, 3, 0), 0.3);
        assert_eq!(suggest_ewma_alpha(0.1, 0.3, 0.02, 3, 0), 0.1);
    }
}

#[cfg(test)]
mod active_bandwidth_probe_tests {
    use super::*;

    #[test]
    fn computes_expected_rate_for_round_numbers() {
        // 1,000,000 bytes (8,000,000 bits) in exactly 1 second = 8 Mbps.
        let mbps = compute_achieved_mbps(1_000_000, 1.0);
        assert!((mbps - 8.0).abs() < 1e-9, "mbps was {mbps}");
    }

    #[test]
    fn faster_transfer_in_less_time_yields_higher_rate() {
        let slow = compute_achieved_mbps(1_000_000, 2.0);
        let fast = compute_achieved_mbps(1_000_000, 0.5);
        assert!(fast > slow, "fast={fast} slow={slow}");
    }

    #[test]
    fn zero_or_near_zero_elapsed_time_does_not_divide_by_zero() {
        let mbps = compute_achieved_mbps(1_000_000, 0.0);
        assert!(mbps.is_finite(), "mbps was {mbps}");
        assert!(mbps > 0.0);
    }

    #[test]
    fn zero_bytes_yields_zero_rate() {
        assert_eq!(compute_achieved_mbps(0, 1.0), 0.0);
    }

    #[test]
    fn receive_elapsed_measures_to_last_data_not_late_done_arrival() {
        // A late-arriving retried `done` packet (up to
        // THROUGHPUT_TEST_DONE_RETRY_DELAY * 2 after the real last data)
        // must not inflate the measured duration -- elapsed should be
        // pinned to when the last real (non-final) packet arrived, not
        // to this delayed done copy's own arrival.
        let first_seen = Instant::now();
        let last_data_at = first_seen + Duration::from_millis(980); // ~1s stream
        let done_arrived_at = first_seen + Duration::from_millis(1480); // 500ms late retry

        let elapsed = receive_elapsed_secs(first_seen, Some(last_data_at), done_arrived_at);
        assert!(
            (elapsed - 0.98).abs() < 1e-9,
            "expected ~0.98s, got {elapsed}"
        );
    }

    #[test]
    fn receive_elapsed_matches_done_arrival_when_nothing_lost() {
        // Normal case: the done packet itself is the last data point
        // (no loss/retry involved) -- same as measuring straight to its
        // own arrival.
        let first_seen = Instant::now();
        let done_arrived_at = first_seen + Duration::from_millis(1000);

        let elapsed = receive_elapsed_secs(first_seen, Some(done_arrived_at), done_arrived_at);
        assert!(
            (elapsed - 1.0).abs() < 1e-9,
            "expected ~1.0s, got {elapsed}"
        );
    }

    #[test]
    fn receive_elapsed_falls_back_to_done_arrival_for_single_packet_stream() {
        // Degenerate one-packet stream: the very first packet is
        // already flagged done, so there's no earlier last_data_at to
        // measure to -- fall back to this packet's own arrival.
        let first_seen = Instant::now();
        let done_arrived_at = first_seen + Duration::from_millis(5);

        let elapsed = receive_elapsed_secs(first_seen, None, done_arrived_at);
        assert!(
            (elapsed - 0.005).abs() < 1e-9,
            "expected ~0.005s, got {elapsed}"
        );
    }

    #[test]
    fn active_bandwidth_probing_is_off_by_default() {
        // `run()` spawns `active_bandwidth_prober` unconditionally for
        // every link (same "spawn unconditionally, check inside"
        // pattern as `reorder_tuning_loop`), and the very first thing
        // that function does is return immediately when this is false
        // -- so an unmodified default config must keep it false, or
        // every tunnel would start sending synthetic probe traffic
        // with no explicit opt-in.
        assert!(!SchedulerConfig::default().active_bandwidth_probing);
    }

    #[test]
    fn target_elapsed_for_bytes_matches_target_rate() {
        // 1250 bytes = 10,000 bits. At 10 Mbps, one packet's worth of
        // bits should take 1 millisecond to "cost" against the budget --
        // this is the exact formula `send_throughput_test_stream`'s
        // pacing loop uses, not a separate copy of it.
        let delay = target_elapsed_for_bytes(1250, 10.0);
        assert!(
            (delay.as_secs_f64() - 0.001).abs() < 0.000_05,
            "expected ~1ms, got {delay:?}"
        );
    }

    #[test]
    fn target_elapsed_for_bytes_zero_at_very_high_target() {
        // A target far above what any real packet size could saturate
        // should never produce a negative or absurd delay.
        let delay = target_elapsed_for_bytes(1400, 100_000.0);
        assert!(delay.as_secs_f64() < 0.001);
    }

    #[test]
    fn target_elapsed_for_bytes_scales_inversely_with_rate() {
        let slow = target_elapsed_for_bytes(1400, 5.0);
        let fast = target_elapsed_for_bytes(1400, 50.0);
        assert!(slow > fast);
        assert!((slow.as_secs_f64() / fast.as_secs_f64() - 10.0).abs() < 0.01);
    }
}

#[cfg(test)]
mod adaptive_bandwidth_ramp_tests {
    use super::*;

    #[tokio::test]
    async fn ramp_finds_ceiling_partway_through() {
        // Clean up to 16 Mbps (achieves ~100%), then 32 Mbps only achieves
        // 50% (well under the 90% threshold) -- ramp should stop there and
        // report 80% of the last clean step's achieved rate (16.0 * 0.8).
        let result = adaptive_bandwidth_ramp(|target| async move {
            if target <= 16.0 {
                Some(target * 0.98)
            } else {
                Some(target * 0.5)
            }
        })
        .await;

        assert_eq!(result.steps.len(), 5); // 2, 4, 8, 16 all clean, 32 fails
        assert!(result.steps[..4].iter().all(|s| s.clean));
        assert!(!result.steps[4].clean);
        assert!((result.confirmed_mbps - (16.0 * 0.98 * 0.8)).abs() < 0.01);
    }

    #[tokio::test]
    async fn ramp_fails_on_first_step_reports_backoff_of_that_step() {
        // Even the very first (lowest, 2 Mbps) step is bad -- there's no
        // earlier clean step to back off from, so the result is 80% of
        // whatever this failing step itself achieved (still better than
        // reporting 0, which would make an already-struggling link look
        // completely dead to the scheduler).
        let result = adaptive_bandwidth_ramp(|_target| async move { Some(0.3) }).await;

        assert_eq!(result.steps.len(), 1);
        assert!(!result.steps[0].clean);
        assert!((result.confirmed_mbps - (0.3 * 0.8)).abs() < 0.01);
    }

    #[tokio::test]
    async fn ramp_stops_at_safety_cap_when_link_never_saturates() {
        // A genuinely very fast link: every step up to the 12-step cap
        // stays clean. Result is the last step's achieved rate (no backoff
        // applied -- nothing was ever found to back off from).
        let result = adaptive_bandwidth_ramp(|target| async move { Some(target * 0.99) }).await;

        assert_eq!(result.steps.len(), 12);
        assert!(result.steps.iter().all(|s| s.clean));
        let last = result.steps.last().unwrap();
        assert!((result.confirmed_mbps - last.achieved_mbps.unwrap()).abs() < 0.01);
    }

    #[tokio::test]
    async fn ramp_treats_missing_result_as_not_clean() {
        let result = adaptive_bandwidth_ramp(|target| async move {
            if target <= 4.0 {
                Some(target * 0.95)
            } else {
                None // step 3 (8 Mbps) times out / never gets a result
            }
        })
        .await;

        assert_eq!(result.steps.len(), 3);
        assert!(!result.steps[2].clean);
        assert!(result.steps[2].achieved_mbps.is_none());
        // Backs off from the last clean step (4 Mbps @ 0.95).
        assert!((result.confirmed_mbps - (4.0 * 0.95 * 0.8)).abs() < 0.01);
    }

    #[tokio::test]
    async fn ramp_reports_no_real_measurement_when_every_step_fails() {
        // Every single step times out / gets no result back -- e.g. an
        // old peer that ignores `ThroughputTestData` entirely, or one
        // that's temporarily unreachable for the whole ramp. Even though
        // `confirmed_mbps` still comes out to a (fabricated) number via
        // the backoff-with-no-clean-step path, callers must be able to
        // tell this apart from a real measurement by checking whether
        // any step actually got a result -- exactly the guard
        // `control.rs`'s CLI path already uses and
        // `active_bandwidth_prober` now mirrors.
        let result = adaptive_bandwidth_ramp(|_target| async move { None }).await;

        assert_eq!(result.steps.len(), 1);
        assert!(!result.steps.iter().any(|s| s.achieved_mbps.is_some()));
        // The fabricated fallback is still there in confirmed_mbps...
        assert!((result.confirmed_mbps - (RAMP_START_MBPS * RAMP_BACKOFF_FACTOR)).abs() < 0.01);
        // ...but nothing in `steps` should ever be mistaken for a real
        // measurement.
    }
}

#[cfg(test)]
mod active_bandwidth_prober_tick_tests {
    use super::*;

    #[test]
    fn prober_full_ramps_when_never_ramped_before() {
        let stats = link::LinkStats::new(0.3);
        assert!(should_full_ramp(&stats, Duration::from_secs(1800)));
    }

    #[test]
    fn prober_verifies_when_recently_ramped_and_no_misses() {
        let mut stats = link::LinkStats::new(0.3);
        stats.confirmed_ceiling_mbps = Some(42.0);
        stats.last_ramp_at = Some(Instant::now());
        stats.consecutive_verify_misses = 0;
        assert!(!should_full_ramp(&stats, Duration::from_secs(1800)));
    }

    #[test]
    fn prober_full_ramps_after_reramp_interval_elapses() {
        let mut stats = link::LinkStats::new(0.3);
        stats.confirmed_ceiling_mbps = Some(42.0);
        stats.last_ramp_at = Some(Instant::now() - Duration::from_secs(2000));
        assert!(should_full_ramp(&stats, Duration::from_secs(1800)));
    }

    #[test]
    fn prober_full_ramps_after_two_consecutive_misses() {
        let mut stats = link::LinkStats::new(0.3);
        stats.confirmed_ceiling_mbps = Some(42.0);
        stats.last_ramp_at = Some(Instant::now());
        stats.consecutive_verify_misses = 2;
        assert!(should_full_ramp(&stats, Duration::from_secs(1800)));
    }

    #[test]
    fn prober_does_not_full_ramp_after_only_one_miss() {
        let mut stats = link::LinkStats::new(0.3);
        stats.confirmed_ceiling_mbps = Some(42.0);
        stats.last_ramp_at = Some(Instant::now());
        stats.consecutive_verify_misses = 1;
        assert!(!should_full_ramp(&stats, Duration::from_secs(1800)));
    }

    #[test]
    fn ramp_result_valid_when_link_stayed_up_the_whole_time() {
        let state_since = Instant::now();
        assert!(ramp_result_still_valid(
            LinkState::Up,
            state_since,
            state_since
        ));
    }

    #[test]
    fn ramp_result_invalid_when_link_no_longer_up() {
        let state_since = Instant::now();
        assert!(!ramp_result_still_valid(
            LinkState::Down,
            state_since,
            state_since
        ));
    }

    #[test]
    fn ramp_result_invalid_when_link_bounced_down_and_back_up_mid_ramp() {
        // Back to `Up` by the time we check, but `state_since` has moved
        // -- proof a Down/Up transition happened somewhere in the
        // window, even though the link "looks" healthy right now.
        let state_since_before_ramp = Instant::now();
        let state_since_after_bounce = state_since_before_ramp + Duration::from_millis(1);
        assert!(!ramp_result_still_valid(
            LinkState::Up,
            state_since_after_bounce,
            state_since_before_ramp
        ));
    }
}

#[cfg(test)]
mod rx_pipeline_tests {
    use super::*;
    use std::collections::HashSet;

    #[derive(Default)]
    struct VecSink(std::sync::Mutex<Vec<Vec<u8>>>);

    impl RxSink for VecSink {
        async fn send(&self, pkt: &[u8]) {
            self.0.lock().unwrap().push(pkt.to_vec());
        }
    }

    struct Harness {
        tx: RxPipelineTx,
        sink: Arc<VecSink>,
        recovered: Arc<AtomicU64>,
        unrecoverable: Arc<AtomicU64>,
        dropped: Arc<AtomicU64>,
    }

    fn spawn_pipeline(window_ms: u64, fec_group: Option<u8>) -> Harness {
        let (chan_tx, chan_rx) = mpsc::channel(RX_PIPELINE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let sink = Arc::new(VecSink::default());
        let recovered = Arc::new(AtomicU64::new(0));
        let unrecoverable = Arc::new(AtomicU64::new(0));
        tokio::spawn(rx_pipeline(
            chan_rx,
            sink.clone(),
            Arc::new(std::sync::Mutex::new(Scheduler::new())),
            window_ms,
            fec::FecRecoveryBuffer::new(fec_group.unwrap_or(4), 1),
            fec_group.is_some(),
            recovered.clone(),
            unrecoverable.clone(),
            dropped.clone(),
            Arc::new(crate::telemetry::RxPipelineStats::default()),
        ));
        Harness {
            tx: RxPipelineTx {
                tx: chan_tx,
                dropped: dropped.clone(),
            },
            sink,
            recovered,
            unrecoverable,
            dropped,
        }
    }

    async fn wait_for_len(sink: &VecSink, want: usize) -> bool {
        for _ in 0..200 {
            if sink.0.lock().unwrap().len() >= want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    fn seq_of(pkt: &[u8]) -> u64 {
        u64::from_be_bytes(pkt[..8].try_into().unwrap())
    }

    /// Several links feeding the pipeline at once: every frame comes out
    /// exactly once, none lost, none duplicated, regardless of how the
    /// senders interleave.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_senders_deliver_every_frame_exactly_once() {
        const SENDERS: u64 = 4;
        const PER_SENDER: u64 = 200;
        let h = spawn_pipeline(30, None);
        let mut joins = Vec::new();
        for s in 0..SENDERS {
            let tx = h.tx.tx.clone();
            joins.push(tokio::spawn(async move {
                for i in 0..PER_SENDER {
                    let seq = i * SENDERS + s + 1;
                    tx.send(RxEvent::Data {
                        seq,
                        plaintext: seq.to_be_bytes().to_vec(),
                    })
                    .await
                    .unwrap();
                    if i % 16 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            }));
        }
        for j in joins {
            j.await.unwrap();
        }
        let total = (SENDERS * PER_SENDER) as usize;
        assert!(
            wait_for_len(&h.sink, total).await,
            "only {} of {total} frames delivered",
            h.sink.0.lock().unwrap().len()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let out = h.sink.0.lock().unwrap();
        assert_eq!(out.len(), total, "duplicate delivery");
        let seqs: HashSet<u64> = out.iter().map(|p| seq_of(p)).collect();
        assert_eq!(seqs.len(), total);
        assert_eq!(h.dropped.load(Ordering::Relaxed), 0);
    }

    /// A frame older than the high watermark is held back, then released
    /// by the periodic flush once the reorder window passes -- with no
    /// further traffic needed to trigger it.
    #[tokio::test]
    async fn late_frame_is_flushed_after_window_without_new_traffic() {
        let h = spawn_pipeline(40, None);
        for seq in [10u64, 5] {
            h.tx.deliver(RxEvent::Data {
                seq,
                plaintext: seq.to_be_bytes().to_vec(),
            });
        }
        assert!(wait_for_len(&h.sink, 2).await);
        let out = h.sink.0.lock().unwrap();
        assert_eq!(seq_of(&out[0]), 10);
        assert_eq!(seq_of(&out[1]), 5);
    }

    /// FEC reconstructs a missing member; the real copy arriving later
    /// through a slower link must not be delivered a second time.
    #[tokio::test]
    async fn fec_recovered_frame_is_not_delivered_twice() {
        let h = spawn_pipeline(20, Some(4));
        let mut sender = fec::FecSender::new(4, 1);
        let mut parity = None;
        let frames: Vec<(u64, Vec<u8>)> = (1u64..=4)
            .map(|seq| {
                let mut p = seq.to_be_bytes().to_vec();
                p.extend_from_slice(&[seq as u8; 20]);
                (seq, p)
            })
            .collect();
        for (seq, p) in &frames {
            parity = sender.accumulate(*seq, p, 0).map(|g| g.p);
        }
        let parity = parity.expect("group of 4 completes parity");

        for (seq, p) in frames.iter().take(3) {
            h.tx.deliver(RxEvent::Data {
                seq: *seq,
                plaintext: p.clone(),
            });
        }
        h.tx.deliver(RxEvent::Parity(fec::ParityKind::P, parity));
        assert!(wait_for_len(&h.sink, 4).await);
        assert_eq!(h.recovered.load(Ordering::Relaxed), 1);

        let (seq4, p4) = frames[3].clone();
        h.tx.deliver(RxEvent::Data {
            seq: seq4,
            plaintext: p4,
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        let out = h.sink.0.lock().unwrap();
        assert_eq!(out.len(), 4, "late real copy was delivered as a duplicate");
        assert_eq!(h.unrecoverable.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn full_channel_drops_and_counts_instead_of_blocking() {
        let (tx, _rx) = mpsc::channel(2);
        let dropped = Arc::new(AtomicU64::new(0));
        let p = RxPipelineTx {
            tx,
            dropped: dropped.clone(),
        };
        for seq in 0..5u64 {
            p.deliver(RxEvent::Data {
                seq,
                plaintext: vec![0],
            });
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 3);
    }
}
