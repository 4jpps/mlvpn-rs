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
//!   for each queued frame and sends the resulting datagram out that
//!   link's socket. Split from `tun_reader` specifically so a slow send
//!   side can never stall draining the TUN device -- a full queue drops
//!   the packet and counts it instead, logged by...
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
//! - one `reorder_flush` task: releases packets from the reorder buffer
//!   that have waited past `reorder_window_ms`, so a permanently missing
//!   packet degrades to out-of-order delivery instead of stalling the
//!   tunnel forever.
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
//!   dump to disk the moment one crosses `loss_threshold_pct`, so a
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
//! traced to `send_scheduled` calling `snapshot_links` (cloning every
//! link's full `Link`, including heap-allocating every `LinkConfig`
//! `String` field) on *every outgoing packet*, just to let the scheduler
//! pick one and throw the rest away. `send_scheduled` now calls
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
//! shared-session design did -- `send_scheduled`/`send_redundant` below
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
//! One real, known gap this leaves relative to the old design: the old
//! `perform_client_handshake` actively raced a link's not-yet-confirmed
//! alternate address family (`link::Link::alternate`/`commit_remote`,
//! see their own doc comments) once, right after the initial handshake,
//! to recover a link whose `pick_remote_addr` guess picked the wrong
//! family. That active-racing step has not been reimplemented here --
//! `Link::alternate`/`alternate_handle`/`commit_remote` still exist in
//! `link.rs` but nothing in this module calls them anymore, so a link
//! configured with a dual-stack `remote_addr` now simply uses whichever
//! family `pick_remote_addr` chose at bind time, with no runtime
//! fallback if that guess is wrong. Worth reconsidering in a later task
//! if this turns out to matter in practice.
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
use crate::error::{MlvpnError, Result};
use crate::fec;
use crate::link::{self, is_interface_gone_error, Link, LinkHandle, LinkScore, LinkState, Links};
use crate::monitor::{self, ProbeTracker};
use crate::peerstats::PeerStatsTable;
use crate::protocol::{
    Header, PacketType, ProbePayload, StatsPayload, ThroughputTestDataPayload,
    ThroughputTestResultPayload, ThroughputTestReverseRequestPayload, VersionInfoPayload,
    HEADER_LEN,
};
use crate::scheduler::Scheduler;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::Mutex as AsyncMutex;
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
    pub loss_threshold_pct: f64,
    pub cooldown: Duration,
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

pub async fn run(
    tun: AsyncDevice,
    links: Vec<Link>,
    params: TunnelParams,
    log_ring: Arc<crate::logbuf::LogRing>,
) -> Result<()> {
    let tun = Arc::new(tun);
    let links: Links = Arc::new(links.into_iter().map(AsyncMutex::new).collect());
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

    let reorder = Arc::new(AsyncMutex::new(ReorderBuffer::new(
        params.scheduler_cfg.reorder_window_ms,
    )));

    // Shared across both links (a FEC group's members can arrive on
    // either physical link), same reasoning as `reorder` above. Its own
    // retention is deliberately NOT derived from `reorder_window_ms`:
    // see `fec::PAYLOAD_TTL`'s doc comment for why those are unrelated
    // timescales. Built unconditionally (it is empty and never touched
    // when FEC is disabled) so nothing downstream needs an Option.
    let fec_recovery = Arc::new(AsyncMutex::new(fec::FecRecoveryBuffer::new(
        params.scheduler_cfg.fec_group_size,
    )));
    let fec_recovered_total = Arc::new(AtomicU64::new(0));
    let fec_unrecoverable_total = Arc::new(AtomicU64::new(0));

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
            let tun = tun.clone();
            let reorder = reorder.clone();
            let fec_recovery = fec_recovery.clone();
            let fec_recovered_total = fec_recovered_total.clone();
            let fec_unrecoverable_total = fec_unrecoverable_total.clone();
            let cfg = params.scheduler_cfg.clone();
            let tracker = tracker.clone();
            let peer_stats = peer_stats.clone();
            let mtu = live_mtu.clone();
            let throughput_test_state = throughput_test_state.clone();
            let throughput_test_ctx = throughput_test_ctx.clone();
            let peer_version = peer_version.clone();
            let peer_mtu = peer_mtu.clone();
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
                    tun,
                    reorder,
                    fec_recovery,
                    fec_recovered_total,
                    fec_unrecoverable_total,
                    cfg,
                    tracker,
                    peer_stats,
                    mtu,
                    throughput_test_state,
                    throughput_test_ctx,
                    peer_version,
                    peer_mtu,
                    peer_primary_link,
                )
                .await;
            }));
        }
        {
            let links = links.clone();
            let scheduler = scheduler.clone();
            let cfg = params.scheduler_cfg.clone();
            let mtu = live_mtu.clone();
            let peer_primary_link = peer_primary_link.clone();
            handles.push(tokio::spawn(async move {
                link_prober(idx, links, scheduler, cfg, mtu, tracker, peer_primary_link).await;
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
        let mtu = live_mtu.clone();
        let scheduler = scheduler.clone();
        let fec_recovered_total = fec_recovered_total.clone();
        let fec_unrecoverable_total = fec_unrecoverable_total.clone();
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
                scheduler,
                fec_recovered_total,
                fec_unrecoverable_total,
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
            scheduler: scheduler.clone(),
            fec_recovered_total: fec_recovered_total.clone(),
            fec_unrecoverable_total: fec_unrecoverable_total.clone(),
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
            scheduler: scheduler.clone(),
            fec_recovered_total: fec_recovered_total.clone(),
            fec_unrecoverable_total: fec_unrecoverable_total.clone(),
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
        let mtu_resizer = params.mtu_resizer.clone();
        let fec_reservation = fec::mtu_reservation_bytes(&params.scheduler_cfg);
        handles.push(tokio::spawn(async move {
            control::mtu_monitor_loop(
                tunnel_cfg,
                tun_ifname,
                bind_interfaces,
                live_mtu,
                mtu_resizer,
                fec_reservation,
            )
            .await;
        }));
    }

    {
        let links = links.clone();
        let scheduler = scheduler.clone();
        let redundant_mode = params.scheduler_cfg.redundant_mode;
        let fec_enabled = params.scheduler_cfg.fec_enabled;
        let fec_group_size = params.scheduler_cfg.fec_group_size;
        let live_mtu = live_mtu.clone();
        let fec_unrecoverable_total = fec_unrecoverable_total.clone();
        handles.push(tokio::spawn(async move {
            outbound_sender(
                outbound_rx,
                links,
                scheduler,
                redundant_mode,
                fec_enabled,
                fec_group_size,
                live_mtu,
                fec_unrecoverable_total,
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
        let reorder = reorder.clone();
        let tun = tun.clone();
        handles.push(tokio::spawn(async move {
            reorder_flush(reorder, tun).await;
        }));
    }

    if params.scheduler_cfg.fec_enabled {
        let fec_recovery = fec_recovery.clone();
        handles.push(tokio::spawn(async move {
            fec_expiry_loop(fec_recovery).await;
        }));
    }

    {
        let links = links.clone();
        let reorder = reorder.clone();
        let cfg = params.scheduler_cfg.clone();
        let scheduler = scheduler.clone();
        handles.push(tokio::spawn(async move {
            reorder_tuning_loop(links, reorder, cfg, scheduler).await;
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
/// asks the `Scheduler` for a link and does the actual socket I/O).
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
/// per-packet overhead `send_scheduled` used to have (cloning every
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
/// `send_scheduled`/`send_redundant` has actually picked a link -- see
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

/// Pulls encrypted frames off the outbound queue and actually sends
/// them -- the other half of `tun_reader`'s split, see
/// `OUTBOUND_QUEUE_CAPACITY`'s doc comment for why this is a separate
/// task rather than `tun_reader` calling `send_scheduled`/`send_redundant`
/// directly. Returns once `tx` (held by `tun_reader`) is dropped, i.e.
/// only during shutdown.
#[allow(clippy::too_many_arguments)]
async fn outbound_sender(
    mut rx: mpsc::Receiver<OutboundFrame>,
    links: Links,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    redundant_mode: bool,
    fec_enabled: bool,
    fec_group_size: u8,
    mtu: LiveMtu,
    fec_unrecoverable_total: Arc<AtomicU64>,
) {
    let mut fec_sender = fec_enabled.then(|| crate::fec::FecSender::new(fec_group_size));
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
    while let Some(frame) = rx.recv().await {
        if redundant_mode {
            send_redundant(&links, &frame.plaintext).await;
            continue;
        }
        let seq = next_send_seq();
        let sent =
            send_scheduled(&links, &scheduler, PacketType::Data, seq, &frame.plaintext).await;
        // Only a frame that genuinely reached the wire may join the
        // current FEC group. A frame that was dropped here (no link
        // available) or whose payload boringtun substituted with a
        // handshake datagram (every WireGuard handshake/rekey) is one the
        // receiver can never observe -- accumulating it anyway made it a
        // phantom group member that permanently consumed the group's one
        // erasure, so a later *real* loss in the same group became
        // unrecoverable, and a group whose phantom was its only missing
        // seq would "reconstruct" and inject into the TUN device a
        // datagram the peer never sent (observed live as a fabricated
        // IPv6 Router Solicitation).
        if !sent {
            continue;
        }
        if let Some(sender) = fec_sender.as_mut() {
            if let Some(parity) = sender.accumulate(seq, &frame.plaintext) {
                let parity_bytes = parity.encode();
                // Belt-and-braces against the MTU reservation being
                // momentarily wrong: `mtu_monitor_loop` can *shrink* the
                // live tunnel MTU (a link reconnecting on smaller
                // hardware) after a group has already accumulated
                // members sized for the old, larger one. Sending an
                // oversized parity frame is strictly worse than sending
                // none at all -- it either gets fragmented (needing
                // *both* fragments to survive, making it less likely to
                // arrive than the data it protects) or fails outright --
                // so drop it and count the group as one FEC could not
                // help with.
                let budget = mtu.load(Ordering::Relaxed) as usize + parity_headroom;
                if parity_bytes.len() > budget {
                    fec_unrecoverable_total.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        parity_bytes = parity_bytes.len(),
                        budget,
                        "skipping an oversized FEC parity frame (tunnel MTU shrank mid-group)"
                    );
                    continue;
                }
                let parity_seq = next_send_seq();
                // Return value deliberately ignored: a parity frame is
                // not itself a group member, so a failed/substituted
                // parity send simply means the receiver never sees it and
                // the group times out as unrecoverable -- already the
                // correct existing behavior, nothing to gate.
                let _ = send_scheduled(
                    &links,
                    &scheduler,
                    PacketType::FecParity,
                    parity_seq,
                    &parity_bytes,
                )
                .await;
            }
        }
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

/// Normal (non-redundant) send path: ask the `Scheduler` for exactly one
/// link and send there. Split out of `tun_reader` purely to keep that
/// loop body readable now that it branches on `redundant_mode`.
///
/// Returns whether `plaintext` genuinely reached the wire: `false` for
/// every "no link available to send on" early return, for a failed
/// `wg_send`, and for a `wg_send` that succeeded at the socket level but
/// whose payload boringtun substituted with a handshake datagram (see
/// `LinkHandle::wg_send`). `outbound_sender` gates FEC group
/// accumulation on this -- a frame counted as a group member the peer
/// never saw is a phantom that permanently consumes the group's single
/// erasure, making a later *real* loss unrecoverable or, worse, letting
/// FEC "reconstruct" and deliver a datagram that was never transmitted.
async fn send_scheduled(
    links: &Links,
    scheduler: &Arc<std::sync::Mutex<Scheduler>>,
    ptype: PacketType,
    seq: u64,
    plaintext: &[u8],
) -> bool {
    // Not the real on-wire size (WireGuard adds its own AEAD overhead on
    // top, invisibly to this layer), but the same approximation the old
    // shared-session design used for the scheduler's own cap-check
    // accounting, which only ever needed a reasonable estimate, not an
    // exact byte count.
    let frame_len = HEADER_LEN + plaintext.len();

    // Fast path first: `Scheduler::select_fast` resolves a primary or
    // an SWRR pick entirely from state the last periodic `refresh()`
    // already cached, with zero link locking. Only fall back to a full
    // `link::snapshot_scores` scan (locks every configured link) when
    // that returns `None` -- the rare case where nothing is cached yet
    // (every link Down). See `select_fast`'s doc comment: this used to
    // run unconditionally on every packet and was confirmed live via
    // `strace -f -c` to be the dominant cost in the entire send path.
    let chosen_idx: Option<usize> = {
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
    };
    let Some(idx) = chosen_idx else {
        tracing::warn!("no link available to send on; dropping packet");
        return false;
    };
    let Some(link_mutex) = links.get(idx) else {
        tracing::warn!("no link available to send on; dropping packet");
        return false;
    };

    // Only *now*, having already picked a winner, do we lock a link at
    // all for its full data -- and only this one, not every candidate
    // that didn't win. `LinkHandle` (which owns this link's own
    // `WgTunnel`) rather than a resolved socket here, specifically so
    // the actual send below always encrypts/sends through whatever
    // socket is current at send time (post-reconnect if one just
    // happened) instead of one captured slightly stale.
    let chosen: Option<(u8, LinkHandle, String)> = {
        let guard = link_mutex.lock().await;
        guard
            .remote
            .map(|_| (guard.id, guard.handle(), guard.config.name.clone()))
    };
    let Some((link_id, handle, link_name)) = chosen else {
        tracing::warn!("no link available to send on; dropping packet");
        return false;
    };

    let mut frame = Vec::with_capacity(frame_len);
    Header {
        ptype,
        link_id,
        seq,
    }
    .encode(&mut frame);
    frame.extend_from_slice(plaintext);

    match handle.wg_send(&frame).await {
        Ok(carried) => {
            // Re-lock just the winning link, only on success, purely to
            // update the lifetime tx counters -- everything else in this
            // function already released `link_mutex` before the `.await`
            // above (see the comment on `chosen` for why), so this is one
            // more short lock on one link, not a scan over every
            // candidate that didn't win.
            //
            // Deliberately unconditional on `carried`: `record_tx`'s own
            // "bytes this link put on the wire" semantics are unchanged
            // by this fix (a substituted handshake datagram really was
            // transmitted, just not carrying this frame). That stat being
            // slightly optimistic during a handshake is a separate,
            // pre-existing concern -- only the returned bool is new.
            link_mutex.lock().await.stats.record_tx(frame_len as u64);
            carried
        }
        Err(e) => {
            tracing::debug!(link = %link_name, error = %e, "send failed");
            false
        }
    }
}

/// Redundancy-mode send path (`scheduler.redundant_mode`): send the same
/// frame on every currently-Up link instead of picking just one via
/// `Scheduler`, trading bandwidth for the lowest possible chance of
/// losing this particular packet. Falls back to every link with a known
/// remote address (regardless of state) if none are currently Up, same
/// zero-downtime rationale as `Scheduler::select`'s own fallback.
/// Deliberately bypasses `bandwidth_cap_mbps` entirely for these sends:
/// this mode is opt-in specifically to prioritize reliability over
/// bandwidth, and quietly skipping a capped link would undermine the
/// one guarantee it exists to provide. The receiving side needs no
/// special handling -- the existing replay window (`crypto::ReplayWindow`)
/// already rejects the second and later copies of the same sequence
/// number, the same protection it provides against a genuine replay
/// attack, so a duplicate delivered via another link is simply dropped
/// rather than double-delivered to the TUN device.
///
/// This is a blunt, whole-tunnel toggle rather than per-flow
/// classification (no DSCP/traffic-class inspection of the inner IP
/// packet) -- simpler to implement and reason about correctly, at the
/// cost of duplicating *every* packet rather than only genuinely
/// latency-sensitive ones. Only worth enabling for a small,
/// latency-critical tunnel (e.g. VoIP/control traffic bonded across a
/// couple of links); a bulk-transfer tunnel should leave this off.
async fn send_redundant(links: &Links, plaintext: &[u8]) {
    let targets: Vec<(u8, LinkHandle, String)> = {
        let snap = link::snapshot_links(links).await;
        let up: Vec<_> = snap
            .iter()
            .filter(|l| l.state == LinkState::Up && l.remote.is_some())
            .map(|l| (l.id, l.handle(), l.config.name.clone()))
            .collect();
        if !up.is_empty() {
            up
        } else {
            snap.iter()
                .filter(|l| l.remote.is_some())
                .map(|l| (l.id, l.handle(), l.config.name.clone()))
                .collect()
        }
    };

    if targets.is_empty() {
        tracing::warn!("redundant mode: no link available to send on; dropping packet");
        return;
    }

    // Every copy carries the SAME seq -- the receiving side's replay
    // window (now per-link, inside each `WgTunnel`) doesn't dedupe
    // across links on its own, but `ReorderBuffer`'s own high-watermark
    // logic (`note_delivered`) treats every copy after the first as "not
    // forward progress" and buffers/discards it via the ordinary
    // stale-duplicate path, the same as before this task.
    let seq = next_send_seq();
    let frame_len = HEADER_LEN + plaintext.len();

    for (link_id, handle, link_name) in targets {
        let mut frame = Vec::with_capacity(frame_len);
        Header {
            ptype: PacketType::Data,
            link_id,
            seq,
        }
        .encode(&mut frame);
        frame.extend_from_slice(plaintext);
        match handle.wg_send(&frame).await {
            // Redundant mode has no FEC group to corrupt (FEC and
            // redundant mode are mutually exclusive send paths in
            // `outbound_sender`), so `wg_send`'s new bool is irrelevant
            // here -- `record_tx` keeps its existing semantics.
            Ok(_carried) => {
                // `link_id` is always the live link's own Vec index (see
                // main.rs's `Link::bind(id, ...)` call site: id is
                // assigned from the config Vec's own position), so this
                // reaches the real, live `Link`, not the `snapshot_links`
                // copy `targets` was built from above.
                if let Some(link_mutex) = links.get(link_id as usize) {
                    link_mutex.lock().await.stats.record_tx(frame_len as u64);
                }
            }
            Err(e) => {
                tracing::debug!(link = %link_name, error = %e, "redundant send failed");
            }
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
    tun: Arc<AsyncDevice>,
    reorder: Arc<AsyncMutex<ReorderBuffer>>,
    fec_recovery: Arc<AsyncMutex<fec::FecRecoveryBuffer>>,
    fec_recovered_total: Arc<AtomicU64>,
    fec_unrecoverable_total: Arc<AtomicU64>,
    cfg: SchedulerConfig,
    tracker: Arc<AsyncMutex<ProbeTracker>>,
    peer_stats: Arc<PeerStatsTable>,
    mtu: LiveMtu,
    throughput_test_state: Arc<AsyncMutex<ThroughputTestReceiveState>>,
    throughput_test_ctx: Arc<ThroughputTestContext>,
    peer_version: PeerVersion,
    peer_mtu: PeerMtu,
    peer_primary_link: PeerPrimaryLink,
) {
    let (handle, link_id, link_name) = {
        let link = links[idx].lock().await;
        (link.handle(), link.id, link.config.name.clone())
    };

    let mut consecutive_failures = 0u32;
    let mut backoff_ms = RECONNECT_BACKOFF_INITIAL_MS;
    loop {
        // `wg_recv` loops internally past any handshake/keepalive
        // traffic on this link's socket -- what comes back here is
        // always either a genuine decrypted mlvpn frame plus the
        // datagram's source address, or a real error (a socket I/O
        // failure, or a malformed/oversized datagram that
        // `wireguard::WgTunnel::decapsulate` rejected outright).
        match handle.wg_recv().await {
            Ok((frame, from)) => {
                consecutive_failures = 0;
                handle_incoming(
                    idx,
                    link_id,
                    &frame,
                    from,
                    &links,
                    &scheduler,
                    &tun,
                    &reorder,
                    &fec_recovery,
                    &fec_recovered_total,
                    &fec_unrecoverable_total,
                    &cfg,
                    &tracker,
                    &peer_stats,
                    &mtu,
                    &throughput_test_state,
                    &throughput_test_ctx,
                    &peer_version,
                    &peer_mtu,
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
    mtu: LiveMtu,
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
                send_version_info(link_id, &links, idx, &mtu, &scheduler).await;
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
    if consecutive_hits > 0 && consecutive_hits % EWMA_ALPHA_SMOOTHING_STREAK == 0 {
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
    if consecutive_hits > 0 && consecutive_hits % PROBE_BACKOFF_STREAK == 0 {
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
    tun: &Arc<AsyncDevice>,
    reorder: &Arc<AsyncMutex<ReorderBuffer>>,
    fec_recovery: &Arc<AsyncMutex<fec::FecRecoveryBuffer>>,
    fec_recovered_total: &Arc<AtomicU64>,
    fec_unrecoverable_total: &Arc<AtomicU64>,
    cfg: &SchedulerConfig,
    tracker: &Arc<AsyncMutex<ProbeTracker>>,
    peer_stats: &Arc<PeerStatsTable>,
    mtu: &LiveMtu,
    throughput_test_state: &Arc<AsyncMutex<ThroughputTestReceiveState>>,
    throughput_test_ctx: &Arc<ThroughputTestContext>,
    peer_version: &PeerVersion,
    peer_mtu: &PeerMtu,
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
    // Owned copy: several branches below (`ReorderBuffer::insert`, the
    // `ThroughputTestReverseRequest` spawn) need to hold onto this past
    // `frame`'s own borrow.
    let plaintext = plaintext.to_vec();
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
    if let Some(l) = links.get(idx) {
        // Merged into one lock acquisition rather than two adjacent ones
        // (the remote-address check below, plus a Data-only record_rx
        // that used to re-lock the same link right after) -- confirmed
        // live via `strace -f -c` that per-packet lock acquisitions
        // dominate mlvpnd's wall-clock time (see send_scheduled's
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
    }

    match hdr.ptype {
        PacketType::Data => {
            // Every real Data frame is a potential FEC group member --
            // this has to run regardless of which delivery branch below
            // handles the frame next, since `FecRecoveryBuffer` needs to
            // see every arriving member to ever recover a *different*
            // missing one later.
            //
            // Guarded on `cfg.fec_enabled` so a default-config daemon
            // genuinely pays nothing for a feature it isn't using: with
            // FEC off this skips a shared async-Mutex acquisition (a
            // cross-link contention point both `link_receiver` tasks
            // would otherwise hit on every single packet), a full heap
            // copy of the plaintext, and a HashMap insert -- on exactly
            // the hot path v0.6.1-v0.6.4 spent a whole release cycle
            // stripping per-packet locks out of.
            //
            // When it *is* enabled, `observe_data`'s return value is the
            // duplicate guard: `false` means FEC already reconstructed
            // and delivered this seq (its parity frame beat the real
            // copy through a slower link), so delivering it now would
            // put a byte-identical duplicate IP packet into the TUN
            // device -- dup-ACKs, spurious fast retransmit, the exact
            // congestion behavior this feature exists to reduce.
            if cfg.fec_enabled {
                // Scoped binding, not an inline condition: the guard is
                // explicitly dropped before any other lock below is
                // touched, keeping this module's "every lock
                // acquisition is a scoped temporary, never nested"
                // invariant obvious rather than dependent on temporary
                // -scope rules.
                let deliver = {
                    let mut buf = fec_recovery.lock().await;
                    buf.observe_data(hdr.seq, &plaintext)
                };
                if !deliver {
                    return;
                }
            }
            // Cheap, uncontended std::sync::Mutex lock (same pattern
            // established by this project's earlier select_fast and
            // reorder_tuning_loop fixes) -- read once per packet, not
            // cached in a persistent flag, so a mid-stream transition
            // (the primary going Down or a peer-followed primary
            // settling) is picked up on the very next packet either
            // way, correctly.
            if scheduler.lock().unwrap().primary().is_some() {
                // Settled single active link: no cross-link reordering
                // is possible, so skip time-based buffering entirely
                // and deliver immediately, matching WireGuard's own
                // architecture for single-path tunnels -- see this
                // module's doc comment and `ReorderBuffer::note_delivered`'s
                // own doc comment for the full reasoning. Each link's
                // own WireGuard session now rekeys entirely internally
                // (invisibly to this module), so there is no longer an
                // app-level session-change event to reset `peer_primary_link`
                // on here.
                reorder.lock().await.note_delivered(hdr.seq);
                let _ = tun.send(&plaintext).await;
            } else {
                let ready = {
                    let mut ro = reorder.lock().await;
                    ro.insert(hdr.seq, plaintext);
                    ro.drain_ready()
                };
                for pkt in ready {
                    let _ = tun.send(&pkt).await;
                }
            }
        }
        PacketType::FecParity => {
            if !cfg.fec_enabled {
                // A peer with FEC on talking to a receiver with it off:
                // nothing here can help (nothing is being observed to
                // reconstruct against), and running the machinery anyway
                // would both cost the hot-path lock #2 exists to avoid
                // and report every group as unrecoverable. Drop it the
                // same way any other unwanted frame type is dropped.
                return;
            }
            let Ok(parity) = crate::protocol::FecParityPayload::decode(&plaintext) else {
                tracing::debug!("malformed FecParity payload, ignoring");
                return;
            };
            let outcome = fec_recovery.lock().await.try_recover(&parity);
            match outcome {
                fec::RecoveryOutcome::Recovered { seq, plaintext } => {
                    fec_recovered_total.fetch_add(1, Ordering::Relaxed);
                    // Mirrors the Data arm's own settled-primary/buffered
                    // delivery branch exactly -- a recovered frame is
                    // delivered the same way a real Data frame with the
                    // same `seq` would have been.
                    if scheduler.lock().unwrap().primary().is_some() {
                        reorder.lock().await.note_delivered(seq);
                        let _ = tun.send(&plaintext).await;
                    } else {
                        let ready = {
                            let mut ro = reorder.lock().await;
                            ro.insert(seq, plaintext);
                            ro.drain_ready()
                        };
                        for pkt in ready {
                            let _ = tun.send(&pkt).await;
                        }
                    }
                }
                fec::RecoveryOutcome::Unrecoverable => {
                    fec_unrecoverable_total.fetch_add(1, Ordering::Relaxed);
                }
                fec::RecoveryOutcome::AlreadyComplete => {}
            }
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
            out.extend_from_slice(&plaintext);
            let _ = handle.wg_send(&out).await;
        }
        PacketType::ProbeReply => {
            let Ok(probe) = ProbePayload::decode(&plaintext) else {
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
            if let Ok(payload) = StatsPayload::decode(&plaintext) {
                // Keyed by our own idx (the link we received this on),
                // not anything the sender included -- see StatsPayload's
                // doc comment for why that's the correct choice here.
                peer_stats.update(idx as u8, &payload);
            }
        }
        PacketType::VersionInfo => match VersionInfoPayload::decode(&plaintext) {
            Ok(payload) => {
                *peer_version.lock().unwrap() = Some(payload.version_str());
                *peer_mtu.lock().unwrap() = Some(payload.tunnel_mtu);
                *peer_primary_link.lock().unwrap() = payload.primary_link_name_str();
            }
            Err(e) => {
                tracing::debug!(error = %e, %from, "failed to decode VersionInfo payload");
            }
        },
        PacketType::ThroughputTestData => {
            let Ok(data) = ThroughputTestDataPayload::decode(&plaintext) else {
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
            let Ok(result) = ThroughputTestResultPayload::decode(&plaintext) else {
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
            let Ok(req) = ThroughputTestReverseRequestPayload::decode(&plaintext) else {
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
    // `send_scheduled`'s own comment for the same reasoning.
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
    mtu: &LiveMtu,
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
        version: VersionInfoPayload::encode_version(crate::VERSION),
        tunnel_mtu: mtu.load(std::sync::atomic::Ordering::Relaxed),
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

/// Holds decrypted, still-possibly-out-of-order Data payloads keyed by the
/// global session sequence number, and releases them to the TUN device
/// once either the gap in front of them is filled or they've waited
/// longer than `window`. This bounds the extra latency multipath
/// reordering can introduce: we would rather deliver a packet slightly
/// out of order than hold up the whole tunnel waiting for one that may
/// never arrive.
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
    high_watermark: Option<u64>,
    pending: BTreeMap<u64, (tokio::time::Instant, Vec<u8>)>,
}

impl ReorderBuffer {
    fn new(window_ms: u64) -> Self {
        Self {
            window: Duration::from_millis(window_ms),
            high_watermark: None,
            pending: BTreeMap::new(),
        }
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
    fn note_delivered(&mut self, seq: u64) {
        self.high_watermark = Some(self.high_watermark.map_or(seq, |wm| wm.max(seq)));
    }

    /// Current window, in milliseconds -- used by `reorder_tuning_loop`
    /// to compare a freshly suggested value against what's actually in
    /// effect right now (hysteresis).
    fn window_ms(&self) -> u64 {
        self.window.as_millis() as u64
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
        self.pending
            .insert(seq, (tokio::time::Instant::now(), payload));
    }

    /// Drain everything now safe to deliver.
    ///
    /// `hdr.seq` (the value `insert` is keyed on) is not a Data-only
    /// sequence space -- it is `Session::next_send_seq()`, a single
    /// counter shared by every packet type sent over the session
    /// (Data, Probe, ProbeReply, StatsShare, ThroughputTestData,
    /// VersionInfo, and more). Periodic non-Data traffic constantly
    /// consumes sequence numbers from that same counter, so a real
    /// Data frame's `seq` essentially never equals "the previous
    /// Data frame's seq, plus one" -- the numbers in between were
    /// never going to arrive as Data. An admission test requiring
    /// exact contiguity therefore treats nearly every Data frame as
    /// "not next," forcing it through the slow staleness path and
    /// adding close to the full reorder window's worth of needless
    /// latency to almost all real traffic -- confirmed as a genuine,
    /// severe production bug (see
    /// `docs/superpowers/specs/2026-08-29-reorder-buffer-watermark-fix-design.md`).
    ///
    /// The fix: track the highest seq delivered so far
    /// (`high_watermark`) instead of the specific next integer. A
    /// frame whose seq exceeds the watermark represents forward
    /// progress -- it can never be "late" relative to anything already
    /// delivered, regardless of how large the gap from the previous
    /// Data frame is -- so it is always immediately safe to deliver.
    /// A frame at or below the watermark is genuine evidence of
    /// cross-link reordering (arriving after a later-sequenced frame
    /// already went out) -- exactly the case this buffer exists to
    /// handle -- and is buffered until either enough of its neighbors
    /// arrive to flush it in order, or it ages out via the existing
    /// staleness window.
    fn drain_ready(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let now = tokio::time::Instant::now();

        while let Some((&seq, (sent_at, _))) = self.pending.iter().next() {
            let is_forward_progress = self.high_watermark.is_none_or(|wm| seq > wm);
            let is_stale = now.duration_since(*sent_at) >= self.window;
            if is_forward_progress || is_stale {
                let (_sent_at, payload) = self.pending.remove(&seq).unwrap();
                out.push(payload);
                self.high_watermark = Some(self.high_watermark.map_or(seq, |wm| wm.max(seq)));
            } else {
                break;
            }
        }
        out
    }
}

async fn reorder_flush(reorder: Arc<AsyncMutex<ReorderBuffer>>, tun: Arc<AsyncDevice>) {
    let mut tick = interval(Duration::from_millis(10));
    loop {
        tick.tick().await;
        // `try_lock`, not `.lock().await`: this tick's only job is to
        // flush entries that would otherwise sit until they age out
        // with no new packet arriving to trigger `handle_incoming`'s
        // own inline `insert` + `drain_ready` (which already does this
        // same draining on every real Data frame, under the same
        // lock). Under real load, `handle_incoming` already holds this
        // lock far more often than this 100-times-a-second timer needs
        // to contend with it -- confirmed live via `strace -f -c` that
        // per-packet lock contention was the dominant cost in mlvpnd's
        // wall-clock time (see `Scheduler::select_fast`'s and
        // `SessionState`'s own doc comments for the two earlier fixes
        // in this same investigation). Skipping a tick when the lock is
        // currently held is free: whatever's holding it right now is
        // either the same drain this tick would have performed, or
        // about to make the same call fresh from an insert -- the
        // worst case is a genuinely idle straggler waits one extra
        // ~10ms tick before its own staleness timeout flushes it,
        // negligible next to `reorder_window_ms`'s own 10-500ms range.
        // Requires no changes for settled-single-link bypass mode
        // (`ReorderBuffer::note_delivered`): bypass-mode packets never go
        // through `insert`, so this tick's `drain_ready` correctly finds
        // nothing new to flush while bypass mode is active -- a harmless
        // no-op, not a bug. Note this only holds once bypass mode has
        // been active long enough to drain whatever the buffered branch
        // left in `pending` at the moment of the transition; `pending`
        // isn't guaranteed empty at the instant bypass mode first
        // engages.
        let Ok(mut ro) = reorder.try_lock() else {
            continue;
        };
        let ready = ro.drain_ready();
        drop(ro);
        for pkt in ready {
            let _ = tun.send(&pkt).await;
        }
    }
}

/// How often `fec_expiry_loop` runs its maintenance pass.
const FEC_EXPIRY_INTERVAL: Duration = Duration::from_millis(250);

/// Periodically ages out `FecRecoveryBuffer`'s retained plaintexts and
/// rotates its seen-seq generations. Only spawned when
/// `scheduler.fec_enabled` is set (see `run`), so a default-config
/// daemon doesn't even have this task.
///
/// `try_lock()`, not `.lock().await`, for exactly the reason
/// `reorder_flush` was switched to it in v0.6.4: this lock *is* taken
/// on the per-packet receive path (`handle_incoming`'s `observe_data`
/// call, on both links' receiver tasks), so a blocking acquisition here
/// every 10ms would inject a contention point into the hot path purely
/// to do housekeeping. Skipping a contended tick is free: everything
/// this buffer relies on for its memory bound is also enforced inline
/// on insert (`MAX_PAYLOADS`, `MAX_SEEN_PER_GENERATION`), so a missed
/// tick only means state is remembered slightly longer.
///
/// Cadence is much slower than `reorder_flush`'s 10ms: nothing is
/// waiting on this (unlike a reorder-buffer straggler, which delays
/// real delivery), and the timescales it manages are seconds.
async fn fec_expiry_loop(fec_recovery: Arc<AsyncMutex<fec::FecRecoveryBuffer>>) {
    let mut tick = interval(FEC_EXPIRY_INTERVAL);
    loop {
        tick.tick().await;
        if let Ok(mut buf) = fec_recovery.try_lock() {
            buf.tick(Instant::now());
        }
    }
}

/// How often `reorder_tuning_loop` re-evaluates the reorder window.
/// Deliberately much slower than the probe interval or `reorder_flush`'s
/// own 10ms tick -- this is tuning a *policy* parameter from an EWMA
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
    reorder: Arc<AsyncMutex<ReorderBuffer>>,
    cfg: SchedulerConfig,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
) {
    if !cfg.auto_tune_reorder_window {
        return;
    }

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

        let mut ro = reorder.lock().await;
        let current = ro.window_ms();
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
            ro.set_window(suggested);
        }
    }
}

#[cfg(test)]
mod send_scheduled_tests {
    use super::*;

    /// The "no link available to send on" early return must report
    /// `false`, not silently look like a successful send -- that return
    /// value is what stops `outbound_sender` from accumulating a dropped
    /// frame into its FEC group as a phantom member (see
    /// `send_scheduled`'s own doc comment).
    ///
    /// An empty `Links` reaches the first of the three early returns:
    /// `Scheduler::select_fast` has nothing cached, and the
    /// `snapshot_scores` fallback has no candidates either, so no index
    /// is chosen. The other two early returns need a live, bound `Link`
    /// to construct and are covered by the veth integration tests.
    #[tokio::test]
    async fn send_scheduled_reports_false_when_no_link_is_available() {
        let links: link::Links = Arc::new(Vec::new());
        let scheduler = Arc::new(std::sync::Mutex::new(Scheduler::new()));
        let sent = send_scheduled(&links, &scheduler, PacketType::Data, 1, b"payload").await;
        assert!(
            !sent,
            "a dropped packet must never be reported as transmitted"
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
    fn note_delivered_updates_watermark_without_touching_pending() {
        let mut buf = ReorderBuffer::new(50);
        // Prime a watermark ahead of 5 first -- on a genuinely fresh
        // buffer (high_watermark still None), drain_ready's own
        // forward-progress test (`is_none_or`) treats *any* first
        // frame as forward progress, so this out-of-order case only
        // arises once something later has already been delivered.
        buf.insert(10, vec![10]);
        assert_eq!(buf.drain_ready(), vec![vec![10]]); // watermark now 10

        // A genuinely out-of-order entry sitting in pending, buffered
        // the normal way.
        buf.insert(5, vec![5]);
        assert_eq!(buf.drain_ready(), Vec::<Vec<u8>>::new()); // nothing forward-progress yet (5 < 10)

        // note_delivered (the bypass-mode path) advances the watermark
        // directly, without going through insert/drain_ready at all.
        buf.note_delivered(100);

        // The watermark is now 100 -- entry 5 is far behind it, so a
        // later drain_ready (e.g. if bypass mode ends and buffered mode
        // resumes) would treat it as forward-progress-eligible... but
        // note_delivered itself must not have removed or delivered it:
        // pending still holds it exactly as inserted.
        assert_eq!(buf.high_watermark, Some(100));
        assert_eq!(buf.pending.len(), 1);
        assert!(buf.pending.contains_key(&5));
    }

    #[test]
    fn note_delivered_advances_watermark_monotonically() {
        let mut buf = ReorderBuffer::new(50);
        buf.note_delivered(10);
        buf.note_delivered(50);
        // A lower seq arriving after a higher one (still real, on a
        // single link occasionally) must not move the watermark
        // backward.
        buf.note_delivered(20);

        // Confirm indirectly via drain_ready's own forward-progress
        // test: inserting exactly at the current watermark (50) must
        // NOT be treated as forward progress (a real regression this
        // test would catch: if note_delivered had let the watermark
        // fall back to 20, seq 50 would wrongly look like forward
        // progress here).
        buf.insert(50, vec![50]);
        assert_eq!(buf.drain_ready(), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn bypass_then_resume_buffered_mode_keeps_watermark_accurate() {
        // The full transition scenario the watermark-staleness fix
        // exists for: buffered mode, then bypass mode advances the
        // watermark far ahead via note_delivered, then buffered mode
        // resumes and must not treat already-passed sequence numbers
        // as forward progress just because it never itself saw them.
        let mut buf = ReorderBuffer::new(50);

        // Buffered mode: seq 10 delivered normally.
        buf.insert(10, vec![10]);
        assert_eq!(buf.drain_ready(), vec![vec![10]]); // watermark now 10

        // Bypass mode takes over (e.g. primary_link_mode settles):
        // real traffic keeps flowing via note_delivered, advancing far
        // past what buffered mode itself ever processed.
        buf.note_delivered(500);

        // Buffered mode resumes (e.g. the primary went Down). A late
        // frame with a seq between the old and new watermark must be
        // correctly recognized as behind the watermark, not wrongly
        // treated as forward progress just because buffered mode
        // itself never saw seq 500 go by.
        buf.insert(200, vec![200]);
        assert_eq!(buf.drain_ready(), Vec::<Vec<u8>>::new());

        // drain_ready only ever delivers from the front of `pending` in
        // ascending-seq order (pre-existing, unmodified behavior --
        // see reorder_buffer_preserves_order_for_buffered_frames_below_
        // watermark) -- so the still-stuck 200 entry would otherwise
        // block 600 from ever being reached, regardless of 600 being
        // past the watermark. That in-order blocking is intentional
        // and out of scope for this task; remove the stuck entry
        // directly so this assertion isolates exactly what this test
        // is for: that note_delivered's watermark stayed accurate.
        buf.pending.remove(&200);

        // A genuinely new frame past the bypass-mode watermark is
        // still correctly forward progress.
        buf.insert(600, vec![600u64 as u8]);
        assert_eq!(buf.drain_ready(), vec![vec![600u64 as u8]]);
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

    #[tokio::test(start_paused = true)]
    async fn reorder_buffer_holds_genuine_reordering_until_stale() {
        // A frame arriving at or below the current watermark is real
        // evidence of cross-link reordering (the buffer's actual intended
        // purpose) -- unlike the "gap" case above, this one legitimately
        // has to wait, same as today's behavior, bounded by the window.
        let mut buf = ReorderBuffer::new(50);
        buf.insert(10, vec![10]);
        assert_eq!(buf.drain_ready(), vec![vec![10]]); // advances watermark to 10

        // seq 5 arrives "late" -- below the watermark. Not immediately
        // delivered.
        buf.insert(5, vec![5]);
        assert_eq!(buf.drain_ready(), Vec::<Vec<u8>>::new());

        // Still not stale yet.
        tokio::time::advance(Duration::from_millis(30)).await;
        assert_eq!(buf.drain_ready(), Vec::<Vec<u8>>::new());

        // Past the 50ms window: delivered via the staleness path, same as
        // today's existing behavior.
        tokio::time::advance(Duration::from_millis(25)).await;
        assert_eq!(buf.drain_ready(), vec![vec![5]]);
    }

    #[test]
    fn reorder_buffer_preserves_order_for_buffered_frames_below_watermark() {
        // Two frames both below/at the watermark, inserted out of order,
        // must still be delivered in ascending seq order relative to each
        // other once they're eligible -- ordering within the genuinely
        // buffered set is still respected, only the "wait for an exact
        // next integer" requirement is gone.
        let mut buf = ReorderBuffer::new(50);
        buf.insert(100, vec![100]);
        assert_eq!(buf.drain_ready(), vec![vec![100]]); // watermark now 100

        // Two "late" frames below the watermark, inserted in reverse order.
        buf.insert(99, vec![99]);
        buf.insert(98, vec![98]);
        // Neither is a forward-progress delivery, so nothing comes out yet.
        assert_eq!(buf.drain_ready(), Vec::<Vec<u8>>::new());
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
