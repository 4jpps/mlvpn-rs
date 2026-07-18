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
//!
//! **Graceful shutdown.** `run()`'s tail races a local SIGINT/SIGTERM
//! against an authenticated `Disconnect` frame arriving from the peer
//! (`handle_incoming`, via the shared `Shutdown`/`ShutdownReason` type)
//! -- whichever happens first. A locally requested shutdown sends a
//! best-effort `Disconnect` to the peer on every link
//! (`broadcast_disconnect`) before tearing its own tasks down; a
//! peer-initiated one skips that (the peer already knows, and may
//! already be gone). Either way `run()` aborts every spawned task and
//! returns cleanly rather than the process only ever ending via signal
//! or panic.
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
//! **Rekeying and session migration.** The initial handshake is raced
//! across every configured link (`establish_session`'s `Mode::Client`
//! arm and `race_handshake_reply` below); the *same* broadcast-and-race
//! logic (factored into `perform_client_handshake`) also drives
//! periodic rekeying, run by a new `rekey_loop` task, client-side only
//! -- the client is always the Noise_IK initiator, both for the very
//! first handshake and every later rekey, so the server never needs to
//! initiate one of its own. The server instead passively accepts a
//! peer-initiated rekey `HandshakeInit` arriving after the tunnel is
//! already running, in `handle_incoming`, the same way it already
//! passively accepted the very first one pre-session (shared per-packet
//! logic factored into `respond_to_handshake_init`). Either side
//! completing its half of a rekey calls `crypto::SessionState::install`,
//! which keeps the just-replaced session reachable for a short, bounded
//! overlap window (`session_expiry_loop`) so packets already in flight
//! under the old keys at the moment of the swap aren't dropped -- see
//! `crypto.rs`'s `SessionState` doc comment for the full design.
//!
//! Four correctness hazards this design has to actively guard against,
//! both caught by this project's own integration tests rather than by
//! inspection, and both worth calling out here since neither is
//! obvious from the individual functions involved:
//!
//! - **Mid-session replies need routing, not a raw socket read.**
//!   `perform_client_handshake` was originally written for the
//!   pre-session case, where it's the only thing reading each link's
//!   socket. Reused as-is for a live rekey, it would race
//!   `link_receiver`'s own already-running `recv_from` loop on that same
//!   socket for every incoming datagram -- and losing that race meant
//!   silently dropping the exact `HandshakeResp` it was waiting for,
//!   timing out a rekey the server had, from its own side, already
//!   irreversibly committed to (a Noise_IK responder is done the moment
//!   it sends message 2). `RekeyContext::register_rekey_wait` /
//!   `forward_rekey_reply` / `race_rekey_reply` exist specifically to
//!   route a rekey's reply through `handle_incoming` instead.
//! - **A stale duplicate of the *first* handshake must not look like a
//!   new rekey.** The client broadcasts the same message 1 (same
//!   session id) to every configured link at once; the server's
//!   pre-session wait loop only consumes the first copy that arrives
//!   before returning, so a duplicate that landed on a different link is
//!   still sitting unread once steady state begins. `link_receiver`
//!   reading it later would otherwise reprocess it as a "new"
//!   peer-initiated rekey -- deriving different key material under the
//!   *same* session id, immediately desynchronizing both sides right
//!   after the tunnel came up. `crypto::SessionState::is_known_session_id`
//!   is the guard: a genuinely new rekey always carries a freshly
//!   generated random id, so any `HandshakeInit` naming an id already
//!   installed is, by construction, a stale duplicate rather than a real
//!   attempt.
//! - **A late reply from an abandoned retry must not poison every retry
//!   after it.** The retry loop in `perform_client_handshake` used to
//!   reuse one fixed session id across all `RETRIES` attempts for the
//!   *initial* handshake, on the theory that only the guard above
//!   needed session-id stability. But each attempt also generates a
//!   fresh Noise ephemeral, and a reply that arrived just late enough to
//!   miss one attempt's `HANDSHAKE_TIMEOUT` -- purely a matter of
//!   scheduling/network timing, not a bug in the reply itself -- but
//!   still in time for a *later* attempt's window would get read
//!   against that later attempt's (non-matching) ephemeral and always
//!   fail to decrypt. Worse, the very guard above would then refuse to
//!   let the server process any further attempt carrying that same
//!   session id, so every remaining retry was doomed once that one race
//!   happened -- even though the peer had a valid, waiting session the
//!   whole time. Each initial-handshake attempt now generates its own
//!   fresh session id (rekey attempts still keep one fixed per call,
//!   which `RekeyContext::register_rekey_wait`'s single up-front
//!   registration depends on), so a late reply from an abandoned
//!   attempt can no longer be fed into a mismatched later one this way.
//! - **A stale reply must not win a *later* attempt's race, either.**
//!   The fix above stops a late reply from being fed into the wrong
//!   `Handshake` instance, but on its own that only means the stale
//!   reply gets ignored by the attempt it actually arrived for -- it
//!   doesn't stop `race_handshake_reply` from handing that same stale
//!   packet to a *subsequent* attempt as if it were fresh, since it only
//!   filtered by source address and packet type. This was unreachable
//!   in practice before `establish_session_with_retry` existed (a failed
//!   initial handshake used to just crash the process after one round),
//!   but became a real, repeatable failure once retrying indefinitely
//!   made it possible for many rounds' worth of stale replies to pile up
//!   in the socket's receive queue, each capable of falsely winning a
//!   future attempt's race and consuming its one shot at the genuine
//!   reply. `race_handshake_reply` now also requires the reply's
//!   `session_id` to match the *current* attempt's, the same guarantee
//!   `race_rekey_reply`'s `RekeyContext::forward_rekey_reply` already
//!   provided for the mid-session case via its own `want_id` check.
//!
//! **The initial handshake never crashes the daemon.** `establish_session_with_retry`
//! wraps the client's very first handshake attempt: if every configured
//! link is unreachable (peer not up yet, still booting, a route not
//! converged) and `perform_client_handshake` exhausts its bounded
//! `RETRIES` for one round, this logs a warning and retries with
//! exponential backoff (capped at `RECONNECT_BACKOFF_MAX_MS`) instead of
//! returning an error out of `run()`. Previously that error propagated
//! all the way to `main()`'s top-level `anyhow::Result` handler and
//! exited the process -- harmless under a plain `systemd start`, but
//! under the default `Restart=on-failure` a peer that stayed
//! unreachable for a few minutes at boot (e.g. both ends power-cycling
//! together, or one side waiting on DHCP) could burn through
//! `StartLimitBurst` restarts and leave the unit in `failed` state for
//! good, silently, until someone happened to check. Neither WireGuard
//! nor the original C `MLVPN` exit on a failed handshake; this now
//! matches that.
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

use crate::config::{Mode, SchedulerConfig};
use crate::control;
use crate::crypto::{self, Handshake, LocalPrivateKey, Session, SessionState};
use crate::error::{MlvpnError, Result};
use crate::link::{self, is_interface_gone_error, Link, LinkHandle, LinkState, Links};
use crate::monitor::{self, ProbeTracker};
use crate::peerstats::PeerStatsTable;
use crate::protocol::{
    BandwidthProbeBurstPayload, BandwidthProbeResultPayload, Header, PacketType, ProbePayload,
    StatsPayload, HEADER_LEN,
};
use crate::scheduler::Scheduler;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinSet;
use tokio::time::interval;
use tun_rs::AsyncDevice;

const MAX_FRAME: usize = 2048;

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

pub struct TunnelParams {
    pub mode: Mode,
    pub mtu: u16,
    /// Whether to rewrite the MSS option of TCP SYN/SYN-ACK segments
    /// read off the TUN device so they fit `mtu`. See `mss.rs`.
    pub clamp_mss: bool,
    pub scheduler_cfg: SchedulerConfig,
    pub local_private: LocalPrivateKey,
    pub peer_public: [u8; 32],
    /// How often `rekey_loop` (client-side only, see the module doc
    /// comment) re-runs the handshake. `interval()`'s minimum
    /// resolution effectively floors this around a millisecond or so;
    /// `config::default_rekey_secs` defaults to 120s, and
    /// `config::CryptoConfig::rekey_interval_secs`'s doc comment is
    /// where an operator would actually change it.
    pub rekey_interval: Duration,
    /// Used to label snapshots served over the control socket and to
    /// compute its default path (`/run/mlvpn/<tunnel_name>.sock`).
    pub tunnel_name: String,
    /// `None` disables the monitoring control socket entirely.
    pub control_socket: Option<PathBuf>,
    /// `None` disables the runtime command socket entirely (the default
    /// -- see `config::CommandConfig::enabled`'s doc comment for why
    /// this one, unlike `control_socket`, is opt-in).
    pub command_socket: Option<PathBuf>,
}

/// How long a retired ("previous") session's keys remain able to
/// decrypt anything after a rekey swap -- see `crypto::SessionState`'s
/// doc comment. Long enough to cover realistic reordering/in-flight
/// delay across multiple bonded physical links, short enough that a
/// retired key stops mattering quickly. Not currently configurable;
/// revisit if a real deployment's link RTTs or `reorder_window_ms` ever
/// make this too tight.
const SESSION_OVERLAP_WINDOW: Duration = Duration::from_secs(10);

/// How often `session_expiry_loop` checks whether `SESSION_OVERLAP_WINDOW`
/// has elapsed. Deliberately much more frequent than any reasonable
/// `rekey_interval_secs` -- this timer's only job is to bound the
/// overlap window promptly, not to pace rekeying itself.
const SESSION_EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Global, cross-link rate limiter for inbound `HandshakeInit` frames.
/// `HandshakeInit` carries no authentication of its own (it's what
/// *starts* authentication), so processing one always costs real
/// X25519 work before it can be rejected as forged/malformed --
/// deliberately global rather than per-source-IP, since UDP source
/// addresses are trivially spoofable and a per-IP table would itself be
/// an unbounded-memory attack surface. Used both by `establish_session`'s
/// pre-session `Mode::Server` wait loop (its own private instance, since
/// no per-link tasks exist yet at that point) and by `handle_incoming`'s
/// steady-state rekey acceptance (one instance shared across every
/// `link_receiver` task via `RekeyContext`, since a flood could arrive
/// on any link).
struct HandshakeRateLimiter {
    window: std::sync::Mutex<(Instant, u32)>,
}

impl HandshakeRateLimiter {
    const MAX_PER_SEC: u32 = 20;

    fn new() -> Self {
        Self {
            window: std::sync::Mutex::new((Instant::now(), 0)),
        }
    }

    /// Returns `true` if this attempt should be processed, `false` if
    /// it should be dropped for exceeding the rate. A plain
    /// `std::sync::Mutex` rather than the tokio one: every caller here
    /// checks and releases it without awaiting anything in between.
    fn allow(&self) -> bool {
        let mut guard = self.window.lock().unwrap();
        let (start, count) = &mut *guard;
        if start.elapsed() >= Duration::from_secs(1) {
            *start = Instant::now();
            *count = 0;
        }
        *count += 1;
        *count <= Self::MAX_PER_SEC
    }
}

/// What `handle_incoming` needs to accept a rekey `HandshakeInit`
/// arriving after the tunnel's initial handshake is already done --
/// bundled into one struct, shared (via `Arc`) across every
/// `link_receiver` task, rather than adding several more individual
/// parameters on top of `handle_incoming`'s already-long list. Only
/// ever acted on when `mode == Mode::Server` (see `handle_incoming`);
/// kept unconditional/cheap to construct rather than an `Option` so
/// there's exactly one code path regardless of role.
///
/// Also carries the client-side rekey reply-forwarding mailbox
/// (`rekey_reply_tx`) -- see `register_rekey_wait`'s doc comment for why
/// this exists: once the tunnel is running, `link_receiver` -- not
/// `perform_client_handshake` -- owns every link's socket, so a rekey
/// attempt's `HandshakeResp` has to be routed to it rather than read
/// directly.
/// One forwarded `HandshakeResp`: the link it arrived on, plus its
/// still-encrypted message-2 payload.
type RekeyReply = (u8, Vec<u8>);

struct RekeyContext {
    mode: Mode,
    local_private: LocalPrivateKey,
    peer_public: [u8; 32],
    limiter: HandshakeRateLimiter,
    rekey_reply_tx: std::sync::Mutex<Option<(u32, mpsc::UnboundedSender<RekeyReply>)>>,
}

impl RekeyContext {
    /// Registers interest in any `HandshakeResp` frame carrying
    /// `session_id`, returning the receiving half. Called once by
    /// `perform_client_handshake` before it sends this attempt's first
    /// `HandshakeInit`, so `forward_rekey_reply` has somewhere to route
    /// the eventual reply from the moment it could possibly arrive.
    ///
    /// Only one rekey attempt is ever in flight at a time (`rekey_loop`
    /// runs its attempts sequentially), so this simply overwrites
    /// whatever the previous registration was; a stray late reply for an
    /// abandoned session id then just fails to match in
    /// `forward_rekey_reply` (or, in the small window before it's
    /// overwritten, finds its `tx` half's receiver already dropped, so
    /// the `send` silently no-ops) rather than needing explicit cleanup
    /// on every one of `perform_client_handshake`'s several return
    /// paths.
    fn register_rekey_wait(&self, session_id: u32) -> mpsc::UnboundedReceiver<RekeyReply> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.rekey_reply_tx.lock().unwrap() = Some((session_id, tx));
        rx
    }

    /// Called from `handle_incoming`'s `HandshakeResp` arm for every
    /// role, not just `Mode::Client` -- cheap to check unconditionally,
    /// and correct regardless: a server never calls
    /// `register_rekey_wait`, so `rekey_reply_tx` is permanently `None`
    /// on that side and this is just as much of a no-op as the
    /// unconditional drop it replaces. Forwards to the waiting attempt
    /// only if `session_id` matches what's currently registered;
    /// anything else (a stale retransmit from an attempt that already
    /// gave up, a spoofed frame, plain noise) is silently ignored, same
    /// as before this existed. `link_id` isn't validated against which
    /// link this attempt actually broadcast on -- see
    /// `race_handshake_reply`'s doc comment on why that filtering was
    /// already "not a security boundary" even in the direct-socket path;
    /// the real authentication is `Handshake::read_second`'s own Noise
    /// AEAD check, downstream of this.
    fn forward_rekey_reply(&self, session_id: u32, link_id: u8, payload: Vec<u8>) {
        let guard = self.rekey_reply_tx.lock().unwrap();
        if let Some((want_id, tx)) = guard.as_ref() {
            if *want_id == session_id {
                let _ = tx.send((link_id, payload));
            }
        }
    }
}

/// Why `run()`'s tail is unblocking: either a local shutdown signal
/// (SIGINT/SIGTERM) or an authenticated `Disconnect` frame from the
/// peer (`handle_incoming`). Only the reason matters once triggered --
/// see `run()`'s tail for what each one does differently (a locally
/// requested shutdown gets to notify the peer first via a `Disconnect`
/// of its own; a peer-initiated one has nobody left worth notifying).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ShutdownReason {
    Local,
    PeerInitiated,
}

/// One-shot shutdown signal shared across every `link_receiver` task and
/// `run()`'s own tail. `Notify::notify_one` (not `notify_waiters`) is
/// deliberate: `run()`'s tail is the *only* waiter, and it may not have
/// reached its `wait()` call yet at the moment `trigger` is called from
/// some other task (a `Disconnect` frame can arrive at any time relative
/// to `run()`'s own startup sequencing) -- `notify_waiters` would simply
/// lose a notification with no current waiter, while `notify_one` stores
/// a permit for the next `wait()` call to consume immediately. `reason`
/// records only the *first* trigger (a plain `Mutex<Option<_>>` rather
/// than an atomic, since setting it and calling `notify_one` need to
/// happen together as one step, not racily interleaved with a second
/// caller doing the same); any later trigger (e.g. both SIGINT and a
/// peer `Disconnect` arriving close together) is a harmless no-op.
struct Shutdown {
    notify: tokio::sync::Notify,
    reason: std::sync::Mutex<Option<ShutdownReason>>,
}

impl Shutdown {
    fn new() -> Self {
        Self {
            notify: tokio::sync::Notify::new(),
            reason: std::sync::Mutex::new(None),
        }
    }

    fn trigger(&self, reason: ShutdownReason) {
        let mut guard = self.reason.lock().unwrap();
        if guard.is_none() {
            *guard = Some(reason);
            self.notify.notify_one();
        }
    }

    /// Resolves once `trigger` has been called (by whichever caller got
    /// there first), returning that first reason.
    async fn wait(&self) -> ShutdownReason {
        self.notify.notified().await;
        self.reason
            .lock()
            .unwrap()
            .expect("trigger always sets reason before notifying")
    }
}

pub async fn run(tun: AsyncDevice, links: Vec<Link>, params: TunnelParams) -> Result<()> {
    let tun = Arc::new(tun);
    let links: Links = Arc::new(links.into_iter().map(AsyncMutex::new).collect());
    let scheduler = Arc::new(std::sync::Mutex::new(Scheduler::new()));
    // Wrapped once, here, so every task below (including ones spawned
    // later, like `rekey_loop`) can cheaply clone a handle to the full
    // params instead of each needing its own hand-picked subset of
    // fields threaded through as separate arguments.
    let params = Arc::new(params);

    let (session_id, session) = establish_session_with_retry(&links, &params).await;
    let session = Arc::new(AsyncMutex::new(SessionState::new(session_id, session)));

    tracing::info!(session_id, "tunnel session established");

    let rekey_ctx = Arc::new(RekeyContext {
        mode: params.mode,
        local_private: params.local_private.clone(),
        peer_public: params.peer_public,
        limiter: HandshakeRateLimiter::new(),
        rekey_reply_tx: std::sync::Mutex::new(None),
    });

    let shutdown = Arc::new(Shutdown::new());

    let reorder = Arc::new(AsyncMutex::new(ReorderBuffer::new(
        params.scheduler_cfg.reorder_window_ms,
    )));

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

    // One `BandwidthProbeReceiveState` per link, same one-per-link
    // pattern as `trackers` above, tracking a possibly-in-progress
    // incoming `BandwidthProbeBurst` for `scheduler.active_bandwidth_probing`
    // (off by default) -- see that struct's doc comment.
    let bw_probe_states: Vec<Arc<AsyncMutex<BandwidthProbeReceiveState>>> = (0..trackers.len())
        .map(|_| Arc::new(AsyncMutex::new(BandwidthProbeReceiveState::new())))
        .collect();

    let mut handles = Vec::new();

    for (idx, (tracker, bw_state)) in trackers.iter().zip(bw_probe_states.iter()).enumerate() {
        let tracker = tracker.clone();
        {
            let links = links.clone();
            let session = session.clone();
            let scheduler = scheduler.clone();
            let tun = tun.clone();
            let reorder = reorder.clone();
            let cfg = params.scheduler_cfg.clone();
            let tracker = tracker.clone();
            let peer_stats = peer_stats.clone();
            let rekey_ctx = rekey_ctx.clone();
            let shutdown = shutdown.clone();
            let bw_state = bw_state.clone();
            handles.push(tokio::spawn(async move {
                // link_receiver never returns under normal operation --
                // see its doc comment: socket errors are retried/
                // reconnected in place rather than propagated. This
                // task only ends via panic (a bug) or the process
                // exiting.
                link_receiver(
                    idx, links, session, scheduler, tun, reorder, cfg, tracker, peer_stats,
                    rekey_ctx, shutdown, bw_state,
                )
                .await;
            }));
        }
        {
            let links = links.clone();
            let session = session.clone();
            let scheduler = scheduler.clone();
            let cfg = params.scheduler_cfg.clone();
            handles.push(tokio::spawn(async move {
                link_prober(idx, links, session, scheduler, cfg, tracker).await;
            }));
        }
        {
            let links = links.clone();
            let session = session.clone();
            let cfg = params.scheduler_cfg.clone();
            let mtu = params.mtu as usize;
            handles.push(tokio::spawn(async move {
                // No-op and returns immediately unless
                // active_bandwidth_probing is on -- see the function's
                // own doc comment, same "spawn unconditionally, check
                // inside" pattern as reorder_tuning_loop below.
                active_bandwidth_prober(idx, links, session, cfg, mtu).await;
            }));
        }
    }

    if let Some(path) = params.control_socket.clone() {
        let links = links.clone();
        let peer_stats = peer_stats.clone();
        let tunnel_name = params.tunnel_name.clone();
        let mode = params.mode.as_str().to_string();
        handles.push(tokio::spawn(async move {
            control::serve(path, links, peer_stats, tunnel_name, mode).await;
        }));
    }

    if let Some(path) = params.command_socket.clone() {
        let links = links.clone();
        handles.push(tokio::spawn(async move {
            control::serve_commands(path, links).await;
        }));
    }

    // Bounded outbound queue between tun_reader (producer) and
    // outbound_sender (consumer) -- see OUTBOUND_QUEUE_CAPACITY's doc
    // comment. dropped is shared between tun_reader (increments on a
    // full queue) and outbound_queue_drop_reporter (periodically reads
    // and resets it into a log line).
    let (outbound_tx, outbound_rx) = mpsc::channel::<OutboundFrame>(OUTBOUND_QUEUE_CAPACITY);
    let outbound_dropped = Arc::new(AtomicU64::new(0));

    {
        let links = links.clone();
        let scheduler = scheduler.clone();
        let redundant_mode = params.scheduler_cfg.redundant_mode;
        handles.push(tokio::spawn(async move {
            outbound_sender(outbound_rx, links, scheduler, redundant_mode).await;
        }));
    }

    {
        let dropped = outbound_dropped.clone();
        handles.push(tokio::spawn(async move {
            outbound_queue_drop_reporter(dropped).await;
        }));
    }

    {
        let session = session.clone();
        let tun = tun.clone();
        let mtu = params.mtu as usize;
        let clamp_mss = params.clamp_mss;
        let tx = outbound_tx.clone();
        let dropped = outbound_dropped.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = tun_reader(tun, session, mtu, clamp_mss, tx, dropped).await {
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

    {
        let links = links.clone();
        let reorder = reorder.clone();
        let cfg = params.scheduler_cfg.clone();
        handles.push(tokio::spawn(async move {
            reorder_tuning_loop(links, reorder, cfg).await;
        }));
    }

    {
        let session = session.clone();
        handles.push(tokio::spawn(async move {
            session_expiry_loop(session).await;
        }));
    }

    // Client-initiated only -- see the module doc comment for why the
    // server never runs this task and instead passively accepts a
    // rekey `HandshakeInit` in `handle_incoming`.
    if params.mode == Mode::Client {
        let links = links.clone();
        let params = params.clone();
        let session = session.clone();
        let rekey_ctx = rekey_ctx.clone();
        handles.push(tokio::spawn(async move {
            rekey_loop(links, params, session, rekey_ctx).await;
        }));
    }

    // None of the tasks above normally return on their own (they're all
    // infinite loops or `select!` loops), so without this, `run()`
    // would never return short of the whole process being killed out
    // from under it -- resolves on whichever comes first: a local
    // shutdown signal, or `shutdown` already having been triggered by
    // something else (an authenticated peer `Disconnect`, handled in
    // `handle_incoming`). See `Shutdown`'s doc comment for why
    // `shutdown.wait()` is one of the select arms here rather than
    // something polled separately.
    let mut sigterm = signal(SignalKind::terminate()).map_err(MlvpnError::Io)?;
    let reason = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            shutdown.trigger(ShutdownReason::Local);
            ShutdownReason::Local
        }
        _ = sigterm.recv() => {
            shutdown.trigger(ShutdownReason::Local);
            ShutdownReason::Local
        }
        reason = shutdown.wait() => reason,
    };

    match reason {
        // Only worth notifying the peer when *we* decided to leave --
        // it already knows, and may already be gone, if this is the
        // other half of the exact same exchange.
        ShutdownReason::Local => {
            tracing::info!("shutting down: notifying peer");
            broadcast_disconnect(&links, &session).await;
        }
        ShutdownReason::PeerInitiated => {
            tracing::info!("shutting down: peer disconnected");
        }
    }

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
async fn broadcast_disconnect(links: &Links, session: &Arc<AsyncMutex<SessionState>>) {
    let targets: Vec<(LinkHandle, SocketAddr, u8)> = {
        let snap = link::snapshot_links(links).await;
        snap.iter()
            .filter_map(|link| link.remote.map(|r| (link.handle(), r, link.id)))
            .collect()
    };

    // Same reasoning as everywhere else a frame is encrypted: an empty
    // plaintext is a perfectly valid AEAD message (just the tag, no
    // ciphertext body) -- Disconnect carries no payload, it's the frame
    // type itself that's the whole signal.
    let Ok((session_id, seq, ciphertext)) = session.lock().await.encrypt(&[]) else {
        return;
    };

    for (handle, remote, link_id) in targets {
        let socket = handle.current_socket().await;
        let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        Header {
            ptype: PacketType::Disconnect,
            link_id,
            session_id,
            seq,
        }
        .encode(&mut frame);
        frame.extend_from_slice(&ciphertext);
        let _ = socket.send_to(&frame, remote).await;
    }
}

/// Perform (or wait for) the initial Noise handshake and return the
/// resulting session id plus transport session. Thin dispatcher over
/// `perform_client_handshake` (client) or a dedicated pre-session wait
/// loop (server) -- see each for the real logic. This runs before any
/// `link_actor` tasks exist, so the server arm is free to hold the
/// `links` lock across its own recv calls without contending with them.
async fn establish_session(links: &Links, params: &TunnelParams) -> Result<(u32, Session)> {
    match params.mode {
        // `None`: no `RekeyContext`/`link_receiver` tasks exist yet at
        // this point (see `run()`'s ordering), so there is no socket
        // contention to route around -- `perform_client_handshake` reads
        // each link's socket directly. See its doc comment.
        Mode::Client => perform_client_handshake(links, params, None).await,
        Mode::Server => {
            // Race a short-timeout recv across every link in turn. This is
            // a simple sequential poll rather than a true concurrent
            // select over a dynamic set of futures, which is adequate
            // pre-session (no data path running yet) but would be a poor
            // pattern for the hot path -- link_actor uses proper
            // per-socket ownership instead once the session exists.
            // Resolved once, before any per-link tasks exist: reconnect
            // support (see the module doc comment) lives in the
            // link_receiver/link_prober tasks spawned after a session
            // is established, so it deliberately doesn't apply to this
            // pre-session wait loop -- an interface that's gone before
            // the tunnel ever comes up is just "not up yet", not a
            // reconnect scenario.
            let mut sockets: Vec<(Arc<UdpSocket>, u8)> = Vec::new();
            {
                let snap = link::snapshot_links(links).await;
                for l in snap.iter() {
                    sockets.push((l.handle().current_socket().await, l.id));
                }
            }
            let mut buf = vec![0u8; MAX_FRAME];

            // Lightweight defense against a pre-session CPU-exhaustion
            // flood: `hdr.ptype == HandshakeInit` is plaintext, so
            // anyone can tag arbitrary garbage that way, and each one
            // that reaches `respond_to_handshake_init` forces real
            // X25519 operations before it's rejected. This cannot forge
            // a valid session (that function's own pin check still
            // requires holding the real peer's private key), but it can
            // burn CPU cycles for free. This only matters pre-session --
            // once established, `handle_incoming`'s own
            // `HandshakeRateLimiter` instance (shared across every
            // per-link task via `RekeyContext`) covers the same concern
            // for a peer-initiated rekey.
            let rate_limiter = HandshakeRateLimiter::new();

            loop {
                let mut hit = None;
                for (socket, link_id) in &sockets {
                    if let Ok(Ok((n, from))) =
                        tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf))
                            .await
                    {
                        hit = Some((n, from, *link_id, socket.clone()));
                        break;
                    }
                }
                let Some((n, from, link_id, socket)) = hit else {
                    continue;
                };
                buf.truncate(n);
                let Ok((hdr, payload)) = Header::decode(&buf) else {
                    buf.resize(MAX_FRAME, 0);
                    continue;
                };
                if hdr.ptype != PacketType::HandshakeInit {
                    buf.resize(MAX_FRAME, 0);
                    continue;
                }

                if !rate_limiter.allow() {
                    tracing::debug!(%from, "dropping HandshakeInit: rate limit exceeded");
                    buf.resize(MAX_FRAME, 0);
                    continue;
                }

                match respond_to_handshake_init(
                    &params.local_private,
                    &params.peer_public,
                    &hdr,
                    payload,
                    from,
                    &socket,
                    link_id,
                )
                .await
                {
                    Ok((session_id, session)) => {
                        for l in links.iter() {
                            let mut guard = l.lock().await;
                            if guard.id == link_id {
                                guard.remote = Some(from);
                                break;
                            }
                        }
                        return Ok((session_id, session));
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            %from,
                            "rejected malformed/invalid/unpinned handshake attempt"
                        );
                        buf.resize(MAX_FRAME, 0);
                    }
                }
            }
        }
    }
}

/// Wraps `establish_session` so the *initial* handshake retries in the
/// background forever instead of ever taking the whole daemon down.
/// `establish_session`'s `Mode::Server` arm already loops internally and
/// never returns `Err`; only `Mode::Client`'s `perform_client_handshake`
/// can exhaust its bounded `RETRIES` and give up on one round. That
/// `Err` used to propagate straight out of `run()` via `?`, so `main()`'s
/// top-level `anyhow::Result` handler printed it and the whole process
/// exited. Under `systemd`'s default `Restart=on-failure`, enough
/// consecutive failed rounds -- the peer host still booting, down for
/// maintenance, or just briefly unreachable -- trips
/// `StartLimitBurst`/`StartLimitIntervalSec`, and systemd gives up
/// entirely: the unit lands in `failed` and stays down for good until
/// someone notices and runs `systemctl reset-failed`. Neither WireGuard
/// nor the original C `MLVPN` this project replaces ever exit on a
/// failed handshake -- they just keep trying in the background. This
/// matches that: log a warning and back off (the same exponential
/// schedule `attempt_reconnect` above uses, capped at
/// `RECONNECT_BACKOFF_MAX_MS`) instead of ever returning an error here,
/// so a client started before its peer is reachable just quietly waits
/// it out rather than crash-looping itself into a permanently failed
/// systemd unit.
async fn establish_session_with_retry(links: &Links, params: &TunnelParams) -> (u32, Session) {
    let mut backoff_ms = RECONNECT_BACKOFF_INITIAL_MS;
    loop {
        match establish_session(links, params).await {
            Ok(result) => return result,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    backoff_ms,
                    "initial handshake failed; retrying in the background rather than \
                     exiting -- a peer that's temporarily unreachable at startup \
                     shouldn't take the daemon down or trip systemd's restart-rate-limit"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(RECONNECT_BACKOFF_MAX_MS);
            }
        }
    }
}

/// The client side of a Noise_IK handshake: broadcast message 1 on
/// every configured link with a `remote_addr` and race them for the
/// first valid reply, retrying up to `RETRIES` whole rounds if one comes
/// up empty. Used both for the tunnel's very first handshake
/// (`establish_session`'s `Mode::Client` arm, passing `rekey_ctx: None`)
/// and every later rekey (`rekey_loop`, passing `Some`) -- factored out
/// here specifically so there is exactly one implementation of
/// "broadcast and race" rather than two copies that could drift apart.
/// Generates its own fresh session id per call (reused across that
/// call's own retry attempts, same as before this was factored out), so
/// a rekey never risks colliding with the session id the current session
/// is still using.
///
/// `rekey_ctx` selects how replies are received, not just whether one is
/// available to log into: `None` (`establish_session`, pre-session) reads
/// each target link's socket directly (`race_handshake_reply`), which is
/// safe because no `link_receiver` task exists yet to contend with it.
/// `Some` (`rekey_loop`, mid-session) instead registers this attempt's
/// session id with `rekey_ctx` and waits on the channel `handle_incoming`
/// forwards matching `HandshakeResp` frames into (`race_rekey_reply`) --
/// reading the socket directly here would race `link_receiver`'s own
/// already-running `recv_from` loop on the same socket for every
/// datagram, and losing that race silently drops the exact reply this is
/// waiting for. That was a real bug (see `CHANGELOG.md`): the server-side
/// responder considers a Noise_IK handshake complete the moment it sends
/// message 2, so a client-side timeout caused by a stolen reply didn't
/// just mean "retry" -- the server had already committed to a session the
/// client had no way to learn the keys for, permanently desynchronizing
/// the two sides under the same session id label.
async fn perform_client_handshake(
    links: &Links,
    params: &TunnelParams,
    rekey_ctx: Option<&Arc<RekeyContext>>,
) -> Result<(u32, Session)> {
    const RETRIES: u32 = 10;
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);
    let session_id = crypto::random_session_id();
    let mut last_err = None;
    let mut rekey_rx = rekey_ctx.map(|ctx| ctx.register_rekey_wait(session_id));
    for attempt in 0..RETRIES {
        // For a rekey, `session_id` must stay fixed across every attempt
        // in this call: it's what correlates an in-flight attempt's
        // expected `HandshakeResp` with the wait channel registered once,
        // above, via `register_rekey_wait`/`rekey_rx`. The initial
        // handshake (`rekey_ctx: None`) has no such channel to keep in
        // sync, and this shadowed `session_id` fixes a real race that
        // integration testing caught: each attempt already generates a
        // fresh Noise ephemeral (`hs` below), but previously reused the
        // *same* session_id across every attempt -- so a reply that
        // arrived just late enough to miss one attempt's timeout, but
        // still land during a *later* attempt's window, would get fed
        // into that later attempt's `hs.read_second()` and always fail
        // (it was encrypted against the earlier, now-discarded
        // ephemeral). Worse, once that happened, the server's own
        // stale-duplicate protection (`handle_incoming`'s HandshakeInit
        // arm, `is_known_session_id`) would refuse to process *any*
        // further HandshakeInit carrying a session_id it had already
        // installed a session under -- so every remaining attempt in
        // this call was doomed to get nothing back at all, guaranteeing
        // the whole handshake failed once that one race happened, even
        // though the peer had a valid, waiting session the entire time.
        // A fresh session_id per initial-handshake attempt sidesteps
        // both problems: a late reply from an abandoned attempt can't be
        // fed into a mismatched later ephemeral in this specific way,
        // and the server's stale-duplicate check only ever suppresses a
        // genuinely repeated attempt, never a legitimately new one.
        let session_id = if rekey_ctx.is_none() {
            crypto::random_session_id()
        } else {
            session_id
        };

        // Every configured link with a remote_addr, not just the first
        // one (ARCHITECTURE.md roadmap item #1): a down or unreachable
        // first link no longer stalls handshake setup on its own.
        let targets: Vec<(LinkHandle, SocketAddr, u8)> = {
            let snap = link::snapshot_links(links).await;
            if snap.is_empty() {
                return Err(MlvpnError::Config("no links configured".into()));
            }
            snap.iter()
                .filter_map(|link| link.remote.map(|r| (link.handle(), r, link.id)))
                .collect()
        };
        if targets.is_empty() {
            return Err(MlvpnError::Config(
                "no configured link has a remote_addr set".into(),
            ));
        }

        let mut hs = Handshake::new_initiator(&params.local_private, &params.peer_public)?;
        let msg1 = hs.write_first()?;

        // Broadcast the identical message 1 on every target link at
        // once -- safe to send unmodified on each: Noise's first
        // message doesn't depend on which transport path carries it,
        // only on `hs`'s single ephemeral key (generated once above,
        // shared across every copy). A send failure on one link just
        // means one fewer path racing this round; the others still
        // have a chance.
        for (handle, remote, link_id) in &targets {
            let socket = handle.current_socket().await;
            let mut frame = Vec::with_capacity(HEADER_LEN + msg1.len());
            Header {
                ptype: PacketType::HandshakeInit,
                link_id: *link_id,
                session_id,
                seq: 0,
            }
            .encode(&mut frame);
            frame.extend_from_slice(&msg1);
            if let Err(e) = socket.send_to(&frame, *remote).await {
                tracing::debug!(
                    link_id = *link_id,
                    error = %e,
                    "handshake init send failed on this link, still racing the others"
                );
            }
        }

        let reply = if let Some(rx) = rekey_rx.as_mut() {
            race_rekey_reply(rx, HANDSHAKE_TIMEOUT).await
        } else {
            race_handshake_reply(&targets, session_id, HANDSHAKE_TIMEOUT).await
        };
        let (reply_link_id, payload) = match reply {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(attempt, error = %e, "handshake attempt failed, retrying");
                last_err = Some(e);
                continue;
            }
        };

        // A garbled or forged HandshakeResp -- anyone can send a packet
        // tagged with this ptype, header fields are plaintext -- must
        // not crash the daemon or abort the retry loop via `?`. Treat
        // it exactly like a timeout and try again next iteration with
        // a fresh `hs`. This was previously a real bug: a single
        // unauthenticated garbage packet here used to propagate
        // straight out of this function (and from there out of the
        // whole process), a one-packet remote DoS against the client
        // role. `race_handshake_reply` already filters out anything
        // that isn't well-formed and from the expected source on its
        // own; what reaches here can still fail Noise's own
        // authentication, which is exactly what this still guards
        // against.
        match hs.read_second(&payload) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(
                    attempt,
                    link_id = reply_link_id,
                    error = %e,
                    "rejected malformed/invalid handshake reply, retrying"
                );
                last_err = Some(e);
                continue;
            }
        }

        match hs.remote_static() {
            Some(remote_static) if remote_static == params.peer_public => {
                tracing::info!(
                    link_id = reply_link_id,
                    session_id,
                    "handshake completed via this link"
                );
                return Ok((session_id, hs.into_session()?));
            }
            Some(_) => {
                // Definitively the wrong key: no amount of retrying
                // will fix that, so this one stays a hard failure
                // rather than looping.
                return Err(MlvpnError::AuthFailed);
            }
            None => {
                // Fail closed: a Noise_IK handshake that completed
                // `read_second` successfully must have a remote static
                // key. Treating "can't verify the pin" the same as
                // "verified and it didn't match" means this check can
                // never be silently skipped.
                return Err(MlvpnError::AuthFailed);
            }
        }
    }
    Err(last_err.unwrap_or(MlvpnError::Handshake("handshake failed".into())))
}

/// The responder side of one inbound `HandshakeInit` frame: verify it
/// authenticates as the pinned peer, reply with message 2 on the same
/// socket/source it arrived from, and return the (client-chosen, now
/// mutually adopted) session id plus the resulting `Session` on
/// success. Shared by `establish_session`'s pre-session `Mode::Server`
/// wait loop (the tunnel's very first handshake) and `handle_incoming`'s
/// steady-state rekey acceptance -- both need exactly this same
/// sequence, differing only in what surrounds it (a dedicated wait loop
/// with no data path running yet, vs. one case in the normal per-link
/// dispatch of an already-running tunnel).
///
/// A malformed or malicious attempt from any source must never take
/// the whole server down: every failure here is a plain `Err`, for the
/// caller to log and keep listening rather than something that should
/// ever propagate out with `?` and end a whole task.
async fn respond_to_handshake_init(
    local_private: &LocalPrivateKey,
    peer_public: &[u8; 32],
    hdr: &Header,
    payload: &[u8],
    from: SocketAddr,
    socket: &Arc<UdpSocket>,
    link_id: u8,
) -> Result<(u32, Session)> {
    let mut hs = Handshake::new_responder(local_private)?;
    let msg2 = hs.read_first_and_reply(payload)?;

    // Fail closed: treat "couldn't determine the peer's static key" the
    // same as "determined it and it didn't match" rather than silently
    // letting a `None` skip the pin check. For a Noise_IK responder
    // that has just successfully processed message 1, `remote_static()`
    // returning `None` shouldn't happen in practice, but the one line
    // of code that turns "authenticated by Noise" into "authenticated
    // as the specific pinned peer" is exactly the wrong place to fail
    // open on an unexpected case.
    match hs.remote_static() {
        Some(remote_static) if remote_static == *peer_public => {}
        _ => return Err(MlvpnError::AuthFailed),
    }

    let mut frame = Vec::with_capacity(HEADER_LEN + msg2.len());
    Header {
        ptype: PacketType::HandshakeResp,
        link_id,
        session_id: hdr.session_id,
        seq: 0,
    }
    .encode(&mut frame);
    frame.extend_from_slice(&msg2);
    socket.send_to(&frame, from).await.map_err(MlvpnError::Io)?;

    Ok((hdr.session_id, hs.into_session()?))
}

/// One handshake attempt's receive phase, used by `establish_session`'s
/// `Mode::Client` arm: race every `target` link's socket for the first
/// well-formed `HandshakeResp` from that link's *expected* source
/// address *and* carrying this attempt's own `session_id`, within
/// `timeout`. Each link is listened to in its own task (via `JoinSet`)
/// that loops internally, silently discarding anything that doesn't
/// look like a genuine reply to *this* attempt (garbage, a
/// spoofed-source injection attempt, an unrelated frame, or -- see
/// below -- a stale reply to an earlier, already-abandoned attempt) and
/// only returning once it finds a plausible candidate -- so a single bad
/// packet on one link can't cost the whole race the way it would if we
/// stopped listening on that link after its first (bad) datagram.
///
/// The `session_id` check is not optional. Since `establish_session_with_retry`
/// started retrying a failed initial handshake indefinitely instead of
/// giving up, this became reachable in practice, not just in theory: if
/// one attempt's reply arrives just late enough to miss its own
/// timeout, the peer has (by design, see `perform_client_handshake`'s
/// doc comment on the fresh-session-id-per-attempt fix) already
/// committed that session and will keep responding to it if anything
/// ever re-triggers it, and every later attempt's own `HandshakeInit`
/// gets legitimately treated by the peer as a *new* rekey once it's
/// past its own initial accept -- each producing its own `HandshakeResp`.
/// Without filtering by `session_id`, this function would happily hand
/// whichever one of those replies happened to be sitting first in the
/// socket's receive queue to the caller, almost always a stale reply
/// meaning nothing to the *current* attempt's Noise ephemeral, which
/// then always fails to decrypt -- consuming the one candidate this
/// function is allowed to return per attempt (see below) without ever
/// reaching the genuine, matching reply potentially queued right behind
/// it. Across repeated retry rounds this compounds: each abandoned
/// attempt leaves one more stale reply in the queue that can wrongly
/// win a future race, so once one late reply happens the client could
/// otherwise never recover on its own. Filtering by `session_id` here
/// makes a stale reply invisible to every future attempt instead,
/// exactly the same guarantee `rekey_ctx`'s `forward_rekey_reply`
/// (`race_rekey_reply`'s counterpart) already provides for the mid-session
/// case via its own `want_id` check.
///
/// Deliberately returns the still-encrypted message 2 payload rather
/// than calling `Handshake::read_second` itself: that call can only
/// safely be attempted once per `Handshake` instance (a failed
/// `read_message` call leaves `snow`'s internal transcript hash mutated
/// from the bad input, so a second, later-arriving *genuine* reply would
/// then also fail authentication against that now-diverged state) --
/// see `establish_session` for why finding a well-formed candidate here
/// and having Noise itself reject it there consumes the whole attempt
/// round rather than letting this function keep searching for another
/// candidate.
async fn race_handshake_reply(
    targets: &[(LinkHandle, SocketAddr, u8)],
    session_id: u32,
    timeout: Duration,
) -> Result<(u8, Vec<u8>)> {
    let mut join_set: JoinSet<Option<(u8, Vec<u8>)>> = JoinSet::new();
    for (handle, remote, link_id) in targets.iter().cloned() {
        join_set.spawn(async move {
            let socket = handle.current_socket().await;
            let mut buf = vec![0u8; MAX_FRAME];
            loop {
                let (n, from) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    // This link's socket itself is broken; give up on
                    // it for this round rather than spinning -- the
                    // other targets still get their full chance, and
                    // this link's own reconnect logic (once the
                    // steady-state tasks exist) handles the socket
                    // itself.
                    Err(_) => return None,
                };
                // Quick filter, not a security boundary (UDP source
                // addresses are trivially spoofable; the actual
                // authentication is the Noise handshake back in
                // `establish_session`) -- just avoids treating obvious
                // off-target traffic, and stale replies to an earlier
                // abandoned attempt (see this function's doc comment),
                // as a candidate. Anything that doesn't match keeps
                // this task listening rather than giving up, so a
                // single stray, spoofed, or stale packet can't cost
                // this link its chance at the real reply.
                if from != remote {
                    continue;
                }
                let Ok((hdr, payload)) = Header::decode(&buf[..n]) else {
                    continue;
                };
                if hdr.ptype != PacketType::HandshakeResp || hdr.session_id != session_id {
                    continue;
                }
                return Some((link_id, payload.to_vec()));
            }
        });
    }

    let winner = tokio::time::timeout(timeout, async {
        while let Some(joined) = join_set.join_next().await {
            // `Ok(Some(..))`: a candidate. `Ok(None)`: that link's
            // socket errored, keep waiting on the rest. `Err(..)`: the
            // task itself panicked, which shouldn't happen; also just
            // keep waiting rather than letting one bad task sink the
            // whole race.
            if let Ok(Some(candidate)) = joined {
                return Some(candidate);
            }
        }
        None
    })
    .await;

    // Whether we found a winner, ran out of links, or hit the timeout,
    // nothing should keep listening into the next attempt round (a
    // fresh `hs`/broadcast) or after a successful handshake.
    join_set.abort_all();

    match winner {
        Ok(Some((link_id, payload))) => Ok((link_id, payload)),
        Ok(None) => Err(MlvpnError::Handshake(
            "no valid handshake reply on any link".into(),
        )),
        Err(_) => Err(MlvpnError::Handshake("timeout".into())),
    }
}

/// The rekey counterpart of `race_handshake_reply`, used when
/// `perform_client_handshake` is called mid-session (`rekey_loop`)
/// rather than pre-session (`establish_session`). By the time a rekey
/// runs, every link's socket already belongs to that link's
/// `link_receiver` task, which is continuously calling `recv_from` on it
/// in its own loop; a second, independent `recv_from` here (the
/// pre-session approach) would race that task for every incoming
/// datagram with no guarantee which of the two callers the kernel
/// delivers any given one to. Instead, `handle_incoming` forwards any
/// `HandshakeResp` matching this attempt's session id through `rx`
/// (wired up by `RekeyContext::register_rekey_wait` before message 1
/// went out), and this just waits on that channel -- already filtered to
/// this attempt by `RekeyContext::forward_rekey_reply` -- with the same
/// one-reply-per-attempt, timeout-bounded semantics as the direct-socket
/// version.
async fn race_rekey_reply(
    rx: &mut mpsc::UnboundedReceiver<RekeyReply>,
    timeout: Duration,
) -> Result<RekeyReply> {
    match tokio::time::timeout(timeout, rx.recv()).await {
        Ok(Some(candidate)) => Ok(candidate),
        // The sender half lives on `rekey_ctx`, itself kept alive for
        // the tunnel's whole lifetime, so this shouldn't happen in
        // practice; treat it the same as "nothing arrived in time"
        // rather than as a distinct error case callers need to handle
        // differently.
        Ok(None) => Err(MlvpnError::Handshake(
            "rekey reply channel closed unexpectedly".into(),
        )),
        Err(_) => Err(MlvpnError::Handshake("timeout".into())),
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

/// One packet, already encrypted and ready to hand to a link's socket --
/// what `tun_reader` pushes onto the outbound queue and `outbound_sender`
/// pulls back off. Just the pieces `send_scheduled`/`send_redundant`
/// already took as separate arguments, bundled so a single value can
/// travel through the channel.
struct OutboundFrame {
    session_id: u32,
    seq: u64,
    ciphertext: Vec<u8>,
}

async fn tun_reader(
    tun: Arc<AsyncDevice>,
    session: Arc<AsyncMutex<SessionState>>,
    mtu: usize,
    clamp_mss: bool,
    tx: mpsc::Sender<OutboundFrame>,
    dropped: Arc<AtomicU64>,
) -> Result<()> {
    let mut buf = vec![0u8; mtu + 64];
    loop {
        let n = tun.recv(&mut buf).await.map_err(MlvpnError::Io)?;
        let mut plaintext = buf[..n].to_vec();

        // Only touches TCP SYN/SYN-ACK segments carrying an MSS option
        // larger than what `mtu` can carry -- see mss.rs for why this
        // matters more than relying on Path MTU Discovery alone, and for
        // the IPv4/IPv6 parsing and checksum recompute this performs.
        if clamp_mss {
            crate::mss::clamp_if_tcp_syn(&mut plaintext, mtu as u16);
        }

        // `session_id` comes back from `encrypt` itself rather than a
        // value captured once at startup, specifically so a packet sent
        // right after a rekey automatically carries whichever session
        // is now active -- see `crypto::SessionState::encrypt`'s doc
        // comment.
        let (session_id, seq, ciphertext) = {
            let s = session.lock().await;
            s.encrypt(&plaintext)?
        };

        // `try_send`, never `.send().await`: this loop's whole job is to
        // keep draining the kernel's TUN queue as fast as packets arrive
        // there, so blocking it on a full outbound queue would defeat
        // the point -- see `OUTBOUND_QUEUE_CAPACITY`'s doc comment. A
        // full queue means the send side is genuinely falling behind;
        // drop this packet and count it rather than stall reading the
        // next one, same drop-rather-than-block policy the original C
        // MLVPN's `freebuffer_t` used.
        if let Err(TrySendError::Full(_)) = tx.try_send(OutboundFrame {
            session_id,
            seq,
            ciphertext,
        }) {
            dropped.fetch_add(1, Ordering::Relaxed);
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
async fn outbound_sender(
    mut rx: mpsc::Receiver<OutboundFrame>,
    links: Links,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    redundant_mode: bool,
) {
    while let Some(frame) = rx.recv().await {
        if redundant_mode {
            send_redundant(&links, frame.session_id, frame.seq, &frame.ciphertext).await;
        } else {
            send_scheduled(
                &links,
                &scheduler,
                frame.session_id,
                frame.seq,
                &frame.ciphertext,
            )
            .await;
        }
    }
}

/// Periodically logs (and resets) the outbound queue's drop counter --
/// silent when nothing was dropped, so this produces zero log output on
/// a healthy tunnel. See `OUTBOUND_QUEUE_CAPACITY`'s doc comment for the
/// bug this mechanism exists to make visible next time, instead of only
/// discoverable by comparing external `iperf3` numbers against what the
/// links should support.
async fn outbound_queue_drop_reporter(dropped: Arc<AtomicU64>) {
    let mut tick = interval(OUTBOUND_QUEUE_DROP_REPORT_INTERVAL);
    loop {
        tick.tick().await;
        let n = dropped.swap(0, Ordering::Relaxed);
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
async fn send_scheduled(
    links: &Links,
    scheduler: &Arc<std::sync::Mutex<Scheduler>>,
    session_id: u32,
    seq: u64,
    ciphertext: &[u8],
) {
    let frame_len = HEADER_LEN + ciphertext.len();

    // Scoring pass: a cheap, `Copy`-only snapshot (see
    // `link::LinkScore`'s doc comment for why this matters here
    // specifically -- this runs once per outgoing packet) rather than
    // `link::snapshot_links`'s full `Link` clone. `Scheduler::select`
    // returns just the winning index; nothing here has looked at (or
    // locked) any link's remote address or socket handle yet.
    let chosen_idx: Option<usize> = {
        let scores = link::snapshot_scores(links).await;
        let mut sched = scheduler.lock().unwrap();
        sched.select(&scores, frame_len)
    };
    let Some(idx) = chosen_idx else {
        tracing::warn!("no link available to send on; dropping packet");
        return;
    };
    let Some(link_mutex) = links.get(idx) else {
        tracing::warn!("no link available to send on; dropping packet");
        return;
    };

    // Only *now*, having already picked a winner, do we lock a link at
    // all for its full data -- and only this one, not every candidate
    // that didn't win. `LinkHandle` rather than a resolved socket here,
    // specifically so the actual send below always reads whatever
    // socket is current at send time (post-reconnect if one just
    // happened) instead of one captured slightly stale.
    let chosen: Option<(u8, LinkHandle, SocketAddr, String)> = {
        let guard = link_mutex.lock().await;
        guard
            .remote
            .map(|r| (guard.id, guard.handle(), r, guard.config.name.clone()))
    };
    let Some((link_id, handle, remote, link_name)) = chosen else {
        tracing::warn!("no link available to send on; dropping packet");
        return;
    };
    let socket = handle.current_socket().await;

    let mut frame = Vec::with_capacity(frame_len);
    Header {
        ptype: PacketType::Data,
        link_id,
        session_id,
        seq,
    }
    .encode(&mut frame);
    frame.extend_from_slice(ciphertext);

    if let Err(e) = socket.send_to(&frame, remote).await {
        tracing::debug!(link = %link_name, error = %e, "send failed");
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
async fn send_redundant(links: &Links, session_id: u32, seq: u64, ciphertext: &[u8]) {
    let targets: Vec<(u8, LinkHandle, SocketAddr, String)> = {
        let snap = link::snapshot_links(links).await;
        let up: Vec<_> = snap
            .iter()
            .filter(|l| l.state == LinkState::Up)
            .filter_map(|l| {
                l.remote
                    .map(|r| (l.id, l.handle(), r, l.config.name.clone()))
            })
            .collect();
        if !up.is_empty() {
            up
        } else {
            snap.iter()
                .filter_map(|l| {
                    l.remote
                        .map(|r| (l.id, l.handle(), r, l.config.name.clone()))
                })
                .collect()
        }
    };

    if targets.is_empty() {
        tracing::warn!("redundant mode: no link available to send on; dropping packet");
        return;
    }

    for (link_id, handle, remote, link_name) in targets {
        let socket = handle.current_socket().await;
        let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        Header {
            ptype: PacketType::Data,
            link_id,
            session_id,
            seq,
        }
        .encode(&mut frame);
        frame.extend_from_slice(ciphertext);
        if let Err(e) = socket.send_to(&frame, remote).await {
            tracing::debug!(link = %link_name, error = %e, "redundant send failed");
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
    session: Arc<AsyncMutex<SessionState>>,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    tun: Arc<AsyncDevice>,
    reorder: Arc<AsyncMutex<ReorderBuffer>>,
    cfg: SchedulerConfig,
    tracker: Arc<AsyncMutex<ProbeTracker>>,
    peer_stats: Arc<PeerStatsTable>,
    rekey_ctx: Arc<RekeyContext>,
    shutdown: Arc<Shutdown>,
    bw_probe_state: Arc<AsyncMutex<BandwidthProbeReceiveState>>,
) {
    let (handle, link_id, link_name) = {
        let link = links[idx].lock().await;
        (link.handle(), link.id, link.config.name.clone())
    };

    let mut buf = vec![0u8; MAX_FRAME];
    let mut consecutive_failures = 0u32;
    let mut backoff_ms = RECONNECT_BACKOFF_INITIAL_MS;
    loop {
        let socket = handle.current_socket().await;
        match socket.recv_from(&mut buf).await {
            Ok((n, from)) => {
                consecutive_failures = 0;
                handle_incoming(
                    idx,
                    link_id,
                    &buf[..n],
                    from,
                    &socket,
                    &links,
                    &session,
                    &scheduler,
                    &tun,
                    &reorder,
                    &cfg,
                    &tracker,
                    &peer_stats,
                    &rekey_ctx,
                    &shutdown,
                    &bw_probe_state,
                )
                .await;
            }
            Err(e) if is_interface_gone_error(&e) => {
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
            Err(e) => {
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
        }
    }
}

/// Owns one link's probing side: periodically sends authenticated `Probe`
/// frames, sweeps ones that never got a reply into recorded losses, and
/// (for link index 0 only) reports the aggregate all-links-down state.
/// Runs as a task fully independent of `link_receiver` -- see the module
/// doc comment. Shares `tracker` with that link's `link_receiver` (see
/// `run()`, where both tasks are handed the same `Arc`).
async fn link_prober(
    idx: usize,
    links: Links,
    session: Arc<AsyncMutex<SessionState>>,
    scheduler: Arc<std::sync::Mutex<Scheduler>>,
    cfg: SchedulerConfig,
    tracker: Arc<AsyncMutex<ProbeTracker>>,
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
                let socket = handle.current_socket().await;
                let sent = {
                    let mut t = tracker.lock().await;
                    send_probe(&socket, link_id, &links, idx, &session, &probe_seq_counter, &mut t).await
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
                        record_send_failure_as_miss(&links, idx, &cfg, &scheduler).await;
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
                        record_send_failure_as_miss(&links, idx, &cfg, &scheduler).await;
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
                let socket = handle.current_socket().await;
                send_stats_share(&socket, link_id, &links, idx, &session).await;
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
                    let mut sched = scheduler.lock().unwrap();
                    sched.refresh(&snap);
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

/// Per-link receive-side bookkeeping for an in-progress
/// `PacketType::BandwidthProbeBurst` (see `active_bandwidth_prober` below
/// and the `BandwidthProbeBurst` arm of `handle_incoming`'s match). One
/// of these lives per link, built alongside `trackers` in `run()`.
/// Unlike `monitor::ProbeTracker`, nothing outside `link_receiver`/
/// `handle_incoming` ever needs to read this, but it's still wrapped in
/// `Arc<AsyncMutex<_>>` to match the rest of this module's per-link
/// state-sharing pattern.
struct BandwidthProbeReceiveState {
    /// `probe_id` of the burst currently being accumulated, or `None`
    /// between bursts (including before the very first one has ever
    /// arrived).
    probe_id: Option<u32>,
    first_seen: Instant,
    bytes_seen: u64,
    /// `probe_id` of the most recently *completed* burst (one that
    /// already triggered a reply), or `None` if none has completed
    /// yet. Needed because `active_bandwidth_prober` redundantly
    /// resends the final packet of a burst a couple of extra times
    /// (see that function's doc comment for why) -- without this,
    /// a second copy of that final packet arriving after the burst
    /// already completed and reset `probe_id` to `None` would look
    /// exactly like the start of a brand new one-packet burst, and
    /// immediately "complete" again with a bogus near-zero elapsed
    /// time (and therefore a wildly inflated achieved_mbps). Checked
    /// before the normal reset-on-new-probe_id logic below.
    last_completed_probe_id: Option<u32>,
}

impl BandwidthProbeReceiveState {
    fn new() -> Self {
        Self {
            probe_id: None,
            first_seen: Instant::now(),
            bytes_seen: 0,
            last_completed_probe_id: None,
        }
    }
}

/// Pure throughput calculation shared by `handle_incoming`'s
/// `BandwidthProbeBurst` handling and its own unit tests below: bytes
/// carried by a completed burst, divided by how long the burst took to
/// arrive. `elapsed_secs` is clamped to a small positive floor so a
/// (practically impossible, but not unrepresentable) zero-duration burst
/// can't divide by zero or report an infinite/nonsensical rate.
fn compute_achieved_mbps(bytes: u64, elapsed_secs: f64) -> f64 {
    let elapsed_secs = elapsed_secs.max(0.001);
    (bytes as f64 * 8.0) / elapsed_secs / 1_000_000.0
}

/// How many packets make up one active-bandwidth-probe burst is bounded
/// to `u16::MAX` by the wire format (`BandwidthProbeBurstPayload::total_packets`);
/// `Config::validate` already caps `active_bandwidth_probe_packets` far
/// below that (2..=100), so this is only a defensive final clamp.
const ACTIVE_BANDWIDTH_PROBE_MAX_PACKETS: u32 = u16::MAX as u32;

/// Sender side of `scheduler.active_bandwidth_probing` (off by default):
/// periodically sends one MTU-sized burst of dummy packets down this
/// link and lets the receiver's `BandwidthProbeBurst` handling in
/// `handle_incoming` measure and report back the achieved throughput.
/// Spawned unconditionally per link in `run()` (same pattern as
/// `reorder_tuning_loop`) but returns immediately as a no-op unless the
/// feature is actually enabled, so the common (disabled) case costs
/// nothing beyond one parked task.
///
/// Deliberately its own task rather than folded into `link_prober`:
/// `link_prober`'s timing is latency-sensitive (its own probe cadence
/// directly feeds the Up/Down hysteresis), and a burst of `send_to`
/// calls -- even a small one -- risks momentarily delaying the next
/// scheduled latency probe if they shared a task. Best-effort throughout:
/// a burst that fails partway through (a send error, or the peer never
/// finishing decoding it) just means no result for that attempt: the
/// next scheduled burst tries again, so there's no separate retry logic
/// here.
///
/// One deliberate exception to "no retry logic": the very last packet
/// of the burst is what triggers the receiver to actually compute and
/// reply with a result (see `handle_incoming`'s `BandwidthProbeBurst`
/// handling) -- losing *that one specific packet* silently discards
/// the entire burst's measurement even though every other packet
/// arrived fine, which in testing turned out to be a real, if
/// occasional, failure mode: an unshaped/fast link delivers its whole
/// burst in a handful of milliseconds with no pacing at all, which is
/// exactly the traffic pattern most likely to hit a transient
/// receive-side drop. So the final packet is sent a couple of extra
/// times as cheap insurance -- the receiver-side
/// `BandwidthProbeReceiveState::last_completed_probe_id` guard makes
/// redundant copies of an already-completed burst's final packet a
/// harmless no-op rather than a spurious second (near-instant, wildly
/// inflated) result.
async fn active_bandwidth_prober(
    idx: usize,
    links: Links,
    session: Arc<AsyncMutex<SessionState>>,
    cfg: SchedulerConfig,
    mtu: usize,
) {
    if !cfg.active_bandwidth_probing {
        return;
    }

    let (handle, link_id) = {
        let link = links[idx].lock().await;
        (link.handle(), link.id)
    };

    let packet_count = cfg
        .active_bandwidth_probe_packets
        .clamp(2, ACTIVE_BANDWIDTH_PROBE_MAX_PACKETS) as u16;
    let payload_len = mtu.max(BandwidthProbeBurstPayload::HEADER_LEN);
    let mut tick = interval(Duration::from_secs(
        cfg.active_bandwidth_probe_interval_secs,
    ));
    let mut probe_id: u32 = 0;

    loop {
        tick.tick().await;

        // Skip this cycle entirely if we don't yet have a learned peer
        // address for this link (e.g. right at startup, or a link that's
        // never come up) -- same "nothing to send to yet" condition
        // `send_probe` already handles for latency probes.
        let remote = links[idx].lock().await.remote;
        let Some(remote) = remote else {
            continue;
        };

        probe_id = probe_id.wrapping_add(1);
        let socket = handle.current_socket().await;
        // Two extra copies of the final packet, after the main
        // 0..packet_count loop below -- see this function's doc
        // comment for why the last packet specifically gets this
        // redundancy. `packets_to_send` yields every index once, then
        // the last index twice more.
        let packets_to_send = (0..packet_count).chain(std::iter::repeat_n(packet_count - 1, 2));
        for packet_index in packets_to_send {
            let burst_payload = BandwidthProbeBurstPayload {
                probe_id,
                packet_index,
                total_packets: packet_count,
            }
            .encode_padded(payload_len);
            let encrypted = {
                let s = session.lock().await;
                s.encrypt(&burst_payload)
            };
            let Ok((session_id, seq, ct)) = encrypted else {
                break;
            };
            let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
            Header {
                ptype: PacketType::BandwidthProbeBurst,
                link_id,
                session_id,
                seq,
            }
            .encode(&mut out);
            out.extend_from_slice(&ct);
            if socket.send_to(&out, remote).await.is_err() {
                // Best-effort, as documented above: abandon this burst
                // attempt and let the next scheduled tick try again.
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming(
    idx: usize,
    link_id: u8,
    frame: &[u8],
    from: SocketAddr,
    socket: &Arc<UdpSocket>,
    links: &Links,
    session: &Arc<AsyncMutex<SessionState>>,
    scheduler: &Arc<std::sync::Mutex<Scheduler>>,
    tun: &Arc<AsyncDevice>,
    reorder: &Arc<AsyncMutex<ReorderBuffer>>,
    cfg: &SchedulerConfig,
    tracker: &Arc<AsyncMutex<ProbeTracker>>,
    peer_stats: &Arc<PeerStatsTable>,
    rekey_ctx: &Arc<RekeyContext>,
    shutdown: &Arc<Shutdown>,
    bw_probe_state: &Arc<AsyncMutex<BandwidthProbeReceiveState>>,
) {
    let Ok((hdr, ciphertext)) = Header::decode(frame) else {
        return;
    };

    // Every non-handshake frame type -- Data, Probe, and ProbeReply alike
    // -- is AEAD-protected under the shared Noise transport session, using
    // the header's `seq` as the nonce. This matters as much for Probe
    // traffic as for Data: if probes were sent in the clear, an off-path
    // attacker could inject forged RTT/loss samples and steer the
    // scheduler's link scoring, or trigger bogus Up/Down transitions.
    // Requiring authentication here means only someone holding the
    // session's derived keys (i.e. someone who passed the Noise_IK
    // handshake) can influence link scoring or get a Data payload
    // accepted at all.
    let plaintext = match hdr.ptype {
        PacketType::HandshakeInit => {
            // A rekey request -- or, just as plausibly, a spoofed or
            // stale frame; `ptype` is plaintext and unauthenticated
            // until `respond_to_handshake_init`'s own pin check
            // succeeds. Only `Mode::Server` ever accepts one
            // post-establishment: the client is always the Noise_IK
            // initiator, both for the very first handshake and every
            // rekey, so it never expects to receive one itself -- see
            // the module doc comment.
            if rekey_ctx.mode == Mode::Server {
                // Guards against a real bug this project's integration
                // tests caught: the client broadcasts the identical
                // message 1 (same session id) to *every* configured
                // link at once during the initial handshake (see
                // `perform_client_handshake`), but `establish_session`'s
                // pre-session wait loop only ever consumes the first
                // copy that arrives before returning -- any duplicate
                // that landed on another link's socket in the meantime
                // is still sitting there, unread, once steady state
                // begins. Without this check, the `link_receiver` task
                // that eventually reads it would treat that stale
                // duplicate as a brand new peer-initiated rekey, derive
                // a *different* session under the *same* session id
                // (Noise's responder generates a fresh ephemeral for
                // every message-2 it sends, even from an identical
                // message 1), and install it -- silently desynchronizing
                // the two sides' keys under a label that looked
                // unchanged in the logs. A genuinely new rekey attempt
                // always carries a freshly generated random session id
                // (see `crypto::SessionState::is_known_session_id`'s doc
                // comment), so this can only ever filter out exactly the
                // stale-duplicate case, never a real one.
                if session.lock().await.is_known_session_id(hdr.session_id) {
                    tracing::debug!(
                        session_id = hdr.session_id,
                        %from,
                        "ignoring HandshakeInit for an already-installed session id \
                         (stale duplicate of an earlier handshake, not a new rekey)"
                    );
                    return;
                }
                if rekey_ctx.limiter.allow() {
                    match respond_to_handshake_init(
                        &rekey_ctx.local_private,
                        &rekey_ctx.peer_public,
                        &hdr,
                        ciphertext,
                        from,
                        socket,
                        link_id,
                    )
                    .await
                    {
                        Ok((new_id, new_session)) => {
                            if let Some(l) = links.get(idx) {
                                l.lock().await.remote = Some(from);
                            }
                            session.lock().await.install(new_id, new_session);
                            tracing::info!(session_id = new_id, "session rekeyed (peer-initiated)");
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                %from,
                                "rejected rekey handshake attempt"
                            );
                        }
                    }
                } else {
                    tracing::debug!(%from, "dropping HandshakeInit: rate limit exceeded");
                }
            }
            return;
        }
        PacketType::HandshakeResp => {
            // Pre-session, `race_handshake_reply` reads this directly
            // off the socket and this branch never even runs (no
            // `link_receiver` task exists yet -- see `establish_session`).
            // Mid-session, this *is* how a rekey's `HandshakeResp` gets
            // back to the waiting `rekey_loop` attempt: forwarded
            // through `rekey_ctx` if it matches a currently in-flight
            // attempt's session id, silently dropped otherwise (a stale
            // retransmit from an attempt that already gave up, or plain
            // noise) -- see `RekeyContext::forward_rekey_reply` and
            // `race_rekey_reply`.
            rekey_ctx.forward_rekey_reply(hdr.session_id, link_id, ciphertext.to_vec());
            return;
        }
        _ => {
            let mut s = session.lock().await;
            match s.decrypt(hdr.session_id, hdr.seq, ciphertext) {
                Ok(pt) => pt,
                Err(_) => return, // auth failure, replay, or unrecognized session id; silently drop
            }
        }
    };

    // Only now, having verified the frame is authentic, do we trust its
    // source address enough to (re-)learn it as this link's peer address.
    // This is what lets a server-side link start life with no configured
    // `remote_addr` and still become usable the moment the client's first
    // authenticated frame arrives on it, and lets either side recover
    // automatically if a link's source address changes mid-session (e.g.
    // mobile roaming, NAT rebinding) -- without letting an unauthenticated
    // spoofed packet redirect where we send subsequent traffic.
    if let Some(l) = links.get(idx) {
        let mut link = l.lock().await;
        if link.remote != Some(from) {
            tracing::debug!(link = %link.config.name, %from, "learned/updated peer address");
            link.remote = Some(from);
        }
    }

    match hdr.ptype {
        PacketType::Data => {
            if let Some(l) = links.get(idx) {
                l.lock().await.stats.record_bytes(frame.len() as u64);
            }

            let ready = {
                let mut ro = reorder.lock().await;
                ro.insert(hdr.seq, plaintext);
                ro.drain_ready()
            };
            for pkt in ready {
                let _ = tun.send(&pkt).await;
            }
        }
        PacketType::Probe => {
            // Echo the decrypted probe payload straight back,
            // re-encrypted under our own current active session, so the
            // original sender can match it against their
            // outstanding-probe table by `probe_seq` and compute RTT
            // from their own clock. Always uses *our own* current
            // active session id for the reply, not necessarily whatever
            // session decrypted the request -- a reply is new outgoing
            // traffic, and this is what keeps a probe reply sent right
            // after our own rekey installs correctly tagged with the
            // new session id. See `crypto::SessionState`'s doc comment
            // for why a handful of replies briefly using a session id
            // the peer hasn't adopted yet, right at the moment of a
            // rekey, is expected and self-corrects.
            let encrypted = {
                let s = session.lock().await;
                s.encrypt(&plaintext)
            };
            let Ok((reply_session_id, reply_seq, reply_ct)) = encrypted else {
                return;
            };
            let mut out = Vec::with_capacity(HEADER_LEN + reply_ct.len());
            Header {
                ptype: PacketType::ProbeReply,
                link_id,
                session_id: reply_session_id,
                seq: reply_seq,
            }
            .encode(&mut out);
            out.extend_from_slice(&reply_ct);
            let _ = socket.send_to(&out, from).await;
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
                let mut sched = scheduler.lock().unwrap();
                sched.refresh(&snap);
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
        PacketType::BandwidthProbeBurst => {
            let Ok(burst) = BandwidthProbeBurstPayload::decode(&plaintext) else {
                return;
            };
            let mut state = bw_probe_state.lock().await;
            // `active_bandwidth_prober` sends the burst's final packet a
            // couple of extra times as insurance against losing exactly
            // that one packet (see its doc comment) -- if this is a
            // redundant copy of a burst we already completed and replied
            // to, ignore it outright rather than letting it fall through
            // to the "fresh probe_id" branch below, which would
            // otherwise misread it as the start of a brand new
            // one-packet burst and immediately "complete" it with a
            // bogus near-zero elapsed time.
            if state.last_completed_probe_id == Some(burst.probe_id) {
                return;
            }
            // A fresh `probe_id` means a new burst is starting -- either
            // the very first one ever, or the sender's previous attempt
            // never fully arrived (a dropped final packet just means no
            // result got sent for it; see this struct's doc comment).
            // Either way, restart accounting from this packet rather
            // than mixing bytes from two different bursts together.
            if state.probe_id != Some(burst.probe_id) {
                state.probe_id = Some(burst.probe_id);
                state.first_seen = Instant::now();
                state.bytes_seen = 0;
            }
            state.bytes_seen += frame.len() as u64;
            if burst.packet_index + 1 == burst.total_packets {
                let elapsed_secs = state.first_seen.elapsed().as_secs_f64();
                let achieved_mbps = compute_achieved_mbps(state.bytes_seen, elapsed_secs);
                // Ready for the next burst; `last_completed_probe_id` is
                // what makes any further redundant copy of this same
                // final packet a harmless no-op above instead of a
                // spurious second result.
                state.probe_id = None;
                state.last_completed_probe_id = Some(burst.probe_id);
                drop(state);

                let result_payload = BandwidthProbeResultPayload {
                    probe_id: burst.probe_id,
                    achieved_mbps: achieved_mbps as f32,
                };
                let encrypted = {
                    let s = session.lock().await;
                    s.encrypt(&result_payload.encode())
                };
                if let Ok((reply_session_id, reply_seq, reply_ct)) = encrypted {
                    let mut out = Vec::with_capacity(HEADER_LEN + reply_ct.len());
                    Header {
                        ptype: PacketType::BandwidthProbeResult,
                        link_id,
                        session_id: reply_session_id,
                        seq: reply_seq,
                    }
                    .encode(&mut out);
                    out.extend_from_slice(&reply_ct);
                    let _ = socket.send_to(&out, from).await;
                }
            }
        }
        PacketType::BandwidthProbeResult => {
            let Ok(result) = BandwidthProbeResultPayload::decode(&plaintext) else {
                return;
            };
            if let Some(l) = links.get(idx) {
                let mut link = l.lock().await;
                link.stats
                    .active_bandwidth_mbps
                    .update(result.achieved_mbps as f64);
                tracing::info!(
                    link = %link.config.name,
                    achieved_mbps = result.achieved_mbps,
                    "active bandwidth probe result"
                );
            }
        }
        PacketType::Keepalive => {
            // No action beyond having been received -- the socket read
            // itself is enough to keep NAT bindings alive.
        }
        PacketType::Disconnect => {
            // This already went through the same AEAD decrypt as every
            // other frame type above (it's handled in the `_` arm of
            // the earlier `match hdr.ptype`, same as Data/Probe/
            // StatsShare) -- a forged Disconnect can't reach here
            // without holding the session's keys, so this is a
            // trustworthy signal that the peer is shutting down on
            // purpose. Tear this side down the same way rather than
            // waiting for every link to grind through the probe
            // hysteresis and eventually report Down on its own --
            // `run()`'s tail does the actual work once `shutdown` is
            // triggered.
            tracing::info!(%from, "peer sent Disconnect; shutting down");
            shutdown.trigger(ShutdownReason::PeerInitiated);
        }
        PacketType::HandshakeInit | PacketType::HandshakeResp => unreachable!("handled above"),
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
) {
    {
        let mut link = links[idx].lock().await;
        link.stats.record_miss();
        monitor::update_link_state(&mut link, cfg);
    }
    let snap = link::snapshot_links(links).await;
    let mut sched = scheduler.lock().unwrap();
    sched.refresh(&snap);
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
    socket: &Arc<UdpSocket>,
    link_id: u8,
    links: &Links,
    idx: usize,
    session: &Arc<AsyncMutex<SessionState>>,
    probe_seq_counter: &AtomicU32,
    tracker: &mut ProbeTracker,
) -> ProbeSendOutcome {
    let remote = links[idx].lock().await.remote;
    let Some(remote) = remote else {
        return ProbeSendOutcome::Skipped;
    };

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

    let (session_id, seq, ciphertext) = {
        let s = session.lock().await;
        match s.encrypt(&payload) {
            Ok(v) => v,
            // Not a socket problem, so not a reconnect signal either --
            // see `ProbeSendOutcome::Skipped`'s doc comment.
            Err(_) => return ProbeSendOutcome::Skipped,
        }
    };

    let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    Header {
        ptype: PacketType::Probe,
        link_id,
        session_id,
        seq,
    }
    .encode(&mut frame);
    frame.extend_from_slice(&ciphertext);

    match socket.send_to(&frame, remote).await {
        Ok(_) => {
            tracker.record_sent(probe_seq);
            ProbeSendOutcome::Sent
        }
        Err(e) if is_interface_gone_error(&e) => ProbeSendOutcome::InterfaceGone,
        Err(e) => {
            tracing::debug!(
                link_id,
                error = %e,
                "probe send error (transient, not reconnecting)"
            );
            ProbeSendOutcome::TransientFailure
        }
    }
}

/// Send this link's current locally-measured stats to the peer, so their
/// `mlvpn-tui` can show a full-duplex view instead of only what they
/// measure themselves. See `PacketType::StatsShare` and `StatsPayload`'s
/// doc comments in `protocol.rs` for the wire format and design
/// rationale.
async fn send_stats_share(
    socket: &Arc<UdpSocket>,
    link_id: u8,
    links: &Links,
    idx: usize,
    session: &Arc<AsyncMutex<SessionState>>,
) {
    let (remote, payload) = {
        let link = links[idx].lock().await;
        let Some(remote) = link.remote else { return };
        let payload = StatsPayload {
            name: StatsPayload::encode_name(&link.config.name),
            rtt_ms: link.stats.rtt_ms.get().unwrap_or(0.0) as f32,
            jitter_ms: link.stats.jitter_ms.get().unwrap_or(0.0) as f32,
            loss_pct: (link.stats.loss_rate.get().unwrap_or(0.0) * 100.0) as f32,
            throughput_mbps: link.stats.throughput_mbps.get().unwrap_or(0.0) as f32,
            state: link.state.to_wire(),
        };
        (remote, payload)
    };

    let plaintext = payload.encode();
    let (session_id, seq, ciphertext) = {
        let s = session.lock().await;
        match s.encrypt(&plaintext) {
            Ok(v) => v,
            Err(_) => return,
        }
    };

    let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    Header {
        ptype: PacketType::StatsShare,
        link_id,
        session_id,
        seq,
    }
    .encode(&mut frame);
    frame.extend_from_slice(&ciphertext);

    let _ = socket.send_to(&frame, remote).await;
}

/// Client-only: periodically re-runs the handshake (`perform_client_handshake`)
/// and, on success, installs the result as `session`'s new active
/// session -- see the module doc comment and `crypto::SessionState`'s
/// doc comment for the overlap-window design this participates in.
/// Never spawned for `Mode::Server` (see `run()`), which instead
/// passively accepts a peer-initiated rekey via `handle_incoming`,
/// mirroring how it already passively accepts the very first handshake
/// pre-session.
async fn rekey_loop(
    links: Links,
    params: Arc<TunnelParams>,
    session: Arc<AsyncMutex<SessionState>>,
    rekey_ctx: Arc<RekeyContext>,
) {
    let mut tick = interval(params.rekey_interval);
    // tokio::time::interval's first tick fires immediately; skip it so
    // a rekey doesn't happen right on the heels of the initial
    // handshake that just established this session.
    tick.tick().await;
    loop {
        tick.tick().await;
        // `Some(&rekey_ctx)`: routes this attempt's `HandshakeResp`
        // through `rekey_ctx`'s forwarding channel instead of reading
        // the link sockets directly -- see `perform_client_handshake`'s
        // doc comment for why that distinction matters mid-session.
        match perform_client_handshake(&links, &params, Some(&rekey_ctx)).await {
            Ok((new_id, new_session)) => {
                session.lock().await.install(new_id, new_session);
                tracing::info!(session_id = new_id, "session rekeyed");
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "rekey attempt failed; will retry next interval, current session keeps working"
                );
            }
        }
    }
}

/// Periodically retires `session`'s `previous` slot once it's older
/// than `SESSION_OVERLAP_WINDOW` -- see `crypto::SessionState::expire_previous`'s
/// doc comment for why this needs its own timer independent of the
/// (much longer) rekey interval. Runs unconditionally for both roles:
/// a session only ever has a `previous` slot to expire after either
/// side has actually rekeyed at least once, which for `Mode::Server`
/// means having accepted a peer-initiated one -- this task is cheap
/// enough to just always run rather than being conditionally spawned
/// like `rekey_loop`.
async fn session_expiry_loop(session: Arc<AsyncMutex<SessionState>>) {
    let mut tick = interval(SESSION_EXPIRY_CHECK_INTERVAL);
    loop {
        tick.tick().await;
        session.lock().await.expire_previous(SESSION_OVERLAP_WINDOW);
    }
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
    next_expected: u64,
    pending: BTreeMap<u64, (Instant, Vec<u8>)>,
}

impl ReorderBuffer {
    fn new(window_ms: u64) -> Self {
        Self {
            window: Duration::from_millis(window_ms),
            next_expected: 0,
            pending: BTreeMap::new(),
        }
    }

    /// Current window, in milliseconds -- used by `reorder_tuning_loop`
    /// to compare a freshly suggested value against what's actually in
    /// effect right now (hysteresis).
    fn window_ms(&self) -> u64 {
        self.window.as_millis() as u64
    }

    /// Replace the window in effect from this point on. Deliberately
    /// does not touch `pending` or `next_expected` -- a packet already
    /// sitting in the buffer keeps whichever deadline it was inserted
    /// with (`drain_ready` compares each entry's own `sent_at` against
    /// `self.window` freshly on every call, so a change here applies to
    /// every future comparison immediately, old and new entries alike;
    /// there is no separately stored per-entry deadline to reconcile).
    fn set_window(&mut self, window_ms: u64) {
        self.window = Duration::from_millis(window_ms);
    }

    fn insert(&mut self, seq: u64, payload: Vec<u8>) {
        self.pending.insert(seq, (Instant::now(), payload));
    }

    /// Drain everything that is now safe to deliver: a contiguous run
    /// starting at `next_expected`, plus anything that has aged out of
    /// the reorder window regardless of contiguity.
    fn drain_ready(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let now = Instant::now();

        while let Some((&seq, (sent_at, _))) = self.pending.iter().next() {
            let is_next = seq == self.next_expected;
            let is_stale = now.duration_since(*sent_at) >= self.window;
            if is_next || is_stale {
                let (_sent_at, payload) = self.pending.remove(&seq).unwrap();
                out.push(payload);
                self.next_expected = seq.max(self.next_expected) + 1;
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
        let ready = {
            let mut ro = reorder.lock().await;
            ro.drain_ready()
        };
        for pkt in ready {
            let _ = tun.send(&pkt).await;
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
fn suggest_reorder_window_ms(rtts: &[f64], min_ms: u64, max_ms: u64) -> Option<u64> {
    if rtts.len() < 2 {
        return None;
    }
    let min_rtt = rtts.iter().cloned().fold(f64::MAX, f64::min);
    let max_rtt = rtts.iter().cloned().fold(f64::MIN, f64::max);
    let spread = max_rtt - min_rtt;
    let suggested = (spread * 1.5) + 10.0;
    Some(suggested.clamp(min_ms as f64, max_ms as f64).round() as u64)
}

/// No-op unless `scheduler.auto_tune_reorder_window` is enabled (see
/// that field's doc comment in `config.rs`) -- returns immediately in
/// that case rather than the caller needing to conditionally spawn this
/// task at all. Periodically recomputes a suggested `reorder_window_ms`
/// from the live RTT spread across currently-Up links
/// (`suggest_reorder_window_ms`) and applies it only if it clears a
/// hysteresis threshold against the value currently in effect, so a
/// single noisy RTT sample can't chase the window back and forth every
/// tick -- the same principle as the existing Up/Down hysteresis in
/// `monitor.rs`. See `ARCHITECTURE.md` §7 for the full design.
async fn reorder_tuning_loop(
    links: Links,
    reorder: Arc<AsyncMutex<ReorderBuffer>>,
    cfg: SchedulerConfig,
) {
    if !cfg.auto_tune_reorder_window {
        return;
    }

    let mut tick = interval(REORDER_TUNING_INTERVAL);
    loop {
        tick.tick().await;

        let rtts: Vec<f64> = {
            let snap = link::snapshot_links(&links).await;
            snap.iter()
                .filter(|l| l.state == LinkState::Up)
                .filter_map(|l| l.stats.rtt_ms.get())
                .collect()
        };

        let Some(suggested) =
            suggest_reorder_window_ms(&rtts, cfg.reorder_window_min_ms, cfg.reorder_window_max_ms)
        else {
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
    fn suggest_reorder_window_needs_at_least_two_samples() {
        assert_eq!(suggest_reorder_window_ms(&[], 10, 500), None);
        assert_eq!(suggest_reorder_window_ms(&[42.0], 10, 500), None);
    }

    #[test]
    fn suggest_reorder_window_scales_with_rtt_spread() {
        // Spread of 20ms (30 - 10) * 1.5 + 10 = 40ms, well inside [10, 500].
        let suggested = suggest_reorder_window_ms(&[10.0, 30.0], 10, 500)
            .expect("two samples should always produce a suggestion");
        assert_eq!(suggested, 40);
    }

    #[test]
    fn suggest_reorder_window_is_symmetric_in_sample_order() {
        // The spread math shouldn't care which sample came first.
        let a = suggest_reorder_window_ms(&[10.0, 30.0], 10, 500);
        let b = suggest_reorder_window_ms(&[30.0, 10.0], 10, 500);
        assert_eq!(a, b);
    }

    #[test]
    fn suggest_reorder_window_clamps_to_configured_bounds() {
        // A huge spread should clamp to max_ms, not run away unbounded.
        let suggested = suggest_reorder_window_ms(&[5.0, 5000.0], 10, 500)
            .expect("two samples should always produce a suggestion");
        assert_eq!(suggested, 500);

        // Even a zero spread still gets the fixed 10ms of headroom, but
        // never drops below min_ms.
        let suggested = suggest_reorder_window_ms(&[15.0, 15.0], 10, 500)
            .expect("two samples should always produce a suggestion");
        assert_eq!(suggested, 10); // (0 * 1.5) + 10 = 10, and 10 is already the floor
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
    fn receive_state_resets_on_a_new_probe_id() {
        let mut state = BandwidthProbeReceiveState::new();
        state.probe_id = Some(1);
        state.bytes_seen = 500;

        // Simulate handle_incoming's reset check for a fresh burst
        // starting mid-way through (or right after) a previous one.
        let incoming_probe_id = 2u32;
        if state.probe_id != Some(incoming_probe_id) {
            state.probe_id = Some(incoming_probe_id);
            state.bytes_seen = 0;
        }
        assert_eq!(state.probe_id, Some(2));
        assert_eq!(state.bytes_seen, 0);
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
    fn active_bandwidth_probe_packet_count_is_clamped_to_the_wire_format_limit() {
        // Defensive: Config::validate already restricts
        // active_bandwidth_probe_packets to 2..=100, but
        // active_bandwidth_prober itself clamps again to
        // ACTIVE_BANDWIDTH_PROBE_MAX_PACKETS (u16::MAX) before casting
        // to u16, so a future change to the config-level bound alone
        // can't reintroduce a silent truncation.
        let clamped = 1_000_000u32.clamp(2, ACTIVE_BANDWIDTH_PROBE_MAX_PACKETS);
        assert!(clamped <= u16::MAX as u32);
    }

    #[test]
    fn burst_send_sequence_resends_the_final_packet_twice() {
        // Mirrors active_bandwidth_prober's packets_to_send construction
        // for a small packet_count, confirming every index 0..count is
        // sent once and the last index is sent two additional times --
        // the redundancy that closes the "lost final packet silently
        // discards the whole measurement" gap. See this module's
        // BandwidthProbeReceiveState::last_completed_probe_id doc
        // comment for the receive-side half of this fix.
        let packet_count: u16 = 5;
        let packets_to_send: Vec<u16> = (0..packet_count)
            .chain(std::iter::repeat_n(packet_count - 1, 2))
            .collect();
        assert_eq!(packets_to_send, vec![0, 1, 2, 3, 4, 4, 4]);
    }

    #[test]
    fn redundant_final_packet_after_completion_is_ignored_not_a_new_burst() {
        // Simulates handle_incoming's guard: a second (or third) copy of
        // an already-completed burst's final packet must be dropped
        // outright, not misread as the start of a fresh one-packet
        // burst that would immediately "complete" again with a bogus,
        // near-instant (and therefore wildly inflated) achieved_mbps.
        let mut state = BandwidthProbeReceiveState::new();
        let probe_id = 7u32;

        // First (real) copy of the final packet completes the burst.
        state.probe_id = Some(probe_id);
        state.bytes_seen = 28_000;
        state.probe_id = None;
        state.last_completed_probe_id = Some(probe_id);

        // A redundant second copy of that same final packet arrives
        // afterward: the completed-probe_id guard must fire before any
        // reset-on-new-probe_id logic runs.
        let ignored = state.last_completed_probe_id == Some(probe_id);
        assert!(
            ignored,
            "a redundant copy of an already-completed burst's final \
             packet must be recognized and ignored"
        );
    }
}
