//! Tunnel-level throughput self-test.
//!
//! Distinct from `tunnel::send_throughput_test_stream`'s per-link
//! self-test (`mlvpnd self-test`, no flag): that sends raw test packets
//! directly on one link's own UDP socket, which measures that one
//! link's raw capacity but never goes anywhere near the TUN device, the
//! bounded outbound queue, or the SWRR scheduler -- so it can't help
//! diagnose a bug in *that* part of the pipeline (the still-open
//! "real loss, zero visibility in our own drop counters" field report
//! this project has been chasing).
//!
//! `mlvpnd self-test --tunnel` fixes that by testing literally the same
//! path real LAN traffic takes: real UDP packets addressed to the
//! peer's tunnel-internal IP (e.g. `10.200.0.2`), picked up by
//! `tunnel::tun_reader` off the TUN device exactly like any other
//! application's traffic, pushed through the real bounded outbound
//! queue, split across whichever links are Up by the real scheduler,
//! decrypted by the peer's `handle_incoming`, and written to the peer's
//! own TUN device. From the tunnel's own point of view this traffic is
//! completely indistinguishable from genuine user traffic -- which is
//! the entire point.
//!
//! Deliberately its own small, self-contained protocol -- *not* built
//! on `protocol.rs`'s `Header`/`PacketType`/Noise machinery, since this
//! traffic doesn't need its own authentication or encryption: it gets
//! both for free by actually transiting the tunnel, the same way real
//! traffic does. Plain UDP between the two tunnel-internal addresses,
//! on `TUNNEL_TEST_PORT`. Gated by `[command] enabled = true`, the same
//! opt-in the per-link self-test and runtime link control already use.
//!
//! **Protocol.** A stream of `DataPayload` packets flows from sender to
//! receiver for `duration_secs`, ending with a few redundant `done`
//! copies (spaced, not back-to-back -- see `send_stream`'s doc comment
//! for why that spacing is load-bearing, not just insurance). The
//! receiver replies once, directly, with a `ResultPayload` carrying its
//! measured `achieved_mbps` -- this is how the *upload* leg's result
//! gets back to the CLI invocation that triggered it. For a
//! bidirectional test, the `DataPayload`'s `bidirectional_requested`
//! flag tells the receiver to autonomously start its own stream back
//! (the *download* leg) once it finishes measuring the upload leg, no
//! second command invocation needed on that side -- mirroring the
//! per-link self-test's own autonomous-reverse-leg design. The download
//! leg's result reaches the original requester through its own
//! persistent listener (`run_listener`, always running when enabled)
//! and `TunnelTestContext`, since that's a separate task from whatever
//! sent the upload leg.
//!
//! **Queue-drop visibility.** Each direction's *sender* embeds its own
//! `outbound_dropped_total` delta (observed across just that send) on
//! its final `done` packet(s) -- direct evidence of whether the real
//! outbound queue actually dropped anything during a genuine sustained
//! load, which is exactly the still-open mystery's blind spot. The
//! upload leg's sender already knows its own delta locally (no wire
//! transport needed); the download leg's sender is the *peer*, so its
//! delta rides along on the reverse stream and reaches the original
//! requester via `TunnelTestContext` alongside the achieved rate.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Fixed port the tunnel-level self-test listener binds to, on the TUN
/// device's own local address -- not configurable, since this is an
/// internal coordination detail between two `mlvpnd` processes, not
/// something an operator needs to tune (unlike a link's `local_port`,
/// which binds to a real routable WAN address an operator controls
/// firewalling for).
pub const TUNNEL_TEST_PORT: u16 = 34551;

const HEADER_LEN: usize = 4 + 1 + 4 + 8;
const FLAG_DONE: u8 = 0b01;
const FLAG_BIDIRECTIONAL_REQUESTED: u8 = 0b10;
const RESULT_LEN: usize = 4 + 4;

/// Largest UDP payload this module ever reads -- generous relative to
/// any realistic tunnel MTU, just a fixed receive-buffer size.
const MAX_APP_FRAME: usize = 9000;

/// Pause between each redundant final ("done") packet -- similar
/// reasoning to `tunnel::THROUGHPUT_TEST_DONE_RETRY_DELAY`, but this
/// path found a harsher real case than that constant's own 250ms was
/// tuned against: sending real UDP through a TUN device (rather than
/// directly on a link's own socket) means the backlog this pause needs
/// to survive isn't just a downstream shaper's queue, it's also
/// whatever the *kernel* buffered for `tun_reader` faster than it could
/// actually drain -- observed in testing on an unshaped local veth pair
/// (no bandwidth cap at all) taking several *seconds* to clear, not
/// milliseconds. Longer and more numerous than the per-link self-test's
/// own retries as a result.
const DONE_RETRY_DELAY: Duration = Duration::from_millis(500);

/// How many redundant "done" copies to send, beyond the first, spaced
/// `DONE_RETRY_DELAY` apart -- see that constant's doc comment for why
/// this path needs more margin than a 2-extra-copies budget provides.
const DONE_RETRY_COUNT: u32 = 4;

/// Extra time a caller waits, beyond a leg's own duration, for its
/// result -- covers the full `DONE_RETRY_COUNT * DONE_RETRY_DELAY`
/// spread plus normal round-trip time.
const RESULT_GRACE: Duration = Duration::from_secs(8);

/// Ceiling `send_stream` paces itself against -- see that function's
/// own doc comment for why this exists at all: without it, a fast
/// enough sender can dump data into the TUN device's own kernel buffer
/// faster than `tunnel::tun_reader` can drain it, building an unbounded
/// backlog no downstream `tc` shaping can prevent (confirmed in
/// testing: even pacing at 1000 Mbps still wasn't conservative enough
/// to keep the real outbound-queue/TUN pipeline's own drain rate ahead
/// of the sender on ordinary test hardware). Deliberately well below
/// what a genuinely fast WAN link might sustain -- this trades some
/// measurement ceiling for reliability, which matters more here: a
/// self-test that frequently returns "no result" on a fast link is
/// worse than one that reports an accurate number up to a conservative
/// cap. Revisit with real adaptive pacing (back off on observed queue
/// drops, not a fixed ceiling) if this cap turns out to matter in
/// practice against a real link faster than it.
const MAX_SEND_RATE_MBPS: f64 = 150.0;

/// Plain (unauthenticated at this layer -- see the module doc comment
/// for why that's fine) app-level payload carried by every packet of a
/// tunnel-level test stream.
struct DataPayload {
    test_id: u32,
    done: bool,
    /// Only meaningful on the very first packet in practice, but sent
    /// on every packet since there's no cost to it and no ordering
    /// guarantee for which packet the receiver's `ReceiveState` first
    /// keys off of.
    bidirectional_requested: bool,
    /// Mirrors the request across to the reverse leg, so the receiver
    /// (should it become a sender for the reverse leg) runs the same
    /// duration the original requester asked for.
    duration_secs: u32,
    /// This *sender's* own `outbound_dropped_total` delta observed
    /// across sending this stream -- meaningful only when `done` is
    /// set, since it's not final until the stream is.
    sender_queue_drops: u64,
}

impl DataPayload {
    fn encode_padded(&self, total_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; total_len.max(HEADER_LEN)];
        out[0..4].copy_from_slice(&self.test_id.to_be_bytes());
        let mut flags = 0u8;
        if self.done {
            flags |= FLAG_DONE;
        }
        if self.bidirectional_requested {
            flags |= FLAG_BIDIRECTIONAL_REQUESTED;
        }
        out[4] = flags;
        out[5..9].copy_from_slice(&self.duration_secs.to_be_bytes());
        out[9..17].copy_from_slice(&self.sender_queue_drops.to_be_bytes());
        out
    }

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        let flags = buf[4];
        Some(Self {
            test_id: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            done: flags & FLAG_DONE != 0,
            bidirectional_requested: flags & FLAG_BIDIRECTIONAL_REQUESTED != 0,
            duration_secs: u32::from_be_bytes(buf[5..9].try_into().unwrap()),
            sender_queue_drops: u64::from_be_bytes(buf[9..17].try_into().unwrap()),
        })
    }
}

/// Reply to a completed upload-leg stream, sent once, directly, back to
/// the ephemeral socket that sent it -- there's exactly one of these in
/// flight per invocation (unlike the persistent listener's own
/// multiplexed traffic), so no correlation registry is needed for it;
/// the caller just reads its own socket.
struct ResultPayload {
    test_id: u32,
    achieved_mbps: f32,
}

impl ResultPayload {
    fn encode(&self) -> [u8; RESULT_LEN] {
        let mut out = [0u8; RESULT_LEN];
        out[0..4].copy_from_slice(&self.test_id.to_be_bytes());
        out[4..8].copy_from_slice(&self.achieved_mbps.to_be_bytes());
        out
    }

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < RESULT_LEN {
            return None;
        }
        Some(Self {
            test_id: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            achieved_mbps: f32::from_be_bytes(buf[4..8].try_into().unwrap()),
        })
    }
}

/// One leg's result, as delivered to a waiting `run_test` invocation by
/// the persistent listener (`run_listener`) when it finishes measuring
/// an incoming stream that turns out to be *this* daemon's own reverse
/// leg rather than someone else testing it fresh.
pub(crate) struct TunnelTestLegResult {
    pub(crate) achieved_mbps: f64,
    /// The *peer's* own outbound-queue-drop delta while it sent this
    /// leg -- see the module doc comment's "Queue-drop visibility"
    /// section.
    pub(crate) peer_queue_drops: u64,
}

/// Keyed by `test_id`, same shape and reasoning as
/// `tunnel::ThroughputTestContext` (which this predates as a design,
/// not a fork of it): `run_listener` is a single long-running task
/// entirely separate from whichever `run_test` invocation is waiting on
/// a download leg's result, so delivery needs a registry rather than a
/// direct return value.
pub(crate) struct TunnelTestContext {
    waiters: std::sync::Mutex<HashMap<u32, mpsc::UnboundedSender<TunnelTestLegResult>>>,
}

impl TunnelTestContext {
    pub(crate) fn new() -> Self {
        Self {
            waiters: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn register_wait(
        &self,
        test_id: u32,
    ) -> mpsc::UnboundedReceiver<TunnelTestLegResult> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut waiters = self.waiters.lock().unwrap();
        waiters.retain(|_, tx| !tx.is_closed());
        waiters.insert(test_id, tx);
        rx
    }

    /// Delivers `result` to the waiter registered for `test_id`, if any,
    /// and reports whether one was found. That return value is what
    /// lets `run_listener` tell "this incoming stream is my own reverse
    /// leg completing" (a waiter was registered -- don't reply, don't
    /// trigger yet another reverse leg) apart from "someone else is
    /// genuinely testing me fresh" (no waiter -- do both).
    fn forward_result(&self, test_id: u32, result: TunnelTestLegResult) -> bool {
        if let Some(tx) = self.waiters.lock().unwrap().remove(&test_id) {
            let _ = tx.send(result);
            true
        } else {
            false
        }
    }
}

/// Same throughput calculation as `tunnel::compute_achieved_mbps` --
/// duplicated rather than shared across a `pub(crate)` boundary since
/// it's a single, trivial, pure arithmetic line and this module is
/// deliberately independent of `tunnel.rs`'s own internals.
fn compute_achieved_mbps(bytes: u64, elapsed_secs: f64) -> f64 {
    let elapsed_secs = elapsed_secs.max(0.000_001);
    (bytes as f64 * 8.0) / elapsed_secs / 1_000_000.0
}

/// Sends a continuous stream of app-level test packets to
/// `peer_addr:TUNNEL_TEST_PORT` for `duration`, then spaced redundant
/// `done` copies -- see `DONE_RETRY_DELAY`'s doc comment for why the
/// spacing matters. Used for both the upload leg (`run_test`, which
/// then reads a reply off `socket` itself) and the autonomous reverse
/// leg (`run_listener`, which doesn't -- its result reaches the
/// original requester through `TunnelTestContext` on the *other* end
/// instead).
async fn send_stream(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    test_id: u32,
    duration: Duration,
    bidirectional_requested: bool,
    mtu: usize,
    outbound_dropped_total: &Arc<AtomicU64>,
) {
    let payload_len = mtu.saturating_sub(48).max(HEADER_LEN);
    let start = Instant::now();
    let deadline = start + duration;
    let queue_drops_before = outbound_dropped_total.load(Ordering::Relaxed);
    let mut bytes_sent: u64 = 0;

    loop {
        let done = Instant::now() >= deadline;
        let sender_queue_drops = if done {
            outbound_dropped_total
                .load(Ordering::Relaxed)
                .saturating_sub(queue_drops_before)
        } else {
            0
        };
        let payload = DataPayload {
            test_id,
            done,
            bidirectional_requested,
            duration_secs: duration.as_secs() as u32,
            sender_queue_drops,
        }
        .encode_padded(payload_len);
        let _ = socket.send_to(&payload, peer_addr).await;
        bytes_sent += payload.len() as u64;
        if done {
            for _ in 0..DONE_RETRY_COUNT {
                tokio::time::sleep(DONE_RETRY_DELAY).await;
                let _ = socket.send_to(&payload, peer_addr).await;
            }
            return;
        }

        // Pace against MAX_SEND_RATE_MBPS -- see that constant's own
        // doc comment for why an *unpaced* version of this loop turned
        // out to be a real bug, not just a theoretical concern: unlike
        // `tunnel::send_throughput_test_stream` (raw UDP directly on a
        // link's own socket), this traffic goes in through the TUN
        // device, and plain UDP `send_to` returns as soon as the
        // *local* kernel accepts the datagram -- it does not wait for
        // the receiver, or even for `tun_reader` to have caught up. A
        // fast enough sender can dump far more data into the TUN
        // device's own kernel-side buffer than `tun_reader` can drain
        // in real time, building an unbounded backlog no amount of
        // `tc` shaping on the *egress* side (downstream of that same
        // buffer) can prevent -- confirmed in testing: an unpaced
        // sender against an uncapped local veth pair, or even a
        // 200mbit-shaped one, left a backlog that took many seconds
        // (well past any reasonable redundant-"done"-packet retry
        // budget) to drain.
        let elapsed = start.elapsed().as_secs_f64();
        let ideal_elapsed_secs = (bytes_sent as f64 * 8.0) / (MAX_SEND_RATE_MBPS * 1_000_000.0);
        if ideal_elapsed_secs > elapsed {
            tokio::time::sleep(Duration::from_secs_f64(ideal_elapsed_secs - elapsed)).await;
        }
    }
}

/// Outcome of `run_test`, mirroring `ipc::TunnelTestCommandResult`
/// (kept as a separate type here so this module doesn't depend on
/// `ipc.rs`; `control::apply_command` converts between the two).
pub(crate) struct TunnelTestOutcome {
    pub(crate) upload_mbps: Option<f64>,
    pub(crate) download_mbps: Option<f64>,
    pub(crate) local_queue_drops: u64,
    pub(crate) peer_queue_drops: Option<u64>,
}

/// Runs a full tunnel-level throughput test against `peer_addr`
/// (already resolved -- `control::apply_command` parses the operator's
/// `--peer-addr` string before calling this). Always runs the upload
/// leg; when `bidirectional`, also waits for the peer's autonomous
/// reverse leg. Best-effort throughout, same philosophy as the per-link
/// self-test: a leg that never produces a result just comes back `None`
/// rather than failing the whole command.
pub(crate) async fn run_test(
    peer_addr: IpAddr,
    duration_secs: u32,
    bidirectional: bool,
    mtu: usize,
    outbound_dropped_total: &Arc<AtomicU64>,
    tunnel_test_ctx: &Arc<TunnelTestContext>,
) -> TunnelTestOutcome {
    let test_id = crate::crypto::random_session_id();
    let duration = Duration::from_secs(duration_secs as u64);
    let remote = SocketAddr::new(peer_addr, TUNNEL_TEST_PORT);

    // Registered *before* sending, same reasoning as
    // ThroughputTestContext's own callers: the peer's autonomous
    // reverse leg could in principle start arriving before this
    // function gets around to awaiting the receiver.
    let mut download_rx = tunnel_test_ctx.register_wait(test_id);

    let socket = match UdpSocket::bind(("0.0.0.0", 0)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "tunnel-level self-test: failed to bind ephemeral socket");
            return TunnelTestOutcome {
                upload_mbps: None,
                download_mbps: None,
                local_queue_drops: 0,
                peer_queue_drops: None,
            };
        }
    };

    let queue_drops_before = outbound_dropped_total.load(Ordering::Relaxed);
    send_stream(
        &socket,
        remote,
        test_id,
        duration,
        bidirectional,
        mtu,
        outbound_dropped_total,
    )
    .await;
    let local_queue_drops = outbound_dropped_total
        .load(Ordering::Relaxed)
        .saturating_sub(queue_drops_before);

    let upload_mbps = {
        let mut buf = [0u8; RESULT_LEN];
        match tokio::time::timeout(duration + RESULT_GRACE, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _from))) => ResultPayload::decode(&buf[..n])
                .filter(|r| r.test_id == test_id)
                .map(|r| r.achieved_mbps as f64),
            _ => None,
        }
    };

    let (download_mbps, peer_queue_drops) = if bidirectional {
        // Sequential, not concurrent, with the upload leg above: the
        // peer only starts its own reverse stream after it finishes
        // measuring and replying to the upload leg, so this can't
        // usefully be raced against it -- generous timeout covering
        // that full sequence.
        let wait = duration * 2 + RESULT_GRACE * 2;
        match tokio::time::timeout(wait, download_rx.recv()).await {
            Ok(Some(result)) => (Some(result.achieved_mbps), Some(result.peer_queue_drops)),
            _ => (None, None),
        }
    } else {
        (None, None)
    };

    TunnelTestOutcome {
        upload_mbps,
        download_mbps,
        local_queue_drops,
        peer_queue_drops,
    }
}

/// Per-listener bookkeeping for an in-progress incoming stream --
/// single-flight, same "one at a time" design as
/// `tunnel::ThroughputTestReceiveState`: this is a manually-invoked
/// operator tool, not something expected to run many concurrent tests
/// against the same daemon.
struct ReceiveState {
    test_id: Option<u32>,
    first_seen: Instant,
    bytes_seen: u64,
    last_completed_test_id: Option<u32>,
}

impl ReceiveState {
    fn new() -> Self {
        Self {
            test_id: None,
            first_seen: Instant::now(),
            bytes_seen: 0,
            last_completed_test_id: None,
        }
    }
}

/// The persistent, always-on (when `[command] enabled = true`) listener
/// that makes the tunnel-level self-test possible at all: bound to the
/// TUN device's own local address on `TUNNEL_TEST_PORT`, so it only
/// ever receives traffic that actually transited the tunnel (or
/// originated locally addressed to that IP -- the same trust boundary
/// as any other traffic reaching this host over the tunnel).
///
/// Handles two distinct cases that look identical on the wire and are
/// only distinguished by whether a local `TunnelTestContext` waiter
/// exists for the incoming `test_id`:
/// - **No waiter**: someone else is genuinely testing us fresh (the
///   upload leg of a test *they* initiated). Measure, reply once with
///   our achieved rate, and -- if they asked for a bidirectional test
///   -- autonomously start our own stream back to them (the download
///   leg from their point of view). Never reply to *that* stream's
///   `bidirectional_requested` flag even if a stray one were set: that
///   would ping-pong forever, so the reverse leg this function sends is
///   hardcoded `bidirectional_requested: false`.
/// - **A waiter exists**: this incoming stream is the autonomous
///   reverse leg answering a test *we* initiated (`run_test`,
///   elsewhere, registered the wait before sending). Deliver the
///   result locally via `TunnelTestContext` and stop -- no reply, no
///   further reverse leg.
pub(crate) async fn run_listener(
    tunnel_local_addr: IpAddr,
    outbound_dropped_total: Arc<AtomicU64>,
    tunnel_test_ctx: Arc<TunnelTestContext>,
    mtu: usize,
) {
    let bind_addr = SocketAddr::new(tunnel_local_addr, TUNNEL_TEST_PORT);
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!(
                error = %e,
                addr = %bind_addr,
                "failed to bind tunnel-level self-test listener; \
                 `mlvpnd self-test --tunnel` will be unavailable against this host"
            );
            return;
        }
    };
    tracing::info!(addr = %bind_addr, "tunnel-level self-test listener bound");

    let mut buf = vec![0u8; MAX_APP_FRAME];
    let mut state = ReceiveState::new();
    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "tunnel-level self-test listener recv error");
                continue;
            }
        };
        let Some(data) = DataPayload::decode(&buf[..n]) else {
            continue;
        };
        if state.last_completed_test_id == Some(data.test_id) {
            continue;
        }
        if state.test_id != Some(data.test_id) {
            state.test_id = Some(data.test_id);
            state.first_seen = Instant::now();
            state.bytes_seen = 0;
        }
        state.bytes_seen += n as u64;
        if !data.done {
            continue;
        }

        let elapsed_secs = state.first_seen.elapsed().as_secs_f64();
        let achieved_mbps = compute_achieved_mbps(state.bytes_seen, elapsed_secs);
        state.test_id = None;
        state.last_completed_test_id = Some(data.test_id);

        let delivered_locally = tunnel_test_ctx.forward_result(
            data.test_id,
            TunnelTestLegResult {
                achieved_mbps,
                peer_queue_drops: data.sender_queue_drops,
            },
        );
        if delivered_locally {
            continue;
        }

        tracing::info!(%from, achieved_mbps, "tunnel-level self-test stream received");

        let result = ResultPayload {
            test_id: data.test_id,
            achieved_mbps: achieved_mbps as f32,
        }
        .encode();
        let _ = socket.send_to(&result, from).await;

        if data.bidirectional_requested {
            let socket = socket.clone();
            let outbound_dropped_total = outbound_dropped_total.clone();
            let test_id = data.test_id;
            let duration = Duration::from_secs(data.duration_secs as u64);
            // *Not* `from` directly: `from` is the client's ephemeral
            // upload-socket source port, which nothing keeps listening
            // on past that leg's own reply -- the reverse leg needs to
            // land on the client's *persistent* listener instead (same
            // IP, well-known `TUNNEL_TEST_PORT`), since that's the task
            // actually watching `TunnelTestContext` for this test_id
            // (registered by `run_test` before the upload leg ever went
            // out).
            let reverse_target = SocketAddr::new(from.ip(), TUNNEL_TEST_PORT);
            tokio::spawn(async move {
                send_stream(
                    &socket,
                    reverse_target,
                    test_id,
                    duration,
                    false,
                    mtu,
                    &outbound_dropped_total,
                )
                .await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_payload_round_trips_all_fields() {
        let payload = DataPayload {
            test_id: 0xdead_beef,
            done: true,
            bidirectional_requested: true,
            duration_secs: 10,
            sender_queue_drops: 42,
        };
        let encoded = payload.encode_padded(1400);
        assert_eq!(encoded.len(), 1400);
        let decoded = DataPayload::decode(&encoded).expect("decode");
        assert_eq!(decoded.test_id, payload.test_id);
        assert!(decoded.done);
        assert!(decoded.bidirectional_requested);
        assert_eq!(decoded.duration_secs, 10);
        assert_eq!(decoded.sender_queue_drops, 42);
    }

    #[test]
    fn data_payload_round_trips_not_done_not_bidirectional() {
        let payload = DataPayload {
            test_id: 7,
            done: false,
            bidirectional_requested: false,
            duration_secs: 5,
            sender_queue_drops: 0,
        };
        let encoded = payload.encode_padded(64);
        let decoded = DataPayload::decode(&encoded).expect("decode");
        assert!(!decoded.done);
        assert!(!decoded.bidirectional_requested);
    }

    #[test]
    fn data_payload_encode_padded_never_truncates_header() {
        let payload = DataPayload {
            test_id: 1,
            done: false,
            bidirectional_requested: false,
            duration_secs: 1,
            sender_queue_drops: 0,
        };
        let encoded = payload.encode_padded(0);
        assert_eq!(encoded.len(), HEADER_LEN);
        assert!(DataPayload::decode(&encoded).is_some());
    }

    #[test]
    fn data_payload_decode_rejects_short_buffer() {
        let buf = [0u8; 4];
        assert!(DataPayload::decode(&buf).is_none());
    }

    #[test]
    fn result_payload_round_trips() {
        let payload = ResultPayload {
            test_id: 99,
            achieved_mbps: 412.3,
        };
        let encoded = payload.encode();
        let decoded = ResultPayload::decode(&encoded).expect("decode");
        assert_eq!(decoded.test_id, 99);
        assert!((decoded.achieved_mbps - 412.3).abs() < f32::EPSILON);
    }

    #[test]
    fn result_payload_decode_rejects_short_buffer() {
        let buf = [0u8; 4];
        assert!(ResultPayload::decode(&buf).is_none());
    }

    #[tokio::test]
    async fn tunnel_test_context_delivers_to_a_registered_waiter() {
        let ctx = TunnelTestContext::new();
        let mut rx = ctx.register_wait(123);
        let delivered = ctx.forward_result(
            123,
            TunnelTestLegResult {
                achieved_mbps: 88.8,
                peer_queue_drops: 2,
            },
        );
        assert!(delivered);
        let result = rx.recv().await.expect("result delivered");
        assert!((result.achieved_mbps - 88.8).abs() < f64::EPSILON);
        assert_eq!(result.peer_queue_drops, 2);
    }

    #[test]
    fn tunnel_test_context_reports_no_delivery_for_an_unregistered_test_id() {
        let ctx = TunnelTestContext::new();
        let _rx = ctx.register_wait(1);
        let delivered = ctx.forward_result(
            2,
            TunnelTestLegResult {
                achieved_mbps: 1.0,
                peer_queue_drops: 0,
            },
        );
        assert!(
            !delivered,
            "a test_id with no registered waiter must not report delivery -- \
             this is exactly what lets run_listener tell 'someone else is \
             testing us fresh' apart from 'this is our own reverse leg'"
        );
    }

    #[test]
    fn compute_achieved_mbps_matches_expected_rate_for_round_numbers() {
        // 1,000,000 bytes (8,000,000 bits) in exactly 1 second = 8 Mbps.
        let mbps = compute_achieved_mbps(1_000_000, 1.0);
        assert!((mbps - 8.0).abs() < 1e-9, "mbps was {mbps}");
    }
}
