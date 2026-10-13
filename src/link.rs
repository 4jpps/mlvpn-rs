//! A `Link` is one bonded physical uplink: a UDP socket bound to a specific
//! network interface (via `SO_BINDTODEVICE`, so traffic provably egresses
//! that interface regardless of the kernel routing table) plus the running
//! statistics the scheduler needs to weigh it against the others.
//!
//! **Self-healing reconnection.** A link's socket is held behind a
//! `RwLock` (see `SharedSocket`/`LinkHandle` below) rather than handed
//! out as a bare `Arc<UdpSocket>`, so it can be replaced at runtime. Most
//! connectivity loss needs no help from this at all -- binding by
//! interface *name* rather than IP address (the whole reason this
//! project binds the way it does, see `ARCHITECTURE.md`'s attribution
//! section) already means a DHCP renewal or an interface briefly going
//! admin-down and back up doesn't disturb an already-bound socket; the
//! kernel just stops/resumes routing through it, and sends that failed
//! during the outage go back to succeeding the moment the route
//! returns, with zero code involvement. The gap this module closes is
//! narrower and worse: an interface that's fully *removed and
//! recreated* (a USB LTE modem unplugged and replugged, a PPP interface
//! torn down and rebuilt) comes back with a new kernel ifindex, and a
//! socket that was `SO_BINDTODEVICE`'d to the old one cannot recover no
//! matter how long it waits -- every send/receive on it keeps failing
//! (typically `ENODEV`) even though an interface with the same *name*
//! is genuinely usable again. `tunnel.rs`'s `link_receiver` and
//! `link_prober` tasks watch for a sustained run of failures on the
//! socket they're using and, past that threshold, call
//! `LinkHandle::reconnect` to rebind from scratch -- see that function's
//! doc comment for the one deployment-model caveat this has (it needs
//! `CAP_NET_RAW` to still be held at the time of the call).

use crate::config::LinkConfig;
use crate::crypto;
use crate::error::{MlvpnError, Result};
use crate::wireguard::{self, WgTunnel};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Never successfully probed since startup or since last Down.
    Probing,
    Up,
    Down,
}

impl LinkState {
    /// Wire encoding used by `protocol::StatsPayload` and the JSON
    /// `ipc::LinkSnapshot` schema.
    pub fn to_wire(self) -> u8 {
        match self {
            LinkState::Probing => 0,
            LinkState::Up => 1,
            LinkState::Down => 2,
        }
    }

    /// Inverse of `to_wire`. Any unrecognized byte (e.g. a future version
    /// on the peer) decodes as `Probing` rather than failing outright --
    /// this only ever feeds a monitoring display, never a security or
    /// scheduling decision, so "unknown" degrading to the most
    /// conservative label is preferable to dropping the whole StatsShare
    /// frame.
    pub fn from_wire(v: u8) -> Self {
        match v {
            1 => LinkState::Up,
            2 => LinkState::Down,
            _ => LinkState::Probing,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LinkState::Probing => "probing",
            LinkState::Up => "up",
            LinkState::Down => "down",
        }
    }
}

/// Exponentially-weighted moving average, used for latency/jitter/loss so
/// the scheduler reacts to trends rather than single noisy samples.
#[derive(Debug, Clone, Copy)]
pub struct Ewma {
    alpha: f64,
    value: Option<f64>,
}

impl Ewma {
    pub fn new(alpha: f64) -> Self {
        Self { alpha, value: None }
    }

    pub fn update(&mut self, sample: f64) -> f64 {
        let v = match self.value {
            None => sample,
            Some(prev) => self.alpha * sample + (1.0 - self.alpha) * prev,
        };
        self.value = Some(v);
        v
    }

    pub fn get(&self) -> Option<f64> {
        self.value
    }

    /// Change the smoothing factor used by future `update` calls.
    /// Doesn't touch `value` -- only the *rate* future samples get
    /// blended in changes, not the current smoothed estimate itself, so
    /// this never causes a visible jump on its own. Used by
    /// `LinkStats::set_alpha` for `scheduler.auto_tune_ewma_alpha`.
    pub fn set_alpha(&mut self, alpha: f64) {
        self.alpha = alpha;
    }
}

#[derive(Debug, Clone)]
pub struct LinkStats {
    pub rtt_ms: Ewma,
    /// Jitter per RFC 3550 sec 6.4.1: EWMA of the absolute difference
    /// between consecutive RTT samples.
    pub jitter_ms: Ewma,
    pub loss_rate: Ewma,
    /// Empirically observed receive-side throughput, updated from bytes
    /// actually received rather than a synthetic bandwidth probe
    /// (cheaper, no extra traffic, and reflects real contention on the
    /// link). A real-time rate (re-sampled every ~1s), not a cumulative
    /// total -- see `rx_bytes` for that. `tx_throughput_mbps` below is
    /// the send-side counterpart.
    pub rx_throughput_mbps: Ewma,
    /// Send-side counterpart to `rx_throughput_mbps` -- same windowed-EWMA
    /// real-time-rate design, fed from bytes actually handed to the
    /// socket rather than received. Kept as an entirely separate EWMA
    /// (own window, own smoothing state) since a link's send and
    /// receive rates are frequently asymmetric (e.g. most real traffic
    /// flowing predominantly one direction) and conflating them would
    /// average away exactly the asymmetry an operator watching live
    /// bonding behavior wants to see.
    pub tx_throughput_mbps: Ewma,
    /// Achieved throughput as measured by an explicit active bandwidth
    /// probe burst (`scheduler.active_bandwidth_probing`, opt-in and off
    /// by default -- see `tunnel::active_bandwidth_prober`), as opposed
    /// to `rx_throughput_mbps` above which only reflects bytes actually
    /// carried by real traffic. `None` until the first probe completes,
    /// or forever if the feature is off. Deliberately a separate EWMA
    /// rather than feeding into `rx_throughput_mbps` itself: an active
    /// probe's burst and a lull in real traffic measure different
    /// things, and conflating them would make either signal noisier.
    /// `monitor::score` prefers this one when it has a value.
    pub active_bandwidth_mbps: Ewma,
    /// Last rate `adaptive_bandwidth_ramp` fully converged on for this
    /// link, cached so `active_bandwidth_prober` can do a cheap
    /// single-step verification most ticks instead of a full ramp
    /// every time -- see `config::SchedulerConfig::active_bandwidth_reramp_interval_secs`.
    /// `None` until the first ramp completes.
    pub confirmed_ceiling_mbps: Option<f64>,
    /// When the cached `confirmed_ceiling_mbps` was last established by
    /// a full ramp (not a verification tick) -- compared against
    /// `active_bandwidth_reramp_interval_secs` to decide when the next
    /// tick should re-ramp instead of just verifying.
    pub last_ramp_at: Option<Instant>,
    /// How many verification ticks in a row have come back below the
    /// ramp's own success threshold -- two in a row triggers an
    /// out-of-cycle full re-ramp (see `active_bandwidth_prober`),
    /// rather than waiting for `active_bandwidth_reramp_interval_secs`.
    /// Reset to 0 on any clean verification or completed ramp.
    pub consecutive_verify_misses: u32,
    last_rtt_ms: Option<f64>,
    pub consecutive_misses: u32,
    pub consecutive_hits: u32,
    /// Raw probe outcomes for the automatic-report trigger only; never read by the scheduler.
    pub probe_window: crate::autoreport::ProbeWindow,
    pub down_transitions: crate::autoreport::DownTransitions,
    pub rx_bytes_since_last_sample: u64,
    pub last_rx_throughput_sample: Instant,
    pub tx_bytes_since_last_sample: u64,
    pub last_tx_throughput_sample: Instant,
    /// Lifetime totals, unlike the `*_bytes_since_last_sample` fields
    /// above (which reset every ~1s into their respective throughput
    /// EWMA) -- these only ever grow, for `mlvpn-tui`'s "how much has
    /// actually crossed this link" display.
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    /// Lock-free send-side health counters, shared with this link's TX
    /// worker and the dispatcher in `tunnel.rs` (they bump these without
    /// taking the link mutex, which matters exactly when a link is
    /// congested and every packet hits one of them).
    pub tx_counters: Arc<TxCounters>,
}

/// Lifetime counters for the per-link TX queue/worker (`tunnel.rs`'s
/// `LinkTxQueue`). Plain relaxed atomics: they are diagnostics, never used
/// to make a correctness decision.
#[derive(Debug, Default)]
pub struct TxCounters {
    /// Times the dispatcher found this link's bounded TX queue full when
    /// it tried to hand it a packet -- i.e. the link's socket send path
    /// was not keeping up.
    pub queue_full: AtomicU64,
    /// Packets this link's worker failed to put on the wire (socket
    /// error, or no remote address known).
    pub send_failed: AtomicU64,
    /// Packets that were redirected to a different link because this one
    /// could not take them (queue full or send failure).
    pub rerouted_away: AtomicU64,
    /// Packets currently waiting in (or being sent from) this link's TX
    /// queue. Incremented by the dispatcher before each enqueue attempt
    /// and decremented by the worker once a batch is finished.
    pub depth: AtomicU32,
    /// Sum / count / max of the queue delay -- how long the oldest packet
    /// of each worker batch sat in the queue before the worker picked it
    /// up. The scheduler turns interval deltas of the first two into an
    /// average delay (`congestion.rs`); the third is a lifetime peak.
    pub queue_delay_sum_us: AtomicU64,
    pub queue_delay_samples: AtomicU64,
    pub queue_delay_max_us: AtomicU64,
    /// Sum / count of the per-packet time spent inside the link's socket
    /// send (`wg_send_parts`), one sample per worker batch.
    pub send_wait_sum_us: AtomicU64,
    pub send_wait_samples: AtomicU64,
    /// `mono_us()` of the worker's last batch start/finish; 0 until the
    /// first batch. A worker wedged inside a blocking send stops updating
    /// it, which is how the scheduler notices a stall that produces no
    /// new delay samples.
    pub last_progress_us: AtomicU64,
    /// Scheduler-published view, refreshed every congestion tick: the
    /// recent average queue delay and send wait (0 when idle), and the
    /// congestion factor in thousandths (1000 = healthy).
    pub queue_delay_recent_us: AtomicU64,
    pub send_wait_recent_us: AtomicU64,
    pub congestion_milli: AtomicU32,
    /// Delivery-feedback factor in millionths (1_000_000 = healthy); see
    /// `delivery.rs`.
    pub delivery_ppm: AtomicU32,
}

impl TxCounters {
    pub fn new() -> Self {
        let c = Self::default();
        c.congestion_milli.store(1000, Ordering::Relaxed);
        c.delivery_ppm.store(1_000_000, Ordering::Relaxed);
        c
    }
}

/// Microseconds on a process-wide monotonic clock, never 0 (0 means
/// "unset" in `TxCounters::last_progress_us`).
pub fn mono_us() -> u64 {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    EPOCH
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_micros() as u64
        + 1
}

impl LinkStats {
    pub fn new(alpha: f64) -> Self {
        Self {
            rtt_ms: Ewma::new(alpha),
            jitter_ms: Ewma::new(alpha),
            loss_rate: Ewma::new(alpha),
            rx_throughput_mbps: Ewma::new(alpha),
            tx_throughput_mbps: Ewma::new(alpha),
            active_bandwidth_mbps: Ewma::new(alpha),
            confirmed_ceiling_mbps: None,
            last_ramp_at: None,
            consecutive_verify_misses: 0,
            last_rtt_ms: None,
            consecutive_misses: 0,
            consecutive_hits: 0,
            probe_window: Default::default(),
            down_transitions: Default::default(),
            rx_bytes_since_last_sample: 0,
            last_rx_throughput_sample: Instant::now(),
            tx_bytes_since_last_sample: 0,
            last_tx_throughput_sample: Instant::now(),
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
            tx_counters: Arc::new(TxCounters::new()),
        }
    }

    /// Apply a new smoothing factor to the per-packet EWMAs that
    /// `scheduler.auto_tune_ewma_alpha` tunes together (see its own doc
    /// comment in `config.rs`), so a caller never needs to reach into
    /// e.g. just `rtt_ms` alone. Deliberately does *not* touch
    /// `active_bandwidth_mbps`: that EWMA is fed by a probe every few
    /// minutes rather than every packet, so the fast-reacting/
    /// slow-reacting tradeoff `auto_tune_ewma_alpha` makes for the
    /// others doesn't apply to it in the same way.
    pub fn set_alpha(&mut self, alpha: f64) {
        self.rtt_ms.set_alpha(alpha);
        self.jitter_ms.set_alpha(alpha);
        self.loss_rate.set_alpha(alpha);
        self.rx_throughput_mbps.set_alpha(alpha);
        self.tx_throughput_mbps.set_alpha(alpha);
    }

    /// Record a successful probe round trip.
    pub fn record_rtt(&mut self, rtt_ms: f64) {
        self.rtt_ms.update(rtt_ms);
        if let Some(prev) = self.last_rtt_ms {
            self.jitter_ms.update((rtt_ms - prev).abs());
        }
        self.last_rtt_ms = Some(rtt_ms);
        self.loss_rate.update(0.0);
        self.consecutive_misses = 0;
        self.consecutive_hits += 1;
        self.probe_window.record(Instant::now(), true);
    }

    /// Record a missed probe (no reply within the timeout).
    pub fn record_miss(&mut self) {
        self.loss_rate.update(1.0);
        self.consecutive_misses += 1;
        self.consecutive_hits = 0;
        self.probe_window.record(Instant::now(), false);
    }

    /// Lifetime counter (`tx_bytes`/`tx_packets`) *and* the windowed
    /// `tx_throughput_mbps` real-time-rate EWMA, both from one call --
    /// call once per packet actually handed to the socket, on the send
    /// side.
    pub fn record_tx(&mut self, n: u64) {
        self.record_tx_many(n, 1);
    }

    /// Batch form of `record_tx`, for a per-link TX worker that sent
    /// several frames under one link lock (`tunnel::link_tx_worker`).
    pub fn record_tx_many(&mut self, bytes: u64, packets: u64) {
        let n = bytes;
        self.tx_bytes += n;
        self.tx_packets += packets;
        self.tx_bytes_since_last_sample += n;
        let elapsed = self.last_tx_throughput_sample.elapsed();
        if elapsed.as_secs_f64() >= 1.0 {
            let mbps = (self.tx_bytes_since_last_sample as f64 * 8.0)
                / elapsed.as_secs_f64()
                / 1_000_000.0;
            self.tx_throughput_mbps.update(mbps);
            self.tx_bytes_since_last_sample = 0;
            self.last_tx_throughput_sample = Instant::now();
        }
    }

    /// Receive-side counterpart to `record_tx`: lifetime counter
    /// (`rx_bytes`/`rx_packets`) and the windowed `rx_throughput_mbps`
    /// real-time-rate EWMA, both from one call.
    pub fn record_rx(&mut self, n: u64) {
        self.rx_bytes += n;
        self.rx_packets += 1;
        self.rx_bytes_since_last_sample += n;
        let elapsed = self.last_rx_throughput_sample.elapsed();
        if elapsed.as_secs_f64() >= 1.0 {
            let mbps = (self.rx_bytes_since_last_sample as f64 * 8.0)
                / elapsed.as_secs_f64()
                / 1_000_000.0;
            self.rx_throughput_mbps.update(mbps);
            self.rx_bytes_since_last_sample = 0;
            self.last_rx_throughput_sample = Instant::now();
        }
    }
}

/// A link's UDP socket, shared between its `link_receiver` and
/// `link_prober` tasks (`tunnel.rs`) behind a `RwLock` instead of a bare
/// `Arc<UdpSocket>`, so either task can install a freshly rebound socket
/// (`LinkHandle::reconnect`) and have the other pick it up on its very
/// next read -- see this module's doc comment for why that's needed.
pub type SharedSocket = Arc<AsyncRwLock<Arc<UdpSocket>>>;

/// Everything a per-link task needs to read the current socket and,
/// if it appears permanently dead, trigger a reconnect -- captured once
/// at task startup the same way those tasks already captured a bare
/// socket handle before this existed, rather than re-locking the shared
/// `Vec<Link>` for every packet. Cloning a `LinkHandle` is cheap (a
/// `LinkConfig` clone plus two `Arc` clones); every clone shares the
/// same underlying socket slot and reconnect lock.
#[derive(Clone)]
pub struct LinkHandle {
    pub link_id: u8,
    config: LinkConfig,
    /// The address `remote_addr` resolved to at `Link::bind` time,
    /// snapshotted here the same way `config` is -- see `reconnect`'s
    /// doc comment for why reconnect reuses this instead of re-resolving
    /// DNS itself.
    remote: Option<SocketAddr>,
    socket: SharedSocket,
    reconnect_lock: Arc<AsyncMutex<()>>,
    /// This link's own independent WireGuard tunnel (own keypair,
    /// handshake, rekey, replay window) -- see `wireguard::WgTunnel`.
    /// Shared (via `Arc`) with the `Link` this handle was built from
    /// (`Link::handle`/`Link::alternate_handle`), since a link's crypto
    /// session is tied to the *link's own identity/keys*, not to
    /// whichever concrete socket currently backs it -- a `reconnect()`
    /// that rebinds the socket must not disturb an already-established
    /// WireGuard session.
    wg: Arc<WgTunnel>,
}

impl LinkHandle {
    /// Read the socket currently in use. Cheap (an uncontended `RwLock`
    /// read plus an `Arc` clone) and meant to be called fresh before
    /// every `send_to`/`recv_from` rather than cached across an await
    /// point, so a reconnect that happened in between is picked up
    /// immediately instead of on the next task restart.
    pub async fn current_socket(&self) -> Arc<UdpSocket> {
        self.socket.read().await.clone()
    }

    /// Encrypt `frame` (an already-serialized mlvpn frame -- header,
    /// seq, `PacketType`, payload; see `protocol.rs`) through this
    /// link's own `WgTunnel` and send the resulting datagram out on the
    /// link's *current* socket (re-read fresh, same reasoning as
    /// `current_socket`'s own doc comment) to `self.remote`.
    ///
    /// Before a WireGuard session is established, `WgTunnel::encapsulate`
    /// returns a handshake-initiation datagram instead of a datagram
    /// actually carrying `frame` (boringtun queues the plaintext
    /// internally and only actually delivers it once the handshake
    /// completes and `encapsulate` is called again) -- this method's
    /// contract is exactly `WgTunnel::encapsulate`'s own: "a datagram
    /// ready to send", not a guarantee this specific call delivered
    /// `frame` to the peer. Callers that need delivery confirmed should
    /// retry, the same way real WireGuard relies on the *upper* protocol
    /// (TCP, or here, mlvpn's own retry/ack behavior) to notice loss and
    /// resend rather than solving it at this layer.
    ///
    /// The returned `bool` (propagated straight from
    /// `WgTunnel::encapsulate`) is `true` only when the datagram actually
    /// put on the wire genuinely carried `frame`, and `false` when
    /// boringtun substituted a handshake datagram for it. `Ok(false)` is
    /// still a successful socket write -- it just means *this* frame did
    /// not reach the wire. Callers that don't care (probes, stats
    /// broadcasts, throughput-test traffic -- nothing whose correctness
    /// depends on the peer observing this exact frame) may ignore it;
    /// FEC group accumulation must not.
    pub async fn wg_send(&self, frame: &[u8]) -> Result<bool> {
        self.wg_send_parts(&[frame]).await
    }

    /// `wg_send` for a frame given as consecutive pieces (header, payload)
    /// -- see `WgTunnel::encapsulate_parts`. Same contract and return
    /// value as `wg_send`.
    pub async fn wg_send_parts(&self, parts: &[&[u8]]) -> Result<bool> {
        let remote = self.remote.ok_or_else(|| {
            MlvpnError::Protocol(format!(
                "wg_send: link '{}' has no remote address to send to yet",
                self.config.name
            ))
        })?;
        let (datagram, carries_frame) = self.wg.encapsulate_parts(parts)?;
        let socket = self.current_socket().await;
        socket
            .send_to(&datagram, remote)
            .await
            .map_err(MlvpnError::Io)?;
        Ok(carries_frame)
    }

    /// `wg_send_parts` for a whole worker batch (`tx_send_mode = "sendmmsg"`).
    /// Every frame is encapsulated in order exactly as the
    /// per-packet path would, then all resulting datagrams go out through
    /// `sendmmsg(2)` (one syscall per kernel-accepted run instead of one
    /// `sendto` each). Returns one result per input frame, same contract
    /// as `wg_send_parts` (`Ok(carries_frame)` / `Err`), so the caller's
    /// per-packet failure handling is unchanged.
    /// `gso` additionally coalesces equal-size runs via `UDP_SEGMENT`.
    pub async fn wg_send_batch(
        &self,
        frames: &[[&[u8]; 2]],
        gso: bool,
    ) -> (Vec<Result<bool>>, SendmmsgStats) {
        let Some(remote) = self.remote else {
            let errs = frames
                .iter()
                .map(|_| {
                    Err(MlvpnError::Protocol(format!(
                        "wg_send: link '{}' has no remote address to send to yet",
                        self.config.name
                    )))
                })
                .collect();
            return (errs, SendmmsgStats::default());
        };
        let mut results: Vec<Result<bool>> = Vec::with_capacity(frames.len());
        let mut datagrams: Vec<Vec<u8>> = Vec::with_capacity(frames.len());
        let mut slot: Vec<usize> = Vec::with_capacity(frames.len());
        for (i, parts) in frames.iter().enumerate() {
            match self.wg.encapsulate_parts(&parts[..]) {
                Ok((datagram, carries)) => {
                    results.push(Ok(carries));
                    datagrams.push(datagram);
                    slot.push(i);
                }
                Err(e) => results.push(Err(e)),
            }
        }
        let socket = self.current_socket().await;
        let (outcomes, stats) = if gso {
            sendmmsg_gso_all(&socket, remote, &datagrams).await
        } else {
            sendmmsg_all(&socket, remote, &datagrams).await
        };
        for (k, outcome) in outcomes.into_iter().enumerate() {
            if let Err(e) = outcome {
                results[slot[k]] = Err(MlvpnError::Io(e));
            }
        }
        (results, stats)
    }

    /// Receive one raw datagram off this link's *current* socket and
    /// feed it through this link's own `WgTunnel`, looping internally
    /// until an actual decrypted mlvpn frame comes out -- callers never
    /// see the handshake/keepalive/rekey traffic `WgTunnel::decapsulate`
    /// also has to process on the very same socket:
    ///  - `DecapsulateOutcome::Frame` -- a real mlvpn frame; returned to
    ///    the caller immediately.
    ///  - `DecapsulateOutcome::SendReply` -- boringtun produced a
    ///    handshake response/keepalive confirmation that must go back to
    ///    whichever address just sent us this datagram (not necessarily
    ///    `self.remote` -- a server-mode link may not have learned that
    ///    yet on its very first incoming packet). Sent immediately, then
    ///    the loop continues waiting for the next datagram.
    ///  - `DecapsulateOutcome::Consumed` -- nothing to send, nothing
    ///    decoded (a bare keepalive ack, a duplicate, handshake
    ///    progress with no reply due yet); the loop simply continues.
    ///
    /// Returns the datagram's own source address alongside the decrypted
    /// frame (deviation from this method's original task-4 shape, added
    /// in task 5): `tunnel.rs`'s `handle_incoming` still needs to learn/
    /// re-learn a server-mode link's peer address the same way it always
    /// has (a server-side link may start with no configured
    /// `remote_addr` at all, becoming usable only once the client's
    /// first authenticated frame arrives -- see `Link::remote`'s doc
    /// comment), and that's only ever observable from the raw socket
    /// read, not from anything `WgTunnel` itself exposes.
    pub async fn wg_recv(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; u16::MAX as usize + 64];
        let mut frame = Vec::new();
        let from = self.wg_recv_into(&mut buf, &mut frame).await?;
        Ok((frame, from))
    }

    /// Hot-path form of `wg_recv`: the receive loop owns `buf` (raw
    /// datagram scratch, must be at least `u16::MAX + 64` bytes so any
    /// legitimate UDP datagram fits -- the same sizing rule `tunnel.rs`'s
    /// other raw-recv buffers follow) and `frame` (the decrypted mlvpn
    /// frame lands here) once for its whole lifetime, so a received
    /// packet costs no allocation and no 64 KB zero-fill. Returns only
    /// the source address; the frame is in `frame` on `Ok`.
    pub async fn wg_recv_into(&self, buf: &mut [u8], frame: &mut Vec<u8>) -> Result<SocketAddr> {
        loop {
            let socket = self.current_socket().await;
            let (n, from) = socket.recv_from(buf).await.map_err(MlvpnError::Io)?;
            match self.wg.decapsulate_into(&buf[..n], frame)? {
                wireguard::DecapsulateKind::Frame => return Ok(from),
                wireguard::DecapsulateKind::SendReply(reply) => {
                    socket.send_to(&reply, from).await.map_err(MlvpnError::Io)?;
                }
                wireguard::DecapsulateKind::Consumed => {}
            }
        }
    }

    /// Drives this link's own `WgTunnel::tick` (boringtun's internal
    /// handshake-retry/keepalive timers) and sends whatever it produces
    /// to `self.remote`, if anything and if a remote is known yet. Added
    /// in task 5, called once per probe interval from `tunnel::link_prober`
    /// -- see that function's doc comment and this module's own `bind`
    /// doc comment on `is_initiator` for why no separate handshake-retry
    /// loop is needed anywhere else: a link's very first `wg_send`
    /// already triggers the handshake, and this is what keeps retrying
    /// it (or sending keepalives) afterward without any real traffic
    /// having to flow.
    pub async fn wg_tick(&self) -> Result<()> {
        let Some(bytes) = self.wg.tick() else {
            return Ok(());
        };
        let Some(remote) = self.remote else {
            return Ok(());
        };
        let socket = self.current_socket().await;
        socket
            .send_to(&bytes, remote)
            .await
            .map_err(MlvpnError::Io)?;
        Ok(())
    }

    /// Re-create and re-bind this link's UDP socket from scratch (the
    /// same steps `bind_socket` performed at startup) and swap it in
    /// for every task sharing this handle.
    ///
    /// Requires the same privilege the original bind needed --
    /// `CAP_NET_RAW` for `SO_BINDTODEVICE` on Linux -- to still be held
    /// *at the time this is called*, which is only guaranteed under the
    /// "never be root" deployment model (`AmbientCapabilities=` in
    /// `systemd/mlvpn.service`, capabilities held for the process's
    /// entire lifetime). Under the alternative "start as root, drop
    /// after setup" model (`privilege.rs`), every capability is
    /// explicitly cleared right after startup, so a reconnect attempt
    /// under that model will fail with `MlvpnError::CapabilityMissing`
    /// every time, forever -- `tunnel.rs`'s reconnect loop specifically
    /// detects that variant to log an actionable explanation once
    /// rather than repeating a generic error on every retry.
    ///
    /// Serialized against concurrent callers (`link_receiver` and
    /// `link_prober` can each independently notice the same dead socket
    /// at nearly the same time) so at most one rebind is ever in flight
    /// for a given link; a second caller that arrives while one is
    /// already running simply waits for it and then reads whichever
    /// socket it installed, rather than both racing to bind the same
    /// interface/port pair.
    ///
    /// Deliberately does *not* re-resolve `remote_addr`, even if it's a
    /// hostname (see `resolve_remote_addr`) -- reconnect exists for one
    /// specific scenario (this module's doc comment: a *local* interface
    /// fully removed and recreated), which has nothing to do with
    /// whether the *remote* peer's hostname now resolves to a different
    /// address. Conflating the two would mean an unrelated local
    /// USB-modem replug could suddenly change which of a dual-stack
    /// hostname's addresses this link talks to, mid-session, for no
    /// reason connected to the actual event. Reuses whichever address
    /// `Link::bind` originally resolved (snapshotted into `self.remote`
    /// the same way `self.config` already is), so a rebind always keeps
    /// the same family/target it started with.
    pub async fn reconnect(&self) -> Result<()> {
        let _guard = self.reconnect_lock.lock().await;
        // `bind_socket` is a handful of synchronous syscalls (socket
        // creation, SO_BINDTODEVICE, an MTU ioctl, bind()) -- individually
        // fast, but this is called from `link_receiver`/`link_prober`,
        // ordinary async tasks running on the shared tokio runtime, and a
        // link that keeps failing calls this repeatedly. Running it
        // in-line here would tie up a runtime worker thread on every
        // attempt; under a low worker-thread-count runtime (small CPU
        // count) that's enough to delay unrelated tasks -- including,
        // concretely, `control::serve`'s snapshot loop, which is how this
        // was first noticed. `spawn_blocking` runs it on tokio's separate
        // blocking-task thread pool instead, and still has access to this
        // runtime's reactor (`UdpSocket::from_std` needs that), since
        // tokio propagates the current runtime handle into blocking tasks.
        let config = self.config.clone();
        let remote = self.remote;
        let (new_socket, _physical_mtu) =
            tokio::task::spawn_blocking(move || bind_socket(&config, remote))
                .await
                .map_err(|e| MlvpnError::Config(format!("reconnect task panicked: {e}")))??;
        *self.socket.write().await = new_socket;
        Ok(())
    }
}

/// Whether an I/O error from a link's already-bound socket indicates the
/// bound interface itself is gone (removed, unplugged, renamed -- a new
/// kernel ifindex is needed) rather than just transiently unusable
/// (administratively down, a momentary route lookup failure). Only the
/// former justifies `LinkHandle::reconnect`'s privileged from-scratch
/// rebind; conflating the two would mean a link that's merely
/// `ip link set ... down` and back churns through pointless reconnects
/// instead of just self-healing on its existing (still validly bound)
/// socket the instant the route returns -- exactly the "most transient
/// loss needs no help from this at all" case described in this module's
/// doc comment. `ENODEV`/`ENXIO` ("no such device") are what a
/// `SO_BINDTODEVICE`-bound socket's send/receive calls return once the
/// named interface no longer exists; `ENETDOWN`/`ENETUNREACH` and
/// similar are what it returns for an interface that still exists but
/// currently has no usable route, which is exactly the case that
/// self-heals on its own once the interface comes back up.
pub fn is_interface_gone_error(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENODEV) | Some(libc::ENXIO))
}

/// Every bonded link, each independently lockable. Deliberately *not*
/// `Arc<AsyncMutex<Vec<Link>>>` (one lock for the whole collection) --
/// see `tunnel.rs`'s module doc comment for why that used to force every
/// link's `link_receiver` task to serialize against every other link's
/// on every single packet, capping aggregate bonded throughput below
/// what either link could do alone. The outer `Vec` itself needs no
/// lock at all: its length and order are fixed at startup (`run()`
/// builds it once from the config and never resizes it), so any task
/// can freely index or iterate it without synchronization -- only each
/// element's *contents* (state, stats, the learned remote address) ever
/// change at runtime, and each now has its own independent lock for
/// that.
pub type Links = Arc<Vec<AsyncMutex<Link>>>;

/// Read every link's current state by locking each one in turn and
/// cloning it out, releasing that link's lock before moving to the
/// next. Used by every call site that needs to look at (or pick from)
/// *all* links at once -- `Scheduler::select`/`refresh`/`all_down`,
/// building a control-socket `Snapshot`, racing/broadcasting a
/// handshake across every link -- without ever holding one lock across
/// the whole collection, which is exactly the contention this type
/// exists to avoid. Each per-link lock here is only ever held long
/// enough to clone that one entry, so this can never block a
/// `link_receiver` task for longer than a single `Link` clone, and
/// never blocks two different links' tasks against each other at all.
pub async fn snapshot_links(links: &Links) -> Vec<Link> {
    let mut out = Vec::with_capacity(links.len());
    for l in links.iter() {
        out.push(l.lock().await.clone());
    }
    out
}

/// Everything `monitor::score()` and `Scheduler::select`'s cap-check/
/// fallback logic need to pick a link for one outgoing packet --
/// deliberately excludes `LinkConfig`'s `String` fields (`name`,
/// `bind_interface`, `local_addr`, `remote_addr`), `remote`, and the
/// socket handle, every one of which `snapshot_links` above *does*
/// clone. That distinction matters here specifically because
/// `tunnel::pick_link` calls this once per outgoing packet (not at
/// probe-interval frequency the way `Scheduler::refresh`'s callers do):
/// a real 200 Mbps / ~19k pps UDP test showed a hard, dead-flat ~65%
/// loss ceiling traced to exactly this -- `snapshot_links` cloning every
/// link's full `Link` (including heap-allocating every `LinkConfig`
/// `String`) just to let the scheduler pick one and then throw the rest
/// away, on every single packet. Every field here is `Copy`, so
/// building this `Vec` allocates nothing beyond the `Vec` itself.
#[derive(Debug, Clone, Copy)]
pub struct LinkScore {
    /// Index into the original `Links` slice this entry came from --
    /// what `Scheduler::select` actually returns, so the caller can go
    /// look up (and lock, just once, just for this one link) whatever
    /// full `Link` data it needs next (remote address, socket handle,
    /// name for logging).
    pub link_index: usize,
    pub state: LinkState,
    pub admin_disabled: bool,
    pub weight: f64,
    pub bandwidth_cap_mbps: Option<f64>,
    pub rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_rate: Option<f64>,
    pub rx_throughput_mbps: Option<f64>,
    pub active_bandwidth_mbps: Option<f64>,
    pub consecutive_misses: u32,
}

/// Cheap, per-packet-safe counterpart to `snapshot_links`: locks each
/// link only long enough to copy out the handful of `Copy` fields
/// scheduling actually needs, never cloning `LinkConfig`'s `String`
/// fields or anything requiring a heap allocation. See `LinkScore`'s
/// doc comment for why this exists as a separate function rather than
/// just a cheaper `Link::clone`.
pub async fn snapshot_scores(links: &Links) -> Vec<LinkScore> {
    let mut out = Vec::with_capacity(links.len());
    for (i, l) in links.iter().enumerate() {
        let guard = l.lock().await;
        out.push(LinkScore {
            link_index: i,
            state: guard.state,
            admin_disabled: guard.admin_disabled,
            weight: guard.config.weight,
            bandwidth_cap_mbps: guard.config.bandwidth_cap_mbps,
            rtt_ms: guard.stats.rtt_ms.get(),
            jitter_ms: guard.stats.jitter_ms.get(),
            loss_rate: guard.stats.loss_rate.get(),
            rx_throughput_mbps: guard.stats.rx_throughput_mbps.get(),
            active_bandwidth_mbps: guard.stats.active_bandwidth_mbps.get(),
            consecutive_misses: guard.stats.consecutive_misses,
        });
    }
    out
}

#[derive(Clone)]
pub struct Link {
    pub id: u8,
    pub config: LinkConfig,
    socket: SharedSocket,
    reconnect_lock: Arc<AsyncMutex<()>>,
    pub remote: Option<SocketAddr>,
    pub state: LinkState,
    /// When `state` last changed, per `monitor::update_link_state` --
    /// the single call site for every transition. Reset to
    /// `Instant::now()` at bind time too, so a link that's never
    /// transitioned still reports a sane (if slightly early) duration
    /// rather than a stale zero/garbage value.
    pub state_since: Instant,
    pub stats: LinkStats,
    /// The `bind_interface`'s actual kernel-reported MTU at bind time
    /// (via `SIOCGIFMTU`), if we could determine it. `None` on non-Linux
    /// targets, or if the ioctl failed for any reason (missing
    /// permissions, interface renamed/removed between config load and
    /// bind, etc.) -- this is a best-effort input to MTU auto-tuning
    /// (see `main.rs`'s `effective_tunnel_mtu()`), never a hard
    /// requirement for the link to come up. Only ever set from the
    /// initial startup bind, deliberately not refreshed by a later
    /// `LinkHandle::reconnect` -- see `main.rs::effective_tunnel_mtu`'s
    /// doc comment for why the tunnel MTU is a one-shot startup decision
    /// rather than something a runtime reconnect should retroactively
    /// change.
    pub physical_mtu: Option<u32>,
    /// Operator-pinned override that forces this link out of scheduling
    /// regardless of its real, probe-measured `state` -- set via a
    /// `Command::SetLinkEnabled { enabled: false, .. }` on the command
    /// socket (see `control.rs::serve_commands`). Deliberately a
    /// separate field rather than a `LinkState` variant: `state` should
    /// keep reflecting genuine link quality even while an operator has
    /// manually pinned traffic off it, so `mlvpn-tui`/`Snapshot` still
    /// show whether the underlying path is actually healthy. Not
    /// persisted -- always starts `false` at process startup, so a
    /// restart clears any earlier manual pin rather than silently
    /// keeping a link disabled with no visible reason.
    pub admin_disabled: bool,
    /// The probe interval actually in effect right now, in milliseconds.
    /// Starts equal to `config.probe_interval_ms` and never goes below
    /// it -- that configured value is the floor, not just a starting
    /// point. Only ever changes at runtime when
    /// `scheduler.auto_tune_probe_interval` is on
    /// (`tunnel::link_prober`/`tunnel::suggest_probe_interval_ms`); left
    /// alone otherwise, so this is always simply equal to
    /// `config.probe_interval_ms` when that feature is off.
    pub effective_probe_interval_ms: u64,
    /// The EWMA smoothing factor actually in effect right now, mirrored
    /// here (in addition to living inside each `Ewma` in `stats`) purely
    /// so `tunnel::suggest_ewma_alpha` has something cheap to read the
    /// current value from without digging into `stats.rtt_ms`
    /// specifically. Starts equal to `scheduler.ewma_alpha` and only
    /// ever changes at runtime when `scheduler.auto_tune_ewma_alpha` is
    /// on -- see `LinkStats::set_alpha`.
    pub effective_ewma_alpha: f64,
    /// A not-yet-confirmed alternate-family candidate for this link's
    /// `remote_addr`, together with its own already-bound socket -- set
    /// at `Link::bind` time only when resolution produced both an IPv4
    /// and IPv6 candidate and `local_addr` didn't pin one (see
    /// `pick_remote_addr`'s doc comment). Raced against `remote`/`socket`
    /// once at tunnel startup (`Link::resolve_alternate`, called from
    /// `tunnel::run`) -- deliberately never re-raced later: per-link
    /// tasks snapshot `remote` in their `LinkHandle` at spawn time and
    /// wouldn't observe a flip. Always `None` again once that race has
    /// resolved, win or lose -- see `commit_remote`.
    pub alternate: Option<(SocketAddr, SharedSocket)>,
    /// This link's own independent WireGuard tunnel, constructed once at
    /// `Link::bind` time from `config.private_key_file`/
    /// `config.peer_public_key` and never replaced afterward -- a
    /// `LinkHandle::reconnect` rebinds the socket only, deliberately
    /// leaving an already-established WireGuard session (and its replay
    /// window/rekey state) untouched, the same way `physical_mtu` and
    /// `state_since` are one-shot startup state rather than something a
    /// reconnect refreshes. `Arc`-wrapped so `handle()`/`alternate_handle()`
    /// can hand every per-link task a shared reference to the same
    /// tunnel instead of a separate one per socket.
    wg: Arc<WgTunnel>,
}

impl Link {
    /// Create the UDP socket for a link, binding it to the configured
    /// local interface/port. This must run before privileges are dropped
    /// if `bind_interface` requires `CAP_NET_RAW`/root on the target
    /// system (SO_BINDTODEVICE itself only needs `CAP_NET_RAW` on Linux,
    /// which `privilege::drop_to` retains explicitly for this reason).
    ///
    /// When `remote_addr` resolved to both an IPv4 and IPv6 candidate
    /// (see `pick_remote_addr`), this also binds a *second* socket for
    /// the alternate family up front -- see `alternate`'s doc comment
    /// for why it exists and when it gets raced/dropped. Both sockets
    /// share the same `bind_interface`/`local_port`, which is fine: one
    /// is `AF_INET`, the other `AF_INET6` (`IPV6_V6ONLY` set, see
    /// `bind_socket`), so there's no actual port conflict at the kernel
    /// level, the same way an ordinary dual-stack service binds both
    /// families to one port today.
    ///
    /// `is_initiator` says whether this link should drive the WireGuard
    /// handshake as the connecting side (`Mode::Client`) or wait to
    /// respond (`Mode::Server`) -- passed in by the caller (`main.rs`,
    /// from `Config.mode`) rather than inferred here, since `LinkConfig`
    /// alone carries no client/server distinction of its own. Purely
    /// advisory: `WgTunnel::new` accepts it for call-site clarity, but
    /// `boringtun` itself doesn't actually need to know which side
    /// initiates at construction time (see that function's own doc
    /// comment) -- whichever side's `encapsulate`/`wg_send` is called
    /// first is the one that in practice emits the handshake init.
    pub async fn bind(
        id: u8,
        config: LinkConfig,
        ewma_alpha: f64,
        is_initiator: bool,
    ) -> Result<Self> {
        let (remote, alternate_remote) = resolve_remote_addr(&config).await?;
        let (socket, physical_mtu) = bind_socket(&config, remote)?;
        let alternate = match alternate_remote {
            Some(alt_remote) => {
                let (alt_socket, _) = bind_socket(&config, Some(alt_remote))?;
                Some((alt_remote, Arc::new(AsyncRwLock::new(alt_socket))))
            }
            None => None,
        };
        let local_private = crypto::StaticKeypair::load_private(&config.private_key_file)?.0;
        let peer_public = crypto::decode_public_key(&config.peer_public_key)?;
        let wg = Arc::new(WgTunnel::new(local_private, peer_public, is_initiator)?);

        let effective_probe_interval_ms = config.probe_interval_ms;

        Ok(Self {
            id,
            config,
            socket: Arc::new(AsyncRwLock::new(socket)),
            reconnect_lock: Arc::new(AsyncMutex::new(())),
            remote,
            state: LinkState::Probing,
            state_since: Instant::now(),
            stats: LinkStats::new(ewma_alpha),
            physical_mtu,
            admin_disabled: false,
            effective_probe_interval_ms,
            effective_ewma_alpha: ewma_alpha,
            alternate,
            wg,
        })
    }

    /// This link's own lifetime count of datagrams its `WgTunnel`
    /// rejected outright -- see `WgTunnel::rejected_count`'s doc comment.
    pub fn wg_rejected_count(&self) -> u64 {
        self.wg.rejected_count()
    }

    /// This link's own lifetime count of `encapsulate` calls whose real
    /// plaintext was silently substituted with a handshake datagram --
    /// see `WgTunnel::substituted_count`'s doc comment.
    pub fn wg_substituted_count(&self) -> u64 {
        self.wg.substituted_count()
    }

    /// Milliseconds since this link's WireGuard session was established,
    /// `None` before the first handshake -- see
    /// `WgTunnel::last_handshake_age`.
    pub fn wg_handshake_age_ms(&self) -> Option<u64> {
        self.wg.last_handshake_age().map(|d| d.as_millis() as u64)
    }

    /// Bundle this link's shareable state for its per-link tasks
    /// (`link_receiver`, `link_prober` in `tunnel.rs`). See
    /// `LinkHandle`'s doc comment for why tasks capture this once
    /// instead of re-reading `Link` itself.
    pub fn handle(&self) -> LinkHandle {
        LinkHandle {
            link_id: self.id,
            config: self.config.clone(),
            remote: self.remote,
            socket: self.socket.clone(),
            reconnect_lock: self.reconnect_lock.clone(),
            wg: self.wg.clone(),
        }
    }

    /// A synthetic `LinkHandle` wrapping `alternate`'s not-yet-confirmed
    /// socket/address, for `tunnel::perform_client_handshake` to race
    /// alongside the real one from `handle()` above -- `None` once
    /// there's no alternate left to race (never had one, or already
    /// resolved via `commit_remote`). `reconnect_lock` is a fresh,
    /// never-shared lock: `reconnect()` is never called against this
    /// handle (there's nothing worth reconnecting *to* until this
    /// candidate has actually won a race and been committed), so it
    /// doesn't need to coordinate with the real link's own lock.
    pub fn alternate_handle(&self) -> Option<LinkHandle> {
        let (remote, socket) = self.alternate.as_ref()?;
        Some(LinkHandle {
            link_id: self.id,
            config: self.config.clone(),
            remote: Some(*remote),
            socket: socket.clone(),
            reconnect_lock: Arc::new(AsyncMutex::new(())),
            // Same underlying WireGuard session as `handle()` above --
            // the alternate is only a not-yet-confirmed *address*/socket
            // for this same link, not a second independent tunnel/peer.
            wg: self.wg.clone(),
        })
    }

    /// Races this link's real WireGuard handshake initiation against its
    /// primary and alternate address at once and commits whichever
    /// answers first (`commit_remote`); a no-op for a link with no
    /// alternate. The same init datagram goes to both addresses, so the
    /// peer accepts exactly one copy (the other is a replay to it) and
    /// the winning socket completes the handshake -- the link comes up
    /// already established on the working family. WireGuard state is
    /// address-independent, so the handshake carries over to the per-link
    /// tasks spawned afterward. If nothing answers within `deadline` the
    /// primary is kept and the normal lazy handshake retries take over.
    ///
    /// Must run before any per-link task takes a `handle()`: those
    /// snapshot `remote` and would never see it change.
    pub async fn resolve_alternate(&mut self, deadline: Duration) {
        let Some((alt_remote, alt_shared)) = self.alternate.clone() else {
            return;
        };
        let Some(primary_remote) = self.remote else {
            self.commit_remote(None);
            return;
        };
        let primary_socket = self.socket.read().await.clone();
        let alt_socket = alt_shared.read().await.clone();

        let mut frame = Vec::with_capacity(crate::protocol::HEADER_LEN);
        crate::protocol::Header {
            ptype: crate::protocol::PacketType::Keepalive,
            link_id: self.id,
            seq: 0,
        }
        .encode(&mut frame);
        let init = match self.wg.encapsulate(&frame) {
            Ok((datagram, _)) => datagram,
            Err(e) => {
                tracing::warn!(link = %self.config.name, error = %e, "could not start the address-family race; keeping the primary address");
                self.commit_remote(None);
                return;
            }
        };

        let mut primary_buf = vec![0u8; u16::MAX as usize + 64];
        let mut alt_buf = vec![0u8; u16::MAX as usize + 64];
        let mut scratch = Vec::with_capacity(2048);
        let mut retry = tokio::time::interval(Duration::from_millis(500));
        let mut first = true;
        let give_up = tokio::time::sleep(deadline);
        tokio::pin!(give_up);

        let winner = loop {
            tokio::select! {
                _ = retry.tick() => {
                    let datagram = if first {
                        first = false;
                        Some(init.clone())
                    } else {
                        self.wg.tick()
                    };
                    if let Some(d) = datagram {
                        let _ = primary_socket.send_to(&d, primary_remote).await;
                        let _ = alt_socket.send_to(&d, alt_remote).await;
                    }
                }
                r = primary_socket.recv_from(&mut primary_buf) => {
                    if let Ok((n, from)) = r {
                        if from == primary_remote
                            && self.answered(&primary_socket, &primary_buf[..n], from, &mut scratch).await
                        {
                            break Some(primary_remote);
                        }
                    }
                }
                r = alt_socket.recv_from(&mut alt_buf) => {
                    if let Ok((n, from)) = r {
                        if from == alt_remote
                            && self.answered(&alt_socket, &alt_buf[..n], from, &mut scratch).await
                        {
                            break Some(alt_remote);
                        }
                    }
                }
                _ = &mut give_up => break None,
            }
        };

        if winner.is_none() {
            tracing::warn!(
                link = %self.config.name,
                primary = %primary_remote,
                alternate = %alt_remote,
                "neither address family answered in time; keeping the primary and retrying normally"
            );
        }
        self.commit_remote(winner);
    }

    /// Feeds one received datagram through this link's `WgTunnel` and
    /// reports whether it was an authenticated answer (handshake
    /// response or data), sending any reply boringtun produced.
    async fn answered(
        &self,
        socket: &UdpSocket,
        datagram: &[u8],
        from: SocketAddr,
        scratch: &mut Vec<u8>,
    ) -> bool {
        match self.wg.decapsulate_into(datagram, scratch) {
            Ok(wireguard::DecapsulateKind::SendReply(reply)) => {
                let _ = socket.send_to(&reply, from).await;
                true
            }
            Ok(wireguard::DecapsulateKind::Frame) => true,
            Ok(wireguard::DecapsulateKind::Consumed) | Err(_) => false,
        }
    }

    /// Resolves `alternate` once the primary-vs-alternate question has
    /// been answered by `resolve_alternate` (or abandoned). Runs exactly
    /// once per link, before any `link_receiver`/`link_prober` task
    /// exists to hold a stale copy of the pre-resolution socket.
    ///
    /// `winner`, if `Some`, is the address that actually answered.  If it
    /// matches `alternate`'s address, that candidate just proved itself
    /// reachable where the original `remote`/`socket` apparently wasn't --
    /// promote it: swap it into `remote`/`socket` so every per-link task
    /// spawned after this point (`link_receiver`, `link_prober`,
    /// `active_bandwidth_prober` -- all spawned later in `tunnel::run`,
    /// using `handle()`/this same `Link`) uses the address that's
    /// actually known to work. Otherwise (the primary won, a *different*
    /// link entirely answered, or nothing answered at all), the
    /// alternate is simply dropped, closing its socket.
    pub fn commit_remote(&mut self, winner: Option<SocketAddr>) {
        let Some((alt_remote, alt_socket)) = self.alternate.take() else {
            return;
        };
        if winner == Some(alt_remote) {
            tracing::info!(
                link = %self.config.name,
                previous = ?self.remote,
                winner = %alt_remote,
                "alternate address family confirmed reachable; switching this link to it"
            );
            self.remote = Some(alt_remote);
            self.socket = alt_socket;
        }
    }
}

/// How long `resolve_remote_addr` waits for `remote_addr` to resolve
/// before giving up. DNS lookups have no built-in timeout of their own,
/// and `Link::bind` runs at startup, before the "retry indefinitely in
/// the background" handshake logic (`tunnel::establish_session_with_retry`)
/// even begins -- an unreachable resolver would otherwise hang the whole
/// daemon at startup forever instead of failing fast with a clear error,
/// exactly the kind of silent hang this project's existing startup
/// behavior (see `main.rs`) deliberately avoids elsewhere.
const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Pick the concrete `SocketAddr`(es) to use as a client-mode link's
/// `remote`, given every address `remote_addr` resolved to. Returns
/// `(primary, alternate)`: `primary` is what `Link::bind` immediately
/// binds a socket to and uses, exactly as before; `alternate`, when
/// `Some`, is a second, not-yet-confirmed candidate from the *other*
/// address family, raced alongside `primary` during the very first
/// handshake attempt only (see `Link::alternate`'s and
/// `tunnel::perform_client_handshake`'s doc comments for why "only the
/// first attempt" and not every rekey). Split out of `resolve_remote_addr`
/// as pure, I/O-free selection logic specifically so it's unit-testable
/// with hand-built address lists, without a real DNS lookup (a hostname
/// actually returning both an `A` and `AAAA` record isn't something a
/// unit test should depend on a real resolver for) -- see `monitor.rs`'s
/// module doc comment for this project's general preference for keeping
/// decision logic separate from the I/O that feeds it.
///
/// If `local_addr` is set, it already declares this link's intended
/// family (see its own doc comment on `LinkConfig`) -- honor that
/// unconditionally (no alternate to race: an operator who pinned a
/// family explicitly gets exactly that family, full stop) and error
/// clearly if no resolved address matches, rather than silently binding
/// the wrong family. Otherwise `primary` prefers an IPv6 result if one
/// exists, falling back to IPv4, with the other family (if resolved)
/// returned as `alternate` -- a real, if deliberately narrow (at most
/// one candidate per family, and only for the very first handshake),
/// two-way happy-eyeballs-style race rather than RFC 8305's full
/// N-candidate concurrent racing, which this project doesn't need: each
/// link is already pinned to one physical interface via
/// `bind_interface`, so there's only ever one dual-stack ambiguity to
/// resolve, not several outbound paths to choose among. This exists
/// because a hostname's `AAAA` record existing is not the same thing as
/// that IPv6 address actually being reachable end-to-end -- routing
/// gaps and silent blackholes on the IPv6 path are common enough on
/// residential/consumer ISPs that blindly committing to "IPv6 if
/// present" with no fallback used to mean a dual-stack hostname could
/// wedge the client's initial handshake forever even though the exact
/// same peer was perfectly reachable over IPv4.
fn pick_remote_addr(
    candidates: &[SocketAddr],
    local_addr: Option<&str>,
    link_name: &str,
) -> Result<(SocketAddr, Option<SocketAddr>)> {
    if let Some(local) = local_addr {
        let want_v6 = local
            .parse::<IpAddr>()
            .map_err(|e| MlvpnError::Config(format!("bad local_addr for link '{link_name}': {e}")))?
            .is_ipv6();
        return candidates
            .iter()
            .find(|a| a.is_ipv6() == want_v6)
            .copied()
            .map(|primary| (primary, None))
            .ok_or_else(|| {
                MlvpnError::Config(format!(
                    "remote_addr for link '{link_name}' resolved to no {} address, but \
                     local_addr requires one",
                    if want_v6 { "IPv6" } else { "IPv4" }
                ))
            });
    }
    let v6 = candidates.iter().find(|a| a.is_ipv6()).copied();
    let v4 = candidates.iter().find(|a| !a.is_ipv6()).copied();
    match (v6, v4) {
        (Some(primary), alternate @ Some(_)) => Ok((primary, alternate)),
        (Some(primary), None) => Ok((primary, None)),
        (None, Some(primary)) => Ok((primary, None)),
        (None, None) => Err(MlvpnError::Config(format!(
            "remote_addr for link '{link_name}' resolved to no addresses"
        ))),
    }
}

/// Resolve `config.remote_addr` (client mode) to concrete `SocketAddr`(es)
/// via `tokio::net::lookup_host` -- accepts everything `remote_addr`
/// always has (a literal `ip:port`, resolved instantly with no real
/// network round trip) plus, now, a `hostname:port` needing an actual DNS
/// lookup, e.g. `"bgp.example.com:5000"`. Returns `(None, None)` if
/// `remote_addr` isn't set at all -- the normal server-mode case, where
/// the peer's address is only ever learned at runtime instead (see
/// `tunnel.rs`'s "learned/updated peer address" handling).
///
/// A hostname commonly resolves to *both* an `A` and an `AAAA` record
/// (ordinary dual-stack DNS, e.g. most cloud providers' own hostnames) --
/// see `pick_remote_addr` for how that produces this function's
/// `(primary, alternate)` pair from that.
async fn resolve_remote_addr(
    config: &LinkConfig,
) -> Result<(Option<SocketAddr>, Option<SocketAddr>)> {
    let Some(remote_addr) = &config.remote_addr else {
        return Ok((None, None));
    };
    let candidates: Vec<SocketAddr> =
        tokio::time::timeout(DNS_RESOLVE_TIMEOUT, tokio::net::lookup_host(remote_addr.as_str()))
            .await
            .map_err(|_| {
                MlvpnError::Config(format!(
                    "resolving remote_addr '{remote_addr}' for link '{}' timed out after {DNS_RESOLVE_TIMEOUT:?}",
                    config.name
                ))
            })?
            .map_err(|e| {
                MlvpnError::Config(format!(
                    "resolving remote_addr '{remote_addr}' for link '{}': {e}",
                    config.name
                ))
            })?
            .collect();
    let (primary, alternate) =
        pick_remote_addr(&candidates, config.local_addr.as_deref(), &config.name)?;
    Ok((Some(primary), alternate))
}

/// Decide whether a link's socket should be IPv4 or IPv6, from whichever
/// of `remote`/`local_addr` actually says -- there's no separate
/// `address_family` config knob; the address(es) already given say it
/// implicitly, the same way they always have, so an existing IPv4-only
/// config needs no changes to keep behaving exactly as before.
///
/// `remote` -- already resolved by `resolve_remote_addr`, not a string to
/// parse here -- is checked first: every client-side link has one, and
/// for a server-side link it still wins if somehow both are set, since
/// it's the address this socket will actually be talking to. Falls back
/// to `local_addr` (a bare IP, no port) for a server-side link with no
/// `remote_addr` -- the peer's address there is only *learned* at
/// runtime from the first authenticated packet (see this module's doc
/// comment), so there is nothing else to infer the family from until an
/// operator wanting an IPv6-only server-side link sets `local_addr` to
/// an IPv6 address (`"::"` for "any"). Defaults to IPv4 if neither is
/// set, matching every config written before this existed.
fn socket_domain(config: &LinkConfig, remote: Option<SocketAddr>) -> Result<Domain> {
    if let Some(remote) = remote {
        return Ok(if remote.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        });
    }
    if let Some(local) = &config.local_addr {
        let ip: IpAddr = local.parse().map_err(|e| {
            MlvpnError::Config(format!("bad local_addr for link '{}': {e}", config.name))
        })?;
        return Ok(if ip.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        });
    }
    Ok(Domain::IPV4)
}

/// Requested `SO_RCVBUF`/`SO_SNDBUF` size, in bytes, for every link
/// socket -- see `raise_socket_buffers`. 8 MiB comfortably covers the
/// bandwidth-delay product of a multi-gigabit link across most
/// real-world WAN latencies (e.g. 1 Gbps x 50ms round trip is only
/// ~6.25MB), without being large enough to meaningfully increase
/// bufferbloat-style latency under sustained loss.
const SOCKET_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// Best-effort: raise this socket's kernel receive/send buffers well
/// past the stock Linux default (`net.core.rmem_default`/
/// `wmem_default`, typically ~208KB). At that size, a link's receive
/// queue overflows the moment its bandwidth-delay product exceeds it --
/// a 1 Gbps link at just 20ms RTT already needs roughly 2.5MB of room
/// in flight -- and the kernel's response to overflow is to silently
/// drop the incoming datagram before `mlvpnd` ever sees it, which looks
/// exactly like ordinary network loss from inside the process. This is
/// the single most common reason a bonded link's real throughput comes
/// in far below its configured/expected speed despite every other stat
/// (RTT, jitter) looking healthy, and specifically explains an
/// asymmetric symptom -- one direction capped, the other fine -- since
/// the two directions' bottleneck is on two different machines' receive
/// paths. See `docs/performance-tuning.md`.
///
/// Tries `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE` first (Linux only, needs
/// `CAP_NET_ADMIN`): unlike plain `SO_RCVBUF`/`SO_SNDBUF`, the "FORCE"
/// variants bypass the `net.core.rmem_max`/`wmem_max` ceiling entirely
/// instead of silently being clamped to it. `Link::bind`'s initial call
/// runs during the privileged setup phase (before
/// `privilege::drop_privileges`), so this is exactly the one point in
/// the process's life where that's guaranteed to work regardless of
/// deployment model; falls back to the plain, ceiling-respecting
/// setsockopt if the forced one fails (notably, `LinkHandle::reconnect`
/// calls this same function again later, potentially after privileges
/// have been dropped under the "start as root, drop after setup" model
/// -- same caveat as `LinkHandle::reconnect`'s own doc comment). Either
/// way this never fails link setup: a socket stuck with the OS default
/// still works, just cannot sustain as much throughput. The actual
/// negotiated size is read back and logged so operators can tell
/// whether they need to raise the sysctl ceiling by hand instead.
fn raise_socket_buffers(socket: &Socket, link_name: &str) {
    #[cfg(target_os = "linux")]
    {
        let size = SOCKET_BUFFER_BYTES as libc::c_int;
        let size_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `socket.as_raw_fd()` is a valid, open socket for the
        // duration of this call; `size` is a valid, initialized
        // `c_int` whose address and length are passed correctly.
        // SO_RCVBUFFORCE/SO_SNDBUFFORCE simply fail (EPERM) without
        // CAP_NET_ADMIN, handled below by falling back to the plain
        // setsockopt -- never a memory-safety concern either way.
        let rcv_forced = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                std::ptr::addr_of!(size).cast(),
                size_len,
            )
        } == 0;
        let snd_forced = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUFFORCE,
                std::ptr::addr_of!(size).cast(),
                size_len,
            )
        } == 0;
        if !rcv_forced {
            let _ = socket.set_recv_buffer_size(SOCKET_BUFFER_BYTES);
        }
        if !snd_forced {
            let _ = socket.set_send_buffer_size(SOCKET_BUFFER_BYTES);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket.set_recv_buffer_size(SOCKET_BUFFER_BYTES);
        let _ = socket.set_send_buffer_size(SOCKET_BUFFER_BYTES);
    }

    // The kernel typically reports back roughly double whatever value
    // it actually accepted (bookkeeping overhead reserve is counted
    // against the same figure), so a healthy result here reads back
    // near or above `2 * SOCKET_BUFFER_BYTES`, not exactly it -- a
    // reading well *below* the requested size is the signal that both
    // the FORCE attempt and the sysctl ceiling lost.
    let actual_recv = socket.recv_buffer_size().ok();
    let actual_send = socket.send_buffer_size().ok();
    tracing::debug!(
        link = %link_name,
        requested_bytes = SOCKET_BUFFER_BYTES,
        actual_recv_bytes = ?actual_recv,
        actual_send_bytes = ?actual_send,
        "link socket buffer sizes negotiated"
    );
    if actual_recv.is_some_and(|n| n < SOCKET_BUFFER_BYTES) {
        tracing::info!(
            link = %link_name,
            actual_recv_bytes = ?actual_recv,
            requested_bytes = SOCKET_BUFFER_BYTES,
            "kernel receive buffer for this link came back smaller than requested; \
             a fast link may see throughput capped well below its real capacity. \
             Raise net.core.rmem_max (see docs/performance-tuning.md) if so."
        );
    }
}

/// Create and bind one link's UDP socket: `SO_BINDTODEVICE` to
/// `config.bind_interface` (Linux only), optionally to a specific
/// `local_addr`, then `bind()` to `local_port`. Shared by `Link::bind`
/// (startup) and `LinkHandle::reconnect` (runtime rebind after the
/// existing socket appears permanently dead) so both paths apply exactly
/// the same steps and error handling. `remote` is the already-resolved
/// address `resolve_remote_addr` produced (or `None`), passed in rather
/// than resolved here -- this function stays a plain synchronous one
/// (safe to run inside `spawn_blocking`), while DNS resolution is async
/// and, for a hostname, needs a real `.await`.
fn bind_socket(
    config: &LinkConfig,
    remote: Option<SocketAddr>,
) -> Result<(Arc<UdpSocket>, Option<u32>)> {
    let domain = socket_domain(config, remote)?;
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(MlvpnError::Io)?;
    socket.set_nonblocking(true).map_err(MlvpnError::Io)?;
    socket.set_reuse_address(true).map_err(MlvpnError::Io)?;
    if domain == Domain::IPV6 {
        // Without this, an IPv6 socket on Linux defaults to dual-stack
        // (IPV6_V6ONLY=0), which would let it silently also accept
        // IPv4-mapped traffic -- surprising for a link the operator
        // configured as IPv6, and a real conflict risk if another
        // `[[links]]` entry binds the same port on the IPv4 domain
        // instead (two separate sockets, `SO_REUSEADDR` set on both,
        // would otherwise race for the same IPv4 traffic on that port).
        // Keeping each link's socket strictly single-family makes "one
        // link, one address family" an invariant enforced by the
        // kernel, not just a convention.
        socket.set_only_v6(true).map_err(MlvpnError::Io)?;
    }

    #[cfg(target_os = "linux")]
    {
        socket
            .bind_device(Some(config.bind_interface.as_bytes()))
            .map_err(|e| {
                // ENODEV specifically means the named interface doesn't
                // exist on this system right now (typo in config, a
                // hot-pluggable interface like wwan0 that hasn't come up
                // yet, or -- for a reconnect attempt -- one that's been
                // unplugged and not yet replugged) -- worth its own
                // error variant so operators get a precise diagnosis
                // instead of a generic one.
                if e.raw_os_error() == Some(libc::ENODEV) {
                    MlvpnError::InterfaceNotFound(config.bind_interface.clone())
                } else if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
                    // Distinct from the generic Config error below:
                    // this specifically means the calling process no
                    // longer holds CAP_NET_RAW. At startup that's
                    // just a misconfigured deployment; from a runtime
                    // `LinkHandle::reconnect` call it specifically
                    // means privileges were already dropped under the
                    // "start as root, drop after setup" model (see
                    // privilege.rs) -- tunnel.rs's reconnect loop
                    // matches on this variant to explain that
                    // distinction instead of retrying with a generic
                    // complaint forever.
                    MlvpnError::CapabilityMissing(format!(
                        "binding link '{}' to interface '{}': permission denied ({e}); \
                         CAP_NET_RAW is required for SO_BINDTODEVICE",
                        config.name, config.bind_interface
                    ))
                } else {
                    MlvpnError::Config(format!(
                        "binding link '{}' to interface '{}': {e} (are we running with CAP_NET_RAW?)",
                        config.name, config.bind_interface
                    ))
                }
            })?;
    }

    // See `raise_socket_buffers`'s doc comment: the Linux default socket
    // buffer (~208KB) silently caps real-world throughput on any link
    // fast enough to have a meaningful bandwidth-delay product, well
    // before anything in this process would notice -- the kernel just
    // drops incoming datagrams that don't fit, indistinguishable from
    // ordinary network loss. Never blocks link setup on failure.
    raise_socket_buffers(&socket, &config.name);

    // Best-effort: feeds MTU auto-tuning (main.rs's
    // effective_tunnel_mtu()) at startup only, never blocks link setup
    // on failure. See `Link::physical_mtu`'s doc comment for why a
    // reconnect doesn't feed a fresh reading back into that decision.
    let physical_mtu = query_interface_mtu(&config.bind_interface);

    // Parsed as a bare `IpAddr`, not built by string-formatting
    // `"{bind_ip}:{port}"` the way this used to work: that approach
    // breaks for IPv6, whose string form needs bracket-wrapping
    // (`[::1]:1234`) before it's a parseable `SocketAddr`, and it's
    // simpler to just construct the pieces directly than to reproduce
    // that quoting rule by hand.
    let unspecified_addr = match domain {
        Domain::IPV6 => "::",
        _ => "0.0.0.0",
    };
    let bind_ip: IpAddr = config
        .local_addr
        .clone()
        .unwrap_or_else(|| unspecified_addr.to_string())
        .parse()
        .map_err(|e| {
            MlvpnError::Config(format!("bad local_addr for link '{}': {e}", config.name))
        })?;
    let bind_addr = SocketAddr::new(bind_ip, config.local_port);
    socket.bind(&bind_addr.into()).map_err(MlvpnError::Io)?;

    let std_socket: StdUdpSocket = socket.into();
    let tokio_socket = UdpSocket::from_std(std_socket).map_err(MlvpnError::Io)?;

    Ok((Arc::new(tokio_socket), physical_mtu))
}

/// Query a network interface's current kernel-reported MTU via the
/// `SIOCGIFMTU` ioctl. `None` on any failure (unknown/renamed interface,
/// insufficient permissions, or simply "not Linux") -- this is an
/// optimization input, not a correctness requirement, so callers must
/// always have a sane fallback rather than treating `None` as fatal.
#[cfg(target_os = "linux")]
pub(crate) fn query_interface_mtu(ifname: &str) -> Option<u32> {
    // Any datagram socket works as the ioctl handle -- it's never bound,
    // connected, or used for actual I/O, just as a file descriptor the
    // kernel will accept SIOCGIFMTU on. AF_INET is used here purely by
    // convention (this ioctl is address-family-agnostic; it queries the
    // interface's link-level MTU, not anything IPv4-specific).
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = ifname.as_bytes();
    // ifr_name is a fixed IFNAMSIZ(16)-byte buffer that must stay
    // NUL-terminated (guaranteed here by the zeroed() above, since we
    // only fill in name_bytes.len() < ifr.ifr_name.len() bytes and leave
    // the rest zero). Reject anything that wouldn't leave room for that
    // terminator rather than silently truncating into a different,
    // valid-looking interface name.
    if name_bytes.len() >= ifr.ifr_name.len() {
        return None;
    }
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name_bytes.iter()) {
        *dst = *src as libc::c_char;
    }

    // SAFETY: `ifr` is a valid, zero-initialized `ifreq` with `ifr_name`
    // populated above and within bounds; SIOCGIFMTU reads only
    // `ifr_name` and writes only the `ifru_mtu` member of the
    // `ifr_ifru` union on success (see netdevice(7)), both inside the
    // struct's allocation. `sock`'s file descriptor is valid for the
    // duration of this call (it isn't dropped until this function
    // returns).
    let ret = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU, &mut ifr) };
    if ret != 0 {
        return None;
    }
    // SAFETY: a successful SIOCGIFMTU call specifically populates the
    // `ifru_mtu` union member (a plain `c_int`), per netdevice(7).
    let mtu = unsafe { ifr.ifr_ifru.ifru_mtu };
    u32::try_from(mtu).ok()
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn query_interface_mtu(_ifname: &str) -> Option<u32> {
    None
}

/// Sets a network interface's kernel-reported MTU via the `SIOCSIFMTU`
/// ioctl -- the write-side counterpart to `query_interface_mtu` above,
/// used by `control::mtu_monitor_loop` to resize the running TUN device
/// live, without a restart. Bypasses `tun_rs` entirely: its `AsyncDevice`
/// (the type this codebase actually holds) has no public accessor to
/// the underlying platform `Device` that owns `set_mtu` -- that
/// accessor is `pub(crate)` inside the `tun_rs` crate itself (confirmed
/// by reading its source during design), so a direct ioctl on the
/// interface name is the only option from outside that crate.
#[cfg(target_os = "linux")]
pub fn set_interface_mtu(ifname: &str, mtu: u16) -> std::io::Result<()> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = ifname.as_bytes();
    if name_bytes.len() >= ifr.ifr_name.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name_bytes.iter()) {
        *dst = *src as libc::c_char;
    }
    ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;

    // SAFETY: `ifr` is a valid, zero-initialized `ifreq` with `ifr_name`
    // and `ifr_ifru.ifru_mtu` populated above, both within the struct's
    // allocation; SIOCSIFMTU reads both fields and writes nothing back
    // (see netdevice(7)). `sock`'s file descriptor is valid for the
    // duration of this call.
    let ret = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFMTU, &ifr) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_interface_mtu(_ifname: &str, _mtu: u16) -> std::io::Result<()> {
    Ok(())
}

/// One resize request handed to the [`MtuResizer`] thread.
struct MtuResizeRequest {
    ifname: String,
    mtu: u16,
    reply: tokio::sync::oneshot::Sender<std::io::Result<()>>,
}

/// A handle to the one dedicated OS thread that performs *every*
/// `SIOCSIFMTU` ioctl this daemon issues.
///
/// This exists for one reason, and it is not concurrency: **Linux
/// capabilities are per-thread**. Under deployment model 1 (start as
/// root, then `privilege::drop_privileges`), `CAP_NET_ADMIN` is retained
/// only on the thread that performs the drop -- glibc's `setuid()`
/// broadcasts the uid change to every *already-existing* thread via
/// `SIGSETXID`, and each of those threads re-runs `setuid` without
/// `PR_SET_KEEPCAPS` (that prctl is per-thread too), so their permitted
/// and effective sets are zeroed and the subsequent narrowing never
/// touches them.
///
/// `main` builds a multi-threaded tokio runtime *before* the drop, so
/// every tokio worker thread is one of those already-existing threads
/// and holds no capabilities at all. `control::mtu_monitor_loop` runs on
/// such a worker, which is why calling `set_interface_mtu` directly from
/// it returned `EPERM` on every tick. A thread created *after* the drop,
/// by contrast, forks its creator's (post-narrowing) capability sets and
/// does hold `CAP_NET_ADMIN` -- so [`MtuResizer::spawn`] is called
/// immediately after `drop_privileges` returns, and the monitor loop
/// sends requests to it instead of doing the ioctl itself.
///
/// Under deployment model 2 (systemd `AmbientCapabilities=`, the shipped
/// default) every thread has the capability regardless, so this
/// indirection is harmless there rather than necessary.
///
/// The thread parks on `recv()` for the daemon's whole lifetime and does
/// no work between requests. It needs no explicit shutdown wiring: when
/// the last `MtuResizer` handle is dropped the channel closes, `recv()`
/// returns `None`, and the loop exits on its own.
#[derive(Clone, Debug)]
pub struct MtuResizer {
    tx: tokio::sync::mpsc::UnboundedSender<MtuResizeRequest>,
}

impl MtuResizer {
    /// Spawns the resize thread. **Must be called after
    /// `privilege::drop_privileges`** -- see the type-level doc comment
    /// for why the ordering is load-bearing rather than stylistic.
    pub fn spawn() -> std::io::Result<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MtuResizeRequest>();
        std::thread::Builder::new()
            .name("mlvpn-mtu-resize".to_string())
            .spawn(move || {
                // `blocking_recv` is correct here (and not a runtime
                // misuse) precisely because this is a plain OS thread
                // with no reactor on it.
                while let Some(req) = rx.blocking_recv() {
                    let result = set_interface_mtu(&req.ifname, req.mtu);
                    // A dropped receiver just means the caller gave up;
                    // the ioctl already happened either way.
                    let _ = req.reply.send(result);
                }
            })?;
        Ok(Self { tx })
    }

    /// Asks the resize thread to set `ifname`'s MTU, and awaits its
    /// result. Semantically a drop-in for calling
    /// [`set_interface_mtu`] directly, just executed on a thread that
    /// actually holds `CAP_NET_ADMIN`.
    pub async fn set_mtu(&self, ifname: &str, mtu: u16) -> std::io::Result<()> {
        let (reply, wait) = tokio::sync::oneshot::channel();
        self.tx
            .send(MtuResizeRequest {
                ifname: ifname.to_string(),
                mtu,
                reply,
            })
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "MTU resize thread has exited",
                )
            })?;
        wait.await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "MTU resize thread dropped the request without replying",
            )
        })?
    }
}

/// Per-call sendmmsg accounting returned alongside a batch send.
#[derive(Default, Clone, Copy, Debug)]
pub struct SendmmsgStats {
    /// `sendmmsg(2)` invocations that were actually issued (a call that
    /// returned `EAGAIN` and was retried after the socket became
    /// writable counts each attempt).
    pub calls: u64,
    /// Calls that the kernel only partially accepted (fewer messages
    /// sent than requested, no error).
    pub partial: u64,
    /// Messages sent that coalesced more than one datagram via
    /// `UDP_SEGMENT` (`sendmmsg_gso` mode only).
    pub gso_runs: u64,
    /// Datagrams carried inside those coalesced messages.
    pub gso_segments: u64,
    /// The kernel rejected a GSO message during this call; the call fell
    /// back to plain `sendmmsg` and the caller should stop asking for GSO.
    pub gso_disabled: bool,
}

/// A contiguous run of datagrams sent as one `sendmmsg` message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GsoRun {
    start: usize,
    len: usize,
}

/// Kernel `UDP_MAX_SEGMENTS`.
const GSO_MAX_SEGS: usize = 64;
/// Stay under the 65507-byte UDP payload limit with headroom.
const GSO_MAX_BYTES: usize = 65_000;

/// Split `dgs` into the fewest valid GSO runs: every datagram of a run has
/// the first one's size, except that the last may be shorter (the kernel
/// allows a short tail segment). Runs never reorder datagrams.
fn plan_gso_runs(dgs: &[Vec<u8>]) -> Vec<GsoRun> {
    let mut runs = Vec::new();
    let mut i = 0;
    while i < dgs.len() {
        let size = dgs[i].len();
        let (mut len, mut bytes) = (1usize, size);
        if size > 0 && size <= u16::MAX as usize {
            while i + len < dgs.len() && len < GSO_MAX_SEGS {
                let s = dgs[i + len].len();
                if s == size && bytes + s <= GSO_MAX_BYTES {
                    len += 1;
                    bytes += s;
                } else {
                    if s > 0 && s < size && bytes + s <= GSO_MAX_BYTES {
                        len += 1;
                    }
                    break;
                }
            }
        }
        runs.push(GsoRun { start: i, len });
        i += len;
    }
    runs
}

/// Most datagrams handed to one `sendmmsg` call; the TX worker batch
/// (`TX_WORKER_BATCH`) is well under this.
const SENDMMSG_MAX: usize = 64;

/// One non-blocking `sendmmsg(2)` over `dgs` (at most `SENDMMSG_MAX`) to
/// `addr`. Returns how many leading datagrams the kernel accepted.
fn raw_sendmmsg(
    fd: std::os::unix::io::RawFd,
    addr: &socket2::SockAddr,
    dgs: &[Vec<u8>],
) -> std::io::Result<usize> {
    let n = dgs.len().min(SENDMMSG_MAX);
    // SAFETY: iovec/mmsghdr are plain C structs for which all-zero is a
    // valid value; every field the kernel reads is filled in below, and
    // every pointer stored (datagram buffers, `addr`) outlives the call.
    let mut iovs: [libc::iovec; SENDMMSG_MAX] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; SENDMMSG_MAX] = unsafe { std::mem::zeroed() };
    for i in 0..n {
        iovs[i].iov_base = dgs[i].as_ptr() as *mut libc::c_void;
        iovs[i].iov_len = dgs[i].len();
        msgs[i].msg_hdr.msg_name = addr.as_ptr() as *mut libc::c_void;
        msgs[i].msg_hdr.msg_namelen = addr.len();
        msgs[i].msg_hdr.msg_iov = &mut iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    // SAFETY: `msgs[..n]` is initialised above and `fd` is a live socket
    // owned by the caller's `UdpSocket` for the duration of the call.
    let rc = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), n as libc::c_uint, 0) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else if rc == 0 {
        Err(std::io::Error::from(std::io::ErrorKind::WriteZero))
    } else {
        Ok(rc as usize)
    }
}

/// Send every datagram in `dgs` to `remote` through `sendmmsg(2)`,
/// waiting for socket writability like `send_to` does. One outcome per
/// datagram, in order: a datagram the kernel rejected gets that error and
/// the run continues with the next one, matching the per-packet path
/// where one failed `send_to` does not stop the rest of the batch.
pub async fn sendmmsg_all(
    socket: &UdpSocket,
    remote: SocketAddr,
    dgs: &[Vec<u8>],
) -> (Vec<std::io::Result<()>>, SendmmsgStats) {
    let addr = socket2::SockAddr::from(remote);
    let fd = socket.as_raw_fd();
    let mut out: Vec<std::io::Result<()>> = Vec::with_capacity(dgs.len());
    let mut stats = SendmmsgStats::default();
    let mut start = 0;
    while start < dgs.len() {
        let want = (dgs.len() - start).min(SENDMMSG_MAX);
        let r = socket
            .async_io(tokio::io::Interest::WRITABLE, || {
                raw_sendmmsg(fd, &addr, &dgs[start..])
            })
            .await;
        stats.calls += 1;
        match r {
            Ok(k) => {
                if k < want {
                    stats.partial += 1;
                }
                out.extend((0..k).map(|_| Ok(())));
                start += k;
            }
            Err(e) => {
                out.push(Err(e));
                start += 1;
            }
        }
    }
    (out, stats)
}

/// One non-blocking `sendmmsg(2)` over `runs` (which must cover at most
/// `SENDMMSG_MAX` datagrams of `dgs`, starting at `dgs[0]`): each run is one
/// message, with a `UDP_SEGMENT` control message when it holds more than
/// one datagram. Returns how many leading runs the kernel accepted.
fn raw_sendmmsg_gso(
    fd: std::os::unix::io::RawFd,
    addr: &socket2::SockAddr,
    dgs: &[Vec<u8>],
    runs: &[GsoRun],
) -> std::io::Result<usize> {
    let n = runs.len().min(SENDMMSG_MAX);
    // SAFETY: as in `raw_sendmmsg`; additionally every control buffer is a
    // `[u64; 3]` (8-aligned, 24 bytes) and `CMSG_SPACE(2)` is checked to fit.
    let mut iovs: [libc::iovec; SENDMMSG_MAX] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; SENDMMSG_MAX] = unsafe { std::mem::zeroed() };
    let mut ctrl = [[0u64; 3]; SENDMMSG_MAX];
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    debug_assert!(space <= std::mem::size_of::<[u64; 3]>());
    for (k, run) in runs[..n].iter().enumerate() {
        for j in run.start..run.start + run.len {
            iovs[j].iov_base = dgs[j].as_ptr() as *mut libc::c_void;
            iovs[j].iov_len = dgs[j].len();
        }
        let hdr = &mut msgs[k].msg_hdr;
        hdr.msg_name = addr.as_ptr() as *mut libc::c_void;
        hdr.msg_namelen = addr.len();
        hdr.msg_iov = &mut iovs[run.start];
        hdr.msg_iovlen = run.len;
        if run.len > 1 {
            hdr.msg_control = ctrl[k].as_mut_ptr() as *mut libc::c_void;
            hdr.msg_controllen = space;
            // SAFETY: `msg_control`/`msg_controllen` were just set to a
            // buffer large enough for one u16 cmsg.
            unsafe {
                let cm = libc::CMSG_FIRSTHDR(hdr);
                (*cm).cmsg_level = libc::SOL_UDP;
                (*cm).cmsg_type = libc::UDP_SEGMENT;
                (*cm).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(cm) as *mut u16,
                    dgs[run.start].len() as u16,
                );
            }
        }
    }
    // SAFETY: `msgs[..n]` is initialised above; `fd` is live for the call.
    let rc = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), n as libc::c_uint, 0) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else if rc == 0 {
        Err(std::io::Error::from(std::io::ErrorKind::WriteZero))
    } else {
        Ok(rc as usize)
    }
}

/// `sendmmsg_all` plus UDP GSO coalescing of equal-size runs. Same
/// per-datagram outcome contract. If the kernel rejects a coalesced
/// message, `stats.gso_disabled` is set and everything not yet sent goes
/// out through plain `sendmmsg_all`, so a GSO failure never costs a packet.
pub async fn sendmmsg_gso_all(
    socket: &UdpSocket,
    remote: SocketAddr,
    dgs: &[Vec<u8>],
) -> (Vec<std::io::Result<()>>, SendmmsgStats) {
    let addr = socket2::SockAddr::from(remote);
    let fd = socket.as_raw_fd();
    let mut out: Vec<std::io::Result<()>> = Vec::with_capacity(dgs.len());
    let mut stats = SendmmsgStats::default();
    let mut start = 0;
    while start < dgs.len() {
        let window = &dgs[start..(start + SENDMMSG_MAX).min(dgs.len())];
        let runs = plan_gso_runs(window);
        let r = socket
            .async_io(tokio::io::Interest::WRITABLE, || {
                raw_sendmmsg_gso(fd, &addr, window, &runs)
            })
            .await;
        stats.calls += 1;
        match r {
            Ok(k) => {
                if k < runs.len() {
                    stats.partial += 1;
                }
                let mut sent = 0;
                for run in &runs[..k] {
                    if run.len > 1 {
                        stats.gso_runs += 1;
                        stats.gso_segments += run.len as u64;
                    }
                    sent += run.len;
                }
                out.extend((0..sent).map(|_| Ok(())));
                start += sent;
            }
            Err(e) if runs[0].len > 1 => {
                tracing::debug!(error = %e, "UDP GSO message rejected; disabling GSO");
                stats.gso_disabled = true;
                let (rest, s2) = sendmmsg_all(socket, remote, &dgs[start..]).await;
                out.extend(rest);
                stats.calls += s2.calls;
                stats.partial += s2.partial;
                return (out, stats);
            }
            Err(e) => {
                out.push(Err(e));
                start += 1;
            }
        }
    }
    (out, stats)
}

/// A `WgTunnel` with a fresh, throwaway keypair on both ends -- only
/// good for filling in `Link::wg` in tests that never actually drive a
/// real handshake (`test_link_for_state_transitions`,
/// `test_link_with_alternate`), which only need *a* tunnel to exist to
/// satisfy `Link`'s field, not one that talks to anything.
#[cfg(test)]
fn test_wg_tunnel() -> Arc<WgTunnel> {
    let local = crypto::StaticKeypair::generate().unwrap();
    let peer = crypto::StaticKeypair::generate().unwrap();
    Arc::new(WgTunnel::new(local.raw_bytes().0, peer.raw_bytes().1, true).unwrap())
}

/// Minimal but fully real `Link` for tests outside this module (e.g.
/// `monitor::tests`) that need to exercise state-transition logic against
/// a genuine `Link` -- a plain loopback-bound socket, no
/// `SO_BINDTODEVICE`/privileged path needed, so it runs in an ordinary
/// unprivileged `cargo test`. `pub(crate)` (not just `#[cfg(test)]`
/// private) specifically so callers in other modules' own test modules
/// can reach it.
#[cfg(test)]
pub(crate) async fn test_link_for_state_transitions(state: LinkState, stats: LinkStats) -> Link {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    Link {
        id: 0,
        config: LinkConfig {
            name: "test".to_string(),
            bind_interface: "lo".to_string(),
            local_addr: None,
            remote_addr: None,
            local_port: 0,
            weight: 1.0,
            bandwidth_cap_mbps: None,
            probe_interval_ms: 200,
            tx_send_mode: crate::config::TxSendMode::default(),
            private_key_file: std::path::PathBuf::from("/tmp/test.key"),
            peer_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        },
        socket: Arc::new(AsyncRwLock::new(Arc::new(socket))),
        reconnect_lock: Arc::new(AsyncMutex::new(())),
        remote: None,
        state,
        state_since: Instant::now(),
        stats,
        physical_mtu: None,
        admin_disabled: false,
        effective_probe_interval_ms: 200,
        effective_ewma_alpha: 0.2,
        alternate: None,
        wg: test_wg_tunnel(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // query_interface_mtu itself needs a real interface and isn't
    // meaningfully unit-testable without one (see integration/manual
    // testing notes in docs/development.md); this covers the pure
    // logic every caller actually depends on instead.

    #[test]
    fn nonexistent_interface_returns_none_not_panic() {
        // "lo" always exists, so pick a name that (almost certainly)
        // doesn't, to exercise the ioctl-failure path without requiring
        // any particular network configuration in CI.
        assert_eq!(query_interface_mtu("mlvpn-test-nonexistent-if0"), None);
    }

    #[test]
    #[ignore] // needs root and a real interface -- run with --ignored
    fn set_interface_mtu_on_loopback_round_trips() {
        // Loopback's MTU is safe to change and change back on any
        // Linux test runner without affecting other interfaces.
        let original = query_interface_mtu("lo").expect("lo should always be queryable");
        set_interface_mtu("lo", 1400).unwrap();
        assert_eq!(query_interface_mtu("lo"), Some(1400));
        // Restore, since this mutates real host state. Loopback's own
        // real-world default MTU is 65536 -- one past u16::MAX, unlike
        // any real physical or VPN link this crate ever resizes -- so
        // `original as u16` would silently wrap it to 0 and leave `lo`
        // corrupted instead of restored (confirmed live while writing
        // this test: it zeroed out `lo`'s MTU on the dev box). Restore
        // through the `ip` CLI instead of round-tripping back through
        // `set_interface_mtu` to avoid that truncation.
        let status = std::process::Command::new("ip")
            .args(["link", "set", "dev", "lo", "mtu", &original.to_string()])
            .status()
            .expect("failed to run `ip link set` to restore lo's MTU");
        assert!(status.success(), "failed to restore lo's original MTU");
        assert_eq!(query_interface_mtu("lo"), Some(original));
    }

    /// `record_tx`/`record_rx` each update a lifetime counter *and* feed
    /// their respective windowed throughput EWMA from one call -- this
    /// pins that repeated calls accumulate the lifetime counters
    /// correctly, and that the tx/rx sides stay independent of each
    /// other (calling one doesn't perturb the other's counters).
    #[test]
    fn record_tx_and_rx_accumulate_lifetime_counters_independently() {
        let mut stats = LinkStats::new(0.2);
        stats.record_tx(100);
        stats.record_tx(50);
        stats.record_rx(300);

        assert_eq!(stats.tx_bytes, 150);
        assert_eq!(stats.tx_packets, 2);
        assert_eq!(stats.rx_bytes, 300);
        assert_eq!(stats.rx_packets, 1);
    }

    /// `socket_domain`/`pick_remote_addr`/`resolve_remote_addr` (feeding
    /// IPv6-on-links and hostname-in-`remote_addr` support) need no real
    /// socket at all -- pure logic (plus, for a literal address, string
    /// parsing that never touches the network -- see
    /// `resolve_remote_addr_accepts_a_literal_ipv4_address`'s doc
    /// comment), so they're covered directly here rather than only via
    /// the integration tests that exercise a real bind.
    fn test_link_config(local_addr: Option<&str>, remote_addr: Option<&str>) -> LinkConfig {
        LinkConfig {
            name: "test".to_string(),
            bind_interface: "lo".to_string(),
            local_addr: local_addr.map(str::to_string),
            remote_addr: remote_addr.map(str::to_string),
            local_port: 0,
            weight: 1.0,
            bandwidth_cap_mbps: None,
            probe_interval_ms: 200,
            tx_send_mode: crate::config::TxSendMode::default(),
            private_key_file: std::path::PathBuf::from("/tmp/test.key"),
            peer_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        }
    }

    #[test]
    fn socket_domain_defaults_to_ipv4_with_nothing_set() {
        let cfg = test_link_config(None, None);
        assert_eq!(socket_domain(&cfg, None).unwrap(), Domain::IPV4);
    }

    #[test]
    fn socket_domain_follows_resolved_remote_ipv4() {
        let cfg = test_link_config(None, None);
        let remote: SocketAddr = "203.0.113.10:51000".parse().unwrap();
        assert_eq!(socket_domain(&cfg, Some(remote)).unwrap(), Domain::IPV4);
    }

    #[test]
    fn socket_domain_follows_resolved_remote_ipv6() {
        let cfg = test_link_config(None, None);
        let remote: SocketAddr = "[2001:db8::1]:51000".parse().unwrap();
        assert_eq!(socket_domain(&cfg, Some(remote)).unwrap(), Domain::IPV6);
    }

    #[test]
    fn socket_domain_resolved_remote_wins_over_local_addr() {
        // Contradictory config, but the resolved remote is what the
        // socket will actually be talking to, so it should win
        // regardless.
        let cfg = test_link_config(Some("192.0.2.5"), None);
        let remote: SocketAddr = "[2001:db8::1]:51000".parse().unwrap();
        assert_eq!(socket_domain(&cfg, Some(remote)).unwrap(), Domain::IPV6);
    }

    #[test]
    fn socket_domain_falls_back_to_local_addr_for_server_links() {
        // No resolved remote -- the server-side case, where the peer's
        // address is only learned at runtime (see this module's doc
        // comment). local_addr is the only thing left to infer from.
        let cfg = test_link_config(Some("::"), None);
        assert_eq!(socket_domain(&cfg, None).unwrap(), Domain::IPV6);

        let cfg = test_link_config(Some("0.0.0.0"), None);
        assert_eq!(socket_domain(&cfg, None).unwrap(), Domain::IPV4);
    }

    #[test]
    fn socket_domain_rejects_unparseable_local_addr() {
        let cfg = test_link_config(Some("not-an-address"), None);
        assert!(socket_domain(&cfg, None).is_err());
    }

    /// `pick_remote_addr` is where a hostname resolving to both an `A`
    /// and `AAAA` record (dual-stack DNS -- what actually motivated this
    /// function, e.g. `bgp.example.com` resolving to both an IPv4 and an
    /// IPv6 address for the same cloud host) gets narrowed to a
    /// (primary, alternate) pair. Pure logic, no real DNS lookup needed
    /// to exercise it.
    #[test]
    fn pick_remote_addr_prefers_ipv6_primary_with_ipv4_as_alternate() {
        let candidates = [
            "203.0.113.10:51000".parse().unwrap(),
            "[2001:db8::1]:51000".parse().unwrap(),
        ];
        let (primary, alternate) = pick_remote_addr(&candidates, None, "test").unwrap();
        assert!(primary.is_ipv6());
        assert!(alternate.unwrap().is_ipv4());
    }

    #[test]
    fn pick_remote_addr_falls_back_to_ipv4_with_no_alternate_when_only_ipv4_present() {
        let candidates = ["203.0.113.10:51000".parse().unwrap()];
        let (primary, alternate) = pick_remote_addr(&candidates, None, "test").unwrap();
        assert!(primary.is_ipv4());
        assert!(alternate.is_none());
    }

    #[test]
    fn pick_remote_addr_honors_local_addr_family_hint_with_no_alternate_to_race() {
        let candidates = [
            "203.0.113.10:51000".parse().unwrap(),
            "[2001:db8::1]:51000".parse().unwrap(),
        ];
        // local_addr says IPv4, so this must pick the IPv4 candidate
        // even though IPv6 would otherwise be preferred as primary --
        // and, since the operator pinned a family explicitly, there's
        // nothing left to race: no alternate at all.
        let (primary, alternate) =
            pick_remote_addr(&candidates, Some("192.0.2.5"), "test").unwrap();
        assert!(primary.is_ipv4());
        assert!(alternate.is_none());
    }

    #[test]
    fn pick_remote_addr_errors_when_local_addr_family_has_no_match() {
        // local_addr demands IPv6, but only an IPv4 candidate resolved --
        // this must error clearly rather than silently binding IPv4
        // anyway.
        let candidates = ["203.0.113.10:51000".parse().unwrap()];
        assert!(pick_remote_addr(&candidates, Some("::1"), "test").is_err());
    }

    #[test]
    fn pick_remote_addr_errors_on_empty_candidates() {
        assert!(pick_remote_addr(&[], None, "test").is_err());
    }

    #[tokio::test]
    async fn resolve_remote_addr_returns_none_when_unset() {
        let cfg = test_link_config(None, None);
        assert_eq!(resolve_remote_addr(&cfg).await.unwrap(), (None, None));
    }

    /// A literal `ip:port` resolves via `ToSocketAddrs`' own fast path
    /// (a plain parse, tried before any real `getaddrinfo` call), so
    /// this stays fast and network-free in CI -- exercising the
    /// hostname-resolution *path* end-to-end needs a real DNS lookup,
    /// which is exactly what `pick_remote_addr`'s tests above avoid by
    /// testing the selection logic directly instead.
    #[tokio::test]
    async fn resolve_remote_addr_accepts_a_literal_ipv4_address() {
        let cfg = test_link_config(None, Some("203.0.113.10:51000"));
        let (primary, alternate) = resolve_remote_addr(&cfg).await.unwrap();
        assert_eq!(primary, Some("203.0.113.10:51000".parse().unwrap()));
        assert_eq!(alternate, None);
    }

    #[tokio::test]
    async fn resolve_remote_addr_accepts_a_literal_ipv6_address() {
        let cfg = test_link_config(None, Some("[2001:db8::1]:51000"));
        let (primary, alternate) = resolve_remote_addr(&cfg).await.unwrap();
        assert_eq!(primary, Some("[2001:db8::1]:51000".parse().unwrap()));
        assert_eq!(alternate, None);
    }

    #[tokio::test]
    async fn resolve_remote_addr_rejects_a_malformed_address() {
        // No port separator at all -- fails during string parsing,
        // before any network access, so this stays fast and non-flaky.
        let cfg = test_link_config(None, Some("not-an-address"));
        assert!(resolve_remote_addr(&cfg).await.is_err());
    }

    /// A minimal but fully real `Link` for `commit_remote` tests --
    /// plain loopback-bound sockets (no `SO_BINDTODEVICE`/privileged
    /// path needed, unlike `Link::bind` itself) so these run in an
    /// ordinary unprivileged `cargo test`.
    async fn test_link_with_alternate() -> (Link, SocketAddr, SocketAddr) {
        let primary_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary_remote: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let alt_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let alt_remote: SocketAddr = "127.0.0.1:2".parse().unwrap();

        let link = Link {
            id: 0,
            config: test_link_config(None, None),
            socket: Arc::new(AsyncRwLock::new(Arc::new(primary_socket))),
            reconnect_lock: Arc::new(AsyncMutex::new(())),
            remote: Some(primary_remote),
            state: LinkState::Probing,
            state_since: Instant::now(),
            stats: LinkStats::new(0.2),
            physical_mtu: None,
            admin_disabled: false,
            effective_probe_interval_ms: 200,
            effective_ewma_alpha: 0.2,
            alternate: Some((alt_remote, Arc::new(AsyncRwLock::new(Arc::new(alt_socket))))),
            wg: test_wg_tunnel(),
        };
        (link, primary_remote, alt_remote)
    }

    #[tokio::test]
    async fn commit_remote_switches_to_the_alternate_when_it_wins() {
        let (mut link, _primary_remote, alt_remote) = test_link_with_alternate().await;
        link.commit_remote(Some(alt_remote));
        assert_eq!(link.remote, Some(alt_remote));
        assert!(link.alternate.is_none());
    }

    #[tokio::test]
    async fn commit_remote_keeps_the_primary_when_it_wins() {
        let (mut link, primary_remote, _alt_remote) = test_link_with_alternate().await;
        link.commit_remote(Some(primary_remote));
        assert_eq!(link.remote, Some(primary_remote));
        assert!(link.alternate.is_none());
    }

    #[tokio::test]
    async fn commit_remote_drops_the_alternate_when_a_different_link_won() {
        // `None` -- or any address that isn't this link's own
        // alternate -- is exactly what `tunnel::run`'s post-handshake
        // cleanup loop passes for every link *other* than the one that
        // actually answered: nothing to switch to, just release the
        // now-pointless alternate socket.
        let (mut link, primary_remote, _alt_remote) = test_link_with_alternate().await;
        link.commit_remote(None);
        assert_eq!(link.remote, Some(primary_remote));
        assert!(link.alternate.is_none());
    }

    #[tokio::test]
    async fn commit_remote_is_a_no_op_once_already_resolved() {
        let (mut link, primary_remote, alt_remote) = test_link_with_alternate().await;
        link.commit_remote(Some(alt_remote));
        assert_eq!(link.remote, Some(alt_remote));
        // Calling it again (as the cleanup loop's unconditional pass
        // over every link would, for the link that already resolved
        // its own race inside perform_client_handshake) must not undo
        // the switch or panic.
        link.commit_remote(Some(primary_remote));
        assert_eq!(link.remote, Some(alt_remote));
    }

    #[tokio::test]
    async fn alternate_handle_is_none_without_an_alternate() {
        let (mut link, _primary_remote, _alt_remote) = test_link_with_alternate().await;
        link.commit_remote(None);
        assert!(link.alternate_handle().is_none());
    }

    #[test]
    fn ewma_set_alpha_changes_future_updates_not_the_current_value() {
        let mut e = Ewma::new(0.5);
        e.update(100.0);
        assert_eq!(e.get(), Some(100.0));
        // Changing alpha must not itself move the already-computed
        // value -- only how strongly the *next* sample gets blended in.
        e.set_alpha(0.1);
        assert_eq!(e.get(), Some(100.0));
        // 0.1 * 0 + 0.9 * 100 = 90 -- if set_alpha hadn't taken effect,
        // the old 0.5 alpha would instead give 0.5*0 + 0.5*100 = 50.
        let updated = e.update(0.0);
        assert!((updated - 90.0).abs() < 1e-9, "updated was {updated}");
    }

    /// Fresh throwaway keypair for wg-transport tests -- mirrors
    /// `wireguard::tests::generate_test_keypair`, duplicated here rather
    /// than reused since that helper is private to `wireguard`'s own
    /// test module.
    fn test_keypair() -> ([u8; 32], [u8; 32]) {
        let kp = crypto::StaticKeypair::generate().unwrap();
        kp.raw_bytes()
    }

    /// A minimal, fully real `Link` bound to a plain loopback socket (no
    /// `SO_BINDTODEVICE` -- same reasoning as `test_link_with_alternate`),
    /// pre-wired with a real `WgTunnel` built from `local_priv`/
    /// `peer_pub`. `remote` starts unset -- the port isn't known until
    /// `bind` returns, so callers point two of these at each other's
    /// actual bound address afterward (see
    /// `link_wg_round_trip_over_loopback_sockets`).
    async fn test_wg_link(local_priv: [u8; 32], peer_pub: [u8; 32]) -> Link {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Link {
            id: 0,
            config: test_link_config(None, None),
            socket: Arc::new(AsyncRwLock::new(Arc::new(socket))),
            reconnect_lock: Arc::new(AsyncMutex::new(())),
            remote: None,
            state: LinkState::Probing,
            state_since: Instant::now(),
            stats: LinkStats::new(0.2),
            physical_mtu: None,
            admin_disabled: false,
            effective_probe_interval_ms: 200,
            effective_ewma_alpha: 0.2,
            alternate: None,
            wg: Arc::new(WgTunnel::new(local_priv, peer_pub, true).unwrap()),
        }
    }

    /// End-to-end proof that `Link`/`LinkHandle` correctly drive a real
    /// `WgTunnel` over real (loopback) sockets, all the way through a
    /// full WireGuard handshake to an actual application frame
    /// delivered client -> server.
    ///
    /// Choreographed the way `wireguard.rs`'s own
    /// `two_tunnels_handshake_and_exchange_a_frame` test confirmed
    /// `boringtun` actually behaves, not the simpler "one send, one
    /// receive" shape a naive reading of `wg_send`/`wg_recv`'s
    /// signatures might suggest: `wg_send`'s very first call only ever
    /// triggers the handshake (boringtun queues the plaintext internally
    /// and hands back a handshake-init datagram instead -- see
    /// `wg_send`'s own doc comment), so it is never actually delivered.
    /// A background task continuously draining the client's own
    /// `wg_recv` is what completes the handshake on the client's side --
    /// processing the server's handshake response and automatically
    /// sending back the post-handshake keepalive confirmation `wg_recv`
    /// forwards for any `SendReply` outcome -- exactly what a real
    /// `link_receiver` task is already doing continuously in production.
    /// Only once that round trip finishes does a second `wg_send` call
    /// actually deliver the real frame.
    #[tokio::test]
    async fn link_wg_round_trip_over_loopback_sockets() {
        let (client_priv, client_pub) = test_keypair();
        let (server_priv, server_pub) = test_keypair();

        let client = test_wg_link(client_priv, server_pub).await;
        let server = test_wg_link(server_priv, client_pub).await;

        let client_addr = client.handle().current_socket().await.local_addr().unwrap();
        let server_addr = server.handle().current_socket().await.local_addr().unwrap();

        let mut client_handle = client.handle();
        client_handle.remote = Some(server_addr);
        let mut server_handle = server.handle();
        server_handle.remote = Some(client_addr);

        let frame = b"a full mlvpn frame's bytes, opaque to this test".to_vec();

        // Drains the client's own inbound socket so the server's
        // handshake response (and any further SendReply traffic) gets
        // processed -- this is what actually completes the handshake on
        // the client's side. Never expected to yield a real `Frame` in
        // this test (only the server is ever sent application data), so
        // it's aborted once this test's own assertions are done.
        let client_drain = {
            let h = client_handle.clone();
            tokio::spawn(async move { h.wg_recv().await })
        };

        let server_recv = {
            let h = server_handle.clone();
            tokio::spawn(async move { h.wg_recv().await })
        };

        // First call only triggers the handshake (see this test's own
        // doc comment); give the client's background drain task time to
        // finish the handshake exchange before retrying with the real
        // frame.
        // ... and that first call is exactly the case `wg_send`'s bool
        // exists to surface: the socket write succeeded, but what went
        // out was a handshake initiation, not this frame.
        assert!(
            !client_handle.wg_send(&frame).await.unwrap(),
            "the handshake-triggering send must report that it did not carry the frame"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            client_handle.wg_send(&frame).await.unwrap(),
            "once the session is up, wg_send must report a real transmission"
        );

        let (received, from) = tokio::time::timeout(Duration::from_secs(5), server_recv)
            .await
            .expect("server_recv timed out")
            .unwrap()
            .unwrap();
        assert_eq!(received, frame);
        assert_eq!(from, client_addr);

        client_drain.abort();
    }

    #[test]
    fn link_stats_set_alpha_applies_to_all_five_ewmas() {
        let mut stats = LinkStats::new(0.5);
        stats.rtt_ms.update(100.0);
        stats.jitter_ms.update(10.0);
        stats.loss_rate.update(0.0);
        stats.rx_throughput_mbps.update(50.0);
        stats.tx_throughput_mbps.update(20.0);
        stats.set_alpha(0.1);
        // Same probe as above: a 0.1 alpha blending toward 0 from a
        // prior value of X gives 0.9 * X.
        assert!((stats.rtt_ms.update(0.0) - 90.0).abs() < 1e-9);
        assert!((stats.jitter_ms.update(0.0) - 9.0).abs() < 1e-9);
        assert!((stats.rx_throughput_mbps.update(0.0) - 45.0).abs() < 1e-9);
        assert!((stats.tx_throughput_mbps.update(0.0) - 18.0).abs() < 1e-9);
    }

    #[tokio::test]
    async fn sendmmsg_all_delivers_every_datagram_in_order() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = rx.local_addr().unwrap();
        // 150 > SENDMMSG_MAX, so this spans several sendmmsg calls.
        let dgs: Vec<Vec<u8>> = (0u32..150)
            .map(|i| {
                let mut v = i.to_be_bytes().to_vec();
                v.extend(std::iter::repeat_n((i % 251) as u8, 1 + (i as usize % 200)));
                v
            })
            .collect();
        let (out, stats) = sendmmsg_all(&tx, remote, &dgs).await;
        assert_eq!(out.len(), dgs.len());
        assert!(out.iter().all(|r| r.is_ok()));
        assert!(stats.calls >= 3, "150 datagrams need >=3 calls of <=64");
        let mut buf = vec![0u8; 2048];
        for want in &dgs {
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_from(&mut buf))
                .await
                .expect("datagram not received")
                .unwrap();
            assert_eq!(&buf[..n], &want[..]);
        }
    }

    #[tokio::test]
    async fn sendmmsg_all_reports_a_bad_datagram_and_keeps_going() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = rx.local_addr().unwrap();
        // Larger than the 65507-byte UDP payload limit -> EMSGSIZE.
        let dgs = vec![vec![1u8; 10], vec![2u8; 70_000], vec![3u8; 10]];
        let (out, _) = sendmmsg_all(&tx, remote, &dgs).await;
        assert_eq!(out.len(), 3);
        assert!(out[0].is_ok());
        assert!(out[1].is_err());
        assert!(out[2].is_ok());
        let mut buf = vec![0u8; 2048];
        let (n, _) = rx.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[1u8; 10][..]);
        let (n, _) = rx.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[3u8; 10][..]);
    }

    fn sized(sizes: &[usize]) -> Vec<Vec<u8>> {
        sizes.iter().map(|&n| vec![0u8; n]).collect()
    }

    fn runs(sizes: &[usize]) -> Vec<(usize, usize)> {
        plan_gso_runs(&sized(sizes))
            .into_iter()
            .map(|r| (r.start, r.len))
            .collect()
    }

    #[test]
    fn gso_plan_groups_equal_sizes_and_allows_a_short_tail() {
        assert_eq!(runs(&[]), vec![]);
        assert_eq!(runs(&[1400]), vec![(0, 1)]);
        assert_eq!(runs(&[1400, 1400, 1400]), vec![(0, 3)]);
        // a shorter datagram may end a run; a longer one starts the next
        assert_eq!(runs(&[1400, 1400, 200]), vec![(0, 3)]);
        assert_eq!(runs(&[200, 1400]), vec![(0, 1), (1, 1)]);
        // after a short tail, a new run begins
        assert_eq!(runs(&[1400, 200, 200, 200]), vec![(0, 2), (2, 2)]);
    }

    #[test]
    fn gso_plan_respects_segment_and_byte_limits() {
        // 100 tiny equal datagrams: capped at 64 segments per run
        let r = runs(&vec![100; 100]);
        assert_eq!(r, vec![(0, 64), (64, 36)]);
        // 1400-byte datagrams: 65_000 / 1400 = 46 per run
        let r = runs(&vec![1400; 100]);
        assert_eq!(r[0], (0, 46));
        assert_eq!(r.iter().map(|x| x.1).sum::<usize>(), 100);
        // empty datagrams are never coalesced
        assert_eq!(runs(&[0, 0, 0]), vec![(0, 1), (1, 1), (2, 1)]);
    }

    #[tokio::test]
    async fn sendmmsg_gso_all_preserves_every_datagram_boundary_and_order() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = rx.local_addr().unwrap();
        // Mostly full-size with periodic short ones and a few odd sizes, so
        // there are long runs, short tails and single-datagram runs.
        let dgs: Vec<Vec<u8>> = (0u32..80)
            .map(|i| {
                let len = match i % 13 {
                    5 => 90,
                    9 => 700,
                    _ => 1380,
                };
                let mut v = i.to_be_bytes().to_vec();
                v.extend(std::iter::repeat_n((i % 251) as u8, len - 4));
                v
            })
            .collect();
        let (out, stats) = sendmmsg_gso_all(&tx, remote, &dgs).await;
        assert_eq!(out.len(), dgs.len());
        assert!(out.iter().all(|r| r.is_ok()), "{out:?}");
        if stats.gso_disabled {
            eprintln!("kernel refused UDP GSO here; fallback path exercised instead");
        } else {
            assert!(
                stats.gso_runs > 0,
                "expected some coalesced runs: {stats:?}"
            );
            assert!(stats.gso_segments > stats.gso_runs);
        }
        // 80 datagrams still span two sendmmsg windows but fit in the default
        // loopback receive buffer, so none can be dropped before we read.
        let mut buf = vec![0u8; 2048];
        for (i, want) in dgs.iter().enumerate() {
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_from(&mut buf))
                .await
                .expect("datagram not received")
                .unwrap();
            assert!(
                buf[..n] == want[..],
                "datagram {i} differs (got {n} bytes, want {})",
                want.len()
            );
        }
    }

    #[tokio::test]
    async fn sendmmsg_gso_all_reports_a_bad_datagram_and_keeps_going() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = rx.local_addr().unwrap();
        let dgs = vec![vec![1u8; 10], vec![2u8; 70_000], vec![3u8; 10]];
        let (out, _) = sendmmsg_gso_all(&tx, remote, &dgs).await;
        assert_eq!(out.len(), 3);
        assert!(out[0].is_ok());
        assert!(out[1].is_err());
        assert!(out[2].is_ok());
    }
}
