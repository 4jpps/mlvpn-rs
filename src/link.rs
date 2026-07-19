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
use crate::error::{MlvpnError, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
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
    last_rtt_ms: Option<f64>,
    pub consecutive_misses: u32,
    pub consecutive_hits: u32,
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
            last_rtt_ms: None,
            consecutive_misses: 0,
            consecutive_hits: 0,
            rx_bytes_since_last_sample: 0,
            last_rx_throughput_sample: Instant::now(),
            tx_bytes_since_last_sample: 0,
            last_tx_throughput_sample: Instant::now(),
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
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
    }

    /// Record a missed probe (no reply within the timeout).
    pub fn record_miss(&mut self) {
        self.loss_rate.update(1.0);
        self.consecutive_misses += 1;
        self.consecutive_hits = 0;
    }

    /// Lifetime counter (`tx_bytes`/`tx_packets`) *and* the windowed
    /// `tx_throughput_mbps` real-time-rate EWMA, both from one call --
    /// call once per packet actually handed to the socket, on the send
    /// side.
    pub fn record_tx(&mut self, n: u64) {
        self.tx_bytes += n;
        self.tx_packets += 1;
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
/// `tunnel::send_scheduled` calls this once per outgoing packet (not at
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
    /// during the very first handshake attempt only
    /// (`tunnel::perform_client_handshake`, gated on `rekey_ctx.is_none()`)
    /// -- deliberately never re-raced on a later rekey: by then,
    /// `link_receiver`/`link_prober` already hold their own `LinkHandle`
    /// snapshotted at spawn time (right after the initial handshake
    /// commits), which wouldn't observe a `remote` flip happening that
    /// late without a much larger change to how those tasks pick up a
    /// changed remote. Always `None` again once the initial handshake
    /// has resolved which family actually works, win or lose -- see
    /// `commit_remote`.
    pub alternate: Option<(SocketAddr, SharedSocket)>,
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
    pub async fn bind(id: u8, config: LinkConfig, ewma_alpha: f64) -> Result<Self> {
        let (remote, alternate_remote) = resolve_remote_addr(&config).await?;
        let (socket, physical_mtu) = bind_socket(&config, remote)?;
        let alternate = match alternate_remote {
            Some(alt_remote) => {
                let (alt_socket, _) = bind_socket(&config, Some(alt_remote))?;
                Some((alt_remote, Arc::new(AsyncRwLock::new(alt_socket))))
            }
            None => None,
        };

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
        })
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
        })
    }

    /// Resolves `alternate` after the very first handshake attempt has
    /// finished (win or lose) -- called once, from
    /// `tunnel::perform_client_handshake`'s success arm for whichever
    /// link actually answered, and unconditionally for every other link
    /// right after `tunnel::establish_session_with_retry` returns (see
    /// `tunnel::run`), so no link is ever left holding an untested
    /// alternate socket open for the rest of the process's life.
    ///
    /// `winner`, if `Some`, is the address that actually answered this
    /// specific handshake attempt. If it matches `alternate`'s address,
    /// that candidate just proved itself reachable where the original
    /// `remote`/`socket` apparently wasn't (within this attempt's
    /// timeout, at least) -- promote it: swap it into `remote`/`socket`
    /// so every per-link task spawned after this point (`link_receiver`,
    /// `link_prober`, `active_bandwidth_prober` -- all spawned later in
    /// `tunnel::run`, using `handle()`/this same `Link`) uses the
    /// address that's actually known to work. Otherwise (the primary
    /// won, a *different* link entirely answered, or nothing answered
    /// yet), the alternate is simply dropped, closing its socket.
    pub fn commit_remote(&mut self, winner: Option<SocketAddr>) {
        let Some((alt_remote, alt_socket)) = self.alternate.take() else {
            return;
        };
        if winner == Some(alt_remote) {
            tracing::info!(
                link = %self.config.name,
                previous = ?self.remote,
                winner = %alt_remote,
                "alternate address family answered the initial handshake first; \
                 switching this link to it"
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
fn query_interface_mtu(ifname: &str) -> Option<u32> {
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
fn query_interface_mtu(_ifname: &str) -> Option<u32> {
    None
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
}
