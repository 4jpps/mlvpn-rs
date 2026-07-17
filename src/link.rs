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
use std::time::Instant;
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

pub struct LinkStats {
    pub rtt_ms: Ewma,
    /// Jitter per RFC 3550 sec 6.4.1: EWMA of the absolute difference
    /// between consecutive RTT samples.
    pub jitter_ms: Ewma,
    pub loss_rate: Ewma,
    /// Empirically observed throughput, updated from bytes actually
    /// transferred rather than a synthetic bandwidth probe (cheaper, no
    /// extra traffic, and reflects real contention on the link).
    pub throughput_mbps: Ewma,
    /// Achieved throughput as measured by an explicit active bandwidth
    /// probe burst (`scheduler.active_bandwidth_probing`, opt-in and off
    /// by default -- see `tunnel::active_bandwidth_prober`), as opposed
    /// to `throughput_mbps` above which only reflects bytes actually
    /// carried by real traffic. `None` until the first probe completes,
    /// or forever if the feature is off. Deliberately a separate EWMA
    /// rather than feeding into `throughput_mbps` itself: an active
    /// probe's burst and a lull in real traffic measure different
    /// things, and conflating them would make either signal noisier.
    /// `monitor::score` prefers this one when it has a value.
    pub active_bandwidth_mbps: Ewma,
    last_rtt_ms: Option<f64>,
    pub consecutive_misses: u32,
    pub consecutive_hits: u32,
    pub bytes_since_last_sample: u64,
    pub last_throughput_sample: Instant,
}

impl LinkStats {
    pub fn new(alpha: f64) -> Self {
        Self {
            rtt_ms: Ewma::new(alpha),
            jitter_ms: Ewma::new(alpha),
            loss_rate: Ewma::new(alpha),
            throughput_mbps: Ewma::new(alpha),
            active_bandwidth_mbps: Ewma::new(alpha),
            last_rtt_ms: None,
            consecutive_misses: 0,
            consecutive_hits: 0,
            bytes_since_last_sample: 0,
            last_throughput_sample: Instant::now(),
        }
    }

    /// Apply a new smoothing factor to the four per-packet EWMAs at once
    /// -- they're always tuned together (see
    /// `scheduler.auto_tune_ewma_alpha`'s doc comment in `config.rs`),
    /// so a caller never needs to reach into e.g. just `rtt_ms` alone.
    /// Deliberately does *not* touch `active_bandwidth_mbps`: that EWMA
    /// is fed by a probe every few minutes rather than every packet, so
    /// the fast-reacting/slow-reacting tradeoff `auto_tune_ewma_alpha`
    /// makes for the others doesn't apply to it in the same way.
    pub fn set_alpha(&mut self, alpha: f64) {
        self.rtt_ms.set_alpha(alpha);
        self.jitter_ms.set_alpha(alpha);
        self.loss_rate.set_alpha(alpha);
        self.throughput_mbps.set_alpha(alpha);
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

    pub fn record_bytes(&mut self, n: u64) {
        self.bytes_since_last_sample += n;
        let elapsed = self.last_throughput_sample.elapsed();
        if elapsed.as_secs_f64() >= 1.0 {
            let mbps =
                (self.bytes_since_last_sample as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
            self.throughput_mbps.update(mbps);
            self.bytes_since_last_sample = 0;
            self.last_throughput_sample = Instant::now();
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
        let (new_socket, _physical_mtu) = tokio::task::spawn_blocking(move || bind_socket(&config))
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

pub struct Link {
    pub id: u8,
    pub config: LinkConfig,
    socket: SharedSocket,
    reconnect_lock: Arc<AsyncMutex<()>>,
    pub remote: Option<SocketAddr>,
    pub state: LinkState,
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
}

impl Link {
    /// Create the UDP socket for a link, binding it to the configured
    /// local interface/port. This must run before privileges are dropped
    /// if `bind_interface` requires `CAP_NET_RAW`/root on the target
    /// system (SO_BINDTODEVICE itself only needs `CAP_NET_RAW` on Linux,
    /// which `privilege::drop_to` retains explicitly for this reason).
    pub async fn bind(id: u8, config: LinkConfig, ewma_alpha: f64) -> Result<Self> {
        let (socket, physical_mtu) = bind_socket(&config)?;

        let remote = match &config.remote_addr {
            Some(addr) => Some(addr.parse().map_err(|e| {
                MlvpnError::Config(format!("bad remote_addr for link '{}': {e}", config.name))
            })?),
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
            stats: LinkStats::new(ewma_alpha),
            physical_mtu,
            admin_disabled: false,
            effective_probe_interval_ms,
            effective_ewma_alpha: ewma_alpha,
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
            socket: self.socket.clone(),
            reconnect_lock: self.reconnect_lock.clone(),
        }
    }
}

/// Decide whether a link's socket should be IPv4 or IPv6, from whichever
/// of `remote_addr`/`local_addr` actually says -- there's no separate
/// `address_family` config knob; the address(es) already given say it
/// implicitly, the same way they always have, so an existing IPv4-only
/// config needs no changes to keep behaving exactly as before.
///
/// `remote_addr` (a full `host:port` `SocketAddr` string) is checked
/// first: every client-side link has one, and for a server-side link it
/// still wins if somehow both are set, since it's the address this
/// socket will actually be talking to. Falls back to `local_addr` (a
/// bare IP, no port) for a server-side link with no `remote_addr` --
/// the peer's address there is only *learned* at runtime from the first
/// authenticated packet (see this module's doc comment), so there is
/// nothing else to infer the family from until an operator wanting an
/// IPv6-only server-side link sets `local_addr` to an IPv6 address
/// (`"::"` for "any"). Defaults to IPv4 if neither is set, matching
/// every config written before this existed.
fn socket_domain(config: &LinkConfig) -> Result<Domain> {
    if let Some(remote) = &config.remote_addr {
        let addr: SocketAddr = remote.parse().map_err(|e| {
            MlvpnError::Config(format!("bad remote_addr for link '{}': {e}", config.name))
        })?;
        return Ok(if addr.is_ipv6() {
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
/// existing socket appears permanently dead) so both paths apply
/// exactly the same steps and error handling.
fn bind_socket(config: &LinkConfig) -> Result<(Arc<UdpSocket>, Option<u32>)> {
    let domain = socket_domain(config)?;
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

    /// `socket_domain` (feeding IPv6-on-links support) needs no real
    /// socket at all -- it's pure string parsing over `LinkConfig`, so
    /// it's covered directly here rather than only via the integration
    /// tests that exercise a real bind.
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
        assert_eq!(socket_domain(&cfg).unwrap(), Domain::IPV4);
    }

    #[test]
    fn socket_domain_follows_ipv4_remote_addr() {
        let cfg = test_link_config(None, Some("203.0.113.10:51000"));
        assert_eq!(socket_domain(&cfg).unwrap(), Domain::IPV4);
    }

    #[test]
    fn socket_domain_follows_ipv6_remote_addr() {
        let cfg = test_link_config(None, Some("[2001:db8::1]:51000"));
        assert_eq!(socket_domain(&cfg).unwrap(), Domain::IPV6);
    }

    #[test]
    fn socket_domain_remote_addr_wins_over_local_addr() {
        // Contradictory config, but remote_addr is what the socket will
        // actually be talking to, so it should win regardless.
        let cfg = test_link_config(Some("192.0.2.5"), Some("[2001:db8::1]:51000"));
        assert_eq!(socket_domain(&cfg).unwrap(), Domain::IPV6);
    }

    #[test]
    fn socket_domain_falls_back_to_local_addr_for_server_links() {
        // No remote_addr -- the server-side case, where the peer's
        // address is only learned at runtime (see this module's doc
        // comment). local_addr is the only thing left to infer from.
        let cfg = test_link_config(Some("::"), None);
        assert_eq!(socket_domain(&cfg).unwrap(), Domain::IPV6);

        let cfg = test_link_config(Some("0.0.0.0"), None);
        assert_eq!(socket_domain(&cfg).unwrap(), Domain::IPV4);
    }

    #[test]
    fn socket_domain_rejects_unparseable_remote_addr() {
        let cfg = test_link_config(None, Some("not-an-address"));
        assert!(socket_domain(&cfg).is_err());
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
    fn link_stats_set_alpha_applies_to_all_four_ewmas() {
        let mut stats = LinkStats::new(0.5);
        stats.rtt_ms.update(100.0);
        stats.jitter_ms.update(10.0);
        stats.loss_rate.update(0.0);
        stats.throughput_mbps.update(50.0);
        stats.set_alpha(0.1);
        // Same probe as above: a 0.1 alpha blending toward 0 from a
        // prior value of X gives 0.9 * X.
        assert!((stats.rtt_ms.update(0.0) - 90.0).abs() < 1e-9);
        assert!((stats.jitter_ms.update(0.0) - 9.0).abs() < 1e-9);
        assert!((stats.throughput_mbps.update(0.0) - 45.0).abs() < 1e-9);
    }
}
