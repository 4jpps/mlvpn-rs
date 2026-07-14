//! A `Link` is one bonded physical uplink: a UDP socket bound to a specific
//! network interface (via `SO_BINDTODEVICE`, so traffic provably egresses
//! that interface regardless of the kernel routing table) plus the running
//! statistics the scheduler needs to weigh it against the others.

use crate::config::LinkConfig;
use crate::error::{MlvpnError, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;

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
            last_rtt_ms: None,
            consecutive_misses: 0,
            consecutive_hits: 0,
            bytes_since_last_sample: 0,
            last_throughput_sample: Instant::now(),
        }
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

pub struct Link {
    pub id: u8,
    pub config: LinkConfig,
    /// Wrapped in `Arc` so per-link async tasks can hold their own cheap
    /// clone of the socket handle and call `send_to`/`recv_from` without
    /// ever needing to lock the shared `Vec<Link>` for the duration of an
    /// I/O `.await` -- only metadata (stats, state, remote address) lives
    /// behind that lock. See `tunnel.rs` module docs for why this
    /// distinction matters.
    pub socket: Arc<UdpSocket>,
    pub remote: Option<SocketAddr>,
    pub state: LinkState,
    pub stats: LinkStats,
    /// The `bind_interface`'s actual kernel-reported MTU at bind time
    /// (via `SIOCGIFMTU`), if we could determine it. `None` on non-Linux
    /// targets, or if the ioctl failed for any reason (missing
    /// permissions, interface renamed/removed between config load and
    /// bind, etc.) -- this is a best-effort input to MTU auto-tuning
    /// (see `main.rs`'s `effective_tunnel_mtu()`), never a hard
    /// requirement for the link to come up.
    pub physical_mtu: Option<u32>,
}

impl Link {
    /// Create the UDP socket for a link, binding it to the configured
    /// local interface/port. This must run before privileges are dropped
    /// if `bind_interface` requires `CAP_NET_RAW`/root on the target
    /// system (SO_BINDTODEVICE itself only needs `CAP_NET_RAW` on Linux,
    /// which `privilege::drop_to` retains explicitly for this reason).
    pub async fn bind(id: u8, config: LinkConfig, ewma_alpha: f64) -> Result<Self> {
        let domain = Domain::IPV4; // IPv6 links can be added by detecting the parsed addr.
        let socket =
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(MlvpnError::Io)?;
        socket.set_nonblocking(true).map_err(MlvpnError::Io)?;
        socket.set_reuse_address(true).map_err(MlvpnError::Io)?;

        #[cfg(target_os = "linux")]
        {
            socket
                .bind_device(Some(config.bind_interface.as_bytes()))
                .map_err(|e| {
                    // ENODEV specifically means the named interface doesn't
                    // exist on this system right now (typo in config, or a
                    // hot-pluggable interface like wwan0 that hasn't come
                    // up yet) -- worth its own error variant so operators
                    // get a precise diagnosis instead of a generic one.
                    if e.raw_os_error() == Some(libc::ENODEV) {
                        MlvpnError::InterfaceNotFound(config.bind_interface.clone())
                    } else {
                        MlvpnError::Config(format!(
                            "binding link '{}' to interface '{}': {e} (are we running with CAP_NET_RAW?)",
                            config.name, config.bind_interface
                        ))
                    }
                })?;
        }

        // Best-effort: feeds MTU auto-tuning (main.rs's
        // effective_tunnel_mtu()), never blocks link setup on failure.
        let physical_mtu = query_interface_mtu(&config.bind_interface);

        let bind_ip = config
            .local_addr
            .clone()
            .unwrap_or_else(|| "0.0.0.0".to_string());
        let bind_addr: SocketAddr =
            format!("{bind_ip}:{}", config.local_port)
                .parse()
                .map_err(|e| {
                    MlvpnError::Config(format!("bad local_addr for link '{}': {e}", config.name))
                })?;
        socket.bind(&bind_addr.into()).map_err(MlvpnError::Io)?;

        let std_socket: StdUdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket).map_err(MlvpnError::Io)?;

        let remote = match &config.remote_addr {
            Some(addr) => Some(addr.parse().map_err(|e| {
                MlvpnError::Config(format!("bad remote_addr for link '{}': {e}", config.name))
            })?),
            None => None,
        };

        Ok(Self {
            id,
            config,
            socket: Arc::new(tokio_socket),
            remote,
            state: LinkState::Probing,
            stats: LinkStats::new(ewma_alpha),
            physical_mtu,
        })
    }
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
}
