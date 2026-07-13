//! A `Link` is one bonded physical uplink: a UDP socket bound to a specific
//! network interface (via `SO_BINDTODEVICE`, so traffic provably egresses
//! that interface regardless of the kernel routing table) plus the running
//! statistics the scheduler needs to weigh it against the others.

use crate::config::LinkConfig;
use crate::error::{MlvpnError, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
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
    pub last_probe_sent_ns: Option<u64>,
    pub next_probe_seq: u32,
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
            last_probe_sent_ns: None,
            next_probe_seq: 0,
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
            let mbps = (self.bytes_since_last_sample as f64 * 8.0)
                / elapsed.as_secs_f64()
                / 1_000_000.0;
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
}

impl Link {
    /// Create the UDP socket for a link, binding it to the configured
    /// local interface/port. This must run before privileges are dropped
    /// if `bind_interface` requires `CAP_NET_RAW`/root on the target
    /// system (SO_BINDTODEVICE itself only needs `CAP_NET_RAW` on Linux,
    /// which `privilege::drop_to` retains explicitly for this reason).
    pub async fn bind(id: u8, config: LinkConfig, ewma_alpha: f64) -> Result<Self> {
        let domain = Domain::IPV4; // IPv6 links can be added by detecting the parsed addr.
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(MlvpnError::Io)?;
        socket.set_nonblocking(true).map_err(MlvpnError::Io)?;
        socket.set_reuse_address(true).map_err(MlvpnError::Io)?;

        #[cfg(target_os = "linux")]
        {
            socket
                .bind_device(Some(config.bind_interface.as_bytes()))
                .map_err(|e| {
                    MlvpnError::Config(format!(
                        "binding link '{}' to interface '{}': {e} (does the interface exist? are we running with CAP_NET_RAW?)",
                        config.name, config.bind_interface
                    ))
                })?;
        }

        let bind_ip = config
            .local_addr
            .clone()
            .unwrap_or_else(|| "0.0.0.0".to_string());
        let bind_addr: SocketAddr = format!("{bind_ip}:{}", config.local_port)
            .parse()
            .map_err(|e| MlvpnError::Config(format!("bad local_addr for link '{}': {e}", config.name)))?;
        socket.bind(&bind_addr.into()).map_err(MlvpnError::Io)?;

        let std_socket: StdUdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket).map_err(MlvpnError::Io)?;

        let remote = match &config.remote_addr {
            Some(addr) => Some(
                addr.parse()
                    .map_err(|e| MlvpnError::Config(format!("bad remote_addr for link '{}': {e}", config.name)))?,
            ),
            None => None,
        };

        Ok(Self {
            id,
            config,
            socket: Arc::new(tokio_socket),
            remote,
            state: LinkState::Probing,
            stats: LinkStats::new(ewma_alpha),
        })
    }
}
