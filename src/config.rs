//! Configuration loading and validation.
//!
//! Security notes:
//! - The config file typically embeds (or references) the local static
//!   private key, so we refuse to run if it is readable by group/other.
//! - We validate cross-field invariants here (not just serde types) so bad
//!   configs fail fast at startup rather than causing confusing runtime
//!   behavior in the data path.

use crate::error::{MlvpnError, Result};
use serde::Deserialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// "server" or "client". Servers bind and wait for a handshake on each
    /// link; clients initiate. Functionally symmetric otherwise.
    pub mode: Mode,

    pub tunnel: TunnelConfig,

    pub crypto: CryptoConfig,

    #[serde(default)]
    pub scheduler: SchedulerConfig,

    /// One entry per physical uplink to bond.
    pub links: Vec<LinkConfig>,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub control: ControlConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Server,
    Client,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Server => "server",
            Mode::Client => "client",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TunnelConfig {
    /// Name of the TUN device to create, e.g. "mlvpn0".
    pub name: String,
    /// CIDR address to assign the local tunnel endpoint, e.g. "10.200.0.1/30".
    pub address: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_mtu() -> u16 {
    1400
}

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    /// Path to a file containing our base64 Curve25519 static private key
    /// (32 bytes, base64-encoded). File must be mode 0600.
    pub private_key_file: PathBuf,
    /// Base64 Curve25519 public key of the remote peer.
    pub peer_public_key: String,
    /// How often to rotate (rekey) the session, in seconds. Rekeying limits
    /// the amount of ciphertext ever protected by one set of keys.
    #[serde(default = "default_rekey_secs")]
    pub rekey_interval_secs: u64,
}

fn default_rekey_secs() -> u64 {
    120
}

#[derive(Debug, Clone, Deserialize)]
pub struct SchedulerConfig {
    /// Consecutive missed probes before a link is marked Down.
    #[serde(default = "default_down_threshold")]
    pub down_threshold: u32,
    /// Consecutive successful probes before a Down link is marked Up again.
    #[serde(default = "default_up_threshold")]
    pub up_threshold: u32,
    /// Max time the receive-side reorder buffer will hold a gap open before
    /// giving up and delivering what it has, in milliseconds.
    #[serde(default = "default_reorder_ms")]
    pub reorder_window_ms: u64,
    /// EWMA smoothing factor (0..1) for latency/jitter/loss stats. Higher =
    /// more reactive to recent samples, lower = smoother/slower to change.
    #[serde(default = "default_ewma_alpha")]
    pub ewma_alpha: f64,
}

fn default_down_threshold() -> u32 {
    5
}
fn default_up_threshold() -> u32 {
    3
}
fn default_reorder_ms() -> u64 {
    50
}
fn default_ewma_alpha() -> f64 {
    0.2
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            down_threshold: default_down_threshold(),
            up_threshold: default_up_threshold(),
            reorder_window_ms: default_reorder_ms(),
            ewma_alpha: default_ewma_alpha(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinkConfig {
    /// Human-readable name for logs/metrics, e.g. "fiber", "lte0".
    pub name: String,
    /// Name of the local network interface to bind to via SO_BINDTODEVICE,
    /// e.g. "eth0", "wwan0". This is what guarantees traffic for this link
    /// actually egresses the intended physical path instead of whatever the
    /// kernel routing table would otherwise pick.
    pub bind_interface: String,
    /// Optional specific local IP to bind the socket to, in addition to
    /// SO_BINDTODEVICE. Useful when an interface has multiple addresses.
    pub local_addr: Option<String>,
    /// Remote host:port of the peer for this link (client mode: where we
    /// connect; server mode: not used for binding, only for source
    /// validation once the peer's address is learned).
    pub remote_addr: Option<String>,
    /// Local UDP port to bind/listen on for this link.
    pub local_port: u16,
    /// Static preference multiplier applied on top of the measured score,
    /// e.g. to bias away from a metered/expensive link. 1.0 = neutral.
    #[serde(default = "default_weight")]
    pub weight: f64,
    /// Optional administrator-declared bandwidth ceiling in Mbps, used to
    /// cap the scheduler's throughput assumption for this link until
    /// empirical measurement is available.
    pub bandwidth_cap_mbps: Option<f64>,
    #[serde(default = "default_probe_interval_ms")]
    pub probe_interval_ms: u64,
}

fn default_weight() -> f64 {
    1.0
}
fn default_probe_interval_ms() -> u64 {
    200
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// tracing-subscriber EnvFilter directive, e.g. "info" or "mlvpn=debug".
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for LoggingConfig {
    // Deliberately hand-written rather than `#[derive(Default)]`: serde's
    // `#[serde(default)]` on the `Config::logging` field calls this impl
    // (via the `Default` trait) when the whole `[logging]` table is
    // absent from the TOML, which is a different code path than the
    // field-level `#[serde(default = "default_log_level")]` above (that
    // one only fires when `[logging]` is present but `level` isn't). A
    // derived impl would silently give `level: String::new()` -- an empty
    // filter directive -- instead of "info" in the fully-omitted case.
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlConfig {
    /// Enable the local Unix-socket monitoring interface used by
    /// `mlvpn-tui`. On by default; the socket exposes no key material and
    /// is created mode 0600 (see `control.rs`), so there's little reason
    /// to disable it, but the option exists for minimal/locked-down
    /// deployments that want to shed anything not strictly required.
    #[serde(default = "default_control_enabled")]
    pub enabled: bool,
    /// Override the Unix socket path. When unset, defaults to
    /// `/run/mlvpn/<tunnel.name>.sock`, which matches the
    /// `RuntimeDirectory=mlvpn` directive in the shipped systemd unit
    /// (that directive is what makes `/run/mlvpn` exist, owned by the
    /// service's unprivileged runtime user, before mlvpnd ever starts --
    /// see systemd/mlvpn.service).
    pub socket_path: Option<String>,
}

fn default_control_enabled() -> bool {
    true
}

impl Default for ControlConfig {
    // Hand-written for the same reason as `LoggingConfig::default()`
    // above: this is what serde calls when the whole `[control]` table is
    // absent from the TOML, and it must still produce `enabled: true`.
    fn default() -> Self {
        Self {
            enabled: default_control_enabled(),
            socket_path: None,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        check_permissions(path)?;
        let raw = fs::read_to_string(path)
            .map_err(|e| MlvpnError::Config(format!("reading {}: {e}", path.display())))?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| MlvpnError::Config(format!("parsing {}: {e}", path.display())))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.links.is_empty() {
            return Err(MlvpnError::Config(
                "at least one [[links]] entry is required".into(),
            ));
        }

        let mut seen_names = std::collections::HashSet::new();
        for link in &self.links {
            if !seen_names.insert(&link.name) {
                return Err(MlvpnError::Config(format!(
                    "duplicate link name '{}'",
                    link.name
                )));
            }
            if self.mode == Mode::Client && link.remote_addr.is_none() {
                return Err(MlvpnError::Config(format!(
                    "link '{}' has no remote_addr; required in client mode",
                    link.name
                )));
            }
            if link.weight <= 0.0 {
                return Err(MlvpnError::Config(format!(
                    "link '{}' weight must be > 0",
                    link.name
                )));
            }
        }

        check_permissions(&self.crypto.private_key_file)?;

        if self.tunnel.mtu < 576 {
            return Err(MlvpnError::Config(
                "tunnel MTU must be at least 576 bytes".into(),
            ));
        }

        // Advisory only, not a hard error: warn if tunnel.mtu plus our own
        // framing overhead is likely to exceed a typical 1500-byte
        // physical link MTU. We can't know the *actual* MTU of every
        // bonded physical interface from here, so this is a rule-of-thumb
        // check against the common case (jumbo-frame environments may
        // legitimately want a higher tunnel.mtu). Getting this wrong
        // doesn't break the tunnel outright, but it means the outer UDP
        // datagram gets IP-fragmented -- which is inefficient, and
        // outright dropped by any firewall/NAT on the path that blocks
        // fragments, a notoriously hard-to-diagnose failure mode. This
        // uses eprintln! rather than tracing::warn! because it runs
        // during config validation, before logging is initialized (see
        // main.rs) -- stderr is the only channel guaranteed visible here.
        let outer_overhead = crate::protocol::HEADER_LEN as u32 + crate::crypto::TAG_LEN as u32
            + 28 /* IPv4(20) + UDP(8); +20 more if the outer transport ends up on IPv6 */;
        const TYPICAL_PHYSICAL_MTU: u32 = 1500;
        if self.tunnel.mtu as u32 + outer_overhead > TYPICAL_PHYSICAL_MTU {
            eprintln!(
                "warning: tunnel.mtu = {} plus ~{outer_overhead} bytes of tunnel overhead \
                 exceeds the typical 1500-byte physical link MTU; outer packets may be \
                 IP-fragmented or silently dropped by firewalls that block fragments. \
                 Consider tunnel.mtu <= {} unless every bonded link's physical MTU is \
                 confirmed higher.",
                self.tunnel.mtu,
                TYPICAL_PHYSICAL_MTU.saturating_sub(outer_overhead)
            );
        }

        Ok(())
    }
}

/// Refuse to load secret material that group/other can read. This is a
/// cheap, high-value check: a leaked static private key breaks the whole
/// Noise_IK identity guarantee for that peer.
fn check_permissions(path: &Path) -> Result<()> {
    let meta = fs::metadata(path).map_err(MlvpnError::Io)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(MlvpnError::InsecurePermissions {
            path: path.display().to_string(),
            mode,
        });
    }
    Ok(())
}
