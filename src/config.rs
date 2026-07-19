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

    #[serde(default)]
    pub command: CommandConfig,
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
    /// Optional IPv6 CIDR to *also* assign to the same TUN device, e.g.
    /// "fd00:200::1/64", so the interface carries both address families
    /// at once instead of picking one. Unset by default: existing
    /// configs are unaffected and the device stays IPv4-only exactly as
    /// before. When present, both stacks share the same encrypted
    /// session and bonded links -- there is no separate "IPv6 tunnel";
    /// it's the same tun_reader path in tunnel.rs handling whichever
    /// address family the kernel happens to hand it a packet for.
    pub address6: Option<String>,
    /// Requested tunnel MTU. Treated as an upper bound, not a fixed
    /// value: at startup this is automatically clamped down (with a
    /// warning) if it would exceed what the bonded links' actual
    /// physical interface MTUs can carry without fragmentation -- see
    /// `main.rs`'s `effective_tunnel_mtu()`. The static warning below
    /// in `validate()` is a config-time-only sanity check against a
    /// generic 1500-byte assumption; the real, link-aware clamp happens
    /// later once links are bound and their true MTUs are known.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Rewrite the MSS option of TCP SYN/SYN-ACK segments passing
    /// through the tunnel so TCP flows negotiate a segment size that
    /// already fits the effective tunnel MTU, rather than relying on
    /// Path MTU Discovery -- which many networks silently break by
    /// dropping the ICMP "fragmentation needed"/"packet too big"
    /// replies it depends on, leaving affected TCP connections to stall
    /// instead of just running slightly slower. See `mss.rs`. On by
    /// default; only worth disabling if something downstream is already
    /// doing MSS clamping and doing it twice would be redundant.
    #[serde(default = "default_clamp_mss")]
    pub clamp_mss: bool,
}

fn default_mtu() -> u16 {
    1400
}

fn default_clamp_mss() -> bool {
    true
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
    /// Opt-in redundancy mode: send every outgoing Data frame on *every*
    /// currently-Up link simultaneously, instead of the normal SWRR pick
    /// of just one. Trades bandwidth (an N-link tunnel with this on uses
    /// up to N times the bandwidth of a single copy) for the lowest
    /// possible chance of losing an individual packet -- worth it for a
    /// small, latency-critical tunnel (e.g. VoIP/control traffic over a
    /// couple of links), not for a bulk-transfer bonded tunnel. This is
    /// a blunt, whole-tunnel toggle rather than per-flow classification
    /// (no DSCP/traffic-class inspection) -- see `tunnel::tun_reader`'s
    /// doc comment for why that scoping was chosen. The receiving side
    /// needs no special handling: the existing replay window already
    /// rejects the second and later copies of the same sequence number
    /// as duplicates, the same protection it already provides against a
    /// genuine replay attack.
    #[serde(default)]
    pub redundant_mode: bool,
    /// Opt-in: periodically re-tune `reorder_window_ms` at runtime based
    /// on the live RTT spread across currently-Up links
    /// (`tunnel::reorder_tuning_loop`), instead of using the fixed value
    /// above for the tunnel's whole lifetime. A tunnel bonding two
    /// similar links wants a tight window; one bonding a fast link with
    /// a slow one needs more slack, and that spread can drift as links
    /// come and go or a cellular link's radio conditions shift over the
    /// life of a long-running tunnel. Off by default -- this changes
    /// runtime behavior beyond what `reorder_window_ms` alone describes,
    /// so an operator has to opt in rather than getting new dynamics
    /// unannounced on upgrade. See `ARCHITECTURE.md` §7 for the full
    /// design.
    #[serde(default)]
    pub auto_tune_reorder_window: bool,
    /// Lower bound the auto-tuner (above) will ever set
    /// `reorder_window_ms` to. Only consulted when
    /// `auto_tune_reorder_window` is true.
    #[serde(default = "default_reorder_window_min_ms")]
    pub reorder_window_min_ms: u64,
    /// Upper bound, same conditions as the min above.
    #[serde(default = "default_reorder_window_max_ms")]
    pub reorder_window_max_ms: u64,
    /// Opt-in: let each link's *effective* probe interval back off above
    /// its configured `[[links]] probe_interval_ms` floor after a long
    /// clean streak of successful probes (less overhead on a link
    /// that's been rock-stable for a while), snapping straight back to
    /// the floor the instant there's any miss at all (fast reaction the
    /// moment a link looks even slightly less reliable). `probe_interval_ms`
    /// itself is never lowered by this -- only ever a floor, same as
    /// before this existed. Off by default: this changes runtime probing
    /// cadence, and touches the timing hysteresis-based Up/Down
    /// decisions (§6) depend on, so it needs a deliberate opt-in same as
    /// `auto_tune_reorder_window` above. See
    /// `tunnel::suggest_probe_interval_ms` for the exact backoff math.
    #[serde(default)]
    pub auto_tune_probe_interval: bool,
    /// Ceiling the auto-tuner (above) will ever back a link's effective
    /// probe interval off to. Only consulted when
    /// `auto_tune_probe_interval` is true; every configured
    /// `[[links]] probe_interval_ms` must be `<=` this (checked in
    /// `Config::validate`), so the floor can never exceed the ceiling.
    #[serde(default = "default_probe_interval_max_ms")]
    pub probe_interval_max_ms: u64,
    /// Opt-in: let each link's own EWMA smoothing factor (shared by its
    /// latency/jitter/loss/throughput estimates, see `link::LinkStats::set_alpha`)
    /// move within `[ewma_alpha_min, ewma_alpha_max]` based on how
    /// stable that link's probes have looked recently, instead of
    /// staying fixed at `ewma_alpha` above for the tunnel's whole life.
    /// Any miss at all jumps a link's alpha straight to `ewma_alpha_max`
    /// (fastest possible reaction the moment there's trouble); a long
    /// clean streak gradually smooths it back down toward
    /// `ewma_alpha_min` instead. Off by default -- of this project's
    /// four auto-tuning knobs, this was originally judged the most
    /// speculative one (real production data, not just design
    /// reasoning, is what would actually justify it -- see
    /// `CHANGELOG.md`), so it gets the most deliberate opt-in of the
    /// four.
    #[serde(default)]
    pub auto_tune_ewma_alpha: bool,
    /// Lower bound (smoothest, slowest-reacting) the auto-tuner above
    /// will ever move a link's alpha to. Only consulted when
    /// `auto_tune_ewma_alpha` is true.
    #[serde(default = "default_ewma_alpha_min")]
    pub ewma_alpha_min: f64,
    /// Upper bound (most reactive, least smooth), same conditions as
    /// the min above.
    #[serde(default = "default_ewma_alpha_max")]
    pub ewma_alpha_max: f64,
    /// Opt-in: periodically send a short, rate-limited burst of MTU-sized
    /// dummy packets on each link purely to measure achieved throughput
    /// (`tunnel::active_bandwidth_prober`), feeding
    /// `link::LinkStats::active_bandwidth_mbps` -- see that field's doc
    /// comment and `monitor::score`. Unlike the other three auto-tuning
    /// knobs, this one injects extra traffic onto the wire rather than
    /// just changing how existing measurements are interpreted, so it
    /// gets the same deliberate off-by-default treatment for a stronger
    /// reason: an operator on a metered or bandwidth-constrained link may
    /// not want *any* synthetic traffic on it, however small. Existing
    /// deployments are unaffected either way.
    #[serde(default)]
    pub active_bandwidth_probing: bool,
    /// How often each link runs one probe burst, in seconds. Only
    /// consulted when `active_bandwidth_probing` is true. Validated
    /// (`Config::validate`) to be at least 30 seconds: this is a
    /// deliberate, injected burst of traffic rather than the tiny
    /// single-packet Probe/ProbeReply exchange used for latency, so a
    /// too-short interval would start to look like a self-inflicted
    /// bandwidth-flood/DoS pattern rather than an occasional
    /// measurement.
    #[serde(default = "default_active_bandwidth_probe_interval_secs")]
    pub active_bandwidth_probe_interval_secs: u64,
    /// How many MTU-sized packets make up one probe burst. Only
    /// consulted when `active_bandwidth_probing` is true. Validated to be
    /// between 2 (need at least a first and last packet to time an
    /// interval) and 100 (an upper sanity bound, so a misconfigured
    /// value can't turn "an occasional measurement" into a sustained
    /// flood every interval).
    #[serde(default = "default_active_bandwidth_probe_packets")]
    pub active_bandwidth_probe_packets: u32,
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
fn default_reorder_window_min_ms() -> u64 {
    10
}
fn default_reorder_window_max_ms() -> u64 {
    500
}
fn default_probe_interval_max_ms() -> u64 {
    2000
}
fn default_ewma_alpha_min() -> f64 {
    0.05
}
fn default_ewma_alpha_max() -> f64 {
    0.5
}
fn default_active_bandwidth_probe_interval_secs() -> u64 {
    300
}
fn default_active_bandwidth_probe_packets() -> u32 {
    20
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            down_threshold: default_down_threshold(),
            up_threshold: default_up_threshold(),
            reorder_window_ms: default_reorder_ms(),
            ewma_alpha: default_ewma_alpha(),
            redundant_mode: false,
            auto_tune_reorder_window: false,
            reorder_window_min_ms: default_reorder_window_min_ms(),
            reorder_window_max_ms: default_reorder_window_max_ms(),
            auto_tune_probe_interval: false,
            probe_interval_max_ms: default_probe_interval_max_ms(),
            auto_tune_ewma_alpha: false,
            ewma_alpha_min: default_ewma_alpha_min(),
            ewma_alpha_max: default_ewma_alpha_max(),
            active_bandwidth_probing: false,
            active_bandwidth_probe_interval_secs: default_active_bandwidth_probe_interval_secs(),
            active_bandwidth_probe_packets: default_active_bandwidth_probe_packets(),
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
    /// Also what selects IPv6 for a server-side link that has no
    /// `remote_addr` to infer it from (e.g. `"::"` to bind any local
    /// IPv6 address) -- see `link::socket_domain`'s doc comment. A bare
    /// IP, no port and no brackets even for IPv6 (unlike `remote_addr`
    /// below).
    pub local_addr: Option<String>,
    /// Remote host:port of the peer for this link (client mode: where we
    /// connect; server mode: not used for binding, only for source
    /// validation once the peer's address is learned). Accepts a literal
    /// IP (bracket the host for IPv6, e.g. `"[2001:db8::1]:51000"`, the
    /// standard `SocketAddr` string form) or a DNS hostname, e.g.
    /// `"bgp.example.com:51000"` -- resolved once, at startup
    /// (`link::resolve_remote_addr`), same as a literal address always
    /// has been; not re-resolved while `mlvpnd` keeps running, so a
    /// restart is needed to pick up a changed IP behind the hostname,
    /// exactly like editing a literal IP in this field always required.
    /// A hostname resolving to both an `A` and `AAAA` record (ordinary
    /// dual-stack DNS) is handled automatically: `local_addr` below, if
    /// set, picks the family with no further checks. Otherwise IPv6 is
    /// tried first, but only provisionally -- both candidates are raced
    /// during the very first handshake attempt, and whichever one
    /// actually answers wins (see `link::pick_remote_addr` and
    /// `link::Link::alternate`). This matters in practice: a hostname's
    /// `AAAA` record existing doesn't mean that IPv6 path is actually
    /// reachable end-to-end, and residential/consumer ISPs with a
    /// broken or absent IPv6 route are common enough that blindly
    /// committing to "IPv6 if present" with no fallback could wedge the
    /// initial handshake forever against a peer that was perfectly
    /// reachable over IPv4 the whole time. Also what selects this
    /// link's socket address family (IPv4 or IPv6) when set at all.
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

// Unlike `ControlConfig` above, a plain `#[derive(Default)]` is correct
// here and clippy (rightly) flags a hand-written impl as redundant:
// `bool::default()` is already `false`, which is exactly the "off by
// default" behavior this type needs, for both the field-level
// `#[serde(default)]` (used when `[command]` is present but `enabled`
// isn't) and the whole-table-absent case (`#[serde(default)]` on
// `Config::command`, which calls this `Default` impl).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CommandConfig {
    /// Enable the command socket (`control.rs::serve_commands`), which
    /// lets an authorized local client pin a link enabled/disabled at
    /// runtime -- see `ipc::Command`. Off by default, unlike the
    /// read-only control socket: this one can affect live traffic, so an
    /// operator has to opt in deliberately rather than getting a
    /// mutation-capable socket "for free" just by upgrading. This is a
    /// *separate* socket rather than an in-place upgrade of the
    /// existing one: a client authorized only to read `[control]`'s
    /// socket -- e.g. a monitoring-only account -- should not gain the
    /// ability to redirect traffic just because both sockets happened
    /// to share a path. See `ARCHITECTURE.md` §9.
    #[serde(default)]
    pub enabled: bool,
    /// Override the command socket path. When unset, defaults to
    /// `/run/mlvpn/<tunnel.name>.command.sock` -- deliberately a
    /// different filename from the read-only socket's default
    /// (`<tunnel.name>.sock`), even though both live in the same
    /// directory, so the two are never confusable at a glance in `ls`
    /// output or a firewall/AppArmor rule.
    pub socket_path: Option<String>,
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
            // Checked unconditionally, not only when
            // auto_tune_probe_interval is on: this keeps the invariant
            // true even if it's enabled later without the config being
            // revisited, and `suggest_probe_interval_ms`'s `u64::clamp`
            // call would otherwise panic (clamp requires min <= max) the
            // first time this link ever backs off.
            if link.probe_interval_ms > self.scheduler.probe_interval_max_ms {
                return Err(MlvpnError::Config(format!(
                    "link '{}' probe_interval_ms ({}) must be <= scheduler.probe_interval_max_ms ({})",
                    link.name, link.probe_interval_ms, self.scheduler.probe_interval_max_ms
                )));
            }
        }

        check_permissions(&self.crypto.private_key_file)?;

        if self.tunnel.mtu < 576 {
            return Err(MlvpnError::Config(
                "tunnel MTU must be at least 576 bytes".into(),
            ));
        }

        if self.crypto.rekey_interval_secs == 0 {
            return Err(MlvpnError::Config(
                "crypto.rekey_interval_secs must be non-zero (tokio::time::interval panics on \
                 a zero duration, and rekey_loop now actually runs this on the client)"
                    .into(),
            ));
        }

        if self.scheduler.reorder_window_min_ms > self.scheduler.reorder_window_max_ms {
            return Err(MlvpnError::Config(format!(
                "scheduler.reorder_window_min_ms ({}) must be <= reorder_window_max_ms ({})",
                self.scheduler.reorder_window_min_ms, self.scheduler.reorder_window_max_ms
            )));
        }

        if self.scheduler.ewma_alpha_min > self.scheduler.ewma_alpha_max {
            return Err(MlvpnError::Config(format!(
                "scheduler.ewma_alpha_min ({}) must be <= ewma_alpha_max ({})",
                self.scheduler.ewma_alpha_min, self.scheduler.ewma_alpha_max
            )));
        }

        // Checked unconditionally (not only when active_bandwidth_probing
        // is on) for the same "stays true if enabled later" reasoning as
        // the probe_interval_ms check above.
        if self.scheduler.active_bandwidth_probe_interval_secs < 30 {
            return Err(MlvpnError::Config(format!(
                "scheduler.active_bandwidth_probe_interval_secs ({}) must be >= 30 -- this is \
                 an injected traffic burst, not a single latency probe, so too-frequent bursts \
                 look like a self-inflicted flood",
                self.scheduler.active_bandwidth_probe_interval_secs
            )));
        }
        if !(2..=100).contains(&self.scheduler.active_bandwidth_probe_packets) {
            return Err(MlvpnError::Config(format!(
                "scheduler.active_bandwidth_probe_packets ({}) must be between 2 and 100",
                self.scheduler.active_bandwidth_probe_packets
            )));
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
