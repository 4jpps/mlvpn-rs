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

    #[serde(default)]
    pub diagnostics: DiagnosticsConfig,
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
    /// Optional hard ceiling on the tunnel MTU. Leave unset (the
    /// default) to let mlvpn-rs pick the tunnel MTU entirely from
    /// live-detected physical link MTUs, adjusting automatically --
    /// including upward, unlike the old fixed-1400 default -- as links
    /// connect, reconnect, or change. Set this only to impose an
    /// explicit operator ceiling (detection can still clamp further
    /// down from it, never up past it).
    #[serde(default)]
    pub mtu: Option<u16>,
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
    /// Transmit queue length (in packets) for the TUN device, passed to
    /// `tun_rs::DeviceBuilder::tx_queue_len`. The OS default on Linux
    /// (500 packets) was confirmed as a real production bottleneck: a
    /// burst of real Data traffic caused 168 TUN-level TX drops in an
    /// 8-second tunneled TCP test on real infrastructure, even though
    /// the underlying WAN links had far more raw capacity available --
    /// the queue was simply too shallow to absorb the burst. Raising it
    /// eliminated further drops on retest. Defaults to 4000, the value
    /// verified live; only worth changing for a deployment with unusual
    /// bandwidth-delay-product characteristics.
    #[serde(default = "default_tx_queue_len")]
    pub tx_queue_len: u32,
}

fn default_clamp_mss() -> bool {
    true
}

fn default_tx_queue_len() -> u32 {
    4000
}

/// Where a FEC group's parity frame(s) are sent.
///
/// A parity frame protects a group only if it survives, and a link
/// failure takes out *all* of that link's members of the group at once.
/// The group is recoverable after a single-link burst only if the
/// failing link carried no more members than there are surviving
/// parity frames -- so the interesting question is which link the
/// parity should sit on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FecParityPlacement {
    /// Parity goes wherever the normal scheduler picks (default; the
    /// pre-Phase-5 behaviour).
    #[default]
    Scheduler,
    /// Parity goes on the usable link that carried the *most* members
    /// of the group. That link's own failure is the one the group
    /// cannot survive anyway (it took out most of the data), so the
    /// parity is kept off the links whose failure it could repair.
    Dominant,
    /// Parity goes on the usable link that carried the *fewest* members
    /// (the literal "put parity on a different path" reading). Kept for
    /// comparison; with SWRR-balanced groups it tends to co-locate
    /// parity with the survivors of a failure of the busy link.
    Diverse,
}

/// `redundant_mode`, `primary_link_mode`, and `follow_peer_primary` are
/// mutually exclusive -- at most one may be `true` at a time (enforced in
/// `Config::validate`). Each represents a fundamentally different
/// traffic-distribution strategy:
/// - `redundant_mode`: send every packet on every currently-Up link at
///   once (max reliability, N times the bandwidth).
/// - `primary_link_mode`: send everything on this host's own best-scoring
///   link, with hysteresis, failing over on a hard Down.
/// - `follow_peer_primary`: don't decide locally at all -- adopt whatever
///   primary link the peer last advertised over the wire.
///
/// See each field's own doc comment below for full detail.
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
    /// Opt-in: XOR single-erasure forward error correction for real Data
    /// traffic. Groups of `fec_group_size` sequential outgoing Data
    /// frames get one extra parity frame; a group missing exactly one
    /// member gets reconstructed on receive without waiting for TCP's
    /// own retransmission. Off by default -- this is a real, new
    /// bandwidth cost (1/fec_group_size extra traffic) that shouldn't
    /// appear on an existing deployment without an explicit choice.
    /// Mutually exclusive with `redundant_mode` (checked in
    /// `Config::validate`) -- both are strategies for the same problem,
    /// and combining them spends bandwidth on FEC parity that
    /// `redundant_mode`'s full duplication already makes redundant. See
    /// `docs/superpowers/specs/2026-09-15-single-erasure-fec-design.md`.
    ///
    /// **Interaction with `primary_link_mode`, worth understanding
    /// before enabling both.** The whole reason groups are formed in
    /// sequential send order rather than per link is that SWRR bonding
    /// spreads a group's members across every Up link, so a loss burst
    /// confined to one link takes only some of a group's members and
    /// the parity frame (itself independently scheduled) usually
    /// survives on another link. Under `primary_link_mode` there is no
    /// such spread: every member *and* the parity frame go out the one
    /// primary link, so a burst on that link takes the whole group
    /// together and the group is unrecoverable by construction -- while
    /// still costing the full `1/fec_group_size` bandwidth overhead.
    /// FEC still earns its keep against *isolated, independent* single
    /// packet losses on the primary link, and against the bonded/SWRR
    /// periods after `primary_link_mode` fails over, which is why this
    /// combination is documented rather than rejected in `validate()`.
    /// But do not expect it to help with burst loss on a single-link
    /// path -- watch `fec_recovered_total` vs `fec_unrecoverable_total`
    /// (both in `mlvpn-tui` and `mlvpnd diag-dump`) to see which regime
    /// a real deployment is actually in before leaving it on.
    ///
    /// Also note this raises the tunnel MTU's own overhead: a parity
    /// frame is larger than the Data frames it covers, so
    /// `control::effective_tunnel_mtu` reserves `1 + 10*fec_group_size
    /// + 2` bytes (83 at the default group size) out of the tunnel MTU
    /// while this is on. Both peers must therefore enable FEC with the
    /// same `fec_group_size` to keep their tunnel MTUs matching.
    #[serde(default)]
    pub fec_enabled: bool,
    /// How many sequential Data frames share one FEC parity frame.
    /// Must be 2..=255 (validated in `Config::validate`) -- the wire
    /// format's own `group_size` field is a `u8` (`protocol::
    /// FecParityPayload`). Lower values recover more of the isolated
    /// single-packet losses that occur alongside real network bursts,
    /// at higher bandwidth cost (`1/fec_group_size` extra traffic);
    /// higher values cost less but recover less. Only meaningful when
    /// `fec_enabled` is true.
    #[serde(default = "default_fec_group_size")]
    pub fec_group_size: u8,
    /// Parity frames per FEC group: 1 (default, a plain-XOR share, one
    /// recoverable loss per group) or 2 (adds a GF(256) `Q` share, so
    /// any two losses in a group are recoverable -- e.g. 8+2). Doubles
    /// the FEC bandwidth overhead (`2/fec_group_size`) and adds one
    /// extra parity frame per group, but parity is sent the moment the
    /// group completes, so it adds no send latency. Both peers must use
    /// the same value. Validated to 1..=2. Only meaningful when
    /// `fec_enabled` is true.
    #[serde(default = "default_fec_parity")]
    pub fec_parity: u8,
    /// Which link carries a group's parity frames (only meaningful with
    /// `fec_enabled`). See `FecParityPlacement`.
    #[serde(default)]
    pub fec_parity_placement: FecParityPlacement,
    /// Opt-in: instead of splitting traffic across every currently-Up
    /// link via SWRR proportional to monitor::score(), send everything
    /// over whichever single link currently looks fastest, failing
    /// over immediately on a hard failure (the primary link going
    /// Down) and switching to a sustained better link only after it
    /// stays ahead by a real margin for several consecutive refreshes
    /// -- see Scheduler's own primary-selection doc comment in
    /// scheduler.rs for the exact hysteresis. Off by default: SWRR
    /// bonding remains the default for anyone genuinely combining two
    /// comparable links for aggregate bandwidth. Mutually exclusive
    /// with redundant_mode (checked in Config::validate) -- send-to-
    /// one-link and send-to-every-link are contradictory strategies.
    ///
    /// **`bandwidth_cap_mbps` is NOT enforced while a link is acting as
    /// the primary.** `Scheduler::select` returns the primary directly,
    /// never reaching `swrr_pick_under_cap` (the only place a per-link
    /// cap/`RateLimitState` is applied). A configured cap still
    /// influences `monitor::score()`'s throughput term, so it can affect
    /// which link gets *picked* as primary, but once picked, sending on
    /// it is unmetered. An operator relying on a cap to protect a
    /// metered/expensive link should be aware primary-link mode bypasses
    /// that protection if the capped link ever becomes primary.
    #[serde(default)]
    pub primary_link_mode: bool,
    /// When true, this host does NOT run its own primary-selection
    /// hysteresis (Scheduler::refresh_from_scores's margin/streak logic).
    /// Instead it directly adopts whatever primary link_id the peer last
    /// advertised over VersionInfo, as long as that link is currently Up
    /// on this side too. Falls back to ordinary SWRR/least-bad selection
    /// whenever the peer hasn't advertised a primary yet, or the
    /// advertised link isn't Up locally.
    ///
    /// Lets one side (the "decider", running `primary_link_mode = true`)
    /// control both directions of a link pair without requiring the other
    /// side to run its own independent primary-selection config -- useful
    /// for a host that answers multiple differently-configured peers.
    ///
    /// **Same `bandwidth_cap_mbps` caveat as `primary_link_mode` above
    /// applies here too**: whatever link this host adopts as primary
    /// (because the peer advertised it) is sent on directly, bypassing
    /// `swrr_pick_under_cap`'s rate limiting.
    #[serde(default)]
    pub follow_peer_primary: bool,
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
    /// Opt-in: periodically run a short, real throughput stream on each
    /// link purely to measure achieved throughput
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
    /// How often each link runs one probe, in seconds. Only consulted
    /// when `active_bandwidth_probing` is true. Validated
    /// (`Config::validate`) to be at least 30 seconds: this is a
    /// deliberate, injected stream of traffic rather than the tiny
    /// single-packet Probe/ProbeReply exchange used for latency, so a
    /// too-short interval would start to look like a self-inflicted
    /// bandwidth-flood/DoS pattern rather than an occasional
    /// measurement.
    #[serde(default = "default_active_bandwidth_probe_interval_secs")]
    pub active_bandwidth_probe_interval_secs: u64,
    /// How long each probe's stream runs, in seconds. Only consulted
    /// when `active_bandwidth_probing` is true. Sized by duration, not a
    /// fixed packet count (this field's predecessor,
    /// `active_bandwidth_probe_packets`, removed): a small fixed packet
    /// count completes a fast link's burst in well under one round trip
    /// -- measuring local send-side overhead more than the path's real
    /// sustained capacity, and the faster the link, the worse that gets
    /// (a real-world 688 Mbps link measured at just 56.7 Mbps by the old
    /// 20-packet burst is what prompted this change). A duration-based
    /// stream naturally scales instead: a fast link moves more bytes in
    /// the same window, a slow link moves fewer, and both produce an
    /// accurate `achieved_mbps`. Reuses the same send/receive code as
    /// `mlvpnd self-test` (`tunnel::send_throughput_test_stream`).
    /// Validated to be between 1 and 30 seconds: long enough to move a
    /// meaningful amount of data even on a fast link, short enough to
    /// stay a bounded, occasional measurement rather than a sustained
    /// flood every interval. Note: `tunnel::active_bandwidth_prober`'s
    /// individual ramp/verification steps are now always a fixed 1
    /// second each regardless of this setting -- duration-based scaling
    /// for a fast link is handled by `adaptive_bandwidth_ramp`'s own
    /// doubling step count instead of one long single stream.
    #[serde(default = "default_active_bandwidth_probe_duration_secs")]
    pub active_bandwidth_probe_duration_secs: u64,
    /// How often `active_bandwidth_prober` discards its cached
    /// per-link ceiling and runs a full `adaptive_bandwidth_ramp`
    /// again from scratch, in seconds -- between re-ramps, each
    /// scheduled probe tick (`active_bandwidth_probe_interval_secs`)
    /// instead does one cheap single-step verification at the cached
    /// rate. Only consulted when `active_bandwidth_probing` is true.
    /// Deliberately defaults higher than
    /// `active_bandwidth_probe_interval_secs`'s own 300s default (this
    /// field defaults to 1800s, 6x that) -- setting them equal would
    /// make every single tick a full re-ramp, which is exactly the
    /// "cheap most of the time" behavior this field exists to avoid.
    /// A link's first probe ever (or its first after coming back Up)
    /// always runs a full ramp regardless of this interval, since
    /// there's no cached rate yet to verify against.
    #[serde(default = "default_active_bandwidth_reramp_interval_secs")]
    pub active_bandwidth_reramp_interval_secs: u64,
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
fn default_fec_group_size() -> u8 {
    8
}
fn default_fec_parity() -> u8 {
    1
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
fn default_active_bandwidth_probe_duration_secs() -> u64 {
    2
}
fn default_active_bandwidth_reramp_interval_secs() -> u64 {
    1800
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            down_threshold: default_down_threshold(),
            up_threshold: default_up_threshold(),
            reorder_window_ms: default_reorder_ms(),
            ewma_alpha: default_ewma_alpha(),
            redundant_mode: false,
            fec_enabled: false,
            fec_group_size: default_fec_group_size(),
            fec_parity: default_fec_parity(),
            fec_parity_placement: FecParityPlacement::default(),
            primary_link_mode: false,
            follow_peer_primary: false,
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
            active_bandwidth_probe_duration_secs: default_active_bandwidth_probe_duration_secs(),
            active_bandwidth_reramp_interval_secs: default_active_bandwidth_reramp_interval_secs(),
        }
    }
}

/// How a link's TX worker puts datagrams on the wire.
///
/// Measured on the production cloud host (3-vCPU KVM guest, Comcast link,
/// iperf3 -P16 -R BBR, 6 runs each): `sendmmsg` moved the link from ~53k to
/// ~73k pps (+37%) with ~31% less send time per packet and no change in
/// total CPU. It stays opt-in until it has soaked in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxSendMode {
    /// One `sendto(2)` per packet (default).
    #[default]
    Sendto,
    /// One `sendmmsg(2)` per TX-worker batch (up to 32 packets). Encryption
    /// and per-packet failure handling are identical to `sendto`.
    Sendmmsg,
    /// EXPERIMENTAL. `sendmmsg(2)` as above, but runs of equal-size
    /// datagrams are additionally coalesced into one message with a
    /// `UDP_SEGMENT` (UDP GSO) control message, so the kernel walks the
    /// IP/UDP stack once per run instead of once per packet. Falls back to
    /// plain `sendmmsg` for the rest of the process if the kernel or NIC
    /// rejects GSO.
    #[serde(rename = "sendmmsg_gso")]
    SendmmsgGso,
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
    /// Server-side links only: accept the peer over IPv4 *or* IPv6 on one
    /// socket, bound to `[::]:local_port` with `IPV6_V6ONLY` off (IPv4
    /// peers appear as IPv4-mapped `::ffff:a.b.c.d` addresses). Lets the
    /// client pick either family per link (e.g. IPv6 over a CGNAT'd
    /// mobile link, IPv4 over a cable link) without separate links.
    /// Replies leave from whatever source address the kernel's routing
    /// picks, so on a host with several addresses set the default
    /// routes' preferred source (`ip route ... src`) to the address
    /// clients connect to. Off by default; `local_addr` must be unset or
    /// `"::"`, and `remote_addr` must be unset.
    #[serde(default)]
    pub dual_stack: bool,
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
    /// How this link's TX worker sends: `"sendto"` (default, one syscall per
    /// packet) or `"sendmmsg"` (one syscall per worker batch). Per link, so
    /// it can be trialled on one link while the others stay on the default.
    /// Changing it needs a restart.
    #[serde(default)]
    pub tx_send_mode: TxSendMode,
    /// Path to a file containing this link's base64 Curve25519 static
    /// private key (32 bytes, base64-encoded). File must be mode 0600.
    /// Generate with `mlvpnd genkey --link <name>`.
    pub private_key_file: PathBuf,
    /// Base64 Curve25519 public key the peer generated for this same
    /// named link on their side.
    pub peer_public_key: String,
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
    /// Let members of the daemon's group (the `mlvpn` group under the
    /// shipped systemd unit) read the stats socket, so `mlvpn-tui` runs
    /// without sudo: the socket is created mode 0660 instead of 0600.
    /// Off by default. Only the read-only stats socket is affected; the
    /// `[command]` socket, which can change link state, always stays 0600.
    #[serde(default)]
    pub group_access: bool,
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
            group_access: false,
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

/// Diagnostic-dump capture -- both the on-demand `mlvpnd diag-dump` CLI
/// command (always available whenever `[command] enabled = true`,
/// unaffected by anything here) and an *automatic* capture this section
/// actually configures: watch every link's own locally-measured loss and
/// write a text dump to disk when one is degraded, flapping or down,
/// so evidence of a transient loss event is captured even if no one is
/// watching `mlvpn-tui` at the exact moment it happens. Off by default:
/// this is the one config section that has the daemon write arbitrary
/// files to disk on its own initiative, so an operator has to opt in
/// deliberately. See `diag.rs` and `control::diagnostics_watch_loop`.
#[derive(Debug, Clone, Deserialize)]
pub struct DiagnosticsConfig {
    #[serde(default)]
    pub auto_dump_enabled: bool,
    /// Also submit an automatic dump to https://software-support.jpps.us
    /// (as a real, findable support ticket) in addition to writing it
    /// to `dump_dir`. Off by default -- writing a local file is silent
    /// and inspectable by the operator at their leisure; submitting one
    /// is an outbound network call this daemon makes on its own, which
    /// needs explicit opt-in regardless of whether `auto_dump_enabled`
    /// itself is already on. Has no effect unless `auto_dump_enabled`
    /// is also true.
    #[serde(default)]
    pub auto_submit_enabled: bool,
    /// Install a panic hook that submits a crash report (hostname plus
    /// the tail of the in-memory log ring) to
    /// https://software-support.jpps.us when a task panics. Off by
    /// default, for exactly the reason `auto_submit_enabled` above is:
    /// it is an outbound network call the daemon makes on its own
    /// initiative, carrying operational detail (link names, bind
    /// interfaces, peer addresses and ports) off the machine, so it
    /// needs a deliberate opt-in rather than being on because a crash
    /// happened to occur. Independent of `auto_dump_enabled` and
    /// `auto_submit_enabled` -- a panic is not a loss event and does not
    /// go through the loss watcher. See `diagnostics::install_crash_report_hook`.
    #[serde(default)]
    pub crash_report_enabled: bool,
    /// A link is degraded when, over the last `window_secs`, raw probe loss
    /// (not the scheduler's loss EWMA, which one missed probe pushes past
    /// 50%) is at least this percentage AND at least `degraded_open_misses`
    /// probes were lost, and that holds for 30 s.
    #[serde(default = "default_diag_degraded_open_pct")]
    pub degraded_open_pct: f64,
    /// Absolute number of lost probes the window needs before a degraded
    /// event can open (a percentage alone is noisy on small counts).
    #[serde(default = "default_diag_degraded_open_misses")]
    pub degraded_open_misses: usize,
    /// An open degraded event is calm while window loss is below this.
    #[serde(default = "default_diag_degraded_close_pct")]
    pub degraded_close_pct: f64,
    /// Minimum time between local dump files while one event continues.
    /// Tickets are separate: exactly one per event, no reminders.
    #[serde(default = "default_diag_cooldown_secs")]
    pub cooldown_secs: u64,
    /// Sliding window the loss percentage is computed over.
    #[serde(default = "default_diag_window_secs")]
    pub window_secs: u64,
    /// Fewer probes than this in the window means too little data to call.
    #[serde(default = "default_diag_min_probes")]
    pub min_probes: usize,
    /// How long a link must stay calm before its event ends.
    #[serde(default = "default_diag_clear_secs")]
    pub clear_secs: u64,
    /// A link that stays not-Up longer than this is an outage.
    #[serde(default = "default_diag_outage_secs")]
    pub outage_secs: u64,
    /// No degradation verdict until a link's probe window is this old, so
    /// a just-started or just-recovered link can't alarm on its first
    /// misses. The window is also cleared whenever a link comes Up.
    #[serde(default = "default_diag_warmup_secs")]
    pub warmup_secs: u64,
    /// At most one degraded ticket per link per this long; further
    /// degraded events are dumped locally and counted in the next ticket.
    #[serde(default = "default_diag_degraded_ticket_gap_secs")]
    pub degraded_ticket_gap_secs: u64,
    /// This many Up->Down transitions within 10 minutes opens an event
    /// even if loss stays under the threshold. 0 disables.
    #[serde(default = "default_diag_flap_downs")]
    pub flap_downs: u32,
    /// Keep at most this many automatic dump files in `dump_dir`.
    #[serde(default = "default_diag_max_dump_files")]
    pub max_dump_files: usize,
    /// Directory dumps are written to. Defaults to `/var/log/mlvpn`,
    /// matching where most other services on the system log to --
    /// already writable under the shipped systemd unit's
    /// `LogsDirectory=mlvpn` (see systemd/mlvpn.service), and persists
    /// across restarts/reboots (unlike `/run/mlvpn`, tmpfs, which would
    /// lose a captured dump before anyone could read it). Pointing this
    /// at some *other* path needs its own `ReadWritePaths=` added to
    /// the unit if running under the hardened default -- `ProtectSystem=strict`
    /// makes everywhere else on the filesystem read-only.
    pub dump_dir: Option<String>,
}

fn default_diag_degraded_open_pct() -> f64 {
    12.0
}

fn default_diag_degraded_open_misses() -> usize {
    8
}

fn default_diag_degraded_close_pct() -> f64 {
    5.0
}

fn default_diag_cooldown_secs() -> u64 {
    300
}

fn default_diag_window_secs() -> u64 {
    300
}

fn default_diag_min_probes() -> usize {
    100
}

fn default_diag_clear_secs() -> u64 {
    300
}

fn default_diag_outage_secs() -> u64 {
    60
}

fn default_diag_warmup_secs() -> u64 {
    120
}

fn default_diag_degraded_ticket_gap_secs() -> u64 {
    21600
}

fn default_diag_flap_downs() -> u32 {
    3
}

fn default_diag_max_dump_files() -> usize {
    50
}

impl Default for DiagnosticsConfig {
    // Hand-written for the same reason as `ControlConfig::default()`
    // above: this is what serde calls when the whole `[diagnostics]`
    // table is absent from the TOML, and it must still produce the same
    // defaults the field-level `#[serde(default = "...")]` attributes
    // above do.
    fn default() -> Self {
        Self {
            auto_dump_enabled: false,
            auto_submit_enabled: false,
            crash_report_enabled: false,
            degraded_open_pct: default_diag_degraded_open_pct(),
            degraded_open_misses: default_diag_degraded_open_misses(),
            degraded_close_pct: default_diag_degraded_close_pct(),
            cooldown_secs: default_diag_cooldown_secs(),
            window_secs: default_diag_window_secs(),
            min_probes: default_diag_min_probes(),
            clear_secs: default_diag_clear_secs(),
            outage_secs: default_diag_outage_secs(),
            warmup_secs: default_diag_warmup_secs(),
            degraded_ticket_gap_secs: default_diag_degraded_ticket_gap_secs(),
            flap_downs: default_diag_flap_downs(),
            max_dump_files: default_diag_max_dump_files(),
            dump_dir: None,
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
            if link.dual_stack {
                if self.mode != Mode::Server || link.remote_addr.is_some() {
                    return Err(MlvpnError::Config(format!(
                        "link '{}': dual_stack is for server-side links without remote_addr",
                        link.name
                    )));
                }
                if link.local_addr.as_deref().is_some_and(|a| a != "::") {
                    return Err(MlvpnError::Config(format!(
                        "link '{}': dual_stack binds [::]; leave local_addr unset (or \"::\")",
                        link.name
                    )));
                }
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

        for link in &self.links {
            check_permissions(&link.private_key_file)?;
        }

        if let Some(mtu) = self.tunnel.mtu
            && mtu < 576
        {
            return Err(MlvpnError::Config(
                "tunnel MTU must be at least 576 bytes".into(),
            ));
        }

        if !(100..=65536).contains(&self.tunnel.tx_queue_len) {
            return Err(MlvpnError::Config(format!(
                "tunnel.tx_queue_len ({}) must be between 100 and 65536",
                self.tunnel.tx_queue_len
            )));
        }

        if self.scheduler.primary_link_mode && self.scheduler.redundant_mode {
            return Err(MlvpnError::Config(
                "scheduler.primary_link_mode and scheduler.redundant_mode cannot both be true \
                 -- send-to-one-link and send-to-every-link are contradictory strategies"
                    .into(),
            ));
        }

        if self.scheduler.follow_peer_primary && self.scheduler.primary_link_mode {
            return Err(MlvpnError::Config(
                "scheduler.follow_peer_primary and scheduler.primary_link_mode cannot both be \
                 true -- a host is either the primary-selection decider or a follower, not both"
                    .into(),
            ));
        }
        if self.scheduler.follow_peer_primary && self.scheduler.redundant_mode {
            return Err(MlvpnError::Config(
                "scheduler.follow_peer_primary and scheduler.redundant_mode cannot both be true \
                 -- send-to-one-link-the-peer-chose and send-to-every-link are contradictory"
                    .into(),
            ));
        }

        if self.scheduler.fec_enabled && self.scheduler.redundant_mode {
            return Err(MlvpnError::Config(
                "scheduler.fec_enabled and scheduler.redundant_mode cannot both be true -- both \
                 are strategies for recovering lost frames, and combining them spends bandwidth \
                 on FEC parity that redundant_mode's full duplication already makes redundant"
                    .into(),
            ));
        }

        // The `<= 255` half of this range is structurally unreachable
        // (the field is a `u8`, so 256 fails at TOML parse time and
        // never reaches here). Kept deliberately: it documents the
        // wire format's own limit (`FecParityPayload`'s `group_size`
        // byte) at the point a reader looks for the valid range, and it
        // stays correct if the field's type ever widens.
        if self.scheduler.fec_enabled && !(2..=255).contains(&self.scheduler.fec_group_size) {
            return Err(MlvpnError::Config(format!(
                "scheduler.fec_group_size ({}) must be between 2 and 255",
                self.scheduler.fec_group_size
            )));
        }

        if self.scheduler.fec_enabled && !(1..=2).contains(&self.scheduler.fec_parity) {
            return Err(MlvpnError::Config(format!(
                "scheduler.fec_parity ({}) must be 1 or 2",
                self.scheduler.fec_parity
            )));
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
        if !(1..=30).contains(&self.scheduler.active_bandwidth_probe_duration_secs) {
            return Err(MlvpnError::Config(format!(
                "scheduler.active_bandwidth_probe_duration_secs ({}) must be between 1 and 30",
                self.scheduler.active_bandwidth_probe_duration_secs
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
        if let Some(mtu) = self.tunnel.mtu {
            let outer_overhead = crate::protocol::HEADER_LEN as u32
                + crate::wireguard::WG_OVERHEAD_BYTES
                + crate::wireguard::FAKE_IPV4_HEADER_LEN as u32
                + 28 /* IPv4(20) + UDP(8); +20 more if the outer transport ends up on IPv6 */;
            const TYPICAL_PHYSICAL_MTU: u32 = 1500;
            if mtu as u32 + outer_overhead > TYPICAL_PHYSICAL_MTU {
                eprintln!(
                    "warning: tunnel.mtu = {mtu} plus ~{outer_overhead} bytes of tunnel \
                     overhead exceeds the typical 1500-byte physical link MTU; outer packets \
                     may be IP-fragmented or silently dropped by firewalls that block \
                     fragments. Consider tunnel.mtu <= {} unless every bonded link's physical \
                     MTU is confirmed higher.",
                    TYPICAL_PHYSICAL_MTU.saturating_sub(outer_overhead)
                );
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// `validate()` calls `check_permissions` on `crypto.private_key_file`,
    /// which does a real `fs::metadata` stat -- a missing path errors,
    /// not just a wrong-permission one -- so this fixture needs a real
    /// 0600 file on disk, not just a plausible-looking path. Leaves the
    /// file in place after the test (harmless, tiny, in the OS temp
    /// dir) rather than adding cleanup machinery for a handful of
    /// zero-byte files.
    ///
    /// Deviates from the brief's fixture in one respect: `validate()`
    /// requires at least one `[[links]] entry (checked directly at
    /// src/config.rs's `if self.links.is_empty()` early in `validate()`),
    /// so an empty `links: vec![]` as the brief originally sketched would
    /// fail every one of these tests for an unrelated reason. This
    /// fixture includes one minimal, valid `LinkConfig` instead.
    fn minimal_valid_config() -> Config {
        let key_path = std::env::temp_dir().join(format!(
            "mlvpn-test-key-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&key_path, b"test-key-material").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        Config {
            mode: Mode::Client,
            tunnel: TunnelConfig {
                name: "mlvpn-test0".to_string(),
                address: "10.200.0.1/30".to_string(),
                address6: None,
                mtu: Some(1400),
                clamp_mss: true,
                tx_queue_len: 4000,
            },
            scheduler: SchedulerConfig::default(),
            links: vec![LinkConfig {
                name: "link0".to_string(),
                bind_interface: "eth0".to_string(),
                local_addr: None,
                dual_stack: false,
                remote_addr: Some("198.51.100.1:51000".to_string()),
                local_port: 51000,
                weight: 1.0,
                bandwidth_cap_mbps: None,
                probe_interval_ms: default_probe_interval_ms(),
                tx_send_mode: TxSendMode::default(),
                private_key_file: key_path,
                peer_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            }],
            logging: LoggingConfig::default(),
            control: ControlConfig::default(),
            command: CommandConfig::default(),
            diagnostics: DiagnosticsConfig {
                auto_dump_enabled: false,
                degraded_open_pct: 12.0,
                degraded_open_misses: 8,
                degraded_close_pct: 5.0,
                cooldown_secs: 60,
                window_secs: 300,
                min_probes: 100,
                clear_secs: 300,
                outage_secs: 60,
                warmup_secs: 120,
                degraded_ticket_gap_secs: 21600,
                flap_downs: 3,
                max_dump_files: 50,
                dump_dir: None,
                auto_submit_enabled: false,
                crash_report_enabled: false,
            },
        }
    }

    #[test]
    fn mtu_none_passes_validation_regardless_of_link_count() {
        let mut cfg = minimal_valid_config();
        cfg.tunnel.mtu = None;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn mtu_some_below_576_is_rejected() {
        let mut cfg = minimal_valid_config();
        cfg.tunnel.mtu = Some(500);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn mtu_some_576_or_above_is_accepted() {
        let mut cfg = minimal_valid_config();
        cfg.tunnel.mtu = Some(1400);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn tx_queue_len_defaults_to_4000_when_absent_from_config() {
        assert_eq!(default_tx_queue_len(), 4000);
    }

    #[test]
    fn tx_queue_len_below_100_is_rejected() {
        let mut cfg = minimal_valid_config();
        cfg.tunnel.tx_queue_len = 99;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tx_queue_len_above_65536_is_rejected() {
        let mut cfg = minimal_valid_config();
        cfg.tunnel.tx_queue_len = 65537;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tx_queue_len_within_bounds_is_accepted() {
        let mut cfg = minimal_valid_config();
        cfg.tunnel.tx_queue_len = 4000;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn primary_link_mode_alone_is_accepted() {
        let mut cfg = minimal_valid_config();
        cfg.scheduler.primary_link_mode = true;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn primary_link_mode_with_redundant_mode_is_rejected() {
        let mut cfg = minimal_valid_config();
        cfg.scheduler.primary_link_mode = true;
        cfg.scheduler.redundant_mode = true;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn follow_peer_primary_alone_is_accepted() {
        let mut cfg = minimal_valid_config();
        cfg.scheduler.follow_peer_primary = true;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn follow_peer_primary_with_primary_link_mode_is_rejected() {
        let mut cfg = minimal_valid_config();
        cfg.scheduler.follow_peer_primary = true;
        cfg.scheduler.primary_link_mode = true;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn follow_peer_primary_with_redundant_mode_is_rejected() {
        let mut cfg = minimal_valid_config();
        cfg.scheduler.follow_peer_primary = true;
        cfg.scheduler.redundant_mode = true;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn redundant_mode_alone_is_still_accepted() {
        let mut cfg = minimal_valid_config();
        cfg.scheduler.redundant_mode = true;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn fec_enabled_defaults_to_false_and_group_size_to_eight() {
        let toml_str = r#"
        mode = "client"
        [tunnel]
        name = "mlvpn0"
        address = "10.200.0.1/30"
        [[links]]
        name = "a"
        bind_interface = "eth0"
        local_port = 6900
        private_key_file = "/tmp/a.key"
        peer_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    "#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(!cfg.scheduler.fec_enabled);
        assert_eq!(cfg.scheduler.fec_group_size, 8);
    }

    #[test]
    fn fec_enabled_and_redundant_mode_together_is_rejected() {
        let mut cfg = minimal_valid_config();
        cfg.scheduler.fec_enabled = true;
        cfg.scheduler.redundant_mode = true;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn fec_group_size_below_two_is_rejected() {
        let mut cfg = minimal_valid_config();
        cfg.scheduler.fec_enabled = true;
        cfg.scheduler.fec_group_size = 1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn fec_parity_defaults_to_one_with_scheduler_placement() {
        let cfg = minimal_valid_config();
        assert_eq!(cfg.scheduler.fec_parity, 1);
        assert_eq!(
            cfg.scheduler.fec_parity_placement,
            FecParityPlacement::Scheduler
        );
    }

    #[test]
    fn fec_parity_and_placement_parse_from_toml() {
        let toml_str = r#"
        mode = "client"
        [tunnel]
        name = "mlvpn0"
        address = "10.200.0.1/30"
        [scheduler]
        fec_enabled = true
        fec_parity = 2
        fec_parity_placement = "dominant"
        [[links]]
        name = "a"
        bind_interface = "eth0"
        local_port = 6900
        private_key_file = "/tmp/a.key"
        peer_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    "#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.scheduler.fec_parity, 2);
        assert_eq!(
            cfg.scheduler.fec_parity_placement,
            FecParityPlacement::Dominant
        );
    }

    fn link_toml(extra: &str) -> String {
        format!(
            r#"
        mode = "client"
        [tunnel]
        name = "mlvpn0"
        address = "10.200.0.1/30"
        [[links]]
        name = "a"
        bind_interface = "eth0"
        local_port = 6900
        private_key_file = "/tmp/a.key"
        peer_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        {extra}
    "#
        )
    }

    #[test]
    fn tx_send_mode_defaults_to_sendto() {
        let cfg: Config = toml::from_str(&link_toml("")).expect("parse");
        assert_eq!(cfg.links[0].tx_send_mode, TxSendMode::Sendto);
    }

    #[test]
    fn tx_send_mode_sendmmsg_parses_from_toml() {
        let cfg: Config =
            toml::from_str(&link_toml(r#"tx_send_mode = "sendmmsg""#)).expect("parse");
        assert_eq!(cfg.links[0].tx_send_mode, TxSendMode::Sendmmsg);
        let cfg: Config = toml::from_str(&link_toml(r#"tx_send_mode = "sendto""#)).expect("parse");
        assert_eq!(cfg.links[0].tx_send_mode, TxSendMode::Sendto);
    }

    #[test]
    fn tx_send_mode_sendmmsg_gso_parses_from_toml() {
        let cfg: Config =
            toml::from_str(&link_toml(r#"tx_send_mode = "sendmmsg_gso""#)).expect("parse");
        assert_eq!(cfg.links[0].tx_send_mode, TxSendMode::SendmmsgGso);
    }

    #[test]
    fn tx_send_mode_rejects_unknown_value() {
        for bad in ["sendmsg", "SENDMMSG", "gso", ""] {
            let toml_str = link_toml(&format!(r#"tx_send_mode = "{bad}""#));
            assert!(
                toml::from_str::<Config>(&toml_str).is_err(),
                "tx_send_mode {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn fec_parity_outside_one_or_two_is_rejected_when_fec_is_on() {
        for bad in [0u8, 3, 255] {
            let mut cfg = minimal_valid_config();
            cfg.scheduler.fec_enabled = true;
            cfg.scheduler.fec_parity = bad;
            assert!(
                cfg.validate().is_err(),
                "fec_parity {bad} should be rejected"
            );
        }
        for good in [1u8, 2] {
            let mut cfg = minimal_valid_config();
            cfg.scheduler.fec_enabled = true;
            cfg.scheduler.fec_parity = good;
            assert!(
                cfg.validate().is_ok(),
                "fec_parity {good} should be accepted"
            );
        }
    }

    #[test]
    fn fec_group_size_within_range_is_accepted() {
        let mut cfg = minimal_valid_config();
        cfg.scheduler.fec_enabled = true;
        cfg.scheduler.fec_group_size = 16;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn link_config_requires_its_own_key_fields() {
        let toml = r#"
            mode = "client"
            [tunnel]
            name = "test"
            address = "10.200.0.1/30"
            [[links]]
            name = "comcast"
            bind_interface = "eth0"
            remote_addr = "127.0.0.1:9999"
            local_port = 51820
            private_key_file = "/tmp/does-not-matter-for-this-test.key"
            peer_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "#;
        let cfg: Config = toml::from_str(toml).expect("per-link key fields must parse");
        assert_eq!(
            cfg.links[0].peer_public_key,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn dual_stack_is_server_side_only() {
        let mut cfg = minimal_valid_config();
        cfg.links[0].dual_stack = true;
        // Client mode (the fixture's default), with a remote_addr: rejected.
        assert!(cfg.validate().unwrap_err().to_string().contains("dual_stack"));
        cfg.mode = Mode::Server;
        assert!(cfg.validate().is_err(), "remote_addr set: still rejected");
        cfg.links[0].remote_addr = None;
        cfg.validate().expect("server link without remote_addr");
        cfg.links[0].local_addr = Some("::".into());
        cfg.validate().expect("\"::\" is what dual_stack binds anyway");
        cfg.links[0].local_addr = Some("204.52.221.1".into());
        assert!(cfg.validate().is_err(), "a specific local_addr can't be dual-stack");
    }
}
