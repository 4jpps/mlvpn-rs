//! Wire format for mlvpn frames -- the plaintext that gets encrypted as a
//! whole by each link's own WireGuard tunnel (see `wireguard.rs`), not the
//! bytes actually visible on the wire (those are `boringtun`'s own
//! WireGuard transport-message format: a 16-byte header plus this entire
//! frame as AEAD ciphertext plus a 16-byte Poly1305 tag -- see
//! `wireguard::WG_OVERHEAD_BYTES`).
//!
//! Every mlvpn frame, before encryption, looks like:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Magic (1)    |  Ver (1)    |   Type (1)  |   LinkId (1)      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Sequence Number (64)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Payload ...                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `Type` and `LinkId` are **not** separately-transmitted plaintext dispatch
//! metadata the way they were under the old shared Noise_IK design (where
//! `snow`'s `StatelessTransportState` had no AAD parameter to bind them
//! to). Under the current per-link WireGuard transport, `wireguard::
//! WgTunnel::encapsulate` takes this entire serialized frame -- header
//! included -- as its plaintext input and encrypts it as one unit
//! (`link::LinkHandle::wg_send`), so `Type`, `LinkId`, and `Sequence
//! Number` are all fully covered by WireGuard's own AEAD tag on the wire,
//! the same as the payload itself: an attacker cannot tamper with any
//! header field without the receiving `WgTunnel::decapsulate` rejecting
//! the whole frame. This is actually a stronger property than the old
//! design had, not merely a different one. Each physical link
//! authenticates independently via its own WireGuard tunnel, with no
//! shared tunnel-wide session and no `session_id` field at all -- see
//! `ARCHITECTURE.md` §4 for the current crypto design.
//!
//! The 64-bit sequence number is a single tunnel-wide monotonic counter
//! (`tunnel::next_send_seq`), shared across every packet type on every
//! link -- not per-link. This is what lets `ReorderBuffer` detect genuine
//! cross-link reordering (the same logical stream arriving out of order
//! because different packets took different physical paths). It is
//! unrelated to, and does not need to agree with, any per-link
//! WireGuard-internal nonce/counter, which is entirely private to that
//! link's own `WgTunnel`/`boringtun::Tunn` and serves as the actual AEAD
//! nonce for that link's ciphertext.

use crate::error::{MlvpnError, Result};

pub const MAGIC: u8 = 0x4D; // 'M'
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 1 + 1 + 1 + 1 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    HandshakeInit = 1,
    HandshakeResp = 2,
    Data = 3,
    Probe = 4,
    ProbeReply = 5,
    Keepalive = 6,
    Disconnect = 7,
    /// One side's locally-measured stats for a single link, sent
    /// periodically so the *peer's* monitoring TUI can show a full-duplex
    /// view instead of only what it can measure itself. See
    /// `StatsPayload` below and `ipc.rs`/`control.rs` for how this
    /// surfaces to `mlvpn-tui`. AEAD-protected like every other
    /// post-handshake frame, for the same reason Probe is: an
    /// unauthenticated stats channel would let an off-path attacker feed
    /// fabricated numbers into the peer's monitoring display.
    StatsShare = 8,
    // 9 and 10 were BandwidthProbeBurst/BandwidthProbeResult, a
    // separate fixed-packet-count-burst mechanism for
    // `scheduler.active_bandwidth_probing` -- removed in favor of
    // reusing ThroughputTestData/ThroughputTestResult below for both
    // the periodic automatic probe and the on-demand `mlvpnd
    // self-test`. A fixed small packet count completes in well under
    // one round trip on a fast link, which measures local send-side
    // overhead more than the path's real sustained capacity -- see
    // `tunnel::active_bandwidth_prober`'s doc comment. Not reused for
    // anything else: an old peer sending one of these degrades the
    // same way any unrecognized `ptype` already does (silently
    // dropped), same as any other version-skew case this project
    // already tolerates.
    /// One packet of an on-demand throughput-measurement stream --
    /// either the on-demand `mlvpnd self-test`
    /// (`ipc::Command::RunThroughputTest`) or the periodic automatic
    /// probe (`scheduler.active_bandwidth_probing`, off by default,
    /// see `tunnel::active_bandwidth_prober`), both of which now share
    /// this exact same wire mechanism and send/receive code
    /// (`tunnel::send_throughput_test_stream`,
    /// `tunnel::handle_incoming`'s handling of this variant). Time-
    /// bounded rather than packet-count-bounded -- the total packet
    /// count isn't known ahead of time, so `ThroughputTestDataPayload`
    /// carries a `done` flag on its final packet(s) instead of a
    /// packet-count field -- which is what lets the same short stream
    /// scale naturally to whatever a link can actually do, fast or
    /// slow, instead of needing a manually-tuned packet count.
    ThroughputTestData = 11,
    /// The receiver's measured achieved throughput for a just-completed
    /// `ThroughputTestData` stream, sent back to whichever address the
    /// stream actually came from. See `ThroughputTestResultPayload`.
    ThroughputTestResult = 12,
    /// Sent by whichever side triggered a bidirectional throughput test
    /// (`Command::RunThroughputTest { bidirectional: true, .. }`), asking
    /// the peer to run its own `ThroughputTestData` stream back for the
    /// reverse-direction leg. See `ThroughputTestReverseRequestPayload`.
    ThroughputTestReverseRequest = 13,
    /// One side's own `mlvpnd` version, sent once right after the
    /// session is established and periodically afterward (piggybacked
    /// on the same per-link timer as `StatsShare`, for the same
    /// multi-link redundancy). Lets `mlvpn-tui` show both sides'
    /// versions and flag a mismatch, and lets a self-test that times
    /// out still report the peer's last-known version instead of
    /// leaving the caller to guess whether version skew is the cause --
    /// the self-test's own on-demand reply can't answer that question
    /// precisely when it's the thing failing to arrive at all. See
    /// `VersionInfoPayload`.
    VersionInfo = 14,
    /// One XOR parity frame covering a group of `fec_group_size`
    /// sequential real Data frames -- see `fec.rs`. Payload is a
    /// `FecParityPayload`. Only ever sent when `scheduler.fec_enabled`
    /// is true; an older peer that doesn't recognize this variant hits
    /// the existing unrecognized-`ptype` path (silently dropped), the
    /// same degrade-gracefully behavior every other unrecognized frame
    /// type already gets.
    FecParity = 15,
}

impl PacketType {
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::HandshakeInit,
            2 => Self::HandshakeResp,
            3 => Self::Data,
            4 => Self::Probe,
            5 => Self::ProbeReply,
            6 => Self::Keepalive,
            7 => Self::Disconnect,
            8 => Self::StatsShare,
            // 9, 10: see the removed BandwidthProbeBurst/Result variants'
            // comment above -- an old peer that still sends one of these
            // just hits the `other` arm below, same as any unrecognized
            // `ptype`.
            11 => Self::ThroughputTestData,
            12 => Self::ThroughputTestResult,
            13 => Self::ThroughputTestReverseRequest,
            14 => Self::VersionInfo,
            15 => Self::FecParity,
            other => {
                return Err(MlvpnError::Protocol(format!(
                    "unknown packet type byte {other}"
                )))
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub ptype: PacketType,
    /// Which physical link the sender transmitted this frame on. Used by
    /// the receiver purely for stats bookkeeping (RTT/jitter per link);
    /// it has no bearing on decryption.
    pub link_id: u8,
    pub seq: u64,
}

impl Header {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(MAGIC);
        out.push(VERSION);
        out.push(self.ptype as u8);
        out.push(self.link_id);
        out.extend_from_slice(&self.seq.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8])> {
        if buf.len() < HEADER_LEN {
            return Err(MlvpnError::Protocol("frame shorter than header".into()));
        }
        if buf[0] != MAGIC {
            return Err(MlvpnError::Protocol("bad magic byte".into()));
        }
        if buf[1] != VERSION {
            return Err(MlvpnError::Protocol(format!(
                "unsupported protocol version {}",
                buf[1]
            )));
        }
        let ptype = PacketType::from_u8(buf[2])?;
        let link_id = buf[3];
        let seq = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        Ok((
            Header {
                ptype,
                link_id,
                seq,
            },
            &buf[HEADER_LEN..],
        ))
    }
}

/// Payload of a Probe/ProbeReply frame, used by the latency monitor.
/// Encoded as plain bytes inside the (still AEAD-encrypted) payload.
#[derive(Debug, Clone, Copy)]
pub struct ProbePayload {
    pub probe_seq: u32,
    /// Sender's monotonic clock timestamp in nanoseconds when the probe (or
    /// reply) was sent. Only meaningful to the side that reads its own
    /// timestamps back; we never trust the peer's clock, only round-trip
    /// deltas measured against our own clock.
    pub send_ts_ns: u64,
}

impl ProbePayload {
    pub const LEN: usize = 4 + 8;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..4].copy_from_slice(&self.probe_seq.to_be_bytes());
        out[4..12].copy_from_slice(&self.send_ts_ns.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::LEN {
            return Err(MlvpnError::Protocol("probe payload too short".into()));
        }
        Ok(Self {
            probe_seq: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            send_ts_ns: u64::from_be_bytes(buf[4..12].try_into().unwrap()),
        })
    }
}

/// Payload of a `StatsShare` frame: one side's locally-measured stats for
/// a single link, so the peer's `mlvpn-tui` can display a full-duplex
/// view. Fixed-size and manually encoded (rather than pulling `bincode`/
/// `serde` into the wire format) to keep this consistent with the rest of
/// the protocol and avoid a second serialization scheme on the data path.
///
/// Deliberately keyed to the *receiving* socket's link index rather than
/// any index the sender includes (see `tunnel.rs::handle_incoming`): each
/// link is a dedicated point-to-point UDP socket pairing, so whichever
/// local link a frame arrived on already unambiguously identifies the
/// physical link, regardless of how the two sides' `[[links]]` happen to
/// be ordered in their own configs. `name` is carried anyway purely for
/// display, since the peer's name for a link doesn't have to match ours.
#[derive(Debug, Clone, Copy)]
pub struct StatsPayload {
    pub name: [u8; Self::NAME_LEN],
    pub rtt_ms: f32,
    pub jitter_ms: f32,
    pub loss_pct: f32,
    pub throughput_mbps: f32,
    /// Wire encoding of `link::LinkState` (0 = Probing, 1 = Up, 2 =
    /// Down) -- see `link::LinkState::to_wire`/`from_wire`.
    pub state: u8,
}

impl StatsPayload {
    pub const NAME_LEN: usize = 16;
    pub const LEN: usize = Self::NAME_LEN + 4 * 4 + 1;

    /// Truncate (to `NAME_LEN` bytes, on a UTF-8 boundary) and zero-pad a
    /// link name for the fixed-size wire field.
    pub fn encode_name(name: &str) -> [u8; Self::NAME_LEN] {
        let mut out = [0u8; Self::NAME_LEN];
        let mut end = name.len().min(Self::NAME_LEN);
        while end > 0 && !name.is_char_boundary(end) {
            end -= 1;
        }
        out[..end].copy_from_slice(&name.as_bytes()[..end]);
        out
    }

    pub fn name_str(&self) -> String {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(Self::NAME_LEN);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        let mut off = 0;
        out[off..off + Self::NAME_LEN].copy_from_slice(&self.name);
        off += Self::NAME_LEN;
        out[off..off + 4].copy_from_slice(&self.rtt_ms.to_be_bytes());
        off += 4;
        out[off..off + 4].copy_from_slice(&self.jitter_ms.to_be_bytes());
        off += 4;
        out[off..off + 4].copy_from_slice(&self.loss_pct.to_be_bytes());
        off += 4;
        out[off..off + 4].copy_from_slice(&self.throughput_mbps.to_be_bytes());
        off += 4;
        out[off] = self.state;
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::LEN {
            return Err(MlvpnError::Protocol("stats payload too short".into()));
        }
        let mut name = [0u8; Self::NAME_LEN];
        name.copy_from_slice(&buf[0..Self::NAME_LEN]);
        let mut off = Self::NAME_LEN;
        let rtt_ms = f32::from_be_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let jitter_ms = f32::from_be_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let loss_pct = f32::from_be_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let throughput_mbps = f32::from_be_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let state = buf[off];
        Ok(Self {
            name,
            rtt_ms,
            jitter_ms,
            loss_pct,
            throughput_mbps,
            state,
        })
    }
}

/// Payload of a `VersionInfo` frame: the sender's own `mlvpnd` version
/// (`env!("CARGO_PKG_VERSION")`), e.g. `"0.4.5"`. Fixed-size and
/// zero-padded exactly like `StatsPayload::name` above -- same
/// truncate-on-a-UTF-8-boundary encoding, same null-terminated
/// decoding -- there's no realistic version string anywhere close to
/// `VERSION_LEN` bytes, so truncation is a non-issue in practice.
#[derive(Debug, Clone)]
pub struct VersionInfoPayload {
    pub version: [u8; Self::VERSION_LEN],
    /// The sender's own raw, pre-negotiation local link capability
    /// (`tunnel::local_capability_mtu`) -- what `control::negotiate_tunnel_mtu`
    /// on *both* sides feeds in as input. Deliberately NOT the sender's
    /// already-negotiated `live_tunnel_mtu` (below): advertising the
    /// post-negotiation value here would create a monotonic ratchet
    /// (each side would advertise its own past concession instead of
    /// its true capability, permanently pinning the tunnel MTU low
    /// after any single downward negotiation, e.g. a failover, even
    /// once local capacity recovered) -- see the "CRITICAL" finding in
    /// commit 420407b and docs/superpowers/specs/2026-09-16-primary-aware-peer-mtu-design.md.
    pub tunnel_mtu: u16,
    /// The sender's own actual, already-negotiated live tunnel MTU
    /// (`tunnel::LiveMtu` -- what's really applied to the TUN device
    /// right now), added alongside `tunnel_mtu` specifically so a
    /// receiver can tell "peer's capability differs from mine" (normal,
    /// expected whenever link characteristics are asymmetric -- see
    /// `tunnel_mtu`'s own doc comment) apart from "peer hasn't actually
    /// converged to the same applied value yet" (a real problem worth
    /// surfacing). `0` means the sender predates this field (decoded
    /// from a shorter buffer) -- treated as "unknown", not a real MTU,
    /// same convention as `tunnel_mtu`'s own zero-sentinel.
    pub live_tunnel_mtu: u16,
    /// The sender's own currently-selected primary link's *name*
    /// (`LinkConfig::name`), when it's running `scheduler.primary_link_mode`.
    /// An all-zero array (empty string once decoded -- see
    /// `primary_link_name_str`) means the sender has no primary selected
    /// right now -- either it isn't running `primary_link_mode` at all, or
    /// it is but hasn't picked one yet.
    ///
    /// Deliberately a name, not a wire `link_id`/local array index:
    /// `link_id` is assigned per-host from each host's own `[[link]]`
    /// config order (see `main.rs`), so it is *not* a namespace shared
    /// between peers -- two hosts can easily configure their links in a
    /// different order, in which case the same numeric id means two
    /// different physical links on each side. A link name is the only
    /// value in this handshake both sides can meaningfully agree on.
    pub primary_link_name: [u8; Self::LINK_NAME_LEN],
}

impl VersionInfoPayload {
    pub const VERSION_LEN: usize = 16;
    /// Same size class as `VERSION_LEN` -- plenty for typical link names
    /// like "comcast"/"tmobile"/"starlink".
    pub const LINK_NAME_LEN: usize = 16;
    /// `+ 2` for `tunnel_mtu`, `+ 2` for `live_tunnel_mtu` -- the latter
    /// appended after `primary_link_name` (not next to `tunnel_mtu`) so
    /// the existing `tunnel_mtu`/`primary_link_name` byte offsets never
    /// move, matching this struct's established append-only extension
    /// pattern (see `decode`'s own doc comment).
    pub const LEN: usize = Self::VERSION_LEN + 2 + Self::LINK_NAME_LEN + 2;

    pub fn encode_version(version: &str) -> [u8; Self::VERSION_LEN] {
        let mut out = [0u8; Self::VERSION_LEN];
        let mut end = version.len().min(Self::VERSION_LEN);
        while end > 0 && !version.is_char_boundary(end) {
            end -= 1;
        }
        out[..end].copy_from_slice(&version.as_bytes()[..end]);
        out
    }

    pub fn version_str(&self) -> String {
        let end = self
            .version
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(Self::VERSION_LEN);
        String::from_utf8_lossy(&self.version[..end]).into_owned()
    }

    /// Same truncate-on-a-UTF-8-boundary, null-padded encoding as
    /// `encode_version` above, sized for `LINK_NAME_LEN` instead. Pass an
    /// empty string to encode the "no primary selected" sentinel.
    pub fn encode_link_name(name: &str) -> [u8; Self::LINK_NAME_LEN] {
        let mut out = [0u8; Self::LINK_NAME_LEN];
        let mut end = name.len().min(Self::LINK_NAME_LEN);
        while end > 0 && !name.is_char_boundary(end) {
            end -= 1;
        }
        out[..end].copy_from_slice(&name.as_bytes()[..end]);
        out
    }

    /// Decodes `primary_link_name` the same way `version_str` decodes
    /// `version`, but returns `None` for the empty-string case -- this is
    /// the "sender has no primary link selected right now" sentinel (an
    /// all-zero/empty-after-truncation field), replacing the old
    /// `NO_PRIMARY: u8` sentinel from before this field was name-based.
    pub fn primary_link_name_str(&self) -> Option<String> {
        let end = self
            .primary_link_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(Self::LINK_NAME_LEN);
        if end == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&self.primary_link_name[..end]).into_owned())
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..Self::VERSION_LEN].copy_from_slice(&self.version);
        out[Self::VERSION_LEN..Self::VERSION_LEN + 2]
            .copy_from_slice(&self.tunnel_mtu.to_be_bytes());
        out[Self::VERSION_LEN + 2..Self::VERSION_LEN + 2 + Self::LINK_NAME_LEN]
            .copy_from_slice(&self.primary_link_name);
        let live_mtu_start = Self::VERSION_LEN + 2 + Self::LINK_NAME_LEN;
        out[live_mtu_start..live_mtu_start + 2]
            .copy_from_slice(&self.live_tunnel_mtu.to_be_bytes());
        out
    }

    /// Tolerant of a shorter-than-current buffer from an older
    /// (pre-0.6.0) peer: only the `version` field is strictly required.
    /// `tunnel_mtu`/`live_tunnel_mtu` default to `0` and `primary_link_name`
    /// defaults to the "no primary" sentinel when the buffer doesn't
    /// carry them. Without this, a newly-upgraded host talking to an
    /// old peer would go completely blind on version/MTU/primary-link
    /// display right when that visibility matters most for catching a
    /// version-skewed deployment (this project's own real-world
    /// upgrade pattern is one host at a time, sometimes up to an hour
    /// apart).
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::VERSION_LEN {
            return Err(MlvpnError::Protocol(
                "version info payload too short".into(),
            ));
        }
        let mut version = [0u8; Self::VERSION_LEN];
        version.copy_from_slice(&buf[0..Self::VERSION_LEN]);

        let tunnel_mtu = if buf.len() >= Self::VERSION_LEN + 2 {
            u16::from_be_bytes([buf[Self::VERSION_LEN], buf[Self::VERSION_LEN + 1]])
        } else {
            0
        };

        let mut primary_link_name = [0u8; Self::LINK_NAME_LEN];
        let name_start = Self::VERSION_LEN + 2;
        let name_end = name_start + Self::LINK_NAME_LEN;
        if buf.len() >= name_end {
            primary_link_name.copy_from_slice(&buf[name_start..name_end]);
        } else if buf.len() > name_start {
            let have = buf.len() - name_start;
            primary_link_name[..have].copy_from_slice(&buf[name_start..buf.len()]);
        }

        let live_mtu_start = name_end;
        let live_tunnel_mtu = if buf.len() >= live_mtu_start + 2 {
            u16::from_be_bytes([buf[live_mtu_start], buf[live_mtu_start + 1]])
        } else {
            0
        };

        Ok(Self {
            version,
            tunnel_mtu,
            live_tunnel_mtu,
            primary_link_name,
        })
    }
}

/// Payload of a `FecParity` frame -- one XOR parity share covering
/// `member_seqs.len()` sequential real Data frames. See `fec.rs` for
/// how this is produced (sender) and consumed (receiver).
///
/// Variable-length (unlike every other payload in this file): the
/// number of members is `scheduler.fec_group_size`, itself configurable
/// (2..=255), and `parity`'s length is the longest member frame's own
/// length, which varies with real traffic (a TCP ACK-only packet vs. a
/// full-MTU segment). Self-describing on the wire (its own encoded
/// `member_seqs.len()`, not a value from local config) so a receiver
/// parses correctly even if its own `fec_group_size` differs from the
/// sender's, or if `fec_enabled` is only turned on on one side during a
/// rolling upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecParityPayload {
    pub member_seqs: Vec<u64>,
    pub member_lens: Vec<u16>,
    pub parity: Vec<u8>,
}

impl FecParityPayload {
    pub fn encode(&self) -> Vec<u8> {
        let group_size = self.member_seqs.len() as u8;
        let mut out = Vec::with_capacity(1 + self.member_seqs.len() * 10 + 2 + self.parity.len());
        out.push(group_size);
        for &seq in &self.member_seqs {
            out.extend_from_slice(&seq.to_be_bytes());
        }
        for &len in &self.member_lens {
            out.extend_from_slice(&len.to_be_bytes());
        }
        out.extend_from_slice(&(self.parity.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.parity);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(MlvpnError::Protocol("fec parity payload empty".into()));
        }
        let group_size = buf[0] as usize;
        let seqs_end = 1 + group_size * 8;
        let lens_end = seqs_end + group_size * 2;
        if buf.len() < lens_end + 2 {
            return Err(MlvpnError::Protocol(
                "fec parity payload too short for its own declared group_size".into(),
            ));
        }
        let mut member_seqs = Vec::with_capacity(group_size);
        for i in 0..group_size {
            let start = 1 + i * 8;
            member_seqs.push(u64::from_be_bytes(
                buf[start..start + 8].try_into().unwrap(),
            ));
        }
        let mut member_lens = Vec::with_capacity(group_size);
        for i in 0..group_size {
            let start = seqs_end + i * 2;
            member_lens.push(u16::from_be_bytes(
                buf[start..start + 2].try_into().unwrap(),
            ));
        }
        let parity_len =
            u16::from_be_bytes(buf[lens_end..lens_end + 2].try_into().unwrap()) as usize;
        if buf.len() < lens_end + 2 + parity_len {
            return Err(MlvpnError::Protocol(
                "fec parity payload shorter than its own declared parity_len".into(),
            ));
        }
        let parity = buf[lens_end + 2..lens_end + 2 + parity_len].to_vec();
        Ok(Self {
            member_seqs,
            member_lens,
            parity,
        })
    }
}

/// Payload of one packet in a `ThroughputTestData` stream (see
/// `tunnel::send_throughput_test_stream`). The header is fixed at
/// `HEADER_LEN` bytes; callers pad the remainder out to the tunnel's
/// MTU with zero bytes so the stream actually exercises the link at
/// realistic packet sizes instead of measuring small-packet overhead.
#[derive(Debug, Clone, Copy)]
pub struct ThroughputTestDataPayload {
    /// Identifies one test run; freshly randomized per test (per
    /// direction -- a bidirectional test uses two distinct `test_id`s,
    /// one per leg) so a stray late packet from an earlier run can never
    /// be mistaken for part of a new one.
    pub test_id: u32,
    /// Set on the final packet(s) of the stream -- the sender's
    /// duration timer has elapsed and this is the last one it's
    /// sending. Repeated a couple of extra times as cheap insurance
    /// against exactly one final packet getting lost, same reasoning
    /// (and same receive-side last-completed-test-id guard) as
    /// `active_bandwidth_prober`'s own final-packet redundancy.
    pub done: bool,
}

impl ThroughputTestDataPayload {
    pub const HEADER_LEN: usize = 4 + 1;

    pub fn encode_padded(&self, total_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; total_len.max(Self::HEADER_LEN)];
        out[0..4].copy_from_slice(&self.test_id.to_be_bytes());
        out[4] = self.done as u8;
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::HEADER_LEN {
            return Err(MlvpnError::Protocol(
                "throughput test data payload too short".into(),
            ));
        }
        Ok(Self {
            test_id: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            done: buf[4] != 0,
        })
    }
}

/// Payload of a `ThroughputTestResult` frame: the receiver's measured
/// achieved throughput for a just-completed `ThroughputTestData`
/// stream, sent back to whichever address the stream actually arrived
/// from. See `tunnel::handle_incoming`'s handling of this variant for
/// why this is delivered both back over the wire *and* to a locally
/// registered waiter, if one exists, in the same step.
#[derive(Debug, Clone, Copy)]
pub struct ThroughputTestResultPayload {
    pub test_id: u32,
    pub achieved_mbps: f32,
}

impl ThroughputTestResultPayload {
    pub const LEN: usize = 4 + 4;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..4].copy_from_slice(&self.test_id.to_be_bytes());
        out[4..8].copy_from_slice(&self.achieved_mbps.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::LEN {
            return Err(MlvpnError::Protocol(
                "throughput test result payload too short".into(),
            ));
        }
        Ok(Self {
            test_id: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            achieved_mbps: f32::from_be_bytes(buf[4..8].try_into().unwrap()),
        })
    }
}

/// Payload of a `ThroughputTestReverseRequest` frame: asks the peer to
/// run its own `ThroughputTestData` stream back to us, for the
/// reverse-direction leg of a bidirectional throughput test. See
/// `tunnel::handle_incoming`'s handling of this variant.
#[derive(Debug, Clone, Copy)]
pub struct ThroughputTestReverseRequestPayload {
    /// The `test_id` to tag the reverse stream with -- distinct from
    /// the forward leg's own `test_id`, so the two legs' measurements
    /// (and any stray late packets from either) can never be confused
    /// with each other.
    pub test_id: u32,
    pub duration_secs: u32,
}

impl ThroughputTestReverseRequestPayload {
    pub const LEN: usize = 4 + 4;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..4].copy_from_slice(&self.test_id.to_be_bytes());
        out[4..8].copy_from_slice(&self.duration_secs.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::LEN {
            return Err(MlvpnError::Protocol(
                "throughput test reverse request payload too short".into(),
            ));
        }
        Ok(Self {
            test_id: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            duration_secs: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let hdr = Header {
            ptype: PacketType::Data,
            link_id: 3,
            seq: 42,
        };
        let mut buf = Vec::new();
        hdr.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN);
        let (decoded, rest) = Header::decode(&buf).unwrap();
        assert_eq!(decoded.ptype, PacketType::Data);
        assert_eq!(decoded.link_id, 3);
        assert_eq!(decoded.seq, 42);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_round_trips_with_large_seq() {
        let hdr = Header {
            ptype: PacketType::Probe,
            link_id: 255,
            seq: 0xdeadbeefcafebabe,
        };
        let mut buf = Vec::new();
        hdr.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN);
        let (decoded, rest) = Header::decode(&buf).unwrap();
        assert_eq!(decoded.ptype, PacketType::Probe);
        assert_eq!(decoded.link_id, 255);
        assert_eq!(decoded.seq, 0xdeadbeefcafebabe);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_has_correct_magic_and_version() {
        let hdr = Header {
            ptype: PacketType::Data,
            link_id: 1,
            seq: 100,
        };
        let mut buf = Vec::new();
        hdr.encode(&mut buf);
        assert_eq!(buf[0], MAGIC);
        assert_eq!(buf[1], VERSION);
    }

    #[test]
    fn header_decode_rejects_short_buffer() {
        let buf = [0u8; 11];
        assert!(Header::decode(&buf).is_err());
    }

    #[test]
    fn header_decode_rejects_bad_magic() {
        let mut buf = vec![0u8; HEADER_LEN];
        buf[0] = 0xFF;
        assert!(Header::decode(&buf).is_err());
    }

    #[test]
    fn header_decode_rejects_bad_version() {
        let buf = vec![MAGIC, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(Header::decode(&buf).is_err());
    }
}

#[cfg(test)]
mod throughput_test_payload_tests {
    use super::*;

    #[test]
    fn data_payload_round_trips_through_padding_not_done() {
        let payload = ThroughputTestDataPayload {
            test_id: 0xdead_beef,
            done: false,
        };
        let encoded = payload.encode_padded(1400);
        assert_eq!(encoded.len(), 1400);
        let decoded = ThroughputTestDataPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.test_id, payload.test_id);
        assert!(!decoded.done);
    }

    #[test]
    fn data_payload_round_trips_done_flag() {
        let payload = ThroughputTestDataPayload {
            test_id: 7,
            done: true,
        };
        let encoded = payload.encode_padded(64);
        let decoded = ThroughputTestDataPayload::decode(&encoded).unwrap();
        assert!(decoded.done);
    }

    #[test]
    fn data_payload_encode_padded_never_truncates_header() {
        let payload = ThroughputTestDataPayload {
            test_id: 1,
            done: false,
        };
        let encoded = payload.encode_padded(0);
        assert_eq!(encoded.len(), ThroughputTestDataPayload::HEADER_LEN);
        assert!(ThroughputTestDataPayload::decode(&encoded).is_ok());
    }

    #[test]
    fn data_payload_decode_rejects_short_buffer() {
        let buf = [0u8; 3];
        assert!(ThroughputTestDataPayload::decode(&buf).is_err());
    }

    #[test]
    fn result_payload_round_trips() {
        let payload = ThroughputTestResultPayload {
            test_id: 99,
            achieved_mbps: 941.3,
        };
        let encoded = payload.encode();
        let decoded = ThroughputTestResultPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.test_id, payload.test_id);
        assert!((decoded.achieved_mbps - payload.achieved_mbps).abs() < f32::EPSILON);
    }

    #[test]
    fn result_payload_decode_rejects_short_buffer() {
        let buf = [0u8; 4];
        assert!(ThroughputTestResultPayload::decode(&buf).is_err());
    }

    #[test]
    fn reverse_request_payload_round_trips() {
        let payload = ThroughputTestReverseRequestPayload {
            test_id: 123,
            duration_secs: 10,
        };
        let encoded = payload.encode();
        let decoded = ThroughputTestReverseRequestPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.test_id, payload.test_id);
        assert_eq!(decoded.duration_secs, payload.duration_secs);
    }

    #[test]
    fn reverse_request_payload_decode_rejects_short_buffer() {
        let buf = [0u8; 4];
        assert!(ThroughputTestReverseRequestPayload::decode(&buf).is_err());
    }
}

#[cfg(test)]
mod version_info_payload_tests {
    use super::*;

    #[test]
    fn round_trips_a_typical_version_string() {
        let payload = VersionInfoPayload {
            version: VersionInfoPayload::encode_version("0.4.5"),
            tunnel_mtu: 1420,
            live_tunnel_mtu: 1300,
            primary_link_name: VersionInfoPayload::encode_link_name(""),
        };
        let encoded = payload.encode();
        let decoded = VersionInfoPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.version_str(), "0.4.5");
    }

    #[test]
    fn truncates_a_version_string_longer_than_the_wire_field() {
        let encoded = VersionInfoPayload::encode_version("0.4.5-some-very-long-prerelease-tag");
        let payload = VersionInfoPayload {
            version: encoded,
            tunnel_mtu: 1420,
            live_tunnel_mtu: 1300,
            primary_link_name: VersionInfoPayload::encode_link_name(""),
        };
        assert_eq!(payload.version_str().len(), VersionInfoPayload::VERSION_LEN);
    }

    #[test]
    fn decode_rejects_buffer_shorter_than_the_version_field() {
        let buf = [0u8; 3];
        assert!(VersionInfoPayload::decode(&buf).is_err());
    }

    #[test]
    fn decode_tolerates_a_pre_0_6_0_peer_sending_only_the_version_field() {
        // Simulates an older sender's shorter payload: exactly
        // VERSION_LEN bytes, nothing else -- must still decode instead of
        // failing closed, per the version-skew tolerance fix.
        let buf = VersionInfoPayload::encode_version("0.4.5");
        let decoded = VersionInfoPayload::decode(&buf).unwrap();
        assert_eq!(decoded.version_str(), "0.4.5");
        assert_eq!(decoded.tunnel_mtu, 0);
        assert_eq!(decoded.live_tunnel_mtu, 0);
        assert_eq!(decoded.primary_link_name_str(), None);
    }

    #[test]
    fn decode_tolerates_a_pre_2026_09_17_peer_with_no_live_tunnel_mtu_field() {
        // Simulates a peer running the version-exchange wire format
        // from just before `live_tunnel_mtu` was added: version + mtu +
        // primary_link_name, nothing after. Must still decode with
        // `live_tunnel_mtu` defaulting to the same "unknown" zero
        // sentinel `tunnel_mtu` itself uses for an even older peer.
        let mut buf = Vec::new();
        buf.extend_from_slice(&VersionInfoPayload::encode_version("0.7.3"));
        buf.extend_from_slice(&1420u16.to_be_bytes());
        buf.extend_from_slice(&VersionInfoPayload::encode_link_name("comcast"));
        let decoded = VersionInfoPayload::decode(&buf).unwrap();
        assert_eq!(decoded.version_str(), "0.7.3");
        assert_eq!(decoded.tunnel_mtu, 1420);
        assert_eq!(decoded.live_tunnel_mtu, 0);
        assert_eq!(decoded.primary_link_name_str(), Some("comcast".to_string()));
    }

    #[test]
    fn version_info_payload_round_trips_live_tunnel_mtu() {
        let payload = VersionInfoPayload {
            version: VersionInfoPayload::encode_version("0.7.3"),
            tunnel_mtu: 1305,
            live_tunnel_mtu: 1285,
            primary_link_name: VersionInfoPayload::encode_link_name(""),
        };
        let encoded = payload.encode();
        let decoded = VersionInfoPayload::decode(&encoded).unwrap();
        // The two fields are genuinely independent: capability (1305)
        // can differ from the actually-applied, already-negotiated
        // value (1285) -- see this struct's own doc comment for why
        // that's expected, not a bug.
        assert_eq!(decoded.tunnel_mtu, 1305);
        assert_eq!(decoded.live_tunnel_mtu, 1285);
    }

    #[test]
    fn decode_tolerates_a_buffer_with_mtu_but_no_primary_link_name() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&VersionInfoPayload::encode_version("0.5.0"));
        buf.extend_from_slice(&1420u16.to_be_bytes());
        let decoded = VersionInfoPayload::decode(&buf).unwrap();
        assert_eq!(decoded.version_str(), "0.5.0");
        assert_eq!(decoded.tunnel_mtu, 1420);
        assert_eq!(decoded.primary_link_name_str(), None);
    }

    #[test]
    fn version_info_payload_round_trips_tunnel_mtu() {
        let payload = VersionInfoPayload {
            version: VersionInfoPayload::encode_version("0.6.0"),
            tunnel_mtu: 1420,
            live_tunnel_mtu: 1300,
            primary_link_name: VersionInfoPayload::encode_link_name(""),
        };
        let encoded = payload.encode();
        let decoded = VersionInfoPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.tunnel_mtu, 1420);
        assert_eq!(decoded.version_str(), "0.6.0");
    }

    #[test]
    fn version_info_payload_round_trips_primary_link_name() {
        let payload = VersionInfoPayload {
            version: VersionInfoPayload::encode_version("0.7.0"),
            tunnel_mtu: 1420,
            live_tunnel_mtu: 1300,
            primary_link_name: VersionInfoPayload::encode_link_name("starlink"),
        };
        let encoded = payload.encode();
        let decoded = VersionInfoPayload::decode(&encoded).unwrap();
        assert_eq!(
            decoded.primary_link_name_str(),
            Some("starlink".to_string())
        );
    }

    #[test]
    fn version_info_payload_round_trips_no_primary_sentinel() {
        let payload = VersionInfoPayload {
            version: VersionInfoPayload::encode_version("0.7.0"),
            tunnel_mtu: 1420,
            live_tunnel_mtu: 1300,
            primary_link_name: VersionInfoPayload::encode_link_name(""),
        };
        let encoded = payload.encode();
        let decoded = VersionInfoPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.primary_link_name_str(), None);
    }

    #[test]
    fn primary_link_name_truncates_a_name_longer_than_the_wire_field() {
        let encoded = VersionInfoPayload::encode_link_name("a-genuinely-very-long-link-name");
        let payload = VersionInfoPayload {
            version: VersionInfoPayload::encode_version("0.7.0"),
            tunnel_mtu: 1420,
            live_tunnel_mtu: 1300,
            primary_link_name: encoded,
        };
        assert_eq!(
            payload.primary_link_name_str().unwrap().len(),
            VersionInfoPayload::LINK_NAME_LEN
        );
    }
}

#[cfg(test)]
mod fec_parity_payload_tests {
    use super::*;

    #[test]
    fn fec_parity_payload_round_trips() {
        let payload = FecParityPayload {
            member_seqs: vec![100, 101, 102, 103, 104, 105, 106, 107],
            member_lens: vec![64, 128, 64, 1400, 64, 64, 64, 512],
            parity: vec![0xAB; 1400],
        };
        let encoded = payload.encode();
        let decoded = FecParityPayload::decode(&encoded).expect("decode");
        assert_eq!(decoded.member_seqs, payload.member_seqs);
        assert_eq!(decoded.member_lens, payload.member_lens);
        assert_eq!(decoded.parity, payload.parity);
    }

    #[test]
    fn fec_parity_payload_decode_rejects_truncated_buffer() {
        let payload = FecParityPayload {
            member_seqs: vec![1, 2],
            member_lens: vec![10, 20],
            parity: vec![0u8; 20],
        };
        let mut encoded = payload.encode();
        encoded.truncate(encoded.len() - 5);
        assert!(FecParityPayload::decode(&encoded).is_err());
    }

    #[test]
    fn packet_type_fec_parity_round_trips_through_header() {
        let mut buf = Vec::new();
        Header {
            ptype: PacketType::FecParity,
            link_id: 0,
            seq: 42,
        }
        .encode(&mut buf);
        let (hdr, _) = Header::decode(&buf).expect("decode");
        assert_eq!(hdr.ptype, PacketType::FecParity);
    }
}
