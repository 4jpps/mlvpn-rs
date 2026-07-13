//! Wire format for packets exchanged between mlvpn peers.
//!
//! Every on-the-wire packet (after the outer UDP header) looks like:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Magic (1)    |  Ver (1)    |   Type (1)  |   LinkId (1)      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Session Id (32)                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Sequence Number (64)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Payload ...                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `SessionId`, `Type` and `LinkId` are plaintext dispatch metadata, *not*
//! AEAD associated data -- `snow`'s `StatelessTransportState` (see
//! `crypto.rs`) doesn't expose an AAD parameter, so they aren't
//! cryptographically bound to the ciphertext. `Payload` is the ciphertext
//! (which includes the AEAD tag at its end) for Data/Keepalive/Probe/
//! ProbeReply frames, or raw Noise handshake bytes for Handshake frames
//! (Noise protects its own handshake messages). See `crypto.rs`'s module
//! doc comment for why this is an acceptable tradeoff: the sequence
//! number doubles as the AEAD nonce and is therefore implicitly
//! authenticated, which is what actually matters here.
//!
//! The 64-bit sequence number is global per session (not per-link): it is
//! what lets the receiver detect replay and reorder packets that arrive
//! out of order because they took different physical paths.

use crate::error::{MlvpnError, Result};

pub const MAGIC: u8 = 0x4D; // 'M'
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 1 + 1 + 1 + 1 + 4 + 8;

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
    pub session_id: u32,
    pub seq: u64,
}

impl Header {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(MAGIC);
        out.push(VERSION);
        out.push(self.ptype as u8);
        out.push(self.link_id);
        out.extend_from_slice(&self.session_id.to_be_bytes());
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
        let session_id = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let seq = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        Ok((
            Header {
                ptype,
                link_id,
                session_id,
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
