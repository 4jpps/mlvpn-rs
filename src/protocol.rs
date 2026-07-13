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
//! `SessionId`, `Type` and `LinkId` are authenticated-but-not-encrypted
//! associated data (AAD) fed into the AEAD along with the sequence number;
//! `Payload` is the ciphertext (which includes the AEAD tag at its end) for
//! Data/Keepalive/Probe frames, or raw Noise handshake bytes for
//! Handshake frames (Noise protects its own handshake messages).
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

    /// Bytes fed to the AEAD as associated data: everything that must be
    /// authenticated but is not itself encrypted.
    pub fn aad(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN);
        self.encode(&mut v);
        v
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
