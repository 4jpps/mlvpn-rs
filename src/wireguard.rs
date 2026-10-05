//! Per-link WireGuard transport. Each configured `[[links]]` entry gets
//! its own independent `WgTunnel` -- its own keypair, handshake, rekey,
//! and replay window -- wrapping `boringtun::noise::Tunn`, the low-level
//! WireGuard protocol implementation that operates purely on byte
//! buffers with no kernel network interface, no netlink, and no policy
//! routing. mlvpn's own already-existing frame (header + seq +
//! PacketType + payload, see `protocol.rs`) is treated as an opaque
//! plaintext blob by this module -- it goes in exactly as serialized
//! before encryption, and comes back out byte-for-byte identical on
//! receive, so nothing above this module (the scheduler, the reorder
//! buffer, probing) needs to know WireGuard is involved at all.
//!
//! **A real, non-obvious `boringtun` behavior this module has to work
//! around, confirmed by reading `boringtun-0.7.1`'s own source
//! (`src/noise/mod.rs`), not assumed from its public docs:** `Tunn`'s
//! *encapsulate* side is a genuine opaque-byte-blob encryptor -- it never
//! looks at what's inside `src`. Its *decapsulate* side is not. Every
//! successfully decrypted DATA packet is run through
//! `Tunn::validate_decapsulated_packet`, which unconditionally
//! interprets the plaintext as a raw IPv4/IPv6 packet: it reads the
//! version nibble out of the first byte, and then reads a length field
//! at a fixed offset (assuming IHL=5, i.e. no options, for IPv4) to
//! decide how many bytes of the plaintext are "real" versus padding --
//! this is how real WireGuard truncates a TUN-device read back to its
//! original length after decryption. Anything that doesn't parse as a
//! plausible IP packet (including mlvpn's own frame format, which has no
//! such structure) either takes the `WireGuardError::InvalidPacket`
//! error path outright, or worse, gets silently *truncated* to whatever
//! garbage length the misinterpreted "length field" bytes happen to spell
//! out -- confirmed by direct source inspection of
//! `Tunn::validate_decapsulated_packet` (`src/noise/mod.rs`), not
//! observed as a symptom first.
//!
//! The fix kept entirely inside this module, so nothing above it needs
//! to know: `encapsulate` prepends a minimal, fake-but-well-formed
//! 20-byte IPv4 header (`FAKE_IPV4_HEADER_LEN`) in front of every real
//! plaintext frame before handing it to `Tunn::encapsulate` -- version/IHL
//! byte `0x45`, a correct total-length field covering header + frame,
//! all other fields zeroed (protocol number 253/`0xFD`, IANA's reserved
//! "for experimentation and testing" value, since this is never a real
//! IP packet and nothing downstream ever inspects it) -- and `decapsulate`
//! strips that same 20 bytes back off before returning
//! `DecapsulateOutcome::Frame`. `Tunn`'s own `WriteToTunnelV4`/`V6` split
//! is irrelevant here (mlvpn always emits the V4 form since it always
//! sets the version nibble to 4); both are still matched exhaustively for
//! safety, with `V6` treated as an unexpected-protocol error since this
//! module should never produce it. Zero-length WireGuard keepalives
//! (boringtun's own internal empty-payload data packets, used for both
//! the post-handshake confirmation and periodic keepalives) are
//! unaffected -- `validate_decapsulated_packet` special-cases a 0-length
//! plaintext as `Done` *before* it ever reaches the IP-parsing logic, so
//! they never need wrapping/unwrapping and surface here as
//! `DecapsulateOutcome::Consumed`, matching real WireGuard's own "nothing
//! to deliver, nothing to send" semantics for a bare keepalive ack.
//!
//! Note this workaround is specific to whatever `boringtun` version is
//! actually resolved (`0.7.1` as of this writing -- see `Cargo.toml`;
//! `0.6` was requested but failed to resolve against this project's
//! existing `curve25519-dalek 4.1.3` pin from `snow`, so `0.7` was used
//! instead). If `boringtun` is ever upgraded, re-verify
//! `validate_decapsulated_packet`'s behavior against the new version's
//! source before assuming this wrapping is still necessary or still
//! sufficient.

use crate::error::{MlvpnError, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// The outcome of feeding one received datagram to `WgTunnel::decapsulate`.
#[derive(Debug)]
pub enum DecapsulateOutcome {
    /// A decrypted mlvpn frame, ready to hand to `protocol::Header::decode`.
    Frame(Vec<u8>),
    /// boringtun consumed a handshake/keepalive message and produced a
    /// reply that must be sent back on this same link's socket (e.g. a
    /// handshake response, or the initiator's post-handshake keepalive
    /// confirmation). Caller sends this verbatim on the link's UDP socket.
    SendReply(Vec<u8>),
    /// Consumed (handshake progress, a bare keepalive ack, a duplicate,
    /// etc.), nothing to send and no plaintext frame produced.
    Consumed,
}

/// Result of `WgTunnel::decapsulate_into`: like `DecapsulateOutcome`, except
/// a decrypted frame was written into the caller's buffer rather than
/// returned by value.
#[derive(Debug)]
pub enum DecapsulateKind {
    Frame,
    SendReply(Vec<u8>),
    Consumed,
}

/// Minimal synthetic IPv4 header prepended to every plaintext frame before
/// it's handed to `boringtun`, and stripped back off on receive -- see
/// this module's own doc comment above for why this exists. `pub` so
/// callers computing real per-packet tunnel overhead (`control.rs`'s
/// `effective_tunnel_mtu`, `config.rs`'s MTU-fragmentation advisory check)
/// can account for this wrapping cost on top of `WG_OVERHEAD_BYTES`.
pub const FAKE_IPV4_HEADER_LEN: usize = 20;

/// boringtun protocol-number convention for our synthetic header:
/// IANA-reserved "for experimentation and testing" (RFC 3692), so it's
/// unambiguous that this was never a real IP packet, even though nothing
/// downstream actually inspects this field.
const FAKE_IPV4_PROTOCOL: u8 = 253;

/// Scratch buffer size for `decapsulate`/`tick`'s output, and the largest
/// incoming datagram `decapsulate` will accept.
///
/// **Not just a generous round number** -- sized to the same
/// `u16::MAX + 64` pattern `tunnel.rs`'s own TUN-read buffer uses (see
/// `tun_reader`'s comment there), and for the same reason: this project
/// treats frame sizes up to `u16::MAX` as a real, supported case (`mtu`
/// is itself a `u16`), not a theoretical one, so a buffer sized from a
/// "should be enough" constant instead of the real maximum would be a
/// live bug, not just defensive slop. This one was originally sized as a
/// plain `2048` in this module's first draft, which was wrong for a much
/// more serious reason than truncation risk: `boringtun`'s own
/// `Session::receive_packet_data` (`src/noise/session.rs`, confirmed by
/// direct source reading) does `if dst.len() < ct_len { panic!(...) }`
/// -- and that length check runs on the still-unauthenticated ciphertext
/// length, *before* AEAD verification. A buffer too small for an
/// oversized incoming datagram doesn't return an `Err` from
/// `decapsulate`, it panics the whole process, and it's reachable by any
/// unauthenticated third party sending a WireGuard-DATA-shaped datagram
/// at the link's socket -- not just a genuine peer. Sizing this to the
/// real maximum removes that risk entirely for anything this project
/// itself would ever legitimately send or receive; the explicit length
/// check in `decapsulate` below is the second, independent layer for
/// anything larger still (e.g. a raw UDP datagram from an attacker that
/// happens to exceed even this).
const MAX_WG_PACKET: usize = u16::MAX as usize + 64;

/// Real WireGuard per-packet overhead added by `WgTunnel::encapsulate`:
/// a 16-byte transport-message header (type + receiver index + counter)
/// plus a 16-byte Poly1305 AEAD tag.
pub const WG_OVERHEAD_BYTES: u32 = 32;

/// Writes the minimal fake IPv4 header (see module doc) for a payload of
/// `payload_len` bytes into `out`, replacing its previous contents. The
/// caller appends the payload itself right after, so the whole wrapped
/// packet is assembled in one reusable buffer with no intermediate `Vec`.
fn write_fake_ipv4_header(out: &mut Vec<u8>, payload_len: usize) -> Result<()> {
    let total_len = FAKE_IPV4_HEADER_LEN + payload_len;
    let total_len_u16 = u16::try_from(total_len).map_err(|_| {
        MlvpnError::Protocol(format!(
            "wg encapsulate: frame too large ({payload_len} bytes) to fit boringtun's fake IPv4 wrapper"
        ))
    })?;

    out.clear();
    out.push(0x45); // version 4, IHL 5 (20-byte header, no options)
    out.push(0x00); // DSCP/ECN
    out.extend_from_slice(&total_len_u16.to_be_bytes()); // total length
    out.extend_from_slice(&[0x00, 0x00]); // identification
    out.extend_from_slice(&[0x00, 0x00]); // flags/fragment offset
    out.push(64); // TTL, unused, arbitrary
    out.push(FAKE_IPV4_PROTOCOL);
    out.extend_from_slice(&[0x00, 0x00]); // header checksum, unchecked by boringtun
    out.extend_from_slice(&[0, 0, 0, 0]); // source address, unused
    out.extend_from_slice(&[0, 0, 0, 0]); // destination address, unused
    debug_assert_eq!(out.len(), FAKE_IPV4_HEADER_LEN);
    Ok(())
}

/// Everything guarded by `WgTunnel`'s one lock: the boringtun state plus the
/// scratch buffers its calls need. Keeping the scratch under the same lock
/// (already held for the duration of every encapsulate/decapsulate) means
/// the hot path allocates and zero-fills nothing per packet.
struct Inner {
    tunn: Tunn,
    /// Wrapped (fake-IPv4 + frame) plaintext being assembled for `encapsulate`.
    wrap_scratch: Vec<u8>,
    /// Ciphertext output for `encapsulate`. Only ever grown, never zeroed
    /// per call.
    enc_scratch: Vec<u8>,
    /// `MAX_WG_PACKET`-sized output for `decapsulate`/`tick`, allocated
    /// once. Needs the full size, not "typical" size: see
    /// `MAX_WG_PACKET`'s doc comment on boringtun's unauthenticated
    /// length-check panic.
    dec_scratch: Vec<u8>,
}

/// One physical link's independent WireGuard tunnel: its own keypair,
/// handshake state, session keys, and replay window, entirely separate
/// from every other link's `WgTunnel` and from the (soon to be retired)
/// shared Noise_IK session in `crypto.rs`.
pub struct WgTunnel {
    // boringtun::noise::Tunn's methods take &mut self; Mutex here is
    // *not* about cross-thread contention (each link's WgTunnel is only
    // ever touched by that one link's own send/receive tasks) -- it's
    // so WgTunnel::encapsulate/decapsulate/tick can take &self, matching
    // the call-site ergonomics the rest of this project already uses for
    // per-link state accessed from both a send path and a receive path
    // concurrently. Confirm against the real `Link` integration (a later
    // task) whether this is still needed once the real call sites are
    // wired up, or whether a plain `&mut self` is achievable there
    // instead.
    inner: Mutex<Inner>,
    /// Lifetime count of datagrams `decapsulate` rejected outright
    /// (`TunnResult::Err` -- bad MAC, replay-window miss, garbled data,
    /// oversized datagram). This class of loss was previously invisible
    /// to every one of mlvpn's own diagnostics: it never touches
    /// `outbound_queue_dropped_total` or the TUN device's `rx_dropped`/
    /// `tx_dropped` (both stay clean, since the rejection happens before
    /// a frame is ever handed to those layers), and the only trace was a
    /// `tracing::debug!` line -- added 2026-09-14 to give this real
    /// visibility after a live investigation found real TCP-level loss
    /// (~15% retransmission under load) with every existing counter
    /// reading zero. See `decapsulate`'s own `TunnResult::Err` arm.
    rejected_total: AtomicU64,
    /// Lifetime count of `encapsulate` calls that were handed real
    /// mlvpn plaintext but, per `boringtun::noise::Tunn::encapsulate`'s
    /// own source (confirmed by direct inspection, `src/noise/mod.rs`),
    /// had no current valid session at that moment -- so the plaintext
    /// was queued *internally* by boringtun and a handshake-initiation
    /// datagram was written to the network *instead*. `TunnResult::
    /// WriteToNetwork` covers both outcomes indistinguishably, so
    /// `encapsulate` reports the difference to its caller explicitly via
    /// the `bool` in its `(Vec<u8>, bool)` return (added 2026-09-15 --
    /// before that, `wg_send` saw an ordinary `Ok(())` identical to a
    /// real send, which let `tunnel::outbound_sender` accumulate phantom
    /// FEC group members). mlvpn's own `LinkStats::record_tx` still
    /// increments as if the frame was actually transmitted. This counter
    /// distinguishes the two by checking the outgoing datagram's own
    /// WireGuard message-type field (a data packet is type 4; anything
    /// else here means the real frame was substituted) -- added
    /// 2026-09-15 after `wg_rejected_total` (the receive-side rejection
    /// counter, added the same night) stayed at zero through two real
    /// loss-reproducing load tests, ruling out receive-side rejection
    /// and motivating a look at the send side instead.
    substituted_total: AtomicU64,
}

impl WgTunnel {
    /// `is_initiator` is accepted for call-site clarity but unused:
    /// confirmed via `boringtun-0.7.1`'s source that `Tunn` does not need
    /// to know which side initiates at construction time -- whichever
    /// side's `encapsulate()` is called first (with no session yet
    /// established) is the one that actually emits a handshake
    /// initiation in practice, regardless of this flag.
    pub fn new(local_private: [u8; 32], peer_public: [u8; 32], is_initiator: bool) -> Result<Self> {
        let _ = is_initiator;
        let static_private = x25519::StaticSecret::from(local_private);
        let peer_static_public = x25519::PublicKey::from(peer_public);
        // boringtun-0.7.1's `Tunn::new` is infallible (returns `Self`
        // directly, not a `Result`) -- differs from the brief's
        // draft, which assumed a fallible constructor matching an
        // older/hypothetical API shape. Kept this function's own return
        // type as `Result<Self>` regardless, since later tasks calling
        // `WgTunnel::new(...)?` shouldn't need to change if a future
        // boringtun version reintroduces fallibility here.
        let tunn = Tunn::new(
            static_private,
            peer_static_public,
            None, // no pre-shared key
            None, // use boringtun's default persistent-keepalive behavior
            0,    // index -- single tunnel per WgTunnel, 0 is fine
            None, // no rate limiter; mlvpn already rate-limits inbound
                  // handshake attempts itself (see tunnel.rs's existing
                  // HandshakeInit rate limiter) -- confirmed this
                  // parameter is present and `Option<Arc<RateLimiter>>`
                  // in the resolved 0.7.1 API, same shape the brief
                  // assumed.
        );
        Ok(Self {
            inner: Mutex::new(Inner {
                tunn,
                wrap_scratch: Vec::with_capacity(2048),
                enc_scratch: vec![0u8; 2048],
                dec_scratch: vec![0u8; MAX_WG_PACKET],
            }),
            rejected_total: AtomicU64::new(0),
            substituted_total: AtomicU64::new(0),
        })
    }

    /// Lifetime count of datagrams this link's `decapsulate` has rejected
    /// outright -- see `rejected_total`'s doc comment for why this exists.
    pub fn rejected_count(&self) -> u64 {
        self.rejected_total.load(Ordering::Relaxed)
    }

    /// Lifetime count of `encapsulate` calls whose real plaintext was
    /// silently substituted with a handshake datagram -- see
    /// `substituted_total`'s doc comment.
    pub fn substituted_count(&self) -> u64 {
        self.substituted_total.load(Ordering::Relaxed)
    }

    /// Time since this link's current WireGuard session was established
    /// (its last completed handshake), or `None` before the first one.
    /// Resets to near zero on every rekey.
    pub fn last_handshake_age(&self) -> Option<Duration> {
        self.inner.lock().unwrap().tunn.time_since_last_handshake()
    }

    /// Wraps `plaintext` (mlvpn's own already-serialized frame) into a
    /// WireGuard datagram ready to send on the link's UDP socket.
    ///
    /// Before any session is established, boringtun's real behavior
    /// (confirmed by source inspection, not assumed) is to *queue*
    /// `plaintext` internally and return a handshake-initiation datagram
    /// instead -- the queued frame is not lost, but it will not actually
    /// reach the peer until a later call (either another `encapsulate`
    /// once the handshake completes, or the peer's own reply draining
    /// boringtun's internal retry queue) actually sends it. This mirrors
    /// real WireGuard's own behavior when userspace tries to send before
    /// a tunnel is up, and is why this method's contract is "a datagram
    /// ready to send" rather than "a datagram carrying this exact frame".
    ///
    /// Returns `(datagram, carries_plaintext)`: the bool is `true` only
    /// when the returned datagram is a real WireGuard *data* message
    /// genuinely carrying `plaintext`, and `false` when boringtun
    /// substituted a handshake/control datagram instead (the same
    /// condition `substituted_total` counts). Callers that track a frame
    /// as "sent" for correctness -- notably `tunnel::outbound_sender`'s
    /// FEC group accumulation, which would otherwise record a phantom
    /// group member the peer can never observe, permanently burning that
    /// group's single-erasure recovery budget -- must gate on this bool
    /// rather than on `Ok(..)` alone.
    pub fn encapsulate(&self, plaintext: &[u8]) -> Result<(Vec<u8>, bool)> {
        self.encapsulate_parts(&[plaintext])
    }

    /// Same as `encapsulate`, but the plaintext is the concatenation of
    /// `parts` -- lets the hot path pass the 12-byte mlvpn header (a stack
    /// array) and the payload separately instead of first copying both into
    /// a freshly allocated frame `Vec`.
    pub fn encapsulate_parts(&self, parts: &[&[u8]]) -> Result<(Vec<u8>, bool)> {
        let payload_len: usize = parts.iter().map(|p| p.len()).sum();
        let mut guard = self.inner.lock().unwrap();
        let Inner {
            tunn,
            wrap_scratch,
            enc_scratch,
            ..
        } = &mut *guard;
        write_fake_ipv4_header(wrap_scratch, payload_len)?;
        for p in parts {
            wrap_scratch.extend_from_slice(p);
        }
        // WG overhead + slack, but never smaller than the largest
        // possible outbound message (a 148-byte handshake initiation,
        // per boringtun's own `Tunn::encapsulate` doc comment) -- a
        // freshly-constructed tunnel's first `encapsulate()` call emits
        // a handshake init instead of the actual (usually much smaller)
        // queued frame, and boringtun errors with
        // `DestinationBufferTooSmall` rather than silently truncating.
        let buf_len = (wrap_scratch.len() + 64).max(148);
        if enc_scratch.len() < buf_len {
            enc_scratch.resize(buf_len, 0);
        }
        match tunn.encapsulate(wrap_scratch, &mut enc_scratch[..buf_len]) {
            TunnResult::WriteToNetwork(bytes) => {
                // Message type is a little-endian u32 at offset 0 of every
                // WireGuard datagram (confirmed against boringtun-0.7.1's
                // own wire-format constants: 1=handshake init, 2=handshake
                // response, 3=cookie reply, 4=data). Anything but 4 here
                // means boringtun had no current session and substituted
                // a control datagram for our real plaintext -- see
                // `substituted_total`'s doc comment.
                const WG_MSG_TYPE_DATA: u32 = 4;
                let is_data = bytes.len() >= 4
                    && u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                        == WG_MSG_TYPE_DATA;
                if !is_data {
                    self.substituted_total.fetch_add(1, Ordering::Relaxed);
                }
                // Same `is_data` check drives both the diagnostic counter
                // above and the caller-visible bool -- deliberately one
                // shared computation, never two parallel ones that could
                // drift apart.
                Ok((bytes.to_vec(), is_data))
            }
            TunnResult::Err(e) => Err(MlvpnError::Protocol(format!("wg encapsulate: {e:?}"))),
            TunnResult::Done => Err(MlvpnError::Protocol(
                "wg encapsulate: handshake not yet complete".into(),
            )),
            other => Err(MlvpnError::Protocol(format!(
                "wg encapsulate: unexpected result {other:?}"
            ))),
        }
    }

    /// Feeds one received datagram (raw bytes off the link's UDP socket)
    /// to boringtun. See `DecapsulateOutcome` for the three possible
    /// results. Allocating convenience wrapper over `decapsulate_into`.
    pub fn decapsulate(&self, datagram: &[u8]) -> Result<DecapsulateOutcome> {
        let mut frame = Vec::new();
        Ok(match self.decapsulate_into(datagram, &mut frame)? {
            DecapsulateKind::Frame => DecapsulateOutcome::Frame(frame),
            DecapsulateKind::SendReply(reply) => DecapsulateOutcome::SendReply(reply),
            DecapsulateKind::Consumed => DecapsulateOutcome::Consumed,
        })
    }

    /// Hot-path form of `decapsulate`: a decrypted mlvpn frame is written
    /// into the caller's reusable `frame_out` (cleared first) instead of a
    /// fresh `Vec`, and boringtun's own output scratch is the persistent
    /// one inside this tunnel rather than a zeroed `MAX_WG_PACKET` buffer
    /// per call.
    pub fn decapsulate_into(
        &self,
        datagram: &[u8],
        frame_out: &mut Vec<u8>,
    ) -> Result<DecapsulateKind> {
        // Explicit pre-check, independent of `MAX_WG_PACKET`'s own
        // sizing above: a real UDP datagram can never exceed 65507 bytes
        // (the IPv4 UDP payload ceiling), so this can only ever reject
        // something that was never a legitimate datagram off a real
        // socket in the first place -- but reject it with a clean `Err`
        // here rather than relying solely on the output buffer being
        // "big enough", since the panic this guards against
        // (`Session::receive_packet_data`'s `dst.len() < ct_len` check,
        // see `MAX_WG_PACKET`'s doc comment) runs on unauthenticated,
        // peer/attacker-controlled input.
        if datagram.len() > MAX_WG_PACKET {
            self.rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err(MlvpnError::Protocol(format!(
                "wg decapsulate: datagram too large ({} bytes, max {})",
                datagram.len(),
                MAX_WG_PACKET
            )));
        }
        let mut guard = self.inner.lock().unwrap();
        let Inner {
            tunn, dec_scratch, ..
        } = &mut *guard;
        match tunn.decapsulate(None, datagram, dec_scratch) {
            TunnResult::Done => Ok(DecapsulateKind::Consumed),
            TunnResult::Err(e) => {
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                Err(MlvpnError::Protocol(format!("wg decapsulate: {e:?}")))
            }
            TunnResult::WriteToNetwork(bytes) => Ok(DecapsulateKind::SendReply(bytes.to_vec())),
            TunnResult::WriteToTunnelV4(bytes, _) => {
                if bytes.len() < FAKE_IPV4_HEADER_LEN {
                    return Err(MlvpnError::Protocol(format!(
                        "wg decapsulate: decrypted packet ({} bytes) shorter than the fake IPv4 header we always add",
                        bytes.len()
                    )));
                }
                frame_out.clear();
                frame_out.extend_from_slice(&bytes[FAKE_IPV4_HEADER_LEN..]);
                Ok(DecapsulateKind::Frame)
            }
            TunnResult::WriteToTunnelV6(_, _) => {
                // mlvpn's own encapsulate() always sets the fake header's
                // version nibble to 4 -- a V6 result here would mean
                // either a peer running different code, or a genuine
                // boringtun/protocol-level surprise. Treat it as an
                // error rather than guessing at how to unwrap it.
                Err(MlvpnError::Protocol(
                    "wg decapsulate: unexpected IPv6-tagged result (mlvpn only ever emits the fake IPv4 form)".into(),
                ))
            }
        }
    }

    /// Drives boringtun's internal handshake-retry/keepalive timers.
    /// Returns `Some(bytes)` if boringtun wants something sent on the
    /// link's socket (a handshake retry, a keepalive), `None` otherwise.
    /// Callers invoke this periodically (a later task wires this to each
    /// link's existing probe-timer cadence).
    pub fn tick(&self) -> Option<Vec<u8>> {
        let mut guard = self.inner.lock().unwrap();
        let Inner {
            tunn, dec_scratch, ..
        } = &mut *guard;
        match tunn.update_timers(dec_scratch) {
            TunnResult::WriteToNetwork(bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_keypair() -> ([u8; 32], [u8; 32]) {
        let kp = crate::crypto::StaticKeypair::generate().unwrap();
        kp.raw_bytes()
    }

    /// Drives a full real handshake between two independent `WgTunnel`s
    /// using nothing but in-memory byte-buffer exchange (no sockets, no
    /// network, no other mlvpn module involved), then exchanges one real
    /// mlvpn-shaped frame end to end.
    ///
    /// Note this test's handshake choreography does *not* match the
    /// brief's original draft: boringtun-0.7.1's real behavior (confirmed
    /// here, not assumed) is that the *client* drives the handshake by
    /// calling `encapsulate()` with real data it wants to send (which
    /// queues the data and emits a handshake-init datagram instead) --
    /// not by calling `tick()` on a freshly constructed tunnel with
    /// nothing queued, which does nothing until at least one send/receive
    /// attempt has happened. And the client's own `decapsulate()` of the
    /// server's handshake response yields a `SendReply` (a post-handshake
    /// keepalive confirmation), not `Consumed` -- real WireGuard always
    /// sends that confirmation immediately, it doesn't just silently
    /// finish the handshake.
    #[test]
    fn two_tunnels_handshake_and_exchange_a_frame() {
        let (client_priv, client_pub) = generate_test_keypair();
        let (server_priv, server_pub) = generate_test_keypair();

        let client = WgTunnel::new(client_priv, server_pub, true).unwrap();
        let server = WgTunnel::new(server_priv, client_pub, false).unwrap();

        let plaintext = b"hello over wireguard";

        // Client wants to send real data immediately; no session exists
        // yet, so boringtun queues the plaintext internally and instead
        // hands back a handshake-initiation datagram to send first.
        let (handshake_init, carries_plaintext) = client.encapsulate(plaintext).unwrap();
        assert!(
            !carries_plaintext,
            "a pre-session encapsulate must report false: the datagram is a handshake \
             initiation, not our plaintext"
        );

        // Server processes the handshake init and produces a handshake
        // response that must go back to the client.
        let server_reply = match server.decapsulate(&handshake_init).unwrap() {
            DecapsulateOutcome::SendReply(bytes) => bytes,
            other => panic!("expected SendReply (handshake response), got {other:?}"),
        };

        // Client processes the handshake response; its session is now
        // established, and it immediately emits a keepalive confirmation
        // that must also be sent back to the server.
        let client_keepalive = match client.decapsulate(&server_reply).unwrap() {
            DecapsulateOutcome::SendReply(bytes) => bytes,
            other => panic!("expected SendReply (post-handshake keepalive), got {other:?}"),
        };

        // Server consumes that keepalive: nothing to send, nothing to
        // deliver -- just confirms the handshake on its side too.
        let outcome = server.decapsulate(&client_keepalive).unwrap();
        assert!(matches!(outcome, DecapsulateOutcome::Consumed));

        // Now both sides have an established session -- send a real
        // frame client -> server and confirm it round-trips exactly.
        let (datagram, carries_plaintext) = client.encapsulate(plaintext).unwrap();
        assert!(
            carries_plaintext,
            "with a session established, encapsulate must report true"
        );
        let received = match server.decapsulate(&datagram).unwrap() {
            DecapsulateOutcome::Frame(bytes) => bytes,
            other => panic!("expected Frame, got {other:?}"),
        };
        assert_eq!(received, plaintext);

        // And the reverse direction too, since mlvpn's real traffic is
        // bidirectional over the same established session.
        let (reply_datagram, carries_plaintext) = server.encapsulate(plaintext).unwrap();
        assert!(
            carries_plaintext,
            "the responder's own post-handshake encapsulate must report true too"
        );
        let received_by_client = match client.decapsulate(&reply_datagram).unwrap() {
            DecapsulateOutcome::Frame(bytes) => bytes,
            other => panic!("expected Frame, got {other:?}"),
        };
        assert_eq!(received_by_client, plaintext);
    }

    /// The specific regression this bool exists for: `encapsulate` must
    /// distinguish "this datagram carries your plaintext" from "boringtun
    /// substituted a handshake datagram for it", and that bool must agree
    /// with `substituted_count`'s own movement on every single call --
    /// they are computed from one shared check on purpose.
    ///
    /// Before this, `tunnel::outbound_sender` accumulated every Data
    /// frame into its FEC group regardless, so every frame handed to a
    /// link that was mid-handshake/rekey became a phantom group member
    /// the peer could never observe, permanently burning the group's one
    /// recoverable erasure.
    #[test]
    fn encapsulate_reports_whether_the_datagram_carries_the_plaintext() {
        let (client_priv, client_pub) = generate_test_keypair();
        let (server_priv, server_pub) = generate_test_keypair();

        let client = WgTunnel::new(client_priv, server_pub, true).unwrap();
        let server = WgTunnel::new(server_priv, client_pub, false).unwrap();

        let plaintext = b"payload that must not become a phantom FEC member";

        // No session yet -> substitution.
        assert_eq!(client.substituted_count(), 0);
        let (handshake_init, carried) = client.encapsulate(plaintext).unwrap();
        assert!(!carried);
        assert_eq!(
            client.substituted_count(),
            1,
            "the bool and the diagnostic counter must move together"
        );

        // Complete the handshake.
        let reply = match server.decapsulate(&handshake_init).unwrap() {
            DecapsulateOutcome::SendReply(bytes) => bytes,
            other => panic!("expected SendReply, got {other:?}"),
        };
        let keepalive = match client.decapsulate(&reply).unwrap() {
            DecapsulateOutcome::SendReply(bytes) => bytes,
            other => panic!("expected SendReply, got {other:?}"),
        };
        assert!(matches!(
            server.decapsulate(&keepalive).unwrap(),
            DecapsulateOutcome::Consumed
        ));

        // Session established -> real data transmission, and the
        // substitution counter must stay where it was.
        let before = client.substituted_count();
        let (datagram, carried) = client.encapsulate(plaintext).unwrap();
        assert!(carried);
        assert_eq!(client.substituted_count(), before);
        match server.decapsulate(&datagram).unwrap() {
            DecapsulateOutcome::Frame(bytes) => assert_eq!(bytes, plaintext),
            other => panic!("expected Frame, got {other:?}"),
        }
    }

    /// `tick()` on a session with nothing queued and no handshake attempt
    /// yet in progress has nothing to do -- confirms it doesn't panic or
    /// spuriously emit a datagram.
    #[test]
    fn tick_on_fresh_idle_tunnel_returns_none() {
        let (priv_key, _pub_key) = generate_test_keypair();
        let (_other_priv, other_pub) = generate_test_keypair();
        let tunnel = WgTunnel::new(priv_key, other_pub, true).unwrap();
        assert!(tunnel.tick().is_none());
    }

    fn wrap_fake_ipv4(plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        write_fake_ipv4_header(&mut out, plaintext.len())?;
        out.extend_from_slice(plaintext);
        Ok(out)
    }

    /// Pins the exact fake-IPv4 header bytes for a known plaintext, so a
    /// future `boringtun` version bump (or any refactor of this
    /// function) has something concrete to diff against -- this header
    /// shape is load-bearing (see the module doc comment on why it
    /// exists at all), not incidental formatting.
    #[test]
    fn wrap_fake_ipv4_produces_the_expected_header_bytes() {
        let plaintext = b"hi"; // 2 bytes -> total length 22 = 0x0016
        let wrapped = wrap_fake_ipv4(plaintext).unwrap();
        assert_eq!(
            wrapped,
            vec![
                0x45,
                0x00, // version/IHL, DSCP/ECN
                0x00,
                0x16, // total length = 22
                0x00,
                0x00, // identification
                0x00,
                0x00, // flags/fragment offset
                64,
                FAKE_IPV4_PROTOCOL, // TTL, protocol
                0x00,
                0x00, // header checksum
                0,
                0,
                0,
                0, // source address
                0,
                0,
                0,
                0, // destination address
                b'h',
                b'i', // payload
            ]
        );
    }

    /// Frames round-trip exactly through two real tunnels for a variety of
    /// lengths, whether passed whole (`encapsulate`) or scattered
    /// (`encapsulate_parts`), and the caller-owned `decapsulate_into`
    /// buffer is correctly reused (shrinking to a shorter frame leaves no
    /// stale bytes from the previous, longer one).
    #[test]
    fn frames_round_trip_whole_scattered_and_through_a_reused_buffer() {
        let (client_priv, client_pub) = generate_test_keypair();
        let (server_priv, server_pub) = generate_test_keypair();
        let client = WgTunnel::new(client_priv, server_pub, true).unwrap();
        let server = WgTunnel::new(server_priv, client_pub, false).unwrap();
        let (init, _) = client.encapsulate(b"x").unwrap();
        let reply = match server.decapsulate(&init).unwrap() {
            DecapsulateOutcome::SendReply(b) => b,
            other => panic!("expected SendReply, got {other:?}"),
        };
        let ka = match client.decapsulate(&reply).unwrap() {
            DecapsulateOutcome::SendReply(b) => b,
            other => panic!("expected SendReply, got {other:?}"),
        };
        assert!(matches!(
            server.decapsulate(&ka).unwrap(),
            DecapsulateOutcome::Consumed
        ));

        let mut out = Vec::new();
        for plaintext in [
            vec![7u8; 1400],
            b"x".to_vec(),
            b"a longer mlvpn-shaped frame".to_vec(),
            vec![9u8; 3000],
        ] {
            let (dg, carried) = client.encapsulate(&plaintext).unwrap();
            assert!(carried);
            assert!(matches!(
                server.decapsulate_into(&dg, &mut out).unwrap(),
                DecapsulateKind::Frame
            ));
            assert_eq!(out, plaintext);

            let split = plaintext.len() / 3;
            let (dg, carried) = client
                .encapsulate_parts(&[&plaintext[..split], &plaintext[split..]])
                .unwrap();
            assert!(carried);
            assert!(matches!(
                server.decapsulate_into(&dg, &mut out).unwrap(),
                DecapsulateKind::Frame
            ));
            assert_eq!(out, plaintext);
        }
    }

    /// The fake header's total-length field is a `u16`, so anything that
    /// would push `20 + plaintext.len()` past `u16::MAX` must be rejected
    /// with a clean `Err`, not silently wrap around or panic on the
    /// `u16::try_from` conversion -- both at the helper and through the
    /// public `encapsulate_parts` entry point, summing across parts.
    #[test]
    fn wrap_fake_ipv4_rejects_oversized_plaintext() {
        let max_ok_len = u16::MAX as usize - FAKE_IPV4_HEADER_LEN; // 65515
        assert!(wrap_fake_ipv4(&vec![0u8; max_ok_len]).is_ok());
        assert!(wrap_fake_ipv4(&vec![0u8; max_ok_len + 1]).is_err());

        let (priv_key, _pub) = generate_test_keypair();
        let (_other_priv, other_pub) = generate_test_keypair();
        let tunnel = WgTunnel::new(priv_key, other_pub, true).unwrap();
        let half = vec![0u8; max_ok_len / 2 + 1];
        assert!(tunnel.encapsulate_parts(&[&half, &half]).is_err());
    }

    /// `decapsulate` must reject an oversized datagram with a clean
    /// `Err` rather than risk boringtun's own pre-authentication
    /// `panic!` on a too-small destination buffer (see `MAX_WG_PACKET`'s
    /// doc comment) -- this is the second, independent layer of defense
    /// beyond simply sizing the buffer generously, and it's the layer
    /// this test can actually exercise without a real oversized
    /// ciphertext to feed boringtun.
    #[test]
    fn decapsulate_rejects_an_oversized_datagram() {
        let (priv_key, _pub_key) = generate_test_keypair();
        let (_other_priv, other_pub) = generate_test_keypair();
        let tunnel = WgTunnel::new(priv_key, other_pub, true).unwrap();
        let oversized = vec![0u8; MAX_WG_PACKET + 1];
        assert!(tunnel.decapsulate(&oversized).is_err());
    }
}
