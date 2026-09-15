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

/// Wraps `plaintext` in a minimal fake IPv4 header so it survives
/// boringtun's receive-side IP-packet validation (see module doc).
fn wrap_fake_ipv4(plaintext: &[u8]) -> Result<Vec<u8>> {
    let total_len = FAKE_IPV4_HEADER_LEN + plaintext.len();
    let total_len_u16 = u16::try_from(total_len).map_err(|_| {
        MlvpnError::Protocol(format!(
            "wg encapsulate: frame too large ({} bytes) to fit boringtun's fake IPv4 wrapper",
            plaintext.len()
        ))
    })?;

    let mut wrapped = Vec::with_capacity(total_len);
    wrapped.push(0x45); // version 4, IHL 5 (20-byte header, no options)
    wrapped.push(0x00); // DSCP/ECN
    wrapped.extend_from_slice(&total_len_u16.to_be_bytes()); // total length
    wrapped.extend_from_slice(&[0x00, 0x00]); // identification
    wrapped.extend_from_slice(&[0x00, 0x00]); // flags/fragment offset
    wrapped.push(64); // TTL, unused, arbitrary
    wrapped.push(FAKE_IPV4_PROTOCOL);
    wrapped.extend_from_slice(&[0x00, 0x00]); // header checksum, unchecked by boringtun
    wrapped.extend_from_slice(&[0, 0, 0, 0]); // source address, unused
    wrapped.extend_from_slice(&[0, 0, 0, 0]); // destination address, unused
    debug_assert_eq!(wrapped.len(), FAKE_IPV4_HEADER_LEN);
    wrapped.extend_from_slice(plaintext);
    Ok(wrapped)
}

/// Strips the fake IPv4 header `wrap_fake_ipv4` added, recovering the
/// original mlvpn frame.
fn unwrap_fake_ipv4(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < FAKE_IPV4_HEADER_LEN {
        return Err(MlvpnError::Protocol(format!(
            "wg decapsulate: decrypted packet ({} bytes) shorter than the fake IPv4 header we always add",
            bytes.len()
        )));
    }
    Ok(bytes[FAKE_IPV4_HEADER_LEN..].to_vec())
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
    inner: Mutex<Tunn>,
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
            inner: Mutex::new(tunn),
            rejected_total: AtomicU64::new(0),
        })
    }

    /// Lifetime count of datagrams this link's `decapsulate` has rejected
    /// outright -- see `rejected_total`'s doc comment for why this exists.
    pub fn rejected_count(&self) -> u64 {
        self.rejected_total.load(Ordering::Relaxed)
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
    pub fn encapsulate(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let wrapped = wrap_fake_ipv4(plaintext)?;
        // WG overhead + slack, but never smaller than the largest
        // possible outbound message (a 148-byte handshake initiation,
        // per boringtun's own `Tunn::encapsulate` doc comment) -- a
        // freshly-constructed tunnel's first `encapsulate()` call emits
        // a handshake init instead of the actual (usually much smaller)
        // queued frame, and boringtun errors with
        // `DestinationBufferTooSmall` rather than silently truncating.
        let buf_len = (wrapped.len() + 64).max(148);
        let mut buf = vec![0u8; buf_len];
        let mut tunn = self.inner.lock().unwrap();
        match tunn.encapsulate(&wrapped, &mut buf) {
            TunnResult::WriteToNetwork(bytes) => Ok(bytes.to_vec()),
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
    /// results.
    pub fn decapsulate(&self, datagram: &[u8]) -> Result<DecapsulateOutcome> {
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
        let mut buf = vec![0u8; MAX_WG_PACKET];
        let mut tunn = self.inner.lock().unwrap();
        match tunn.decapsulate(None, datagram, &mut buf) {
            TunnResult::Done => Ok(DecapsulateOutcome::Consumed),
            TunnResult::Err(e) => {
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                Err(MlvpnError::Protocol(format!("wg decapsulate: {e:?}")))
            }
            TunnResult::WriteToNetwork(bytes) => Ok(DecapsulateOutcome::SendReply(bytes.to_vec())),
            TunnResult::WriteToTunnelV4(bytes, _) => {
                Ok(DecapsulateOutcome::Frame(unwrap_fake_ipv4(bytes)?))
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
        let mut buf = vec![0u8; MAX_WG_PACKET];
        let mut tunn = self.inner.lock().unwrap();
        match tunn.update_timers(&mut buf) {
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
        let handshake_init = client.encapsulate(plaintext).unwrap();

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
        let datagram = client.encapsulate(plaintext).unwrap();
        let received = match server.decapsulate(&datagram).unwrap() {
            DecapsulateOutcome::Frame(bytes) => bytes,
            other => panic!("expected Frame, got {other:?}"),
        };
        assert_eq!(received, plaintext);

        // And the reverse direction too, since mlvpn's real traffic is
        // bidirectional over the same established session.
        let reply_datagram = server.encapsulate(plaintext).unwrap();
        let received_by_client = match client.decapsulate(&reply_datagram).unwrap() {
            DecapsulateOutcome::Frame(bytes) => bytes,
            other => panic!("expected Frame, got {other:?}"),
        };
        assert_eq!(received_by_client, plaintext);
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

    /// `wrap_fake_ipv4`/`unwrap_fake_ipv4` round-trip exactly for a
    /// variety of lengths, including the empty case.
    #[test]
    fn wrap_and_unwrap_fake_ipv4_round_trip() {
        for plaintext in [&b""[..], &b"x"[..], &b"a longer mlvpn-shaped frame"[..]] {
            let wrapped = wrap_fake_ipv4(plaintext).unwrap();
            assert_eq!(wrapped.len(), FAKE_IPV4_HEADER_LEN + plaintext.len());
            let unwrapped = unwrap_fake_ipv4(&wrapped).unwrap();
            assert_eq!(unwrapped, plaintext);
        }
    }

    /// `wrap_fake_ipv4`'s total-length field is a `u16`, so anything that
    /// would push `20 + plaintext.len()` past `u16::MAX` must be rejected
    /// with a clean `Err`, not silently wrap around or panic on the
    /// `u16::try_from` conversion.
    #[test]
    fn wrap_fake_ipv4_rejects_oversized_plaintext() {
        let max_ok_len = u16::MAX as usize - FAKE_IPV4_HEADER_LEN; // 65515
        assert!(wrap_fake_ipv4(&vec![0u8; max_ok_len]).is_ok());
        assert!(wrap_fake_ipv4(&vec![0u8; max_ok_len + 1]).is_err());
    }

    /// `unwrap_fake_ipv4` must reject anything shorter than the header it
    /// always expects, rather than panicking on the slice index.
    #[test]
    fn unwrap_fake_ipv4_rejects_input_shorter_than_the_header() {
        assert!(unwrap_fake_ipv4(&[0u8; FAKE_IPV4_HEADER_LEN - 1]).is_err());
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
