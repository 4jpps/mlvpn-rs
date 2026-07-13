//! Authentication and encryption for the tunnel, built on the Noise
//! Protocol Framework (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) via the `snow`
//! crate.
//!
//! Design choices, and why:
//!
//! - **Noise_IK** gives us a single-round-trip, mutually authenticated
//!   handshake with forward secrecy, the same family of guarantees
//!   WireGuard is built on. Both peers hold each other's long-term Curve25519
//!   public key out of band (from the config file), which lets the
//!   initiator authenticate the responder in the very first message.
//! - We use `snow`'s `StatelessTransportState` rather than `TransportState`.
//!   The stateful variant assumes messages arrive in order and increments
//!   an internal nonce; that assumption doesn't hold here; the same tunnel
//!   session sends packets across multiple physical links simultaneously,
//!   so receive order is not send order. The stateless variant instead
//!   takes an explicit `nonce: u64` on every call, which we set to our own
//!   monotonically increasing sequence number, and it is safe to encrypt
//!   and decrypt out of order as long as each nonce is used at most once.
//! - `StatelessTransportState` does not expose an AEAD associated-data
//!   parameter, so header fields (session id, packet type, link id) are
//!   *not* cryptographically bound to the ciphertext. This is a deliberate,
//!   documented tradeoff: those fields are only used for local dispatch
//!   (which session's keys to try, which link a probe reply refers to);
//!   tampering with them either points decryption at the wrong key
//!   (decrypt fails, packet dropped) or corrupts routing metadata with no
//!   security consequence. The sequence number *is* the AEAD nonce, so it
//!   is implicitly authenticated: an attacker cannot replay a ciphertext
//!   under a different sequence number and have it verify.
//! - Sessions are rekeyed periodically (see `CryptoConfig::rekey_interval_secs`)
//!   by tearing down and re-running the handshake, bounding the amount of
//!   data ever protected by one set of transport keys.

use crate::error::{MlvpnError, Result};
use rand::RngCore;
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Curve25519 static keypair, held only as long as needed and zeroized on
/// drop so a coredump or swapped page is less likely to leak it.
pub struct StaticKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl Drop for StaticKeypair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl StaticKeypair {
    /// Generate a fresh keypair (used by `mlvpnd genkey`).
    pub fn generate() -> Result<Self> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| MlvpnError::Handshake(format!("bad noise pattern: {e:?}")))?;
        let kp = Builder::new(params)
            .generate_keypair()
            .map_err(|e| MlvpnError::Handshake(format!("keygen failed: {e}")))?;
        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        private.copy_from_slice(&kp.private);
        public.copy_from_slice(&kp.public);
        Ok(Self { private, public })
    }

    /// Load a base64-encoded private key from disk. The caller is
    /// responsible for having already checked file permissions (see
    /// `config::check_permissions`).
    ///
    /// Note: this does *not* attempt to (re-)derive the matching public
    /// key. The daemon never needs its own public key at run time --
    /// `snow` derives it internally from the private key during the DH
    /// steps of the handshake. The public key only needs to exist as a
    /// human-visible artifact so the operator can hand it to the peer,
    /// which is why `mlvpnd genkey` prints/saves both halves at generation
    /// time (see `StaticKeypair::generate`) instead of it being
    /// recomputed here.
    pub fn load_private(path: &Path) -> Result<LocalPrivateKey> {
        let raw = fs::read_to_string(path)
            .map_err(|e| MlvpnError::Config(format!("reading key file {}: {e}", path.display())))?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw.trim())
            .map_err(|e| MlvpnError::Config(format!("key file is not valid base64: {e}")))?;
        if bytes.len() != 32 {
            return Err(MlvpnError::Config(format!(
                "private key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut private = [0u8; 32];
        private.copy_from_slice(&bytes);
        Ok(LocalPrivateKey(private))
    }

    pub fn public_base64(&self) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, self.public)
    }

    pub fn private_base64(&self) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, self.private)
    }
}

/// A private key loaded from disk, with no known public counterpart in
/// memory (see `StaticKeypair::load_private`). Wrapped in its own type so
/// call sites can't accidentally mix it up with a full keypair.
pub struct LocalPrivateKey(pub [u8; 32]);

impl Drop for LocalPrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn decode_public_key(b64: &str) -> Result<[u8; 32]> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
        .map_err(|e| MlvpnError::Config(format!("public key is not valid base64: {e}")))?;
    if bytes.len() != 32 {
        return Err(MlvpnError::Config(format!(
            "public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// One in-flight Noise handshake, either as initiator (client) or responder
/// (server side of a given link/session).
pub struct Handshake {
    state: HandshakeState,
}

impl Handshake {
    pub fn new_initiator(local_private: &LocalPrivateKey, remote_public: &[u8; 32]) -> Result<Self> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| MlvpnError::Handshake(format!("bad noise pattern: {e:?}")))?;
        let state = Builder::new(params)
            .local_private_key(&local_private.0)
            .map_err(|e| MlvpnError::Handshake(e.to_string()))?
            .remote_public_key(remote_public)
            .map_err(|e| MlvpnError::Handshake(e.to_string()))?
            .build_initiator()
            .map_err(|e| MlvpnError::Handshake(e.to_string()))?;
        Ok(Self { state })
    }

    pub fn new_responder(local_private: &LocalPrivateKey) -> Result<Self> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| MlvpnError::Handshake(format!("bad noise pattern: {e:?}")))?;
        let state = Builder::new(params)
            .local_private_key(&local_private.0)
            .map_err(|e| MlvpnError::Handshake(e.to_string()))?
            .build_responder()
            .map_err(|e| MlvpnError::Handshake(e.to_string()))?;
        Ok(Self { state })
    }

    /// Produce the initiator's first handshake message (`-> e, es, s, ss`).
    pub fn write_first(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 1024];
        let n = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| MlvpnError::Handshake(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Responder processes message 1 and produces message 2 (`<- e, ee, se`).
    pub fn read_first_and_reply(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut discard = vec![0u8; 1024];
        self.state
            .read_message(msg, &mut discard)
            .map_err(|_| MlvpnError::AuthFailed)?;
        let mut buf = vec![0u8; 1024];
        let n = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| MlvpnError::Handshake(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Initiator processes message 2. Handshake is complete afterward.
    pub fn read_second(&mut self, msg: &[u8]) -> Result<()> {
        let mut discard = vec![0u8; 1024];
        self.state
            .read_message(msg, &mut discard)
            .map_err(|_| MlvpnError::AuthFailed)?;
        Ok(())
    }

    /// Unused today (the handshake state machine in `tunnel.rs` already
    /// knows when it's done by which message it just sent/received), but
    /// kept as public API for the rekey roadmap item in ARCHITECTURE.md,
    /// where a background task will need to poll handshake progress.
    #[allow(dead_code)]
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// The peer's static public key, as revealed during the handshake.
    /// Callers MUST compare this against the configured, pinned
    /// `peer_public_key` before trusting the session -- Noise authenticates
    /// "whoever holds the matching private key", not "the specific peer we
    /// intended to talk to". Pinning is what turns the former into the
    /// latter.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        let s = self.state.get_remote_static()?;
        if s.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        Some(out)
    }

    pub fn into_session(self) -> Result<Session> {
        let transport: StatelessTransportState = self
            .state
            .into_stateless_transport_mode()
            .map_err(|e| MlvpnError::Handshake(e.to_string()))?;
        Ok(Session {
            transport,
            send_seq: AtomicU64::new(0),
            replay: ReplayWindow::new(),
        })
    }
}

/// Bit width of the `ReplayWindow` sliding bitmap and its word count.
/// Kept as free module-level consts (rather than associated consts
/// referenced from within `ReplayWindow`'s own field declaration) so the
/// struct definition has no dependency on `impl` resolution order.
const REPLAY_WINDOW_BITS: usize = 2048;
const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_BITS / 64;

/// Sliding-window replay filter, tracking the last `REPLAY_WINDOW_BITS`
/// sequence numbers seen. This is the same scheme WireGuard uses: because
/// multiple physical links can deliver packets out of order, we cannot
/// simply require a strictly increasing sequence number, but we still
/// need to reject anything already seen or too far in the past.
pub struct ReplayWindow {
    /// Highest sequence number accepted so far.
    last: u64,
    /// Bitmap covering (last - REPLAY_WINDOW_BITS, last]; bit i set means
    /// (last - i) has been seen.
    bitmap: [u64; REPLAY_WINDOW_WORDS],
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            last: 0,
            bitmap: [0u64; REPLAY_WINDOW_WORDS],
            initialized: false,
        }
    }

    /// Returns Ok(()) and marks `seq` seen if it's acceptable; returns
    /// Err(Replay) if it's a duplicate or too old to track.
    pub fn check_and_update(&mut self, seq: u64) -> Result<()> {
        if !self.initialized {
            self.initialized = true;
            self.last = seq;
            self.set_bit(0);
            return Ok(());
        }

        if seq > self.last {
            let shift = seq - self.last;
            if shift as usize >= REPLAY_WINDOW_BITS {
                self.bitmap = [0u64; REPLAY_WINDOW_WORDS];
            } else {
                self.shift_left(shift as usize);
            }
            self.last = seq;
            self.set_bit(0);
            return Ok(());
        }

        let diff = self.last - seq;
        if diff as usize >= REPLAY_WINDOW_BITS {
            return Err(MlvpnError::Replay);
        }
        if self.test_bit(diff as usize) {
            return Err(MlvpnError::Replay);
        }
        self.set_bit(diff as usize);
        Ok(())
    }

    fn set_bit(&mut self, i: usize) {
        self.bitmap[i / 64] |= 1u64 << (i % 64);
    }

    fn test_bit(&self, i: usize) -> bool {
        (self.bitmap[i / 64] >> (i % 64)) & 1 == 1
    }

    fn shift_left(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        if n >= REPLAY_WINDOW_BITS {
            self.bitmap = [0u64; REPLAY_WINDOW_WORDS];
            return;
        }
        let word_shift = n / 64;
        let bit_shift = n % 64;
        let mut new = [0u64; REPLAY_WINDOW_WORDS];
        for i in (0..REPLAY_WINDOW_WORDS).rev() {
            if i + word_shift < REPLAY_WINDOW_WORDS {
                new[i + word_shift] |= self.bitmap[i];
            }
        }
        if bit_shift != 0 {
            let mut carried = [0u64; REPLAY_WINDOW_WORDS];
            for i in (0..REPLAY_WINDOW_WORDS).rev() {
                carried[i] = new[i] << bit_shift;
                if i + 1 < REPLAY_WINDOW_WORDS {
                    carried[i + 1] |= new[i] >> (64 - bit_shift);
                }
            }
            new = carried;
        }
        self.bitmap = new;
    }
}

/// An established, post-handshake session: a pair of directional keys plus
/// our own send-sequence counter and the peer's replay window.
pub struct Session {
    transport: StatelessTransportState,
    send_seq: AtomicU64,
    replay: ReplayWindow,
}

/// AEAD tag length added by ChaChaPoly.
pub const TAG_LEN: usize = 16;

impl Session {
    /// Allocate the next sequence number for an outgoing packet. This value
    /// must be used both as the wire header's `seq` field and as the AEAD
    /// nonce, and must never be reused for this session.
    pub fn next_send_seq(&self) -> u64 {
        self.send_seq.fetch_add(1, Ordering::Relaxed)
    }

    pub fn encrypt(&self, seq: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; plaintext.len() + TAG_LEN];
        let n = self
            .transport
            .write_message(seq, plaintext, &mut out)
            .map_err(|e| MlvpnError::Protocol(format!("encrypt failed: {e}")))?;
        out.truncate(n);
        Ok(out)
    }

    /// Decrypt and replay-check in one step. `seq` must be the sequence
    /// number carried in the packet's header (also used as nonce).
    pub fn decrypt(&mut self, seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Replay-check first: cheaper than a full AEAD open, and avoids
        // doing decrypt work for packets we're going to discard anyway.
        self.replay.check_and_update(seq)?;
        if ciphertext.len() < TAG_LEN {
            return Err(MlvpnError::AuthFailed);
        }
        let mut out = vec![0u8; ciphertext.len()];
        let n = self
            .transport
            .read_message(seq, ciphertext, &mut out)
            .map_err(|_| MlvpnError::AuthFailed)?;
        out.truncate(n);
        Ok(out)
    }
}

/// Generate a cryptographically secure random session id, used to
/// distinguish handshake attempts / sessions on the wire.
pub fn random_session_id() -> u32 {
    rand::rngs::OsRng.next_u32()
}
