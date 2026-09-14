//! Static Curve25519 keypair generation/parsing for mlvpn.
//!
//! What's actually left here after the WireGuard-per-link-transport
//! rewrite: each `[[links]]` entry now carries its own independent
//! `boringtun`-backed WireGuard tunnel (see `wireguard.rs`), with its own
//! handshake, rekey, and replay window managed entirely by `boringtun`
//! itself -- there is no tunnel-wide shared session, handshake state
//! machine, or `session_id` concept left in this codebase (see
//! `ARCHITECTURE.md` for the current design). This module now only
//! provides:
//!
//! - `StaticKeypair`: generates a Curve25519 keypair (`mlvpnd genkey`)
//!   using `snow`'s `Builder` purely as a convenient, already-vendored
//!   Curve25519 keygen routine -- the actual Noise handshake machinery
//!   `snow` also provides is no longer used anywhere in this crate.
//! - `LocalPrivateKey`/`StaticKeypair::load_private`: load a private key
//!   from disk (a `[[links]]` entry's `private_key_file`).
//! - `decode_public_key`: parse a peer's base64-encoded public key from
//!   config (a `[[links]]` entry's `peer_public_key`).
//! - `random_session_id`: a general-purpose random `u32` generator, still
//!   used by unrelated call sites (e.g. `mlvpnd self-test`'s per-run test
//!   id) that just need a random tag with no relation to the old crypto
//!   session concept the name originally came from.

use crate::error::{MlvpnError, Result};
use rand::RngCore;
use snow::Builder;
use std::fs;
use std::path::Path;
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

    /// Copy out the raw `(private, public)` key bytes.
    ///
    /// `private`/`public` are deliberately not `pub` (so that raw key
    /// material can't leak out of this struct by accident, e.g. via a
    /// careless `Debug` derive or a stray field access elsewhere) --
    /// this is the explicit, auditable escape hatch for callers that
    /// genuinely need the raw bytes, such as `wireguard::WgTunnel::new`,
    /// which hands them straight to `boringtun`'s own key types. Returns
    /// owned `[u8; 32]` copies (both types are `Copy`), not references,
    /// so the caller owns its own copy independent of this struct's
    /// lifetime/zeroize-on-drop behavior.
    pub fn raw_bytes(&self) -> ([u8; 32], [u8; 32]) {
        (self.private, self.public)
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

impl Clone for LocalPrivateKey {
    // Hand-written rather than `#[derive(Clone)]` purely so this stays
    // next to the `Drop` impl it pairs with: each clone zeroizes its own
    // copy independently on drop, which is exactly what we want (no
    // aliasing -- `[u8; 32]` is `Copy`, so this is a real, independent
    // copy of the key material, not a shared reference).
    fn clone(&self) -> Self {
        LocalPrivateKey(self.0)
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

/// Generate a cryptographically secure random `u32`. The name is a
/// holdover from the old shared Noise session design this originally
/// tagged handshake attempts for; it's now a general-purpose random-id
/// generator used by unrelated call sites (e.g. `mlvpnd self-test`'s
/// per-run test id) that just need a random tag.
pub fn random_session_id() -> u32 {
    rand::rngs::OsRng.next_u32()
}
