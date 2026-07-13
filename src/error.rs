//! Central error type for the daemon. Keeping one error enum makes it easy
//! to reason about every failure mode that can cross a module boundary,
//! which matters for a security-sensitive network daemon: we never want an
//! error to be silently swallowed or to leak sensitive detail (e.g. key
//! material) into logs.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MlvpnError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("config file {path} has insecure permissions {mode:o}; expected 0600 or stricter")]
    InsecurePermissions { path: String, mode: u32 },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TUN device error: {0}")]
    Tun(String),

    #[error("crypto handshake failed: {0}")]
    Handshake(String),

    #[error("decryption/authentication failed (possible tampering or replay)")]
    AuthFailed,

    #[error("replayed or out-of-window packet dropped")]
    Replay,

    #[error("no interfaces are currently usable: link aggregate is down")]
    AllLinksDown,

    #[error("interface '{0}' not found on this system")]
    InterfaceNotFound(String),

    #[error("privilege drop failed: {0}")]
    Privilege(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("channel closed unexpectedly")]
    ChannelClosed,
}

pub type Result<T> = std::result::Result<T, MlvpnError>;
