//! Privilege dropping.
//!
//! `mlvpnd` needs elevated privileges for exactly two operations, both of
//! which happen once at startup, before any packet is processed: creating
//! the TUN device and binding UDP sockets to specific interfaces via
//! `SO_BINDTODEVICE`. Neither the data path nor the control path need any
//! privilege after that -- the TUN file descriptor and bound sockets stay
//! usable regardless of the process's uid.
//!
//! Two deployment models are supported:
//!
//! 1. **Run as root, drop after setup** (what this module implements):
//!    the systemd unit starts the daemon as root, it does its privileged
//!    setup, then calls `drop_privileges()` to permanently become an
//!    unprivileged `mlvpn` user/group with an empty capability set before
//!    touching the network.
//! 2. **Never be root at all**: grant `CAP_NET_ADMIN` and `CAP_NET_RAW` to
//!    the binary/unit directly (systemd `AmbientCapabilities=`, see
//!    `systemd/mlvpn.service`) and run as the `mlvpn` user from the start.
//!    In that case `drop_privileges()` detects it is not root and is a
//!    no-op (the process already has the minimum it needs and nothing
//!    more).
//!
//! Model 2 is the stronger posture (the process is never root, so there
//! is no privileged window at all, however brief) and is what the shipped
//! systemd unit uses by default; model 1 is kept as a fallback for
//! environments where assigning file capabilities isn't practical.

use crate::error::{MlvpnError, Result};
use nix::unistd::{setgid, setgroups, setuid};

pub struct DropTarget {
    pub user: String,
    pub group: String,
}

impl Default for DropTarget {
    fn default() -> Self {
        Self {
            user: "mlvpn".to_string(),
            group: "mlvpn".to_string(),
        }
    }
}

pub fn drop_privileges(target: &DropTarget) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        tracing::info!(
            "not running as root (likely started with pre-granted capabilities); \
             privilege drop is a no-op"
        );
        return Ok(());
    }

    let user = nix::unistd::User::from_name(&target.user)
        .map_err(|e| MlvpnError::Privilege(format!("looking up user '{}': {e}", target.user)))?
        .ok_or_else(|| MlvpnError::Privilege(format!("user '{}' does not exist", target.user)))?;
    let group = nix::unistd::Group::from_name(&target.group)
        .map_err(|e| MlvpnError::Privilege(format!("looking up group '{}': {e}", target.group)))?
        .ok_or_else(|| MlvpnError::Privilege(format!("group '{}' does not exist", target.group)))?;

    // Order matters: clear supplementary groups and set the real/effective
    // gid *before* dropping the uid. Once we're no longer root we lose the
    // ability to change gid at all.
    setgroups(&[]).map_err(|e| MlvpnError::Privilege(format!("clearing supplementary groups: {e}")))?;
    setgid(group.gid).map_err(|e| MlvpnError::Privilege(format!("setgid: {e}")))?;
    setuid(user.uid).map_err(|e| MlvpnError::Privilege(format!("setuid: {e}")))?;

    // Belt and suspenders: explicitly clear every capability set. The
    // kernel already does this as a side effect of setuid() away from
    // root (see capabilities(7)), but making it explicit means this code
    // stays correct even if that implicit behavior is ever bypassed (e.g.
    // via a future PR_SET_KEEPCAPS change elsewhere in the process).
    for set in [
        caps::CapSet::Effective,
        caps::CapSet::Permitted,
        caps::CapSet::Inheritable,
    ] {
        if let Err(e) = caps::clear(None, set) {
            tracing::debug!(?set, error = %e, "clearing capability set (likely already empty)");
        }
    }

    tracing::info!(user = %target.user, group = %target.group, "dropped privileges");
    Ok(())
}

/// Sanity check to run right after `drop_privileges`: confirm we can no
/// longer act as root. Cheap, and catches privilege-drop bugs loudly at
/// startup instead of silently running over-privileged.
pub fn assert_unprivileged() -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        return Err(MlvpnError::Privilege(
            "still running as root after privilege drop was requested".into(),
        ));
    }
    Ok(())
}
