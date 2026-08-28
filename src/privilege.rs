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
//!    unprivileged `mlvpn` user/group, retaining exactly one capability --
//!    `CAP_NET_ADMIN` -- and nothing else.
//! 2. **Never be root at all**: grant `CAP_NET_ADMIN` and `CAP_NET_RAW` to
//!    the binary/unit directly (systemd `AmbientCapabilities=`, see
//!    `systemd/mlvpn.service`) and run as the `mlvpn` user from the start.
//!    In that case `drop_privileges()` detects it is not root and is a
//!    no-op (the process already has the minimum it needs and nothing
//!    more).
//!
//! `CAP_NET_ADMIN` is retained under model 1 because one privileged
//! operation is *not* startup-only: `control::mtu_monitor_loop` resizes
//! the live TUN device with `SIOCSIFMTU` (see `link::set_interface_mtu`)
//! whenever the detected link capacity changes, for the lifetime of the
//! process. Without it, adaptive MTU silently stops working after the
//! drop -- every resize returns `EPERM` and the daemon warns forever.
//! Model 2 grants the same capability via the unit file's
//! `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`, so both deployment
//! models end up with `CAP_NET_ADMIN` available at runtime. Note that
//! model 1 deliberately does *not* retain `CAP_NET_RAW`: reconnecting a
//! link needs it for `SO_BINDTODEVICE`, and that limitation of model 1 is
//! pre-existing, documented in `link.rs`, and handled by `tunnel.rs`'s
//! `MlvpnError::CapabilityMissing` arm. Retaining more than what is
//! actually required here would weaken the drop for no benefit.
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

    // PR_SET_KEEPCAPS must be set *before* setuid(): by default the kernel
    // clears the permitted set entirely when a process's uid transitions
    // away from 0 (capabilities(7)), which would take CAP_NET_ADMIN with
    // it. With KEEPCAPS the permitted set survives the transition (the
    // effective set is still cleared, so we re-raise it below), letting us
    // then narrow it down to exactly the one capability we still need.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1) } != 0 {
        return Err(MlvpnError::Privilege(format!(
            "prctl(PR_SET_KEEPCAPS): {}",
            std::io::Error::last_os_error()
        )));
    }

    // Order matters: clear supplementary groups and set the real/effective
    // gid *before* dropping the uid. Once we're no longer root we lose the
    // ability to change gid at all.
    setgroups(&[])
        .map_err(|e| MlvpnError::Privilege(format!("clearing supplementary groups: {e}")))?;
    setgid(group.gid).map_err(|e| MlvpnError::Privilege(format!("setgid: {e}")))?;
    setuid(user.uid).map_err(|e| MlvpnError::Privilege(format!("setuid: {e}")))?;

    // Narrow the retained capabilities to exactly CAP_NET_ADMIN. KEEPCAPS
    // preserved the whole permitted set across setuid(), which is far more
    // than we want, so shrink permitted first (a set can only ever be
    // reduced from here), then raise the same single capability into the
    // effective set so `SIOCSIFMTU` actually works. Inheritable is cleared
    // outright -- nothing here execs a child, so nothing should inherit.
    let keep: caps::CapsHashSet = std::iter::once(caps::Capability::CAP_NET_ADMIN).collect();
    caps::set(None, caps::CapSet::Permitted, &keep)
        .map_err(|e| MlvpnError::Privilege(format!("restricting permitted capabilities: {e}")))?;
    caps::set(None, caps::CapSet::Effective, &keep)
        .map_err(|e| MlvpnError::Privilege(format!("raising CAP_NET_ADMIN: {e}")))?;
    if let Err(e) = caps::clear(None, caps::CapSet::Inheritable) {
        tracing::debug!(error = %e, "clearing inheritable capabilities (likely already empty)");
    }

    // Leave KEEPCAPS off again now that the narrowing is done, so any
    // future uid change in this process gets the kernel's default
    // clear-everything behavior rather than silently carrying caps along.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0) } != 0 {
        tracing::debug!(
            error = %std::io::Error::last_os_error(),
            "clearing PR_SET_KEEPCAPS after privilege drop"
        );
    }

    tracing::info!(
        user = %target.user,
        group = %target.group,
        "dropped privileges (retaining CAP_NET_ADMIN for live TUN MTU resize)"
    );
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
