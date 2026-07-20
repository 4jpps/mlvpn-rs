//! Library crate backing the `mlvpnd` daemon binary and the `mlvpn-tui`
//! monitoring binary. Split out so both binaries can share the on-disk/
//! wire-adjacent types (`ipc`, `protocol`) without duplicating them --
//! `mlvpnd` writes `ipc::Snapshot`s to the control socket, `mlvpn-tui`
//! reads them back, and both need the same struct definitions to agree.
//!
//! Everything here is `pub` for the sake of the two binaries in this same
//! workspace, not because it's meant as a general-purpose external API:
//! this crate is not published, and its `Cargo.toml` has no `[lib]`
//! consumers outside `src/main.rs` and `src/bin/mlvpn-tui.rs`.

pub mod config;
pub mod control;
pub mod crypto;
pub mod diag;
pub mod error;
pub mod firewall;
pub mod ipc;
pub mod link;
pub mod logbuf;
pub mod monitor;
pub mod mss;
pub mod peerstats;
pub mod privilege;
pub mod procstats;
pub mod protocol;
pub mod scheduler;
pub mod sysfs_net;
pub mod tunnel;
pub mod tunneltest;
