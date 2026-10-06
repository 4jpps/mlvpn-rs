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
pub mod congestion;
pub mod control;
pub mod crypto;
pub mod delivery;
pub mod diag;
pub mod diagnostics;
pub mod error;
pub mod events;
pub mod fec;
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
pub mod telemetry;
pub mod tunnel;
pub mod tunneltest;
pub mod wireguard;

/// `Cargo.toml`'s own semver-only version (e.g. "0.7.3") -- the same
/// for every build regardless of release channel. Prefer [`version()`]
/// for anything user-facing; this exists mainly as the input it's
/// built from.
pub const CARGO_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Set by CI for a Beta build (e.g. "beta7") via the `MLVPN_BUILD_SUFFIX`
/// env var at `cargo build` time -- see `.beta_build_suffix` in
/// `.gitlab-ci.yml`. `None` for a real `vX.Y.Z` Stable release build and
/// for any local dev build (`cargo build` with the var unset).
pub const BUILD_SUFFIX: Option<&str> = option_env!("MLVPN_BUILD_SUFFIX");

/// This build's own full, user-facing `mlvpnd`/`mlvpn-tui` version --
/// the single source `PacketType::VersionInfo`'s sender
/// (`tunnel::send_version_info`), `DaemonSnapshot::local_version`
/// (`control::build_snapshot`), and the CLI self-test commands'
/// mismatch check (`main.rs`) all read from, rather than each building
/// it separately. `CARGO_VERSION` alone for a Stable release (e.g.
/// "0.7.3"); `CARGO_VERSION-BUILD_SUFFIX` for a Beta build (e.g.
/// "0.7.3-beta7"), so a Beta install is identifiable at a glance
/// instead of every Beta showing the same bare base version as the
/// eventual Stable release -- and two different Betas sharing a base
/// version (e.g. beta6 vs beta7) are no longer indistinguishable to
/// the peer-version-mismatch check either. See
/// `jpps_stable_beta_release_pattern` memory / the `.beta_build_suffix`
/// CI block this mirrors. `VERSION_LEN` (`protocol.rs`) is 16 bytes,
/// comfortably fitting any realistic `X.Y.Z-betaNN`.
pub fn version() -> String {
    format_version(CARGO_VERSION, BUILD_SUFFIX)
}

/// Pure formatting logic behind [`version()`], pulled out purely so
/// `#[test]` can exercise both branches directly -- `BUILD_SUFFIX` is
/// an `option_env!` read at compile time, so a real `cargo test` run
/// (with `MLVPN_BUILD_SUFFIX` unset) can never observe the `Some(...)`
/// branch through `version()` itself.
fn format_version(cargo_version: &str, suffix: Option<&str>) -> String {
    match suffix {
        Some(s) if !s.is_empty() => format!("{cargo_version}-{s}"),
        _ => cargo_version.to_string(),
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn stable_build_has_no_suffix() {
        assert_eq!(format_version("0.7.3", None), "0.7.3");
    }

    #[test]
    fn beta_build_appends_the_suffix() {
        assert_eq!(format_version("0.7.3", Some("beta7")), "0.7.3-beta7");
    }

    #[test]
    fn an_empty_suffix_is_treated_the_same_as_none() {
        // Defensive: `MLVPN_BUILD_SUFFIX=""` (set but empty) shouldn't
        // produce a trailing bare hyphen like "0.7.3-".
        assert_eq!(format_version("0.7.3", Some("")), "0.7.3");
    }
}
