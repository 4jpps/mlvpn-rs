//! Reads the TUN device's own kernel-tracked counters from
//! `/sys/class/net/<iface>/statistics/*`.
//!
//! This is an independent view of the same device `mlvpnd` reads
//! plaintext packets from in `tunnel::tun_reader` -- unlike the
//! per-link `LinkSnapshot` tx/rx counters (which only count bytes this
//! process actually handed to a link's socket), these are the kernel's
//! own counters for the TUN device as a whole, useful as a cross-check
//! and for spotting kernel-side drops/errors this process would never
//! otherwise see.

use std::path::Path;

/// One `/sys/class/net/<iface>/statistics/*` snapshot. Every field is
/// `Option` rather than defaulting to 0 on a read failure -- a missing
/// or renamed interface should read as "unknown" to a viewer, not
/// "zero traffic".
#[derive(Debug, Clone, Default)]
pub struct TunIfaceStats {
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub rx_errors: Option<u64>,
    pub tx_errors: Option<u64>,
    pub rx_dropped: Option<u64>,
    pub tx_dropped: Option<u64>,
}

/// Reads all six counters for `iface`. Never panics -- a torn-down or
/// renamed interface (or an environment without sysfs) just yields a
/// `TunIfaceStats` full of `None`s.
pub fn read_tun_stats(iface: &str) -> TunIfaceStats {
    let base = Path::new("/sys/class/net").join(iface).join("statistics");
    TunIfaceStats {
        rx_bytes: read_counter(&base, "rx_bytes"),
        tx_bytes: read_counter(&base, "tx_bytes"),
        rx_errors: read_counter(&base, "rx_errors"),
        tx_errors: read_counter(&base, "tx_errors"),
        rx_dropped: read_counter(&base, "rx_dropped"),
        tx_dropped: read_counter(&base, "tx_dropped"),
    }
}

fn read_counter(base: &Path, name: &str) -> Option<u64> {
    std::fs::read_to_string(base.join(name))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_interface_yields_all_none_not_a_panic() {
        let stats = read_tun_stats("mlvpn-definitely-does-not-exist-0");
        assert_eq!(stats.rx_bytes, None);
        assert_eq!(stats.tx_bytes, None);
        assert_eq!(stats.rx_errors, None);
        assert_eq!(stats.tx_errors, None);
        assert_eq!(stats.rx_dropped, None);
        assert_eq!(stats.tx_dropped, None);
    }

    #[test]
    fn loopback_interface_yields_real_counters() {
        // "lo" exists on essentially every Linux host, including CI
        // containers -- a reasonable, always-available real-sysfs
        // smoke test without needing root or a veth pair.
        let stats = read_tun_stats("lo");
        assert!(stats.rx_bytes.is_some());
        assert!(stats.tx_bytes.is_some());
    }
}
