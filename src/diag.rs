//! Human-readable diagnostic dump: renders an `ipc::Snapshot` (the same
//! link/daemon health data `mlvpn-tui` shows) into a single text bundle
//! meant to be attached to a bug report -- see `ipc::Command::DiagDump`
//! (on-demand, via `mlvpnd diag-dump`) and `control::diagnostics_watch_loop`
//! (automatic, on a loss-threshold trip -- see `config::DiagnosticsConfig`).
//!
//! Deliberately daemon-visible data only: no shelling out to external
//! tools (`nstat`/`ss`) from here, since `diagnostics_watch_loop` renders
//! this same text from inside the (systemd-sandboxed by default) daemon
//! process itself, where spawning arbitrary external binaries is both
//! more restricted and a bigger attack-surface question than it is for a
//! CLI invocation. `mlvpnd diag-dump`'s kernel-level UDP diagnostics
//! (`main.rs::capture_kernel_udp_diagnostics`) are gathered by the CLI
//! process instead, running as the invoking operator, and appended
//! alongside this text there -- not part of this module.

use crate::ipc::Snapshot;

/// Renders `snapshot` into a plain-text diagnostic bundle, prefixed with
/// `trigger` (e.g. `"manual (mlvpnd diag-dump)"` or an automatic
/// threshold-trip description). Callers building a dump specifically
/// (as opposed to a routine `mlvpn-tui` poll) should fetch `snapshot`
/// with a log cursor of `0` so `new_log_lines` carries everything
/// currently in the ring rather than just a recent delta -- see
/// `logbuf::LogRing::entries_since`'s doc comment.
pub fn format_dump(snapshot: &Snapshot, trigger: &str) -> String {
    let mut out = String::new();
    out.push_str("=== mlvpn diagnostic dump ===\n");
    out.push_str(&format!("generated_unix_ms: {}\n", snapshot.unix_ts_ms));
    out.push_str(&format!(
        "tunnel: {} ({})\n",
        snapshot.tunnel_name, snapshot.mode
    ));
    out.push_str(&format!("trigger: {trigger}\n\n"));

    out.push_str("--- Links ---\n");
    if snapshot.links.is_empty() {
        out.push_str("(no links configured)\n\n");
    }
    for l in &snapshot.links {
        out.push_str(&format!(
            "{name}: state={state} up_for={dur}ms score={score:.2}\n",
            name = l.name,
            state = l.state,
            dur = l.state_duration_ms,
            score = l.score,
        ));
        out.push_str(&format!(
            "  local:  rtt={rtt} jitter={jitter} loss={loss} rx={rx} tx={tx} active_bw={bw} \
             hits={hits} misses={misses}\n",
            rtt = fmt_opt_ms(l.local_rtt_ms),
            jitter = fmt_opt_ms(l.local_jitter_ms),
            loss = fmt_opt_pct(l.local_loss_pct),
            rx = fmt_opt_mbps(l.local_rx_throughput_mbps),
            tx = fmt_opt_mbps(l.local_tx_throughput_mbps),
            bw = fmt_opt_mbps(l.local_active_bandwidth_mbps),
            hits = l.local_consecutive_hits,
            misses = l.local_consecutive_misses,
        ));
        out.push_str(&format!(
            "  peer:   state={state} rtt={rtt} jitter={jitter} loss={loss} throughput={tp} \
             age={age}\n",
            state = l.peer_state.as_deref().unwrap_or("n/a"),
            rtt = fmt_opt_ms(l.peer_rtt_ms),
            jitter = fmt_opt_ms(l.peer_jitter_ms),
            loss = fmt_opt_pct(l.peer_loss_pct),
            tp = fmt_opt_mbps(l.peer_throughput_mbps),
            age = l
                .peer_stats_age_ms
                .map(|v| format!("{v}ms"))
                .unwrap_or_else(|| "n/a".to_string()),
        ));
        out.push_str(&format!(
            "  totals: tx_bytes={} rx_bytes={} tx_packets={} rx_packets={}\n\n",
            l.tx_bytes, l.rx_bytes, l.tx_packets, l.rx_packets,
        ));
    }

    let d = &snapshot.daemon;
    out.push_str("--- Daemon ---\n");
    out.push_str(&format!(
        "version: local={} peer={}\n",
        d.local_version,
        d.peer_version.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "session_id={} session_uptime_ms={} rekey_count={}\n",
        d.session_id, d.session_uptime_ms, d.rekey_count
    ));
    out.push_str(&format!(
        "outbound_queue: {}/{} (dropped_lifetime={})\n",
        d.outbound_queue_len, d.outbound_queue_capacity, d.outbound_queue_dropped_total
    ));
    out.push_str(&format!(
        "tun({}): rx_bytes={} tx_bytes={} rx_errors={} tx_errors={} rx_dropped={} \
         tx_dropped={}\n",
        d.tun.iface,
        fmt_opt_u64(d.tun.rx_bytes),
        fmt_opt_u64(d.tun.tx_bytes),
        fmt_opt_u64(d.tun.rx_errors),
        fmt_opt_u64(d.tun.tx_errors),
        fmt_opt_u64(d.tun.rx_dropped),
        fmt_opt_u64(d.tun.tx_dropped),
    ));
    out.push_str(&format!(
        "system: load={},{},{} mem_total_kb={} mem_available_kb={} uptime_secs={}\n\n",
        fmt_opt_f64(d.system.load1),
        fmt_opt_f64(d.system.load5),
        fmt_opt_f64(d.system.load15),
        fmt_opt_u64(d.system.mem_total_kb),
        fmt_opt_u64(d.system.mem_available_kb),
        fmt_opt_u64(d.system.uptime_secs),
    ));

    out.push_str(&format!(
        "--- Recent log lines ({}) ---\n",
        snapshot.new_log_lines.len()
    ));
    for entry in &snapshot.new_log_lines {
        out.push_str(&format!(
            "[{}] {} {}: {}\n",
            entry.unix_ts_ms,
            entry.level,
            entry.target.as_deref().unwrap_or("-"),
            entry.message,
        ));
    }

    out
}

/// The link with the highest `local_loss_pct` that exceeds
/// `threshold_pct`, if any -- `None` when every link is at or below
/// threshold, or has no loss reading yet (e.g. before that link's first
/// probe completes). Used by `control::diagnostics_watch_loop` to decide
/// whether an automatic dump should fire this tick; picking the worst
/// (not just the first) offender means the dump's `trigger` line always
/// names the link actually responsible when more than one is degraded.
pub fn worst_loss_link(snapshot: &Snapshot, threshold_pct: f64) -> Option<(String, f64)> {
    snapshot
        .links
        .iter()
        .filter_map(|l| l.local_loss_pct.map(|loss| (l.name.clone(), loss)))
        .filter(|(_, loss)| *loss > threshold_pct)
        .max_by(|a, b| a.1.total_cmp(&b.1))
}

fn fmt_opt_ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}ms"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn fmt_opt_pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn fmt_opt_mbps(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}Mbps"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn fmt_opt_u64(v: Option<u64>) -> String {
    v.map(|v| v.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

fn fmt_opt_f64(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "n/a".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{DaemonSnapshot, LinkSnapshot, SystemSnapshot, TunSnapshot};

    fn fixture_link(name: &str, local_loss_pct: Option<f64>) -> LinkSnapshot {
        LinkSnapshot {
            name: name.to_string(),
            bind_interface: "eth0".to_string(),
            local_port: 6900,
            remote_addr: Some("203.0.113.5:6900".to_string()),
            state: "up".to_string(),
            score: 0.75,
            state_duration_ms: 12_345,
            tx_bytes: 1_000,
            rx_bytes: 2_000,
            tx_packets: 10,
            rx_packets: 20,
            local_rtt_ms: Some(24.1),
            local_jitter_ms: Some(3.2),
            local_loss_pct,
            local_rx_throughput_mbps: Some(93.4),
            local_tx_throughput_mbps: Some(12.1),
            local_active_bandwidth_mbps: Some(39.4),
            local_consecutive_hits: 0,
            local_consecutive_misses: 5,
            peer_name: Some("lte0".to_string()),
            peer_state: Some("up".to_string()),
            peer_rtt_ms: Some(25.0),
            peer_jitter_ms: Some(3.5),
            peer_loss_pct: Some(2.1),
            peer_throughput_mbps: Some(10.2),
            peer_stats_age_ms: Some(412),
        }
    }

    fn fixture_snapshot(links: Vec<LinkSnapshot>) -> Snapshot {
        Snapshot {
            tunnel_name: "mlvpn0".to_string(),
            mode: "client".to_string(),
            unix_ts_ms: 1_753_000_000_000,
            links,
            daemon: DaemonSnapshot {
                session_id: 42,
                session_uptime_ms: 60_000,
                rekey_count: 3,
                outbound_queue_len: 0,
                outbound_queue_capacity: 1024,
                outbound_queue_dropped_total: 0,
                tun: TunSnapshot {
                    iface: "mlvpn0".to_string(),
                    rx_bytes: Some(1_000_000),
                    tx_bytes: Some(2_000_000),
                    rx_errors: Some(0),
                    tx_errors: Some(0),
                    rx_dropped: Some(0),
                    tx_dropped: Some(0),
                },
                system: SystemSnapshot {
                    load1: Some(0.38),
                    load5: Some(0.25),
                    load15: Some(0.18),
                    mem_total_kb: Some(16_000_000),
                    mem_available_kb: Some(8_000_000),
                    uptime_secs: Some(79_200),
                },
                local_version: "0.4.5".to_string(),
                peer_version: Some("0.4.5".to_string()),
            },
            new_log_lines: Vec::new(),
        }
    }

    #[test]
    fn format_dump_includes_link_daemon_and_trigger_details() {
        let snap = fixture_snapshot(vec![fixture_link("comcast", Some(41.0))]);
        let text = format_dump(&snap, "manual (mlvpnd diag-dump)");
        assert!(text.contains("trigger: manual (mlvpnd diag-dump)"));
        assert!(text.contains("tunnel: mlvpn0 (client)"));
        assert!(text.contains("comcast: state=up"));
        assert!(text.contains("loss=41.0%"));
        assert!(text.contains("version: local=0.4.5 peer=0.4.5"));
        assert!(text.contains("session_id=42"));
        assert!(text.contains("outbound_queue: 0/1024"));
        assert!(text.contains("tun(mlvpn0):"));
        assert!(text.contains("load=0.38,0.25,0.18"));
    }

    #[test]
    fn format_dump_handles_no_links_and_missing_optional_fields() {
        let snap = fixture_snapshot(Vec::new());
        let text = format_dump(&snap, "test");
        assert!(text.contains("(no links configured)"));
    }

    #[test]
    fn format_dump_renders_recent_log_lines() {
        use crate::ipc::LogEntry;
        let mut snap = fixture_snapshot(Vec::new());
        snap.new_log_lines.push(LogEntry {
            seq: 1,
            unix_ts_ms: 1_753_000_000_500,
            level: "WARN".to_string(),
            target: Some("mlvpn::tunnel".to_string()),
            message: "link comcast: 5 consecutive probe misses".to_string(),
        });
        let text = format_dump(&snap, "test");
        assert!(text.contains("Recent log lines (1)"));
        assert!(text.contains("WARN mlvpn::tunnel: link comcast: 5 consecutive probe misses"));
    }

    #[test]
    fn worst_loss_link_returns_none_when_every_link_is_under_threshold() {
        let snap = fixture_snapshot(vec![
            fixture_link("comcast", Some(2.0)),
            fixture_link("tmobile", Some(9.9)),
        ]);
        assert_eq!(worst_loss_link(&snap, 10.0), None);
    }

    #[test]
    fn worst_loss_link_ignores_links_with_no_loss_reading_yet() {
        let snap = fixture_snapshot(vec![fixture_link("comcast", None)]);
        assert_eq!(worst_loss_link(&snap, 10.0), None);
    }

    #[test]
    fn worst_loss_link_picks_the_highest_offender_not_just_the_first() {
        let snap = fixture_snapshot(vec![
            fixture_link("comcast", Some(41.0)),
            fixture_link("tmobile", Some(73.0)),
        ]);
        assert_eq!(
            worst_loss_link(&snap, 10.0),
            Some(("tmobile".to_string(), 73.0))
        );
    }

    #[test]
    fn worst_loss_link_boundary_is_strictly_greater_than_threshold() {
        let snap = fixture_snapshot(vec![fixture_link("comcast", Some(10.0))]);
        assert_eq!(worst_loss_link(&snap, 10.0), None);
    }
}
