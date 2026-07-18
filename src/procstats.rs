//! Reads machine-wide health from `/proc/loadavg`, `/proc/meminfo`, and
//! `/proc/uptime` -- context for whether a link/tunnel problem is
//! actually a host problem (e.g. the box itself is under heavy load or
//! low on memory) rather than anything link- or tunnel-specific.
//!
//! The actual line-parsing is factored into small functions taking
//! `&str`, not a path, so they're unit-testable against fixed sample
//! content without depending on real `/proc` content being available
//! (or having any particular shape) in CI.

/// Always constructible (`Default`), with every field `Option` since
/// each of the three underlying reads/parses can fail independently.
#[derive(Debug, Clone, Default)]
pub struct SystemStats {
    pub load1: Option<f64>,
    pub load5: Option<f64>,
    pub load15: Option<f64>,
    pub mem_total_kb: Option<u64>,
    pub mem_available_kb: Option<u64>,
    pub uptime_secs: Option<u64>,
}

/// Reads and parses all three `/proc` sources. Never panics -- any
/// individual read/parse failure just leaves that field (or set of
/// fields) `None` in the result.
pub fn read_system_stats() -> SystemStats {
    let (load1, load5, load15) = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| parse_loadavg(&s))
        .unwrap_or((None, None, None));
    let (mem_total_kb, mem_available_kb) = std::fs::read_to_string("/proc/meminfo")
        .map(|s| parse_meminfo(&s))
        .unwrap_or((None, None));
    let uptime_secs = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| parse_uptime(&s));

    SystemStats {
        load1,
        load5,
        load15,
        mem_total_kb,
        mem_available_kb,
        uptime_secs,
    }
}

/// `/proc/loadavg` looks like `"0.52 0.58 0.59 1/234 12345\n"` -- the
/// first three whitespace-separated fields are the 1/5/15-minute load
/// averages. Returns `None` (as a whole) only if the line doesn't even
/// have three fields; a single unparseable field still yields `Some`
/// with that one slot `None` rather than discarding the other two.
fn parse_loadavg(s: &str) -> Option<(Option<f64>, Option<f64>, Option<f64>)> {
    let mut fields = s.split_whitespace();
    let one = fields.next()?;
    let five = fields.next()?;
    let fifteen = fields.next()?;
    Some((one.parse().ok(), five.parse().ok(), fifteen.parse().ok()))
}

/// `/proc/meminfo` is one `"Key:       12345 kB\n"` line per field --
/// only `MemTotal`/`MemAvailable` are needed here, so this just scans
/// for those two keys and ignores the rest of the (much longer) file.
fn parse_meminfo(s: &str) -> (Option<u64>, Option<u64>) {
    let mut total = None;
    let mut available = None;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    (total, available)
}

/// `/proc/uptime` looks like `"12345.67 98765.43\n"` -- the first field
/// is system uptime in seconds (the second, idle time summed across
/// all CPUs, isn't needed here). Truncated to whole seconds, matching
/// this codebase's other duration fields (`state_duration_ms` etc.
/// are all integer units, never fractional).
fn parse_uptime(s: &str) -> Option<u64> {
    let first = s.split_whitespace().next()?;
    let secs: f64 = first.parse().ok()?;
    Some(secs as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_loadavg_line() {
        let (one, five, fifteen) = parse_loadavg("0.52 0.58 0.59 1/234 12345\n").unwrap();
        assert_eq!(one, Some(0.52));
        assert_eq!(five, Some(0.58));
        assert_eq!(fifteen, Some(0.59));
    }

    #[test]
    fn loadavg_with_too_few_fields_yields_none() {
        assert_eq!(parse_loadavg("0.52 0.58\n"), None);
    }

    #[test]
    fn loadavg_with_a_garbled_field_still_parses_the_others() {
        let (one, five, fifteen) = parse_loadavg("oops 0.58 0.59 1/234 12345\n").unwrap();
        assert_eq!(one, None);
        assert_eq!(five, Some(0.58));
        assert_eq!(fifteen, Some(0.59));
    }

    #[test]
    fn parses_mem_total_and_available_out_of_a_full_meminfo_sample() {
        let sample = "MemTotal:       16384000 kB\n\
                       MemFree:         1234000 kB\n\
                       MemAvailable:    8192000 kB\n\
                       Buffers:          100000 kB\n";
        let (total, available) = parse_meminfo(sample);
        assert_eq!(total, Some(16_384_000));
        assert_eq!(available, Some(8_192_000));
    }

    #[test]
    fn meminfo_missing_a_key_yields_none_for_just_that_field() {
        let (total, available) = parse_meminfo("MemTotal:       16384000 kB\n");
        assert_eq!(total, Some(16_384_000));
        assert_eq!(available, None);
    }

    #[test]
    fn parses_uptime_truncated_to_whole_seconds() {
        assert_eq!(parse_uptime("12345.67 98765.43\n"), Some(12_345));
    }

    #[test]
    fn empty_uptime_content_yields_none() {
        assert_eq!(parse_uptime(""), None);
    }

    #[test]
    fn real_proc_read_does_not_panic() {
        // Smoke test against the real /proc on whatever host runs the
        // suite -- every field should come back Some on any real Linux
        // box (including CI containers), but this test doesn't assert
        // that; it only asserts read_system_stats never panics, since
        // the string-based parser tests above already cover correctness.
        let _ = read_system_stats();
    }
}
