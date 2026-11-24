// Shared with the apps' build scripts (`include!("<vendor>/jpps-update/src/display.rs")` sets APP_VERSION), so
// this file holds only this one function and uses nothing else.

/// Date versions (Jeff 2026-11-22: YY.MM.DD.hhmm). `Cargo.toml` can only hold three numbers without leading zeros,
/// so it carries `YY.MMDD.hhmm` (26.1122.2130); everything people see uses `YY.MM.DD.hhmm` (26.11.22.2130). Any other
/// version (the old 0.x ones) is returned as it is.
pub fn display_version(cargo: &str) -> String {
    // Written for both Rust editions (JPPS VPN is 2021): no let chains.
    // A Beta keeps its suffix: 26.1123.1400-beta1 shows as 26.11.23.1400-beta1.
    if let Some(i) = cargo.find('-') {
        return format!("{}{}", display_version(&cargo[..i]), &cargo[i..]);
    }
    let parts: Vec<&str> = cargo.split('.').collect();
    let n: Vec<u32> = parts.iter().filter_map(|p| p.parse().ok()).collect();
    if parts.len() == 3 && n.len() == 3 {
        let (yy, mmdd, hhmm) = (n[0], n[1], n[2]);
        let date_like = (20..=99).contains(&yy)
            && (1..=12).contains(&(mmdd / 100))
            && (1..=31).contains(&(mmdd % 100))
            && hhmm / 100 <= 23
            && hhmm % 100 <= 59;
        if date_like {
            return format!("{yy:02}.{:02}.{:02}.{hhmm:04}", mmdd / 100, mmdd % 100);
        }
    }
    cargo.to_string()
}
