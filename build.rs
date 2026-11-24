// YY.MM.DD.hhmm for people (Jeff 2026-11-22); Cargo.toml holds YY.MMDD.hhmm. Set it at each release with
// `python3 vendor/jpps-update/tools/version.py now` (copied from jpps/jpps-update).
include!("vendor/jpps-update/src/display.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vendor/jpps-update/src/display.rs");
    let app_version = display_version(&std::env::var("CARGO_PKG_VERSION").unwrap());
    println!("cargo:rustc-env=APP_VERSION={app_version}");
}
