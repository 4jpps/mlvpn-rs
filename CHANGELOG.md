# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/) once this
project has a stable public release -- pre-1.0, minor bumps may still
include breaking config/wire changes, called out explicitly below.

## [0.2.0] - 2026-07-13

### Added

- **IPv6 dual-stack support on the TUN interface.** New optional
  `tunnel.address6` config field (an IPv6 CIDR, e.g. `fd00:200::1/64`)
  assigns a second address family to the same `mlvpn0` device alongside
  the existing IPv4 `tunnel.address` -- both share the same encrypted
  Noise session and bonded links; there is no separate "IPv6 tunnel."
  Backward compatible: omitting `address6` leaves the interface exactly
  as IPv4-only as before. The underlying UDP transport between `mlvpnd`
  instances is still IPv4-only (see `ARCHITECTURE.md` §11 item 4) --
  this is dual-stack *payload*, not dual-stack transport; scoped that
  way deliberately rather than also touching `link.rs`'s socket
  binding, `firewall.rs`'s rule generation, and everything downstream
  of them in the same change.
- **Adaptive tunnel MTU.** `tunnel.mtu` is now an upper bound, not a
  fixed value. At startup, each bonded link's real physical interface
  MTU is queried via the `SIOCGIFMTU` ioctl (`link::query_interface_mtu`,
  Linux-only, best-effort -- a link whose MTU can't be determined
  simply doesn't participate, it never blocks startup). `main.rs`'s new
  `effective_tunnel_mtu()` auto-clamps the configured value down (with
  a logged warning explaining why and to what) if it would exceed what
  the smallest detected physical MTU can carry without fragmentation.
  This replaces relying solely on the previous config-time-only
  advisory warning (still present in `config.rs`'s `validate()` as a
  generic pre-flight sanity check, since it runs before any link
  exists to ask) with a real, self-correcting default that reflects
  each deployment's actual hardware.
- **TCP MSS clamping** (`mss.rs`), on by default via the new
  `tunnel.clamp_mss` config option. Adaptive MTU alone only bounds the
  tunnel's own outer packet size; individual TCP connections passing
  *through* the tunnel still negotiate their own segment size via Path
  MTU Discovery, which many networks silently break by dropping the
  ICMP messages it depends on (the "PMTUD black hole" -- affected
  connections don't run slower, they stall). `tunnel::tun_reader` now
  inspects plaintext packets read off the TUN device before encryption
  and, for TCP SYN/SYN-ACK segments (IPv4 or IPv6) whose advertised MSS
  exceeds what the effective tunnel MTU can carry, rewrites that option
  in place and recomputes the TCP checksum -- the same technique
  `iptables --clamp-mss-to-pmtu` and most consumer VPN/router firmware
  use. Deliberately conservative: anything that doesn't cleanly parse
  as a well-formed TCP SYN (wrong protocol, truncated packet, IPv6
  extension headers, a malformed option list) is left completely
  untouched rather than risk corrupting it. Covered by unit tests that
  build synthetic IPv4/IPv6 SYN packets and self-verify the recomputed
  checksum (summing pseudo-header + segment including the written
  checksum folds to exactly 0, the standard property of the algorithm)
  in addition to checking the clamped MSS value itself.
- **`ARCHITECTURE.md`: "Relationship to the original MLVPN" section.**
  Credits [MLVPN](https://github.com/zehome/MLVPN) (Laurent Coustet,
  `zehome`, BSD-2-Clause, C/libev/libsodium) for the bonding/monitoring/
  failover concept this project is a from-scratch Rust rewrite of --
  no code is shared between the two -- and documents the specific,
  deliberate departures from that design and why: binding to a network
  interface (`SO_BINDTODEVICE`) rather than a specific IP address (the
  original's `bindhost` is documented as "IPv4 only," and breaks when
  that address changes, e.g. DHCP renewal or LTE roaming, until
  manually reconfigured), a memory-safe implementation, a
  `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake with mutual
  authentication and forward secrecy instead of a shared
  password-derived key, `async`/tokio concurrency instead of a
  single-threaded event loop, privilege *dropping* rather than
  multi-process privilege *separation*, and this release's IPv6/MTU/
  MSS additions. Verified against the original project's actual README
  and `mlvpn.conf.5` man page rather than assumed.

## [0.1.2] - 2026-07-13

### Security

- **`lru` IterMut soundness advisory (RUSTSEC, affects `lru` >= 0.9.0,
  < 0.16.3, fixed in 0.16.3).** `lru` entered the dependency tree only
  transitively, via `ratatui` 0.29.0 (which pins `lru = "0.12.0"`,
  resolving to the vulnerable 0.12.5) -- reachable only through
  `mlvpn-tui`, the terminal monitoring binary; `mlvpnd`'s core/data-path
  code never depends on it. A Cargo `[patch]` override can't fix this
  while staying on `ratatui` 0.29: patched versions must still satisfy
  the original dependency's semver requirement, and 0.12.x/0.16.x are
  incompatible pre-1.0 minors. Fixed by bumping `ratatui` to 0.30 (its
  latest release, and the version whose own dependency graph requires
  `lru` >= 0.16). Reviewed ratatui's published 0.30 breaking-changes
  list line by line against `src/bin/mlvpn-tui.rs`'s actual usage
  (removed `block::Title`, the `Style`/`Stylize` split, the
  `Alignment` rename, `Marker`, `Flex::SpaceAround`, and the `Backend`
  trait's new associated `Error`/`clear_region` requirement) -- none of
  it is exercised by this codebase, so no source changes were needed
  beyond the dependency bump itself. `Cargo.toml`'s `ratatui` feature
  list is now explicit (`default-features = false` plus `crossterm`,
  `underline-color`, `layout-cache`) to keep the same footprint as
  0.29, since 0.30's new defaults would otherwise pull in an unused
  `time` dependency for a calendar widget this project doesn't use.

- Full dependency audit against the RustSec advisory database (every
  crate in `Cargo.lock` with a published advisory, checked against our
  actual locked version): `tokio` 1.52.3 (patched for RUSTSEC-2025-0023
  since >=1.44.2), `bytes` 1.12.1 (patched for RUSTSEC-2026-0007 since
  >=1.11.1), `rand` 0.8.7/0.9.5 (patched for RUSTSEC-2026-0097),
  `tracing-subscriber` 0.3.23 (patched for RUSTSEC-2025-0055 since
  >=0.3.20), `ring` 0.17.14 (patched for RUSTSEC-2025-0009 since
  >=0.17.12), `time` 0.3.53 (patched for RUSTSEC-2026-0009 since
  >=0.3.47), `snow` 0.10.0 (patched for RUSTSEC-2024-0011 since
  >=0.9.5 -- our core Noise implementation), `curve25519-dalek` 4.1.3
  and `aes-gcm` 0.10.3 (each exactly at their patched floor), `nix`
  0.27.1/0.29-0.31 (patched for RUSTSEC-2021-0119 since >=0.23.0),
  `zerocopy` 0.8.54 and `hashbrown` 0.16.1/0.17.1 (both well past their
  patched floors). Every one of them already resolves to a
  non-vulnerable version under the existing `Cargo.toml` semver ranges
  -- no further pins or `[patch]` entries needed beyond the `lru` fix
  above.

### Changed

- Minimum supported Rust version raised from 1.75 to 1.86, which
  `ratatui` 0.30 itself requires. Updated everywhere it's declared:
  `Cargo.toml`, `debian/control`, `packaging/rpm/mlvpn.spec`, and the
  CI/release workflow comments referencing it.

### Fixed

- `.github/workflows/release.yml`'s RPM build failed on the
  RHEL-family leg (`rockylinux:9`) with `cargo/rust >= 1.75 is needed`
  regardless of the actual toolchain version, because Rust is installed
  there via `dtolnay/rust-toolchain` (rustup), which `rpmbuild`'s
  internal `BuildRequires` check can't see -- it only knows about
  dnf-tracked packages. Same root cause as the `.deb` build's
  `dpkg-buildpackage -d` flag exists for. Added the equivalent
  `rpmbuild -ba --nodeps`.
- With that fixed, the RPM build then failed at packaging time with
  `Empty %files file .../debugsourcefiles.list`: `[profile.release]`
  in `Cargo.toml` sets `strip = true`, so the compiled binaries carry
  no debug symbols for `rpmbuild`'s automatic `find-debuginfo` pass to
  extract, and it errors out rather than silently producing an empty
  `mlvpn-debugsource` subpackage. Added `%global debug_package %{nil}`
  to `packaging/rpm/mlvpn.spec` to disable debuginfo package
  generation entirely, the standard fix for pre-stripped binaries.

## [0.1.1] - 2026-07-13

### Added

- `mlvpn-tui`: a terminal monitoring view. Shows every bonded link's
  state, the peer address it's talking to, this side's own measured
  RTT/jitter/loss/throughput, and the peer's self-reported view of the
  same link side by side, refreshed live.
- `mlvpnd` control socket: a local Unix domain socket
  (`/run/mlvpn/<tunnel.name>.sock` by default, mode 0600) that streams
  newline-delimited JSON snapshots of link/traffic state. On by default;
  disable with `[control] enabled = false`. See `ARCHITECTURE.md` §9.
- `PacketType::StatsShare`: a new authenticated wire frame type peers use
  to exchange their own locally-measured link stats, so each side's
  `mlvpn-tui` can show a full-duplex view instead of only its own
  measurements. Old builds that don't recognize this frame type simply
  drop it (forward-compatible).
- `[control]` config section (`enabled`, `socket_path`).
- GitHub Actions CI (`build + cargo test` on every push/PR to `main`) and
  a release workflow that builds and publishes a `.deb` via
  `dpkg-buildpackage` on version tags (`v*`), or on manual dispatch.
- arm64 support: CI and the release workflow now build natively on both
  amd64 (`ubuntu-latest`) and arm64 (`ubuntu-24.04-arm`) runners --
  `debian/control` already declared `Architecture: any`, so this is just
  running the existing build on a second native runner, not
  cross-compiling. Tagged releases attach a `.deb` for each
  architecture.
- `.gitignore` for build artifacts, debian packaging scratch directories,
  and generated key material.
- `mlvpnd firewall-setup` subcommand (`src/firewall.rs`): detects which
  of `firewalld`, `ufw`, `nftables`, or `iptables` (legacy) is actively
  managing the host and opens inbound UDP access for every configured
  `[[links]]` port, on either end regardless of `client`/`server` mode.
  Supports `--dry-run` (prints the exact commands without running them),
  `--remove` (closes the same ports), and `--backend` (skip
  auto-detection). Deliberately a separate one-shot admin command, not
  something `mlvpnd run` does on every startup -- mutating firewall
  state is a different trust boundary than anything else this daemon
  touches. Every command runs as an argv vector, never through a shell.
- RPM packaging (`packaging/rpm/mlvpn.spec`) targeting current Fedora
  and RHEL/Rocky/Alma 9+, alongside the existing `.deb`. Creates the
  `mlvpn` user/group and `/etc/mlvpn` via `%pre`/`%post` scriptlets,
  mirroring `debian/mlvpn.postinst` -- except it does not remove the
  user/group on uninstall, per Fedora packaging convention (the Debian
  package's `postrm` does, on explicit `purge`). CI now builds both
  package formats across amd64/arm64 (`.github/workflows/release.yml`,
  the RPM legs built inside `fedora:latest`/`rockylinux:9` containers on
  the same native arm64 runners used for the `.deb`) and publishes all
  of them to one GitHub Release. Replaces `release-deb.yml`.
- `docs/` -- full documentation, split out of the README (installation,
  getting started, firewall, monitoring, troubleshooting, development/
  releases) so the README can stay a short overview with links. See
  `docs/README.md` for the index.
- `docs/platforms/opnsense-pfsense.md`: a scoping/TODO document for a
  future FreeBSD-based port to OPNsense and pfSense CE (current stable
  series as of writing: OPNsense 26.1/FreeBSD 14.x, pfSense CE 2.8.1/
  FreeBSD 14.x). Gap analysis only -- no code changed. Identifies that
  `tun-rs` (already a dependency) claims FreeBSD support so TUN
  creation is likely fine as-is, but `SO_BINDTODEVICE`-based interface
  binding (`link.rs`) and Linux-capability clearing (`privilege.rs`'s
  use of the `caps` crate) have no FreeBSD equivalent and need real
  redesign, not just a recompile; `mlvpnd firewall-setup` is Linux-only
  by design and out of scope for either platform (both are pf-based,
  configured through their own GUI/plugin frameworks).

### Changed

- **License changed from MIT to AGPL-3.0-only.** Deliberately pinned to
  that exact version, not "or any later version" -- see
  `CONTRIBUTING.md`'s "Licensing" section for why, and `LICENSE` for
  the full text. The `v0.1.1` tag was re-cut after this change, and any
  release/artifacts previously published under the old tag while it
  was still MIT-licensed were deleted rather than left alongside the
  relicensed build.
- Crate restructured into a library (`src/lib.rs`) plus two binaries
  (`mlvpnd`, `mlvpn-tui`) so both can share the control-socket JSON
  schema (`ipc.rs`) without duplicating type definitions.
- `tunnel.rs`'s single per-link actor task split into two independent
  tasks, `link_receiver` and `link_prober`: under sustained receive
  load, a `select!` between "receive" and "probe timer" branches could
  starve the timer branch, silently disabling latency probing on the
  busiest (most important) links. Splitting them removes that failure
  mode entirely rather than just making it rare.
- `config.rs` now warns (to stderr, before logging initializes) when
  `tunnel.mtu` plus protocol overhead is likely to exceed a typical
  1500-byte physical link MTU, since that leads to a hard-to-diagnose
  IP-fragmentation/firewall-drop failure mode.

### Security

Found and fixed during a multi-pass review (including an independent
review pass) specifically looking for remotely-triggerable flaws:

- **(High) Unauthenticated remote DoS via a single forged handshake
  reply.** The client's handshake-response handler used `?` on a Noise
  decrypt/authentication call instead of the retry-and-continue pattern
  used everywhere else in that loop, and didn't check the reply's source
  address. Any UDP packet reaching the client's socket with a
  `HandshakeResp`-tagged header and any payload (no key material needed
  -- it only has to fail Noise authentication, which garbage always does)
  crashed the whole daemon process instead of being rejected and retried.
  Fixed: malformed/forged replies are now logged and retried exactly like
  a timeout, and the reply's source address must match the configured
  peer before it's processed at all.
- **(High) Replay window updated before authentication succeeded.**
  `Session::decrypt` marked a sequence number as "seen" as a side effect
  of checking it, before the AEAD tag was verified. Since frame headers
  (including the sequence number) are plaintext, an attacker with no key
  material could pre-burn sequence numbers in the replay window with
  garbage packets, causing the legitimate peer's later, genuinely
  authenticated packets at those sequence numbers to be misclassified as
  replays and dropped. Fixed by splitting `ReplayWindow` into a
  non-mutating `check()` and a `commit()` that's only called after AEAD
  authentication actually succeeds (the same check/commit split
  WireGuard's replay protection uses); added regression tests.
- **(Low) Fail-open peer-identity pin check.** Both the client and server
  only rejected a peer when `remote_static()` returned a key that
  *mismatched* the pinned `peer_public_key`; a `None` (not expected in
  practice for a completed Noise_IK handshake, but not previously
  guarded against either) would have silently skipped the pin check
  instead of rejecting. Now fails closed in both cases.
- **(Low) Control-socket permission race.** `mlvpnd`'s monitoring Unix
  socket was `bind()`-ed and only made mode 0600 afterward, leaving a
  brief window where it existed at whatever the ambient umask allowed.
  Now created with a temporarily tightened process umask so it's 0600
  from the instant it exists, with the explicit `chmod` kept as defense
  in depth.
- **(Low) Unauthenticated pre-session handshake flood.** A remote sender
  with no key material could force repeated elliptic-curve operations by
  flooding the server with garbage tagged as `HandshakeInit` before the
  legitimate session is established. Cannot forge a session (the pin
  check above still applies), but could burn CPU. Added a global
  (not per-source-IP, since UDP source addresses are trivially spoofable)
  rate limit on how many handshake attempts get processed per second.
- **(Low, defensive)** Replaced `partial_cmp(..).unwrap()` in the SWRR
  scheduler's comparisons with `total_cmp`, so link selection can never
  panic even in a hypothetical future where a score computation produces
  NaN -- current score inputs are already clamped away from that, but a
  scheduling hot path should be panic-free by construction.

### Fixed

- `systemd/mlvpn.service`'s `ExecStart` pointed at `/usr/local/bin/mlvpnd`
  while the Debian package installs to `/usr/bin/mlvpnd` -- a packaged
  install's service would have failed to start. Both now agree on
  `/usr/bin`. Added `RuntimeDirectory=mlvpn` so the control socket has a
  writable, correctly-owned directory available under
  `ProtectSystem=strict` without a broader filesystem exception.
- A redundant double lock/encrypt of the session in the `Probe` reply
  path in `handle_incoming`, collapsed into one critical section.
- `debian/compat` conflicted with `debian/control`'s
  `debhelper-compat (= 13)` Build-Depends -- debhelper refuses to build
  at all when the compat level is declared both ways, regardless of
  whether the values agree (`dh: error: debhelper compat level
  specified both in debian/compat and via build-dependency on
  debhelper-compat`). Removed `debian/compat`; the Build-Depends entry
  is the only source of truth now.
- README's Quick Start ran `mlvpnd genkey --out /etc/mlvpn/private.key`
  before `/etc/mlvpn` existed and without `sudo`, so it would fail on a
  clean host; and it never created the `mlvpn` system user/group that
  `privilege::drop_privileges()` requires, so a from-source install
  following those steps literally would get through all privileged
  setup and then exit with `privilege drop failed: user 'mlvpn' does
  not exist`. Rewrote the README's setup instructions (found via a
  full walkthrough simulating a real two-node deployment) to fix both
  and cover the `.deb`/systemd path, firewall rules, verification, and
  troubleshooting end to end.

## [0.1.0] - 2026-07-13

Initial implementation and first successful build.

### Added

- Core bonding daemon (`mlvpnd`): binds one UDP socket per configured
  physical interface via `SO_BINDTODEVICE`, and combines their bandwidth
  behind a single Noise-encrypted tunnel rather than merely failing over
  between them (`scheduler.rs`'s smooth weighted round robin spreads
  traffic across every currently-healthy link in proportion to its
  measured score).
- `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake and transport (`snow`
  crate), with WireGuard-style replay protection tolerant of the
  packet reordering multipath introduces.
- Self-measured per-link latency, jitter, loss, and throughput
  (`monitor.rs`), combined into one score used for scheduling; hysteresis
  on Up/Down transitions to avoid flapping a marginal link in and out of
  rotation.
- Zero-downtime failover semantics: the scheduler always attempts
  delivery on the least-bad link rather than refusing to send, so
  traffic resumes the moment any path recovers without operator
  intervention -- true silence only happens if every configured
  interface is actually unreachable.
- Receive-side reordering buffer bounded by a configurable window, so one
  permanently-lost packet can't stall the tunnel.
- Privilege dropping (`privilege.rs`) with two supported postures: start
  as root and drop after binding sockets/opening the TUN device, or never
  be root at all via systemd `AmbientCapabilities`.
- Hardened systemd unit (`systemd/mlvpn.service`) and Debian packaging
  (`debian/`) targeting Debian 13.
- `ARCHITECTURE.md` design document and example client/server configs.

[0.2.0]: https://github.com/4jpps/mlvpn-rs/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/4jpps/mlvpn-rs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/4jpps/mlvpn-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/4jpps/mlvpn-rs/releases/tag/v0.1.0
