# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/) once this
project has a stable public release -- pre-1.0, minor bumps may still
include breaking config/wire changes, called out explicitly below.

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

### Changed

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

[0.1.1]: https://github.com/4jpps/mlvpn-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/4jpps/mlvpn-rs/releases/tag/v0.1.0
