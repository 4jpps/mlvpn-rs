# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/) once this
project has a stable public release -- pre-1.0, minor bumps may still
include breaking config/wire changes, called out explicitly below.

For implementation detail beyond what's here, read the code -- most
modules and non-trivial functions have doc comments explaining the
design, and `ARCHITECTURE.md` covers the system as a whole.

## [0.3.2] - 2026-07-17

### Added

- **`mlvpn-tui`'s header now shows this machine's own hostname**
  alongside the tunnel name and mode, so a snapshot copied out of
  context (a bug report, a chat with someone helping debug a two-host
  tunnel) is unambiguous about which end of the tunnel it came from --
  previously just `tunnel 'name' (client|server)`, which doesn't help
  when, as is typical, both ends share the same tunnel name.

### Performance

- **Bonding two links together could be *slower* than using either one
  alone.** A real two-host deployment (Comcast + a T-Mobile MVNO bonded
  together) measured download throughput at 55-90 Mbps bonded, versus
  143 Mbps on Comcast by itself and 118 Mbps on T-Mobile by itself --
  isolating each link (`mlvpnd set-link <link> disable`) made the
  tunnel faster, not slower, which should never happen. Root cause: all
  of a tunnel's links shared one single `Arc<AsyncMutex<Vec<Link>>>` --
  a single lock covering every link's metadata (stats, state, learned
  remote address) at once -- so each link's `link_receiver` task had to
  serialize against every *other* link's task on every single packet's
  metadata update, even though the two links touch completely disjoint
  data. Replaced with `Arc<Vec<AsyncMutex<Link>>>`: each link now has
  its own independent lock, so locking one link's metadata never blocks
  another's. See `docs/performance-tuning.md` and `tunnel.rs`'s module
  doc comment for the full write-up.

### Fixed

- **`systemd/mlvpn.service`'s `PrivateDevices=no` had a trailing inline
  comment on the same line**, which systemd's unit-file parser doesn't
  support -- it was logging `Invalid argument` at load time (non-fatal
  only because `no` is also this directive's own default). Moved the
  comment to its own line above.
- **The `mlvpn` system user's primary group could end up as `nogroup`
  instead of `mlvpn`** on an existing install: both the `.deb` postinst
  and the `.rpm` `%pre` scriptlet only ever created the user once, on
  first install, and never revisited its group on a later upgrade even
  if it had somehow ended up wrong (an account from a version predating
  either of these scripts, or created by hand). Both now also run
  `usermod -g mlvpn mlvpn` unconditionally on every install/upgrade,
  harmless if it's already correct. Run `sudo usermod -g mlvpn mlvpn`
  by hand in the meantime on an already-affected host; see
  [Troubleshooting](docs/troubleshooting.md).
- **The `.deb` package left the old `mlvpnd` binary running in memory
  after an upgrade** instead of restarting it, unlike the `.rpm`
  package (which already did this via `%systemd_postun_with_restart`).
  `debian/rules` intentionally builds with `dh_installsystemd
  --no-enable --no-start` so a *fresh* install doesn't try to start
  `mlvpnd` before `/etc/mlvpn/mlvpn.toml` even exists, but that flag
  also suppresses the usual restart-on-upgrade behavior as a side
  effect. `debian/mlvpn.postinst` now explicitly restarts the service
  after an upgrade if (and only if) it was already running, leaving a
  fresh install or a deliberately-stopped service alone.

## [0.3.1] - 2026-07-16

### Performance

- **Link sockets now request an 8 MiB kernel receive/send buffer**
  (`link::raise_socket_buffers`), using `SO_RCVBUFFORCE`/
  `SO_SNDBUFFORCE` to bypass the `net.core.rmem_max`/`wmem_max` sysctl
  ceiling when the process still holds `CAP_NET_ADMIN` (always true at
  initial startup), falling back to a plain, ceiling-respecting request
  otherwise. The stock Linux default (~208KB) silently drops incoming
  packets -- indistinguishable from ordinary network loss -- the moment
  a link's bandwidth-delay product exceeds it, which is an easy trap
  for any link above a few hundred Mbps. See the new
  [Performance tuning](docs/performance-tuning.md) doc for how to
  confirm this was the bottleneck and raise the sysctl ceiling if the
  forced request still didn't get everything it asked for.

### Fixed

- **The initial handshake no longer crashes the daemon if the peer is
  unreachable at startup.** `mlvpnd` (client mode) used to exit the
  whole process if every configured link's handshake attempt timed out
  -- fine under a one-off manual run, but under `systemd`'s default
  `Restart=on-failure` a peer that stayed unreachable for a few minutes
  (both ends power-cycling together, one side still waiting on DHCP, a
  route not yet converged) could burn through enough restarts to trip
  `StartLimitBurst`/`StartLimitIntervalSec` and leave the unit
  permanently in `failed` state -- silently down until someone happened
  to check and run `systemctl reset-failed`. Found via exactly that
  scenario on a real two-host deployment. Neither WireGuard nor the
  original C `MLVPN` this project replaces ever exit on a failed
  handshake; `mlvpnd` now matches that, logging a warning and retrying
  with exponential backoff (same schedule as link-socket reconnection,
  capped at 30s) in the background indefinitely instead of returning an
  error out of `tunnel::run`.
- **A stale handshake reply could permanently starve every future retry
  once the initial handshake started retrying indefinitely (the fix
  directly above).** `race_handshake_reply` only checked a reply's
  source address and packet type, not which attempt it actually
  belonged to. Once a reply arrived late enough to miss its own
  attempt's timeout, the peer had already committed that session and
  would keep responding to related traffic; every later attempt's own
  `HandshakeInit` then got legitimately treated as a new rekey by the
  peer, each producing its own reply -- and without a session-id check,
  a stale one of those could win a later attempt's race, consuming that
  attempt's one chance at the genuine reply. Before this release, 10
  failed attempts just ended the process, never enough rounds for this
  to compound; retrying indefinitely let stale replies pile up across
  rounds with nothing ever clearing them, so once one late reply
  happened the client could never recover on its own. Caught
  immediately by re-running this project's own integration tests after
  the fix directly above. `race_handshake_reply` now also requires a
  reply's session id to match the current attempt's, the same guarantee
  the mid-session (rekey) path already had.

## [0.3.0] - 2026-07-14

### Added

- **Self-healing link reconnection.** A link whose interface is fully
  removed and recreated (e.g. a USB LTE modem replugged) now gets its
  socket automatically rebound instead of staying dead until the daemon
  restarts.
- **Handshake racing across every configured link.** The client now
  tries the initial handshake on all configured links at once instead
  of only the first one, so a single down link at startup no longer
  blocks the tunnel from coming up.
- **Rekeying and session migration.** Sessions are now periodically
  rekeyed (`crypto.rekey_interval_secs`, default 120s) with a brief
  overlap window so in-flight packets aren't dropped during the swap.
- **Graceful shutdown.** `mlvpnd` now handles SIGINT/SIGTERM (`systemctl
  stop` sends SIGTERM, which wasn't previously handled at all) by
  notifying its peer and exiting cleanly, instead of just disappearing
  and leaving the peer to notice via probe timeouts.
- **Per-link bandwidth cap enforcement and redundancy mode.**
  `bandwidth_cap_mbps` is now an actual enforced ceiling (the scheduler
  stops sending more to a link once it's hit that rate, picking another
  link instead) rather than just biasing its score. New opt-in
  `scheduler.redundant_mode` sends every packet on every currently-up
  link at once instead of picking one, trading bandwidth for
  reliability -- meant for small, latency-critical tunnels, not
  general-purpose bonded ones.
- **Runtime link control.** A new, separate command socket
  (`[command] enabled`, off by default) lets `mlvpnd set-link <link>
  <enable|disable>` pin a link out of scheduling without editing the
  config and restarting -- the link's real quality stats keep updating
  the whole time, so monitoring stays accurate even while it's pinned
  off. The existing monitoring socket is untouched and stays read-only.
- **IPv6 on the bonded links themselves.** Each `[[links]]` entry is
  now independently IPv4 or IPv6 (inferred from `remote_addr`/
  `local_addr`, no new config field needed), so a tunnel can mix both
  address families across its links -- e.g. a fiber link over IPv4 and
  an LTE link that only has an IPv6 address. Existing IPv4-only configs
  are unaffected. Distinct from the IPv6 TUN interface support shipped
  in v0.2.0 (`tunnel.address6`), which is about the tunnel's own
  address, not the transport between the two `mlvpnd` instances.
- **Reorder window auto-tuning (opt-in).** New
  `scheduler.auto_tune_reorder_window` (off by default) periodically
  re-tunes `reorder_window_ms` itself from the live RTT spread across
  bonded links, instead of leaving it fixed at whatever was configured
  for the tunnel's whole life -- useful when bonding links with very
  different latency characteristics (e.g. fiber plus a satellite or
  high-latency cellular link).
- **Probe interval auto-tuning (opt-in).** New
  `scheduler.auto_tune_probe_interval` (off by default) lets a link's
  probe interval back off above its configured floor after a long
  clean streak (less overhead on a link that's been stable), snapping
  straight back to the floor the instant there's any miss at all.
- **EWMA alpha auto-tuning (opt-in).** New `scheduler.auto_tune_ewma_alpha`
  (off by default) lets a link's latency/jitter/loss/throughput
  smoothing factor move within a configured range: any miss jumps it to
  the fastest-reacting end immediately, a long clean streak gradually
  smooths it toward the slowest/steadiest end instead.
- **Active bandwidth probing (opt-in).** New
  `scheduler.active_bandwidth_probing` (off by default) periodically
  sends a short, rate-limited burst of MTU-sized dummy packets on each
  link purely to measure its achieved throughput, instead of only ever
  inferring bandwidth from bytes that happen to already be flowing --
  so `monitor::score()` can judge an under-used link on its true
  capacity rather than looking artificially slow. Injects real (small,
  infrequent -- interval floor of 30s) extra traffic onto the wire, so
  this is opt-in for a stronger reason than the other auto-tuning knobs
  above: leave it off on a metered or bandwidth-constrained link.

### Fixed

- **A late handshake reply could poison every remaining retry.** The
  initial handshake's retry loop reused one fixed session id across
  all 10 attempts. A reply that arrived just late enough to miss one
  attempt's timeout, but still in time for a later attempt's window,
  got read against that later attempt's (non-matching) Noise ephemeral
  and always failed to decrypt -- and the existing stale-duplicate
  protection would then refuse to let the server process any further
  attempt carrying that same session id, so every remaining retry was
  doomed once that one timing race happened, even though the peer had
  a valid, waiting session the whole time. Each initial-handshake
  attempt now generates its own fresh session id; rekey attempts are
  unaffected (they still keep one fixed per call, as their own
  reply-routing design requires). Caught by re-running this project's
  own integration tests, not by inspection.
- **Log output no longer carries embedded ANSI color escape codes.**
  `tracing_subscriber`'s color coding defaulted to on unconditionally
  (it doesn't auto-detect a non-terminal destination), so every log
  line carried invisible color escape sequences even when going to
  journald or a log file rather than an interactive terminal -- a real
  terminal renders them away, so this went unnoticed until something
  read the raw bytes.

### Testing

- New integration test harness (`tests/veth_*.rs`) spins up two real
  `mlvpnd` processes in Linux network namespaces connected by veth
  pairs, covering handshake racing, link failover, rekeying, graceful
  shutdown, redundancy mode, runtime link control, reorder-window
  auto-tuning (using real injected network latency), probe-interval
  auto-tuning, EWMA-alpha auto-tuning, active-bandwidth-probing (using
  real `tc tbf` rate shaping), and a mixed IPv4/IPv6 bonded link set,
  end-to-end. Needs root; see `docs/development.md`.
- **Full test suite verified passing.** `scripts/full-check.sh`
  (build, `cargo test` unit tests, `clippy -D warnings`, `cargo fmt
  --check`, and every `tests/veth_*.rs` integration scenario listed
  above, run as root) was run clean end-to-end before this release,
  including after the two fixes in the section above -- not just
  checked in isolation.

## [0.2.0] - 2026-07-13

### Added

- **IPv6 dual-stack support** on the TUN interface (`tunnel.address6`).
- **Adaptive tunnel MTU**: each link's real physical MTU is detected at
  startup and the configured MTU is auto-clamped down if needed.
- **TCP MSS clamping** (on by default), avoiding the "PMTUD black hole"
  stall some networks cause for TCP connections passing through the
  tunnel.
- `ARCHITECTURE.md` now credits and documents the design differences
  from [MLVPN](https://github.com/zehome/MLVPN), the C project this is
  a from-scratch Rust rewrite of.

## [0.1.2] - 2026-07-13

### Security

- Bumped `ratatui` to 0.30 to pick up a fixed `lru` dependency
  (RUSTSEC advisory, reachable only via `mlvpn-tui`). Full dependency
  audit against the RustSec database found nothing else needing a pin.

### Changed

- Minimum supported Rust version raised to 1.86.

### Fixed

- RPM release build failures on the RHEL-family CI leg.

## [0.1.1] - 2026-07-13

### Added

- `mlvpn-tui`: a terminal monitoring view for bonded links.
- `mlvpnd` control socket: a local Unix socket streaming live
  link/traffic stats as JSON.
- `mlvpnd firewall-setup`: detects the active firewall backend
  (`firewalld`/`ufw`/`nftables`/`iptables`) and opens the configured
  link ports.
- RPM packaging alongside the existing `.deb`, both built for
  amd64/arm64 in CI.
- `docs/` split out of the README into a full documentation set.
- GitHub Actions CI and a release workflow publishing packages on
  version tags.

### Changed

- **License changed from MIT to AGPL-3.0-only.**
- Crate restructured into a shared library plus two binaries
  (`mlvpnd`, `mlvpn-tui`).

### Security

Found and fixed during a security review pass:

- **(High)** A forged handshake reply could crash the client daemon
  (unauthenticated remote DoS).
- **(High)** The replay window could be pre-burned by unauthenticated
  garbage packets, causing legitimate traffic to be misclassified as
  replayed and dropped.
- **(Low)** Peer-identity pin check failed open on an unexpected case
  instead of rejecting.
- **(Low)** Brief window where the control socket existed with
  looser-than-intended permissions.
- **(Low)** No rate limit on pre-session handshake attempts, allowing a
  CPU-exhaustion flood.

### Fixed

- systemd service file pointed at the wrong binary path for a packaged
  install.
- Debian packaging build failure (conflicting `debhelper-compat`
  declarations).
- README Quick Start didn't actually work on a clean host (missing
  setup steps); rewritten and verified end to end.

## [0.1.0] - 2026-07-13

Initial implementation and first successful build.

### Added

- Core bonding daemon (`mlvpnd`): binds one UDP socket per configured
  physical interface and combines their bandwidth behind a single
  encrypted tunnel, rather than merely failing over between them.
- `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake and transport, with
  replay protection tolerant of multipath reordering.
- Per-link latency/jitter/loss/throughput monitoring feeding a scored
  scheduler, with hysteresis to avoid flapping a marginal link.
- Zero-downtime failover: traffic keeps flowing on the best remaining
  link, with no operator intervention needed.
- Privilege dropping, a hardened systemd unit, and Debian packaging.
- `ARCHITECTURE.md` design document and example configs.

[0.3.2]: https://github.com/4jpps/mlvpn-rs/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/4jpps/mlvpn-rs/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/4jpps/mlvpn-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/4jpps/mlvpn-rs/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/4jpps/mlvpn-rs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/4jpps/mlvpn-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/4jpps/mlvpn-rs/releases/tag/v0.1.0
