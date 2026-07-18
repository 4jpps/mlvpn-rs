# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/) once this
project has a stable public release -- pre-1.0, minor bumps may still
include breaking config/wire changes, called out explicitly below.

For implementation detail beyond what's here, read the code -- most
modules and non-trivial functions have doc comments explaining the
design, and `ARCHITECTURE.md` covers the system as a whole.

## [0.3.5] - 2026-07-17

### Added

- **A link's `remote_addr` now accepts a DNS hostname, not just a
  literal IP** -- e.g. `"bgp.example.com:51000"`, handy when the server
  side doesn't have (or you don't want to hard-code) a fixed IP.
  Resolved once at startup via `tokio::net::lookup_host` (a 10s timeout
  so an unreachable resolver fails fast instead of hanging the daemon
  at boot); not re-resolved while running, so a restart is needed to
  pick up a changed IP, same as editing a literal IP always required.
  A hostname resolving to both an `A` and `AAAA` record (ordinary
  dual-stack DNS) is handled automatically: `local_addr`, if set, picks
  the family; otherwise IPv6 is preferred when both are available.
- **New outbound queue overflow logging**, loosely modeled on the
  original C `MLVPN`'s `freebuffer_t` (a fixed-size packet pool that
  logs and drops rather than growing or blocking once exhausted).
  `tun_reader` and the actual per-link send are now split across a
  bounded channel; if the send side ever falls behind the rate packets
  arrive from the TUN device again (exactly the failure mode the
  Performance fix below addresses, but this catches *any* future
  regression with the same shape), the queue fills, packets are
  dropped rather than silently lost in the kernel's TUN queue, and a
  `WARN`-level `"outbound queue overflowed"` line with a drop count
  logs every couple of seconds until it clears. Silent on a healthy
  tunnel. See `docs/performance-tuning.md` §3b.

### Performance

- **Bonded throughput still plateaued well below what the links could
  do individually, even after 0.3.2's cross-link lock fix.** A real
  two-host test pushing 200 Mbps of small UDP datagrams (~19,000
  packets/sec) through the tunnel found a hard, flat ~65% loss ceiling
  -- steady, non-varying loss at high packet rate, unlike the bursty
  pattern real network congestion produces. Root cause: `tunnel::
  send_scheduled` called `link::snapshot_links` -- a full clone of
  every configured link, including every `LinkConfig` `String` field
  -- on **every single outgoing packet**, just so `Scheduler::select`
  could pick one link and discard the rest of the clones. At high
  packet rates the heap allocation and per-link lock/clone overhead of
  doing that every packet outpaced how fast packets arrived from the
  TUN device, silently overflowing the kernel's TUN queue before
  `mlvpnd` ever read the dropped packets -- invisible from inside the
  process, the same way 0.3.1's socket-buffer overflow was. `Scheduler::
  select` now works off a new `Copy`-only `link::LinkScore` snapshot
  (no heap data at all) and returns just the winning link's index, so
  only that one link is ever locked-and-cloned for its remote
  address/socket handle -- not every candidate, on every packet,
  regardless of which one wins. See `docs/performance-tuning.md` §3b.

## [0.3.4] - 2026-07-17

### Fixed

- **The 0.3.3 restart-on-upgrade fix always lost the race against
  debhelper's own generated postinst code.** It checked whether
  `mlvpnd` was active and restarted it *before* `#DEBHELPER#`, but
  debhelper's compat-10+ default (`--restart-after-upgrade`, with
  `debian/rules`'s `--no-start` only suppressing the "start" half of
  that pair) unconditionally stops the service *after* that, on every
  upgrade -- so 0.3.3's restart always got immediately undone, leaving
  `mlvpnd` stopped after every `.deb` upgrade exactly as before that
  fix shipped. Found on a real two-host upgrade immediately after
  0.3.3. Fixed by recording whether the service was active before
  anything in the postinst (debhelper's generated code included) can
  touch it, and restarting -- last, after `#DEBHELPER#` -- based on
  that recorded state instead. Debian packaging only; the `.rpm` was
  never affected (`%systemd_postun_with_restart` already handled this
  correctly), version bumped only to keep both packages on the same
  release number.

## [0.3.3] - 2026-07-17

### Fixed

- **Restarting either side of a tunnel used to silently stop the
  *other* side too**, requiring a manual restart there -- the exact
  "I have to start it every time" complaint that led to 0.3.2's
  restart-on-upgrade packaging fix (below) in the first place, except
  this cascade meant that very fix made the *other* end stop more
  often, not less. Root cause: a peer-initiated `Disconnect` makes
  `mlvpnd` exit cleanly (code 0) by design (see `tunnel.rs`'s
  `ShutdownReason::PeerInitiated`), and the shipped systemd unit only
  restarted on a *nonzero* exit (`Restart=on-failure`) -- so the moment
  one side restarted for any reason (a routine package upgrade, a
  manual `systemctl restart`), it sent the other side a graceful
  Disconnect, and that side's `mlvpnd` exited and simply stayed down.
  `systemd/mlvpn.service` now uses `Restart=always` instead, so any
  exit -- this one included -- gets the daemon back up within
  `RestartSec=2`; an explicit `systemctl stop` is unaffected, since
  systemd never overrides a deliberate stop regardless of `Restart=`.
- **`mlvpn-tui` failed to auto-detect the control socket with
  `multiple control sockets found` once `[command] enabled = true`**
  was set. Its auto-detection matched any file under `/run/mlvpn`
  ending in `.sock`, which also matched `<tunnel>.command.sock` -- a
  completely different, write-capable protocol for `mlvpnd set-link`
  (see `control.rs::serve_commands`), not the streaming snapshot
  `mlvpn-tui` actually reads. Now explicitly excludes `*.command.sock`.

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

[0.3.5]: https://github.com/4jpps/mlvpn-rs/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/4jpps/mlvpn-rs/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/4jpps/mlvpn-rs/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/4jpps/mlvpn-rs/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/4jpps/mlvpn-rs/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/4jpps/mlvpn-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/4jpps/mlvpn-rs/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/4jpps/mlvpn-rs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/4jpps/mlvpn-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/4jpps/mlvpn-rs/releases/tag/v0.1.0
