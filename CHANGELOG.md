# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/) once this
project has a stable public release -- pre-1.0, minor bumps may still
include breaking config/wire changes, called out explicitly below.

For implementation detail beyond what's here, read the code -- most
modules and non-trivial functions have doc comments explaining the
design, and `ARCHITECTURE.md` covers the system as a whole.

## [Unreleased]

### Added

- **Per-link bounded TX workers (failure isolation).** Previously a single `outbound_sender` task did every link's `send_to` inline, so one blocked socket (a WAN path that stops draining while its send buffer is full) froze transmission on every link until it cleared. `outbound_sender` now only picks a link and `try_send`s onto that link's own 128-slot queue (`TxDispatcher`); a `link_tx_worker` per link encrypts and sends, batching up to 32 frames per wakeup. A full queue is counted (`tx_queue_full`), applies a 200 ms scheduler penalty to that link (`Scheduler::note_queue_full`), and spills the packet to the usable link with the most free slots; under `primary_link_mode`/`follow_peer_primary` there is no spill and the packet is dropped and counted in `outbound_dropped_total`, so traffic never leaks onto a backup. A worker send failure (or a link with no remote yet) reroutes the packet once to another link. `redundant_mode` enqueues a clone on every Up link's queue (no spill), replacing the old inline `send_redundant`. Limitation: with FEC enabled (and not `redundant_mode`) the legacy inline `send_scheduled` path is kept, since FEC grouping needs to know a frame actually went out; this moves with the planned FEC/reorder pipeline rework.
- **Per-link TX counters** `tx_queue_full_total`, `tx_send_failed_total`, `tx_rerouted_total` in the control-socket snapshot, `diag-dump` per-link totals, and `mlvpn-tui` (shown only when nonzero).
- **Congestion-aware scheduling (no wire or config change).** Each link's TX worker now records how long its oldest queued job waited (queue delay), how long each `send_to` took, its queue depth and the time since it last made progress. A new 100 ms `congestion_loop` (atomics only, no link locking) turns those samples, plus `queue_full` and `send_failed` deltas, into a per-link congestion factor in [0.1, 1.0] that scales that link's SWRR weight (`effective_weight = base_weight x factor`): under 1 ms of queue delay keeps full weight, 5 ms -> 0.8, 20 ms -> 0.3, 60 ms or more -> 0.1. A worker blocked inside `send_to` produces no new samples, so the time since its last progress is used as the delay while its queue is non-empty. The factor drops immediately, holds for 1 s, then recovers at 0.15/s so a flapping link does not oscillate. A congested link keeps a trickle of traffic (never below 10%), and primary-link selection ignores the factor.
- **Queue-delay and send-failure telemetry.** The control-socket snapshot, `mlvpn-tui` and `diag-dump` now report per link `tx_queue_depth`, `tx_queue_delay_us`, `tx_queue_delay_max_us`, `tx_send_wait_us`, `congestion_factor` and a `degraded` flag (an overlay on an `Up` link whose factor is below 0.7, deliberately not a new `LinkState`, so the wire encoding and `StatsPayload` are unchanged). `mlvpn-tui` shows a "DEGRADED: queue X ms, share xY" line. New snapshot fields are `serde(default)`, so older clients and snapshots still parse.

### Fixed

- **Dual-stack address-family race restored.** A client link whose `remote_addr` hostname resolves to both an A and an AAAA record could stay stuck on an unreachable address family. The race that settles this was lost in 0.7.0, when the tunnel-wide handshake it hung off was removed: `Link::alternate` was still populated by `pick_remote_addr`, but nothing ever resolved it. `Link::resolve_alternate` (called once per link, concurrently, from `tunnel::run` before any per-link task spawns, with a 10 s deadline) now sends a real WireGuard handshake initiation to both candidates, retransmitting via `wg.tick()` every 500 ms, and commits whichever family answers first. If neither answers in time the primary is kept and normal retry continues. Known limitation: a peer that is down at startup can leave the link on the wrong-family primary until restart. Caught by `veth_dualstack_link`, which had been failing since 0.7.0.

### Tests

- New `veth_tx_isolation` (two tests): stalls one link with a deep `tbf` qdisc (a real blocked `send_to`; `netem delay` does not apply backpressure to the sending socket) while a paced UDP stream runs. Asserts the other link never stops transmitting, the stalled link's own `tx_bytes` freezes, and the link recovers to `up` and carries traffic again. The `redundant_mode` variant, where the scheduler cannot route around the stalled link, also asserts the stalled link's queue-full counter rises; it fails on the previous release with a 4.5 s multi-link transmit gap and passes now.
- Unit tests for the receive pipeline (`rx_pipeline_tests`, against a channel sink, since a unit test cannot open a TUN device): four concurrent senders deliver every frame exactly once with nothing lost or duplicated; a frame behind the watermark is released by the periodic flush with no further traffic; a FEC-recovered frame is not delivered again when its real copy arrives later; a full channel drops and counts instead of blocking.
- Brought six `#[ignore]` veth integration tests back in line with 0.7.x behaviour: `veth_mtu_monitor` (MTU bounds now account for the 112-byte outer overhead), `veth_tunnel_selftest` (explicit `--protocol udp`), `veth_wireguard_style_immediate_delivery` (no tunnel-wide rekey exists any more; now checks the follow-peer-primary client settling into bypass mode), `veth_wireguard_transport` (per-link key files), `veth_primary_mtu` (server uses `follow_peer_primary` alone since it is mutually exclusive with `primary_link_mode`, and netem on the second link makes the primary deterministic), and `veth_diag_dump`'s auto-submit test (the mock intake server is now reachable from the client netns over a dedicated host veth instead of the host's own loopback).
- New `congestion` unit tests (delay-to-target curve, immediate drop, hold-down, gradual recovery, `queue_full`/`send_failed` caps, stall estimate) and `scheduler` tests (a congested link loses share but keeps a trickle, the factor survives a `refresh` rebuild, a send-failure penalty lapses and never shortens an existing one), plus a `try_enqueue` depth-accounting test in `tunnel.rs`.
- New `veth_congestion`: squeezes one of two bonded links behind a 1 Mbit/s deep `tbf` under ~48 Mbps of UDP and checks the healthy link carries the clear majority, the new telemetry stays within bounds, and the link rejoins and carries traffic again once the squeeze is removed. In that topology the existing RTT/loss weighting and Down detection shed the link before its socket ever blocks, so the factor itself only dips slightly there; its response to a backed-up worker is covered by the unit tests.

### Changed

- **Per-packet hot-path allocation cleanup (no wire or config change).** Receive previously allocated and zero-filled a fresh ~64 KB scratch buffer for every datagram (`wg_recv`), plus a second buffer inside `WgTunnel::decapsulate`, plus an extra `plaintext.to_vec()` in `handle_incoming`; transmit built a frame `Vec`, a fake-IPv4-wrapped copy, and an encryption buffer per packet. Now `link_receiver` owns one reusable receive buffer and one frame buffer (`Link::wg_recv_into` / `WgTunnel::decapsulate_into`), `WgTunnel` keeps reusable wrap/encrypt/decrypt scratch buffers behind its existing lock, and transmit encapsulates a header + payload pair directly (`encapsulate_parts`, `Header::to_bytes`) without building an intermediate frame. `benches/wg_path.rs` (`cargo bench --bench wg_path`) measures it with a counting allocator: receive goes from ~131 KB and 4 allocations per packet to 0 (about 10x faster for small packets, 6.0 us -> 0.6 us at 100 B), transmit from 5 allocations to 2.
- **Settled-single-link ("bypass") mode no longer takes the reorder-buffer lock per packet.** The reorder buffer's high watermark is now an atomic, so delivering a frame in bypass mode just advances it lock-free. (Superseded in the same release by the single-owner receive pipeline below, which removes the lock entirely.)
- **Single-owner receive pipeline: no async mutex on the reorder or FEC hot path.** Every link's `link_receiver` used to take an `AsyncMutex` on the shared `SharedReorder` (and, with FEC enabled, on the shared `FecRecoveryBuffer`) for every received Data frame, so receivers on different links serialised on each other and a slow TUN write held the lock for everyone. Now `link_receiver` only decrypts, records link stats, and hands the frame to one `rx_pipeline` task over a bounded channel (1024 events, `RxEvent::{Data, Parity, SetReorderWindow}`). That task exclusively owns the `ReorderBuffer` and `FecRecoveryBuffer` (plain `&mut`, no locks), is the only writer of received packets to the TUN device, and absorbs the periodic work of the former `reorder_flush` (10 ms) and `fec_expiry_loop` (250 ms, only when FEC is enabled) tasks, which no longer exist. `reorder_tuning_loop` sends window changes to the pipeline as an `RxEvent` rather than locking the buffer. Sequence/reorder semantics are unchanged: the same high-watermark rules, the same settled-primary bypass (re-read per packet), and the same FEC duplicate guard apply, now in one place, so a recovered frame can no longer race a real frame from another link. If the TUN write side falls behind and the channel fills, frames are dropped at the hand-off (counted, and reported as a rate-limited warning every 2 s) instead of blocking the link's task, which keeps probes and stats flowing on that link; this is the same outcome the kernel socket buffer would have produced. On the same veth benchmark against the previous build (4 alternating runs each) throughput is about 366 Mbps upload and 363 Mbps download vs about 354 and 349, with retransmits unchanged (about 73 vs 76), so the extra channel hop and per-packet copy cost nothing measurable.

Measured on a veth pair with no netem (`veth_tcp_selftest`, 4 alternating runs per build): tunnel TCP throughput ~220 -> ~325 Mbps upload and ~257 -> ~337 Mbps download, with far fewer TCP retransmits.
- **Send failures now briefly penalize the failing link in the scheduler.** A failed `send_to` (either failure path in the TX worker) adds a 500 ms scheduling penalty on top of the existing reroute, which never shortens a penalty already in force.

Measured on the same veth pair (`veth_tcp_selftest`, 4 alternating runs per build, Phase 3 vs Phase 4): ~364 -> ~364 Mbps upload and ~369 -> ~365 Mbps download, i.e. no throughput cost from the extra per-batch timestamping and the 100 ms congestion loop.


## [0.7.5] - 2026-09-24

### Fixed

- **Automatic diagnostic reports to software-support have been silently failing since this feature existed.** `diagnostics::build_report_body` serialized an absent message (`control.rs`'s loss-threshold watcher always passes `None` for the automatic path) as JSON `null` -- but software-support's `SubmitReport.message` is a required `String`, not `Option<String>`, so axum's `Json` extractor rejected the whole request with `422 Unprocessable Entity` before the handler ever ran. Confirmed against the real live service both ways: an empty-string message gets a real `201` + ticket id, a `null` message gets the exact `"invalid type: null, expected a string"` error seen in production logs. omnibridge's own client (the only other real consumer of this shared endpoint) never hit this, because its equivalent field has always been a plain `String`. Fixed by sending an empty string instead of `null` for an absent message, matching the real contract. New test submits through the real `reqwest` JSON path (not just checking the in-process `serde_json::Value`) and asserts the literal wire bytes never contain `"message":null` -- the previous test suite's mock server ignored the request body entirely, which is exactly why this shipped unnoticed.

## [0.7.4] - 2026-09-22

### Changed

- Full dependency update pass (including RUSTSEC-2026-0285, a rustls TLS 1.3 handshake-validation issue) found via a project-wide `cargo-audit` sweep. No source changes.

## [0.7.3] - 2026-09-15

### Added

- **New diagnostic counter: `wg_substituted_total`, per link and daemon-wide.** Direct inspection of `boringtun-0.7.1`'s own source (`Tunn::encapsulate`, `src/noise/mod.rs`) found a real, previously invisible loss path: when a link has no current valid WireGuard session at the moment `encapsulate` is called, boringtun queues the real plaintext *internally* and writes a handshake-initiation datagram to the network *instead* -- but both outcomes return the identical `TunnResult::WriteToNetwork`, so `wg_send`'s caller sees an ordinary successful send either way, and `LinkStats::record_tx` increments as if the frame was actually delivered even when it wasn't. `WgTunnel::encapsulate` (`src/wireguard.rs`) now checks the outgoing datagram's own WireGuard message-type field (a little-endian u32 at offset 0; 4 = data, anything else = a substituted control packet) and counts every substitution. Surfaced per link via `LinkSnapshot::wg_substituted_total` and daemon-wide via `DaemonSnapshot::wg_substituted_total`, shown in `mlvpn-tui` (a red "wg substituted: N" line in the Links tab, and folded into the Outbound Queue panel's "WG rejected/substituted: R / S" line) and in `mlvpnd diag-dump`'s text output. Added directly after `wg_rejected_total` (0.7.2) stayed at zero through two real loss-reproducing load tests on live production hardware, ruling out receive-side rejection and motivating a look at the send side instead.
- **Opt-in single-erasure FEC for real Data traffic** (`scheduler.fec_enabled`, `scheduler.fec_group_size`, default 8). Groups of sequential Data frames get one XOR parity frame (new `PacketType::FecParity`); a group missing exactly one member is reconstructed on receive and delivered transparently, without waiting for TCP's own retransmission. Motivated directly by a real dual-ended packet capture (2026-09-14/15, see `CLAUDE.local.md`) that found ~32% real physical loss on the home-bgp<->cloud-bgp comcast link, in bursty runs of 20+ consecutive packets -- this design deliberately does not attempt to recover bursts that large (that would need a much heavier, higher-overhead Reed-Solomon-style scheme); it targets the isolated single-packet losses that occur alongside the bursts, at a fixed, low (12.5% at the default group size) bandwidth cost. Mutually exclusive with `redundant_mode` (config-load error if both are enabled). New `fec_recovered_total`/`fec_unrecoverable_total` daemon-wide counters, surfaced in `mlvpn-tui`'s Outbound Queue panel and `mlvpnd diag-dump`, give a direct live answer to whether it's actually helping on a real link. Off by default. See `docs/superpowers/specs/2026-09-15-single-erasure-fec-design.md` for the full design, including the explicitly-scoped-out heavier alternative and the planned follow-up (a separate future effort to contribute FEC support upstream to `cloudflare/boringtun`'s long-open issue #68, once this implementation has real production evidence to point to). Enabling FEC also reserves `1 + 10*fec_group_size + 2` bytes (83 at the default group size) out of the tunnel MTU, because a parity frame is necessarily larger than the Data frames it covers -- without that reservation every parity frame protecting real bulk traffic would exceed the path MTU and fragment, and a fragmented parity frame needs *both* fragments to survive, making it strictly less likely to arrive than the data it exists to protect; both peers must therefore enable FEC with the same `fec_group_size` to keep their tunnel MTUs matching. The receiver tracks recently-delivered sequence numbers independently of the (shorter-lived, memory-bounded) plaintexts it retains for reconstruction, so a frame that FEC reconstructs early -- the normal case, since a parity frame gets its own scheduler pick and routinely overtakes a member still in flight on a slower link -- is never delivered a second time when its real copy arrives behind it, and a member whose plaintext has aged out is never mistaken for a lost one and "recovered" into a duplicate. With `fec_enabled = false` (the default) the receive path skips the FEC buffer entirely: no extra lock, allocation, or map insert per packet, and the expiry task is not even spawned.
- **Primary-aware, peer-negotiated tunnel MTU.** `effective_tunnel_mtu` no longer caps the tunnel MTU at the minimum across every *configured* link regardless of which is actually carrying traffic -- under `primary_link_mode`/`follow_peer_primary` it now tracks whichever link is actually primary, so an idle worse-MTU failover link no longer holds back a healthy primary. Peers also negotiate down to the lower of the two sides' own live MTUs (`negotiate_tunnel_mtu`, using the existing `VersionInfoPayload.tunnel_mtu`/`PeerMtu` wire exchange, previously display-only) instead of requiring both sides to be hand-pinned to the same `tunnel.mtu` value, which silently went stale the moment either side's real link capacity changed. A hard floor still guarantees dual-stack tunnels never compute below IPv6's real 1280 MTU minimum. See `docs/superpowers/specs/2026-09-16-primary-aware-peer-mtu-design.md`.
- **`mlvpnd self-test --tunnel` gains a real-TCP mode**: `--protocol tcp|udp` (`tcp` is the new default). The existing raw-UDP mode measured ~150 Mbps on production home-bgp/cloud-bgp while real `iperf3` TCP on the identical path at the identical time measured only ~5-22 Mbps -- both numbers were real, but unpaced UDP doesn't react to this link's well-documented loss/jitter the way real traffic (almost entirely TCP) does, so the UDP figure wasn't representative. The new TCP mode gives a number directly comparable to `iperf3` without needing `iperf3` installed separately; the old UDP mode stays available (now opt-in via `--protocol udp`) since the gap between the two is itself useful loss-impact signal. Verified with a real veth integration test run for real (not just compiled) on the `mlvpn-mtu-test` Proxmox VM (VMID 105). See `docs/superpowers/specs/2026-09-16-tcp-tunnel-self-test-design.md`.
- **`mlvpn-tui`/`mlvpnd self-test` now show the full Beta build identifier (e.g. "0.7.3-beta7"), not just the bare base version.** `mlvpn::version()` appends a `MLVPN_BUILD_SUFFIX` compiled in by CI (`.beta_build_suffix` in `.gitlab-ci.yml`) for a Beta build; a real `vX.Y.Z` Stable release still shows just the bare version. Also makes the peer-version-mismatch check (`mlvpnd self-test`, `mlvpn-tui`'s Session panel) distinguish two different Betas sharing the same base version (beta6 vs. beta7), not just Stable-vs-Beta.

### Fixed

- **`mlvpn-tui`'s Session panel flagged a false "MISMATCH" for any healthy, fully-negotiated tunnel where the peer's link simply supports more headroom than this side's own.** `VersionInfo`'s `tunnel_mtu` field is each side's *raw, pre-negotiation* local capability (deliberately, to avoid the monotonic-ratchet bug `negotiate_tunnel_mtu` fixed) -- `peer_tunnel_mtu > local_tunnel_mtu` is the normal, expected result whenever link characteristics are asymmetric, not an error. Confirmed live on home-bgp/cloud-bgp: both sides had correctly negotiated down to a shared, applied tunnel MTU of 1285, yet home-bgp's TUI showed "Peer: 1305 (MISMATCH)" in red because its peer's raw capability (1305) legitimately differed from its own negotiated value. Added a second wire field, `VersionInfoPayload::live_tunnel_mtu` (surfaced as `DaemonSnapshot::peer_applied_tunnel_mtu`), carrying each side's own already-negotiated live MTU alongside its raw capability -- `mlvpn-tui` now only flags a real problem when the peer's *applied* value is lower than this side's own (negotiation hasn't converged), and shows the peer's raw capability as a plain, unstyled "Peer capability: N" line otherwise. Backward-compatible: `0`/absent from an older peer decodes as "unknown", same convention as `tunnel_mtu`'s own pre-0.6.0 zero-sentinel.

## [0.7.2] - 2026-09-14

### Added

- **New diagnostic counter: `wg_rejected_total`, per link and daemon-wide.** Every incoming UDP datagram is fed to boringtun's `WgTunnel::decapsulate`; until now, if boringtun rejected one outright (bad MAC, replay-window miss, garbled/oversized data), that rejection was silently swallowed after a `tracing::debug!` line and never counted anywhere -- invisible to `outbound_queue_dropped_total` and the TUN device's own `rx_dropped`/`tx_dropped`, since the rejection happens inside boringtun before a frame is ever handed to those layers. Added a lifetime `AtomicU64` on `WgTunnel` (`src/wireguard.rs`), incremented on every `TunnResult::Err` and oversized-datagram rejection in `decapsulate`, surfaced per link via `LinkSnapshot::wg_rejected_total` and daemon-wide (sum across links) via `DaemonSnapshot::wg_rejected_total`. Shown in `mlvpn-tui`'s Links tab (a red "wg rejected: N" line under Tx/Rx, only once nonzero) and its Outbound Queue panel ("WG rejected (all links)"), and in `mlvpnd diag-dump`'s text output. Motivated directly by a live investigation finding real TCP-level loss (~15% retransmission under load, confirmed via `ss -tin`) with every pre-existing counter reading zero -- this closes that specific blind spot so a future round of the same investigation can tell whether boringtun's own rejection path is the actual cause.

## [0.7.1] - 2026-09-14

### Added

- **`mlvpn-tui`'s Links tab now shows which link is actually primary.** A new "Role" column shows "Primary" (bold green) on whichever link `Scheduler::primary()` currently points at, and "Failover" (muted) on every other link -- but only when `primary_link_mode`/`follow_peer_primary` is actually active. `LinkSnapshot` gains a new `is_primary` field (backward-compatible: `#[serde(default)]`, defaults to `false`) to carry this over the control socket. Motivated directly by a real troubleshooting session where confirming which link was actually selected required diffing raw `tx_bytes` counters by hand across two control-socket polls.
- **Same Role column also tags plain SWRR/bonded mode.** When no link is primary (i.e. `primary_link_mode`/`follow_peer_primary` off, every Up link genuinely sharing traffic by score), each currently-Up link now shows "Bonded" (cyan) instead of a blank cell; a Down/Probing link still renders blank since it isn't part of the active bonding set.

### Fixed

- Corrected `Cargo.toml`'s package description, which still said "Noise-encrypted tunnel" -- stale since the v0.7.0 WireGuard-per-link rewrite; now says "WireGuard-encrypted".

### Reverted

- **`mlvpnd self-test --tunnel`'s adaptive bandwidth ramp.** A same-night attempt to replace the tunnel-level self-test's fixed `MAX_SEND_RATE_MBPS = 150` pacing cap with the same adaptive ramp mechanism already proven for the per-link self-test (motivated by real active-bandwidth-probing data showing ~400 Mbps of real per-link capacity, far above the old fixed cap) was tested directly against live production hardware and reverted: it converged to a much lower, misleading throughput number (~3-6 Mbps) than the simple fixed-rate approach it was meant to replace, for reasons that remain unexplained after two independent attempts (1-second and 3-second probe-step durations both hit the identical cliff at the same target rate). `tunneltest.rs` is back to its exact pre-attempt behavior; both the attempt and its ruled-out follow-up are preserved as a permanent doc comment on `MAX_SEND_RATE_MBPS` so a future try doesn't re-discover the same dead end from scratch.

## [0.7.0] - 2026-09-13

### Changed

- **BREAKING WIRE-PROTOCOL CHANGE: mlvpn-rs now uses an independent WireGuard tunnel (via `boringtun`) per physical link, instead of a single shared Noise_IK session. Both peers MUST be upgraded together; an old build cannot communicate with a new one.** Motivated by a real, repeatedly-reproduced throughput gap: on the identical physical link, at the same time, a parallel WireGuard tunnel sustained roughly 4x mlvpn-rs's own transport (e.g. ~98 Mbps vs. ~25 Mbps in one clean side-by-side measurement, with CPU confirmed idle throughout -- ruling out raw encryption cost as the explanation). An extensive same-project investigation across several point releases (v0.6.1-v0.6.4) tested and ruled out shared-session lock contention specifically as the cause -- the "% time in futex" signal that investigation initially chased turned out to be tokio's own worker threads correctly idle-parking, not genuine contention -- so the exact root cause of the gap in the old transport was never conclusively identified. Rather than continue chasing it, this change replaces the shared-session transport entirely with per-link WireGuard tunnels, adopting a transport already proven at the throughput this project needs. This also happens to remove the old design's single daemon-wide crypto session as a structural bottleneck candidate, even though it was never proven to be the actual one.

  **Configuration changes (non-optional):**
  - The `[crypto]` section (`rekey_interval_secs`, `preferred_cipher`, `noise_pattern`, `dh_function`) has been completely removed. Each link now manages its own independent WireGuard session -- no daemon-wide rekey timer or shared key material.
  - Each `[[links]]` entry now *requires* `private_key_file` (path to this link's WireGuard private key) and `peer_public_key` (the peer's corresponding WireGuard public key for that same link). Both are non-optional; config validation will error if either is absent.
  - `mlvpnd genkey` now requires `--link <name>` instead of generating a daemon-global key -- it generates a WireGuard keypair for a specific link. Write the private key to the path specified in `[[links.<name>.private_key_file]]`.

  **Migration from 0.6.x:** The tunnel is not backward-compatible. Upgrading both peers together requires:
  1. Generate new WireGuard keypairs for each link via `mlvpnd genkey --link <linkname>`.
  2. Update both hosts' configs with the matching public/private key material for each link.
  3. Restart both `mlvpnd` processes together (or very close in time -- no version negotiation exists; an older peer rejects a newer one).

  All higher-layer functionality (bonding, failover, load balancing, monitoring, self-test, TUI) remains identical -- only the link-level transport and crypto changed.

## [0.6.6] - 2026-09-01

### Changed

- **Settled single-link scheduling (`primary_link_mode`/`follow_peer_primary`) now bypasses `ReorderBuffer` entirely and delivers to the TUN device immediately, matching WireGuard's own architecture for single-path tunnels.** `ReorderBuffer` exists specifically to handle genuine cross-link reordering from bonding across multiple links with different real-world latencies -- but once scheduling has settled on one active link, there is no cross-link reordering left to protect against, only whatever minor natural reordering a single network path occasionally produces, which TCP's own SACK/fast-retransmit machinery already handles without help from the tunnel layer. The prior fix in this same investigation (v0.6.5, shrinking the auto-tuned reorder window) was verified in production and did not help; this is the more direct fix the negative result pointed toward. A new `ReorderBuffer::note_delivered` method keeps `high_watermark` accurate during bypass (without touching the buffer's `pending` map) so a later fallback to buffered multi-link delivery -- if the primary goes Down -- resumes from an accurate watermark rather than a stale one, avoiding the same class of bug this project has already been burned by twice (the original reorder-buffer delay bug, and the v0.5.3 rekey-stranding regression). Independent review caught and fixed a real gap in the initial implementation: the bypass branch now also resets `peer_primary_link` on a session-id change (matching the existing buffered-branch behavior), since `Scheduler::primary()` is driven purely by probe/monitor ticks and is not guaranteed to hand control back to the buffered branch on any predictable cadence -- without this, an adopted `peer_primary_link` under `follow_peer_primary` could have latched indefinitely across rekeys if the peer's `VersionInfo` stopped decoding. Zero behavior change for any host not running `primary_link_mode`/`follow_peer_primary` with a settled primary -- plain SWRR and `redundant_mode` are entirely unaffected.

## [0.6.5] - 2026-09-01

### Fixed

- **Reorder-window auto-tuning (`scheduler.auto_tune_reorder_window`) is now scheduling-mode-aware and jitter-aware.** Previously it computed the suggested `reorder_window_ms` purely from RTT spread across every currently-Up link, regardless of whether the active scheduling mode could actually deliver packets from more than one of them. With `primary_link_mode`/`follow_peer_primary` settled on a single active link, an idle backup link's own RTT (which can be dramatically different -- e.g. a cellular backup vs. a wired primary) was still inflating the auto-tuned window, adding real, unnecessary latency to every packet on the actual active link. The formula also never read `jitter_ms` at all, despite it already being tracked per link as an RFC 3550-style EWMA -- a link's own timing variance, not its distance from another link, is the physically correct signal for how much a single link's own packets could legitimately arrive out of order. Now: with a settled `Scheduler::primary()`, the suggestion is driven entirely by that one link's own jitter (multiplier 4.0, deliberately mirroring TCP's own RTO formula, Jacobson/Karels `RTO = SRTT + 4*RTTVAR`); without a settled primary (plain SWRR, `redundant_mode`, or a primary/follow mode before one has settled), it combines the existing RTT-spread term (multiplier 1.5, unchanged) with a new worst-case-jitter term across Up links. No new config fields; existing `reorder_window_min_ms`/`reorder_window_max_ms` bounds and hysteresis logic are unchanged. This targets a real production throughput investigation: tunneled TCP was observed exhibiting sawtooth retransmission-timeout cycling (bursts to 60+ Mbps followed by complete collapses to zero, repeating) despite 0% loss reported by mlvpn's own active probes and the raw physical path independently measuring 886 Mbps of sustained capacity -- the suspected root cause is exactly this kind of unnecessary tunnel-induced latency variance tripping TCP's own RTO estimate, even though nothing is actually being lost end-to-end.

## [0.6.4] - 2026-09-01

### Fixed

- **Fourth same-night follow-up: `reorder_flush` now uses `try_lock()` instead of unconditionally blocking on the reorder buffer's lock.** This periodic task ticks every 10ms specifically to catch entries that would otherwise sit in the reorder buffer until a staleness timeout, since `handle_incoming`'s own inline `insert()`+`drain_ready()` only runs when a new packet actually arrives to trigger it. Under real load, `handle_incoming` already drains the buffer far more often than this timer needs to, so `reorder_flush`'s own lock acquisition was almost always redundant contention against the hot per-packet path. Skips the tick entirely when the lock is currently held; worst case, a genuinely idle straggler waits one extra ~10ms tick before its own staleness timeout flushes it on the next successful tick -- negligible next to `reorder_window_ms`'s own 10-500ms range.

## [0.6.3] - 2026-09-01

### Fixed

- **Third same-night follow-up: split `SessionState`'s locking from a plain `Mutex` into an `RwLock`.** `SessionState` is a single, daemon-wide crypto session (not per-link) used for every encrypt on send and every decrypt on receive. `SessionState::encrypt` has always taken `&self` -- it only reads the active session's key material and the already-lock-free `next_send_seq()` atomic counter -- yet every encrypt call site (real Data traffic, Probe replies, StatsShare, VersionInfo, ThroughputTest -- 11 call sites) was serialized behind the same exclusive lock as `decrypt`/`install`/`expire_previous` (the only methods that genuinely mutate state: the replay-protection window, or which session is active during a rekey), and behind every *other* encrypt call too. Modeled directly on WireGuard's own design (researched from its actual `wireguard-go` source: the outgoing nonce is a lock-free atomic, and the lock only ever guards which keypair is currently active, never the AEAD computation itself): encrypt call sites now take a shared read lock and can run concurrently with each other; `decrypt`/`install`/`expire_previous` still take an exclusive write lock where genuinely needed, so an in-flight encrypt can never observe a torn mid-rekey session swap. No behavior change to encrypt/decrypt/replay-window/rekey semantics -- purely a lock-type change plus using the access level each call site already logically needed. Independently reviewed for correctness given the crypto-adjacent stakes: all 16 call-site classifications verified against `crypto.rs`'s real method signatures, concurrent-encrypt safety verified against the underlying `snow` crate's actual cipher implementation (a fresh cipher instance per call, no shared mutable state), and the `Sync` bound `RwLock` newly requires confirmed as genuinely, soundly satisfied (not just compiling by coincidence).

## [0.6.2] - 2026-08-31

### Fixed

- **Follow-up to 0.6.1's send-path lock-contention fix: the receive path had a matching, smaller version of the same issue.** Every incoming Data packet locked the same per-link mutex twice in a row -- once to check/update the learned remote address (done for every packet type), once immediately after just to record rx byte/packet counters (Data-only). Merged into a single lock acquisition. Live `strace` after 0.6.1 was deployed showed futex contention essentially unchanged (~76-84% of wall-clock time on both production hosts), confirming the send-path fix alone wasn't the full picture; this closes the matching gap on the receive side.

## [0.6.1] - 2026-08-31

### Fixed

- **A real, confirmed throughput-limiting bug in the per-packet send path.** `send_scheduled()` was calling `link::snapshot_scores()` -- an async lock acquisition on *every* configured link -- unconditionally, on every single outgoing Data packet, purely to satisfy an `is_empty()` guard that `Scheduler::select()`'s actual primary/SWRR decision logic never reads (both are populated entirely by the last periodic `refresh()` call, not anything live at send time). Confirmed live in production via `strace -f -c` on `mlvpnd` during a loaded tunnel: **~75% of the daemon's wall-clock time was spent in `futex`** (async-lock contention), averaging ~1.9ms per wait, while `sendto` -- the actual work -- accounted for only ~5%. Real tunneled throughput was capped around 15-30 Mbps despite the underlying link measuring 400+ Mbps raw, 0% loss on mlvpn's own active probes, zero TUN-device drops, and negligible CPU usage -- the daemon was spending nearly all its time waiting on its own locks, not doing I/O. New `Scheduler::select_fast()` resolves a primary or SWRR pick straight from already-cached state with zero link locking, falling back to the original `snapshot_scores()` + `select()` path only in the rare case where nothing is cached yet (every link Down). Same algorithm, same results -- purely eliminates redundant per-packet lock contention in the common case.

## [0.6.0] - 2026-08-31

### Added

- **New opt-in `scheduler.primary_link_mode`: send all traffic over whichever single bonded link currently looks fastest, instead of splitting via SWRR across every Up link.** Off by default -- existing deployments genuinely combining two comparable links for aggregate bandwidth see no change. When enabled, failover to the next-best link on a hard failure (the primary going Down) is immediate; switching to a link that merely looks a little better right now requires it to stay ahead by a real margin (20%) for several consecutive probe cycles, preventing flapping between two close-scoring links on ordinary measurement noise. Reuses the existing `monitor::score()` composite metric -- no new scoring mechanism. Non-primary links keep probing (and, if `active_bandwidth_probing` is on, ramping) normally in the background, so failover is instant rather than starting from a cold, unmeasured link. **Caveat:** `bandwidth_cap_mbps` is not enforced while a link is acting as primary -- it only affects primary *selection* via `monitor::score()`'s throughput term, not the sending rate once a link is selected. An operator relying on a cap to protect a metered/expensive link should be aware primary-link mode bypasses it.
- **New opt-in `scheduler.follow_peer_primary`: let one host be the sole "decider" for both directions of a link pair.** Instead of running its own independent primary-selection hysteresis, a host in this mode adopts whatever primary link its peer last advertised over the existing periodic `VersionInfo` wire exchange, falling back to ordinary SWRR scheduling whenever the peer hasn't chosen a primary yet or chose one that isn't Up on this side too (e.g. asymmetric loss between the two hosts' views of the same link). Useful for a host serving multiple differently-configured peers without needing a matching `primary_link_mode` config for each one. The advertised primary is resolved by **link name**, not a raw wire index -- wire `link_id` is assigned per-host from each host's own `[[link]]` config order and is not a namespace shared between peers, so both hosts' `[[link]]` entries for the same physical path must use the same `name` for this to work correctly. Requires v0.6.0+ on both ends; against an older peer this is a silent no-op (no primary is ever advertised, so the follower always falls back to ordinary scheduling). The adopted primary is reset whenever the underlying session rekeys, so a peer that stops advertising (e.g. rolled back to an older build) can't permanently strand a follower on one link.
- **`mlvpn-tui` now shows both sides' live tunnel MTU** in the Session panel, flagging a mismatch the same way peer version already is. Piggybacked on the existing periodic `VersionInfo` wire exchange (`VersionInfoPayload` gains a `tunnel_mtu` field) rather than a new packet type. Previously neither side's tunnel MTU was shown anywhere in `mlvpn-tui` at all.

### Changed

- **`VersionInfoPayload::decode` is now tolerant of a shorter payload from a pre-0.6.0 peer**, rather than failing closed. Only the `version` field is required; `tunnel_mtu` and the new primary-link-name field default sanely when the buffer is shorter (defaults to `0` and "no primary" respectively). Previously a mixed-version tunnel during a rolling upgrade (this project's actual deployment pattern -- one host upgraded, the other up to an hour later) would go completely blind on peer version, MTU, and primary-link display right at the moment that visibility matters most for catching skew. A residual decode failure (buffer shorter than even the version field) is now logged at `debug` level instead of silently discarded.

## [0.5.4] - 2026-08-31

### Added

- **`tunnel.tx_queue_len` -- the TUN device's transmit queue length is now a first-class config option, defaulting to 4000 instead of the OS default (500 packets on Linux).** Confirmed live on real production infrastructure: a burst of real Data traffic caused 168 TUN-level TX drops in an 8-second tunneled TCP test, even though the underlying WAN links had far more raw capacity available -- the queue was simply too shallow to absorb the burst under bursty encrypted tunnel traffic. Raising it eliminated further drops on retest. Previously this required a manual, easy-to-miss, per-deployment `systemd-networkd` workaround; every deployment now gets the fix automatically with no config changes needed. Bounded to `100..=65536` in `Config::validate()`; still tunable for deployments with unusual bandwidth-delay-product characteristics. See `docs/superpowers/specs/2026-08-31-tun-tx-queue-length-design.md`.

## [0.5.3] - 2026-08-31

### Fixed

- **`ReorderBuffer`'s v0.5.2 fix was itself undone by every rekey.** `Session::next_send_seq()` (in `src/crypto.rs`) starts a fresh, low sequence counter every time a rekey installs a new session -- but `ReorderBuffer::high_watermark` is a separate, tunnel-lifetime value that was never reset when that happened. With any real `crypto.rekey_interval_secs` configured, every single rekey permanently stranded the watermark far above the new session's low sequence numbers, meaning every real Data frame after the first rekey failed the "forward progress" check forever -- silently re-introducing v0.5.2's own just-fixed bug on a rekey cadence, and compounding worse with each subsequent rekey rather than staying constant. Confirmed live on real production infrastructure: v0.5.2 measured a healthy round-trip shortly after a fresh daemon restart (before the first rekey elapsed), then degraded back to roughly the pre-v0.5.2 baseline once a rekey occurred, while the raw physical link underneath stayed fast and clean throughout -- conclusively isolating the added latency to this daemon's own pipeline. Fixed by resetting `ReorderBuffer`'s watermark and pending state the moment a received Data frame's session ID changes; `hdr.session_id` is authenticated (checked only after successful decryption) before it's used for this, so it cannot be forged to trigger spurious resets. No configuration change, no wire-protocol change.

## [0.5.2] - 2026-08-29

### Fixed

- **`ReorderBuffer` was needlessly delaying nearly every real Data packet by close to the full `reorder_window_ms`, on every default-configuration deployment.** It compared each incoming Data frame's sequence number against the exact integer it expected next -- but that sequence number is shared by every packet type sent over the session (Data, health probes, periodic stats/version broadcasts, self-test traffic), so the specific next integer a Data frame "should" have was almost always consumed by something else instead, and would never arrive as Data. A real production deployment showed this costing ~110ms of needless round-trip latency (measured via a plain ping through the tunnel against the underlying link's own ~71ms real RTT) and collapsing real end-to-end TCP throughput to a small fraction of the link's actual measured capacity (3-4.5 Mbps against a link whose real ceiling, per v0.5.1's adaptive bandwidth ramp, was 12+ Mbps upload / 400+ Mbps download) -- while every loss/drop counter available anywhere in the daemon or the OS network stack read clean throughout, since nothing was actually being dropped, only delayed. This may also be the true explanation for a previously unresolved mystery in this project's own development notes: real UDP loss observed via `iperf3` with every counter reading zero. Fixed by tracking the highest sequence number delivered so far instead of requiring exact contiguity -- any frame that represents forward progress is now delivered immediately regardless of gaps from non-Data traffic; only frames that genuinely arrive out of order (real cross-link reordering, the buffer's actual purpose) are still held, exactly as before. No configuration change needed, no wire-protocol change, safe to deploy to one end of a tunnel at a time. See `docs/superpowers/specs/2026-08-29-reorder-buffer-watermark-fix-design.md`.

## [0.5.1] - 2026-08-28

### Fixed

- **`mlvpnd self-test` and the background `active_bandwidth_prober` no longer blast UDP unpaced, which was silently getting policed off-host and reporting a link's throughput as far lower than its real capacity.** A real production link with a 45 Mbps upload plan measured only 6-8 Mbps via self-test while attempting roughly 390 Mbps of unthrottled send rate -- with zero drops anywhere in the local network stack (interface counters, `tc qdisc` all clean), meaning the loss was happening entirely off-host at the ISP's policer, invisible to any of this daemon's own instrumentation. `send_throughput_test_stream` now paces every send to a target rate, and a new stepped adaptive ramp (`mlvpnd self-test`'s upload leg, and the periodic background prober) discovers each link's real ceiling by pacing successive bursts at doubling rates until one isn't delivered cleanly, then backs off to a safety margin below that cliff -- no manual per-link configuration needed, matching the auto-detect philosophy of v0.5.0's adaptive MTU feature. The background prober caches the discovered rate and only re-ramps occasionally (new `scheduler.active_bandwidth_reramp_interval_secs`, default 1800s) rather than paying the full ramp's cost on every tick, and now immediately discards its cache and re-ramps after a link recovers from a Down state rather than trusting a possibly-stale pre-outage number. `mlvpnd self-test`'s CLI output now also prints each ramp step's target/achieved pair, so a real throughput ceiling is visible in the output instead of hidden behind one opaque average. `mlvpn-tui`'s Links tab now shows each link's probed bandwidth and confirmed ceiling, previously daemon-side data with no visual surface at all. See `docs/superpowers/specs/2026-08-28-adaptive-bandwidth-pacing-design.md`.
- **A background bandwidth probe that got no result at all (e.g. an old peer that doesn't understand the throughput-test packet type, or a temporarily unreachable peer) no longer reports and caches a fabricated rate.** Found during this release's own code review: the ramp still produced a non-zero "confirmed" number even when every step failed, which then permanently overrode the scheduler's real-traffic-based weighting for that link and self-perpetuated via the new cache. A probe with zero real results now leaves that link's stats untouched and simply retries next cycle, matching how the manual self-test CLI already handled this case.
- **The peer-autonomous reverse/download self-test leg no longer paces at a hardcoded 20 Mbps for every deployment that hasn't opted into background bandwidth probing** (the majority, since that feature defaults off). It now prefers a configured `bandwidth_cap_mbps` for that link when set, before falling back to the fixed constant.
- **A single lost "done" packet at the end of a throughput-test stream no longer inflates the measured duration enough to wrongly fail an otherwise-healthy ramp step.** The receiver now measures elapsed time against the last real data packet it saw, not against whichever retried copy of the final packet happened to arrive.

## [0.5.0] - 2026-08-27

### Added

- **Diagnostics reports can now be submitted to `software-support.jpps.us` as real, trackable support tickets** instead of only ever landing as a local text file. `mlvpnd diag-dump --submit [--message "..."]` submits a manual dump and prints the ticket ID/status URL; automatic loss-threshold dumps do the same when `[diagnostics] auto_submit_enabled = true` (off by default -- this is a new outbound network call the daemon makes on its own initiative, separate consent from `auto_dump_enabled`'s own opt-in); and a new crash panic hook best-effort-submits a report (recent log lines + the panic message) before the process exits when `[diagnostics] crash_report_enabled = true` -- also off by default, and deliberately a separate opt-in from both of the above, since a crash report is the same kind of daemon-initiated outbound call carrying the same operational detail (link names, bind interfaces, peer addresses and ports) off the machine. With it off, a panic prints its backtrace exactly as before. See `docs/monitoring.md`'s "Filing a dump as a support ticket" section and `docs/superpowers/specs/2026-08-27-diagnostics-report-client-design.md`.

### Changed

- **`tunnel.mtu` is no longer a fixed default of 1400 -- it's optional, and unset (the new default) means mlvpn-rs picks the tunnel MTU entirely from live-detected physical link MTUs, adjusting automatically, including upward.** Previously, `tunnel.mtu` defaulted to a hardcoded 1400 and the existing "adaptive" MTU logic only ever clamped that number *down* further if a link's real physical MTU was smaller -- it never used the full capacity of a link whose physical MTU was actually higher (e.g. a real 1500-byte-MTU WireGuard-bonded link), silently capping throughput below what the hardware could carry. mlvpn-rs now also continuously re-checks every 30 seconds and live-resizes the running TUN device (no restart needed) if a link's detected MTU changes, e.g. on reconnect to different hardware. Setting `tunnel.mtu` explicitly in your config still works exactly as before (an operator ceiling that detection can clamp further down from, never up past) -- only the *default*, unset behavior changed. The shipped example configs and `docs/getting-started.md` now leave `tunnel.mtu` commented out to match, so a fresh install actually gets the new behavior. See `docs/superpowers/specs/2026-08-27-adaptive-mtu-design.md`.
- **Known limitation -- the two ends of a tunnel now pick their MTUs independently, and there is no negotiation between them.** With `tunnel.mtu` unset, each end derives its own tunnel MTU from its own local link detection. Bonding genuinely asymmetric hardware (an LTE modem at ~1428 on one end, plain Ethernet at 1500 on the other) can therefore leave the two ends settled on different tunnel MTUs. TCP is unaffected -- MSS clamping keeps each direction correct -- but UDP and ICMP packets large enough to fit the bigger side and not the smaller are silently discarded on arrival, so the symptom is a size-dependent blackhole that looks fine in casual (TCP) testing. Note that the fix for this is *not* to set a matching `tunnel.mtu` ceiling on both ends by hand: that caps the faster link down to the slower one everywhere, throwing away exactly the capacity this release exists to recover. The correct fix is real negotiation -- each side learning the peer's MTU over the existing periodic peer version exchange and applying `min(local, peer)` only where it is actually needed -- which is out of scope for this release and tracked as a follow-up.
- **Under the "start as root, drop privileges" deployment model, `mlvpnd` now retains `CAP_NET_ADMIN` across the drop instead of clearing every capability.** Resizing the live TUN device needs that capability *at the moment of the resize*, not just at startup, so without this the new continuous MTU adjustment silently stopped working after the drop. This matches what the shipped systemd unit already granted persistently via `AmbientCapabilities=`, so both deployment models now hold the same one capability at runtime. `CAP_NET_RAW` is deliberately still dropped -- link reconnection's pre-existing limitation under this model is unchanged. Retaining the capability is necessary but *not sufficient* on its own: Linux capabilities are per-thread, and the daemon builds its multi-threaded async runtime before dropping, so its worker threads (one of which runs the MTU monitor) end up with no capabilities at all. Every `SIOCSIFMTU` is therefore routed to a dedicated thread spawned immediately after the drop, which does inherit the retained `CAP_NET_ADMIN`. Under the ambient-capability model, where all threads hold it, that routing is simply a no-op detail.

## [0.4.6] - 2026-07-20

### Fixed

- **A peer's `Disconnect` (sent on any routine restart -- a `.deb` upgrade, a manual `systemctl restart`) used to make the *receiving* side exit its own process too**, cascading a full stop-then-cold-restart onto the other end even when nothing was wrong with it -- a full `RestartSec` gap, every task (TUN device, outbound queue, control sockets, all links) rebuilt from scratch, and a fresh handshake renegotiated from zero. A real diagnostic dump showed that reconnection dance taking up to ~18 seconds of repeated handshake-timeout retries, and likely explains a false loss-threshold auto-dump trip observed in the field too (the dual-stack address-family switch right after a cold handshake losing a few in-flight probes into a freshly-initialized, not-yet-stable loss EWMA). A received `Disconnect` now just means the peer's session went stale: `mlvpnd` in client mode immediately attempts a fresh handshake instead of waiting up to `rekey_interval_secs` (which can be configured up to hours out); server mode needs no extra action, since it already accepts a handshake at any time. Neither side's own process ever stops running anymore just because the peer said goodbye -- reconnection now happens in about a second instead of a multi-second-to-tens-of-seconds full restart cascade. A genuinely local `systemctl stop`/SIGTERM is unaffected: still notifies the peer, still exits cleanly.
- **`debian/mlvpn.postinst`'s restart-after-upgrade state capture could read the wrong value if `mlvpnd` crashed or exited during dpkg's own unpacking step**, since that capture ran at the top of `postinst`, which only starts *after* unpacking finishes -- real field evidence (a `systemd` "Scheduled restart job" line, showing `mlvpnd` exiting unexpectedly, not via an explicit stop) showed this landing in exactly that window on a real upgrade. New `debian/mlvpn.preinst` captures whether the service was active *before* dpkg unpacks anything, immune to whatever happens during unpacking; `postinst` now reads that instead of doing its own (too-late) live check.

### Added

- **Peer version exchange**: each side now periodically broadcasts its own `mlvpnd` version to the peer over the existing authenticated session (piggybacked on the same timer as link stats, no new socket). `mlvpn-tui`'s Session panel shows both sides' versions and flags a mismatch; both `mlvpnd self-test` commands print a `peer version: ...` line, sourced from this independent exchange rather than the self-test's own round trip -- so it's still available to help rule out version skew even when a test itself times out with no result. `mlvpnd diag-dump`'s text output picks this up for free.

## [0.4.5] - 2026-07-20

### Added

- **New tunnel-level throughput self-test**: `mlvpnd self-test --tunnel --peer-addr <tunnel-internal ip>` (new `ipc::Command::RunTunnelThroughputTest`). The existing self-test sends raw UDP directly on a link's own socket, bypassing the TUN device, outbound queue, and scheduler -- useful for characterizing one physical link, but blind to buffering/queueing problems in the real bonded path. This one sends real UDP addressed to the peer's tunnel-internal IP, so the kernel genuinely routes it through the TUN device end to end, exercising the real pipeline. `--bidirectional` has the peer autonomously send its own stream back; each direction's report includes that leg's own outbound-queue-drop count, so loss can be narrowed down to "never left our own queue" versus loss elsewhere on the path -- directly aimed at the still-open field mystery of real UDP loss with mlvpn's own drop counters reading zero. The server side's listener runs unconditionally regardless of its own `[command]` config, matching the existing self-test's "any daemon can be the target" precedent. See `docs/monitoring.md`'s new "Tunnel-level self-test" section.

### Fixed

- **Active bandwidth probing (`scheduler.active_bandwidth_probing`) badly underreported fast links.** The old mechanism sent a small fixed-size burst (`active_bandwidth_probe_packets`, 2-100 packets) and timed it -- accurate for a slow link, but wrong for a fast one: a real 688 Mbps link that `mlvpnd self-test` measured correctly was reported by the probe as just 56.7 Mbps, because a ~28KB burst completes in a fraction of one round trip on a fast link and mostly measures local send-side overhead, not the path's real sustained capacity. Replaced `active_bandwidth_probe_packets` with `active_bandwidth_probe_duration_secs` (default 2s, 1-30s) and switched to reusing `mlvpnd self-test`'s own duration-based streaming code, so the probe scales naturally to whatever the link can actually do. **Config change**: `active_bandwidth_probe_packets` is removed; set `active_bandwidth_probe_duration_secs` instead if you had customized the old field (most deployments use the default and need no config change).

## [0.4.4] - 2026-07-19

### Fixed

- **`mlvpnd`'s log ring (feeds `mlvpn-tui`'s Logs tab and `mlvpnd diag-dump`) dropped every structured field but the bare message.** This codebase's own logging convention routinely puts the actually useful diagnostic detail in named fields (`error = %e`, `dir = %path`, etc.), not the free-text message -- found live when a real `diagnostics_watch_loop` failure ("failed to write diagnostic dump") showed up in an actual `diag-dump` output with no `error`/`dir` detail at all, even though journald had the full fields the whole time. `logbuf::MessageVisitor` now captures every field and appends them as `key=value` pairs after the message.

### Added

- **`mlvpnd self-test` now logs at the start of each leg** (and when the receiving side starts seeing a stream), not just on completion -- a diagnostic dump covering that window now clearly shows a deliberate self-test was running, rather than looking like unexplained loss.

### Changed

- **Default `[diagnostics] dump_dir` changed from `/run/mlvpn` (tmpfs, cleared on stop/reboot) to `/var/log/mlvpn`** (persistent, matches where most other services log to), backed by a new `LogsDirectory=mlvpn` in the systemd unit -- no manual `mkdir`/`chown`/`ReadWritePaths=` needed for the default case anymore. A custom `dump_dir` still needs its own `ReadWritePaths=` added to the unit.
- **Loosened the systemd unit's restart rate limit** (`StartLimitBurst`/`StartLimitIntervalSec`, 5/60s -> 10/120s) as headroom against two hosts restarting near-simultaneously (e.g. both upgrading at once) potentially exhausting the old, tighter limit and landing the service in a `failed` state that `Restart=always` can't recover from on its own -- a suspected but not confirmed cause of a real field report of the service not coming back up after a package upgrade.

## [0.4.3] - 2026-07-19

### Fixed

- **A client-mode link whose `remote_addr` hostname resolves to both an `A` and `AAAA` record could get permanently stuck trying an unreachable address family** (e.g. IPv6 disabled on that link's own interface) while a second, unrelated link came up fine. The v0.4.1 happy-eyeballs fix (`link::pick_remote_addr` racing IPv4/IPv6 on the first handshake) only ever resolved the family for whichever *one* link's reply happened to win the tunnel's overall initial-handshake race across every configured link -- the peer deduplicates every copy of that broadcast by session id, so only the very first arrival across *all* targets ever gets a reply, and every other link's own primary-vs-alternate ambiguity was simply discarded unused (`commit_remote(None)`, unconditionally, for every link that didn't win). Added `tunnel::resolve_remaining_alternates`: right after the session is established, it races a real authenticated `Probe`/`ProbeReply` round trip between each remaining link's primary and alternate address (no second handshake needed) and commits whichever one actually answers, falling back to the original primary -- exactly the old behavior -- only if neither does.

### Added

- **On-demand diagnostic-dump capture**: `mlvpnd diag-dump --config ... [--output PATH]` (new `ipc::Command::DiagDump` on the command socket) captures every link's health, daemon/session state, outbound queue, TUN counters, system stats, and every log line currently held in the log ring into one text bundle, plus kernel-level UDP diagnostics (`nstat -az` filtered to UDP lines, `ss -lu -n -a`, `/proc/net/udp`) gathered by the CLI process itself rather than the sandboxed daemon -- meant to be attached to a bug report the moment loss is observed.
- **Automatic loss-triggered dumps**: new `[diagnostics]` config section (`auto_dump_enabled`, off by default; `loss_threshold_pct`, default 10%; `cooldown_secs`, default 300; `dump_dir`, default `/run/mlvpn`). With it enabled, the daemon watches every link's own locally-measured loss and writes the daemon-visible half of the same dump to disk on its own the moment one crosses the threshold -- catching a transient loss event's evidence even if no one is watching `mlvpn-tui` at the time.

## [0.4.2] - 2026-07-19

### Fixed

- **Empty Daemon-tab System panel** (`Load: - - -`, `Mem: --`, `Uptime: --`) on systemd-managed installs. The shipped unit's `ProcSubset=pid` hid every non-PID top-level `/proc` file (`/proc/loadavg`, `/proc/meminfo`, `/proc/uptime`) that `procstats.rs` reads, even though `ProtectProc=invisible` alone already provides the isolation property actually intended (hiding other processes' `/proc/<PID>` trees). Removed `ProcSubset=pid` from `systemd/mlvpn.service`.
- **Active-bandwidth-probe measurements deflated by per-packet session lock contention.** The probe burst previously acquired the shared Noise session lock once per packet, so real concurrent Data traffic competing for that same lock could inflate the measured burst duration and silently understate the link's true capacity -- observed in the field as a fast link (independently verified at 1.36 Gbps) reporting well under 40 Mbps. The burst is now encrypted under a single lock acquisition instead of one per packet. Verified via a real veth-pair test: an unshaped baseline jumped from ~226 Mbps to ~948 Mbps from this change alone, even with zero concurrent traffic. `active_bandwidth_mbps` feeds scheduler weight, so an artificially low reading here was causing the affected link to be systematically underweighted in bonding decisions.

### Added

- **`mlvpn-tui` real-time per-link and aggregate throughput display.** The existing Tx/Rx columns were cumulative lifetime totals, making it hard to watch bonding behavior live. `LinkStats` now tracks a windowed tx throughput EWMA alongside the existing rx one; the Links tab shows both live rx/tx rates per link, plus a tunnel-wide aggregate (summed across currently-up links) in the panel title.
- **On-demand throughput self-test**: `mlvpnd self-test --config ... [--link NAME] [--duration SECS] [--bidirectional]` sends a real MTU-sized packet stream to the peer over the existing (off-by-default) command socket and reports the peer's measured achieved rate -- no configuration or command-socket access needed on the peer's end. `--bidirectional` additionally has the peer send its own stream back afterward, entirely autonomously (three new wire packet types: `ThroughputTestData`, `ThroughputTestResult`, `ThroughputTestReverseRequest`). Built to let throughput/loss issues be reproduced and measured directly against the daemon's own diagnostics, rather than only inferred from an external tool like `iperf3`.

## [0.4.1] - 2026-07-18

### Fixed

- **A client-side link whose `remote_addr` is a hostname resolving to both an IPv4 and an IPv6 address could hang its initial handshake indefinitely** if the IPv6 path wasn't actually reachable end-to-end -- a broken or absent route, not uncommon on residential/consumer ISPs, and not the same thing as the `AAAA` record simply existing. `pick_remote_addr` previously committed to the IPv6 candidate up front with no fallback, so the daemon would retry the handshake against a dead address forever (visible as repeated "handshake attempt failed, retrying... timeout" log lines) even though the exact same peer was perfectly reachable over IPv4 the whole time. Both resolved candidates are now raced during the very first handshake attempt only (never on a later rekey), and whichever one actually answers wins -- logged at INFO when the fallback kicks in. `local_addr`, when set, still pins one family outright with no racing, unchanged.

### Added

- **`mlvpn-tui` gains a new Overview tab**, now the default tab at startup: condensed Links/Daemon/Logs panes stacked into one screen, for an at-a-glance and screenshot-friendly view without switching tabs. Tab keybindings shift to `1`/`2`/`3`/`4` (Overview/Links/Daemon/Logs) accordingly.
- More color coding in `mlvpn-tui`: link score (by how much traffic share it's actually carrying), loss percentage within the Links tab's measurement text (muted uniformly when peer data is stale, rather than color-coding numbers that might be well out of date), and the Daemon tab's memory-used percentage.
- **`mlvpn-tui` no longer fails immediately at startup if the control socket doesn't exist yet.** Previously a hard, immediate error even when `mlvpnd` was actually running and simply hadn't finished its initial handshake -- the control socket isn't created until that handshake succeeds, so a freshly (re)started daemon waiting on an unreachable peer genuinely has nothing to connect to yet. Auto-detecting with nothing found now checks whether the `mlvpn` systemd service is active: if so, it goes straight to the full-screen view (which keeps watching for the socket to appear in the background); if the service isn't running at all, it offers to start it right at the prompt.

## [0.4.0] - 2026-07-18

### Added

- **`mlvpn-tui` redesigned as a tabbed Links / Daemon / Logs interface**, replacing the single always-visible link table:
  - **Links**: existing per-link state/peer-addr/score/local-and-peer-measurement columns, now joined by "Up For" (how long the link has held its current state) and cumulative "Tx / Rx" byte totals.
  - **Daemon** (new): session id/uptime/rekey count; the outbound queue's current depth (a fill-ratio-colored gauge) and lifetime drop count; the TUN interface's own kernel-tracked byte/error/drop counters (`/sys/class/net/<iface>/statistics/*`); and machine-wide load average/memory/uptime (`/proc`).
  - **Logs** (new): a live tail of the daemon's own log output (INFO and above), streamed incrementally over the existing control socket rather than requiring a separate `journalctl -f` window. `Up`/`Down`/`PageUp`/`PageDown` scroll back through history; staying at the newest line auto-follows, same as `tail -f`.
  - Switch tabs with `Tab`/`Shift+Tab` or `1`/`2`/`3`. Coloring across every tab now goes through five shared semantic constants (good/warn/bad/muted/accent) instead of scattered inline color literals.
- New `ipc::DaemonSnapshot` (session/rekey metadata, outbound queue health, TUN sysfs counters, `/proc` system stats) and `Snapshot::new_log_lines` (a per-connection delta of new log lines since that client's last poll) on the control-socket wire format, backing the Daemon and Logs tabs above.
- New `SessionMeta` (`tunnel.rs`): session id/uptime/rekey count now live in their own atomics-and-`Instant` struct instead of requiring a getter on the per-packet-locked `SessionState`, so reading them from the control socket adds no contention to the hot path.
- New `logbuf::LogRing` and `LogRingLayer`: an in-memory ring of the daemon's own log lines, fed by a `tracing_subscriber::Layer` filtered to INFO+ independent of whatever verbosity `[logging].level` is actually configured to, so a debug/trace run can't flood the ring or the control socket.
- New `sysfs_net.rs` (TUN interface kernel counters) and `procstats.rs` (`/proc/loadavg`/`meminfo`/`uptime`) modules.
- New integration test `tests/veth_daemon_health.rs`, covering all of the above against two real `mlvpnd` processes -- including that `new_log_lines` delivers a genuine delta, never repeating a line already sent to the same connection.

### Changed

- **Breaking wire change**: `ipc::Snapshot` gained two required (non-`Option`) fields, `daemon` and `new_log_lines`. `mlvpnd` and `mlvpn-tui` must be upgraded together on a given host -- an old `mlvpn-tui` talking to a new `mlvpnd`, or a new `mlvpn-tui` talking to an old `mlvpnd`, will fail to parse the control socket's JSON rather than degrading gracefully.
- The outbound-queue drop counter (`outbound_queue_drop_reporter`) is now a monotonic lifetime total (also exposed via `DaemonSnapshot::outbound_queue_dropped_total`) instead of being reset to 0 by its own periodic log line; the reporter tracks its own windowed delta locally, so its "silent unless something was actually dropped" logging behavior is unchanged.

## [0.3.7] - 2026-07-18

### Fixed

- **`compute_achieved_mbps`'s elapsed-time floor silently capped active-bandwidth-probe results at ~229 Mbps on fast links.** The floor guards against a zero-duration divide, but at `0.001` (1ms) it was high enough to override real, correctly-measured durations: a ~28KB probe burst only needs to sustain ~229 Mbps to be delivered in under a millisecond, which any modern broadband link can do, so `Instant::elapsed()`'s accurate (smaller) duration got replaced by the 1ms floor and `achieved_mbps` ceilinged at the same value every time -- confirmed from production `journalctl` logs showing the exact value `229.1199951171875` recurring dozens of times on a fast link. Since `active_bandwidth_mbps` feeds `monitor::score()`'s scheduler weight (`throughput.sqrt()`), a link stuck reporting a fake low ceiling was systematically underweighted relative to its real capacity -- a plausible contributor to the sub-additive bonded-throughput behavior tracked since 0.3.1. Lowered the floor to `0.000_001` (1 microsecond); `Instant` has nanosecond resolution, so this still only guards the literal zero/negative case.

## [0.3.6] - 2026-07-17

### Fixed

- **`.deb` postinst corruption left `mlvpn` 0.3.5 unable to install at
  all** (`dpkg --configure` failing with exit 127, quoting a mangled
  fragment of a comment as an unrecognized command). Root cause:
  debhelper's `dh_installdeb` substitutes *every* occurrence of the
  literal marker token in a maintainer script, not just the one
  intended insertion point -- undocumented as a footgun, but
  documented behavior (see `dh_installdeb(1)`). `debian/mlvpn.postinst`'s
  own explanatory comments mentioned that token five more times in
  prose, so each one got a second copy of debhelper's generated
  `systemctl restart`/`daemon-reload` code spliced into the middle of
  the sentence, breaking the script's syntax. Rewrote every comment to
  describe the marker without repeating the literal token pattern
  debhelper matches on. The `.rpm` was never affected -- version
  bumped only to keep both packages on the same release number.

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

[0.4.1]: https://github.com/4jpps/mlvpn-rs/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/4jpps/mlvpn-rs/compare/v0.3.7...v0.4.0
[0.3.7]: https://github.com/4jpps/mlvpn-rs/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/4jpps/mlvpn-rs/compare/v0.3.5...v0.3.6
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
