# mlvpn-rs Architecture

A Rust rewrite of MLVPN: a daemon that bonds several physical network
uplinks (fiber, DSL, LTE, ...) into a single encrypted tunnel, spreading
traffic across them in proportion to measured quality and failing over
automatically when a link degrades. Target platform is Debian 13
(trixie) and other current systemd-based Linux distributions.

This document is a map of the design and the reasoning behind the major
decisions. For implementation detail, read the code -- most modules
carry their own doc comments.

## Relationship to the original MLVPN

The name and core idea -- bond several physical uplinks into one
encrypted, monitored, auto-failing-over tunnel -- come from
[MLVPN](https://github.com/zehome/MLVPN) by Laurent Coustet (`zehome`).
Credit for the idea belongs there; this is a from-scratch rewrite in a
different language and shares no code with it.

The original is written in C (BSD-2-Clause). This project makes a few
deliberate departures from that design:

- **Binds to a network interface, not an IP address**, so a link
  survives a DHCP renewal or an LTE modem reconnecting with a new
  address instead of going stale until someone notices.
- **Memory-safe implementation** (Rust) instead of C, which matters
  most exactly where this daemon parses attacker-reachable network
  input.
- **Modern authenticated-key-exchange cryptography** -- a full
  `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake (the same family
  WireGuard is built on) with mutual authentication and forward
  secrecy, instead of a shared password-derived key.
- **`async`/tokio concurrency** instead of a single-threaded event
  loop.
- **Privilege dropping**, not multi-process privilege separation.
- **IPv4/IPv6 dual-stack tunnel interface, adaptive MTU, and TCP MSS
  clamping** -- see §12. Bonded links are independently IPv4/IPv6
  too -- see §6.
- **Packaged and CI-built for current distributions**, with automatic
  firewall configuration (`mlvpnd firewall-setup`).

This project is licensed [AGPL-3.0-only](LICENSE), a copyleft license,
in contrast to MLVPN's permissive BSD-2-Clause -- see
`CONTRIBUTING.md`'s "Licensing" section for why. That choice has no
bearing on MLVPN's own licensing.

## 1. Goals

Automatic tunnel latency measurement, correct binding to specific
physical interfaces, priority/scheduling based on latency + throughput
+ jitter, zero downtime unless *every* bound interface is actually
unreachable, and current security best practice.

| Requirement | Where |
|---|---|
| Bind to the correct interface | `link::Link::bind` (`SO_BINDTODEVICE`) |
| Self-measured latency/jitter | `monitor.rs` + `Probe`/`ProbeReply` frames |
| Priority by latency/jitter/throughput | `monitor::score()` |
| No downtime unless all links are down | `scheduler::Scheduler::select()` fallback |
| Security best practices | `crypto.rs`, `privilege.rs`, `systemd/mlvpn.service` |

## 2. Process layout

One binary, `mlvpnd`, run in either `client` or `server` mode. Both
roles run the identical data path once a session is established; the
only asymmetry is who initiates the Noise handshake.

At startup: open the TUN device, bind one UDP socket per configured
link to its named interface (requesting an 8 MiB kernel receive/send
buffer on each, well past the stock ~208KB Linux default that would
otherwise silently drop packets under a fast link's real
bandwidth-delay product -- see `docs/performance-tuning.md`), load key
material, drop privileges, then
perform the Noise handshake and spawn the steady-state tasks. A client
whose peer is unreachable never gives up and exits: it logs a warning
and retries the handshake with exponential backoff indefinitely in the
background (`tunnel::establish_session_with_retry`), the same way
WireGuard and the original MLVPN behave -- earlier versions instead
exited the process on a failed handshake, which under systemd's default
`Restart=on-failure` could trip the restart-rate-limit and leave the
unit permanently `failed` if a peer stayed unreachable for more than a
few minutes at boot.

Steady state (`tunnel.rs`) is a small set of tokio tasks:

- `tun_reader` -- reads the TUN device, encrypts, and hands each frame
  off (a bounded, non-blocking queue) to `outbound_sender`, which asks
  the scheduler which link to use and sends it. Split into two tasks
  specifically so a slow send side can never stall draining the TUN
  device; a full queue drops the packet and counts it instead of
  blocking. `outbound_queue_drop_reporter` periodically logs that count
  (silent when it's zero) -- modeled on the original C `MLVPN`'s
  `freebuffer_t`. See §6 and `docs/performance-tuning.md`.
- two tasks per physical link -- `link_receiver` reads and dispatches
  incoming frames; `link_prober` independently sends probes and stats
  on its own timer. Kept as separate tasks so a busy link's receive
  volume can never starve its own probe timer.
- `reorder_flush` -- releases anything that's aged past the reorder
  window, so one missing packet can't stall the tunnel.
- `reorder_tuning_loop` (optional, off by default) -- periodically
  re-tunes that window itself from live link conditions. See §7.
- `active_bandwidth_prober`, one per physical link (optional, off by
  default) -- periodically sends a short burst of dummy packets purely
  to measure that link's achieved throughput. See §5.
- `control::serve` (optional, on by default) -- streams live stats to
  `mlvpn-tui` over a local Unix socket. See §9.
- `control::serve_commands` (optional, off by default) -- a separate
  Unix socket accepting runtime link-control commands. See §9.

## 3. Wire protocol

Defined in `protocol.rs`. Every frame has a small plaintext header
(packet type, link id, session id, sequence number) followed by a
payload. Handshake payloads are raw Noise messages; every other frame
type -- `Data`, `Probe`, `ProbeReply`, `StatsShare`,
`BandwidthProbeBurst`, `BandwidthProbeResult` -- is AEAD ciphertext, so
an off-path attacker can't inject forged probe/stats samples, forge a
fake bandwidth result, or read tunnel traffic.

The sequence number is global per session, not per link -- this is
what makes replay protection and receive-side reordering work
correctly when the same stream is spread across links with different
latencies.

## 4. Crypto

`Noise_IK_25519_ChaChaPoly_BLAKE2s` via the `snow` crate -- the same
protocol family WireGuard is built on. Both peers hold each other's
long-term public key out of band (from the config file) and pin it
after the handshake, so "authenticated" means "authenticated as the
specific configured peer," not just "holds some valid key."

Replay protection is a sliding-window bitmap keyed on the session's
sequence number, tolerant of the reordering multipath introduces.

Sessions rekey periodically (`crypto.rekey_interval_secs`, default
120s) to bound how much traffic is ever protected by one set of keys.
The client always initiates a rekey the same way it initiates the
first handshake; the server passively accepts it. A short overlap
window keeps the outgoing session's keys valid briefly after a swap so
packets already in flight aren't dropped. See `crypto.rs`'s
`SessionState` doc comment for the full design.

Key handling: `mlvpnd genkey` writes a private key to a 0600 file;
`mlvpnd` refuses to start if key/config files are group- or
other-readable, and zeroizes private key bytes on drop.

## 5. Link quality: latency, jitter, throughput

Each link runs its own probe cycle: send a timestamped `Probe` frame
on an interval (default 200ms), the far end echoes it back, and RTT is
computed from our own clock. RTT feeds an EWMA; jitter is the EWMA of
delta between consecutive samples; loss is an EWMA of a hit/miss
series. Throughput is measured passively from actual bytes
transferred by default, with an opt-in active alternative below.

**Probe interval auto-tuning (opt-in).** `scheduler.auto_tune_probe_interval`
(off by default) lets a link's *effective* probe interval back off
above its configured `probe_interval_ms` floor after a long clean
streak (every 10 consecutive good probes, ×1.5, capped at
`probe_interval_max_ms`) -- less overhead on a link that's been stable
for a while. Any miss at all snaps it straight back to the floor, so a
link that starts looking even slightly less reliable gets the fastest
hysteresis reaction available again immediately. The configured
`probe_interval_ms` is always the floor, never lowered by this. See
`tunnel::suggest_probe_interval_ms`.

**EWMA alpha auto-tuning (opt-in).** `scheduler.auto_tune_ewma_alpha`
(off by default, the most speculative of this project's four
auto-tuning knobs) lets a link's smoothing factor -- shared by all four
of its EWMAs (`link::LinkStats::set_alpha`) -- move within
`[ewma_alpha_min, ewma_alpha_max]`. Any miss jumps it straight to the
max (fastest reaction to trouble); a long clean streak gradually
smooths it back toward the min instead (less noise-sensitive on a
stable link). See `tunnel::suggest_ewma_alpha`.

**Active bandwidth probing (opt-in).** `scheduler.active_bandwidth_probing`
(off by default) has `tunnel::active_bandwidth_prober` periodically send
a short, rate-limited burst of MTU-sized dummy packets
(`active_bandwidth_probe_packets`, default 20) down each link on a slow
timer (`active_bandwidth_probe_interval_secs`, default 300s, validated
floor of 30s -- this is injected traffic, not a single latency probe, so
it needs a much lower ceiling on frequency than `Probe`/`ProbeReply`).
The receiver times how long the whole burst took to arrive and reports
the achieved rate back (`BandwidthProbeResult`), which feeds a separate
`link::LinkStats::active_bandwidth_mbps` EWMA -- kept distinct from the
passive `throughput_mbps` above, since a deliberate burst and organic
traffic measure genuinely different things. This is what lets an
under-used link (one whose current low score means real traffic rarely
saturates it) still get judged on its true capacity rather than looking
artificially slow. Off by default for a stronger reason than the other
three auto-tuning knobs: unlike those, this one puts real (if small and
infrequent) extra traffic on the wire, which isn't appropriate for every
link (e.g. a metered connection).

An unshaped/fast link delivers its whole burst in a handful of
milliseconds with no pacing at all -- exactly the traffic pattern most
likely to hit a transient receive-side drop, and losing specifically
the *final* packet (the one that triggers the receiver to compute and
reply with a result) would otherwise silently discard the entire
measurement even though every other packet arrived fine. `tunnel::active_bandwidth_prober`
sends the final packet a couple of extra times as cheap insurance
against exactly that; the receiver-side
`tunnel::BandwidthProbeReceiveState::last_completed_probe_id` guard
makes a redundant copy of an already-completed burst's final packet a
harmless no-op instead of a spurious second (near-instant, wildly
inflated) result.

`monitor::score()` combines these into one number per link, weighted
by an operator-configured static bias (`[[links]] weight`). Throughput
is rewarded sub-linearly so one very fast link doesn't starve a
slower-but-useful one; latency/jitter/loss are multiplicative
penalties so a fast-but-flaky link can't outscore a slower-but-reliable
one.

## 6. Scheduling and failover

`scheduler.rs` implements smooth weighted round robin (SWRR, the same
algorithm nginx uses for weighted upstream balancing) over every link
currently `Up`, re-weighted as new scores come in.

**Per-link bandwidth cap.** A link's `bandwidth_cap_mbps` is a real,
enforced ceiling, not just a scoring bias: once a link has carried that
much in the current second, the scheduler picks a different link
instead until the next window, falling back to sending anyway (rather
than dropping the packet) only if every link happens to be over its
cap at once.

**Redundancy mode.** Opt-in (`scheduler.redundant_mode`, off by
default): instead of picking one link per packet, send every packet on
every currently-Up link at once. Trades bandwidth for the lowest
possible chance of losing any individual packet -- worth it for a
small, latency-critical tunnel, not a bulk-transfer one. The receiving
side needs no special handling: the existing replay window already
drops the second and later copies of the same packet as duplicates.

**Up/Down transitions use hysteresis**, not a single missed probe --
several consecutive misses to go down, several consecutive hits to
come back -- so a marginal link doesn't flap in and out of rotation.

**Zero-downtime semantics**: if every link is currently judged `Down`,
the scheduler still sends on the least-bad one rather than refusing to
send, since "probe-Down" is a quality judgment, not proof the
interface is actually gone. The moment any path starts working again,
traffic flows without operator intervention.

**Self-healing reconnection.** Binding by interface name rather than
IP address means most connectivity loss (DHCP renewal, a brief
admin-down) needs no special handling at all. The harder case -- an
interface fully removed and recreated (a USB LTE modem replugged) --
gets a new kernel ifindex, so an already-bound socket can't recover on
its own; `link_receiver`/`link_prober` detect a sustained run of
socket failures and rebind that link's socket from scratch, with
backoff. See §8 for a deployment-model caveat.

**Per-link address family.** Each bonded link is independently IPv4 or
IPv6 -- there's no tunnel-wide setting, and a single tunnel can mix
both across its links. `link::socket_domain` infers which from
whichever of `remote_addr`/`local_addr` is set on that link's config
entry (a client-side link always has `remote_addr`; a server-side link
with none set falls back to `local_addr`, e.g. `"::"` for IPv6), so an
existing IPv4-only config keeps working unchanged. `remote_addr` accepts
a DNS hostname as well as a literal IP (`link::resolve_remote_addr`,
resolved once at startup); if it resolves to both an `A` and `AAAA`
record, `local_addr` picks the family if set, otherwise IPv6 is
preferred (`link::pick_remote_addr`). This is distinct from
`tunnel.address6` (§12), which is about the TUN interface's own
address, not the transport sockets between the two `mlvpnd` instances.

## 7. Receive-side reordering

`tunnel::ReorderBuffer` holds decrypted packets keyed by sequence
number and releases a run as soon as the gap fills, or unconditionally
once a packet has waited past `reorder_window_ms` (default 50ms) --
whichever comes first. This is what prevents one permanently lost
packet from stalling the whole tunnel.

**Auto-tuning the window (opt-in).** `scheduler.auto_tune_reorder_window`
(off by default) hands the window over to `tunnel::reorder_tuning_loop`,
which re-evaluates it every 30s from the live RTT spread across
currently-Up links -- a tunnel bonding two similar links wants a tight
window, one bonding a fast link with a slow one needs more slack, and
that spread can drift over a long-running tunnel's life. A suggestion
only takes effect once it clears a hysteresis threshold against the
value currently in effect, the same anti-flapping principle as the
Up/Down hysteresis in §6, and is always clamped to a configured
`[reorder_window_min_ms, reorder_window_max_ms]` range (defaults 10ms/
500ms). Applied changes are logged at `info` level; left off, behavior
is unchanged from a fixed `reorder_window_ms` for the tunnel's whole
life, same as before this existed.

## 8. Privilege and system hardening

Two supported deployment postures:

1. **Start as root, drop after setup** -- open the TUN device and bind
   sockets while root, then drop to an unprivileged `mlvpn` user and
   explicitly clear every capability.
2. **Never be root** -- grant exactly the two needed capabilities via
   systemd `AmbientCapabilities=` and run as `mlvpn` from process
   start. This is the stronger posture and what the shipped
   `systemd/mlvpn.service` uses.

This choice also determines whether self-healing reconnection (§6) can
actually reconnect: it needs a capability held at the moment of
reconnect, which model 2 keeps for the process's whole life and model
1 deliberately clears at startup. Under model 1, a reconnect attempt
fails cleanly with a one-time logged explanation rather than retrying
forever -- a real trade-off between the two models, not a bug in
either.

The shipped systemd unit also applies standard sandboxing
(`NoNewPrivileges`, `ProtectSystem=strict`, syscall filtering, and
more -- see the unit file itself for the full list).

Other practices applied throughout: config/key files rejected at
startup if group/other-readable; private key material zeroized on
drop; all non-handshake wire traffic AEAD-authenticated; a link's peer
address is only learned from a packet's source *after* that packet
passes authentication, to prevent spoofed-source redirection; a
malformed handshake attempt is logged and discarded, never crashes or
hangs the daemon; and an unreachable peer at startup is retried with
backoff in the background rather than exiting the daemon (§2).

## 9. Monitoring and runtime control: mlvpn-tui and the two sockets

`mlvpn-tui` makes link health visible at a glance on either end,
without needing shell access to the other side.

Each link periodically shares its own measured stats with the peer
over an authenticated wire frame (`StatsShare`), so each side can show
a full-duplex view. Separately, `mlvpnd` optionally (on by default)
streams live JSON snapshots over a local Unix socket
(`/run/mlvpn/<tunnel.name>.sock`, mode 0600) for `mlvpn-tui` to render
-- read-only, no command/write side.

Beyond per-link stats, each `Snapshot` carries a `DaemonSnapshot`
(session id/uptime/rekey count off the hot-path lock via `SessionMeta`;
outbound queue depth/capacity/lifetime drops; the TUN device's own
`/sys/class/net/<iface>/statistics/*` counters via `sysfs_net.rs`;
machine-wide load/memory/uptime from `/proc` via `procstats.rs`) and a
`new_log_lines` delta from an in-memory ring of the daemon's own INFO+
log output (`logbuf::LogRing`, fed by a `tracing_subscriber::Layer`
independent of whatever verbosity `[logging].level` sets for the
primary log output). Each connected client tracks its own cursor into
the ring (`control::serve_client`'s `last_log_seq`), so the log tail
streams as a delta over the same 500ms cadence rather than needing a
dedicated socket. `mlvpn-tui` renders all of this as three tabs --
Links, Daemon, Logs -- see [monitoring.md](docs/monitoring.md).

**Command socket** (`[command] enabled`, off by default). A second,
separate Unix socket -- different path
(`/run/mlvpn/<tunnel.name>.command.sock` by default), same mode-0600
creation as the monitoring socket above -- for runtime link control:
currently one command, pin a link enabled/disabled
(`ipc::Command::SetLinkEnabled`, `mlvpnd set-link` on the CLI). This
sets `Link::admin_disabled`, which `monitor::score()` treats as an
automatic 0 (excluded from scheduling, same as a probe-Down link),
kept deliberately independent of the link's real `state` -- a manually
pinned-off link still reports its true probe-measured quality, it's
just not eligible for picking. Not persisted: a restart always starts
every link enabled. Kept as a second socket, not a write mode bolted
onto the monitoring one, so a client authorized only to read link/traffic
stats (a monitoring-only account) never incidentally gains the ability
to redirect live traffic.

## 10. Build and deployment

```
cargo build --release
sudo install -m0755 target/release/mlvpnd /usr/bin/mlvpnd
sudo install -m0755 target/release/mlvpn-tui /usr/bin/mlvpn-tui
```

Or build the `.deb`/`.rpm` packages -- see `docs/development.md`. See
`config/mlvpn.toml.example` / `config/mlvpn-server.toml.example` for a
paired client/server configuration.

## 11. Known limitations / roadmap

**QUIC as an additional link transport** is the one substantial piece
of this design not yet built -- deliberately deferred to a later
release rather than a gap in the current one. See
[`docs/roadmap.md`](docs/roadmap.md) for that design. Everything else
originally tracked here has shipped; see [`CHANGELOG.md`](CHANGELOG.md)
for the full history of what and when.

## 12. Dual-stack addressing, adaptive MTU, and TCP MSS clamping

**IPv4/IPv6 dual-stack TUN interface.** The optional IPv6
`tunnel.address6` is assigned alongside the required IPv4
`tunnel.address` on the same device -- there's no separate "IPv6
tunnel." Both address families share the one encrypted session and the
one set of bonded links.

**Adaptive MTU.** `tunnel.mtu` is an upper bound, not a fixed value:
at startup, each link's real physical interface MTU is detected, and
the configured value is clamped down if it would exceed what the
smallest detected physical MTU can carry. This is a one-shot decision
at startup, not a continuous control loop -- physical MTUs essentially
never change while an interface stays up.

**TCP MSS clamping** (on by default). Adaptive MTU alone only bounds
the tunnel's own outer packet size; individual TCP connections
*through* the tunnel still negotiate their own segment size via Path
MTU Discovery, which many networks silently break (the "PMTUD black
hole" -- affected connections stall rather than just running slower).
`mlvpnd` rewrites the MSS option on outgoing TCP SYN/SYN-ACK segments
when it exceeds what the tunnel can carry, the same technique
`iptables --clamp-mss-to-pmtu` uses. Anything that doesn't cleanly
parse as a well-formed TCP SYN is left untouched.
