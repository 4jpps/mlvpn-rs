# mlvpn-rs Architecture

A Rust rewrite of MLVPN: a daemon that bonds several physical network
uplinks (fiber, DSL, LTE, ...) into a single encrypted tunnel, spreading
traffic across them in proportion to measured quality and failing over
automatically when a link degrades. Target platform is Debian 13
(trixie) and other current systemd-based Linux distributions.

This document covers the design as implemented in this first pass, the
reasoning behind the major decisions, and what's explicitly deferred to
later work. It's meant to be read alongside the source -- most modules
carry their own design-rationale doc comments; this file is the map that
ties them together.

## 1. Goals, restated precisely

The request this implements: automatic tunnel latency measurement, correct
binding to specific physical interfaces, priority/scheduling based on
latency + speed (throughput) + jitter, zero downtime unless *every* bound
interface is actually unreachable, and adherence to current security best
practice. Each of these maps to a specific module:

| Requirement | Where |
|---|---|
| Bind to the correct interface | `link::Link::bind` (`SO_BINDTODEVICE`) |
| Self-measured latency/jitter | `monitor.rs` + the `Probe`/`ProbeReply` frames in `protocol.rs` |
| Priority by latency/jitter/throughput | `monitor::score()` |
| No downtime unless all links are down | `scheduler::Scheduler::select()` fallback path |
| Security best practices | `crypto.rs` (Noise_IK), `privilege.rs`, `systemd/mlvpn.service` |

## 2. Process layout

One binary, `mlvpnd`, run in either `client` or `server` mode (see
`config.rs::Mode`). Both roles run the identical data path once a session
is established; the only asymmetry is who initiates the Noise handshake.

At startup (`main.rs::run`):

1. Open the TUN device (`tun-rs`, requires `CAP_NET_ADMIN`).
2. Bind one UDP socket per configured link to its named interface via
   `SO_BINDTODEVICE` (requires `CAP_NET_RAW`).
3. Load the local static private key and the peer's pinned public key.
4. **Drop privileges** (`privilege::drop_privileges`) -- from here on the
   process runs as an unprivileged `mlvpn` user with an empty capability
   set. See `systemd/mlvpn.service` for the alternative (stronger) posture
   of never being root in the first place.
5. Hand the already-open TUN device and already-bound sockets to
   `tunnel::run`, which performs the Noise handshake and then spawns the
   steady-state tasks described below.

Steady state (`tunnel.rs`) is a small set of tokio tasks:

- `tun_reader` -- TUN → encrypt → `Scheduler::select()` → chosen link's
  socket.
- two tasks per physical link -- `link_receiver` owns that link's socket
  and reads incoming frames, dispatching by type (Data → reorder buffer →
  TUN; Probe → authenticate, reply; ProbeReply → feed `monitor`; StatsShare
  → feed `peerstats::PeerStatsTable`); `link_prober` independently sends
  `Probe` frames on a timer, sweeps timed-out ones into `monitor` as
  losses, and sends `StatsShare` frames on a slower timer. These are two
  separate tasks rather than one task `select!`-ing between "receive" and
  "timer" branches: under sustained receive load, a `select!` can starve
  the timer branches, silently disabling probing on exactly the busiest
  links. See the module doc comment at the top of `tunnel.rs` for the full
  reasoning.
- `reorder_flush` -- periodically releases anything in the reorder buffer
  that's aged past the configured window, so one missing packet can't
  stall the tunnel indefinitely.
- `control::serve` (optional, on by default) -- accepts connections on the
  local monitoring Unix socket and streams live stats to `mlvpn-tui`. See
  §11.

See the module doc comment at the top of `tunnel.rs` for the locking
discipline (short summary: the shared `Vec<Link>` mutex guards metadata
only; every socket read/write happens on an `Arc<UdpSocket>` clone taken
out from under the lock first, so one slow link can never block another).

## 3. Wire protocol

Defined in `protocol.rs`. Every frame after the outer UDP header has a
16-byte plaintext header (magic, version, packet type, link id, session
id, 64-bit sequence number) followed by a payload. `HandshakeInit` /
`HandshakeResp` payloads are raw Noise handshake messages (Noise protects
those itself); every other type's payload -- `Data`, `Probe`, `ProbeReply`,
and `StatsShare` alike -- is AEAD ciphertext produced by the session
established during the handshake.

Authenticating `Probe`/`ProbeReply` (and `StatsShare`), not just `Data`,
was a deliberate choice made partway through implementation: an
unauthenticated probe channel would let an off-path attacker inject forged
RTT/loss samples and steer scheduling decisions, or falsely flip a healthy
link to `Down` -- and an unauthenticated stats channel would let one feed
fabricated numbers straight into the peer's monitoring display. Wire
format details and the AAD tradeoff (the sequence number is the AEAD
nonce and is therefore implicitly authenticated; the other header fields
are not cryptographically bound to the ciphertext because `snow`'s
`StatelessTransportState` doesn't expose an AAD parameter) are documented
in `crypto.rs`'s module doc comment.

The sequence number is global per session, not per link -- this is what
makes replay protection and receive-side reordering work correctly when
the same stream of packets is spread across physically different paths
with different latencies.

## 4. Crypto

`Noise_IK_25519_ChaChaPoly_BLAKE2s` via the `snow` crate:

- **IK** gives a single-round-trip, mutually authenticated handshake with
  forward secrecy -- the same family of guarantee WireGuard's protocol is
  built on. Both peers hold each other's long-term Curve25519 public key
  out of band (from the config file); after the handshake, each side
  additionally **pins** the peer's revealed static key against the
  configured `peer_public_key` before trusting the session, which is what
  turns "authenticated as someone holding a matching key" into
  "authenticated as the specific peer we intended to talk to."
- `StatelessTransportState` (not `TransportState`) is used for the
  transport phase because the same session sends and receives across
  multiple physical links concurrently, so packets do not arrive in send
  order. The stateless variant takes an explicit nonce per call instead of
  assuming one; we set that nonce to our own monotonic sequence counter.
- Replay protection is a WireGuard-style sliding bitmap window
  (`crypto::ReplayWindow`, 2048-entry) keyed on that same sequence number,
  tolerant of the reordering multipath introduces while still rejecting
  genuine duplicates.
- Sessions are meant to be rekeyed periodically
  (`crypto.rekey_interval_secs`) to bound how much ciphertext is ever
  protected by one set of transport keys. **Not yet wired up** -- see
  Roadmap.

Key handling: `mlvpnd genkey` generates a keypair and can write the
private half directly to a 0600 file. `config::Config::load` refuses to
start if the private key file (or the config file itself, since it may
embed key material via its path) is readable by group/other. `crypto.rs`
zeroizes private key bytes on drop.

## 5. Link quality: latency, jitter, throughput

Each link runs its own probe cycle (`link_actor` in `tunnel.rs`,
`monitor::ProbeTracker` for the bookkeeping):

- Every `probe_interval_ms` (default 200ms), send an authenticated `Probe`
  frame carrying our own timestamp and a local probe sequence number.
- The far end echoes it back as `ProbeReply` (also authenticated).
- On reply, RTT is computed from *our own* clock (`sent_at.elapsed()`) --
  we never trust the peer's timestamp, only round-trip delta against our
  own monotonic clock.
- RTT feeds an EWMA (`link::Ewma`, configurable `ewma_alpha`); jitter is
  the EWMA of the absolute delta between consecutive RTT samples (RFC
  3550 §6.4.1 style); loss is an EWMA of a 0/1 hit-or-miss series.
- Throughput is measured passively from actual bytes transferred
  (`LinkStats::record_bytes`), not a synthetic bandwidth probe -- cheaper,
  adds no extra traffic, and reflects real contention rather than a
  potentially-uncontended synthetic burst.

`monitor::score()` combines these into one number per link:

```
score = weight * sqrt(throughput_mbps) * latency_factor * jitter_factor * loss_factor
latency_factor = 1 / (1 + rtt_ms / 50)
jitter_factor  = 1 / (1 + jitter_ms / 20)
loss_factor    = (1 - loss_rate)^2
```

Throughput is rewarded sub-linearly (square root) so one very fast link
doesn't completely starve a slower-but-useful one; latency/jitter/loss
are multiplicative penalties so a fast-but-flaky link can't outscore a
slower-but-reliable one. `weight` is the operator-configured static bias
from `[[links]] weight` (e.g. to deprioritize a metered connection).

## 6. Scheduling and failover

`scheduler.rs` implements smooth weighted round robin (SWRR) -- the same
algorithm nginx uses for weighted upstream balancing -- over every link
currently in the `Up` state, re-weighted by `monitor::score()` every time
a probe result or timeout sweep changes the picture.

**Up/Down transitions use hysteresis**, not a single missed probe:
`down_threshold` consecutive misses to go `Up → Down`, `up_threshold`
consecutive hits to come back. This exists specifically to stop a link
that's marginal (occasionally dropping one probe in ten) from bouncing in
and out of rotation every few hundred milliseconds, which would be worse
for real traffic than just staying down a beat longer than strictly
necessary.

**Zero-downtime semantics**: `Scheduler::select()` only returns `None`
when there are zero configured links (a startup config error, not a
runtime state). If every link is currently `Down`, `select()` falls back
to the least-bad one (fewest consecutive misses, then lowest last-known
RTT) instead of refusing to send. The reasoning: a probe-`Down`
determination is a *quality judgment about the overlay path*, not proof
the physical interface is gone -- it could equally be the peer being
briefly overloaded, a transient carrier-side issue, or a probe packet
itself being dropped while data would have gotten through. Continuing to
attempt transmission means the moment any path actually starts working
again, traffic flows without an operator having to intervene, which is
what "no downtime unless every bound interface is actually offline"
means in practice: from inside the process, "every interface is
unreachable" and "every interface is being judged Down by the monitor"
are indistinguishable, so the only responsible behavior is to keep trying
rather than to guess.

## 7. Receive-side reordering

Because the same stream is spread across links with different latencies,
packets can and will arrive out of order relative to how they were
generated on the TUN device. `tunnel::ReorderBuffer` holds decrypted Data
payloads keyed by sequence number and releases a run starting at
`next_expected` as soon as the gap fills, or unconditionally once a
packet has waited past `reorder_window_ms` (default 50ms) regardless of
whether the gap ever fills. The latter is what prevents one permanently
lost packet from stalling the whole tunnel: we would rather deliver
slightly out of order than not deliver at all.

## 8. Privilege and system hardening

Two supported deployment postures (`privilege.rs` module doc, and see
`systemd/mlvpn.service`):

1. **Start as root, drop after setup** -- open the TUN device and bind
   sockets while root, then `setgroups([])` → `setgid` → `setuid` to an
   unprivileged `mlvpn` user, then explicitly clear every capability set
   as defense in depth (the kernel already does this implicitly on
   `setuid()` away from root per `capabilities(7)`, but making it
   explicit means the code stays correct even if that implicit behavior
   is ever bypassed elsewhere in the process).
2. **Never be root** -- grant exactly `CAP_NET_ADMIN` and `CAP_NET_RAW` to
   the unit via `AmbientCapabilities=`/`CapabilityBoundingSet=` and run as
   `mlvpn` from process start. This is the stronger posture (no privileged
   window at all, however brief) and is what the shipped
   `systemd/mlvpn.service` uses.

The shipped unit additionally applies the standard systemd sandboxing
surface: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, kernel/proc/clock/hostname protections, namespace and
real-time restriction, `MemoryDenyWriteExecute`, a `SystemCallFilter`
allow-listing `@system-service` and explicitly excluding privileged/mount/
debug/cpu-emulation syscall groups, and a restrictive `UMask`. `/dev/net/tun`
is the one device explicitly allowed through `PrivateDevices=no` +
`DeviceAllow`.

Other practices applied throughout:

- Config and key files are rejected at startup if group/other-readable
  (`config::check_permissions`).
- Private key material is zeroized on drop (`zeroize` crate).
- All non-handshake wire traffic is AEAD-authenticated (§3) -- there is no
  plaintext, unauthenticated control channel an attacker could use to
  manipulate scheduling or inject traffic.
- A link's peer address is only (re-)learned from a packet's source IP
  *after* that packet has passed AEAD authentication, specifically to
  prevent an off-path attacker from redirecting where we send subsequent
  encrypted traffic via a spoofed-source unauthenticated packet.
- A malformed or hostile handshake attempt on the server is logged and
  discarded; it cannot crash or hang the accept loop (see the comments in
  `tunnel::establish_session`'s `Mode::Server` arm).

## 9. Monitoring: mlvpn-tui and the control socket

Operating a bonding VPN by tailing `journalctl -u mlvpn` on both ends and
mentally correlating timestamps doesn't scale past "it's obviously
broken." `mlvpn-tui` exists to make link health visible at a glance, on
either end, without needing shell access to the other side.

**Wire side** (`protocol.rs`): each link's `link_prober` task sends a
`PacketType::StatsShare` frame roughly once a second, carrying that link's
own current `rtt_ms` / `jitter_ms` / `loss_pct` / `throughput_mbps` /
state and its configured name (`StatsPayload`, fixed 33-byte encoding,
AEAD-protected like every other post-handshake frame type -- see §3 for
why authentication matters here specifically). The receiving
`link_receiver` task decodes it and stores it in
`peerstats::PeerStatsTable`, keyed by *our own* local link index rather
than anything the sender includes -- each link is a dedicated
point-to-point socket pairing, so the local receiving index already
unambiguously identifies the physical link regardless of how the two
sides happen to order their own `[[links]]` config.

**IPC side** (`ipc.rs`, `control.rs`): `mlvpnd` optionally (on by default,
`[control] enabled`) binds a Unix domain socket at
`/run/mlvpn/<tunnel.name>.sock` (mode 0600) and streams one
newline-delimited JSON `ipc::Snapshot` per connected client roughly twice
a second, combining each link's locally-measured stats with whatever
`peerstats::PeerStatsTable` currently holds for it. There is deliberately
no write/command side -- a client can only observe. `mlvpn-tui`
(`src/bin/mlvpn-tui.rs`) is the reference client: a small, tokio-free
binary that reads the socket on a background OS thread and renders a
`ratatui` table on the main thread, color-coding link state and dimming
peer-side stats once they go stale (no `StatsShare` received recently,
e.g. because the peer is on an older build or the return path is down).

Two access notes:

- Systemd's `RuntimeDirectory=mlvpn` (in `systemd/mlvpn.service`) is what
  makes `/run/mlvpn` exist, owned by the unprivileged `mlvpn` user, under
  `ProtectSystem=strict` -- without it the daemon would have nowhere
  permitted to create the socket file post-privilege-drop.
- The socket's 0600 permissions mean only the `mlvpn` user (or root) can
  connect by default; add another account to the `mlvpn` group and loosen
  `RuntimeDirectoryMode`/the socket's own mode if you want a
  non-privileged monitoring-only account to run `mlvpn-tui` too.

## 10. Build and deployment

```
cargo build --release
sudo install -m0755 target/release/mlvpnd /usr/bin/mlvpnd
sudo install -m0755 target/release/mlvpn-tui /usr/bin/mlvpn-tui
```

(`/usr/bin`, not `/usr/local/bin`, to match where the shipped systemd unit
and Debian package expect the binaries -- see `systemd/mlvpn.service`'s
header comment if you'd rather install elsewhere.)

Or build the `.deb` in `debian/` (targets Debian 13 / any recent
debhelper-compat 13 system):

```
dpkg-buildpackage -us -uc -b
```

See the top of `systemd/mlvpn.service` for one-time host setup
(`mlvpn` user/group, `/etc/mlvpn` permissions, key generation), and
`config/mlvpn.toml.example` / `config/mlvpn-server.toml.example` for a
paired client/server configuration.

**A note on verification**: the core tunnel (everything through §8) has
been built successfully with `cargo build --release` (0 errors) and its
unit tests pass (`monitor::score`, `scheduler`'s SWRR distribution). The
monitoring layer in §9 (`StatsShare`, `ipc.rs`, `control.rs`,
`mlvpn-tui`, and the `lib.rs`/`main.rs` restructuring that split the
crate into a library plus two binaries so they could share `ipc.rs`) is
new and has not yet had a `cargo build --release` run against it -- run
that first after pulling these changes and expect to fix any small
API-surface mismatches in the `ratatui`/`crossterm` calls in
`src/bin/mlvpn-tui.rs`, which is the least-verified file in the tree.
Neither the core tunnel nor the monitoring layer has yet been exercised
as two real processes exchanging traffic over real network links/veth
pairs -- see item 6 in the roadmap below for the integration-test gap
that would close out that remaining uncertainty.

## 11. Known limitations / roadmap

Deliberately out of scope for this first pass, in rough priority order:

1. **Handshake is only attempted on the first configured link.** If that
   specific link is down at startup, initial connection setup stalls even
   though other links might work. Fix: race the initial handshake across
   every link simultaneously, first valid response wins.
2. **No rekey scheduling.** `rekey_interval_secs` is parsed and threaded
   through but nothing triggers a re-handshake yet; `Session` lives for
   the life of the process. Needs: a timer that initiates a fresh
   handshake and atomically swaps the active `Session` without dropping
   in-flight packets.
3. **No session migration/multi-session overlap.** During a rekey, there
   should be a brief window where both old and new session keys accept
   traffic so nothing is dropped mid-transition.
4. **IPv6 links.** `link::Link::bind` hardcodes `Domain::IPV4`; extending
   to IPv6 is mechanical (detect the parsed address family) but untested
   here.
5. **`PacketType::Disconnect` is parsed but unhandled** -- there's no
   graceful teardown signal yet; the tunnel only ever ends via process
   shutdown.
6. **No integration/end-to-end tests.** Unit tests exist for the
   self-contained logic (`monitor::score`, `scheduler`'s SWRR
   distribution, `crypto::ReplayWindow` indirectly via the module) but
   nothing spins up two real `mlvpnd` processes against a pair of veth
   links yet -- that's the natural next step before calling this
   production-ready.
7. **Bandwidth ceiling is operator-declared only** (`bandwidth_cap_mbps`);
   there's no active bandwidth probing to discover it automatically the
   way latency/jitter are discovered.
8. **The control socket is read-only.** `mlvpn-tui` can observe but not
   act -- there's no way to, say, temporarily pin traffic off a flapping
   link from the TUI. Adding a command channel would need its own
   authorization story (the socket's 0600 permissions are enough for
   "can observe," not necessarily enough for "can redirect live traffic").
9. **Bonding is score-proportional only.** `scheduler.rs`'s SWRR already
   spreads traffic across every `Up` link in proportion to its measured
   score, which combines their bandwidth rather than just failing over --
   but there's no explicit per-link bandwidth cap/shaping (beyond the
   passive `bandwidth_cap_mbps` ceiling on the score itself) or optional
   redundancy/broadcast mode (duplicating latency-sensitive traffic across
   multiple links for extra reliability at the cost of bandwidth). Neither
   was needed for the current use case; both are natural extensions to
   `scheduler::Scheduler::select()` if a future need justifies the added
   complexity.
