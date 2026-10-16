# Monitoring and runtime control

`mlvpnd` exposes live per-link and daemon/host health over a local Unix
socket (on by default; see `[control]` in the example configs).
`mlvpn-tui` connects to it and renders a continuously-updating terminal
view:

```sh
mlvpn-tui                    # auto-detects the socket under /run/mlvpn
mlvpn-tui --socket /run/mlvpn/mlvpn0.sock
```

A health banner is always on screen: one state, `● HEALTHY`,
`! DEGRADED`, `↻ FAILOVER`, `× DOWN`, `… STARTING` or `⊘ DISCONNECTED`,
with a one-line reason, the host name, the tunnel and how long it has
been up. Every state has a symbol as well as a color, so it still reads
on a monochrome terminal. The daemon decides the state (see
`telemetry.rs`); DEGRADED is an overlay (a link not up, congested, at 5%
loss or more, or a recent loss event), not a link state. DISCONNECTED is
the one state only the TUI can show: the control socket is gone or has
stopped updating for 3 seconds, and it takes precedence over whatever
the last snapshot said.

- **1 Overview** -- the default: the Links table, tunnel and reliability
  summaries, and the most recent events, so the whole picture fits one
  screenshot.
- **2 Links** -- a compact table (state, role, how long it has held
  that state, RTT, jitter, loss, rx/tx, score, and DEG/QF/ERR flags).
  `Up`/`Down` selects a row and `Enter` opens a detail panel for it:
  this side's own measurements, the peer's self-reported view of the
  same link (received over the tunnel itself), totals, the send queue
  and per-link error counters. `Esc` closes the panel.
- **3 Traffic** -- tunnel and per-link tx/rx rates as bars, each link's
  share of tx, and a one-minute sparkline.
- **4 Reliability** -- FEC (mode, groups and parity sent, frames
  recovered, unrecoverable groups), the reorder buffer (window, depth,
  wait, late/duplicate/timed-out frames), and every drop and error
  counter in one place. Nonzero counters are highlighted, so a clean
  tunnel is a quiet screen.
- **5 System** -- host load/memory/uptime, the daemon process (CPU,
  RSS, threads, open files), the TUN interface's counters, the outbound
  queue, and version and MTU agreement with the peer.
- **6 Debug** -- connection details, the structured event list
  (`LINK_DOWN`, `FEC_UNRECOVERABLE`, ...) and a live tail of the
  daemon's own log, so a separate `journalctl -f` window isn't needed.

Switch views with `Tab`/`Shift+Tab` or `1`-`6`. On the Debug view,
`Up`/`Down`/`PageUp`/`PageDown` scroll back through the log; scrolling
back to the newest line keeps the view pinned to the tail, like
`tail -f`. `q` quits from any view, and `Esc` quits too (after closing
an open link detail panel). On a terminal narrower than 80 columns or
shorter than 20 rows the layout switches to a compact form: no borders,
fewer table columns, short tab names. Reconnecting to a restarted
daemon clears the buffered events, logs and history, because the daemon
replays its rings to every new connection. See
[ARCHITECTURE.md](../ARCHITECTURE.md)'s "Monitoring" section for the
wire/IPC details (`ipc.rs`, `control.rs`, `PacketType::StatsShare`,
`logbuf.rs`, `events.rs`).

The control socket is mode 0600 under `/run/mlvpn` (mode 0750), both
owned by `mlvpn`. Run `sudo mlvpn-tui`, or add your own account to the
`mlvpn` group to connect without `sudo`.

### Startup when the control socket doesn't exist yet

`control::serve` isn't spawned until `mlvpnd`'s initial handshake with
its peer actually succeeds (see `tunnel::run`), so a freshly (re)started
daemon waiting on an unreachable peer genuinely has no control socket
to find yet -- that's not an error, just something to wait out.
Auto-detecting (no `--socket` given) with nothing found under
`/run/mlvpn` checks whether `mlvpn.service` is active:

- **Active**: prints a note that it's likely still waiting for the
  remote end to connect, then goes straight to the full-screen view
  (default Overview), which keeps watching `/run/mlvpn` in the
  background and starts populating live the moment the socket appears
  -- no restart needed.
- **Not running**: offers to start it (`systemctl start mlvpn.service`,
  via `sudo` if not already root) right there at the prompt, before
  switching to full-screen mode.
- **Can't tell** (no `systemctl`, non-systemd host, or `mlvpnd` run some
  other way): falls back to the original plain error asking you to pass
  `--socket` explicitly or check `mlvpnd` yourself.

## Web telemetry API

`mlvpn-web` is an optional, read-only HTTP API for the same data the TUI
shows. It is a separate process, so `mlvpnd` itself gains no listening
socket and no HTTP code. It connects to the daemon's control socket,
keeps the latest snapshot, the last 600 samples (about five minutes) of
throughput/RTT/loss history and the last 500 events in memory, and
serves them as JSON. It is off by default: nothing listens until you run

```
sudo systemctl enable --now mlvpn-web.service
```

(`systemd/mlvpn-web.service`; the unit runs as the `mlvpn` user with no
capabilities.) Or run it by hand as a user that can read the control
socket: `mlvpn-web [--socket PATH] [--listen 127.0.0.1:8765]`.

| Endpoint | Returns |
|---|---|
| `/api/v1/version` | API version, `mlvpn-web` version, local and peer daemon versions |
| `/api/v1/snapshot` | The full snapshot (health, links, daemon, FEC, reorder, system) |
| `/api/v1/links` | Per-link state and counters only |
| `/api/v1/events?since=<seq>&limit=<n>` | Structured events newer than `since` (default 100, max 500), oldest first; poll with the returned `next_since` |
| `/api/v1/history?limit=<n>` | Up to 600 samples at 500 ms: tunnel tx/rx Mbps plus per-link tx/rx Mbps, RTT and loss (default 120) |

Every response is `{"api": 1, "connected": bool, "age_ms": ms-or-null,
"data": ...}`. `connected` is false while the daemon is unreachable and
`age_ms` is how old the data is, so a client can tell stale from live.
Before the first snapshot arrives, `snapshot` and `links` return 503.
Errors are `{"api": 1, "error": "..."}`.

What it will and won't do:

- **Read-only.** Only `GET` and `HEAD`; anything else is a 405, and a
  request with a body is a 400.
- **Loopback only.** Any `--listen` address that isn't loopback is
  refused at startup, because exposing it beyond the host would need
  authentication, which doesn't exist yet. To read it remotely, forward
  the port over SSH. The `Host` header must also be `localhost`,
  `127.0.0.1` or `[::1]` (otherwise 421), which blocks DNS-rebinding
  from a browser on the same machine. No CORS headers are sent.
- **No logs, no secrets.** The daemon's log ring is never served and the
  control socket carries no key material. The snapshot does include each
  link's `remote_addr` and `bind_interface`, which describe your network
  topology, so treat access to the port as access to that.
- **Bounded.** Requests are capped at 8 KiB and 64 headers, must
  complete within 10 s, and at most 32 connections are served at once
  (further ones get an immediate 503). Each connection serves one
  request and closes.

Reconnecting to a restarted daemon clears the buffered events and
history, as in the TUI. There is no dashboard yet; this is the data
layer for one.

## Runtime link control

A separate, off-by-default `[command]` socket lets an operator pin a
link out of scheduling without editing the config and restarting --
useful for taking a flapping or metered link out of rotation
temporarily:

```sh
mlvpnd set-link --config /etc/mlvpn/mlvpn.toml lte disable
mlvpnd set-link --config /etc/mlvpn/mlvpn.toml lte enable
```

Requires `[command] enabled = true` in the config first (see
`config/mlvpn.toml.example`). A disabled link's real quality stats keep
updating in `mlvpn-tui` the whole time -- it's excluded from picking,
not marked unhealthy, and reverts to enabled on the next restart. This
is a deliberately separate socket from the read-only one above, so
being allowed to watch link stats never implies being allowed to
redirect traffic.

## Throughput self-test

The same command socket also runs an on-demand throughput test against
the peer, without needing a separate tool like `iperf3`:

```sh
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml                        # every link, upload only
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml --link lte             # one named link
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml --duration 15          # longer stream, more stable number
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml --bidirectional        # also measure the reverse direction
```

Sends a real, MTU-sized packet stream to the peer for `--duration`
seconds (default 10) and reports the achieved rate -- the receiving
side measures it and reports back, no configuration or command-socket
access needed on that end. `--bidirectional` additionally asks the
peer to send its own stream back afterward (sequentially, not at the
same time, so this roughly doubles the total time); the peer does this
entirely on its own in response to that request, so both directions
can be measured by running the command from just one side. Omitting
`--link` tests every configured link with a currently-known peer
address, one at a time -- useful for spot-checking each physical
uplink's real achievable rate independent of the scheduler's own
bonding decisions.

A `None` result for a direction means it timed out or the peer doesn't
support this feature yet (an older `mlvpnd` silently drops the
unrecognized packet type) -- not necessarily that the link is down.

Both this command and the tunnel-level one below print a `peer
version: ...` line at the end, and a warning if it doesn't match the
version you're running -- worth checking first if a result comes back
`None` on both sides at once, before assuming the test itself found a
problem. This comes from an independent, always-on wire exchange
between the two daemons (not the self-test's own round trip), so it's
still available even when the self-test result itself times out.

## Tunnel-level self-test

The link-level self-test above measures each physical link's own raw
UDP capacity, bypassing the TUN device, the outbound queue, and the
scheduler entirely. To instead measure the *whole bonded path* --
real traffic actually routed through the tunnel, exercising the same
queue and scheduler real Data traffic uses -- run:

```sh
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml --tunnel --peer-addr 10.200.0.2                # upload only, real TCP (default)
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml --tunnel --peer-addr 10.200.0.2 --duration 15   # longer stream
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml --tunnel --peer-addr 10.200.0.2 --bidirectional # also measure the reverse direction
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml --tunnel --peer-addr 10.200.0.2 --protocol udp  # raw UDP stream instead
```

`--peer-addr` is the peer's *tunnel-internal* IP (the `tunnel.address`
on the other end, without the `/<prefix>`), not a link's physical
address. Only the initiating side needs `[command]` enabled -- the
target's listener runs unconditionally, same as the link-level
self-test's own "any daemon can be the target" precedent, so nothing
needs to be enabled ahead of time on the far end.

**`--protocol tcp|udp` (default `tcp`).** TCP mode opens a real TCP
connection through the tunnel and reports genuine, kernel-measured
retransmit counts (`TCP_INFO`) alongside throughput -- real loss on
the path shows up directly as retransmits, the same signal `ss -ti`/
`iperf3` surface, instead of the old UDP self-test's blind spot (its
own active-loss probing is separate and doesn't reflect what a real
bulk TCP flow experiences). UDP mode is the original behavior:
raw UDP packets through the tunnel, with each direction's *sender*
reporting its own outbound-queue-drop delta instead of a retransmit
count (TCP has no outbound-queue concept in this design; UDP has no
retransmit concept).

**A real limitation of TCP mode, disclosed rather than silently wrong:**
only the **upload** leg's retransmit count is genuine. It's measured
locally, on the sender's own socket, right after it finishes sending --
the only way to get a reading that means anything (a receiver only
ever sends ACKs, never retransmits, so reading `TCP_INFO` on the
*receiving* side is structurally always 0 regardless of real loss).
For the **download** leg, the real sender is the peer, and there is no
wire path for the peer's own sender-side measurement to reach back to
the host that initiated the test -- so the download leg's retransmit
count is reported as explicitly unavailable rather than printing the
always-0 receiver-side reading a naive implementation would.

Sample output (TCP, the default):

```
running tunnel-level self-test against 10.200.0.2 (10s per direction, bidirectional, tcp) -- this will take a while...
upload: 148.3 Mbps
  real TCP goodput, retransmits: 12
download: 151.9 Mbps
  retransmits: unavailable for the download leg -- the peer is the real sender for this leg and has no way to report its own TCP_INFO reading back to us (see docs/monitoring.md)
peer version: 0.7.7 (matches this host)
```

Sample output (`--protocol udp`):

```
running tunnel-level self-test against 10.200.0.2 (10s per direction, bidirectional, udp) -- this will take a while...
upload: 148.3 Mbps
  our own outbound queue dropped 0 packets during this leg
download: 151.9 Mbps
  peer's outbound queue dropped 0 packets during this leg
peer version: 0.7.7 (matches this host)
```

In UDP mode, each direction reports its own outbound-queue drop count
alongside the achieved rate. A non-zero count on the *sender's own*
leg means the traffic never even made it out of that host's outbound
queue -- a locally-observable cause, not something that requires
guessing about what happened on the wire or at the peer. A clean queue
on both legs combined with real measured loss (compare against
`iperf3`, or the link-level self-test above) narrows the search to
somewhere between the outbound queue and the peer's own application --
the kernel UDP socket buffers, most likely (see `mlvpnd diag-dump`'s
kernel-level UDP diagnostics, below). In TCP mode, the upload leg's
real retransmit count is often a faster way to spot this same class of
loss directly, without needing a separate `iperf3` comparison.

## Diagnostic dump

Also over the command socket: capture a single text bundle of every
link's health, daemon/session state, and recent log lines -- meant to be
attached to a bug report, e.g. right after reproducing loss with
`iperf3` or `mlvpnd self-test` above:

```sh
mlvpnd diag-dump --config /etc/mlvpn/mlvpn.toml
mlvpnd diag-dump --config /etc/mlvpn/mlvpn.toml --output /tmp/before-upgrade.txt
```

Writes `mlvpn-diag-<tunnel>-<unix-seconds>.txt` in the current directory
(or `--output`'s path). The file has two parts: the daemon-visible
section (link state/score/rtt/jitter/loss/throughput, both this side's
own measurement and the peer's; session id/uptime/rekey count; outbound
queue depth and lifetime drops; the TUN device's kernel counters;
machine load/memory/uptime; and every log line currently held in the
daemon's log ring, not just a recent delta), and a kernel-diagnostics
section gathered by the CLI process itself, not the daemon: `nstat -az`
(filtered to UDP-related lines), `ss -lu -n -a`, and `/proc/net/udp`'s
own drop counters. Each of those degrades gracefully to a note in the
output if the tool isn't installed or the read fails, rather than
failing the whole dump.

**Automatic capture on trouble.** `[diagnostics] auto_dump_enabled = true`
has the daemon watch every link and write the same daemon-visible dump
section to disk when one is in trouble. There are three event classes,
strongest first:

- **OUTAGE** -- the link has been not-Up for longer than `outage_secs`
  (default 60 s).
- **FLAP** -- `flap_downs` (default 3, 0 disables) Up -> Down transitions
  within 10 minutes.
- **DEGRADED** -- over the last `window_secs` (default 300 s, needing at
  least `min_probes` = 100 probes in it) at least `degraded_open_misses`
  (default 8) probes were lost *and* the loss is at least
  `degraded_open_pct` (default 12%), and that holds for 30 s. The
  percentage is computed from raw probe outcomes, deliberately *not* the
  smoothed loss figure the Links tab shows: that one jumps past 50% on a
  single missed probe, so it would raise an alarm on every blip. A link's
  probe window is cleared whenever it comes Up and a degraded verdict is
  not given until the window is `warmup_secs` (default 120 s) old, so a
  restart or recovery can't alarm on its first few misses.

An event ends once the link has been calm (window loss under
`degraded_close_pct`, default 5%, and neither outage nor flap) for
`clear_secs` (default 300 s). There is one event per link at a time; an
event that gets worse (DEGRADED -> OUTAGE) is reported once more as an
escalation. Each dump's `trigger:` text carries a per-event ID, the
numbers behind the verdict, the event's peak loss and age, and how long
ago the previous event on that link ended.

```toml
[diagnostics]
auto_dump_enabled = true
degraded_open_pct = 12.0         # default
degraded_open_misses = 8         # default
degraded_close_pct = 5.0         # default
window_secs = 300                # default
min_probes = 100                 # default
clear_secs = 300                 # default
outage_secs = 60                 # default
warmup_secs = 120                # default
flap_downs = 3                   # default, 0 disables the flap trigger
cooldown_secs = 300              # minimum time between local dumps while one
                                  # event continues, default
degraded_ticket_gap_secs = 21600 # default: at most one DEGRADED ticket per
                                  # link per 6 hours
max_dump_files = 50              # oldest automatic dumps are deleted past this
dump_dir = "/var/log/mlvpn"      # default -- matches where most other
                                  # services log to, already writable
                                  # under the shipped systemd unit's
                                  # LogsDirectory=mlvpn
```

(`loss_threshold_pct` and `reminder_secs` from earlier betas no longer
exist; they are ignored if still present in a config file.)

Off by default -- this is the one setting that has the daemon write
arbitrary files to disk on its own initiative. A `dump_dir` other than
the default needs its own `ReadWritePaths=` added to the systemd unit
under the hardened `ProtectSystem=strict` (which makes everywhere else
on the filesystem read-only) -- create the directory and `chown` it to
the `mlvpn` user first. The automatic dump does
*not* include the kernel-diagnostics section (that needs shelling out to
external tools, which the daemon deliberately doesn't do on its own --
see `diag.rs`'s module doc comment); run `mlvpnd diag-dump` by hand
alongside it for the fuller picture while the loss condition is likely
still reproducible.

## Filing a dump as a support ticket

A dump can be sent to <https://software-support.jpps.us> as a real,
trackable ticket instead of being emailed around as a text file. Every
path here is opt-in and best-effort: a network failure never turns into
a harder failure than a warning, and the local file is always written
regardless of whether the submission succeeded.

**By hand.** Add `--submit` to any `diag-dump`, optionally with a note
describing what you were doing when the problem happened:

```sh
mlvpnd diag-dump --config /etc/mlvpn/mlvpn.toml --submit
mlvpnd diag-dump --config /etc/mlvpn/mlvpn.toml --submit \
  --message "carrier-b drops to ~40% loss whenever the LTE modem re-registers"
```

On success the command prints a ticket ID and a status-page URL. On
failure it warns on stderr and still exits 0 -- you keep the local file
either way.

**Automatically, on a loss event.** `[diagnostics] auto_submit_enabled
= true` submits each automatic loss-threshold dump in addition to
writing it to `dump_dir`. It has no effect unless `auto_dump_enabled`
is also on. Tickets are per event, not per dump: exactly one is
submitted when an event opens (plus one more if it escalates to a worse
class) and there are no reminders, so a two-hour outage files one ticket,
not one every few minutes. A second link that starts losing within 60 s
of the first rides on that first ticket (its own local dump is still
written). Re-opened events within 30 minutes of a link's last ticket, and
DEGRADED events within `degraded_ticket_gap_secs` of its last DEGRADED
ticket, are still dumped locally but not ticketed; the next ticket that
does go out says how many were held back. Ticket times and the previous
event are kept in a small file in `dump_dir`, so restarting the daemon
mid-outage doesn't file a duplicate.

**Automatically, on a panic.** `[diagnostics] crash_report_enabled =
true` installs a panic hook that submits the hostname and the tail of
the in-memory log ring if a task panics.

```toml
[diagnostics]
auto_dump_enabled = true
auto_submit_enabled = true      # off by default
crash_report_enabled = false    # off by default
```

Both automatic paths default to off deliberately, and separately from
`auto_dump_enabled`. Writing a local file is silent and inspectable at
your leisure; submitting one is an outbound network call the daemon
makes on its own initiative, carrying operational detail (link names,
bind interfaces, peer addresses and ports) off the machine. That needs
a deliberate yes, not an inherited one -- so enabling automatic dumps
does not enable automatic submission, and neither one enables crash
reporting. With `crash_report_enabled` off, a panic just prints its
backtrace as it always has.

## Tunnel MTU

As of 0.5.0 the tunnel MTU is not a fixed configured number. With
`tunnel.mtu` left unset (the recommendation), `mlvpnd` sizes the tunnel
from the physical MTUs it detects on the bonded links and keeps
re-checking while it runs, resizing the TUN device if a link's MTU
changes underneath it. Setting `tunnel.mtu` imposes a ceiling, which is
still clamped further down if the links can't carry it.

To see what the tunnel actually settled on:

```sh
ip -o link show mlvpn0        # the live MTU, including after any resize
journalctl -u mlvpn | grep -i mtu   # each resize, and any resize failure
```

A resize logs at info level when it succeeds. If it fails, the most
likely cause is a deployment that lacks `CAP_NET_ADMIN` at runtime --
`SIOCSIFMTU` needs it held at the moment of the call, not just at
startup. The shipped systemd unit grants it ambiently; if you run
`mlvpnd` yourself under some other supervisor, make sure it still has
that capability after startup. See ARCHITECTURE.md section 12.

A repeated failure is logged **once**, not on every 30-second check, so
a persistent problem doesn't bury the rest of the log (and the diagnostic
dump's captured log lines) under one line repeated forever. It warns
again only if the target MTU changes, and logs a recovery line -- with a
count of the warnings it suppressed -- once a resize succeeds again. So
a single "failed to resize tunnel MTU" line in the log may represent a
failure that has been ongoing for hours; check the live MTU with `ip -o
link show` above rather than assuming it was a one-off.

Note that the two ends pick their MTUs independently, with no
negotiation between them -- see the same section for what that means
when bonding hardware whose links differ substantially in MTU.

## Reading `outbound_queue_dropped_total`

Despite the name, this lifetime counter (also `dropped_lifetime` in `diag-dump`) counts every packet dropped on the local TX path: the outbound queue overflowing *and* the per-link TX queues all being full (or, under `primary_link_mode`/`follow_peer_primary`, the primary's queue being full, since there is no spill). It is local backpressure, not wire loss. Under a fast TCP sender such as BBR it normally tracks that sender's retransmit count; a rising value with zero UDP errors on the peer means the send path is the bottleneck, not the network.
