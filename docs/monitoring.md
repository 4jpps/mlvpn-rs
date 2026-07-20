# Monitoring and runtime control

`mlvpnd` exposes live per-link and daemon/host health over a local Unix
socket (on by default; see `[control]` in the example configs).
`mlvpn-tui` connects to it and renders a continuously-updating, tabbed
view:

```sh
mlvpn-tui                    # auto-detects the socket under /run/mlvpn
mlvpn-tui --socket /run/mlvpn/mlvpn0.sock
```

- **Overview** -- the default tab at startup: condensed panes from
  every other tab stacked into one screen (the Links table, a 2x2 grid
  of the four Daemon panels, and a following Logs tail) so the whole
  picture is visible -- and screenshot-friendly -- without switching
  tabs.
- **Links** -- every bonded link's state, current SWRR score (colored
  by how much traffic it's actually carrying), how long it's held that
  state, cumulative tx/rx byte totals, and both this side's own
  measured RTT/jitter/loss/throughput *and* the peer's self-reported
  view of the same link (received over the tunnel itself, so one
  terminal on either end shows the full picture without
  cross-referencing logs on both machines) -- the loss percentage in
  each is colored by severity.
- **Daemon** -- session id/uptime/rekey count, the outbound queue's
  current depth and lifetime drop count, the TUN interface's own
  kernel-tracked byte/error/drop counters, and machine-wide load
  average/memory/uptime (memory-used percentage colored by severity).
- **Logs** -- a live tail of the daemon's own log output (INFO and
  above, streamed incrementally over the same control socket), so an
  operator doesn't need a separate `journalctl -f` window open
  alongside `mlvpn-tui`.

Switch tabs with `Tab`/`Shift+Tab` or `1`/`2`/`3`/`4`. On the Logs tab,
`Up`/`Down`/`PageUp`/`PageDown` scroll back through history; scrolling
back to the newest line (or never having scrolled at all) keeps the
view pinned to the tail, same as `tail -f`. Press `q` or `Esc` to quit
from any tab. See [ARCHITECTURE.md](../ARCHITECTURE.md)'s "Monitoring"
section for the wire/IPC details (`ipc.rs`, `control.rs`,
`PacketType::StatsShare`, `logbuf.rs`).

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
  (default Overview tab), which keeps watching `/run/mlvpn` in the
  background and starts populating live the moment the socket appears
  -- no restart needed.
- **Not running**: offers to start it (`systemctl start mlvpn.service`,
  via `sudo` if not already root) right there at the prompt, before
  switching to full-screen mode.
- **Can't tell** (no `systemctl`, non-systemd host, or `mlvpnd` run some
  other way): falls back to the original plain error asking you to pass
  `--socket` explicitly or check `mlvpnd` yourself.

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
real IP/UDP traffic actually routed through the tunnel, exercising the
same queue and scheduler real Data traffic uses -- run:

```sh
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml --tunnel --peer-addr 10.200.0.2                # upload only
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml --tunnel --peer-addr 10.200.0.2 --duration 15   # longer stream
mlvpnd self-test --config /etc/mlvpn/mlvpn.toml --tunnel --peer-addr 10.200.0.2 --bidirectional # also measure the reverse direction
```

`--peer-addr` is the peer's *tunnel-internal* IP (the `tunnel.address`
on the other end, without the `/<prefix>`), not a link's physical
address. Only the initiating side needs `[command]` enabled -- the
target's listener runs unconditionally, same as the link-level
self-test's own "any daemon can be the target" precedent, so nothing
needs to be enabled ahead of time on the far end.

Sample output:

```
running tunnel-level self-test against 10.200.0.2 (10s per direction, bidirectional) -- this will take a while...
upload: 148.3 Mbps
  our own outbound queue dropped 0 packets during this leg
download: 151.9 Mbps
  peer's outbound queue dropped 0 packets during this leg
peer version: 0.4.6 (matches this host)
```

Each direction reports its own outbound-queue drop count alongside the
achieved rate. A non-zero count on the *sender's own* leg means the
traffic never even made it out of that host's outbound queue -- a
locally-observable cause, not something that requires guessing about
what happened on the wire or at the peer. A clean queue on both legs
combined with real measured loss (compare against `iperf3`, or the
link-level self-test above) narrows the search to somewhere between
the outbound queue and the peer's own application -- the kernel UDP
socket buffers, most likely (see `mlvpnd diag-dump`'s kernel-level UDP
diagnostics, below).

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

**Automatic capture on loss.** `[diagnostics] auto_dump_enabled = true`
has the daemon watch its own locally-measured per-link loss and write
the same daemon-visible dump section to disk on its own the moment a
link's loss crosses `loss_threshold_pct` (default 10%) -- catching a
transient loss event's evidence even if no one is watching
`mlvpn-tui` at the exact moment it happens:

```toml
[diagnostics]
auto_dump_enabled = true
loss_threshold_pct = 10.0        # default
cooldown_secs = 300              # minimum time between auto dumps, default
dump_dir = "/var/log/mlvpn"      # default -- matches where most other
                                  # services log to, already writable
                                  # under the shipped systemd unit's
                                  # LogsDirectory=mlvpn
```

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
