# Monitoring and runtime control

`mlvpnd` exposes live per-link and daemon/host health over a local Unix
socket (on by default; see `[control]` in the example configs).
`mlvpn-tui` connects to it and renders a continuously-updating, tabbed
view:

```sh
mlvpn-tui                    # auto-detects the socket under /run/mlvpn
mlvpn-tui --socket /run/mlvpn/mlvpn0.sock
```

- **Links** -- every bonded link's state, current SWRR score, how long
  it's held that state, cumulative tx/rx byte totals, and both this
  side's own measured RTT/jitter/loss/throughput *and* the peer's
  self-reported view of the same link (received over the tunnel
  itself, so one terminal on either end shows the full picture without
  cross-referencing logs on both machines).
- **Daemon** -- session id/uptime/rekey count, the outbound queue's
  current depth and lifetime drop count, the TUN interface's own
  kernel-tracked byte/error/drop counters, and machine-wide load
  average/memory/uptime.
- **Logs** -- a live tail of the daemon's own log output (INFO and
  above, streamed incrementally over the same control socket), so an
  operator doesn't need a separate `journalctl -f` window open
  alongside `mlvpn-tui`.

Switch tabs with `Tab`/`Shift+Tab` or `1`/`2`/`3`. On the Logs tab,
`Up`/`Down`/`PageUp`/`PageDown` scroll back through history; scrolling
back to the newest line (or never having scrolled at all) keeps the
view pinned to the tail, same as `tail -f`. Press `q` or `Esc` to quit
from any tab. See [ARCHITECTURE.md](../ARCHITECTURE.md)'s "Monitoring"
section for the wire/IPC details (`ipc.rs`, `control.rs`,
`PacketType::StatsShare`, `logbuf.rs`).

The control socket is mode 0600 under `/run/mlvpn` (mode 0750), both
owned by `mlvpn`. Run `sudo mlvpn-tui`, or add your own account to the
`mlvpn` group to connect without `sudo`.

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
