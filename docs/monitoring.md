# Monitoring and runtime control

`mlvpnd` exposes live per-link stats over a local Unix socket (on by
default; see `[control]` in the example configs). `mlvpn-tui` connects to
it and renders a continuously-updating table with, for every bonded link:
state, the peer address it's talking to, this side's own measured RTT/
jitter/loss/throughput, *and* the peer's self-reported view of the same
link -- received over the tunnel itself, so one terminal on either end
shows the full picture without cross-referencing logs on both machines.

```sh
mlvpn-tui                    # auto-detects the socket under /run/mlvpn
mlvpn-tui --socket /run/mlvpn/mlvpn0.sock
```

Press `q` or `Esc` to quit. See [ARCHITECTURE.md](../ARCHITECTURE.md)'s
"Monitoring" section for the wire/IPC details (`ipc.rs`, `control.rs`,
`PacketType::StatsShare`).

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
