# Monitoring: mlvpn-tui

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
