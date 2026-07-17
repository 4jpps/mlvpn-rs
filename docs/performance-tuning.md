# Performance tuning

This covers what to check if a bonded tunnel's real throughput comes in
below what its underlying links should support -- most commonly noticed
as one direction (upload or download) being fine while the other plateaus
well below the expected combined bandwidth of the bonded links.

## 1. Kernel UDP socket buffers (the usual culprit)

`mlvpnd` moves every packet through a plain UDP socket per link. Linux's
default socket buffer size (`net.core.rmem_default`/`wmem_default`,
typically ~208KB) is sized for ordinary traffic, not a multi-gigabit
tunnel: the moment a link's bandwidth-delay product exceeds that buffer,
the kernel starts silently dropping incoming datagrams that don't fit,
before `mlvpnd` ever reads them. From inside the process this is
indistinguishable from ordinary network loss -- it doesn't show up as an
error, just as a throughput ceiling with otherwise-healthy RTT/jitter
stats.

As of v0.3.1, `mlvpnd` asks the kernel for an 8 MiB socket buffer on every
link (`link::raise_socket_buffers`), using `SO_RCVBUFFORCE`/
`SO_SNDBUFFORCE` (bypasses the sysctl ceiling entirely) when it still has
`CAP_NET_ADMIN` at bind time -- true for the initial startup bind under
either deployment model (see `docs/installation.md`), and true for a
runtime reconnect only under the "never be root" ambient-capabilities
model. If it can't force the value, it falls back to a plain
`SO_RCVBUF`/`SO_SNDBUF` request, which the kernel silently clamps to
whatever `net.core.rmem_max`/`wmem_max` currently allow.

**Check what actually got negotiated.** Run with `logging.level = "debug"`
briefly and look for `link socket buffer sizes negotiated` in the log --
compare `actual_recv_bytes`/`actual_send_bytes` against the `8388608`
(8 MiB) requested. A much smaller actual value, or an `initial handshake
failed`-style `info`-level warning about it, means the FORCE attempt
didn't have `CAP_NET_ADMIN` and the sysctl ceiling won.

**Raise the ceiling** on both ends of the tunnel (the VPS and every home
host) if so:

```sh
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.core.rmem_default=8388608
sudo sysctl -w net.core.wmem_default=8388608
```

Make it permanent in `/etc/sysctl.d/99-mlvpn.conf`:

```
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608
```

then `sudo sysctl --system` (or reboot) to apply.

**Confirm the diagnosis directly**, rather than just inferring it: while
running a throughput test, watch the receive-error counters on the
bottlenecked host --

```sh
watch -n1 'nstat -az UdpInErrors; netstat -su | grep -i "receive errors"'
```

A count that climbs during the test is the kernel dropping packets at
the socket layer, confirming this is the cause (as opposed to a
downstream ISP/modem/Wi-Fi issue, or something in `mlvpnd` itself).

## 2. Isolate which link (or which direction) is actually the bottleneck

Before assuming the tunnel software is at fault, narrow down where the
ceiling actually is:

- **Per-link isolation.** With `[command] enabled = true` in the config,
  disable every link but one (`mlvpnd set-link <link> disable`) and
  re-run the throughput test against just that one. Repeat per link.
  This tells you whether one specific link is the bottleneck (a modem,
  a bad cable, an ISP-side rate limit) versus something that only shows
  up once links are bonded together.
- **Per-direction.** Run `iperf3` in both directions explicitly
  (`iperf3 -c <server> -R` for reverse/download vs. the default
  upload direction) rather than trusting a single run's default
  direction -- the two directions terminate on different machines'
  receive paths, and it's entirely possible for only one side to be
  buffer-starved as in §1.
- **Check `bandwidth_cap_mbps`.** If a `[[links]]` entry was set up by
  copying `mlvpn.toml.example`/`mlvpn-server.toml.example` verbatim,
  confirm it doesn't still carry that example's illustrative cap (or
  any cap lower than the link's real speed) -- `mlvpnd`'s scheduler
  enforces this as a hard per-link ceiling
  (`scheduler.rs::swrr_pick_under_cap`), by design, not a bug. Leave it
  unset for a link that shouldn't be capped at all.

## 3. How the scheduler splits traffic across links

`scheduler.rs` uses smooth weighted round robin, weighting each Up link
by `monitor::score()` -- which factors in each link's measured
throughput, RTT, jitter, and loss. Two things worth knowing when
interpreting results:

- **Throughput is weighted by its square root, deliberately.** A 1.2
  Gbps link and a 300 Mbps link get roughly a 2:1 traffic split, not
  4:1 -- this keeps one very fast link from starving a slower-but-still-
  useful one of virtually all traffic. If you want a stronger bias
  toward a specific link regardless, raise its `weight` in the config
  (default `1.0`); `score()` multiplies by it directly (linearly), so
  doubling `weight` roughly doubles that link's share independent of
  the throughput term.
- **Throughput estimates start low and ramp up.** Until a link has
  either carried enough real traffic to build a stable
  `throughput_mbps` EWMA, or `scheduler.active_bandwidth_probing` is
  enabled (off by default -- see `mlvpn.toml.example`), a freshly-started
  link's score assumes a low placeholder bandwidth. A short throughput
  test run immediately after startup may under-use a fast link for its
  first few seconds; turning on active bandwidth probing gets the
  scheduler a real measurement much sooner instead of waiting on
  passive traffic to reveal it.
