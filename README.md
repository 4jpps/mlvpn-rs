# mlvpn-rs

**In plain terms:** if a site has two or more separate internet
connections -- a fiber line plus a cellular modem, two different ISPs,
whatever -- mlvpn-rs combines them into one connection that's both
faster (it uses all of them at once, not just one as backup) and more
reliable (if one connection slows down or drops out, traffic
automatically shifts to the others, with no manual intervention and
no dropped sessions). It runs as a background service on two Linux
machines, one at each end of the link you want to bond, and everything
in between is encrypted.

More precisely: mlvpn-rs bonds multiple physical network links
(fiber, DSL, LTE, ...) into one resilient, Noise-encrypted VPN tunnel,
load-balancing and failing over between them based on continuously
measured latency, jitter, loss and throughput. Dual-stack (IPv4 +
IPv6) tunnel interface, with adaptive MTU detection and TCP MSS
clamping so real link hardware -- not a hand-tuned config value --
decides sizing. Targets current Debian/Ubuntu (13+/24.04+) and
Fedora/RHEL-family (Fedora, RHEL, Rocky, Alma 9+) systemd-based
distributions, on both amd64 and arm64.

A Rust rewrite of [MLVPN](https://github.com/zehome/MLVPN) by Laurent
Coustet, which the core bonding/monitoring/failover idea is credited
to -- no code is shared between the two. See
[ARCHITECTURE.md](ARCHITECTURE.md#relationship-to-the-original-mlvpn)
for what specifically changed and why (binds to a network interface
instead of an IP address so it survives DHCP/roaming changes, a
memory-safe implementation, a modern authenticated-key-exchange
handshake instead of a shared password, and more).

By [Jeff Parrish PC Services](https://www.jpps.us), vibe-coded with
[Claude](https://claude.com/claude-code). License:
[AGPL-3.0-only](LICENSE) -- if you run a modified version as a network
service, you must make your changes' source available to its users; see
`LICENSE` and [CONTRIBUTING.md](CONTRIBUTING.md#licensing) for why this
version specifically.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, threat model,
and known limitations/roadmap -- read that before relying on this for
anything real. See [CHANGELOG.md](CHANGELOG.md) for release history.

## Quick start

```sh
# Debian/Ubuntu
sudo apt install ./mlvpn_0.4.5-1_amd64.deb

# Fedora/RHEL/Rocky/Alma
sudo dnf install ./mlvpn-0.4.5-1.fc41.x86_64.rpm
```

Grab the package matching your distro/architecture from the
[latest release](https://github.com/4jpps/mlvpn-rs/releases). Both
package types automatically create the unprivileged `mlvpn` user and
`/etc/mlvpn` for you.

## Documentation

Full setup lives in **[docs/](docs/)**, not this README:

- [Installation](docs/installation.md) -- package or build from source
- [Getting started](docs/getting-started.md) -- worked example: bonding
  two ISPs to a single-uplink hub, keys, config, verifying it's up
- [Firewall](docs/firewall.md) -- `mlvpnd firewall-setup`, or manual
- [Monitoring: mlvpn-tui](docs/monitoring.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Performance tuning](docs/performance-tuning.md) -- socket buffers,
  sysctls, and isolating a throughput bottleneck
- [Development](docs/development.md) -- build/test/lint, CI, releases
- [Platform roadmap: OPNsense / pfSense](docs/platforms/opnsense-pfsense.md)
  -- scoping notes for a future FreeBSD-based port (not implemented)
- [Platform roadmap: OpenWrt](docs/platforms/openwrt.md) -- scoping
  notes for a future embedded-router port (not implemented)

See also [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR, and
[SECURITY.md](SECURITY.md) if you've found a vulnerability rather than a
regular bug -- please don't file those as public issues.

## Layout

```
src/
  main.rs        CLI (run / genkey / set-link), startup sequencing, privilege drop
  lib.rs          Library crate shared by mlvpnd and mlvpn-tui
  config.rs       TOML config + validation + permission checks
  crypto.rs       Noise_IK handshake, AEAD session, replay window
  protocol.rs     Wire frame header, probe payload, stats-share payload
  link.rs         Per-interface UDP socket + running stats (EWMA)
  mss.rs          TCP MSS clamping for packets transiting the TUN device
  monitor.rs      Probe RTT bookkeeping, up/down hysteresis, scoring
  scheduler.rs    Smooth weighted round robin link selection
  tunnel.rs       Ties it together: TUN <-> links, per-link actor tasks
  privilege.rs    Drop root -> unprivileged user, clear capabilities
  peerstats.rs    Table of the peer's most recently reported link stats
  ipc.rs          JSON schema for the monitoring/command sockets
  control.rs      Unix-socket servers: streams ipc::Snapshot to mlvpn-tui,
                  and (opt-in) accepts runtime link-control commands
  sysfs_net.rs    TUN interface's own kernel byte/error/drop counters
  procstats.rs    Machine-wide load/memory/uptime from /proc
  logbuf.rs       In-memory log ring + tracing layer feeding mlvpn-tui's Logs tab
  firewall.rs     mlvpnd firewall-setup: detects/drives firewalld, ufw,
                  nftables, iptables
  bin/mlvpn-tui.rs  Terminal monitoring view: Links/Daemon/Logs tabs
                  (see docs/monitoring.md)
config/          Example client/server TOML configs
systemd/         Hardened systemd unit
debian/          .deb packaging
packaging/rpm/   .rpm packaging (Fedora/RHEL-family)
docs/            Full documentation -- see docs/README.md
.github/workflows/  CI (build+test) and release (.deb + .rpm build/publish)
CHANGELOG.md     Release history
```
