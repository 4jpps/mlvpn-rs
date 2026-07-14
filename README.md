# mlvpn-rs

Bonds multiple physical network links (fiber, DSL, LTE, ...) into one
resilient, Noise-encrypted VPN tunnel, load-balancing and failing over
between them based on continuously measured latency, jitter, loss and
throughput. A Rust rewrite of MLVPN, targeting current Debian/Ubuntu
(13+/24.04+) and Fedora/RHEL-family (Fedora, RHEL, Rocky, Alma 9+)
systemd-based distributions, on both amd64 and arm64.

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
sudo apt install ./mlvpn_0.1.1-1_amd64.deb

# Fedora/RHEL/Rocky/Alma
sudo dnf install ./mlvpn-0.1.1-1.fc41.x86_64.rpm
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
- [Development](docs/development.md) -- build/test/lint, CI, releases
- [Platform roadmap: OPNsense / pfSense](docs/platforms/opnsense-pfsense.md)
  -- scoping notes for a future FreeBSD-based port (not implemented)

See also [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR, and
[SECURITY.md](SECURITY.md) if you've found a vulnerability rather than a
regular bug -- please don't file those as public issues.

## Layout

```
src/
  main.rs        CLI (run / genkey), startup sequencing, privilege drop
  lib.rs          Library crate shared by mlvpnd and mlvpn-tui
  config.rs       TOML config + validation + permission checks
  crypto.rs       Noise_IK handshake, AEAD session, replay window
  protocol.rs     Wire frame header, probe payload, stats-share payload
  link.rs         Per-interface UDP socket + running stats (EWMA)
  monitor.rs      Probe RTT bookkeeping, up/down hysteresis, scoring
  scheduler.rs    Smooth weighted round robin link selection
  tunnel.rs       Ties it together: TUN <-> links, per-link actor tasks
  privilege.rs    Drop root -> unprivileged user, clear capabilities
  peerstats.rs    Table of the peer's most recently reported link stats
  ipc.rs          JSON schema for the monitoring control socket
  control.rs      Unix-socket server that streams ipc::Snapshot to mlvpn-tui
  firewall.rs     mlvpnd firewall-setup: detects/drives firewalld, ufw,
                  nftables, iptables
  bin/mlvpn-tui.rs  Terminal monitoring view (see docs/monitoring.md)
config/          Example client/server TOML configs
systemd/         Hardened systemd unit
debian/          .deb packaging
packaging/rpm/   .rpm packaging (Fedora/RHEL-family)
docs/            Full documentation -- see docs/README.md
.github/workflows/  CI (build+test) and release (.deb + .rpm build/publish)
CHANGELOG.md     Release history
```
