<p align="center">
  <img src="docs/icon.svg" alt="mlvpn-rs" width="96">
</p>

# mlvpn-rs

Primary home: https://gitlab.jpps.us/jpps/mlvpn-rs (issues, merge requests and releases live there). The GitHub copy at https://github.com/4jpps/mlvpn-rs is a read-only mirror, updated automatically from GitLab.

**In plain terms:** if a site has two or more separate internet
connections -- a fiber line plus a cellular modem, two different ISPs,
whatever -- mlvpn-rs combines them into one connection that's both
faster (it uses all of them at once, not just one as backup) and more
reliable (if one connection slows down or drops out, traffic
automatically shifts to the others, with no manual intervention;
connections you already have open normally carry on, perhaps with a
brief pause while it shifts). It runs as a background service on two Linux
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

By [Jeff Parrish PC Services LLC](https://www.jpps.us), vibe-coded with
[Claude](https://claude.com/claude-code). License:
[AGPL-3.0-only](LICENSE) -- if you run a modified version as a network
service, you must make your changes' source available to its users; see
`LICENSE` and [CONTRIBUTING.md](CONTRIBUTING.md#licensing) for why this
version specifically.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, threat model,
and known limitations/roadmap -- read that before relying on this for
anything real. See [CHANGELOG.md](CHANGELOG.md) for release history.

## Quick start

Do these steps on **both** machines (the "client" at the site with the
multiple connections, and the "server" with one stable public address).
[Getting started](docs/getting-started.md) walks through a full worked
example with the config filled in.

1. **Install the package.** Grab the one matching your distro and
   architecture from the
   [latest release](https://gitlab.jpps.us/jpps/mlvpn-rs/-/releases)
   (replace `<version>` with the number on the release page, e.g. the
   `0.7.7` in `mlvpn_0.7.7-1_amd64.deb`). It creates the unprivileged
   `mlvpn` user and `/etc/mlvpn` for you.

   ```sh
   # Debian/Ubuntu
   sudo apt install ./mlvpn_<version>-1_amd64.deb

   # Fedora/RHEL/Rocky/Alma
   sudo dnf install ./mlvpn-<version>-1.x86_64.rpm
   ```

2. **Generate a key for each link** (one per link name, on both ends),
   and note the public key each command prints.

   ```sh
   sudo mlvpnd genkey --link fiber --out /etc/mlvpn/fiber.key
   sudo chown mlvpn:mlvpn /etc/mlvpn/fiber.key
   ```

3. **Copy the example config** (`mlvpn.toml.example` on the client,
   `mlvpn-server.toml.example` on the server), then edit it: your link
   names, the network interface for each link, the server's address, and
   the *other* end's public keys.

   ```sh
   sudo cp /usr/share/doc/mlvpn/mlvpn.toml.example /etc/mlvpn/mlvpn.toml
   sudo chown mlvpn:mlvpn /etc/mlvpn/mlvpn.toml
   sudo chmod 600 /etc/mlvpn/mlvpn.toml
   ```

4. **Open the firewall** for the link ports: `sudo mlvpnd firewall-setup --dry-run`
   shows what it would do. See [Firewall](docs/firewall.md).

5. **Start it** on both ends, then check that every link shows `up`:

   ```sh
   sudo systemctl enable --now mlvpn.service
   sudo mlvpn-tui
   ```

## Running a VPN through the tunnel

Anything can run over the tunnel, including another VPN. The tunnel's
packet size (MTU) is set automatically from your links, typically a bit
under 1400 bytes, and TCP traffic is adjusted to fit. Check the current
value with `ip link show mlvpn0`.

- **VPNs that run over TCP** (OpenVPN in TCP mode, SSTP) need no changes.
- **VPNs that run over UDP** (WireGuard, OpenVPN in UDP mode) work, but
  their default packet size is larger than the tunnel can carry in one
  piece, so big packets get split in two. That costs speed, and a VPN
  that forbids splitting will lose those packets. Set the VPN's own MTU
  to **1280**:
  - WireGuard: add `MTU = 1280` to its `[Interface]` section.
  - OpenVPN: add `tun-mtu 1280` and `mssfix 1240` to its config.

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
  logbuf.rs       In-memory log ring + tracing layer feeding mlvpn-tui's Debug view
  firewall.rs     mlvpnd firewall-setup: detects/drives firewalld, ufw,
                  nftables, iptables
  bin/mlvpn-tui/    Terminal monitoring view: health banner + Overview/Links/
                    Traffic/Reliability/System/Debug views
                  (see docs/monitoring.md)
  bin/mlvpn-web/    Optional read-only loopback HTTP telemetry API
                    (http.rs, api.rs; see docs/monitoring.md)
config/          Example client/server TOML configs
systemd/         Hardened systemd units (mlvpn.service, optional mlvpn-web.service)
debian/          .deb packaging
packaging/rpm/   .rpm packaging (Fedora/RHEL-family)
docs/            Full documentation -- see docs/README.md
.github/workflows/  CI (build+test) and release (.deb + .rpm build/publish)
CHANGELOG.md     Release history
```
