# Troubleshooting

- **`privilege drop failed: user 'mlvpn' does not exist`** -- the
  one-time `groupadd`/`useradd` step was skipped (only an issue when
  building from source; a `.deb`/`.rpm` install does this automatically
  -- see [Installation](installation.md)).
- **`interface 'X' not found on this system`** -- `bind_interface`
  doesn't match `ip link show` on that host, or (for something like a
  USB LTE modem) the interface hasn't enumerated yet at daemon start.
- **`config file ... has insecure permissions`** -- `chmod 600` the
  config and/or private key file; `mlvpnd` refuses to start otherwise.
- **Tunnel never establishes / stuck retrying the handshake** -- the
  client broadcasts its initial handshake attempt on *every* configured
  link with a `remote_addr` and races them (see
  [Getting started](getting-started.md)), so this now means none of
  them got a reply: check the hub is reachable and its firewall allows
  each link's port, and check `mlvpnd`'s own log for
  `handshake attempt failed` to see which link(s), if any, are at least
  getting a malformed or unexpected reply back (as opposed to nothing at
  all).
- **`mlvpn-tui: connection refused` / permission denied on the socket**
  -- see [Monitoring](monitoring.md) -- the control socket is mode 0600
  under `/run/mlvpn` (mode 0750), both owned by `mlvpn`. Run
  `sudo mlvpn-tui`, or add your own account to the `mlvpn` group.
- **Links show `up` in `mlvpn-tui` but no traffic flows** -- double
  check both ends' `[tunnel] address` are in the same `/30` and that
  nothing upstream (firewall, NAT) is dropping the UDP frames on the
  configured ports.
- **`firewall-setup` says "no supported firewall backend detected"**
  -- none of `firewall-cmd`, `ufw`, `nft`, or `iptables` were found on
  `$PATH`; open the ports in whatever's actually managing this host's
  packet filtering (a container network policy, a cloud provider
  security group, etc. aren't things this tool can see or touch). See
  [Firewall](firewall.md) for the manual commands per backend.
- **`firewall-setup must run as root`** -- re-run with `sudo`; it needs
  to inspect and modify live firewall state, which every backend it
  supports requires root for, regardless of how `mlvpnd run` itself
  drops privileges.
- **Throughput comes in well below the bonded links' expected combined
  speed** (especially if only one direction is affected) -- almost
  always the kernel's default UDP socket buffer size silently dropping
  packets under a fast link's real bandwidth-delay product. See
  [Performance tuning](performance-tuning.md).
- **A link goes down after its interface is unplugged/replugged (a USB
  LTE modem, typically) and never comes back, logging "cannot
  reconnect this link's socket: ... missing required capability"
  repeatedly** -- expected under the "start as root, drop after setup"
  privilege model (see `privilege.rs`): it explicitly clears every
  capability after startup, so the daemon can no longer re-bind that
  link's socket once the interface reappears with a new ifindex. Switch
  to the "never be root" model instead (the shipped
  `systemd/mlvpn.service` default: `AmbientCapabilities=CAP_NET_ADMIN
  CAP_NET_RAW`), which keeps `CAP_NET_RAW` for the process's whole
  life and lets this self-heal on its own -- see `ARCHITECTURE.md` §6
  and §8. A link recovering successfully logs "link socket
  reconnected" instead.
