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
  client only dials the *first* `[[links]]` entry initially (see
  [Getting started](getting-started.md)); confirm that specific link is
  actually up and the hub's firewall allows its port, or reorder the
  config so a reliably-up link is first.
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
