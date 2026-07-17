# mlvpn-rs documentation

- [Installation](installation.md) -- `.deb`, `.rpm`, or build from source
- [Getting started](getting-started.md) -- worked example: bonding two
  ISPs to a single-uplink hub, keys, config, verifying the tunnel is up
- [Firewall](firewall.md) -- `mlvpnd firewall-setup`, or the manual
  commands per backend
- [Monitoring: mlvpn-tui](monitoring.md)
- [Troubleshooting](troubleshooting.md)
- [Performance tuning](performance-tuning.md) -- socket buffers,
  sysctls, and isolating a throughput bottleneck
- [Development](development.md) -- build/test/lint, CI, cutting a release
- [Platform roadmap: OPNsense / pfSense](platforms/opnsense-pfsense.md)
  -- scoping notes for a future FreeBSD-based port; not implemented yet
- [Platform roadmap: OpenWrt](platforms/openwrt.md) -- scoping notes
  for a future embedded-router port; not implemented yet
- [Roadmap: QUIC transport](roadmap.md) -- planning only, the one
  major feature not yet implemented

See also, at the repo root: [ARCHITECTURE.md](../ARCHITECTURE.md) (design
and threat model), [CHANGELOG.md](../CHANGELOG.md), [SECURITY.md](../SECURITY.md),
and [CONTRIBUTING.md](../CONTRIBUTING.md).
