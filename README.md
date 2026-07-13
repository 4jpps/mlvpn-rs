# mlvpn-rs

Bonds multiple physical network links (fiber, DSL, LTE, ...) into one
resilient, Noise-encrypted VPN tunnel, load-balancing and failing over
between them based on continuously measured latency, jitter, loss and
throughput. A Rust rewrite of MLVPN, targeting Debian 13 and other
current systemd-based Linux distributions.

By [Jeff Parrish PC Services](https://www.jpps.us). License: MIT.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, threat model,
and known limitations/roadmap -- read that before relying on this for
anything real. This is a first implementation pass, not yet compiled in
the environment it was written in (no Rust toolchain was available); see
ARCHITECTURE.md §9 for details and what to expect when you first run
`cargo build`.

## Quick start

```sh
# Build
cargo build --release

# On each end: generate a keypair
./target/release/mlvpnd genkey --out /etc/mlvpn/private.key
# -> prints the public key; put the *other* side's public key into your config

# Configure
sudo mkdir -p /etc/mlvpn
sudo cp config/mlvpn.toml.example /etc/mlvpn/mlvpn.toml   # client side
# or config/mlvpn-server.toml.example on the server side
sudo $EDITOR /etc/mlvpn/mlvpn.toml
sudo chmod 600 /etc/mlvpn/mlvpn.toml   # mlvpnd refuses to start if this is group/other readable

# Run
sudo ./target/release/mlvpnd run --config /etc/mlvpn/mlvpn.toml
```

For a persistent, hardened install, see `systemd/mlvpn.service` (includes
one-time host setup instructions at the top of the file) and the Debian
packaging under `debian/` (`dpkg-buildpackage -us -uc -b`).

## Layout

```
src/
  main.rs        CLI (run / genkey), startup sequencing, privilege drop
  config.rs       TOML config + validation + permission checks
  crypto.rs       Noise_IK handshake, AEAD session, replay window
  protocol.rs     Wire frame header + probe payload encoding
  link.rs         Per-interface UDP socket + running stats (EWMA)
  monitor.rs      Probe RTT bookkeeping, up/down hysteresis, scoring
  scheduler.rs    Smooth weighted round robin link selection
  tunnel.rs       Ties it together: TUN <-> links, per-link actor tasks
  privilege.rs    Drop root -> unprivileged user, clear capabilities
config/          Example client/server TOML configs
systemd/         Hardened systemd unit
debian/          .deb packaging
```
# mlvpn-rs
