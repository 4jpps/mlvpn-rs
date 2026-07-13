# mlvpn-rs

Bonds multiple physical network links (fiber, DSL, LTE, ...) into one
resilient, Noise-encrypted VPN tunnel, load-balancing and failing over
between them based on continuously measured latency, jitter, loss and
throughput. A Rust rewrite of MLVPN, targeting Debian 13 and other
current systemd-based Linux distributions.

By [Jeff Parrish PC Services](https://www.jpps.us), vibe-coded with
[Claude](https://claude.com/claude-code). License: MIT.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, threat model,
and known limitations/roadmap -- read that before relying on this for
anything real. See [CHANGELOG.md](CHANGELOG.md) for release history.

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

## Monitoring: mlvpn-tui

`mlvpnd` exposes live per-link stats over a local Unix socket (on by
default; see `[control]` in the example configs). `mlvpn-tui` connects to
it and renders a continuously-updating table with, for every bonded link:
state, the peer address it's talking to, this side's own measured RTT/
jitter/loss/throughput, *and* the peer's self-reported view of the same
link -- received over the tunnel itself, so one terminal on either end
shows the full picture without cross-referencing logs on both machines.

```sh
./target/release/mlvpn-tui                    # auto-detects the socket under /run/mlvpn
./target/release/mlvpn-tui --socket /run/mlvpn/mlvpn0.sock
```

Press `q` or `Esc` to quit. See ARCHITECTURE.md's "Monitoring" section for
the wire/IPC details (`ipc.rs`, `control.rs`, `PacketType::StatsShare`).

## Development

This targets Debian 13 / other current systemd Linux, so on Windows the
supported setup is [WSL2](https://learn.microsoft.com/windows/wsl/) with
a Debian distro, plus VS Code's
[WSL extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-wsl)
(`code .` from inside the WSL repo clone) and the
[rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
extension installed *in* that WSL window. Clone into WSL's native
filesystem (`~/mlvpn-rs`), not `/mnt/c/...` -- NTFS-backed paths break
`chmod`/git filemode handling that `cargo` and `git` both rely on.

```sh
cargo build --release
cargo test --release --lib
cargo clippy --all-targets
cargo fmt
```

GitHub Actions runs the same build+test on every push/PR
(`.github/workflows/ci.yml`). Pushing a tag like `v0.1.1` triggers
`.github/workflows/release-deb.yml`, which builds the `.deb` and attaches
it to a GitHub Release; see [CHANGELOG.md](CHANGELOG.md) before cutting
one to keep the version notes current.

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR, and
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
  bin/mlvpn-tui.rs  Terminal monitoring view (see "Monitoring" above)
config/          Example client/server TOML configs
systemd/         Hardened systemd unit
debian/          .deb packaging
.github/workflows/  CI (build+test) and release (.deb build/publish)
CHANGELOG.md     Release history
```
