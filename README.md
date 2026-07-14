# mlvpn-rs

Bonds multiple physical network links (fiber, DSL, LTE, ...) into one
resilient, Noise-encrypted VPN tunnel, load-balancing and failing over
between them based on continuously measured latency, jitter, loss and
throughput. A Rust rewrite of MLVPN, targeting current Debian/Ubuntu
(13+/24.04+) and Fedora/RHEL-family (Fedora, RHEL, Rocky, Alma 9+)
systemd-based distributions, on both amd64 and arm64.

By [Jeff Parrish PC Services](https://www.jpps.us), vibe-coded with
[Claude](https://claude.com/claude-code). License: MIT.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, threat model,
and known limitations/roadmap -- read that before relying on this for
anything real. See [CHANGELOG.md](CHANGELOG.md) for release history.

## Installation

### Option A: install a package (recommended)

Grab the package matching your distro and architecture from the
[latest GitHub Release](https://github.com/4jpps/mlvpn-rs/releases):

```sh
# Debian/Ubuntu
sudo apt install ./mlvpn_0.1.1-1_amd64.deb   # or the _arm64.deb build

# Fedora/RHEL/Rocky/Alma
sudo dnf install ./mlvpn-0.1.1-1.fc41.x86_64.rpm   # or the matching el9/aarch64 build
```

Installing via the package manager (not bare `dpkg -i`/`rpm -i`) so any
missing dependency resolves automatically. Either package installs
`mlvpnd`/`mlvpn-tui` to `/usr/bin` and the systemd unit, and
automatically creates everything the daemon needs to actually start: the
unprivileged `mlvpn` system user/group, and `/etc/mlvpn` (mode 0750,
`root:mlvpn`) -- via `debian/mlvpn.postinst` on Debian/Ubuntu, or the
`%pre`/`%post` scriptlets in `packaging/rpm/mlvpn.spec` on Fedora/RHEL.
Nothing further to set up here; the service itself is installed but not
yet started, since it still needs keys and a config -- **skip straight
to "First-time setup" below.**

One packaging difference worth knowing: on removal, the Debian package
can delete the `mlvpn` user/group (`purge`, an explicit opt-in); the RPM
never does, following Fedora packaging convention that system accounts
outlive a plain uninstall. Neither removes `/etc/mlvpn`'s contents.

### Option B: build from source

```sh
cargo build --release
sudo install -m0755 target/release/mlvpnd target/release/mlvpn-tui /usr/bin/
sudo groupadd --system mlvpn
sudo useradd --system --no-create-home --shell /usr/sbin/nologin -g mlvpn mlvpn
sudo mkdir -p /etc/mlvpn && sudo chown root:mlvpn /etc/mlvpn && sudo chmod 750 /etc/mlvpn
sudo cp systemd/mlvpn.service /etc/systemd/system/ && sudo systemctl daemon-reload
```

There's no post-install script here -- building from source means *you*
are responsible for everything Option A's package would otherwise do
automatically: creating the `mlvpn` user/group and `/etc/mlvpn` above.
This isn't optional even if you don't plan to use systemd:
`privilege::drop_privileges()` always drops to an account literally
named `mlvpn` after binding sockets and opening the TUN device, and
refuses to start if it doesn't exist yet. Skipping this step is the most
common first-run failure -- everything up through the privileged setup
succeeds, then the daemon exits with `privilege drop failed: user
'mlvpn' does not exist`.

## First-time setup: bonding two ISPs to a single-uplink hub

A concrete example most deployments map onto: a branch site with two
WAN links on different carriers (`branch`), bonded into one tunnel back
to a single-uplink hub (`hub`) -- a cloud VPS, colo box, or anything with
one stable public IP. `hub` runs in `server` mode (Noise_IK responder,
no `remote_addr` needed -- it learns each link's source address from the
authenticated handshake); `branch` runs in `client` mode (dials out on
both its links).

Do this on **both** ends first:

```sh
sudo mlvpnd genkey --out /etc/mlvpn/private.key
sudo chown mlvpn:mlvpn /etc/mlvpn/private.key
```

Run as `sudo`, not as the `mlvpn` user -- `/etc/mlvpn` is only
group-readable (`0750`), so `mlvpn` itself can't write into it; genkey
creates the file mode 0600 as root, then you hand ownership to `mlvpn`.
Note each side's printed public key; you'll paste each into the *other*
side's config.

**On `hub`** (single WAN, `eth0`, public IP `198.51.100.10` in this
example), write `/etc/mlvpn/mlvpn.toml`:

```toml
mode = "server"

[tunnel]
name = "mlvpn0"
address = "10.200.0.1/30"
mtu = 1400

[crypto]
private_key_file = "/etc/mlvpn/private.key"
peer_public_key = "<branch's public key, printed above>"

[[links]]
name = "carrier-a"
bind_interface = "eth0"   # one NIC serves both links -- see local_port below
local_port = 51000
weight = 1.0

[[links]]
name = "carrier-b"
bind_interface = "eth0"
local_port = 51001
weight = 1.0
```

**On `branch`** (two WAN NICs, one per carrier -- `eth0` and `eth1` in
this example), write `/etc/mlvpn/mlvpn.toml`:

```toml
mode = "client"

[tunnel]
name = "mlvpn0"
address = "10.200.0.2/30"
mtu = 1400

[crypto]
private_key_file = "/etc/mlvpn/private.key"
peer_public_key = "<hub's public key, printed above>"

[[links]]
name = "carrier-a"
bind_interface = "eth0"
remote_addr = "198.51.100.10:51000"
local_port = 51000
weight = 1.0

[[links]]
name = "carrier-b"
bind_interface = "eth1"
remote_addr = "198.51.100.10:51001"
local_port = 51001
weight = 1.0
```

`config/mlvpn.toml.example` and `config/mlvpn-server.toml.example`
(installed to `/usr/share/doc/mlvpn/` by the `.deb`) are the same
templates with `[scheduler]`/`[logging]`/`[control]` defaults spelled
out. Both example templates above put the *most reliable* link first --
`establish_session` only attempts the initial handshake over the first
`[[links]]` entry (see `tunnel.rs`'s module doc comment; racing the
handshake over every link is a roadmap item), so ordering matters at
startup even though all configured links carry data once the tunnel is
up.

Then, on **both** ends:

```sh
sudo chown mlvpn:mlvpn /etc/mlvpn/mlvpn.toml
sudo chmod 600 /etc/mlvpn/mlvpn.toml   # mlvpnd refuses to start otherwise
sudo systemctl enable --now mlvpn.service
```

(Built from source instead of the `.deb`? Run
`sudo mlvpnd run --config /etc/mlvpn/mlvpn.toml` directly, or install
your own copy of `systemd/mlvpn.service` first.)

## Verify the tunnel is up

```sh
sudo systemctl status mlvpn.service       # both ends: should be active (running)
sudo journalctl -u mlvpn -f                # watch for "tunnel session established"
ip addr show mlvpn0                        # should show the 10.200.0.x/30 address
ping -c3 10.200.0.1                        # from branch
ping -c3 10.200.0.2                        # from hub
```

Then check per-link state with `mlvpn-tui` (see the next section) -- both
`carrier-a` and `carrier-b` should show `up` on both ends, with nonzero
RTT and the peer's self-reported stats alongside your own.

## Firewall

Both ends need inbound UDP allowed on every configured `local_port`
(`51000`, `51001` above), from anywhere -- both client and server learn
the peer's address from the authenticated handshake, not a static
allowlist, so there's no source-IP restriction to configure even if
`branch`'s carrier IPs aren't static.

`mlvpnd firewall-setup` does this for you: it detects whichever of
`firewalld`, `ufw`, `nftables`, or `iptables` is actively managing the
host and opens exactly the ports your config's `[[links]]` declare.
Run it on **both** ends, after the config is in place:

```sh
sudo mlvpnd firewall-setup --config /etc/mlvpn/mlvpn.toml --dry-run   # review first
sudo mlvpnd firewall-setup --config /etc/mlvpn/mlvpn.toml            # then apply
```

`--dry-run` prints the exact commands it would run without touching
anything -- worth doing at least once before trusting it on a box you
care about, since this is the one command in this project that modifies
system security state rather than something the daemon owns itself. Add
`--remove` later to close the same ports, or `--backend nftables` (etc.)
to skip auto-detection. See `src/firewall.rs`'s module doc comment for
exactly how each backend is handled, including why nftables specifically
needs a bit more care than the others (multiple base chains can be
hooked at the same point with ambiguous evaluation order across them).

Prefer to do it yourself? The equivalent manual commands:

```sh
# nftables
sudo nft insert rule inet filter input position 0 udp dport { 51000, 51001 } accept
# ufw
sudo ufw allow 51000:51001/udp
# firewalld
sudo firewall-cmd --permanent --add-port={51000-51001}/udp && sudo firewall-cmd --reload
# iptables (legacy)
sudo iptables -I INPUT 1 -p udp --dport 51000:51001 -j ACCEPT
```

`branch` only needs outbound UDP on those same ports permitted per WAN
interface, which most default outbound-open rulesets already allow --
`firewall-setup` opens it inbound on both ends regardless, since a
strict default-deny host can't always be relied on to track UDP return
traffic as established.

## Troubleshooting

- **`privilege drop failed: user 'mlvpn' does not exist`** -- the
  one-time `groupadd`/`useradd` step above was skipped (only an issue
  when building from source; the `.deb` does this in `postinst`).
- **`interface 'X' not found on this system`** -- `bind_interface`
  doesn't match `ip link show` on that host, or (for something like a
  USB LTE modem) the interface hasn't enumerated yet at daemon start.
- **`config file ... has insecure permissions`** -- `chmod 600` the
  config and/or private key file; `mlvpnd` refuses to start otherwise.
- **Tunnel never establishes / stuck retrying the handshake** -- the
  client only dials the *first* `[[links]]` entry initially (see above);
  confirm that specific link is actually up and the hub's firewall
  allows its port, or reorder the config so a reliably-up link is first.
- **`mlvpn-tui: connection refused` / permission denied on the socket**
  -- the control socket is mode 0600 under `/run/mlvpn` (mode 0750),
  both owned by `mlvpn`. Run `sudo mlvpn-tui`, or add your own account
  to the `mlvpn` group to connect without sudo.
- **Links show `up` in `mlvpn-tui` but no traffic flows** -- double
  check both ends' `[tunnel] address` are in the same `/30` and that
  nothing upstream (firewall, NAT) is dropping the UDP frames on the
  configured ports.
- **`firewall-setup` says "no supported firewall backend detected"**
  -- none of `firewall-cmd`, `ufw`, `nft`, or `iptables` were found on
  `$PATH`; open the ports in whatever's actually managing this host's
  packet filtering (a container network policy, a cloud provider
  security group, etc. aren't things this tool can see or touch).
- **`firewall-setup must run as root`** -- re-run with `sudo`; it needs
  to inspect and modify live firewall state, which every backend here
  requires root for regardless of how `mlvpnd run` itself drops
  privileges.

## Monitoring: mlvpn-tui

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

GitHub Actions runs the same build+test on every push/PR, on both amd64
and arm64 runners (`.github/workflows/ci.yml`). Pushing a tag like
`v0.1.1` triggers `.github/workflows/release-deb.yml`, which builds a
`.deb` for each architecture and attaches both to a GitHub Release; see
[CHANGELOG.md](CHANGELOG.md) before cutting one to keep the version notes
current.

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
