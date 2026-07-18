# Installation

## Option A: install a package (recommended)

Grab the package matching your distro and architecture from the
[latest GitHub Release](https://github.com/4jpps/mlvpn-rs/releases):

```sh
# Debian/Ubuntu
sudo apt install ./mlvpn_0.3.5-1_amd64.deb   # or the _arm64.deb build

# Fedora/RHEL/Rocky/Alma
sudo dnf install ./mlvpn-0.3.5-1.fc41.x86_64.rpm   # or the matching el9/aarch64 build
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
to [Getting started](getting-started.md).**

One packaging difference worth knowing: on removal, the Debian package
can delete the `mlvpn` user/group (`purge`, an explicit opt-in); the RPM
never does, following Fedora packaging convention that system accounts
outlive a plain uninstall. Neither removes `/etc/mlvpn`'s contents.

## Option B: build from source

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

Next: [Getting started](getting-started.md).
