# Getting started: bonding two ISPs to a single-uplink hub

A concrete example most deployments map onto: a branch site with two
WAN links on different carriers (`branch`), bonded into one tunnel back
to a single-uplink hub (`hub`) -- a cloud VPS, colo box, or anything with
one stable public IP. `hub` runs in `server` mode (Noise_IK responder,
no `remote_addr` needed -- it learns each link's source address from the
authenticated handshake); `branch` runs in `client` mode (dials out on
both its links).

Assumes you've already completed [Installation](installation.md) on
both ends.

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

(Built from source instead of a package? Run
`sudo mlvpnd run --config /etc/mlvpn/mlvpn.toml` directly, or install
your own copy of `systemd/mlvpn.service` first.)

Before traffic will actually flow, both ends also need the right ports
open -- see [Firewall](firewall.md), ideally via
`mlvpnd firewall-setup --dry-run` right now while you're already here.

## Verify the tunnel is up

```sh
sudo systemctl status mlvpn.service       # both ends: should be active (running)
sudo journalctl -u mlvpn -f                # watch for "tunnel session established"
ip addr show mlvpn0                        # should show the 10.200.0.x/30 address
ping -c3 10.200.0.1                        # from branch
ping -c3 10.200.0.2                        # from hub
```

Then check per-link state with [`mlvpn-tui`](monitoring.md) -- both
`carrier-a` and `carrier-b` should show `up` on both ends, with nonzero
RTT and the peer's self-reported stats alongside your own.

Something not working? See [Troubleshooting](troubleshooting.md).
