# Firewall

Both ends need inbound UDP allowed on every configured `local_port`
(`51000`, `51001` in the [getting started](getting-started.md) example),
from anywhere -- both client and server learn the peer's address from
the authenticated handshake, not a static allowlist, so there's no
source-IP restriction to configure even if the client side's carrier IPs
aren't static.

## `mlvpnd firewall-setup`

Does this for you: it detects whichever of `firewalld`, `ufw`,
`nftables`, or `iptables` is actively managing the host and opens
exactly the ports your config's `[[links]]` declare. Run it on **both**
ends, after the config is in place:

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

## Doing it yourself

Prefer to do it yourself, or running a backend `firewall-setup` doesn't
support? The equivalent manual commands:

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

The client side only strictly needs outbound UDP on those same ports
permitted per WAN interface, which most default outbound-open rulesets
already allow -- `firewall-setup` opens it inbound on both ends
regardless, since a strict default-deny host can't always be relied on
to track UDP return traffic as established.
