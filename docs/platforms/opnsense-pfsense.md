# Platform roadmap: OPNsense / pfSense

**Status: scoping only -- nothing in this document is implemented.** No
code has changed for this yet; this is a gap analysis and a proposed
plan, written so a future session (or contributor) can pick it up
without re-deriving all of this from scratch. See
[`openwrt.md`](openwrt.md) for the equivalent scoping document covering
that platform -- together, these three are the major router/firewall
platforms this project is likely to target beyond generic
Debian/Fedora-family Linux.

## Why this is a different kind of port than the Linux packaging work

Everything shipped so far (`.deb`, `.rpm`, arm64) targets the same
underlying platform: Linux, glibc, systemd. Different init system,
different package manager, same kernel APIs underneath. OPNsense and
pfSense are both FreeBSD-based firewall distributions, not Linux --
this is a port to a different kernel and userland, not just another
package format. Several pieces of the current implementation are
Linux-specific by name, not by accident, and need a real BSD
equivalent, not just a recompile.

## Target versions (as of mid-2026)

- **OPNsense**: current stable series is **26.1** ("Witty Woodpecker"),
  based on **FreeBSD 14.x**. OPNsense ships two major releases a year
  (January/July); **26.7**, bringing **FreeBSD 15.1**, lands around the
  same time this document was written, so treat FreeBSD 14.x and 15.x
  as both realistically in scope. ([26.1 release notes](https://docs.opnsense.org/releases/CE_26.1.html))
- **pfSense CE**: current stable is **2.8.1** (released September
  2025), based on **FreeBSD 14.x**. ([Netgate: pfSense CE 2.8.1](https://www.netgate.com/blog/netgate-releases-pfsense-community-edition-version-2.8.1))
  Note Netgate's commercial **pfSense Plus** now uses a separate,
  date-based version scheme (e.g. 26.03) with its own FreeBSD baseline
  -- out of scope here; **pfSense CE only**, per your request.

Re-check these before starting real work -- both projects release on a
predictable but ongoing cadence, and this document will age.

## Architecture gaps: what actually needs to change

### 1. TUN device creation -- likely fine as-is

`main.rs::open_tun` uses the `tun-rs` crate (already a dependency,
`Cargo.toml`'s `tun-rs = { version = "2", features = ["async"] }`).
tun-rs advertises TUN support on Linux, macOS, **FreeBSD**, Windows,
Android, and iOS with one API, so this layer probably needs little to
no change. Needs verification on an actual FreeBSD 14 box (jail vs.
bare metal permissions for `/dev/tun*` can differ from Linux
`/dev/net/tun` in ways only real testing will surface), but this is the
best-case piece of the port.

### 2. Per-link interface binding -- needs a real redesign

`link.rs::Link::bind` binds each link's UDP socket to a specific
physical interface via `SO_BINDTODEVICE`:

```rust
#[cfg(target_os = "linux")]
{
    socket.bind_device(Some(config.bind_interface.as_bytes()))...
}
```

already gated to Linux only -- on any other OS today, this block is
simply skipped, and only the `local_addr`/`local_port` bind still runs.
`SO_BINDTODEVICE` doesn't exist on FreeBSD. The practical fallback that
already exists in the config schema is `LinkConfig::local_addr`: bind
each link's socket to that WAN interface's specific IP address instead
of the interface name. That covers the common case (each WAN interface
already has its own address), but loses the stronger guarantee the
current doc comment makes -- "traffic for this link actually egresses
the intended physical path *regardless of routing table*" -- since
binding to a local IP alone doesn't force FreeBSD's routing table to
egress out the matching interface if a route to the destination exists
elsewhere. Two paths forward, both real work:

- **Minimum viable**: require `local_addr` on FreeBSD (make it
  mandatory there, still optional on Linux), document the weaker
  guarantee, ship it.
- **Closer to feature parity**: use FreeBSD's per-socket routing table
  (`setfib(2)`/`SO_SETFIB`) with one fib per link, which is the
  standard multi-WAN technique on FreeBSD-based routers (pfSense's own
  multi-WAN support leans on this). More correct, meaningfully more
  work, and needs its own interaction with each firewall's existing
  fib/routing setup rather than something this daemon can own in
  isolation.

### 3. Privilege dropping -- mostly portable, one Linux-only piece

`privilege.rs` calls `nix::unistd::{setuid, setgid, setgroups}` (the
`nix` crate supports FreeBSD) -- that part ports as-is. The capability
clearing at the end of `drop_privileges()` uses the `caps` crate, which
wraps **Linux capabilities** specifically and has no FreeBSD
equivalent as a concept -- FreeBSD's nearest analog is **Capsicum**
(`capsicum(4)`), a fundamentally different capability-mode sandboxing
model, not an extended-permission-bits system, and adopting it properly
would be its own project. Minimum fix: gate the `caps::clear(...)` loop
behind `#[cfg(target_os = "linux")]` so the block still compiles and
runs correctly on FreeBSD (setuid/setgid alone is still a real privilege
drop, just without the Linux-specific belt-and-suspenders step);
Capsicum adoption is a stretch goal, not a blocker.

### 4. Init system -- systemd unit needs a FreeBSD rc.d script

`systemd/mlvpn.service`'s hardening (`ProtectSystem=strict`,
`AmbientCapabilities=`, `RuntimeDirectory=`, etc.) has no FreeBSD
equivalent as one-to-one directives -- rc.d scripts are much simpler,
and FreeBSD's sandboxing story for a hand-rolled daemon leans on
running as an unprivileged user (which `privilege.rs` already does) plus
optionally `jail(8)`, not systemd-style unit sandboxing. Needs a new
`/usr/local/etc/rc.d/mlvpnd` script with the standard
`rcvar`/`start_cmd`/`stop_cmd` boilerplate, plus (for OPNsense/pfSense
specifically) registering with *their* service-management layer, not
just raw rc.d -- see packaging below.

### 5. Firewall integration -- the new `firewall-setup` subcommand doesn't apply

`mlvpnd firewall-setup` (added this session) detects and drives
`firewalld`/`ufw`/`nftables`/`iptables` -- none of which exist on
OPNsense or pfSense. Both are built on **pf** (FreeBSD's packet
filter), entirely configured through their own web GUI/XML config, not
a CLI a third-party daemon should be shelling out to modify. This
subcommand should not attempt to support either platform; instead, the
GUI integration work (see below) is what would let the plugin register
its own pf rules through each platform's normal rule-management layer.

## Packaging: OPNsense and pfSense are not equivalent effort

- **FreeBSD `pkg`** itself (`pkg create`) is the easy, well-understood
  part -- straightforward once the code builds on FreeBSD, and roughly
  comparable effort to the `.rpm`/`.deb` work already done.
- **OPNsense** has the more open path: third-party plugins live in the
  public [opnsense/plugins](https://github.com/opnsense/plugins) repo,
  built through their Makefile/ports-style plugin build system, and a
  *functional* plugin (installable, starts the daemon) is realistic
  without necessarily building full GUI/MVC integration first --
  OPNsense's plugin framework supports a "legacy"/config-file style
  plugin as a smaller first step, with the Phalcon-MVC GUI module
  (controllers, ACL entries, menu registration, translated strings) as
  a larger follow-on for a "native-feeling" experience.
- **pfSense** packaging is more gated: official inclusion in Netgate's
  package repository has historically required coordination with
  Netgate rather than being a simple pull-request-to-a-public-repo
  process the way OPNsense's plugin repo is. A **self-hosted pkg
  repository** (build `.pkg`s in CI, host them, document
  `pkg add`/repo-config steps for users) is realistic without that
  relationship; official Netgate package-manager listing is a separate,
  much longer conversation and shouldn't block anything else here.

## Suggested phased plan

1. **Prove the daemon runs on bare FreeBSD 14** (no GUI, no plugin
   packaging yet): get `cargo build --release` working on a FreeBSD 14
   VM/jail, fix whatever `tun-rs`/`nix`/`caps`-gating issues turn up,
   confirm a manual two-node tunnel comes up using `local_addr`-based
   binding. This is the load-bearing milestone -- everything else is
   packaging/UX on top of a working binary.
2. **`rc.d` script + FreeBSD `pkg`**, self-hosted repo. Gets it
   installable and runnable on stock FreeBSD, independent of either
   firewall distro's plugin frameworks.
3. **OPNsense plugin** (config-file style first, GUI/MVC module later)
   via `opnsense/plugins`. Chosen first over pfSense because the
   contribution path is public and self-serve.
4. **pfSense package**, self-hosted repo initially; revisit official
   Netgate repo inclusion only if this is going somewhere long-term.
5. **Stretch**: `setfib`-based per-link routing (closes the gap #2
   left open), Capsicum sandboxing (closes the gap #3 left open).

## Open questions that need a decision before starting

- Is a self-hosted pkg repo (for pfSense, and optionally OPNsense too)
  an acceptable end state, or is official inclusion in either
  project's repo a hard requirement? This materially changes the
  packaging milestones above.
- Is the "minimum viable" `local_addr`-only interface binding (gap #2)
  acceptable for a first release, or is `setfib`-based binding a
  launch requirement? The former is dramatically less work.
- Does a useful first version need GUI integration at all, or is
  "installable via `pkg`, configured by hand-editing
  `/usr/local/etc/mlvpn/mlvpn.toml`, controlled via `service mlvpnd
  start`" an acceptable v1 on both platforms, with GUI work deferred?
