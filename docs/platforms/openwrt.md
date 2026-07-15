# Platform roadmap: OpenWrt

**Status: scoping only -- nothing in this document is implemented.** No
code has changed for this yet; this is a gap analysis and a proposed
plan, written so a future session (or contributor) can pick it up
without re-deriving all of this from scratch. See
[`opnsense-pfsense.md`](opnsense-pfsense.md) for the equivalent
scoping document covering those two platforms -- together, these three
are the major router/firewall platforms this project is likely to
target beyond generic Debian/Fedora-family Linux.

## Why this is a different kind of port than the Linux packaging work

Unlike OPNsense/pfSense (FreeBSD-based -- a genuinely different kernel
and userland), OpenWrt **is** Linux, so the kernel-level pieces this
project already depends on -- `SO_BINDTODEVICE` per-link interface
binding, Linux capabilities for privilege dropping, the `tun-rs`
TUN device path -- keep working essentially unchanged. The real
differences are further up the stack: a different (and much smaller)
C library, a different init system, a different package manager, a
very different build/cross-compilation story, and, most
consequentially, hardware this project has never had to think about
before -- routers with a fraction of the RAM and flash storage a
typical Debian/Fedora server or even an OPNsense/pfSense box has.

## Target version and platform facts (as of mid-2026)

- Current stable series is **OpenWrt 25.12** (25.12.0 released March
  2026, with point releases since -- 25.12.5 in June 2026).
  ([OpenWrt downloads](https://downloads.openwrt.org/))
- **musl libc**, not glibc -- this is what most Linux distros this
  project already targets use, and it's a meaningfully smaller/leaner
  libc that embedded builds specifically favor.
- **BusyBox** userland, **procd** as PID 1/service supervisor (not
  systemd, not traditional SysVinit).
- **25.12 replaced `opkg` with `apk`** (Alpine Linux's package
  manager) as the default package manager -- a significant, recent
  change worth designing packaging around from the start rather than
  targeting the now-deprecated `opkg` format.
  ([OpenWrt 25.12 release coverage](https://linuxiac.com/openwrt-25-12-released-with-apk-package-manager-replacing-opkg/))
- Targets a wide architecture spread: ARM (various), MIPS, x86/x86_64,
  and RISC-V, across a much more fragmented hardware landscape than
  "amd64 + arm64" -- OpenWrt's own device database lists 2200+
  supported devices as of the 25.12 release.
  ([Help Net Security coverage of 25.12.0](https://www.helpnetsecurity.com/2026/03/09/openwrt-25-12-0-released/))

Re-check these before starting real work -- OpenWrt releases on an
ongoing cadence and this document will age, same caveat as the
OPNsense/pfSense document.

## Architecture gaps: what actually needs to change

### 1. TUN device creation, per-link binding, and privilege dropping -- likely fine as-is

Because OpenWrt runs a real Linux kernel, the three pieces that
needed a genuine redesign for the FreeBSD port are non-issues here:

- `tun-rs` already supports Linux, and OpenWrt's kernel exposes the
  same `/dev/net/tun` this project already uses on every other Linux
  target.
- `link.rs::Link::bind`'s `SO_BINDTODEVICE` call is already
  Linux-specific and needs no change -- it works identically on
  OpenWrt's kernel.
- `privilege.rs`'s `nix`-based `setuid`/`setgid`/`setgroups` and the
  `caps` crate's Linux-capabilities clearing both target real Linux
  kernel APIs, present regardless of which libc userland sits on top.

Needs verification with a real musl build (Rust's
`*-unknown-linux-musl` target triples are well-supported, but this
project hasn't built against musl before), not a redesign.

### 2. Binary size and resource footprint -- the real new constraint

This is the gap that doesn't exist for the OPNsense/pfSense port
(those run on comparatively hefty x86 hardware) but matters a great
deal here: OpenWrt targets routers that can have as little as 4-16MB
of flash and 64-128MB of RAM at the low end, alongside much more
capable modern devices. `Cargo.toml`'s current `[profile.release]`
(`opt-level = 3`, `lto = true`, `codegen-units = 1`, `strip = true`)
already optimizes for speed and does strip debug symbols, but a
size-optimized build profile (`opt-level = "z"` or `"s"`) specifically
for OpenWrt targets is worth evaluating against real flash budgets
before committing to a device-support list. `tokio`'s
`rt-multi-thread` feature (currently enabled) also assumes it's
worth spinning up a multi-threaded work-stealing runtime; on a
single- or dual-core router SoC, the plain `rt` (single-threaded)
feature may be the more appropriate choice, trading a small amount of
theoretical throughput for a meaningfully smaller/simpler runtime.

### 3. Init system -- systemd unit needs a procd init script

`systemd/mlvpn.service`'s directives have no procd equivalent as
one-to-one settings -- procd init scripts are a different, much
smaller shape (`/etc/init.d/mlvpnd` implementing `start_service()`/
`stop_service()`, calling `procd_open_instance`/`procd_set_param
command`/`procd_close_instance`, with `procd`'s own respawn/watchdog
handling replacing systemd's). This is a rewrite of the service
definition, not a port of the existing unit file, but is
well-trodden ground -- most OpenWrt packages ship exactly this shape
of init script.

### 4. Firewall integration -- needs UCI, not raw nftables/iptables edits

`mlvpnd firewall-setup` (which drives `firewalld`/`ufw`/`nftables`/
`iptables` directly) shouldn't attempt to support OpenWrt as-is, for
the same reason it doesn't attempt OPNsense/pfSense: OpenWrt manages
its firewall through **UCI** (`/etc/config/firewall`) and its own
`fw4` layer (an nftables-based wrapper, replacing the older `fw3`/
iptables-based one), regenerating the actual ruleset from that config
on every `/etc/init.d/firewall reload` -- rules poked in directly via
`nft`/`iptables` would simply be wiped out. The correct integration
is a package-provided UCI config snippet (and/or a small helper that
writes one), not an extension of the existing subcommand's
detection logic.

## Packaging: OpenWrt's build model is a feed, not a spec file

Unlike `.deb`/`.rpm` (build once per architecture against a normal
host toolchain) or FreeBSD `pkg`, OpenWrt packages are built via the
**OpenWrt SDK** (a prebuilt cross-compilation toolchain per target
architecture) or a full buildroot checkout, driven by a package
`Makefile` living in a **feed** -- either the official
[openwrt/packages](https://github.com/openwrt/packages) feed (public,
pull-request-based, similar in spirit to OPNsense's plugin repo) or a
self-hosted feed users add manually. Given the architecture spread
noted above, "supports OpenWrt" in practice means picking an initial
subset of architectures (most likely `x86_64` and one or two popular
ARM targets first) rather than attempting the full device matrix from
day one -- each additional target architecture is close to free once
the package Makefile and any musl-specific code changes exist, since
the SDK provides the cross-compilation toolchain, but each one still
needs at least a build-verification pass.

## Suggested phased plan

1. **Prove the daemon builds and runs against musl** (no packaging
   yet): cross-compile for `x86_64-unknown-linux-musl` first (the
   architecture requiring the least new toolchain work), confirm a
   manual two-node tunnel comes up under a real or emulated OpenWrt
   environment.
2. **Evaluate a size-optimized release profile** against real flash
   budgets for the initial target architecture(s) -- this determines
   whether the low end of OpenWrt's supported hardware is realistically
   in scope at all, or whether v1 should explicitly target only
   higher-end (more RAM/flash) devices.
3. **`procd` init script**, hand-written against the standard
   template every OpenWrt package uses.
4. **UCI firewall config integration** -- likely a config snippet
   template rather than code, given `mlvpnd firewall-setup` explicitly
   doesn't apply here.
5. **Package Makefile + feed**, `x86_64` first via a self-hosted feed;
   broaden the architecture list and pursue inclusion in the official
   `openwrt/packages` feed once the above has proven out.

## Open questions that need a decision before starting

- Is a self-hosted feed an acceptable end state, or is inclusion in
  the official `openwrt/packages` feed a hard requirement? Mirrors the
  same open question in the OPNsense/pfSense document.
- How low-end a device does this need to run acceptably on? This is
  the single biggest scoping question specific to OpenWrt -- it
  determines whether step 2 above (size-optimized build, possibly a
  single-threaded tokio runtime) is a nice-to-have or a hard
  requirement before any release.
- Does a useful first version need UCI-based configuration at all, or
  is "installed via `apk`, configured by hand-editing
  `/etc/mlvpn/mlvpn.toml`, controlled via `/etc/init.d/mlvpnd start`"
  an acceptable v1, with a UCI config layer (and any LuCI web-UI
  integration) deferred entirely?

---

Sources consulted: [OpenWrt downloads](https://downloads.openwrt.org/), [OpenWrt 25.12 release coverage (linuxiac.com)](https://linuxiac.com/openwrt-25-12-released-with-apk-package-manager-replacing-opkg/), [OpenWrt 25.12.0 coverage (Help Net Security)](https://www.helpnetsecurity.com/2026/03/09/openwrt-25-12-0-released/), [OpenWrt end-of-life dates](https://eosl.date/eol/product/openwrt/).
