# RPM package for mlvpn, targeting current Fedora and RHEL/Rocky/Alma
# (9+). Built and tested via .github/workflows/release.yml's build-rpm
# matrix, inside fedora:latest and rockylinux:9 containers -- see that
# workflow for the exact `rpmbuild` invocation. Mirrors debian/ in
# structure and intent; see debian/mlvpn.postinst for the Debian-side
# equivalent of the user/group creation below.
#
# Note on %{?dist}: left in place (standard Fedora/RHEL convention) so
# the same spec produces e.g. mlvpn-0.4.1-1.fc41.x86_64.rpm on Fedora and
# mlvpn-0.4.1-1.el9.x86_64.rpm on RHEL/Rocky/Alma from one source tree.
#
# debug_package disabled: [profile.release] in Cargo.toml sets
# strip = true, so the compiled mlvpnd/mlvpn-tui binaries carry no
# debug symbols for rpmbuild's automatic find-debuginfo pass to
# extract. Without this, rpmbuild still tries to generate a
# mlvpn-debugsource subpackage, finds nothing, and fails the whole
# build with "Empty %files file .../debugsourcefiles.list" -- this is
# the standard fix for Rust (and other pre-stripped-binary) packages.
%global debug_package %{nil}

Name:           mlvpn
Version:        0.4.4
Release:        1%{?dist}
Summary:        Multi-link VPN bonding daemon

License:        AGPL-3.0-only
URL:            https://github.com/4jpps/mlvpn-rs
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo >= 1.86
BuildRequires:  rust >= 1.86
BuildRequires:  gcc
BuildRequires:  pkgconf-pkg-config
BuildRequires:  systemd-rpm-macros
%{?systemd_requires}

Requires:       shadow-utils

%description
mlvpn bonds several physical network uplinks (e.g. fiber + LTE) into a
single encrypted tunnel, load-balancing and failing over between them
based on continuously measured latency, jitter, loss and throughput.

This is a Rust rewrite built on the Noise Protocol Framework (Noise_IK,
the same family WireGuard uses) for a single-round-trip, mutually
authenticated, forward-secret handshake.

Includes mlvpn-tui, a terminal monitoring view, and an
`mlvpnd firewall-setup` subcommand that opens the ports a config needs
on firewalld, ufw, nftables, or iptables.

%prep
%autosetup

%build
# --offline first, matching debian/rules: CI vendors/caches crates.io
# ahead of time, so this only falls through to a network fetch when
# building outside that pipeline (e.g. a local `rpmbuild -ba`).
export CARGO_HOME=%{_builddir}/cargo_home
cargo build --release --locked --offline || cargo build --release --locked

%install
install -Dm0755 target/release/mlvpnd %{buildroot}%{_bindir}/mlvpnd
install -Dm0755 target/release/mlvpn-tui %{buildroot}%{_bindir}/mlvpn-tui
install -Dm0644 systemd/mlvpn.service %{buildroot}%{_unitdir}/mlvpn.service
install -Dm0644 config/mlvpn.toml.example %{buildroot}%{_pkgdocdir}/mlvpn.toml.example
install -Dm0644 config/mlvpn-server.toml.example %{buildroot}%{_pkgdocdir}/mlvpn-server.toml.example
install -dm0750 %{buildroot}%{_sysconfdir}/mlvpn

%pre
getent group mlvpn >/dev/null || groupadd -r mlvpn
getent passwd mlvpn >/dev/null || \
    useradd -r -g mlvpn -d /nonexistent -s /sbin/nologin -c "mlvpn daemon" mlvpn
# Enforce the primary group even when the mlvpn user already existed
# (the useradd above is skipped entirely on upgrade once the account
# exists, so a user whose primary group ended up wrong for any reason
# would otherwise never get corrected by a routine package upgrade).
# No-op, and silent, if it's already mlvpn.
usermod -g mlvpn mlvpn
exit 0

%post
chown root:mlvpn %{_sysconfdir}/mlvpn
chmod 0750 %{_sysconfdir}/mlvpn
%systemd_post mlvpn.service

%preun
%systemd_preun mlvpn.service

%postun
%systemd_postun_with_restart mlvpn.service
# Deliberately does NOT remove the mlvpn user/group here, unlike the
# Debian package's postrm on `purge`: Fedora packaging guidelines
# recommend against deleting system accounts on erase (a later
# reinstall should get the same uid back, and the account may still own
# files outside anything this package tracks). This is an intentional
# behavioral difference from the .deb, not an oversight.

%files
%{_bindir}/mlvpnd
%{_bindir}/mlvpn-tui
%{_unitdir}/mlvpn.service
%license LICENSE
%doc %{_pkgdocdir}/mlvpn.toml.example
%doc %{_pkgdocdir}/mlvpn-server.toml.example
%dir %attr(0750, root, mlvpn) %{_sysconfdir}/mlvpn

%changelog
* Sun Jul 19 2026 Jeff Parrish PC Services <www.jpps.us> - 0.4.4-1
- Fix mlvpnd's log ring (feeds mlvpn-tui's Logs tab and mlvpnd
  diag-dump) dropping every structured field but the bare message --
  found live when a real "failed to write diagnostic dump" warning
  showed up in a diag-dump with no error/dir detail at all, even
  though journald had the full fields the whole time.
- mlvpnd self-test now logs at the start of each leg (and when the
  receiving side starts seeing a stream), not just on completion, so
  a diagnostic dump covering that window clearly shows a deliberate
  self-test was running rather than looking like unexplained loss.
- Default [diagnostics] dump_dir changed from /run/mlvpn (tmpfs,
  cleared on stop/reboot) to /var/log/mlvpn (persistent, matches
  where other services log to), backed by a new LogsDirectory=mlvpn
  in the systemd unit -- no manual mkdir/chown/ReadWritePaths=
  needed for the default case anymore.
- Loosened the systemd unit's restart rate limit
  (StartLimitBurst/StartLimitIntervalSec, 5/60s -> 10/120s) as
  headroom against two hosts restarting near-simultaneously
  (e.g. both upgrading at once) potentially exhausting the old,
  tighter limit and landing the service in a failed state that
  Restart=always can't recover from on its own.

* Sun Jul 19 2026 Jeff Parrish PC Services <www.jpps.us> - 0.4.3-1
- Fix a client-mode link whose remote_addr hostname resolves to both
  an A and AAAA record getting permanently stuck trying an
  unreachable address family (e.g. IPv6 disabled on that link's own
  interface) while a second, unrelated link came up fine. The
  v0.4.1 happy-eyeballs fix only ever resolved the family for
  whichever one link's reply happened to win the tunnel's overall
  initial-handshake race; every other link's own primary-vs-
  alternate ambiguity was simply discarded unused. Added
  tunnel::resolve_remaining_alternates: right after the session is
  established, it races a real authenticated probe between each
  remaining link's primary and alternate address and commits
  whichever one actually answers, instead of just dropping the
  alternate outright.
- Add an on-demand diagnostic-dump capture (mlvpnd diag-dump):
  captures every link's health, daemon/session state, outbound
  queue, TUN counters, system stats, and recent logs into one text
  file, plus kernel-level UDP diagnostics (nstat, ss, /proc/net/udp)
  gathered by the CLI itself -- meant to be attached to a bug
  report. Also adds an automatic variant ([diagnostics]
  auto_dump_enabled = true, off by default) that watches every
  link's own locally-measured loss and writes the daemon-visible
  half of the dump to disk on its own when a link crosses
  loss_threshold_pct.

* Sun Jul 19 2026 Jeff Parrish PC Services <www.jpps.us> - 0.4.2-1
- Fix empty Daemon-tab System panel: drop ProcSubset=pid from the
  shipped systemd unit. That option hid all non-PID top-level /proc
  files (loadavg, meminfo, uptime) that procstats.rs needs, even
  though ProtectProc=invisible alone already provides the isolation
  property intended (hiding other processes' /proc/<PID> trees).
- Fix active-bandwidth-probe measurements deflated by per-packet
  session lock contention: the probe burst's packets are now
  encrypted under a single lock acquisition instead of one per
  packet, removing per-packet lock-wait time from the measured
  duration. Verified via a real veth-pair test: an unshaped baseline
  jumped from ~226 Mbps to ~948 Mbps from this change alone.
  active_bandwidth_mbps feeds scheduler weight, so a link measuring
  artificially low here was being systematically underweighted in
  bonding decisions.
- mlvpn-tui: real-time per-link and aggregate throughput display.
  LinkStats now tracks a windowed tx throughput EWMA alongside the
  existing rx one; the Links tab shows both live rx/tx rates per
  link plus a tunnel-wide aggregate (summed across up links) in the
  panel title, distinct from the existing cumulative Tx/Rx byte
  totals column.
- Add an on-demand throughput self-test (mlvpnd self-test --config
  ... [--link NAME] [--duration SECS] [--bidirectional]): sends a
  real MTU-sized packet stream to the peer and reports the measured
  achieved rate, with no configuration needed on the peer's end.
  --bidirectional additionally has the peer send its own stream
  back afterward, entirely autonomously. Built to help reproduce
  throughput/loss issues directly against the daemon's own
  diagnostics instead of inferring them from an external tool.

* Sat Jul 18 2026 Jeff Parrish PC Services <www.jpps.us> - 0.4.1-1
- Fix a client-side link whose remote_addr is a hostname resolving to
  both an IPv4 and an IPv6 address being able to hang its initial
  handshake indefinitely when the IPv6 path wasn't actually reachable
  end-to-end (a broken or absent route -- not uncommon on residential/
  consumer ISPs, and not the same thing as the AAAA record simply
  existing). mlvpnd previously committed to IPv6 first with no
  fallback; both resolved candidates are now raced during the first
  handshake attempt and whichever one actually answers wins, with a
  log line when the fallback kicks in.
- mlvpn-tui: new Overview tab (now the default at startup), combining
  condensed Links/Daemon/Logs panes into one screen for an
  at-a-glance, screenshot-friendly view. More color coding (link
  score, loss percentage, memory-used percentage). Startup no longer
  fails immediately when the control socket doesn't exist yet if
  mlvpnd is running but still waiting on its peer -- it now watches
  for the socket to appear, and offers to start the service if it
  isn't running at all.

* Sat Jul 18 2026 Jeff Parrish PC Services <www.jpps.us> - 0.4.0-1
- mlvpn-tui: replace the single link table with a tabbed Links /
  Daemon / Logs view. Links gains state-duration and cumulative
  tx/rx-byte columns; Daemon shows session id/uptime/rekey count,
  outbound queue depth and lifetime drops, the TUN interface's own
  kernel byte/error/drop counters, and machine-wide load/memory/
  uptime; Logs streams the daemon's own INFO+ log output live
  (Up/Down/PageUp/PageDown to scroll, auto-follows the tail unless
  scrolled back). Switch tabs with Tab/Shift+Tab or 1/2/3.
- mlvpnd: the control-socket wire format (ipc::Snapshot) gained the
  fields the above needs -- a new daemon: DaemonSnapshot and
  new_log_lines: Vec<LogEntry>, both required (not optional), plus
  new per-link fields on LinkSnapshot. This is a breaking wire
  change: mlvpnd and mlvpn-tui must be upgraded together on a given
  host, since an old mlvpn-tui talking to a new mlvpnd (or vice
  versa) will fail to parse the control socket's JSON.
- New in-memory log ring (logbuf.rs) feeding mlvpn-tui's Logs tab,
  filtered to INFO+ independent of the daemon's own configured log
  level so a debug/trace run can't flood it. Session/rekey metadata
  moved off the per-packet session lock into its own SessionMeta to
  avoid adding contention to that hot path.

* Sat Jul 18 2026 Jeff Parrish PC Services <www.jpps.us> - 0.3.7-1
- Fix compute_achieved_mbps's elapsed-time floor silently capping
  active-bandwidth-probe results at ~229 Mbps on fast links. The 1ms
  floor was high enough to override real, correctly-measured
  durations for bursts that legitimately completed faster than that,
  so achieved_mbps ceilinged at the same value every time -- confirmed
  from production logs showing the exact same figure recurring on a
  fast link. Since active_bandwidth_mbps feeds the scheduler's
  throughput weighting, this systematically underweighted a link
  relative to its real capacity. Lowered the floor to 1 microsecond
  (Instant has nanosecond resolution, so this still only guards the
  literal zero/negative case).

* Fri Jul 17 2026 Jeff Parrish PC Services <www.jpps.us> - 0.3.6-1
- Fix a .deb-only postinst corruption bug: debhelper's dh_installdeb
  substitutes every occurrence of the literal token marking where its
  generated code gets spliced in, not just the one intended marker
  line -- this script's own explanatory comments mentioned that token
  five more times in prose, so each one got a second copy of
  debhelper's generated systemctl restart/daemon-reload code spliced
  into the middle of the sentence, corrupting the script and failing
  dpkg --configure with exit 127 on a real install. Rewrote every
  comment to describe the marker without repeating the literal token
  pattern debhelper matches on. This .rpm was never affected --
  version bumped only to keep both packages on the same release
  number.

* Fri Jul 17 2026 Jeff Parrish PC Services <www.jpps.us> - 0.3.5-1
- A link's remote_addr now accepts a DNS hostname, not just a literal
  IP (e.g. "bgp.example.com:51000"). Resolved once at startup with a
  10s timeout; a hostname resolving to both an A and AAAA record
  prefers IPv6 unless local_addr pins the family.
- New outbound queue overflow logging, modeled on the original C
  MLVPN's freebuffer_t: tun_reader and the actual per-link send are
  now split across a bounded channel, so a send side that falls behind
  drops packets and logs a WARN-level "outbound queue overflowed" line
  (with a drop count) instead of silently losing them in the kernel's
  TUN queue, as happened below. Silent on a healthy tunnel.
- Performance: bonded throughput still plateaued well below what the
  links could do individually, even after 0.3.2's cross-link lock fix.
  A real two-host test pushing 200 Mbps of small UDP datagrams
  (~19,000 packets/sec) found a hard, flat ~65%% loss ceiling. Root
  cause: send_scheduled cloned every configured link's full Link
  (including every LinkConfig String field) on every single outgoing
  packet just to let the scheduler pick one and discard the rest --
  the heap allocation and per-link lock/clone overhead of that
  outpaced packet arrival at high rates, silently overflowing the
  kernel's TUN queue before mlvpnd ever read the dropped packets.
  Scheduler::select now works off a Copy-only LinkScore snapshot and
  returns just the winning link's index, so only that one link is ever
  locked-and-cloned. See docs/performance-tuning.md.

* Fri Jul 17 2026 Jeff Parrish PC Services <www.jpps.us> - 0.3.4-1
- Debian packaging only this release: fixes debian/mlvpn.postinst's
  restart-on-upgrade check always losing a race against debhelper's
  own generated postinst code and leaving mlvpnd stopped after every
  .deb upgrade. This .rpm was never affected (%%systemd_postun_with_restart
  already handled this correctly) -- version bumped only to keep both
  packages on the same release number.

* Fri Jul 17 2026 Jeff Parrish PC Services <www.jpps.us> - 0.3.3-1
- Fix restarting either side of a tunnel silently stopping the other
  side too, requiring a manual restart there. A peer-initiated
  Disconnect makes mlvpnd exit cleanly (code 0) by design, and the
  previous Restart=on-failure systemd policy never restarts a process
  that exited 0 -- so restarting one side for any reason sent the
  other side a graceful Disconnect and left it stopped indefinitely.
  systemd/mlvpn.service now uses Restart=always, so any exit -- this
  one included -- gets the daemon back up within RestartSec=2; an
  explicit systemctl stop is unaffected.
- Fix mlvpn-tui failing with "multiple control sockets found" once
  [command] enabled = true was set. Auto-detection matched any file
  under /run/mlvpn ending in .sock, which also matched the
  <tunnel>.command.sock write-capable command socket -- a completely
  different protocol, not the streaming snapshot mlvpn-tui actually
  reads. Now explicitly excludes *.command.sock.

* Fri Jul 17 2026 Jeff Parrish PC Services <www.jpps.us> - 0.3.2-1
- Performance: bonding two links together could be slower than using
  either one alone -- all links shared one single lock over every
  link's metadata, so two links' receive tasks serialized against each
  other on every packet even though they touch disjoint data. Each
  link now has its own independent lock, removing that cross-link
  contention entirely. See docs/performance-tuning.md.
- Add mlvpn-tui's header showing this machine's own hostname alongside
  the tunnel name and mode.
- Fix systemd/mlvpn.service's PrivateDevices=no having an unsupported
  trailing inline comment on the same line.
- Fix the mlvpn system user's primary group being able to end up as
  nogroup instead of mlvpn on an existing install; %%pre now enforces
  this on every install/upgrade.
- The .deb package now also restarts mlvpnd after an upgrade if it was
  already running (this .rpm already did, via
  %%systemd_postun_with_restart).

* Thu Jul 16 2026 Jeff Parrish PC Services <www.jpps.us> - 0.3.1-1
- Fix the initial handshake exiting the whole daemon if every configured
  link's peer is unreachable at startup; now retries in the background
  with exponential backoff instead, matching WireGuard/the original
  MLVPN. Found on a real two-host deployment.
- Performance: request an 8 MiB kernel socket buffer per link
  (SO_RCVBUFFORCE/SO_SNDBUFFORCE, falling back to plain SO_RCVBUF/
  SO_SNDBUF), instead of relying on the stock ~208KB Linux default,
  which silently drops packets once a fast link's bandwidth-delay
  product exceeds it. See docs/performance-tuning.md.
- Fix a stale handshake reply being able to permanently starve every
  future retry once the initial handshake started retrying
  indefinitely (previous entry): race_handshake_reply now also requires
  a reply's session id to match the current attempt's, instead of only
  checking source address and packet type. Caught by this project's own
  integration tests immediately after the retry change above.

* Tue Jul 14 2026 Jeff Parrish PC Services <www.jpps.us> - 0.3.0-1
- Add self-healing link reconnection, handshake racing across every
  configured link, rekeying with session migration, and graceful
  shutdown on SIGINT/SIGTERM.
- Add per-link bandwidth cap enforcement and an opt-in redundancy mode
  (scheduler.redundant_mode).
- Add a runtime link-control command socket ([command] enabled, off by
  default): mlvpnd set-link <link> <enable|disable>.
- Add IPv6 support to the bonded links themselves (independent of the
  IPv4 tunnel address), inferred from remote_addr/local_addr.
- Add periodic tunnel auto-tuning, all opt-in: reorder_window_ms,
  probe_interval_ms, EWMA alpha, and active bandwidth probing can each
  re-tune themselves from live link conditions.
- New integration test harness (tests/veth_*.rs) covering all of the
  above against two real mlvpnd processes in Linux network namespaces.
- Fix log output carrying embedded ANSI color escape codes even when
  not writing to an interactive terminal; now explicitly disabled.
- Fix a race in the initial handshake's retry loop where a late reply
  could poison every remaining retry attempt; each attempt now uses
  its own session id (rekeying is unaffected).

* Mon Jul 13 2026 Jeff Parrish PC Services <www.jpps.us> - 0.2.0-1
- Add IPv6 dual-stack support to the TUN interface (tunnel.address6).
- Add adaptive tunnel MTU: detects each bonded link's real physical
  interface MTU (SIOCGIFMTU) and auto-clamps tunnel.mtu down if it
  would fragment, instead of just warning.
- Add TCP MSS clamping (tunnel.clamp_mss, on by default) for IPv4 and
  IPv6 TCP SYN/SYN-ACK segments transiting the tunnel.
- Fix RPM debuginfo packaging: disable debug_package, since
  Cargo.toml's strip = true leaves nothing for find-debuginfo to
  extract.

* Mon Jul 13 2026 Jeff Parrish PC Services <www.jpps.us> - 0.1.2-1
- Security: bump ratatui 0.29 -> 0.30 to pull in lru >= 0.16.3, fixing
  a soundness advisory in lru's IterMut (RUSTSEC, affects >= 0.9.0,
  < 0.16.3). Only reachable via mlvpn-tui, never mlvpnd itself.
  Raises the minimum toolchain to rust >= 1.86 accordingly.

* Mon Jul 13 2026 Jeff Parrish PC Services <www.jpps.us> - 0.1.1-1
- Initial RPM packaging, mirroring the existing .deb: firewalld-aware
  mlvpnd firewall-setup, systemd unit, unprivileged mlvpn user/group
  created automatically on install.
- Relicensed from MIT to AGPL-3.0-only.
