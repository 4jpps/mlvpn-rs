# RPM package for mlvpn, targeting current Fedora and RHEL/Rocky/Alma
# (9+). Built and tested via .github/workflows/release.yml's build-rpm
# matrix, inside fedora:latest and rockylinux:9 containers -- see that
# workflow for the exact `rpmbuild` invocation. Mirrors debian/ in
# structure and intent; see debian/mlvpn.postinst for the Debian-side
# equivalent of the user/group creation below.
#
# Note on %{?dist}: left in place (standard Fedora/RHEL convention) so
# the same spec produces e.g. mlvpn-0.1.1-1.fc41.x86_64.rpm on Fedora and
# mlvpn-0.1.1-1.el9.x86_64.rpm on RHEL/Rocky/Alma from one source tree.

Name:           mlvpn
Version:        0.1.1
Release:        1%{?dist}
Summary:        Multi-link VPN bonding daemon

License:        AGPL-3.0-only
URL:            https://github.com/4jpps/mlvpn-rs
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo >= 1.75
BuildRequires:  rust >= 1.75
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
* Mon Jul 13 2026 Jeff Parrish PC Services <www.jpps.us> - 0.1.1-1
- Initial RPM packaging, mirroring the existing .deb: firewalld-aware
  mlvpnd firewall-setup, systemd unit, unprivileged mlvpn user/group
  created automatically on install.
- Relicensed from MIT to AGPL-3.0-only.
