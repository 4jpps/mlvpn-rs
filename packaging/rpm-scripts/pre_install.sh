#!/bin/sh
set -e

# cargo-generate-rpm's pre_install_script, replacing packaging/rpm/
# mlvpn.spec's %pre + the systemd-rpm-macros package (%systemd_post
# etc.) which cargo-generate-rpm has no equivalent of -- there is no
# rpmbuild/spec-file processing in this path at all, so every macro
# expansion the old .spec relied on needs to be spelled out by hand
# here and in post_install.sh/pre_uninstall.sh.
#
# Reuses the same MLVPN_WAS_ACTIVE-across-a-state-file pattern as
# packaging/deb-scripts/preinst+postinst, for the same reason: %pre
# nominally runs before an upgrade's new files are unpacked, same as
# dpkg's preinst, but a live is-active check placed too late (e.g. in
# %post, after unpacking) was a real, fixed bug on the .deb side --
# applying the same fix preemptively here instead of waiting to hit
# the same class of bug on the RPM side too.
getent group mlvpn >/dev/null || groupadd -r mlvpn
getent passwd mlvpn >/dev/null || \
    useradd -r -g mlvpn -d /nonexistent -s /sbin/nologin -c "mlvpn daemon" mlvpn
usermod -g mlvpn mlvpn

STATE_FILE=/run/mlvpn/.preinst-was-active
mkdir -p /run/mlvpn
if systemctl is-active --quiet mlvpn.service 2>/dev/null; then
  echo yes > "$STATE_FILE"
else
  echo no > "$STATE_FILE"
fi

exit 0
