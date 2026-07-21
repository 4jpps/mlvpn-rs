#!/bin/sh
set -e

# cargo-generate-rpm's pre_uninstall_script -- replaces packaging/rpm/
# mlvpn.spec's %preun + %systemd_preun. $1 = 0 means a real removal
# (the last/only version being uninstalled); $1 >= 1 means this run is
# part of an upgrade transaction (a newer version's files are already
# being installed), where the unit should keep running, not be
# stopped. Restart-on-upgrade is handled entirely by the *new*
# version's post_install.sh (see its MLVPN_WAS_ACTIVE handling) so
# this script does nothing at all in that case.
#
# Deliberately does not delete the mlvpn user/group on removal, unlike
# packaging/deb-scripts/postrm's purge handling -- matches packaging/
# rpm/mlvpn.spec's own existing, deliberate choice (Fedora packaging
# guidelines recommend against deleting system accounts on erase).
if [ "$1" = "0" ]; then
  systemctl stop mlvpn.service >/dev/null 2>&1 || true
fi

exit 0
