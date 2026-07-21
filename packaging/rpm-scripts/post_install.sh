#!/bin/sh
set -e

# cargo-generate-rpm's post_install_script -- replaces packaging/rpm/
# mlvpn.spec's %post + %systemd_post. Deliberately does not enable/
# start the unit on a fresh install, matching the .deb side's explicit
# --no-enable --no-start (dh_installsystemd) and this project's stated
# reasoning: a fresh install has no /etc/mlvpn/mlvpn.toml yet, so
# starting immediately would just fail on a missing config.
mkdir -p /etc/mlvpn
chown root:mlvpn /etc/mlvpn
chmod 0750 /etc/mlvpn
if [ -f /etc/mlvpn/mlvpn.toml ]; then
  chown mlvpn:mlvpn /etc/mlvpn/mlvpn.toml
  chmod 0600 /etc/mlvpn/mlvpn.toml
fi
if [ -f /etc/mlvpn/private.key ]; then
  chown mlvpn:mlvpn /etc/mlvpn/private.key
  chmod 0600 /etc/mlvpn/private.key
fi

systemctl daemon-reload || true

STATE_FILE=/run/mlvpn/.preinst-was-active
MLVPN_WAS_ACTIVE=no
if [ -f "$STATE_FILE" ]; then
  MLVPN_WAS_ACTIVE=$(cat "$STATE_FILE")
  rm -f "$STATE_FILE"
fi

echo "mlvpn post_install: was mlvpn.service active before this upgrade? $MLVPN_WAS_ACTIVE"
if [ "$MLVPN_WAS_ACTIVE" = "yes" ]; then
  if ! systemctl restart mlvpn.service; then
    echo "mlvpn post_install: WARNING: mlvpn.service was active before this upgrade but" \
         "failed to restart automatically -- run 'systemctl status mlvpn.service' and" \
         "'journalctl -u mlvpn.service' to diagnose, then 'systemctl start mlvpn.service'" \
         "once fixed" >&2
  fi
fi

exit 0
