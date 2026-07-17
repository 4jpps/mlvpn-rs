#!/usr/bin/env bash
# Full regression suite: everything that should stay green as features
# get added, in one command instead of retyping the growing list by
# hand each time. See docs/development.md for what each step covers.
#
# Run as your normal user, NOT under sudo -- the integration test loop
# below invokes sudo itself, only for the specific commands that need
# root (network namespace/veth creation). Running the whole script
# under sudo would leave target/ and any fmt-rewritten files owned by
# root, which is exactly the kind of permission headache this is
# trying to avoid.
#
# Usage: scripts/full-check.sh [--skip-integration]

set -euo pipefail
cd "$(dirname "$0")/.."

skip_integration=0
if [[ "${1:-}" == "--skip-integration" ]]; then
    skip_integration=1
fi

# Get the sudo password prompt out of the way up front, before any real
# output exists to scroll past it -- the veth integration tests each
# sudo themselves individually (see the loop below), so without this
# the prompt lands unpredictably in the middle of whichever test
# happens to run first. `sudo -v` just refreshes/caches credentials
# without running a real command; harmless (and near-instant) to call
# even when --skip-integration means nothing below will actually need
# it.
sudo -v
clear

echo "== build =="
cargo build --release

echo "== unit tests =="
cargo test --release --lib

echo "== clippy (warnings are errors here) =="
cargo clippy --all-targets -- -D warnings

echo "== fmt =="
cargo fmt
if ! git diff --quiet -- '*.rs'; then
    echo "cargo fmt changed files -- review and commit the formatting fix:"
    git diff --stat -- '*.rs'
fi

if [[ "$skip_integration" == "1" ]]; then
    echo "== skipping integration tests (--skip-integration) =="
    echo "All non-integration checks passed."
    exit 0
fi

echo "== integration tests (needs root; each one sudo's itself) =="
for t in veth_handshake_race veth_failover veth_rekey veth_disconnect veth_redundant veth_link_control veth_reorder_tuning veth_ipv6_link veth_probe_interval_tuning veth_ewma_alpha_tuning veth_active_bandwidth_probing; do
    echo "-- $t --"
    sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test "$t" -- --ignored --nocapture
done

echo "All checks passed."
