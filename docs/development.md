# Development

This targets current Debian/Ubuntu and Fedora/RHEL-family systemd Linux,
so on Windows the supported setup is
[WSL2](https://learn.microsoft.com/windows/wsl/) with a Debian distro,
plus VS Code's
[WSL extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-wsl)
(`code .` from inside the WSL repo clone) and the
[rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
extension installed *in* that WSL window. Clone into WSL's native
filesystem (`~/mlvpn-rs`), not `/mnt/c/...` -- NTFS-backed paths break
`chmod`/git filemode handling that `cargo` and `git` both rely on.

```sh
cargo build --release
cargo test --release --lib
cargo clippy --all-targets
cargo fmt
```

`scripts/full-check.sh` runs all of the above plus every integration
test below in one command -- the full regression suite, meant to be
run after any change of substance. Run it as your normal user, not
under `sudo` (it invokes `sudo` itself only for the parts that need
root): `bash scripts/full-check.sh`, or `--skip-integration` to skip
the parts needing root/`iproute2`. If it's not already executable:
`chmod +x scripts/full-check.sh`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) before opening a PR, and
[SECURITY.md](../SECURITY.md) if you've found a vulnerability rather
than a regular bug -- please don't file those as public issues.

## Integration tests (`tests/veth_*.rs`)

`cargo test --lib` (used above, and by CI) only runs the self-contained
unit tests under `src/`. Separately, `tests/veth_*.rs` spin up two
*real* `mlvpnd` processes in their own Linux network namespaces,
connected by real veth pairs, and drive them exactly like two real
hosts on separate physical links -- real `SO_BINDTODEVICE` binds, a
real Noise handshake, real probing, real rekeying, real graceful
shutdown, real redundancy-mode traffic, a real control-socket JSON
stream, (via the real `mlvpnd set-link` CLI) a real command-socket
round trip, (via real `tc netem` latency injection) a real
reorder-window auto-tuning decision, and (via real `tc tbf` rate
shaping) a real active-bandwidth-probing discovery. This needs root
(namespace/veth creation, `mlvpnd`'s own `CAP_NET_ADMIN`/`CAP_NET_RAW`
setup), `iproute2`'s `ip` on `PATH`, and the `mlvpn` system user/group
(created automatically if missing, mirroring
[Installation](installation.md) Option B's manual steps). None of that
is available in a normal `cargo test` run, so all of these are marked
`#[ignore]` and need to be invoked explicitly:

```sh
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_handshake_race -- --ignored --nocapture
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_failover -- --ignored --nocapture
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_rekey -- --ignored --nocapture
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_disconnect -- --ignored --nocapture
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_redundant -- --ignored --nocapture
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_link_control -- --ignored --nocapture
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_reorder_tuning -- --ignored --nocapture
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_ipv6_link -- --ignored --nocapture
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_probe_interval_tuning -- --ignored --nocapture
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_ewma_alpha_tuning -- --ignored --nocapture
sudo env "PATH=$PATH" HOME="$HOME" cargo test --release --locked --test veth_active_bandwidth_probing -- --ignored --nocapture
```

`veth_reorder_tuning` and `veth_active_bandwidth_probing` additionally
need `tc` (also part of `iproute2`, though occasionally packaged
separately as `iproute2-tc`), and both take noticeably longer than the
others (tens of seconds): `veth_reorder_tuning` has to wait through at
least one real 30-second `reorder_tuning_loop` tick, and
`veth_active_bandwidth_probing` waits through the validated 30-second
floor of `active_bandwidth_probe_interval_secs` -- see each test's own
module doc comment.

Plain `sudo -E` isn't enough for a rustup-managed toolchain: many
sudoers configs force `secure_path` for `PATH` regardless of `-E` (so
`cargo`, installed under `~/.cargo/bin`, isn't found at all), and even
once that's fixed, rustup's `cargo` shim still consults `$HOME` to pick
a toolchain -- root's own `$HOME` has none configured. Explicitly
passing both `PATH` and `HOME` through via `env` (as above) is what
actually works. `--nocapture` shows both the test's own progress and
the daemon's own logs (inherited stdout/stderr, see
`tests/support/mod.rs`'s `MlvpnProcess`) as they happen, which matters
here since a failing assertion's usual first question is "what was the
daemon actually doing at that point."

These files (and their shared helpers in `tests/support/mod.rs`) *are*
covered by `cargo clippy --all-targets` and `cargo fmt` -- only actually
*running* them needs the setup above; compiling and formatting them
doesn't. See `tests/support/mod.rs`'s module doc comment for exactly
what each test exercises and what's deliberately still out of scope
(notably: self-healing socket reconnection after an interface is fully
removed and recreated, `link::LinkHandle::reconnect`, isn't covered yet
-- only the pre-existing quality-based up/down hysteresis is).

## CI and releases

`.github/workflows/ci.yml` runs `cargo build`/`test`/`clippy`/`fmt` on
every push/PR to `main`, on both amd64(`ubuntu-latest`) and arm64
(`ubuntu-24.04-arm`) runners.

`.github/workflows/release.yml` builds packages on a version tag push
(`v*`) or manual dispatch:

- `build-deb`: `.deb` for amd64 + arm64 (native runners, `Architecture:
  any` in `debian/control`).
- `build-rpm`: `.rpm` for amd64 + arm64, across `fedora:latest` and
  `rockylinux:9` containers (also run on the native arm64 runner, so
  these are native builds too, not cross-compiled/emulated).
- `publish`: waits on both, downloads every package artifact, and
  attaches all of them to one GitHub Release via a single
  `softprops/action-gh-release` call -- deliberately not one call per
  job, to avoid multiple jobs racing to create/update the same tag's
  Release.

## Cutting a release

1. Bump the version in `Cargo.toml`, `debian/changelog`,
   `packaging/rpm/mlvpn.spec`'s `Version:` field, and the two
   `mlvpn-X.Y.Z` source-tarball prefixes in
   `.github/workflows/release.yml`'s `build-rpm` job -- none of these
   are currently linked, so all four need updating by hand. Missing
   the `release.yml` one specifically breaks the RPM build: `rpmbuild`
   expects the tarball's top-level directory to match
   `%{name}-%{version}` from the spec file.
2. Update `CHANGELOG.md`. Get this one right before tagging: the
   published GitHub Release's body is this version's own `## [X.Y.Z]`
   section, pulled verbatim from `CHANGELOG.md` by `release.yml`'s
   `publish` job (not GitHub's auto-generated commit/PR list) -- see
   that job's "Extract this version's CHANGELOG.md section" step.
3. `git tag vX.Y.Z && git push origin vX.Y.Z` -- this triggers
   `release.yml`, which builds and publishes every package, with the
   Release's notes taken from step 2 above.

## Local package builds, without waiting on CI

```sh
# .deb (needs debhelper, dpkg-dev, build-essential, pkg-config, libc6-dev)
dpkg-buildpackage -us -uc -b -d

# .rpm (needs rpm-build, rpmdevtools, systemd-rpm-macros, gcc, pkgconf-pkg-config)
rpmdev-setuptree
git archive --prefix=mlvpn-0.3.3/ -o ~/rpmbuild/SOURCES/mlvpn-0.3.3.tar.gz HEAD
cp packaging/rpm/mlvpn.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/mlvpn.spec
```

The RPM path needs an actual Fedora/RHEL-family system or container --
there's no `rpmbuild` on Debian/Ubuntu. Easiest local approximation of
what CI does:

```sh
docker run --rm -v "$PWD":/src -w /src fedora:latest bash -c '
  dnf -y install git tar rust cargo gcc pkgconf-pkg-config systemd-rpm-macros rpm-build rpmdevtools &&
  git config --global --add safe.directory /src &&
  rpmdev-setuptree &&
  git archive --prefix=mlvpn-0.3.3/ -o ~/rpmbuild/SOURCES/mlvpn-0.3.3.tar.gz HEAD &&
  cp packaging/rpm/mlvpn.spec ~/rpmbuild/SPECS/ &&
  rpmbuild -ba ~/rpmbuild/SPECS/mlvpn.spec &&
  find ~/rpmbuild/RPMS -name "*.rpm" -exec cp {} /src/ \;
'
```
