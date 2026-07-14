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

See [CONTRIBUTING.md](../CONTRIBUTING.md) before opening a PR, and
[SECURITY.md](../SECURITY.md) if you've found a vulnerability rather
than a regular bug -- please don't file those as public issues.

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

1. Bump the version in `Cargo.toml`, `debian/changelog`, and
   `packaging/rpm/mlvpn.spec`'s `Version:` field -- these are not
   currently linked, so all three need updating by hand.
2. Update `CHANGELOG.md`.
3. `git tag vX.Y.Z && git push origin vX.Y.Z` -- this triggers
   `release.yml`, which builds and publishes every package.

## Local package builds, without waiting on CI

```sh
# .deb (needs debhelper, dpkg-dev, build-essential, pkg-config, libc6-dev)
dpkg-buildpackage -us -uc -b -d

# .rpm (needs rpm-build, rpmdevtools, systemd-rpm-macros, gcc, pkgconf-pkg-config)
rpmdev-setuptree
git archive --prefix=mlvpn-0.1.1/ -o ~/rpmbuild/SOURCES/mlvpn-0.1.1.tar.gz HEAD
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
  git archive --prefix=mlvpn-0.1.1/ -o ~/rpmbuild/SOURCES/mlvpn-0.1.1.tar.gz HEAD &&
  cp packaging/rpm/mlvpn.spec ~/rpmbuild/SPECS/ &&
  rpmbuild -ba ~/rpmbuild/SPECS/mlvpn.spec &&
  find ~/rpmbuild/RPMS -name "*.rpm" -exec cp {} /src/ \;
'
```
