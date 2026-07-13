# Contributing to mlvpn-rs

Thanks for considering a contribution. This project targets Debian 13
and other current systemd Linux distributions; see `ARCHITECTURE.md`
before making non-trivial changes -- it documents the design rationale
behind most non-obvious decisions in the code, and most modules carry
their own "why", not just "what", in their doc comments. Please match
that style: a comment explaining *why* a lock is held across a
particular scope, or *why* a check exists, is worth far more than one
restating the code.

## Getting set up

On Windows, the supported path is [WSL2](https://learn.microsoft.com/windows/wsl/)
with a Debian distro; this has Linux-only dependencies (`SO_BINDTODEVICE`,
TUN devices, Linux capabilities) so there is no native Windows build.
Clone into WSL's native filesystem (`~/mlvpn-rs`), not `/mnt/c/...` --
NTFS-backed paths break `chmod`/git filemode handling that `cargo` and
`git` both rely on. See the README's "Development" section for the full
VS Code + WSL + rust-analyzer setup.

```sh
git clone https://github.com/4jpps/mlvpn-rs.git
cd mlvpn-rs
cargo build --release
cargo test --release --lib
```

## Before opening a PR

```sh
cargo build --release
cargo test --release --lib
cargo clippy --all-targets
cargo fmt
```

GitHub Actions (`.github/workflows/ci.yml`) runs build + test on every
PR automatically; `clippy`/`fmt` currently run informationally rather
than gating (see that workflow's comments), but please run them locally
and fix what they flag anyway.

If you touch anything in `crypto.rs`, `protocol.rs`, `tunnel.rs`, or
`control.rs` -- i.e. anything on the network-facing data path -- please
think specifically about what an unauthenticated remote sender (someone
with no valid Noise key, just the ability to send UDP packets to a
listening port) could do with your change, and what a malicious
*authenticated* peer could do beyond its intended trust boundary. See
`SECURITY.md` for the exact threat model and `CHANGELOG.md`'s `[0.1.1]`
"Security" entries for worked examples of the kind of issue that matters
here (state committed before authentication, fail-open checks, TOCTOU on
file permissions, unbounded resource use keyed by attacker-controlled
values).

## Commit / PR expectations

- Add a `CHANGELOG.md` entry under `[Unreleased]` (create that section
  if it doesn't exist yet) describing the change from a user's
  perspective -- Added/Changed/Fixed/Security, matching the existing
  entries' format.
- Keep `debian/changelog` and `Cargo.toml`'s `version` in sync when
  cutting a release; see the existing entries for the expected format.
  Day-to-day PRs don't need to bump the version themselves.
- New wire-protocol frame types or config fields should stay
  backward-compatible where practical (see `protocol.rs`'s doc comment
  on `PacketType::StatsShare` for what "an old build silently drops an
  unrecognized frame type" buys you) -- call out explicitly in the PR
  description if a change can't be.
- Prefer a focused PR over a large one; this is a security-sensitive
  daemon, and small diffs are much easier to review carefully.

## Reporting bugs vs. vulnerabilities

Regular bugs: open a GitHub issue using the bug report template.
Suspected security vulnerabilities: do **not** open a public issue --
see `SECURITY.md` for private reporting channels.
