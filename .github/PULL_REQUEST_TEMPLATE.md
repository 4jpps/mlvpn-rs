## What does this change?

<!-- Brief description of the change and why it's needed. -->

## Checklist

- [ ] `cargo build --release` succeeds
- [ ] `cargo test --release --lib` passes
- [ ] `cargo clippy --all-targets` and `cargo fmt` were run locally
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (Added/Changed/Fixed/Security)
- [ ] If this touches `crypto.rs`, `protocol.rs`, `tunnel.rs`, or
      `control.rs`: I considered what an unauthenticated remote sender
      or a malicious authenticated peer could do with this change (see
      `SECURITY.md` / `CONTRIBUTING.md`)
- [ ] If this changes the wire protocol or config schema: backward
      compatibility considered and called out below if it isn't

## Security-relevant?

<!--
If this PR touches the network-facing data path, briefly note what you
checked -- e.g. "new field is length-validated before being sliced",
"new state is only committed after AEAD auth succeeds". If not
applicable, just say so.
-->
