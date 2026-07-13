---
name: Bug report
about: Something isn't working as expected
title: ""
labels: bug
assignees: ""
---

**Are you sure this isn't a security vulnerability?**
If it involves an unauthenticated remote sender causing a crash/DoS, a
way to bypass the peer authentication or replay protection, or anything
else in `SECURITY.md`'s scope, please report it privately instead --
see `SECURITY.md` -- rather than filing a public issue.

**Describe the bug**
A clear description of what's wrong.

**To reproduce**
Steps to reproduce, ideally including the relevant `[[links]]`/config
shape (redact real IPs/keys) and whether this is `client` or `server`
mode.

**Expected behavior**
What you expected to happen instead.

**Environment**
- `mlvpnd --version` output:
- OS / kernel version (`uname -a`):
- Installed via: `.deb` package / `cargo build` from source
- Running under systemd, or manually?

**Logs**
Relevant `journalctl -u mlvpn` (or stderr) output. Run with
`[logging] level = "debug"` if the default `info` level doesn't show
enough detail. Please redact IP addresses/public keys you don't want
public if this is a public issue.

**Additional context**
Anything else that might help -- network topology, whether this
reproduces consistently, etc.
