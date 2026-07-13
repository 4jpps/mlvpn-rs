# Security Policy

mlvpn-rs is a network-facing VPN daemon handling encrypted tunnel
traffic between two peers. Its Noise_IK handshake, AEAD transport, replay
protection, and privilege-dropping behavior are all security-critical --
please report suspected vulnerabilities responsibly rather than opening a
public issue.

## Supported versions

Only the latest `0.1.x` release is supported. This project is pre-1.0;
there is no long-term-support branch, and fixes land as new `0.1.x`
releases rather than backports.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1.0 | No        |

## Reporting a vulnerability

Preferred: open a
[GitHub Security Advisory](https://github.com/4jpps/mlvpn-rs/security/advisories/new)
for this repository (Security tab -> "Report a vulnerability"). This
creates a private discussion visible only to maintainers until a fix is
ready.

Alternative: email **security reports to Jeff Parrish PC Services**
via [www.jpps.us](https://www.jpps.us) with "mlvpn-rs security" in the
subject. Please include:

- Affected version/commit.
- A description of the issue and its impact (what an attacker can do,
  and what they need -- e.g. network position, valid keys, local access).
- Steps to reproduce, or a proof-of-concept if you have one.

Please do not open a public GitHub issue for a suspected vulnerability
until a fix has been released and you've coordinated disclosure with us.

## What counts as a security issue here

Given the threat model in `ARCHITECTURE.md` (two pre-configured peers,
pinned public keys, no multi-client server mode), the highest-value
reports are:

- Anything exploitable by an **unauthenticated remote sender** (someone
  who can send UDP packets to a listening port but holds no valid Noise
  static key for either peer) -- authentication bypass, crash/DoS,
  memory-safety issues, replay-protection bypass, or resource exhaustion.
- Anything a **malicious authenticated peer** (a compromised or
  misbehaving remote end that *does* hold valid keys) could do beyond
  its intended trust boundary -- e.g. escalate beyond "send/receive
  tunnel traffic and observe its own link stats."
- Privilege-drop or systemd-hardening gaps that leave the daemon more
  privileged than `ARCHITECTURE.md` §8 describes.
- Local issues on the monitoring control socket (`control.rs`) --
  though note by design it's read-only and exposes no key material, so
  its severity ceiling is lower than the wire-protocol issues above.

Denial-of-service reports are welcome, but please include a realistic
assessment of attacker cost vs. impact -- see `CHANGELOG.md`'s
`[0.1.1]` "Security" section for examples of the kind of finding and
writeup that's useful (a prior internal review's fixes are documented
there).

## Response expectations

This is maintained by a small team, not a dedicated security org --
please expect an initial response within a few days, not hours. Fixes
for confirmed high-severity issues are prioritized over everything else
in the backlog.
