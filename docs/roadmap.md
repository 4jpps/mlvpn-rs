# Roadmap: QUIC as a link transport

**Status: planning only -- nothing in this document is implemented.**
Everything else this document used to track (closing out
`ARCHITECTURE.md`'s former "known limitations" list, and periodic
tunnel auto-tuning) has since shipped -- see
[CHANGELOG.md](../CHANGELOG.md) for what and when, and
[ARCHITECTURE.md](../ARCHITECTURE.md) for how each behaves today. QUIC
is the one deliberately deferred exception, planned for a future
release rather than this one, so this document is now scoped to it
alone.

## What QUIC would actually buy this project

QUIC (RFC 9000) is UDP-based, so it doesn't change the fundamental
"binds to an interface, sends datagrams" shape of `link.rs` -- it
replaces what rides on top of that socket. Three properties are
directly relevant here:

- **Per-path loss recovery and congestion control that's already
  correct.** Right now this project's own reliability story is "don't
  bother" -- `Data` frames are fire-and-forget UDP, and the tunnel
  tolerates loss/reordering at the bonding layer (`ReorderBuffer`, see
  `ARCHITECTURE.md` §7) rather than retransmitting anything itself,
  which is the right call for a tunnel carrying arbitrary IP traffic
  (TCP inside the tunnel already retransmits; retransmitting twice is
  wasteful). QUIC wouldn't change that calculus for `Data` frames.
  Where it would help is the **`Probe`/`ProbeReply`/`StatsShare`/
  `HandshakeInit` control traffic** -- currently hand-rolled UDP with
  no framing guarantees beyond what `protocol.rs` implements itself. A
  QUIC stream for control traffic gets ordered, reliable delivery and
  loss detection for free.
- **TLS 1.3 as the transport security, instead of layering our own.**
  QUIC mandates TLS 1.3 for its handshake. This project currently runs
  `Noise_IK` directly over raw UDP (see `ARCHITECTURE.md` §4). Moving
  to QUIC raises a real design question addressed below, not a free
  upgrade.
- **0-RTT reconnection and connection migration.** A QUIC connection
  survives its endpoint's IP address changing mid-connection (the
  mechanism mobile clients rely on switching Wi-Fi to cellular).
  Tempting to read as "solves the same problem `SO_BINDTODEVICE`
  solves," but it's a different mechanism solving a different half of
  it -- see below.

## Migration is not multipath -- this distinction drives the whole design

QUIC connection migration is **single-path**: a connection has one
active path at a time and can *switch* which path that is when the
old one breaks or a better one appears. That's valuable (see below)
but it is not what this project needs at its core, which is *using
several paths simultaneously* and blending their throughput --
exactly what `scheduler.rs`'s SWRR implementation already does over
plain UDP.

There is a real IETF draft for **multipath QUIC**
(`draft-ietf-quic-multipath`, currently at revision -21 as of mid-2026,
adopted by the QUIC working group, not yet an RFC) that adds explicit
per-path packet number spaces and connection IDs so a single QUIC
connection can use multiple paths concurrently -- conceptually much
closer to what this project actually wants. Rust ecosystem support for
it is immature enough to rule it out for now:

- **`quinn`** (the tokio-native, idiomatic-Rust QUIC implementation,
  and the obvious first choice for a codebase already built on tokio)
  has an open tracking issue (`quinn-rs/quinn#224`) and no shipped
  multipath support; third-party fork work exists (n0-computer) but
  nothing merged or released as of this writing.
- **`quiche`** (Cloudflare's implementation, C-API-shaped with Rust
  bindings) has made real progress -- `set_multipath()`,
  `is_multipath_enabled()`, `send_on_path()`, `path_stats()` exist on
  a merged branch -- but it's a lower-level, poll/FFI-oriented API
  that doesn't integrate with tokio the way this codebase is written;
  adopting it would mean building our own async wrapper around it, a
  substantial undertaking on its own.
- **`s2n-quic`** (AWS): no multipath status found; not evaluated
  further here.

Building this project's core value proposition on top of an IETF draft
still 6+ months (optimistically) from RFC status, implemented by a
library with an open-not-started tracking issue, would be building on
sand. **Recommendation: do not wait for or adopt multipath QUIC.**

## The recommended design: QUIC per link, bonding stays ours

Give each configured `[[links]]` entry a `transport = "udp" | "quic"`
option (default `"udp"`, fully backward compatible). When a link is
`quic`, `link::Link::bind` opens a `quinn::Endpoint` bound to that
link's interface/port instead of a raw `UdpSocket`, and dials (or
accepts) a single QUIC connection to the peer over that path. Nothing
about `scheduler.rs`, `monitor.rs`, or the reorder buffer changes --
they already treat each link as an opaque scored channel; a QUIC
connection is just a different kind of channel underneath.

What rides on the QUIC connection, mapped onto the existing wire
protocol:

- **Control traffic** (`Probe`/`ProbeReply`/`StatsShare`,
  `HandshakeInit`/`HandshakeResp`) moves onto a dedicated
  bidirectional QUIC stream per link, gaining reliable, ordered
  delivery for free -- directly closes part of the fragility in
  today's raw-UDP probe/stats channel (a lost `StatsShare` frame today
  just means one stale sample; not a correctness issue, but a QUIC
  stream removes the question).
- **`Data` frames** ride QUIC datagrams (RFC 9221, an unreliable,
  unordered extension QUIC explicitly supports for exactly this kind
  of use case: not everything wants TCP-like guarantees), preserving
  today's fire-and-forget semantics and avoiding head-of-line blocking
  from QUIC's own stream ordering guarantees, which would otherwise
  fight with the bonding layer's own reordering tolerance.
- **Encryption layering is the open design question.** Two options,
  worth deciding deliberately rather than defaulting into one:
  1. **QUIC's TLS 1.3 replaces Noise_IK entirely** for `quic`-transport
     links. Means maintaining two auth/session models side by side
     (Noise for `udp` links, TLS for `quic` links) unless UDP support
     is dropped outright, and requires rethinking the peer-pinning
     model (Noise's explicit static-key pin) in terms of TLS
     certificates or a raw-public-key/PSK mode -- `rustls` supports
     raw public keys (RFC 7250), which maps reasonably cleanly onto
     the existing "pin the peer's known key" posture without needing a
     CA.
  2. **Noise_IK keeps running as an inner session inside a QUIC
     stream**, with QUIC providing only transport-level loss
     recovery/congestion control and TLS providing nothing this
     project actually relies on (defense in depth against a QUIC
     implementation bug, at the cost of double encryption overhead).
     Keeps one auth model for both transports, at the cost of not
     using QUIC for what it's best at.

  Leaning toward **option 1** for `quic` links specifically (simpler,
  uses QUIC as intended, `rustls` raw-public-key support avoids
  needing a CA/cert-management story) but this needs a real decision
  before implementation starts, not a default.

## What this does and doesn't solve

Does: gives operators an alternative transport that may traverse
DPI-hostile or DPI-throttled networks better (QUIC looks like ordinary
HTTP/3 traffic; some ISPs and firewalls that rate-limit or drop
unrecognized UDP treat QUIC differently), gets better loss recovery on
individual lossy links (e.g. a marginal LTE connection) than
hand-rolled UDP ever will, and removes a whole class of "did the probe
frame actually get lost or did I mis-parse it" hardening work from
`protocol.rs` for the control channel specifically.

Doesn't: replace `scheduler.rs`'s bonding logic (still needed, still
ours), or remove `link.rs`'s per-interface binding requirement
(`quinn`'s `Endpoint::new` still needs a socket bound the same way
today's does). Per-link IPv4/IPv6 selection (shipped for the `udp`
transport, see `ARCHITECTURE.md` §6) will need the same treatment for
`quic` links whenever this is built -- `link::socket_domain`'s
approach should carry over directly rather than needing to be
redesigned.

## Suggested sequencing

1. Prototype a `quic` transport for a *single* link (no bonding
   interaction yet) to validate the `quinn`-over-`SO_BINDTODEVICE`
   integration and settle the encryption-layering question above.
2. Wire `Data` frames onto QUIC datagrams once the prototype proves
   out loss/reordering behavior is acceptable for the bonding layer.
3. Move control traffic (`Probe`/`StatsShare`) onto QUIC streams.
4. Only then consider mixed-transport tunnels (some links `udp`, some
   `quic`) as a supported, tested configuration -- not a side effect
   of adding the option.

---

Sources consulted: [draft-ietf-quic-multipath-21](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath), [quicwg/multipath](https://github.com/quicwg/multipath), [quinn-rs/quinn#224](https://github.com/quinn-rs/quinn/issues/224), [cloudflare/quiche#278](https://github.com/cloudflare/quiche/issues/278), [cloudflare/quiche#1310](https://github.com/cloudflare/quiche/pull/1310).
