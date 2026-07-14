//! TCP MSS clamping for packets transiting the TUN device.
//!
//! Path MTU Discovery (RFC 1191/8201) is how TCP normally learns to
//! avoid fragmentation: a router along the path that can't forward an
//! over-sized packet without fragmenting it sends back an ICMP
//! "Fragmentation Needed" (IPv4) or "Packet Too Big" (IPv6) message, and
//! the sending TCP stack lowers its segment size in response. In
//! practice this mechanism is unreliable on the open internet -- some
//! middleboxes and firewalls drop the relevant ICMP messages outright
//! (sometimes deliberately, sometimes as an overly broad "drop all
//! ICMP" policy), which leaves the sender never finding out its packets
//! are being silently dropped. The connection doesn't just run slower
//! in that failure mode, it stalls completely: this is the classic
//! "PMTUD black hole."
//!
//! A tunnel is exactly the situation where this bites hardest, because
//! the effective MTU inside the tunnel is *lower* than a typical
//! physical-link MTU (this protocol's header + AEAD tag + outer UDP/IP
//! overhead, subtracted in `main.rs`'s `effective_tunnel_mtu()`), so
//! paths that worked fine outside the tunnel can black-hole once
//! traffic goes through it.
//!
//! The standard fix (the same one `iptables --clamp-mss-to-pmtu` and
//! most consumer VPN/router firmware apply) is to stop relying on PMTUD
//! for TCP entirely: rewrite the MSS option in TCP SYN and SYN-ACK
//! segments so both ends of the connection negotiate a segment size
//! that already fits, before either side ever sends a full-size
//! segment. This module does exactly that to plaintext packets read off
//! the TUN device (see `tunnel.rs`'s `tun_reader`), for both IPv4 and
//! IPv6. Controlled by `config.rs`'s `tunnel.clamp_mss` (on by default).
//!
//! Deliberately conservative about what it touches: anything that
//! doesn't parse as a well-formed TCP SYN or SYN-ACK segment (wrong
//! protocol, truncated packet, unsupported IPv6 extension header chain)
//! is left completely untouched and passed through as-is. Getting this
//! wrong in the direction of "clamp something we shouldn't have" risks
//! corrupting a packet; getting it wrong in the direction of "miss a
//! packet we could have clamped" just means that one connection falls
//! back to relying on PMTUD same as before this module existed -- a
//! strictly smaller downside, so every parsing step below fails closed
//! into "don't touch it."

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_OPT_END: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;
const IPV6_HEADER_LEN: usize = 40;
const PROTO_TCP: u8 = 6;

/// Entry point: given a plaintext IP packet as read off the TUN device
/// and the effective tunnel MTU (the max size of a *whole* IP packet,
/// header included -- the same meaning as an interface MTU), rewrite
/// its TCP MSS option in place if (and only if) it is a TCP SYN or
/// SYN-ACK segment whose advertised MSS is larger than what `mtu` can
/// actually carry. No-op for everything else, including
/// malformed/truncated input -- see the module doc comment on why that
/// direction of error is the safe one.
pub fn clamp_if_tcp_syn(packet: &mut [u8], mtu: u16) {
    let Some(&first) = packet.first() else {
        return;
    };
    match first >> 4 {
        4 => clamp_ipv4(packet, mtu),
        6 => clamp_ipv6(packet, mtu),
        _ => {} // unrecognized IP version; not our concern
    }
}

fn clamp_ipv4(packet: &mut [u8], mtu: u16) {
    if packet.len() < 20 {
        return;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl + 20 {
        return;
    }
    if packet[9] != PROTO_TCP {
        return;
    }

    let tcp_start = ihl;
    let Some(tcp_header_len) = tcp_header_len(&packet[tcp_start..]) else {
        return;
    };
    if packet.len() < tcp_start + tcp_header_len {
        return;
    }

    let max_segment = match (mtu as usize)
        .checked_sub(ihl)
        .and_then(|v| v.checked_sub(tcp_header_len))
    {
        Some(v) if v > 0 => v as u16,
        _ => return, // mtu too small to carry even an empty segment; leave alone
    };

    let clamped = rewrite_mss_if_syn(
        &mut packet[tcp_start..tcp_start + tcp_header_len],
        max_segment,
    );
    if !clamped {
        return;
    }

    let src = packet[12..16].to_vec();
    let dst = packet[16..20].to_vec();
    let checksum = tcp_checksum_v4(&src, &dst, &packet[tcp_start..]);
    packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
}

fn clamp_ipv6(packet: &mut [u8], mtu: u16) {
    if packet.len() < IPV6_HEADER_LEN {
        return;
    }
    // Deliberately does not walk IPv6 extension headers -- a TCP SYN
    // preceded by extension headers is rare in practice, and getting
    // extension-header traversal wrong risks misidentifying some other
    // protocol's payload as a TCP header. Any next_header other than
    // TCP directly is left untouched (see module doc comment on failing
    // closed).
    if packet[6] != PROTO_TCP {
        return;
    }

    let tcp_start = IPV6_HEADER_LEN;
    let Some(tcp_header_len) = tcp_header_len(&packet[tcp_start..]) else {
        return;
    };
    if packet.len() < tcp_start + tcp_header_len {
        return;
    }

    // `mtu` is the whole IP packet's size budget (fixed header
    // included); the available TCP-segment budget is whatever's left
    // after that fixed 40-byte IPv6 header and the TCP header/options.
    let max_segment = match (mtu as usize)
        .checked_sub(IPV6_HEADER_LEN)
        .and_then(|v| v.checked_sub(tcp_header_len))
    {
        Some(v) if v > 0 => v as u16,
        _ => return,
    };

    let clamped = rewrite_mss_if_syn(
        &mut packet[tcp_start..tcp_start + tcp_header_len],
        max_segment,
    );
    if !clamped {
        return;
    }

    let src = packet[8..24].to_vec();
    let dst = packet[24..40].to_vec();
    let checksum = tcp_checksum_v6(&src, &dst, &packet[tcp_start..]);
    packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
}

/// Parses the TCP data-offset field (top nibble of byte 12 of the TCP
/// header) into a byte length. Returns `None` if the slice is too short
/// to even contain a fixed 20-byte TCP header, or the data offset is
/// smaller than that -- both indicate a malformed or truncated segment,
/// not a real TCP header.
fn tcp_header_len(tcp: &[u8]) -> Option<usize> {
    if tcp.len() < 20 {
        return None;
    }
    let len = ((tcp[12] >> 4) as usize) * 4;
    if len < 20 {
        None
    } else {
        Some(len)
    }
}

/// If `tcp_header` (the full TCP header *including* options, i.e.
/// `tcp[..tcp_header_len]`) is a SYN segment carrying an MSS option
/// whose value exceeds `max_segment`, rewrites that option's value down
/// to `max_segment` in place and returns `true` (meaning: the caller
/// still needs to recompute the checksum, since this function only
/// touches the option bytes). Returns `false` -- and leaves the header
/// completely untouched -- for anything else: not a SYN, no MSS option
/// present, or an MSS option that's already small enough.
fn rewrite_mss_if_syn(tcp_header: &mut [u8], max_segment: u16) -> bool {
    if tcp_header.len() < 20 {
        return false;
    }
    if tcp_header[13] & TCP_FLAG_SYN == 0 {
        return false;
    }

    let mut i = 20;
    while i < tcp_header.len() {
        match tcp_header[i] {
            TCP_OPT_END => break,
            TCP_OPT_NOP => i += 1,
            TCP_OPT_MSS => {
                // Kind(1) + Length(1) + Value(2) = 4 bytes total; bail
                // if what's left doesn't actually hold that much (a
                // truncated/malformed option list) rather than reading
                // out of bounds.
                if i + 4 > tcp_header.len() || tcp_header[i + 1] != 4 {
                    return false;
                }
                let current = u16::from_be_bytes([tcp_header[i + 2], tcp_header[i + 3]]);
                if current <= max_segment {
                    return false; // already fits; nothing to do
                }
                tcp_header[i + 2..i + 4].copy_from_slice(&max_segment.to_be_bytes());
                return true;
            }
            _ => {
                // Any other option kind: byte i+1 is its length
                // (including the kind/length bytes themselves), per
                // RFC 793. Skip past it, or bail if that length is
                // missing/zero/would run past the end -- a malformed
                // option list, not one we can safely keep walking.
                if i + 1 >= tcp_header.len() {
                    return false;
                }
                let opt_len = tcp_header[i + 1] as usize;
                if opt_len < 2 || i + opt_len > tcp_header.len() {
                    return false;
                }
                i += opt_len;
            }
        }
    }
    false
}

/// RFC 1071 Internet checksum over an arbitrary byte slice: sum of
/// 16-bit big-endian words (a trailing odd byte, if any, is padded with
/// a zero low byte), with carries folded back in, then one's
/// complemented. Used both to compute a checksum to write (called with
/// the checksum field zeroed) and, in this module's tests, to verify
/// one (called with the real field in place, which sums to exactly 0
/// when the checksum is correct) -- both are the same algorithm, just
/// used at different points.
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP checksum over an IPv4 pseudo-header (RFC 793 §3.1) plus the TCP
/// segment. `tcp_segment`'s existing checksum bytes (offset 16..18) are
/// zeroed out inside this function's own scratch copy before summing,
/// so callers don't need to pre-zero the real packet themselves.
fn tcp_checksum_v4(src: &[u8], dst: &[u8], tcp_segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp_segment.len());
    buf.extend_from_slice(src);
    buf.extend_from_slice(dst);
    buf.push(0); // reserved
    buf.push(PROTO_TCP);
    buf.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(tcp_segment);
    // Zero the checksum field in our scratch copy -- it must not
    // include its own prior value when summed.
    let cksum_at = 12 + 16;
    buf[cksum_at] = 0;
    buf[cksum_at + 1] = 0;
    internet_checksum(&buf)
}

/// TCP checksum over an IPv6 pseudo-header (RFC 8200 §8.1) plus the TCP
/// segment. Same checksum-field-zeroing behavior as `tcp_checksum_v4`.
fn tcp_checksum_v6(src: &[u8], dst: &[u8], tcp_segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + tcp_segment.len());
    buf.extend_from_slice(src);
    buf.extend_from_slice(dst);
    buf.extend_from_slice(&(tcp_segment.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0]); // reserved
    buf.push(PROTO_TCP); // next header
    buf.extend_from_slice(tcp_segment);
    let cksum_at = 40 + 16;
    buf[cksum_at] = 0;
    buf[cksum_at + 1] = 0;
    internet_checksum(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_syn(mss: u16) -> Vec<u8> {
        let tcp_header_len = 24; // 20 fixed + 4-byte MSS option
        let mut pkt = vec![0u8; 20 + tcp_header_len];

        pkt[0] = 0x45; // version 4, IHL 5 (20 bytes)
        pkt[9] = PROTO_TCP;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst

        let t = 20;
        pkt[t + 12] = ((tcp_header_len / 4) as u8) << 4; // data offset
        pkt[t + 13] = TCP_FLAG_SYN;
        pkt[t + 20] = TCP_OPT_MSS;
        pkt[t + 21] = 4;
        pkt[t + 22..t + 24].copy_from_slice(&mss.to_be_bytes());

        // Fill in a correct initial checksum so the packet is
        // well-formed before we ever call the function under test.
        let src = pkt[12..16].to_vec();
        let dst = pkt[16..20].to_vec();
        let cksum = tcp_checksum_v4(&src, &dst, &pkt[t..]);
        pkt[t + 16..t + 18].copy_from_slice(&cksum.to_be_bytes());

        pkt
    }

    fn build_ipv6_syn(mss: u16) -> Vec<u8> {
        let tcp_header_len = 24;
        let mut pkt = vec![0u8; IPV6_HEADER_LEN + tcp_header_len];

        pkt[0] = 0x60; // version 6
        let payload_len = tcp_header_len as u16;
        pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
        pkt[6] = PROTO_TCP; // next header
        pkt[7] = 64; // hop limit
        pkt[8..24].copy_from_slice(&[0xfd; 16]); // src
        pkt[24..40].copy_from_slice(&[0xfe; 16]); // dst

        let t = IPV6_HEADER_LEN;
        pkt[t + 12] = ((tcp_header_len / 4) as u8) << 4;
        pkt[t + 13] = TCP_FLAG_SYN;
        pkt[t + 20] = TCP_OPT_MSS;
        pkt[t + 21] = 4;
        pkt[t + 22..t + 24].copy_from_slice(&mss.to_be_bytes());

        let src = pkt[8..24].to_vec();
        let dst = pkt[24..40].to_vec();
        let cksum = tcp_checksum_v6(&src, &dst, &pkt[t..]);
        pkt[t + 16..t + 18].copy_from_slice(&cksum.to_be_bytes());

        pkt
    }

    #[test]
    fn clamps_oversized_ipv4_mss_and_fixes_checksum() {
        let mut pkt = build_ipv4_syn(1460);
        // ihl(20) + tcp_header_len(24) = 44; mtu 100 => max_segment = 56
        clamp_if_tcp_syn(&mut pkt, 100);

        let mss = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert_eq!(mss, 56);

        // Self-verifying checksum: summing the whole pseudo-header +
        // segment, including the checksum field we just wrote, should
        // fold to exactly 0 when the checksum is correct.
        let src = pkt[12..16].to_vec();
        let dst = pkt[16..20].to_vec();
        let mut verify_buf = Vec::new();
        verify_buf.extend_from_slice(&src);
        verify_buf.extend_from_slice(&dst);
        verify_buf.push(0);
        verify_buf.push(PROTO_TCP);
        verify_buf.extend_from_slice(&((pkt.len() - 20) as u16).to_be_bytes());
        verify_buf.extend_from_slice(&pkt[20..]);
        assert_eq!(internet_checksum(&verify_buf), 0);
    }

    #[test]
    fn leaves_small_enough_mss_untouched() {
        let mut pkt = build_ipv4_syn(40);
        let before = pkt.clone();
        clamp_if_tcp_syn(&mut pkt, 100); // max_segment would be 56; 40 already fits
        assert_eq!(pkt, before);
    }

    #[test]
    fn leaves_non_syn_untouched() {
        let mut pkt = build_ipv4_syn(1460);
        pkt[20 + 13] = 0x10; // ACK only, no SYN
        let before = pkt.clone();
        clamp_if_tcp_syn(&mut pkt, 100);
        assert_eq!(pkt, before);
    }

    #[test]
    fn leaves_non_tcp_untouched() {
        let mut pkt = build_ipv4_syn(1460);
        pkt[9] = 17; // UDP, not TCP
        let before = pkt.clone();
        clamp_if_tcp_syn(&mut pkt, 100);
        assert_eq!(pkt, before);
    }

    #[test]
    fn clamps_oversized_ipv6_mss_and_fixes_checksum() {
        let mut pkt = build_ipv6_syn(1440);
        // budget = mtu - 40 - tcp_header_len(24); mtu 100 => 36
        clamp_if_tcp_syn(&mut pkt, 100);

        let mss = u16::from_be_bytes([pkt[40 + 22], pkt[40 + 23]]);
        assert_eq!(mss, 36);

        let src = pkt[8..24].to_vec();
        let dst = pkt[24..40].to_vec();
        let mut verify_buf = Vec::new();
        verify_buf.extend_from_slice(&src);
        verify_buf.extend_from_slice(&dst);
        verify_buf.extend_from_slice(&((pkt.len() - 40) as u32).to_be_bytes());
        verify_buf.extend_from_slice(&[0, 0, 0, PROTO_TCP]);
        verify_buf.extend_from_slice(&pkt[40..]);
        assert_eq!(internet_checksum(&verify_buf), 0);
    }

    #[test]
    fn ipv6_next_header_other_than_tcp_untouched() {
        let mut pkt = build_ipv6_syn(1440);
        pkt[6] = 17; // UDP, not TCP
        let before = pkt.clone();
        clamp_if_tcp_syn(&mut pkt, 100);
        assert_eq!(pkt, before);
    }

    #[test]
    fn truncated_packet_does_not_panic() {
        let mut pkt = vec![0x45u8, 0, 0, 0]; // version 4, way too short
        clamp_if_tcp_syn(&mut pkt, 1400);
    }

    #[test]
    fn empty_packet_does_not_panic() {
        let mut pkt: Vec<u8> = vec![];
        clamp_if_tcp_syn(&mut pkt, 1400);
    }

    #[test]
    fn mtu_too_small_for_headers_leaves_packet_untouched() {
        let mut pkt = build_ipv4_syn(1460);
        let before = pkt.clone();
        clamp_if_tcp_syn(&mut pkt, 10); // smaller than ihl + tcp_header_len alone
        assert_eq!(pkt, before);
    }
}
