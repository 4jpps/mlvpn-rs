//! Pure XOR single-erasure FEC logic -- no networking, no async. See
//! `docs/superpowers/specs/2026-09-15-single-erasure-fec-design.md` for
//! the full design. `tunnel.rs` owns the actual send/receive plumbing
//! that drives `FecSender`/`FecRecoveryBuffer`; this module only knows
//! how to accumulate/reconstruct, kept separate so both halves of the
//! algorithm are testable without spinning up any real sockets or TUN
//! devices.

use crate::protocol::FecParityPayload;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Sender-side accumulator: XORs sequential real Data frames' plaintext
/// together into one parity share per `group_size` frames. Owned by
/// whichever task drives the outgoing Data path (`tunnel::outbound_sender`)
/// -- one instance per tunnel, since groups span both links by design
/// (see the design doc's Architecture section for why sequential-order
/// grouping, not per-link grouping, is what makes cross-link survival
/// work at all).
///
/// Known limitation, deliberately not fixed with a timer-based flush:
/// a group that stops accumulating mid-way (traffic pauses after, say,
/// 5 of 8 members) never emits a parity frame at all, so the frames
/// sitting in that partial group stay unprotected until enough further
/// traffic arrives to complete it. Adding an idle-flush timer would mean
/// emitting parity for a group whose own size the receiver learns only
/// from the wire (it already does -- `FecParityPayload` is
/// self-describing), so it is implementable, but it needs its own
/// careful timeout design and would add a timer + shared-state path to
/// the hottest send loop in the daemon for a case that matters least:
/// an idle tunnel is exactly when a lost packet costs the least. FEC
/// here is aimed at sustained bulk traffic, where groups complete
/// continuously and this gap never appears.
///
/// This deferral is safe on the receive side regardless of how long a
/// partial group sits open: `FecRecoveryBuffer`'s `seen_floor` makes an
/// arbitrarily old group's already-delivered members classify as
/// `Handled`, never as a recoverable erasure, so an unbounded group
/// lifetime costs at most a missed recovery -- never a duplicate
/// delivery.
pub struct FecSender {
    group_size: usize,
    member_seqs: Vec<u64>,
    member_lens: Vec<u16>,
    parity: Vec<u8>,
}

impl FecSender {
    pub fn new(group_size: u8) -> Self {
        Self {
            group_size: group_size as usize,
            member_seqs: Vec::with_capacity(group_size as usize),
            member_lens: Vec::with_capacity(group_size as usize),
            parity: Vec::new(),
        }
    }

    /// Feed one real Data frame's `seq` and plaintext into the current
    /// group. Returns the completed group's parity payload exactly when
    /// this call was the group's last member -- `None` otherwise. Starts
    /// a fresh, empty group immediately after returning `Some`.
    pub fn accumulate(&mut self, seq: u64, plaintext: &[u8]) -> Option<FecParityPayload> {
        if plaintext.len() > self.parity.len() {
            self.parity.resize(plaintext.len(), 0);
        }
        for (i, &byte) in plaintext.iter().enumerate() {
            self.parity[i] ^= byte;
        }
        self.member_seqs.push(seq);
        // `as u16` is safe for every frame this can ever see: the source
        // is a single read off the TUN device, whose own MTU is the
        // tunnel MTU (<= 65535 by the type of `LiveMtu`, and in practice
        // ~1400), so a frame long enough to wrap 16 bits cannot exist
        // here. Asserted rather than checked at runtime so a future
        // change that breaks the assumption fails loudly in tests/debug
        // builds instead of silently truncating a member length.
        debug_assert!(
            plaintext.len() <= u16::MAX as usize,
            "FEC member frame longer than u16::MAX -- tunnel MTU invariant broken"
        );
        self.member_lens.push(plaintext.len() as u16);

        if self.member_seqs.len() < self.group_size {
            return None;
        }

        let payload = FecParityPayload {
            member_seqs: std::mem::take(&mut self.member_seqs),
            member_lens: std::mem::take(&mut self.member_lens),
            parity: std::mem::take(&mut self.parity),
        };
        Some(payload)
    }
}

/// Bytes a `FecParity` frame's payload costs *beyond* the longest Data
/// frame plaintext it covers: `FecParityPayload::encode` writes one
/// `group_size` byte, then 8 bytes of `seq` plus 2 bytes of `len` per
/// member, then a 2-byte parity-length prefix, then the parity bytes
/// themselves (as long as the group's longest member).
///
/// This is what `control::effective_tunnel_mtu` reserves when
/// `scheduler.fec_enabled` is set: without it, a parity frame covering
/// a group of full-MTU frames is systematically larger than the path
/// MTU (83 bytes larger at the default `fec_group_size = 8`), so every
/// parity frame protecting real bulk traffic would either fragment or
/// fail to send -- and a fragmented parity frame needs *both* fragments
/// to survive, making it strictly less likely to arrive than the data
/// it exists to protect.
pub fn parity_frame_overhead_bytes(group_size: u8) -> u16 {
    1 + (group_size as u16) * 10 + 2
}

/// How much smaller the tunnel MTU has to be for this config's parity
/// frames to fit the same path budget a full-size Data frame does.
/// Zero when FEC is off, so a disabled tunnel's MTU is bit-for-bit what
/// it was before this feature existed.
pub fn mtu_reservation_bytes(cfg: &crate::config::SchedulerConfig) -> u16 {
    if cfg.fec_enabled {
        parity_frame_overhead_bytes(cfg.fec_group_size)
    } else {
        0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// Exactly one member was missing and has been reconstructed.
    Recovered { seq: u64, plaintext: Vec<u8> },
    /// Two or more members were missing, or a missing member's own
    /// group-mates are no longer reconstructible (their payloads have
    /// aged out) -- either way, nothing to deliver.
    Unrecoverable,
    /// Every member had already arrived directly -- the parity frame
    /// itself was unnecessary this time. Nothing to deliver.
    AlreadyComplete,
}

/// How long a received Data frame's plaintext is kept available for a
/// later same-group parity frame to XOR against. Deliberately a fixed,
/// FEC-specific value rather than `reorder_window_ms`: what matters
/// here is "how long after a group's last member does its parity frame
/// arrive," which is a function of group-fill time plus cross-link
/// delivery skew -- completely unrelated to the reorder window's own
/// auto-tuned 10-500ms range, and routinely much longer than its floor.
pub const PAYLOAD_TTL: Duration = Duration::from_secs(2);

/// Hard ceiling on retained plaintexts, so `PAYLOAD_TTL` can be
/// generous without the buffer's memory scaling with link rate: at a
/// real ~400 Mbps this is ~100ms of history (~5.7 MB at full MTU), and
/// on a slow link it never binds at all and the TTL governs instead.
const MAX_PAYLOADS: usize = 4096;

/// How often the "recently seen seq" generations rotate. Combined with
/// the two-generation scheme below, a seq is remembered for at least
/// this long and at most twice this long -- comfortably longer than
/// `PAYLOAD_TTL`, which is the invariant that keeps an aged-out member
/// classified as *known-arrived* rather than *missing*.
pub const SEEN_GENERATION: Duration = Duration::from_secs(2);

/// Hard ceiling per generation, same memory-vs-rate reasoning as
/// `MAX_PAYLOADS`. Deliberately far larger than `STALE_SEQ_WINDOW`, so
/// that any seq forgotten by this cap is already old enough for the
/// window check below to classify it correctly anyway.
const MAX_SEEN_PER_GENERATION: usize = 131_072;

/// A member seq more than this far behind the highest seq seen so far
/// is treated as already-handled rather than missing, even if it is no
/// longer in either `seen` generation.
///
/// This is a *rate-dependent* backstop and is deliberately no longer
/// the load-bearing one: on a busy tunnel it retires ancient seqs
/// promptly, but on a quiet tunnel 65536 seqs can take hours to elapse.
/// `FecRecoveryBuffer::seen_floor` is the rate-independent guarantee
/// that actually makes duplicate delivery impossible; this window is
/// kept because it is free and still fires first under bulk traffic.
/// Either way the hazard is the same: "not in the seen set" alone can
/// mean *forgotten*, and reconstructing a forgotten-but-already-
/// delivered frame would inject a byte-identical duplicate into the TUN
/// device (dup-ACKs -> spurious fast retransmit -- the exact behavior
/// this feature exists to reduce).
const STALE_SEQ_WINDOW: u64 = 65_536;

/// A seq this far *below* the highest seen is read as the peer having
/// restarted (`tunnel::next_send_seq` is a process-global counter that
/// restarts near zero on a fresh process) rather than as an ancient
/// straggler, and resets all tracking state. Without this, every
/// post-restart seq would sit below `STALE_SEQ_WINDOW` forever and FEC
/// would silently never recover anything again.
const SEQ_RESET_GAP: u64 = 1 << 24;

/// Receiver-side companion to `FecSender`. Tracks recently-arrived real
/// Data frames' plaintext by `seq`, so that when a `FecParity` frame
/// arrives, it can check which of that group's members are missing and
/// attempt reconstruction. Owned once per tunnel (shared across both
/// links' receive tasks), separate from `tunnel::ReorderBuffer` --
/// reconstruction happens first; a recovered frame is then fed into
/// `ReorderBuffer` exactly like a directly-received one, so nothing
/// downstream of that point needs any FEC awareness at all.
///
/// Two distinct kinds of state, with deliberately different lifetimes,
/// because conflating them is what made the first implementation of
/// this deliver duplicate packets:
///
/// - `payloads`: full plaintext, needed only to XOR a group back
///   together. Expensive (one `Vec` per packet), so bounded by both a
///   TTL and a hard count.
/// - `seen`: bare seq numbers, needed far longer -- both to recognize
///   an already-delivered frame arriving a second time (after FEC
///   already reconstructed it), and to keep a member whose *payload*
///   aged out from being misread as "missing" and therefore falsely
///   "recovered" into a duplicate delivery. Cheap, so it outlives the
///   payloads by design.
///
/// The ordering invariant that makes this correct: every seq in
/// `payloads` is also in `seen`, and `seen` retains for longer than
/// `payloads` does. So a member can be `Known` (payload available,
/// usable for XOR), `Handled` (seen, or too old to still be in flight,
/// but no payload -- group is not reconstructible), or `Missing` (never
/// seen and recent enough to genuinely still be outstanding). Only
/// exactly one `Missing` with zero `Handled` is recoverable.
///
/// `seen`'s retention is finite, though, so "not in `seen`" on its own
/// is ambiguous between *never arrived* and *arrived, then forgotten*.
/// `seen_floor` removes that ambiguity in sequence space rather than in
/// time: every seq a generation rotation forgets is provably at or
/// below the floor, so `member_state` can treat at-or-below-the-floor
/// as `Handled` unconditionally. That makes "forgotten" and "handled"
/// exactly equivalent at every packet rate and for any group lifetime,
/// which is what makes duplicate delivery impossible rather than merely
/// unlikely -- independently of `PAYLOAD_TTL`, `STALE_SEQ_WINDOW`, and
/// how long a sender-side group happens to stay open on a quiet link.
pub struct FecRecoveryBuffer {
    payload_ttl: Duration,
    seen_generation: Duration,
    /// Every recently-observed real Data frame's plaintext, keyed by its
    /// own `seq`, alongside when it was recorded.
    payloads: HashMap<u64, (Instant, Vec<u8>)>,
    /// Insertion order for `payloads`, so both TTL expiry and the hard
    /// count cap can evict oldest-first without scanning the map.
    payload_order: VecDeque<u64>,
    /// Current and previous generations of "seqs we have already
    /// accounted for" (arrived directly, or reconstructed and
    /// delivered). Rotating two sets is how a bounded-memory
    /// "remembered for at least `seen_generation`" is achieved without
    /// storing a timestamp per seq.
    seen_current: HashSet<u64>,
    seen_previous: HashSet<u64>,
    seen_rotated_at: Instant,
    /// Sequence-space floor beneath which "not in `seen`" provably means
    /// *forgotten by a rotation*, never *never-arrived*. Every seq a
    /// generation rotation discards was marked before the rotation
    /// before it, so it is by construction `<= highest_seq` as of that
    /// earlier rotation -- which is exactly the value kept here. See
    /// `rotate_seen`. `None` until two rotations have happened (nothing
    /// has been forgotten yet, so there is no floor to enforce).
    seen_floor: Option<u64>,
    /// `highest_seq` as of the most recent rotation. Becomes `seen_floor`
    /// at the next one, at which point the set it bounds is the one being
    /// dropped.
    seen_rotation_high: Option<u64>,
    /// Highest seq observed on any Data or parity frame -- the anchor
    /// for `STALE_SEQ_WINDOW`/`SEQ_RESET_GAP`.
    highest_seq: u64,
}

/// How a single group member looks to `try_recover`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberState {
    /// Arrived, and its plaintext is still available to XOR with.
    Known,
    /// Already accounted for (arrived earlier, or already reconstructed
    /// by an earlier copy of this parity frame, or simply too old to
    /// still be outstanding) but its plaintext is gone -- so this group
    /// can no longer be reconstructed, and this member must never be
    /// "recovered" again.
    Handled,
    /// Genuinely never seen and recent enough to still be a real loss.
    Missing,
}

impl FecRecoveryBuffer {
    pub fn new(group_size: u8) -> Self {
        Self::with_params(group_size, PAYLOAD_TTL, SEEN_GENERATION)
    }

    fn with_params(group_size: u8, payload_ttl: Duration, seen_generation: Duration) -> Self {
        // The only real use for the group-size hint: pre-size the map to
        // a few groups' worth so a steady stream of arrivals doesn't
        // rehash repeatedly at startup.
        let hint = (group_size as usize).saturating_mul(4).max(16);
        Self {
            payload_ttl,
            seen_generation,
            payloads: HashMap::with_capacity(hint),
            payload_order: VecDeque::with_capacity(hint),
            seen_current: HashSet::with_capacity(hint),
            seen_previous: HashSet::new(),
            seen_rotated_at: Instant::now(),
            seen_floor: None,
            seen_rotation_high: None,
            highest_seq: 0,
        }
    }

    /// Record a real Data frame's plaintext as it arrives, in case a
    /// same-group `FecParity` frame later needs it (either to confirm
    /// the group is already complete, or to reconstruct a *different*
    /// missing member).
    ///
    /// Returns whether the caller should actually deliver this frame:
    /// `false` means this exact seq has already been accounted for --
    /// almost always because FEC itself reconstructed and delivered it
    /// moments ago and the real copy has now turned up behind it (the
    /// normal, expected outcome whenever a parity frame overtakes a
    /// straggler on a slower link). Delivering it again would put a
    /// byte-identical duplicate IP packet into the TUN device.
    ///
    /// Only ever called when `scheduler.fec_enabled` is set -- with FEC
    /// off, nothing can recover a frame early, so nothing can duplicate
    /// one either, and the receive path skips this entirely.
    #[must_use]
    pub fn observe_data(&mut self, seq: u64, plaintext: &[u8]) -> bool {
        self.note_seq(seq);
        if self.seen_current.contains(&seq) || self.seen_previous.contains(&seq) {
            return false;
        }
        self.mark_seen(seq);
        self.insert_payload(seq, plaintext.to_vec());
        true
    }

    /// Given a just-arrived `FecParity` frame, determine and (if
    /// possible) perform recovery for its group. A `Recovered` seq is
    /// marked as handled before returning, so the real copy arriving
    /// afterwards is rejected by `observe_data` rather than delivered
    /// twice.
    pub fn try_recover(&mut self, parity: &FecParityPayload) -> RecoveryOutcome {
        if parity.member_seqs.len() != parity.member_lens.len() || parity.member_seqs.is_empty() {
            return RecoveryOutcome::Unrecoverable;
        }
        if let Some(&max) = parity.member_seqs.iter().max() {
            self.note_seq(max);
        }

        let mut missing_idx: Option<usize> = None;
        let mut missing_count = 0usize;
        let mut handled_count = 0usize;
        for (i, seq) in parity.member_seqs.iter().enumerate() {
            match self.member_state(*seq) {
                MemberState::Known => {}
                MemberState::Handled => handled_count += 1,
                MemberState::Missing => {
                    missing_count += 1;
                    if missing_idx.is_none() {
                        missing_idx = Some(i);
                    }
                }
            }
        }

        if missing_count == 0 {
            // Nothing outstanding. If some members are only `Handled`
            // (payload aged out) that is still "nothing to do" -- they
            // were delivered when they arrived.
            return RecoveryOutcome::AlreadyComplete;
        }
        if missing_count > 1 || handled_count > 0 {
            // More than one erasure, or one erasure whose group-mates
            // can no longer be XORed back together. Either way this
            // group is not reconstructible -- and crucially, we do NOT
            // guess: reconstructing against an incomplete set of
            // group-mates would produce garbage, and "recovering" a
            // member that was really just forgotten would produce a
            // duplicate.
            return RecoveryOutcome::Unrecoverable;
        }

        let missing_idx = missing_idx.expect("missing_count == 1 implies an index");
        let missing_seq = parity.member_seqs[missing_idx];
        let missing_len = parity.member_lens[missing_idx] as usize;
        if missing_len > parity.parity.len() {
            // Self-inconsistent frame (a member declared longer than the
            // parity share that is supposed to cover it). Authenticated,
            // so this means a peer bug rather than an attack, but there
            // is nothing recoverable here either way.
            return RecoveryOutcome::Unrecoverable;
        }

        let mut reconstructed = parity.parity.clone();
        for (i, seq) in parity.member_seqs.iter().enumerate() {
            if i == missing_idx {
                continue;
            }
            let Some((_, bytes)) = self.payloads.get(seq) else {
                // Unreachable given the classification above (every
                // non-missing member was `Known`), but bail rather than
                // silently XOR an incomplete set.
                return RecoveryOutcome::Unrecoverable;
            };
            if bytes.len() > reconstructed.len() {
                return RecoveryOutcome::Unrecoverable;
            }
            for (j, &b) in bytes.iter().enumerate() {
                reconstructed[j] ^= b;
            }
        }
        reconstructed.truncate(missing_len);

        // Mark the recovered seq handled *and* keep its reconstructed
        // plaintext: a duplicate copy of this same parity frame then
        // reads the group as `AlreadyComplete` instead of trying to
        // "recover" it a second time, and the real copy arriving later
        // is rejected by `observe_data`.
        self.mark_seen(missing_seq);
        self.insert_payload(missing_seq, reconstructed.clone());

        RecoveryOutcome::Recovered {
            seq: missing_seq,
            plaintext: reconstructed,
        }
    }

    /// Periodic maintenance: age out plaintexts past their TTL and
    /// rotate the seen-seq generations. Safe to call at any cadence (or
    /// to skip entirely under lock contention) -- every bound this
    /// buffer relies on for memory safety is also enforced inline on
    /// insert, so a missed tick only means state is remembered slightly
    /// longer, never that it grows without limit.
    pub fn tick(&mut self, now: Instant) {
        while let Some(&seq) = self.payload_order.front() {
            let expired = self
                .payloads
                .get(&seq)
                .map(|(at, _)| now.duration_since(*at) >= self.payload_ttl)
                .unwrap_or(true);
            if !expired {
                break;
            }
            self.payload_order.pop_front();
            self.payloads.remove(&seq);
        }

        if now.duration_since(self.seen_rotated_at) >= self.seen_generation {
            self.rotate_seen(now);
        }
    }

    /// Current retained-plaintext count -- test/diagnostic helper.
    #[cfg(test)]
    fn payload_count(&self) -> usize {
        self.payloads.len()
    }

    fn member_state(&self, seq: u64) -> MemberState {
        if self.payloads.contains_key(&seq) {
            return MemberState::Known;
        }
        if self.seen_current.contains(&seq) || self.seen_previous.contains(&seq) {
            return MemberState::Handled;
        }
        if self.seen_floor.is_some_and(|floor| seq <= floor) {
            // Below the sequence-space floor the `seen` rotations have
            // already swept past: if this seq had arrived, it would have
            // been marked before that rotation and therefore dropped by
            // it. "Forgotten" and "handled" are exactly equivalent here,
            // at any packet rate -- which is what makes duplicate
            // delivery impossible rather than merely unlikely. Without
            // this, a quiet tunnel (where `STALE_SEQ_WINDOW`'s 65536
            // seqs can take hours to elapse) leaves a window in which a
            // delivered seq is forgotten by `seen` yet still "recent"
            // by seq count, and gets reconstructed into a byte-identical
            // duplicate.
            return MemberState::Handled;
        }
        if seq + STALE_SEQ_WINDOW <= self.highest_seq {
            // Too far behind the live stream to plausibly still be in
            // flight -- treat as handled (and therefore never
            // reconstructible) rather than missing. This is the
            // conservative direction: the cost is a missed recovery
            // opportunity for an ancient group; the alternative is a
            // duplicate delivery, which is actively harmful.
            return MemberState::Handled;
        }
        MemberState::Missing
    }

    fn note_seq(&mut self, seq: u64) {
        if seq > self.highest_seq {
            self.highest_seq = seq;
            return;
        }
        if self.highest_seq.saturating_sub(seq) >= SEQ_RESET_GAP {
            // The peer restarted its sequence counter. Everything we
            // remember is about a previous incarnation of the stream and
            // would now misclassify every arriving frame.
            self.payloads.clear();
            self.payload_order.clear();
            self.seen_current.clear();
            self.seen_previous.clear();
            // The floors describe the *previous* incarnation's sequence
            // space and would classify every seq of the new one as
            // already-handled forever. Drop them with everything else.
            self.seen_floor = None;
            self.seen_rotation_high = None;
            self.highest_seq = seq;
        }
    }

    fn mark_seen(&mut self, seq: u64) {
        self.seen_current.insert(seq);
        if self.seen_current.len() > MAX_SEEN_PER_GENERATION {
            self.rotate_seen(Instant::now());
        }
    }

    /// Rotate the two `seen` generations, and with them the
    /// sequence-space floor that makes forgetting unambiguous.
    ///
    /// The set discarded by this rotation is the old `seen_previous`,
    /// whose members were all marked before the *previous* rotation.
    /// Every `mark_seen` call site runs `note_seq` first with a seq at
    /// least as high, so each of those seqs is `<= highest_seq` as it
    /// stood at that earlier rotation -- the value carried in
    /// `seen_rotation_high`. Promoting it to `seen_floor` here therefore
    /// gives `member_state` an exact bound: nothing above the floor has
    /// been forgotten, and everything at or below it either arrived (and
    /// was forgotten) or is far too old to still be in flight. Either
    /// way it must never be reconstructed again.
    fn rotate_seen(&mut self, now: Instant) {
        self.seen_previous = std::mem::take(&mut self.seen_current);
        self.seen_floor = self.seen_rotation_high;
        self.seen_rotation_high = Some(self.highest_seq);
        self.seen_rotated_at = now;
    }

    fn insert_payload(&mut self, seq: u64, plaintext: Vec<u8>) {
        if self
            .payloads
            .insert(seq, (Instant::now(), plaintext))
            .is_none()
        {
            self.payload_order.push_back(seq);
        }
        while self.payload_order.len() > MAX_PAYLOADS {
            if let Some(oldest) = self.payload_order.pop_front() {
                self.payloads.remove(&oldest);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parity_of(members: &[(u64, &[u8])]) -> FecParityPayload {
        let width = members.iter().map(|(_, b)| b.len()).max().unwrap_or(0);
        let mut parity = vec![0u8; width];
        for (_, bytes) in members {
            for (i, &b) in bytes.iter().enumerate() {
                parity[i] ^= b;
            }
        }
        FecParityPayload {
            member_seqs: members.iter().map(|(s, _)| *s).collect(),
            member_lens: members.iter().map(|(_, b)| b.len() as u16).collect(),
            parity,
        }
    }

    #[test]
    fn sender_returns_none_until_group_completes() {
        let mut sender = FecSender::new(4);
        assert!(sender.accumulate(1, b"aaaa").is_none());
        assert!(sender.accumulate(2, b"bb").is_none());
        assert!(sender.accumulate(3, b"cccccccc").is_none());
        let parity = sender
            .accumulate(4, b"d")
            .expect("group of 4 should complete");
        assert_eq!(parity.member_seqs, vec![1, 2, 3, 4]);
        assert_eq!(parity.member_lens, vec![4, 2, 8, 1]);
        assert_eq!(parity.parity.len(), 8); // padded to the longest member
    }

    #[test]
    fn sender_starts_a_fresh_group_after_completing_one() {
        let mut sender = FecSender::new(2);
        assert!(sender.accumulate(1, b"xx").is_none());
        assert!(sender.accumulate(2, b"yy").is_some());
        // Second group starts fresh.
        assert!(sender.accumulate(3, b"zz").is_none());
        let parity = sender
            .accumulate(4, b"ww")
            .expect("second group should complete");
        assert_eq!(parity.member_seqs, vec![3, 4]);
    }

    #[test]
    fn parity_overhead_matches_the_real_encoded_size() {
        let mut sender = FecSender::new(8);
        let full = vec![0xabu8; 1368];
        let mut parity = None;
        for seq in 1..=8u64 {
            parity = sender.accumulate(seq, &full);
        }
        let encoded = parity.expect("group of 8 completes").encode();
        assert_eq!(
            encoded.len(),
            full.len() + parity_frame_overhead_bytes(8) as usize,
            "the MTU reservation must exactly match what encode() produces"
        );
    }

    #[test]
    fn mtu_reservation_is_zero_when_fec_is_disabled() {
        let mut cfg = crate::config::SchedulerConfig::default();
        assert!(!cfg.fec_enabled);
        assert_eq!(mtu_reservation_bytes(&cfg), 0);
        cfg.fec_enabled = true;
        cfg.fec_group_size = 8;
        assert_eq!(mtu_reservation_bytes(&cfg), 83);
    }

    #[test]
    fn recovery_reconstructs_the_single_missing_member() {
        let parity = parity_of(&[(10, b"aaaa"), (11, b"bb"), (12, b"cccc")]);
        let mut buf = FecRecoveryBuffer::new(3);
        assert!(buf.observe_data(10, b"aaaa"));
        assert!(buf.observe_data(12, b"cccc"));
        // seq 11 ("bb") never arrived -- reconstruct it from the parity.
        match buf.try_recover(&parity) {
            RecoveryOutcome::Recovered { seq, plaintext } => {
                assert_eq!(seq, 11);
                assert_eq!(plaintext, b"bb");
            }
            other => panic!("expected Recovered, got {other:?}"),
        }
    }

    #[test]
    fn recovery_reports_unrecoverable_when_two_members_are_missing() {
        let parity = parity_of(&[(20, b"aaaa"), (21, b"bbbb"), (22, b"cccc")]);
        let mut buf = FecRecoveryBuffer::new(3);
        assert!(buf.observe_data(20, b"aaaa"));
        // seq 21 AND seq 22 both never arrived.
        assert!(matches!(
            buf.try_recover(&parity),
            RecoveryOutcome::Unrecoverable
        ));
    }

    #[test]
    fn recovery_reports_already_complete_when_nothing_is_missing() {
        let parity = parity_of(&[(30, b"aa"), (31, b"bb")]);
        let mut buf = FecRecoveryBuffer::new(2);
        assert!(buf.observe_data(30, b"aa"));
        assert!(buf.observe_data(31, b"bb"));
        assert!(matches!(
            buf.try_recover(&parity),
            RecoveryOutcome::AlreadyComplete
        ));
    }

    /// The core of the duplicate-delivery bug: a member really did
    /// arrive and was delivered, but its *plaintext* aged out before the
    /// parity frame landed. It must be classified as already-handled,
    /// never "recovered" into a second copy of an already-delivered
    /// packet.
    #[test]
    fn aged_out_member_is_never_falsely_recovered() {
        let mut buf =
            FecRecoveryBuffer::with_params(2, Duration::from_millis(10), Duration::from_secs(60));
        assert!(buf.observe_data(40, b"aa"));
        assert!(buf.observe_data(41, b"bb"));
        std::thread::sleep(Duration::from_millis(25));
        buf.tick(Instant::now());
        assert_eq!(buf.payload_count(), 0, "payloads should have aged out");

        let parity = parity_of(&[(40, b"aa"), (41, b"bb")]);
        // Both members are `Handled` (seen, payload gone) -- zero
        // missing, so nothing is delivered. Before the fix this read as
        // "both missing" and, with only one member, would have produced
        // a duplicate.
        assert!(matches!(
            buf.try_recover(&parity),
            RecoveryOutcome::AlreadyComplete
        ));
    }

    #[test]
    fn single_aged_out_member_alongside_a_real_loss_is_unrecoverable_not_duplicated() {
        let mut buf =
            FecRecoveryBuffer::with_params(3, Duration::from_millis(10), Duration::from_secs(60));
        assert!(buf.observe_data(50, b"aaaa"));
        std::thread::sleep(Duration::from_millis(25));
        buf.tick(Instant::now());
        // 51 genuinely lost; 50 arrived but aged out; 52 arrives fresh.
        assert!(buf.observe_data(52, b"cccc"));
        let parity = parity_of(&[(50, b"aaaa"), (51, b"bbbb"), (52, b"cccc")]);
        assert!(
            matches!(buf.try_recover(&parity), RecoveryOutcome::Unrecoverable),
            "one real erasure plus an un-XORable group-mate is not reconstructible"
        );
    }

    /// The other half of the duplicate-delivery bug: the parity frame
    /// beat a straggler still in flight on the slower link. Recovering
    /// early is correct and desirable -- but the real copy arriving
    /// afterwards must be dropped, not delivered a second time.
    #[test]
    fn real_frame_arriving_after_its_own_recovery_is_not_delivered_twice() {
        let parity = parity_of(&[(60, b"aaaa"), (61, b"bbbb")]);
        let mut buf = FecRecoveryBuffer::new(2);
        assert!(buf.observe_data(60, b"aaaa"));
        match buf.try_recover(&parity) {
            RecoveryOutcome::Recovered { seq, plaintext } => {
                assert_eq!(seq, 61);
                assert_eq!(plaintext, b"bbbb");
            }
            other => panic!("expected Recovered, got {other:?}"),
        }
        assert!(
            !buf.observe_data(61, b"bbbb"),
            "the straggler's real copy must be suppressed after FEC already delivered it"
        );
    }

    #[test]
    fn a_duplicate_parity_frame_does_not_recover_twice() {
        let parity = parity_of(&[(70, b"aaaa"), (71, b"bbbb")]);
        let mut buf = FecRecoveryBuffer::new(2);
        assert!(buf.observe_data(70, b"aaaa"));
        assert!(matches!(
            buf.try_recover(&parity),
            RecoveryOutcome::Recovered { .. }
        ));
        assert!(
            matches!(buf.try_recover(&parity), RecoveryOutcome::AlreadyComplete),
            "a second copy of the same parity frame must not re-deliver its member"
        );
    }

    #[test]
    fn seqs_far_behind_the_live_stream_are_never_recovered() {
        let mut buf = FecRecoveryBuffer::new(2);
        // Drive the highest-seq anchor well past the stale window.
        assert!(buf.observe_data(1_000_000, b"zz"));
        let parity = parity_of(&[(10, b"aa"), (11, b"bb")]);
        assert!(
            matches!(buf.try_recover(&parity), RecoveryOutcome::AlreadyComplete),
            "ancient, long-forgotten seqs are handled, not missing"
        );
    }

    #[test]
    fn a_peer_sequence_restart_resets_tracking_state() {
        let mut buf = FecRecoveryBuffer::new(2);
        assert!(buf.observe_data(1 << 40, b"zz"));
        // Peer restarts: seqs begin near zero again.
        assert!(buf.observe_data(3, b"aaaa"));
        assert_eq!(buf.highest_seq, 3, "state should have reset to the new run");
        let parity = parity_of(&[(3, b"aaaa"), (4, b"bbbb")]);
        match buf.try_recover(&parity) {
            RecoveryOutcome::Recovered { seq, .. } => assert_eq!(seq, 4),
            other => panic!("expected Recovered after a peer restart, got {other:?}"),
        }
    }

    #[test]
    fn payload_retention_is_hard_capped_regardless_of_ttl() {
        let mut buf =
            FecRecoveryBuffer::with_params(2, Duration::from_secs(3600), Duration::from_secs(3600));
        for seq in 0..(MAX_PAYLOADS as u64 + 500) {
            assert!(buf.observe_data(seq, b"aaaa"));
        }
        assert_eq!(buf.payload_count(), MAX_PAYLOADS);
    }

    #[test]
    fn tick_rotates_the_seen_generations_without_losing_recent_seqs() {
        let mut buf =
            FecRecoveryBuffer::with_params(2, Duration::from_millis(5), Duration::from_millis(10));
        assert!(buf.observe_data(80, b"aa"));
        std::thread::sleep(Duration::from_millis(15));
        buf.tick(Instant::now());
        // One rotation: 80 moved to the previous generation but is still
        // remembered, so a re-arrival is still recognized as a duplicate.
        assert!(!buf.observe_data(80, b"aa"));
    }

    /// Regression test for the residual duplicate-delivery path: a seq
    /// that survives *two* generation rotations is forgotten by `seen`
    /// entirely, while remaining far too recent for `STALE_SEQ_WINDOW`
    /// (65536 seqs) to retire -- the everyday shape of a quiet tunnel,
    /// where a group can stay open for minutes. Before `seen_floor`
    /// existed this classified the delivered seq as genuinely `Missing`
    /// and reconstructed a byte-identical duplicate into the TUN device.
    #[test]
    fn a_seq_forgotten_by_two_rotations_is_handled_not_recovered_again() {
        let mut buf =
            FecRecoveryBuffer::with_params(2, Duration::from_millis(5), Duration::from_millis(10));
        // Delivered for real, payload + seen recorded.
        assert!(buf.observe_data(100, b"aaaa"));

        // Rotation 1: payload expires, 100 demoted to `seen_previous`.
        std::thread::sleep(Duration::from_millis(15));
        buf.tick(Instant::now());
        // Rotation 2: 100 is dropped from `seen` altogether.
        std::thread::sleep(Duration::from_millis(15));
        buf.tick(Instant::now());
        assert!(
            !buf.seen_current.contains(&100) && !buf.seen_previous.contains(&100),
            "the scenario requires seq 100 to be genuinely forgotten by `seen`"
        );

        // The group's other member arrives, then the parity frame. Note
        // 100 is only one seq behind the live stream -- nowhere near
        // `STALE_SEQ_WINDOW`, so that backstop cannot save us here.
        assert!(buf.observe_data(101, b"bbbb"));
        assert!(
            100 + STALE_SEQ_WINDOW > buf.highest_seq,
            "the stale-seq window must NOT be what rejects this seq, or the test is vacuous"
        );

        let parity = parity_of(&[(100, b"aaaa"), (101, b"bbbb")]);
        let outcome = buf.try_recover(&parity);
        assert!(
            !matches!(outcome, RecoveryOutcome::Recovered { .. }),
            "a forgotten-but-already-delivered seq must never be reconstructed again, got {outcome:?}"
        );
        assert_eq!(
            outcome,
            RecoveryOutcome::AlreadyComplete,
            "both members are accounted for, so there is simply nothing to do"
        );
    }

    /// The floor must not swallow a genuine loss: a member that never
    /// arrived, whose seq is *above* the last rotation's high-water
    /// mark, is still a real erasure and must still be recoverable.
    #[test]
    fn the_seen_floor_does_not_block_recovering_a_genuinely_recent_loss() {
        let mut buf =
            FecRecoveryBuffer::with_params(2, Duration::from_secs(60), Duration::from_millis(10));
        assert!(buf.observe_data(200, b"zzzz"));
        std::thread::sleep(Duration::from_millis(15));
        buf.tick(Instant::now());
        std::thread::sleep(Duration::from_millis(15));
        buf.tick(Instant::now());
        // Floor is now 200; 201/202 are a fresh group above it.
        assert!(buf.observe_data(201, b"aaaa"));
        let parity = parity_of(&[(201, b"aaaa"), (202, b"bbbb")]);
        match buf.try_recover(&parity) {
            RecoveryOutcome::Recovered { seq, plaintext } => {
                assert_eq!(seq, 202);
                assert_eq!(plaintext, b"bbbb");
            }
            other => panic!("expected Recovered for a real, recent erasure, got {other:?}"),
        }
    }

    /// A peer restart resets the sequence space, so the floor (which
    /// describes the previous incarnation's much higher seqs) must be
    /// dropped too -- otherwise FEC would classify every seq of the new
    /// run as already-handled and silently never recover anything again.
    #[test]
    fn a_peer_sequence_restart_also_clears_the_seen_floor() {
        let mut buf =
            FecRecoveryBuffer::with_params(2, Duration::from_millis(5), Duration::from_millis(10));
        assert!(buf.observe_data(1 << 40, b"zz"));
        std::thread::sleep(Duration::from_millis(15));
        buf.tick(Instant::now());
        std::thread::sleep(Duration::from_millis(15));
        buf.tick(Instant::now());
        assert!(
            buf.seen_floor.is_some(),
            "floor should be armed pre-restart"
        );

        // Peer restarts: seqs begin near zero again, far below the floor.
        assert!(buf.observe_data(3, b"aaaa"));
        assert!(buf.seen_floor.is_none(), "the restart must clear the floor");
        let parity = parity_of(&[(3, b"aaaa"), (4, b"bbbb")]);
        match buf.try_recover(&parity) {
            RecoveryOutcome::Recovered { seq, .. } => assert_eq!(seq, 4),
            other => panic!("expected Recovered after a peer restart, got {other:?}"),
        }
    }
}
