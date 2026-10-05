//! Pure XOR single-erasure FEC logic -- no networking, no async. See
//! `docs/superpowers/specs/2026-09-15-single-erasure-fec-design.md` for
//! the full design. `tunnel.rs` owns the actual send/receive plumbing
//! that drives `FecSender`/`FecRecoveryBuffer`; this module only knows
//! how to accumulate/reconstruct, kept separate so both halves of the
//! algorithm are testable without spinning up any real sockets or TUN
//! devices.

use crate::config::FecParityPlacement;
use crate::protocol::FecParityPayload;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// GF(256) arithmetic (polynomial 0x11d, generator 2 -- the RAID-6
/// field) for the second parity share. `P` is plain XOR; `Q = sum g^i *
/// D_i` with `i` the member's position in its group. Because the `g^i`
/// are distinct and non-zero for `i < 255`, any two erasures give a
/// solvable 2x2 system -- which is why a group size is capped at 255
/// anyway (the wire format's `u8`).
pub mod gf {
    use std::sync::OnceLock;

    const fn build_tables() -> ([u8; 512], [u8; 256]) {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        let mut i = 0;
        while i < 255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
            i += 1;
        }
        // Doubled so `exp[log a + log b]` never needs a modulo.
        let mut j = 255;
        while j < 512 {
            exp[j] = exp[j - 255];
            j += 1;
        }
        (exp, log)
    }

    static TABLES: ([u8; 512], [u8; 256]) = build_tables();
    /// `MUL[c * 256 + x] = c * x`, built once on first use (64 KiB) so
    /// the per-byte inner loop is a single table lookup.
    static MUL: OnceLock<Box<[u8]>> = OnceLock::new();

    fn mul_table() -> &'static [u8] {
        MUL.get_or_init(|| {
            let mut t = vec![0u8; 256 * 256].into_boxed_slice();
            for c in 1..256usize {
                for x in 1..256usize {
                    t[c * 256 + x] = mul_slow(c as u8, x as u8);
                }
            }
            t
        })
    }

    fn mul_slow(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        TABLES.0[TABLES.1[a as usize] as usize + TABLES.1[b as usize] as usize]
    }

    pub fn mul(a: u8, b: u8) -> u8 {
        mul_slow(a, b)
    }

    /// `g^i` (`i` taken modulo 255).
    pub fn pow2(i: usize) -> u8 {
        TABLES.0[i % 255]
    }

    /// Multiplicative inverse; `a` must be non-zero.
    pub fn inv(a: u8) -> u8 {
        debug_assert!(a != 0);
        TABLES.0[255 - TABLES.1[a as usize] as usize]
    }

    /// `dst[i] ^= coef * src[i]`; `dst` must be at least as long as `src`.
    pub fn mul_acc(dst: &mut [u8], src: &[u8], coef: u8) {
        debug_assert!(dst.len() >= src.len());
        if coef == 0 {
            return;
        }
        let row = &mul_table()[coef as usize * 256..coef as usize * 256 + 256];
        for (d, &s) in dst.iter_mut().zip(src) {
            *d ^= row[s as usize];
        }
    }

    /// `dst[i] = coef * dst[i]`.
    pub fn scale(dst: &mut [u8], coef: u8) {
        let row = &mul_table()[coef as usize * 256..coef as usize * 256 + 256];
        for d in dst.iter_mut() {
            *d = row[*d as usize];
        }
    }
}

/// Sender-side FEC counters, shared with the control socket so a
/// snapshot can report how much parity actually left the sender.
#[derive(Debug, Default)]
pub struct FecSendStats {
    /// Groups whose parity was queued for the wire.
    pub groups: std::sync::atomic::AtomicU64,
    /// P / Q parity frames queued.
    pub parity_p: std::sync::atomic::AtomicU64,
    pub parity_q: std::sync::atomic::AtomicU64,
}

/// One completed sender-side group: the `P` share, the `Q` share when
/// `fec_parity = 2`, and which link carried each member (for parity
/// placement).
pub struct FecGroup {
    pub p: FecParityPayload,
    pub q: Option<FecParityPayload>,
    pub member_links: Vec<usize>,
}

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
    with_q: bool,
    member_seqs: Vec<u64>,
    member_lens: Vec<u16>,
    member_links: Vec<usize>,
    parity: Vec<u8>,
    q: Vec<u8>,
}

impl FecSender {
    pub fn new(group_size: u8, parity_count: u8) -> Self {
        Self {
            group_size: group_size as usize,
            with_q: parity_count >= 2,
            member_seqs: Vec::with_capacity(group_size as usize),
            member_lens: Vec::with_capacity(group_size as usize),
            member_links: Vec::with_capacity(group_size as usize),
            parity: Vec::new(),
            q: Vec::new(),
        }
    }

    /// Feed one real Data frame's `seq`, plaintext and the link that
    /// carried it into the current group. Returns the completed group
    /// exactly when this call was the group's last member -- `None`
    /// otherwise. Starts a fresh, empty group immediately after
    /// returning `Some`.
    pub fn accumulate(&mut self, seq: u64, plaintext: &[u8], link: usize) -> Option<FecGroup> {
        if plaintext.len() > self.parity.len() {
            self.parity.resize(plaintext.len(), 0);
        }
        for (i, &byte) in plaintext.iter().enumerate() {
            self.parity[i] ^= byte;
        }
        if self.with_q {
            if plaintext.len() > self.q.len() {
                self.q.resize(plaintext.len(), 0);
            }
            gf::mul_acc(&mut self.q, plaintext, gf::pow2(self.member_seqs.len()));
        }
        self.member_seqs.push(seq);
        self.member_links.push(link);
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

        let member_seqs = std::mem::take(&mut self.member_seqs);
        let member_lens = std::mem::take(&mut self.member_lens);
        let q = self.with_q.then(|| FecParityPayload {
            member_seqs: member_seqs.clone(),
            member_lens: member_lens.clone(),
            parity: std::mem::take(&mut self.q),
        });
        let p = FecParityPayload {
            member_seqs,
            member_lens,
            parity: std::mem::take(&mut self.parity),
        };
        Some(FecGroup {
            p,
            q,
            member_links: std::mem::take(&mut self.member_links),
        })
    }
}

/// Pick the link a group's parity frames should be forced onto, or
/// `None` to let the normal scheduler decide (always the answer for
/// `Scheduler`, for an empty/ambiguous group, and when no link both
/// qualifies and is usable).
///
/// A link failure takes out every member of the group that link
/// carried, all at once, so a group survives it only if that link
/// carried no more members than there are surviving parity frames.
/// - `Dominant`: the usable link carrying the *most* members. Its own
///   failure sinks the group regardless of where parity sits, so parity
///   is better spent on the failures it can repair -- every other
///   link's. Both parity frames go there together (splitting them would
///   leave a single survivor after the *other* link's failure).
/// - `Diverse`: the usable link carrying the *fewest* members.
///
/// A tie returns `None`: nothing distinguishes the candidates, and the
/// scheduler's own pick is as good as any.
pub fn choose_parity_link(
    placement: FecParityPlacement,
    member_links: &[usize],
    usable: &[bool],
) -> Option<usize> {
    if placement == FecParityPlacement::Scheduler {
        return None;
    }
    let mut counts = vec![0usize; usable.len()];
    for &l in member_links {
        if let Some(c) = counts.get_mut(l) {
            *c += 1;
        }
    }
    let candidates = || {
        usable
            .iter()
            .enumerate()
            .filter(|(_, &u)| u)
            .map(|(i, _)| i)
    };
    let best = match placement {
        FecParityPlacement::Dominant => candidates().map(|i| counts[i]).max()?,
        FecParityPlacement::Diverse => candidates().map(|i| counts[i]).min()?,
        FecParityPlacement::Scheduler => return None,
    };
    if placement == FecParityPlacement::Dominant && best == 0 {
        return None;
    }
    let mut hits = candidates().filter(|&i| counts[i] == best);
    let first = hits.next()?;
    if hits.next().is_some() {
        return None;
    }
    Some(first)
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

/// Which share of a group a parity frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParityKind {
    /// Plain XOR (`PacketType::FecParity`).
    P,
    /// GF(256) weighted sum (`PacketType::FecParityQ`).
    Q,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// One member (or, with both shares, two) was missing and has been
    /// reconstructed: `(seq, plaintext)` pairs, ascending by group
    /// position.
    Recovered(Vec<(u64, Vec<u8>)>),
    /// More members were missing than the group's shares can repair, or
    /// a missing member's group-mates are no longer reconstructible
    /// (their payloads have aged out) -- either way, nothing to deliver.
    Unrecoverable,
    /// Every member had already arrived directly -- the parity frame
    /// itself was unnecessary this time. Nothing to deliver.
    AlreadyComplete,
    /// Two members are missing and only one share has arrived so far
    /// (`fec_parity = 2`): the group is parked and re-checked when the
    /// other share, or a late member, arrives. Expiry without a resolve
    /// is counted through `FecRecoveryBuffer::tick`.
    Pending,
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

/// Ceiling on groups parked waiting for a second parity share or a late
/// member (`fec_parity = 2` only). Oldest is evicted -- and counted as
/// unrecoverable -- beyond this.
const MAX_PARKED_GROUPS: usize = 512;

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
    /// Shares per group the peer is configured to send (1 or 2). With 1
    /// nothing is ever parked and behaviour is the original
    /// single-erasure XOR recovery, unchanged.
    parity_count: u8,
    /// Groups with two members missing and a share still to come, keyed
    /// by the group's first member seq.
    parked: HashMap<u64, ParkedGroup>,
    /// Missing member seq -> key of the parked group waiting on it. Empty
    /// whenever `parked` is, so the `observe_data` hot path pays one
    /// `is_empty` check at most.
    parked_by_seq: HashMap<u64, u64>,
    /// Frames recovered by a parked group's re-check when a late member
    /// arrived; drained by the caller after `observe_data`.
    late_recoveries: Vec<(u64, Vec<u8>)>,
    /// Groups given up on outside a `try_recover` call (parked-group
    /// expiry, eviction, or a late re-check that found them hopeless).
    /// Reported and zeroed by `tick`.
    given_up: u64,
}

/// The shares seen so far for one group.
struct ShareSet {
    p: Option<FecParityPayload>,
    q: Option<FecParityPayload>,
}

struct ParkedGroup {
    at: Instant,
    shares: ShareSet,
    missing: Vec<u64>,
}

enum Eval {
    Recovered(Vec<(u64, Vec<u8>)>),
    AlreadyComplete,
    Unrecoverable,
    NeedMore { missing: Vec<u64> },
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
    pub fn new(group_size: u8, parity_count: u8) -> Self {
        Self::with_params(group_size, parity_count, PAYLOAD_TTL, SEEN_GENERATION)
    }

    fn with_params(
        group_size: u8,
        parity_count: u8,
        payload_ttl: Duration,
        seen_generation: Duration,
    ) -> Self {
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
            parity_count,
            parked: HashMap::new(),
            parked_by_seq: HashMap::new(),
            late_recoveries: Vec::new(),
            given_up: 0,
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
        if !self.parked.is_empty() {
            self.recheck_parked_for(seq);
        }
        true
    }

    /// Whether `observe_data` produced recoveries (a parked group that a
    /// late member just made solvable) waiting in `take_late_recoveries`.
    pub fn has_late_recoveries(&self) -> bool {
        !self.late_recoveries.is_empty()
    }

    /// Take the recoveries a late data frame unlocked. Call after
    /// `observe_data` when `has_late_recoveries()`.
    pub fn take_late_recoveries(&mut self) -> Vec<(u64, Vec<u8>)> {
        std::mem::take(&mut self.late_recoveries)
    }

    /// Given a just-arrived parity frame (either share), determine and
    /// (if possible) perform recovery for its group. Every recovered seq
    /// is marked as handled before returning, so the real copy arriving
    /// afterwards is rejected by `observe_data` rather than delivered
    /// twice.
    pub fn try_recover(&mut self, kind: ParityKind, parity: &FecParityPayload) -> RecoveryOutcome {
        if parity.member_seqs.len() != parity.member_lens.len() || parity.member_seqs.is_empty() {
            return RecoveryOutcome::Unrecoverable;
        }
        if let Some(&max) = parity.member_seqs.iter().max() {
            self.note_seq(max);
        }

        // Merge with a share of the same group that arrived earlier.
        let key = parity.member_seqs[0];
        let mut shares = match self.parked.remove(&key) {
            Some(parked) => {
                for seq in &parked.missing {
                    self.parked_by_seq.remove(seq);
                }
                parked.shares
            }
            None => ShareSet { p: None, q: None },
        };
        match kind {
            ParityKind::P => shares.p = Some(parity.clone()),
            ParityKind::Q => shares.q = Some(parity.clone()),
        }

        match self.evaluate(&shares) {
            Eval::Recovered(r) => RecoveryOutcome::Recovered(r),
            Eval::AlreadyComplete => RecoveryOutcome::AlreadyComplete,
            Eval::Unrecoverable => RecoveryOutcome::Unrecoverable,
            Eval::NeedMore { missing } => {
                self.park(key, shares, missing);
                RecoveryOutcome::Pending
            }
        }
    }

    fn park(&mut self, key: u64, shares: ShareSet, missing: Vec<u64>) {
        if self.parked.len() >= MAX_PARKED_GROUPS {
            if let Some(oldest) = self
                .parked
                .iter()
                .min_by_key(|(_, g)| g.at)
                .map(|(k, _)| *k)
            {
                self.drop_parked(oldest);
                self.given_up += 1;
            }
        }
        for &seq in &missing {
            self.parked_by_seq.insert(seq, key);
        }
        self.parked.insert(
            key,
            ParkedGroup {
                at: Instant::now(),
                shares,
                missing,
            },
        );
    }

    fn drop_parked(&mut self, key: u64) {
        if let Some(g) = self.parked.remove(&key) {
            for seq in &g.missing {
                self.parked_by_seq.remove(seq);
            }
        }
    }

    /// A late data frame landed: if it was one a parked group was
    /// waiting on, re-evaluate that group now.
    fn recheck_parked_for(&mut self, seq: u64) {
        let Some(key) = self.parked_by_seq.remove(&seq) else {
            return;
        };
        let Some(parked) = self.parked.remove(&key) else {
            return;
        };
        for s in &parked.missing {
            self.parked_by_seq.remove(s);
        }
        match self.evaluate(&parked.shares) {
            Eval::Recovered(mut r) => self.late_recoveries.append(&mut r),
            Eval::AlreadyComplete => {}
            Eval::Unrecoverable => self.given_up += 1,
            Eval::NeedMore { missing } => {
                let at = parked.at;
                self.park(key, parked.shares, missing);
                if let Some(g) = self.parked.get_mut(&key) {
                    g.at = at;
                }
            }
        }
    }

    /// Classify the group's members and reconstruct whatever the shares
    /// in hand allow. Does not touch the parked maps.
    fn evaluate(&mut self, shares: &ShareSet) -> Eval {
        let Some(any) = shares.p.as_ref().or(shares.q.as_ref()) else {
            return Eval::Unrecoverable;
        };
        let seqs = &any.member_seqs;
        let lens = &any.member_lens;

        let mut missing_idx: Vec<usize> = Vec::new();
        let mut handled_count = 0usize;
        for (i, seq) in seqs.iter().enumerate() {
            match self.member_state(*seq) {
                MemberState::Known => {}
                MemberState::Handled => handled_count += 1,
                MemberState::Missing => missing_idx.push(i),
            }
        }

        if missing_idx.is_empty() {
            // Nothing outstanding. If some members are only `Handled`
            // (payload aged out) that is still "nothing to do" -- they
            // were delivered when they arrived.
            return Eval::AlreadyComplete;
        }
        let max_erasures = if self.parity_count >= 2 { 2 } else { 1 };
        if missing_idx.len() > max_erasures || handled_count > 0 {
            // More erasures than shares, or erasures whose group-mates
            // can no longer be combined back together. Either way this
            // group is not reconstructible -- and crucially, we do NOT
            // guess: reconstructing against an incomplete set of
            // group-mates would produce garbage, and "recovering" a
            // member that was really just forgotten would produce a
            // duplicate.
            return Eval::Unrecoverable;
        }

        // Which shares usable for this erasure count.
        let have_p = shares.p.is_some();
        let have_q = shares.q.is_some();
        if missing_idx.len() == 2 && !(have_p && have_q) {
            return Eval::NeedMore {
                missing: missing_idx.iter().map(|&i| seqs[i]).collect(),
            };
        }

        // Share width: both shares cover the same group, so both are as
        // wide as its longest member.
        let width = match (&shares.p, &shares.q) {
            (Some(p), Some(q)) => {
                if p.parity.len() != q.parity.len()
                    || p.member_seqs != q.member_seqs
                    || p.member_lens != q.member_lens
                {
                    return Eval::Unrecoverable;
                }
                p.parity.len()
            }
            (Some(p), None) => p.parity.len(),
            (None, Some(q)) => q.parity.len(),
            (None, None) => return Eval::Unrecoverable,
        };
        // A member declared longer than the share that is supposed to
        // cover it is a self-inconsistent frame (a peer bug rather than
        // an attack -- it is authenticated), and nothing is recoverable.
        if missing_idx.iter().any(|&i| lens[i] as usize > width) {
            return Eval::Unrecoverable;
        }

        // P' / Q': the shares with every known member's contribution
        // removed. `P' = sum of the missing D`, `Q' = sum g^i * missing D_i`.
        let mut p_prime = shares.p.as_ref().map(|p| p.parity.clone());
        let mut q_prime = shares.q.as_ref().map(|q| q.parity.clone());
        for (i, seq) in seqs.iter().enumerate() {
            if missing_idx.contains(&i) {
                continue;
            }
            let Some((_, bytes)) = self.payloads.get(seq) else {
                // Unreachable given the classification above (every
                // non-missing member was `Known`), but bail rather than
                // silently combine an incomplete set.
                return Eval::Unrecoverable;
            };
            if bytes.len() > width {
                return Eval::Unrecoverable;
            }
            if let Some(pp) = p_prime.as_mut() {
                for (j, &b) in bytes.iter().enumerate() {
                    pp[j] ^= b;
                }
            }
            if let Some(qp) = q_prime.as_mut() {
                gf::mul_acc(qp, bytes, gf::pow2(i));
            }
        }

        let mut out: Vec<(usize, Vec<u8>)> = Vec::with_capacity(missing_idx.len());
        match missing_idx.as_slice() {
            [a] => {
                let data = match (p_prime, q_prime) {
                    (Some(pp), _) => pp,
                    (None, Some(mut qp)) => {
                        gf::scale(&mut qp, gf::inv(gf::pow2(*a)));
                        qp
                    }
                    (None, None) => return Eval::Unrecoverable,
                };
                out.push((*a, data));
            }
            [a, b] => {
                let (Some(pp), Some(mut qp)) = (p_prime, q_prime) else {
                    return Eval::Unrecoverable;
                };
                // Db = (Q' + g^a P') / (g^a + g^b);  Da = P' + Db.
                let ga = gf::pow2(*a);
                let gb = gf::pow2(*b);
                gf::mul_acc(&mut qp, &pp, ga);
                gf::scale(&mut qp, gf::inv(ga ^ gb));
                let db = qp;
                let mut da = pp;
                for (x, &y) in da.iter_mut().zip(&db) {
                    *x ^= y;
                }
                out.push((*a, da));
                out.push((*b, db));
            }
            _ => return Eval::Unrecoverable,
        }

        // Mark each recovered seq handled *and* keep its reconstructed
        // plaintext: a duplicate copy of this same parity frame then
        // reads the group as `AlreadyComplete` instead of trying to
        // "recover" it a second time, and the real copy arriving later
        // is rejected by `observe_data`.
        let mut recovered = Vec::with_capacity(out.len());
        for (idx, mut data) in out {
            data.truncate(lens[idx] as usize);
            let seq = seqs[idx];
            self.mark_seen(seq);
            self.insert_payload(seq, data.clone());
            recovered.push((seq, data));
        }
        Eval::Recovered(recovered)
    }

    /// Periodic maintenance: age out plaintexts past their TTL, expire
    /// parked groups, and rotate the seen-seq generations. Safe to call
    /// at any cadence (or to skip entirely under lock contention) --
    /// every bound this buffer relies on for memory safety is also
    /// enforced inline on insert, so a missed tick only means state is
    /// remembered slightly longer, never that it grows without limit.
    ///
    /// Returns how many groups were given up on since the last tick
    /// (parked groups that expired or were evicted, or re-checked and
    /// found hopeless), for the caller's unrecoverable counter.
    pub fn tick(&mut self, now: Instant) -> u64 {
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

        if !self.parked.is_empty() {
            let ttl = self.payload_ttl;
            let expired: Vec<u64> = self
                .parked
                .iter()
                .filter(|(_, g)| now.duration_since(g.at) >= ttl)
                .map(|(k, _)| *k)
                .collect();
            for key in expired {
                self.drop_parked(key);
                self.given_up += 1;
            }
        }

        if now.duration_since(self.seen_rotated_at) >= self.seen_generation {
            self.rotate_seen(now);
        }
        std::mem::take(&mut self.given_up)
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
        let mut sender = FecSender::new(4, 1);
        assert!(sender.accumulate(1, b"aaaa", 0).is_none());
        assert!(sender.accumulate(2, b"bb", 0).is_none());
        assert!(sender.accumulate(3, b"cccccccc", 0).is_none());
        let parity = sender
            .accumulate(4, b"d", 0)
            .expect("group of 4 should complete")
            .p;
        assert_eq!(parity.member_seqs, vec![1, 2, 3, 4]);
        assert_eq!(parity.member_lens, vec![4, 2, 8, 1]);
        assert_eq!(parity.parity.len(), 8); // padded to the longest member
    }

    #[test]
    fn sender_starts_a_fresh_group_after_completing_one() {
        let mut sender = FecSender::new(2, 1);
        assert!(sender.accumulate(1, b"xx", 0).is_none());
        assert!(sender.accumulate(2, b"yy", 0).is_some());
        // Second group starts fresh.
        assert!(sender.accumulate(3, b"zz", 0).is_none());
        let parity = sender
            .accumulate(4, b"ww", 0)
            .expect("second group should complete")
            .p;
        assert_eq!(parity.member_seqs, vec![3, 4]);
    }

    #[test]
    fn parity_overhead_matches_the_real_encoded_size() {
        let mut sender = FecSender::new(8, 1);
        let full = vec![0xabu8; 1368];
        let mut parity = None;
        for seq in 1..=8u64 {
            parity = sender.accumulate(seq, &full, 0);
        }
        let encoded = parity.expect("group of 8 completes").p.encode();
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
        let mut buf = FecRecoveryBuffer::new(3, 1);
        assert!(buf.observe_data(10, b"aaaa"));
        assert!(buf.observe_data(12, b"cccc"));
        // seq 11 ("bb") never arrived -- reconstruct it from the parity.
        match buf.try_recover(ParityKind::P, &parity) {
            RecoveryOutcome::Recovered(frames) => {
                let [(seq, plaintext)] = &frames[..] else {
                    panic!("expected exactly one recovered frame, got {frames:?}")
                };
                let (seq, plaintext) = (*seq, plaintext.clone());
                assert_eq!(seq, 11);
                assert_eq!(plaintext, b"bb");
            }
            other => panic!("expected Recovered, got {other:?}"),
        }
    }

    #[test]
    fn recovery_reports_unrecoverable_when_two_members_are_missing() {
        let parity = parity_of(&[(20, b"aaaa"), (21, b"bbbb"), (22, b"cccc")]);
        let mut buf = FecRecoveryBuffer::new(3, 1);
        assert!(buf.observe_data(20, b"aaaa"));
        // seq 21 AND seq 22 both never arrived.
        assert!(matches!(
            buf.try_recover(ParityKind::P, &parity),
            RecoveryOutcome::Unrecoverable
        ));
    }

    #[test]
    fn recovery_reports_already_complete_when_nothing_is_missing() {
        let parity = parity_of(&[(30, b"aa"), (31, b"bb")]);
        let mut buf = FecRecoveryBuffer::new(2, 1);
        assert!(buf.observe_data(30, b"aa"));
        assert!(buf.observe_data(31, b"bb"));
        assert!(matches!(
            buf.try_recover(ParityKind::P, &parity),
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
        let mut buf = FecRecoveryBuffer::with_params(
            2,
            1,
            Duration::from_millis(10),
            Duration::from_secs(60),
        );
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
            buf.try_recover(ParityKind::P, &parity),
            RecoveryOutcome::AlreadyComplete
        ));
    }

    #[test]
    fn single_aged_out_member_alongside_a_real_loss_is_unrecoverable_not_duplicated() {
        let mut buf = FecRecoveryBuffer::with_params(
            3,
            1,
            Duration::from_millis(10),
            Duration::from_secs(60),
        );
        assert!(buf.observe_data(50, b"aaaa"));
        std::thread::sleep(Duration::from_millis(25));
        buf.tick(Instant::now());
        // 51 genuinely lost; 50 arrived but aged out; 52 arrives fresh.
        assert!(buf.observe_data(52, b"cccc"));
        let parity = parity_of(&[(50, b"aaaa"), (51, b"bbbb"), (52, b"cccc")]);
        assert!(
            matches!(
                buf.try_recover(ParityKind::P, &parity),
                RecoveryOutcome::Unrecoverable
            ),
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
        let mut buf = FecRecoveryBuffer::new(2, 1);
        assert!(buf.observe_data(60, b"aaaa"));
        match buf.try_recover(ParityKind::P, &parity) {
            RecoveryOutcome::Recovered(frames) => {
                let [(seq, plaintext)] = &frames[..] else {
                    panic!("expected exactly one recovered frame, got {frames:?}")
                };
                let (seq, plaintext) = (*seq, plaintext.clone());
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
        let mut buf = FecRecoveryBuffer::new(2, 1);
        assert!(buf.observe_data(70, b"aaaa"));
        assert!(matches!(
            buf.try_recover(ParityKind::P, &parity),
            RecoveryOutcome::Recovered(_)
        ));
        assert!(
            matches!(
                buf.try_recover(ParityKind::P, &parity),
                RecoveryOutcome::AlreadyComplete
            ),
            "a second copy of the same parity frame must not re-deliver its member"
        );
    }

    #[test]
    fn seqs_far_behind_the_live_stream_are_never_recovered() {
        let mut buf = FecRecoveryBuffer::new(2, 1);
        // Drive the highest-seq anchor well past the stale window.
        assert!(buf.observe_data(1_000_000, b"zz"));
        let parity = parity_of(&[(10, b"aa"), (11, b"bb")]);
        assert!(
            matches!(
                buf.try_recover(ParityKind::P, &parity),
                RecoveryOutcome::AlreadyComplete
            ),
            "ancient, long-forgotten seqs are handled, not missing"
        );
    }

    #[test]
    fn a_peer_sequence_restart_resets_tracking_state() {
        let mut buf = FecRecoveryBuffer::new(2, 1);
        assert!(buf.observe_data(1 << 40, b"zz"));
        // Peer restarts: seqs begin near zero again.
        assert!(buf.observe_data(3, b"aaaa"));
        assert_eq!(buf.highest_seq, 3, "state should have reset to the new run");
        let parity = parity_of(&[(3, b"aaaa"), (4, b"bbbb")]);
        match buf.try_recover(ParityKind::P, &parity) {
            RecoveryOutcome::Recovered(frames) => assert_eq!(frames[0].0, 4),
            other => panic!("expected Recovered after a peer restart, got {other:?}"),
        }
    }

    #[test]
    fn payload_retention_is_hard_capped_regardless_of_ttl() {
        let mut buf = FecRecoveryBuffer::with_params(
            2,
            1,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );
        for seq in 0..(MAX_PAYLOADS as u64 + 500) {
            assert!(buf.observe_data(seq, b"aaaa"));
        }
        assert_eq!(buf.payload_count(), MAX_PAYLOADS);
    }

    #[test]
    fn tick_rotates_the_seen_generations_without_losing_recent_seqs() {
        let mut buf = FecRecoveryBuffer::with_params(
            2,
            1,
            Duration::from_millis(5),
            Duration::from_millis(10),
        );
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
        let mut buf = FecRecoveryBuffer::with_params(
            2,
            1,
            Duration::from_millis(5),
            Duration::from_millis(10),
        );
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
        let outcome = buf.try_recover(ParityKind::P, &parity);
        assert!(
            !matches!(outcome, RecoveryOutcome::Recovered(_)),
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
        let mut buf = FecRecoveryBuffer::with_params(
            2,
            1,
            Duration::from_secs(60),
            Duration::from_millis(10),
        );
        assert!(buf.observe_data(200, b"zzzz"));
        std::thread::sleep(Duration::from_millis(15));
        buf.tick(Instant::now());
        std::thread::sleep(Duration::from_millis(15));
        buf.tick(Instant::now());
        // Floor is now 200; 201/202 are a fresh group above it.
        assert!(buf.observe_data(201, b"aaaa"));
        let parity = parity_of(&[(201, b"aaaa"), (202, b"bbbb")]);
        match buf.try_recover(ParityKind::P, &parity) {
            RecoveryOutcome::Recovered(frames) => {
                let [(seq, plaintext)] = &frames[..] else {
                    panic!("expected exactly one recovered frame, got {frames:?}")
                };
                let (seq, plaintext) = (*seq, plaintext.clone());
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
        let mut buf = FecRecoveryBuffer::with_params(
            2,
            1,
            Duration::from_millis(5),
            Duration::from_millis(10),
        );
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
        match buf.try_recover(ParityKind::P, &parity) {
            RecoveryOutcome::Recovered(frames) => assert_eq!(frames[0].0, 4),
            other => panic!("expected Recovered after a peer restart, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod parity_tests {
    use super::*;

    fn payload(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_mul(31).wrapping_add(i as u8).wrapping_mul(7) ^ 0x5a)
            .collect()
    }

    /// Build a completed group of `n` members with varying lengths.
    fn group(base: u64, n: usize, parity: u8) -> (Vec<(u64, Vec<u8>)>, FecGroup) {
        let mut sender = FecSender::new(n as u8, parity);
        let mut frames = Vec::new();
        let mut done = None;
        for i in 0..n {
            let seq = base + i as u64;
            let data = payload(i as u8 + 1, 40 + i * 13);
            done = sender.accumulate(seq, &data, i % 2);
            frames.push((seq, data));
        }
        (frames, done.expect("group completes"))
    }

    #[test]
    fn gf_multiplication_is_commutative_and_every_nonzero_has_an_inverse() {
        for a in 1..=255u8 {
            assert_eq!(gf::mul(a, gf::inv(a)), 1, "a={a}");
            for b in [1u8, 2, 3, 29, 143, 255] {
                assert_eq!(gf::mul(a, b), gf::mul(b, a));
            }
        }
        assert_eq!(gf::mul(0, 77), 0);
        assert_eq!(gf::mul(1, 77), 77);
    }

    #[test]
    fn gf_generator_powers_are_distinct_across_the_largest_group() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..255 {
            let v = gf::pow2(i);
            assert_ne!(v, 0);
            assert!(seen.insert(v), "g^{i} collided");
        }
    }

    #[test]
    fn parity_one_emits_no_q_share() {
        let (_, g) = group(1, 4, 1);
        assert!(g.q.is_none());
    }

    #[test]
    fn parity_two_emits_a_q_share_aligned_with_p() {
        let (frames, g) = group(100, 5, 2);
        let q = g.q.expect("Q share");
        assert_eq!(q.member_seqs, g.p.member_seqs);
        assert_eq!(q.member_lens, g.p.member_lens);
        assert_eq!(q.parity.len(), g.p.parity.len());
        // Q is the g^i-weighted sum of the zero-padded members.
        let mut want = vec![0u8; q.parity.len()];
        for (i, (_, d)) in frames.iter().enumerate() {
            gf::mul_acc(&mut want, d, gf::pow2(i));
        }
        assert_eq!(q.parity, want);
        assert_ne!(q.parity, g.p.parity, "Q must differ from plain XOR");
        assert_eq!(g.member_links, vec![0, 1, 0, 1, 0]);
    }

    #[test]
    fn parity_two_encoded_q_is_exactly_as_wide_as_p() {
        let (_, g) = group(1, 8, 2);
        assert_eq!(g.p.encode().len(), g.q.unwrap().encode().len());
    }

    #[test]
    fn single_erasure_recovers_from_either_share_alone() {
        let n = 6;
        for missing in 0..n {
            for use_q in [false, true] {
                let (frames, g) = group(10, n, 2);
                let mut buf = FecRecoveryBuffer::new(n as u8, 2);
                for (i, (seq, d)) in frames.iter().enumerate() {
                    if i != missing {
                        assert!(buf.observe_data(*seq, d));
                    }
                }
                let (kind, share) = if use_q {
                    (ParityKind::Q, g.q.as_ref().unwrap())
                } else {
                    (ParityKind::P, &g.p)
                };
                match buf.try_recover(kind, share) {
                    RecoveryOutcome::Recovered(r) => {
                        assert_eq!(
                            r,
                            vec![frames[missing].clone()],
                            "missing={missing} q={use_q}"
                        );
                    }
                    other => panic!("missing={missing} q={use_q}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn every_pair_of_erasures_recovers_in_either_arrival_order() {
        let n = 8;
        for a in 0..n {
            for b in (a + 1)..n {
                for q_first in [false, true] {
                    let (frames, g) = group(1000, n, 2);
                    let mut buf = FecRecoveryBuffer::new(n as u8, 2);
                    for (i, (seq, d)) in frames.iter().enumerate() {
                        if i != a && i != b {
                            assert!(buf.observe_data(*seq, d));
                        }
                    }
                    let q = g.q.as_ref().unwrap();
                    let (first, second) = if q_first {
                        ((ParityKind::Q, q), (ParityKind::P, &g.p))
                    } else {
                        ((ParityKind::P, &g.p), (ParityKind::Q, q))
                    };
                    assert_eq!(
                        buf.try_recover(first.0, first.1),
                        RecoveryOutcome::Pending,
                        "a={a} b={b}"
                    );
                    match buf.try_recover(second.0, second.1) {
                        RecoveryOutcome::Recovered(r) => {
                            assert_eq!(
                                r,
                                vec![frames[a].clone(), frames[b].clone()],
                                "a={a} b={b} q_first={q_first}"
                            );
                        }
                        other => panic!("a={a} b={b}: {other:?}"),
                    }
                    // The real copies turning up afterwards are not
                    // delivered a second time.
                    assert!(!buf.observe_data(frames[a].0, &frames[a].1));
                    assert!(!buf.observe_data(frames[b].0, &frames[b].1));
                }
            }
        }
    }

    #[test]
    fn three_missing_members_are_unrecoverable_immediately_even_with_both_shares() {
        let (frames, g) = group(1, 8, 2);
        let mut buf = FecRecoveryBuffer::new(8, 2);
        for (seq, d) in frames.iter().skip(3) {
            assert!(buf.observe_data(*seq, d));
        }
        assert_eq!(
            buf.try_recover(ParityKind::P, &g.p),
            RecoveryOutcome::Unrecoverable
        );
        assert_eq!(
            buf.try_recover(ParityKind::Q, g.q.as_ref().unwrap()),
            RecoveryOutcome::Unrecoverable
        );
    }

    #[test]
    fn parity_one_buffer_still_treats_two_missing_as_unrecoverable() {
        let (frames, g) = group(1, 4, 1);
        let mut buf = FecRecoveryBuffer::new(4, 1);
        assert!(buf.observe_data(frames[0].0, &frames[0].1));
        assert!(buf.observe_data(frames[1].0, &frames[1].1));
        assert_eq!(
            buf.try_recover(ParityKind::P, &g.p),
            RecoveryOutcome::Unrecoverable
        );
    }

    #[test]
    fn a_late_member_unlocks_a_parked_group_via_the_single_share() {
        let (frames, g) = group(1, 4, 2);
        let mut buf = FecRecoveryBuffer::new(4, 2);
        assert!(buf.observe_data(frames[0].0, &frames[0].1));
        assert!(buf.observe_data(frames[3].0, &frames[3].1));
        // Members 1 and 2 missing, only P arrived.
        assert_eq!(
            buf.try_recover(ParityKind::P, &g.p),
            RecoveryOutcome::Pending
        );
        assert!(!buf.has_late_recoveries());
        // Member 1 limps in late: deliver it, and 2 falls out of P alone.
        assert!(buf.observe_data(frames[1].0, &frames[1].1));
        assert!(buf.has_late_recoveries());
        assert_eq!(buf.take_late_recoveries(), vec![frames[2].clone()]);
        assert!(!buf.has_late_recoveries());
        assert!(!buf.observe_data(frames[2].0, &frames[2].1), "no duplicate");
        assert_eq!(
            buf.tick(Instant::now()),
            0,
            "a resolved group is not given up on"
        );
    }

    #[test]
    fn a_parked_group_that_never_resolves_is_counted_as_unrecoverable_by_tick() {
        let (frames, g) = group(1, 4, 2);
        let mut buf =
            FecRecoveryBuffer::with_params(4, 2, Duration::from_millis(5), Duration::from_secs(60));
        assert!(buf.observe_data(frames[0].0, &frames[0].1));
        assert!(buf.observe_data(frames[3].0, &frames[3].1));
        assert_eq!(
            buf.try_recover(ParityKind::Q, g.q.as_ref().unwrap()),
            RecoveryOutcome::Pending
        );
        assert_eq!(buf.tick(Instant::now()), 0, "not expired yet");
        std::thread::sleep(Duration::from_millis(15));
        assert_eq!(buf.tick(Instant::now()), 1, "expiry is reported once");
        assert_eq!(buf.tick(Instant::now()), 0);
        // The parked bookkeeping is gone: a late member is just data.
        assert!(buf.observe_data(frames[1].0, &frames[1].1));
        assert!(!buf.has_late_recoveries());
    }

    #[test]
    fn parked_groups_are_bounded() {
        let mut buf = FecRecoveryBuffer::new(4, 2);
        for k in 0..(MAX_PARKED_GROUPS as u64 + 50) {
            let (frames, g) = group(10_000 + k * 10, 4, 2);
            assert!(buf.observe_data(frames[0].0, &frames[0].1));
            assert!(buf.observe_data(frames[3].0, &frames[3].1));
            assert_eq!(
                buf.try_recover(ParityKind::P, &g.p),
                RecoveryOutcome::Pending
            );
        }
        assert!(buf.parked.len() <= MAX_PARKED_GROUPS);
        assert!(buf.tick(Instant::now()) >= 50, "evictions are reported");
    }

    #[test]
    fn a_duplicate_share_does_not_recover_twice() {
        let (frames, g) = group(1, 5, 2);
        let mut buf = FecRecoveryBuffer::new(5, 2);
        for (i, (seq, d)) in frames.iter().enumerate() {
            if i != 2 && i != 4 {
                assert!(buf.observe_data(*seq, d));
            }
        }
        assert_eq!(
            buf.try_recover(ParityKind::P, &g.p),
            RecoveryOutcome::Pending
        );
        assert!(matches!(
            buf.try_recover(ParityKind::Q, g.q.as_ref().unwrap()),
            RecoveryOutcome::Recovered(_)
        ));
        assert_eq!(
            buf.try_recover(ParityKind::Q, g.q.as_ref().unwrap()),
            RecoveryOutcome::AlreadyComplete
        );
        assert_eq!(
            buf.try_recover(ParityKind::P, &g.p),
            RecoveryOutcome::AlreadyComplete
        );
    }

    #[test]
    fn mismatched_shares_are_rejected_not_combined() {
        let (frames, g) = group(1, 4, 2);
        let (_, other) = group(1, 4, 2);
        let mut bad_q = other.q.unwrap();
        bad_q.member_lens[0] += 1;
        let mut buf = FecRecoveryBuffer::new(4, 2);
        assert!(buf.observe_data(frames[0].0, &frames[0].1));
        assert!(buf.observe_data(frames[1].0, &frames[1].1));
        assert_eq!(
            buf.try_recover(ParityKind::P, &g.p),
            RecoveryOutcome::Pending
        );
        assert_eq!(
            buf.try_recover(ParityKind::Q, &bad_q),
            RecoveryOutcome::Unrecoverable
        );
    }

    #[test]
    fn dominant_placement_picks_the_link_carrying_the_most_members() {
        let usable = [true, true];
        let links = [0, 0, 0, 0, 0, 0, 1, 1];
        assert_eq!(
            choose_parity_link(FecParityPlacement::Dominant, &links, &usable),
            Some(0)
        );
        assert_eq!(
            choose_parity_link(FecParityPlacement::Diverse, &links, &usable),
            Some(1)
        );
    }

    #[test]
    fn placement_ignores_unusable_links_and_defers_on_ties() {
        let links = [0, 0, 0, 1, 1];
        assert_eq!(
            choose_parity_link(FecParityPlacement::Dominant, &links, &[false, true]),
            Some(1),
            "the dominant link is down: use the one that is up"
        );
        assert_eq!(
            choose_parity_link(FecParityPlacement::Dominant, &[0, 0, 1, 1], &[true, true]),
            None,
            "a tie leaves the choice to the scheduler"
        );
        assert_eq!(
            choose_parity_link(FecParityPlacement::Dominant, &[0, 1], &[false, false]),
            None
        );
        assert_eq!(
            choose_parity_link(FecParityPlacement::Dominant, &[], &[true, true]),
            None
        );
        assert_eq!(
            choose_parity_link(FecParityPlacement::Scheduler, &links, &[true, true]),
            None
        );
    }

    #[test]
    fn dominant_placement_never_picks_a_usable_link_that_carried_nothing() {
        // Everything rode link 0, which is now down; link 1 carried no
        // members, so "dominant" has no real preference.
        assert_eq!(
            choose_parity_link(FecParityPlacement::Dominant, &[0, 0, 0], &[false, true]),
            None
        );
    }
}

/// Deterministic loss-pattern simulation (plan Phase 5): drives the real
/// `FecSender` / `FecRecoveryBuffer` / `choose_parity_link` through
/// scripted loss over a modelled two-link wire and reports recovery %,
/// bandwidth overhead and recovery delay per configuration. Run with
/// `cargo test --release --lib fec_sim -- --nocapture` for the table.
#[cfg(test)]
mod fec_sim_tests {
    use super::*;

    const GROUP: usize = 8;
    const GROUPS: usize = 400;
    const DATA_LEN: usize = 1200;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum Frame {
        Data(usize),
        P(usize),
        Q(usize),
    }

    #[derive(Clone, Copy)]
    struct Cfg {
        name: &'static str,
        parity: u8,
        placement: FecParityPlacement,
    }

    const CONFIGS: [Cfg; 4] = [
        Cfg {
            name: "P1 scheduler",
            parity: 1,
            placement: FecParityPlacement::Scheduler,
        },
        Cfg {
            name: "P2 scheduler",
            parity: 2,
            placement: FecParityPlacement::Scheduler,
        },
        Cfg {
            name: "P2 dominant",
            parity: 2,
            placement: FecParityPlacement::Dominant,
        },
        Cfg {
            name: "P2 diverse",
            parity: 2,
            placement: FecParityPlacement::Diverse,
        },
    ];

    /// Loss decision for one wire frame: `(frame, wire_index, link)`.
    type Loss = fn(Frame, usize, usize) -> bool;

    fn splitmix(mut x: u64) -> u64 {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    fn data_bytes(i: usize) -> Vec<u8> {
        let len = DATA_LEN - (i % 5) * 37;
        (0..len)
            .map(|j| (splitmix((i * 4099 + j) as u64) & 0xff) as u8)
            .collect()
    }

    fn pos(i: usize) -> (usize, usize) {
        (i / GROUP, i % GROUP)
    }

    fn loss_single(f: Frame, _: usize, _: usize) -> bool {
        matches!(f, Frame::Data(i) if { let (g, p) = pos(i); p == (g * 3) % GROUP })
    }
    fn loss_adjacent2(f: Frame, _: usize, _: usize) -> bool {
        matches!(f, Frame::Data(i) if { let (g, p) = pos(i); let s = (g * 3) % (GROUP - 1); p == s || p == s + 1 })
    }
    fn loss_adjacent3(f: Frame, _: usize, _: usize) -> bool {
        matches!(f, Frame::Data(i) if { let (g, p) = pos(i); let s = (g * 3) % (GROUP - 2); (s..s + 3).contains(&p) })
    }
    fn loss_random5(f: Frame, _: usize, _: usize) -> bool {
        let key = match f {
            Frame::Data(i) => i as u64 * 4,
            Frame::P(g) => g as u64 * 4 + 1,
            Frame::Q(g) => g as u64 * 4 + 2,
        };
        splitmix(key ^ 0xfeed) % 100 < 5
    }
    /// Short bursts alternate between the paths: 4 wire frames with
    /// link 0 dead, 14 healthy, 4 with link 1 dead, 14 healthy.
    fn loss_alternating_path(_: Frame, w: usize, link: usize) -> bool {
        match w % 36 {
            0..=3 => link == 0,
            18..=21 => link == 1,
            _ => false,
        }
    }
    /// A hard link outage: 20 wire frames with link 0 dead, 20 healthy,
    /// 20 with link 1 dead, 20 healthy. Far beyond any parity count.
    fn loss_link_outage(_: Frame, w: usize, link: usize) -> bool {
        match w % 80 {
            0..=19 => link == 0,
            40..=59 => link == 1,
            _ => false,
        }
    }

    #[derive(Default, Debug)]
    struct Report {
        lost: usize,
        recovered: usize,
        parity_bytes: usize,
        data_bytes: usize,
        delay_sum: usize,
        wire_frames: usize,
    }

    impl Report {
        fn pct(&self) -> f64 {
            if self.lost == 0 {
                100.0
            } else {
                self.recovered as f64 * 100.0 / self.lost as f64
            }
        }
        fn overhead(&self) -> f64 {
            self.parity_bytes as f64 * 100.0 / self.data_bytes as f64
        }
        fn mean_delay(&self) -> f64 {
            if self.recovered == 0 {
                0.0
            } else {
                self.delay_sum as f64 / self.recovered as f64
            }
        }
    }

    /// Run one scenario. `cycle` is the scheduler's repeating link
    /// assignment for unforced frames (data and unforced parity alike).
    fn simulate(cfg: Cfg, cycle: &[usize], loss: Loss) -> Report {
        // Sender: build the wire (frame, link) sequence.
        let mut wire: Vec<(Frame, usize, Vec<u8>)> = Vec::new();
        let mut sender = FecSender::new(GROUP as u8, cfg.parity);
        let mut rot = 0usize;
        let next_link = |rot: &mut usize| {
            let l = cycle[*rot % cycle.len()];
            *rot += 1;
            l
        };
        let mut originals: Vec<Vec<u8>> = Vec::new();
        let mut rep = Report::default();
        for i in 0..GROUPS * GROUP {
            let data = data_bytes(i);
            let link = next_link(&mut rot);
            rep.data_bytes += data.len();
            if let Some(g) = sender.accumulate(i as u64, &data, link) {
                wire.push((Frame::Data(i), link, data.clone()));
                let gi = i / GROUP;
                let forced = choose_parity_link(cfg.placement, &g.member_links, &[true, true]);
                let pl = forced.unwrap_or_else(|| next_link(&mut rot));
                rep.parity_bytes += g.p.encode().len();
                wire.push((Frame::P(gi), pl, g.p.encode()));
                if let Some(q) = g.q {
                    let ql = forced.unwrap_or_else(|| next_link(&mut rot));
                    rep.parity_bytes += q.encode().len();
                    wire.push((Frame::Q(gi), ql, q.encode()));
                }
            } else {
                wire.push((Frame::Data(i), link, data.clone()));
            }
            originals.push(data);
        }
        rep.wire_frames = wire.len();

        // Receiver: deliver surviving frames in wire order.
        let mut buf = FecRecoveryBuffer::new(GROUP as u8, cfg.parity);
        let mut delivered = std::collections::HashSet::new();
        let mut wire_pos_of_data = std::collections::HashMap::new();
        for (w, (f, _, _)) in wire.iter().enumerate() {
            if let Frame::Data(i) = f {
                wire_pos_of_data.insert(*i as u64, w);
            }
        }
        for (w, (f, link, bytes)) in wire.iter().enumerate() {
            let dropped = loss(*f, w, *link);
            if dropped {
                if matches!(f, Frame::Data(_)) {
                    rep.lost += 1;
                }
                continue;
            }
            let mut recovered: Vec<(u64, Vec<u8>)> = Vec::new();
            match f {
                Frame::Data(i) => {
                    if buf.observe_data(*i as u64, bytes) {
                        assert!(delivered.insert(*i as u64), "duplicate delivery of {i}");
                    }
                    if buf.has_late_recoveries() {
                        recovered.extend(buf.take_late_recoveries());
                    }
                }
                Frame::P(_) | Frame::Q(_) => {
                    let kind = if matches!(f, Frame::P(_)) {
                        ParityKind::P
                    } else {
                        ParityKind::Q
                    };
                    let payload = FecParityPayload::decode(bytes).expect("decode parity");
                    if let RecoveryOutcome::Recovered(r) = buf.try_recover(kind, &payload) {
                        recovered = r;
                    }
                }
            }
            for (seq, data) in recovered {
                assert_eq!(
                    data, originals[seq as usize],
                    "recovered bytes differ for {seq}"
                );
                assert!(
                    delivered.insert(seq),
                    "duplicate delivery of recovered {seq}"
                );
                rep.recovered += 1;
                rep.delay_sum += w - wire_pos_of_data[&seq];
            }
        }
        rep
    }

    const PATTERNS: [(&str, Loss); 6] = [
        ("single loss", loss_single),
        ("2 adjacent losses", loss_adjacent2),
        ("3 adjacent losses", loss_adjacent3),
        ("random 5% loss", loss_random5),
        ("alternating-path burst", loss_alternating_path),
        ("hard link outage", loss_link_outage),
    ];

    fn table(title: &str, cycle: &[usize]) -> Vec<Vec<Report>> {
        println!("\n== {title} (link cycle {cycle:?}, group {GROUP}) ==");
        println!(
            "{:<22} {:<14} {:>9} {:>10} {:>11} {:>14}",
            "pattern", "config", "recov %", "overhead %", "lost frames", "mean delay (wire frames)"
        );
        let mut all = Vec::new();
        for (pname, loss) in PATTERNS {
            let mut row = Vec::new();
            for cfg in CONFIGS {
                let r = simulate(cfg, cycle, loss);
                println!(
                    "{:<22} {:<14} {:>9.1} {:>10.1} {:>11} {:>14.2}",
                    pname,
                    cfg.name,
                    r.pct(),
                    r.overhead(),
                    r.lost,
                    r.mean_delay()
                );
                row.push(r);
            }
            all.push(row);
        }
        all
    }

    #[test]
    fn fec_sim_balanced_links() {
        let t = table("balanced links", &[0, 1]);
        // single: everyone recovers everything; P2 costs twice the parity.
        for r in &t[0] {
            assert_eq!(r.recovered, r.lost);
        }
        // 1/8 of the data bytes plus the per-member header and the
        // longest-member padding (members here are 1015-1200 bytes).
        assert!(
            (12.0..16.0).contains(&t[0][0].overhead()),
            "P1 overhead {}",
            t[0][0].overhead()
        );
        assert!(
            (24.0..32.0).contains(&t[0][1].overhead()),
            "P2 overhead {}",
            t[0][1].overhead()
        );
        assert!(
            (t[0][1].overhead() / t[0][0].overhead() - 2.0).abs() < 0.01,
            "P2 costs exactly twice P1's parity bytes"
        );
        // 2 adjacent: P1 recovers nothing, P2 recovers everything.
        assert_eq!(t[1][0].recovered, 0);
        for r in &t[1][1..] {
            assert_eq!(r.recovered, r.lost, "P2 must repair any 2 erasures");
        }
        // 3 adjacent exceeds any parity count.
        for r in &t[2] {
            assert_eq!(r.recovered, 0);
        }
        // P2 is never worse than P1 under random loss, and strictly better.
        assert!(t[3][1].recovered > t[3][0].recovered);
        // Added delay: recovery lands when the group's parity does, within a group's span.
        for row in &t {
            for r in row {
                assert!(
                    r.mean_delay() <= (GROUP + 2) as f64,
                    "delay {}",
                    r.mean_delay()
                );
            }
        }
    }

    #[test]
    fn fec_sim_skewed_links_favor_dominant_placement() {
        let t = table("skewed 3:1 links", &[0, 0, 0, 1]);
        // Short bursts: any parity=2 config beats parity=1; where the
        // parity frames land is within noise (they are rarely inside
        // the burst), so nothing is asserted about placement here.
        let burst = &t[4];
        for r in &burst[1..] {
            assert!(
                r.recovered > burst[0].recovered,
                "P2 must beat P1 on short bursts"
            );
        }
        // Sustained outages: the minority link (1 of 4 slots) failing is
        // the only recoverable case, and only if parity is not on it.
        // `dominant` always keeps parity off the minority link; `diverse`
        // always puts it there and loses everything; the scheduler's
        // rotation lands in between.
        let outage = &t[5];
        let (p1, p2_sched, p2_dom, p2_div) = (&outage[0], &outage[1], &outage[2], &outage[3]);
        assert_eq!(
            p2_div.recovered, 0,
            "diverse parity dies with the minority link"
        );
        assert!(
            p2_dom.recovered > p2_sched.recovered,
            "dominant beats the scheduler's pick"
        );
        assert!(p2_dom.recovered > p1.recovered, "dominant P2 beats P1");
    }
}

/// CPU cost of the FEC paths for full-size frames. `#[ignore]`d: timing
/// is only meaningful in release. Run with
/// `cargo test --release --lib fec_cpu_cost -- --ignored --nocapture`.
#[cfg(test)]
mod fec_cpu_bench {
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore = "timing benchmark; run in release with --nocapture"]
    fn fec_cpu_cost() {
        const ITERS: usize = 20_000;
        let frames: Vec<Vec<u8>> = (0..8)
            .map(|i| (0..1368).map(|j| (i * 31 + j) as u8).collect())
            .collect();

        for parity in [1u8, 2] {
            let mut sender = FecSender::new(8, parity);
            let t = Instant::now();
            let mut seq = 0u64;
            let mut last = None;
            for _ in 0..ITERS {
                for f in &frames {
                    last = sender.accumulate(seq, f, 0);
                    seq += 1;
                }
            }
            let per_group = t.elapsed().as_nanos() as f64 / ITERS as f64;
            println!(
                "encode  parity={parity}: {per_group:8.0} ns/group  ({:.0} ns/frame, {:.2} Gbit/s of payload)",
                per_group / 8.0,
                8.0 * 1368.0 * 8.0 / per_group
            );
            assert!(last.is_some());
        }

        for (missing, label) in [(1usize, "1 erasure (P)"), (2, "2 erasures (P+Q)")] {
            let mut sender = FecSender::new(8, 2);
            let mut group = None;
            for (i, f) in frames.iter().enumerate() {
                group = sender.accumulate(i as u64, f, 0);
            }
            let g = group.unwrap();
            let q = g.q.clone().unwrap();
            let t = Instant::now();
            for it in 0..ITERS {
                let base = (it as u64) * 1000;
                let remap = |p: &FecParityPayload| FecParityPayload {
                    member_seqs: (0..8).map(|i| base + i).collect(),
                    member_lens: p.member_lens.clone(),
                    parity: p.parity.clone(),
                };
                let (p, q) = (remap(&g.p), remap(&q));
                let mut buf = FecRecoveryBuffer::new(8, 2);
                for (i, f) in frames.iter().enumerate().skip(missing) {
                    let _ = buf.observe_data(base + i as u64, f);
                }
                let _ = buf.try_recover(ParityKind::P, &p);
                if missing == 2 {
                    let _ = buf.try_recover(ParityKind::Q, &q);
                }
            }
            let per = t.elapsed().as_nanos() as f64 / ITERS as f64;
            println!("recover {label:<16}: {per:8.0} ns/group (includes buffer setup and cloning)");
        }
    }
}
