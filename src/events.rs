//! Structured daemon events: the typed counterpart to `logbuf`'s free-text
//! log ring. An `EventDetector` diffs successive observations of daemon
//! state (link states, counters) and emits an `EventRecord` per
//! operationally interesting transition; `EventRing` keeps the most recent
//! ones and serves per-client deltas into `Snapshot::new_events`.
//!
//! Detection is poll-based (see `telemetry::run`) rather than hooked into
//! the data path, so it adds nothing to per-packet cost and cannot stall a
//! worker. Counter-driven kinds are aggregated per (kind, link) and
//! emitted at most once per `COUNTER_THROTTLE_MS`, carrying the number of
//! occurrences in `fields["count"]`, so a sustained fault produces a
//! steady trickle instead of flooding the ring.
//!
//! `MtuNegotiationFailed` is part of the schema but not emitted yet: the
//! daemon has no point at which it can distinguish a failed negotiation
//! from one still converging.

use crate::ipc::EventRecord;
use crate::link::LinkState;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const EVENT_RING_CAPACITY: usize = 1000;
const COUNTER_THROTTLE_MS: u64 = 2_000;
/// A throttle window's worth of late frames below this is ordinary
/// cross-link jitter, not worth an event.
const REORDER_WARN_MIN: u64 = 50;
const LOSSY_ENTER_PCT: f64 = 5.0;
const LOSSY_EXIT_PCT: f64 = 2.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    LinkUp,
    LinkDown,
    LinkDegraded,
    LinkRecovered,
    CongestionDetected,
    CongestionCleared,
    TxQueueFull,
    SendFailure,
    Reroute,
    FecRecovery,
    FecUnrecoverable,
    ReorderWarning,
    MtuChanged,
    MtuNegotiationFailed,
    WireguardHandshake,
    WireguardRekey,
    WireguardError,
    TunDrop,
    OutboundQueueDrop,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::LinkUp => "LINK_UP",
            EventKind::LinkDown => "LINK_DOWN",
            EventKind::LinkDegraded => "LINK_DEGRADED",
            EventKind::LinkRecovered => "LINK_RECOVERED",
            EventKind::CongestionDetected => "CONGESTION_DETECTED",
            EventKind::CongestionCleared => "CONGESTION_CLEARED",
            EventKind::TxQueueFull => "TX_QUEUE_FULL",
            EventKind::SendFailure => "SEND_FAILURE",
            EventKind::Reroute => "REROUTE",
            EventKind::FecRecovery => "FEC_RECOVERY",
            EventKind::FecUnrecoverable => "FEC_UNRECOVERABLE",
            EventKind::ReorderWarning => "REORDER_WARNING",
            EventKind::MtuChanged => "MTU_CHANGED",
            EventKind::MtuNegotiationFailed => "MTU_NEGOTIATION_FAILED",
            EventKind::WireguardHandshake => "WIREGUARD_HANDSHAKE",
            EventKind::WireguardRekey => "WIREGUARD_REKEY",
            EventKind::WireguardError => "WIREGUARD_ERROR",
            EventKind::TunDrop => "TUN_DROP",
            EventKind::OutboundQueueDrop => "OUTBOUND_QUEUE_DROP",
        }
    }

    /// Kinds that mean packets were lost or the tunnel could not carry
    /// them -- what flips overall health to DEGRADED for a short while.
    pub fn is_loss(self) -> bool {
        matches!(
            self,
            EventKind::FecUnrecoverable
                | EventKind::SendFailure
                | EventKind::TunDrop
                | EventKind::OutboundQueueDrop
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewEvent {
    pub kind: EventKind,
    pub severity: Severity,
    pub link: Option<String>,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

pub struct EventRing {
    entries: Mutex<VecDeque<EventRecord>>,
    next_seq: AtomicU64,
}

impl EventRing {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(EVENT_RING_CAPACITY)),
            // Starts at 1 so a cursor of 0 means "nothing seen yet", same
            // convention as `LogRing`.
            next_seq: AtomicU64::new(1),
        }
    }

    pub fn push(&self, ev: NewEvent) {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let unix_ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut entries = self.entries.lock().unwrap();
        if entries.len() == EVENT_RING_CAPACITY {
            entries.pop_front();
        }
        entries.push_back(EventRecord {
            seq,
            unix_ts_ms,
            severity: ev.severity.as_str().to_string(),
            kind: ev.kind.as_str().to_string(),
            link: ev.link,
            message: ev.message,
            fields: ev.fields,
        });
    }

    pub fn entries_since(&self, since: u64) -> Vec<EventRecord> {
        let entries = self.entries.lock().unwrap();
        entries.iter().filter(|e| e.seq > since).cloned().collect()
    }
}

impl Default for EventRing {
    fn default() -> Self {
        Self::new()
    }
}

/// One link's state as seen by one `observe` call.
#[derive(Debug, Clone)]
pub struct LinkObs {
    pub name: String,
    pub state: LinkState,
    pub congested: bool,
    pub loss_pct: Option<f64>,
    pub queue_full: u64,
    pub send_failed: u64,
    pub rerouted: u64,
    pub wg_rejected: u64,
    pub handshake_age_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Obs {
    pub now_ms: u64,
    pub links: Vec<LinkObs>,
    pub fec_recovered: u64,
    pub fec_unrecoverable: u64,
    pub outbound_dropped: u64,
    pub tun_dropped: u64,
    pub reorder_timeouts: u64,
    pub mtu: u16,
}

#[derive(Default)]
struct LinkTrack {
    state: Option<LinkState>,
    ever_up: bool,
    congested: bool,
    lossy: bool,
    queue_full: u64,
    send_failed: u64,
    rerouted: u64,
    wg_rejected: u64,
    handshake_age_ms: Option<u64>,
}

type CounterKey = (EventKind, usize);
const GLOBAL: usize = usize::MAX;

#[derive(Default)]
pub struct EventDetector {
    seeded: bool,
    links: Vec<LinkTrack>,
    fec_recovered: u64,
    fec_unrecoverable: u64,
    outbound_dropped: u64,
    tun_dropped: u64,
    reorder_timeouts: u64,
    mtu: u16,
    pending: HashMap<CounterKey, u64>,
    last_emit_ms: HashMap<CounterKey, u64>,
}

fn fields(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

impl EventDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compare `obs` with the previous observation and return the events
    /// for everything that changed. The first call only records a
    /// baseline.
    pub fn observe(&mut self, obs: &Obs) -> Vec<NewEvent> {
        let mut out = Vec::new();
        if self.links.len() < obs.links.len() {
            self.links.resize_with(obs.links.len(), LinkTrack::default);
        }

        for (idx, l) in obs.links.iter().enumerate() {
            self.observe_link(idx, l, self.seeded, &mut out);
        }

        if self.seeded {
            if obs.mtu != self.mtu && self.mtu != 0 {
                out.push(NewEvent {
                    kind: EventKind::MtuChanged,
                    severity: Severity::Info,
                    link: None,
                    message: format!("tunnel MTU changed {} -> {}", self.mtu, obs.mtu),
                    fields: fields(&[("from", self.mtu.to_string()), ("to", obs.mtu.to_string())]),
                });
            }
            self.add_delta(
                EventKind::FecRecovery,
                GLOBAL,
                obs.fec_recovered,
                self.fec_recovered,
            );
            self.add_delta(
                EventKind::FecUnrecoverable,
                GLOBAL,
                obs.fec_unrecoverable,
                self.fec_unrecoverable,
            );
            self.add_delta(
                EventKind::OutboundQueueDrop,
                GLOBAL,
                obs.outbound_dropped,
                self.outbound_dropped,
            );
            self.add_delta(
                EventKind::TunDrop,
                GLOBAL,
                obs.tun_dropped,
                self.tun_dropped,
            );
            self.add_delta(
                EventKind::ReorderWarning,
                GLOBAL,
                obs.reorder_timeouts,
                self.reorder_timeouts,
            );
        }
        self.fec_recovered = obs.fec_recovered;
        self.fec_unrecoverable = obs.fec_unrecoverable;
        self.outbound_dropped = obs.outbound_dropped;
        self.tun_dropped = obs.tun_dropped;
        self.reorder_timeouts = obs.reorder_timeouts;
        self.mtu = obs.mtu;
        self.seeded = true;

        self.flush_counters(obs.now_ms, obs, &mut out);
        out
    }

    fn observe_link(&mut self, idx: usize, l: &LinkObs, emit: bool, out: &mut Vec<NewEvent>) {
        let mut deltas: Vec<(EventKind, u64, u64)> = Vec::new();
        {
            let t = &mut self.links[idx];
            let link = Some(l.name.clone());
            let mk = |kind, severity, message: String, f: BTreeMap<String, String>| NewEvent {
                kind,
                severity,
                link: link.clone(),
                message,
                fields: f,
            };

            if let Some(prev) = t.state {
                if prev != l.state && emit {
                    let f = fields(&[
                        ("from", prev.as_str().to_string()),
                        ("to", l.state.as_str().to_string()),
                    ]);
                    match l.state {
                        LinkState::Up if t.ever_up => out.push(mk(
                            EventKind::LinkRecovered,
                            Severity::Info,
                            format!("link {} is back up", l.name),
                            f,
                        )),
                        LinkState::Up => out.push(mk(
                            EventKind::LinkUp,
                            Severity::Info,
                            format!("link {} is up", l.name),
                            f,
                        )),
                        LinkState::Down => out.push(mk(
                            EventKind::LinkDown,
                            Severity::Error,
                            format!("link {} is down", l.name),
                            f,
                        )),
                        LinkState::Probing => {}
                    }
                }
            }
            if l.state == LinkState::Up {
                t.ever_up = true;
            }
            t.state = Some(l.state);

            if emit && l.state == LinkState::Up {
                if l.congested && !t.congested {
                    out.push(mk(
                        EventKind::CongestionDetected,
                        Severity::Warn,
                        format!(
                            "link {} is congested; traffic is being shifted away",
                            l.name
                        ),
                        BTreeMap::new(),
                    ));
                } else if !l.congested && t.congested {
                    out.push(mk(
                        EventKind::CongestionCleared,
                        Severity::Info,
                        format!("link {} congestion cleared", l.name),
                        BTreeMap::new(),
                    ));
                }
                if let Some(loss) = l.loss_pct {
                    if loss >= LOSSY_ENTER_PCT && !t.lossy {
                        out.push(mk(
                            EventKind::LinkDegraded,
                            Severity::Warn,
                            format!("link {} loss is {:.1}%", l.name, loss),
                            fields(&[("loss_pct", format!("{loss:.1}"))]),
                        ));
                    } else if loss <= LOSSY_EXIT_PCT && t.lossy {
                        out.push(mk(
                            EventKind::LinkRecovered,
                            Severity::Info,
                            format!("link {} loss is back to {:.1}%", l.name, loss),
                            fields(&[("loss_pct", format!("{loss:.1}"))]),
                        ));
                    }
                }
            }
            if l.state == LinkState::Up {
                t.congested = l.congested;
            } else {
                t.congested = false;
            }
            match l.loss_pct {
                Some(loss) if l.state == LinkState::Up => {
                    if loss >= LOSSY_ENTER_PCT {
                        t.lossy = true;
                    } else if loss <= LOSSY_EXIT_PCT {
                        t.lossy = false;
                    }
                }
                _ => t.lossy = false,
            }

            if emit {
                match (t.handshake_age_ms, l.handshake_age_ms) {
                    (None, Some(age)) => out.push(mk(
                        EventKind::WireguardHandshake,
                        Severity::Info,
                        format!("link {} completed its WireGuard handshake", l.name),
                        fields(&[("age_ms", age.to_string())]),
                    )),
                    (Some(prev), Some(now)) if now < prev => out.push(mk(
                        EventKind::WireguardRekey,
                        Severity::Info,
                        format!("link {} rekeyed", l.name),
                        BTreeMap::new(),
                    )),
                    _ => {}
                }
                deltas.push((EventKind::TxQueueFull, l.queue_full, t.queue_full));
                deltas.push((EventKind::SendFailure, l.send_failed, t.send_failed));
                deltas.push((EventKind::Reroute, l.rerouted, t.rerouted));
                deltas.push((EventKind::WireguardError, l.wg_rejected, t.wg_rejected));
            }
            t.handshake_age_ms = l.handshake_age_ms;
            t.queue_full = l.queue_full;
            t.send_failed = l.send_failed;
            t.rerouted = l.rerouted;
            t.wg_rejected = l.wg_rejected;
        }
        for (kind, now, prev) in deltas {
            self.add_delta(kind, idx, now, prev);
        }
    }

    fn add_delta(&mut self, kind: EventKind, idx: usize, now: u64, prev: u64) {
        if now > prev {
            *self.pending.entry((kind, idx)).or_insert(0) += now - prev;
        }
    }

    fn flush_counters(&mut self, now_ms: u64, obs: &Obs, out: &mut Vec<NewEvent>) {
        let mut due: Vec<CounterKey> = self
            .pending
            .iter()
            .filter(|(k, n)| {
                **n > 0
                    && self
                        .last_emit_ms
                        .get(*k)
                        .is_none_or(|t| now_ms.saturating_sub(*t) >= COUNTER_THROTTLE_MS)
            })
            .map(|(k, _)| *k)
            .collect();
        due.sort_by_key(|(k, idx)| (k.as_str(), *idx));
        for key in due {
            let n = self.pending.remove(&key).unwrap_or(0);
            self.last_emit_ms.insert(key, now_ms);
            let (kind, idx) = key;
            if kind == EventKind::ReorderWarning && n < REORDER_WARN_MIN {
                continue;
            }
            let link = obs.links.get(idx).map(|l| l.name.clone());
            let who = link.clone().unwrap_or_default();
            let (severity, message) = match kind {
                EventKind::TxQueueFull => (
                    Severity::Warn,
                    format!("link {who}: TX queue was full {n} time(s)"),
                ),
                EventKind::SendFailure => (
                    Severity::Warn,
                    format!("link {who}: {n} packet(s) failed to send"),
                ),
                EventKind::Reroute => (
                    Severity::Info,
                    format!("link {who}: {n} packet(s) rerouted to another link"),
                ),
                EventKind::WireguardError => (
                    Severity::Warn,
                    format!("link {who}: {n} datagram(s) rejected by WireGuard"),
                ),
                EventKind::FecRecovery => {
                    (Severity::Info, format!("FEC recovered {n} lost frame(s)"))
                }
                EventKind::FecUnrecoverable => (
                    Severity::Warn,
                    format!("FEC could not recover {n} parity group share(s)"),
                ),
                EventKind::OutboundQueueDrop => (
                    Severity::Warn,
                    format!("{n} packet(s) dropped: outbound queue full"),
                ),
                EventKind::TunDrop => (Severity::Warn, format!("TUN device dropped {n} packet(s)")),
                EventKind::ReorderWarning => (
                    Severity::Warn,
                    format!("{n} frame(s) waited out the full reorder window"),
                ),
                _ => continue,
            };
            out.push(NewEvent {
                kind,
                severity,
                link,
                message,
                fields: fields(&[("count", n.to_string())]),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(name: &str, state: LinkState) -> LinkObs {
        LinkObs {
            name: name.to_string(),
            state,
            congested: false,
            loss_pct: None,
            queue_full: 0,
            send_failed: 0,
            rerouted: 0,
            wg_rejected: 0,
            handshake_age_ms: None,
        }
    }

    fn obs(now_ms: u64, links: Vec<LinkObs>) -> Obs {
        Obs {
            now_ms,
            links,
            fec_recovered: 0,
            fec_unrecoverable: 0,
            outbound_dropped: 0,
            tun_dropped: 0,
            reorder_timeouts: 0,
            mtu: 1400,
        }
    }

    fn kinds(ev: &[NewEvent]) -> Vec<&'static str> {
        ev.iter().map(|e| e.kind.as_str()).collect()
    }

    #[test]
    fn first_observation_is_only_a_baseline() {
        let mut d = EventDetector::new();
        assert!(d
            .observe(&obs(0, vec![link("a", LinkState::Up)]))
            .is_empty());
    }

    #[test]
    fn link_state_transitions_map_to_up_down_recovered() {
        let mut d = EventDetector::new();
        d.observe(&obs(0, vec![link("a", LinkState::Probing)]));
        let ev = d.observe(&obs(500, vec![link("a", LinkState::Up)]));
        assert_eq!(kinds(&ev), ["LINK_UP"]);
        let ev = d.observe(&obs(1000, vec![link("a", LinkState::Down)]));
        assert_eq!(kinds(&ev), ["LINK_DOWN"]);
        assert_eq!(ev[0].severity, Severity::Error);
        let ev = d.observe(&obs(1500, vec![link("a", LinkState::Up)]));
        assert_eq!(kinds(&ev), ["LINK_RECOVERED"]);
        assert_eq!(ev[0].link.as_deref(), Some("a"));
    }

    #[test]
    fn congestion_flag_emits_detected_then_cleared_once_each() {
        let mut d = EventDetector::new();
        d.observe(&obs(0, vec![link("a", LinkState::Up)]));
        let mut l = link("a", LinkState::Up);
        l.congested = true;
        assert_eq!(
            kinds(&d.observe(&obs(500, vec![l.clone()]))),
            ["CONGESTION_DETECTED"]
        );
        assert!(d.observe(&obs(1000, vec![l])).is_empty());
        assert_eq!(
            kinds(&d.observe(&obs(1500, vec![link("a", LinkState::Up)]))),
            ["CONGESTION_CLEARED"]
        );
    }

    #[test]
    fn loss_uses_hysteresis() {
        let mut d = EventDetector::new();
        d.observe(&obs(0, vec![link("a", LinkState::Up)]));
        let at = |loss: f64| {
            let mut l = link("a", LinkState::Up);
            l.loss_pct = Some(loss);
            l
        };
        assert_eq!(
            kinds(&d.observe(&obs(500, vec![at(6.0)]))),
            ["LINK_DEGRADED"]
        );
        assert!(d.observe(&obs(1000, vec![at(3.0)])).is_empty());
        assert_eq!(
            kinds(&d.observe(&obs(1500, vec![at(1.0)]))),
            ["LINK_RECOVERED"]
        );
    }

    #[test]
    fn counter_events_aggregate_and_throttle() {
        let mut d = EventDetector::new();
        d.observe(&obs(0, vec![link("a", LinkState::Up)]));
        let with_full = |n: u64| {
            let mut l = link("a", LinkState::Up);
            l.queue_full = n;
            l
        };
        let ev = d.observe(&obs(500, vec![with_full(3)]));
        assert_eq!(kinds(&ev), ["TX_QUEUE_FULL"]);
        assert_eq!(ev[0].fields["count"], "3");
        // Within the throttle window: accumulated, not emitted.
        assert!(d.observe(&obs(1000, vec![with_full(5)])).is_empty());
        assert!(d.observe(&obs(1500, vec![with_full(9)])).is_empty());
        // Window elapsed: one event carrying everything since the last.
        let ev = d.observe(&obs(2600, vec![with_full(9)]));
        assert_eq!(kinds(&ev), ["TX_QUEUE_FULL"]);
        assert_eq!(ev[0].fields["count"], "6");
    }

    #[test]
    fn global_counters_and_mtu_change() {
        let mut d = EventDetector::new();
        d.observe(&obs(0, vec![link("a", LinkState::Up)]));
        let mut o = obs(500, vec![link("a", LinkState::Up)]);
        o.fec_recovered = 2;
        o.fec_unrecoverable = 1;
        o.outbound_dropped = 4;
        o.tun_dropped = 1;
        o.reorder_timeouts = 70;
        o.mtu = 1280;
        let ev = d.observe(&o);
        let mut k = kinds(&ev);
        k.sort();
        assert_eq!(
            k,
            [
                "FEC_RECOVERY",
                "FEC_UNRECOVERABLE",
                "MTU_CHANGED",
                "OUTBOUND_QUEUE_DROP",
                "REORDER_WARNING",
                "TUN_DROP"
            ]
        );
        assert!(ev.iter().any(|e| e.kind.is_loss()));
    }

    #[test]
    fn small_reorder_timeout_counts_are_not_worth_an_event() {
        let mut d = EventDetector::new();
        d.observe(&obs(0, vec![link("a", LinkState::Up)]));
        let mut o = obs(500, vec![link("a", LinkState::Up)]);
        o.reorder_timeouts = 7;
        assert!(d.observe(&o).is_empty());
    }

    #[test]
    fn handshake_then_rekey_from_age_reset() {
        let mut d = EventDetector::new();
        d.observe(&obs(0, vec![link("a", LinkState::Probing)]));
        let at = |age: Option<u64>| {
            let mut l = link("a", LinkState::Probing);
            l.handshake_age_ms = age;
            l
        };
        assert_eq!(
            kinds(&d.observe(&obs(500, vec![at(Some(10))]))),
            ["WIREGUARD_HANDSHAKE"]
        );
        assert!(d.observe(&obs(1000, vec![at(Some(510))])).is_empty());
        assert_eq!(
            kinds(&d.observe(&obs(1500, vec![at(Some(5))]))),
            ["WIREGUARD_REKEY"]
        );
    }

    #[test]
    fn ring_serves_cursor_deltas_and_evicts_oldest() {
        let ring = EventRing::new();
        let ev = |m: &str| NewEvent {
            kind: EventKind::LinkUp,
            severity: Severity::Info,
            link: None,
            message: m.to_string(),
            fields: BTreeMap::new(),
        };
        ring.push(ev("one"));
        ring.push(ev("two"));
        assert_eq!(ring.entries_since(0).len(), 2);
        let after = ring.entries_since(1);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].message, "two");
        for i in 0..EVENT_RING_CAPACITY {
            ring.push(ev(&format!("x{i}")));
        }
        let all = ring.entries_since(0);
        assert_eq!(all.len(), EVENT_RING_CAPACITY);
        assert_eq!(all[0].message, "x0");
    }
}
