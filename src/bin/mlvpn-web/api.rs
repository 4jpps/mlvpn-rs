//! Shared telemetry state and the versioned, read-only `/api/v1` routes.
//!
//! Every response is an envelope `{api, connected, age_ms, data}` so a
//! client can tell stale data from live data. Only fields of the daemon's
//! control-socket snapshot are exposed; the daemon log ring is never
//! served, and the control socket carries no key material.

use crate::http::{query_param, Method, Request, Response};
use mlvpn::ipc::{EventRecord, Snapshot};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::time::Instant;

pub const EVENT_CAPACITY: usize = 500;
/// 5 minutes at the daemon's 500 ms snapshot cadence.
pub const HISTORY_CAPACITY: usize = 600;
pub const MAX_EVENTS_PER_REQUEST: usize = 500;
pub const MAX_HISTORY_PER_REQUEST: usize = HISTORY_CAPACITY;

#[derive(Serialize, Clone, Debug)]
pub struct LinkSample {
    pub name: String,
    pub tx_mbps: Option<f64>,
    pub rx_mbps: Option<f64>,
    pub rtt_ms: Option<f64>,
    pub loss_pct: Option<f64>,
}

#[derive(Serialize, Clone, Debug)]
pub struct HistorySample {
    pub unix_ts_ms: u64,
    pub tx_mbps: f64,
    pub rx_mbps: f64,
    pub links: Vec<LinkSample>,
}

#[derive(Default)]
pub struct Shared {
    pub snapshot: Option<Snapshot>,
    pub connected: bool,
    pub last_update: Option<Instant>,
    pub events: VecDeque<EventRecord>,
    pub history: VecDeque<HistorySample>,
}

impl Shared {
    /// A new control-socket connection replays the daemon's whole event
    /// ring, so what the previous connection collected is dropped first.
    pub fn on_connect(&mut self) {
        self.connected = true;
        self.events.clear();
        self.history.clear();
    }

    pub fn ingest(&mut self, mut snapshot: Snapshot) {
        for ev in snapshot.new_events.drain(..) {
            if self.events.len() == EVENT_CAPACITY {
                self.events.pop_front();
            }
            self.events.push_back(ev);
        }
        snapshot.new_log_lines.clear();

        if self.history.len() == HISTORY_CAPACITY {
            self.history.pop_front();
        }
        let rates = &snapshot.daemon.telemetry.rates;
        self.history.push_back(HistorySample {
            unix_ts_ms: snapshot.unix_ts_ms,
            tx_mbps: rates.tx_mbps,
            rx_mbps: rates.rx_mbps,
            links: snapshot
                .links
                .iter()
                .map(|l| LinkSample {
                    name: l.name.clone(),
                    tx_mbps: l.local_tx_throughput_mbps,
                    rx_mbps: l.local_rx_throughput_mbps,
                    rtt_ms: l.local_rtt_ms,
                    loss_pct: l.local_loss_pct,
                })
                .collect(),
        });

        self.snapshot = Some(snapshot);
        self.last_update = Some(Instant::now());
    }

    fn envelope(&self, data: Value) -> Value {
        json!({
            "api": 1,
            "connected": self.connected,
            "age_ms": self.last_update.map(|t| t.elapsed().as_millis() as u64),
            "data": data,
        })
    }
}

pub fn handle(state: &Shared, req: &Request) -> Response {
    debug_assert!(matches!(req.method, Method::Get | Method::Head));
    match req.path.as_str() {
        "/" | "/api" | "/api/v1" => Response::json(200, &index()),
        "/api/v1/version" => version(state),
        "/api/v1/snapshot" => snapshot(state),
        "/api/v1/links" => links(state),
        "/api/v1/events" => events(state, &req.query),
        "/api/v1/history" => history(state, &req.query),
        _ => Response::error(404, "not found"),
    }
}

fn index() -> Value {
    json!({
        "api": 1,
        "name": "mlvpn-web",
        "read_only": true,
        "endpoints": [
            "/api/v1/version",
            "/api/v1/snapshot",
            "/api/v1/links",
            "/api/v1/events?since=<seq>&limit=<n>",
            "/api/v1/history?limit=<n>",
        ],
    })
}

fn no_data(state: &Shared) -> Response {
    let mut v = state.envelope(Value::Null);
    v["error"] = json!("no snapshot received from the daemon yet");
    Response::json(503, &v)
}

fn version(state: &Shared) -> Response {
    let (daemon, peer, tunnel) = state
        .snapshot
        .as_ref()
        .map(|s| {
            (
                Some(s.daemon.local_version.clone()),
                s.daemon.peer_version.clone(),
                Some(s.tunnel_name.clone()),
            )
        })
        .unwrap_or((None, None, None));
    Response::json(
        200,
        &state.envelope(json!({
            "api_version": 1,
            "mlvpn_web": env!("CARGO_PKG_VERSION"),
            "daemon": daemon,
            "peer": peer,
            "tunnel": tunnel,
        })),
    )
}

fn snapshot(state: &Shared) -> Response {
    let Some(snap) = &state.snapshot else {
        return no_data(state);
    };
    let mut data = serde_json::to_value(snap).unwrap_or(Value::Null);
    if let Some(obj) = data.as_object_mut() {
        obj.remove("new_log_lines");
        obj.remove("new_events");
    }
    Response::json(200, &state.envelope(data))
}

fn links(state: &Shared) -> Response {
    let Some(snap) = &state.snapshot else {
        return no_data(state);
    };
    let data = serde_json::to_value(&snap.links).unwrap_or(Value::Null);
    Response::json(200, &state.envelope(data))
}

fn clamp_limit(query: &str, default: usize, max: usize) -> Result<usize, Response> {
    match query_param(query, "limit") {
        None => Ok(default),
        Some(v) => v
            .parse::<usize>()
            .map(|n| n.clamp(1, max))
            .map_err(|_| Response::error(400, "limit must be a positive integer")),
    }
}

fn events(state: &Shared, query: &str) -> Response {
    let since = match query_param(query, "since") {
        None => 0,
        Some(v) => match v.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return Response::error(400, "since must be a non-negative integer"),
        },
    };
    let limit = match clamp_limit(query, 100, MAX_EVENTS_PER_REQUEST) {
        Ok(n) => n,
        Err(r) => return r,
    };
    // Newest `limit` events after the cursor, oldest first, so a client
    // polling with `since=<last seq>` never skips or repeats one.
    let matching: Vec<&EventRecord> = state.events.iter().filter(|e| e.seq > since).collect();
    let skip = matching.len().saturating_sub(limit);
    let page: Vec<&&EventRecord> = matching.iter().skip(skip).collect();
    let next_since = state.events.back().map_or(since, |e| e.seq.max(since));
    Response::json(
        200,
        &state.envelope(json!({ "events": page, "next_since": next_since })),
    )
}

fn history(state: &Shared, query: &str) -> Response {
    let limit = match clamp_limit(query, 120, MAX_HISTORY_PER_REQUEST) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let skip = state.history.len().saturating_sub(limit);
    let samples: Vec<&HistorySample> = state.history.iter().skip(skip).collect();
    Response::json(
        200,
        &state.envelope(json!({ "interval_ms": 500, "samples": samples })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlvpn::ipc::LinkSnapshot;

    fn req(path: &str, query: &str) -> Request {
        Request {
            method: Method::Get,
            path: path.into(),
            query: query.into(),
        }
    }

    fn event(seq: u64) -> EventRecord {
        EventRecord {
            seq,
            unix_ts_ms: 1_000 + seq,
            severity: "info".into(),
            kind: "LINK_UP".into(),
            link: Some("wan1".into()),
            message: format!("event {seq}"),
            fields: Default::default(),
        }
    }

    fn snap(events: Vec<EventRecord>) -> Snapshot {
        let mut s = Snapshot {
            tunnel_name: "t0".into(),
            mode: "client".into(),
            unix_ts_ms: 5,
            links: vec![LinkSnapshot {
                name: "wan1".into(),
                state: "up".into(),
                local_rtt_ms: Some(10.0),
                ..Default::default()
            }],
            daemon: Default::default(),
            new_log_lines: vec![mlvpn::ipc::LogEntry {
                seq: 1,
                unix_ts_ms: 1,
                level: "INFO".into(),
                target: None,
                message: "secret-ish log line".into(),
            }],
            new_events: events,
        };
        s.daemon.local_version = "9.9.9".into();
        s.daemon.telemetry.rates.tx_mbps = 12.5;
        s
    }

    fn body(r: &Response) -> Value {
        serde_json::from_slice(&r.body).unwrap()
    }

    #[test]
    fn no_data_is_503_with_envelope() {
        let state = Shared::default();
        for p in ["/api/v1/snapshot", "/api/v1/links"] {
            let r = handle(&state, &req(p, ""));
            assert_eq!(r.status, 503, "{p}");
            assert_eq!(body(&r)["connected"], json!(false));
            assert!(body(&r)["age_ms"].is_null());
        }
        assert_eq!(handle(&state, &req("/api/v1/version", "")).status, 200);
        assert_eq!(handle(&state, &req("/api/v1/events", "")).status, 200);
        assert_eq!(handle(&state, &req("/api/v1/history", "")).status, 200);
    }

    #[test]
    fn snapshot_never_carries_logs_or_event_deltas() {
        let mut state = Shared::default();
        state.on_connect();
        state.ingest(snap(vec![event(1)]));
        let r = handle(&state, &req("/api/v1/snapshot", ""));
        assert_eq!(r.status, 200);
        let text = String::from_utf8(r.body.clone()).unwrap();
        assert!(!text.contains("secret-ish"));
        assert!(!text.contains("new_log_lines"));
        assert!(!text.contains("new_events"));
        let v = body(&r);
        assert_eq!(v["api"], json!(1));
        assert_eq!(v["connected"], json!(true));
        assert_eq!(v["data"]["tunnel_name"], json!("t0"));
        assert_eq!(v["data"]["links"][0]["name"], json!("wan1"));
    }

    #[test]
    fn links_and_version_routes() {
        let mut state = Shared::default();
        state.on_connect();
        state.ingest(snap(vec![]));
        let l = body(&handle(&state, &req("/api/v1/links", "")));
        assert_eq!(l["data"].as_array().unwrap().len(), 1);
        let v = body(&handle(&state, &req("/api/v1/version", "")));
        assert_eq!(v["data"]["daemon"], json!("9.9.9"));
        assert_eq!(v["data"]["tunnel"], json!("t0"));
        assert_eq!(v["data"]["api_version"], json!(1));
    }

    #[test]
    fn events_use_a_cursor_without_gaps_or_repeats() {
        let mut state = Shared::default();
        state.on_connect();
        state.ingest(snap((1..=5).map(event).collect()));
        let v = body(&handle(&state, &req("/api/v1/events", "since=2")));
        let seqs: Vec<u64> = v["data"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(seqs, vec![3, 4, 5]);
        assert_eq!(v["data"]["next_since"], json!(5));

        let v = body(&handle(&state, &req("/api/v1/events", "limit=2")));
        let seqs: Vec<u64> = v["data"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(seqs, vec![4, 5]);

        let v = body(&handle(&state, &req("/api/v1/events", "since=5")));
        assert!(v["data"]["events"].as_array().unwrap().is_empty());
        assert_eq!(v["data"]["next_since"], json!(5));
    }

    #[test]
    fn bad_query_values_are_400() {
        let state = Shared::default();
        for q in ["since=abc", "since=-1", "limit=x", "limit=-3"] {
            assert_eq!(handle(&state, &req("/api/v1/events", q)).status, 400, "{q}");
        }
        assert_eq!(
            handle(&state, &req("/api/v1/history", "limit=zz")).status,
            400
        );
    }

    #[test]
    fn limits_are_clamped() {
        let mut state = Shared::default();
        state.on_connect();
        for _ in 0..HISTORY_CAPACITY + 50 {
            state.ingest(snap(vec![]));
        }
        assert_eq!(state.history.len(), HISTORY_CAPACITY);
        let v = body(&handle(&state, &req("/api/v1/history", "limit=999999")));
        assert_eq!(
            v["data"]["samples"].as_array().unwrap().len(),
            MAX_HISTORY_PER_REQUEST
        );
        let v = body(&handle(&state, &req("/api/v1/history", "limit=0")));
        assert_eq!(v["data"]["samples"].as_array().unwrap().len(), 1);
        assert_eq!(v["data"]["samples"][0]["tx_mbps"], json!(12.5));
    }

    #[test]
    fn event_ring_is_capped_and_on_connect_clears() {
        let mut state = Shared::default();
        state.on_connect();
        state.ingest(snap(
            (1..=(EVENT_CAPACITY as u64 + 10)).map(event).collect(),
        ));
        assert_eq!(state.events.len(), EVENT_CAPACITY);
        assert_eq!(state.events.front().unwrap().seq, 11);
        state.on_connect();
        assert!(state.events.is_empty());
        assert!(state.history.is_empty());
    }

    #[test]
    fn unknown_paths_are_404() {
        let state = Shared::default();
        for p in [
            "/api/v2/snapshot",
            "/api/v1/",
            "/etc/passwd",
            "/api/v1/stream",
        ] {
            assert_eq!(handle(&state, &req(p, "")).status, 404, "{p}");
        }
        assert_eq!(handle(&state, &req("/", "")).status, 200);
    }
}
