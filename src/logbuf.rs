//! In-memory ring buffer of recent log lines, fed by a
//! `tracing_subscriber::Layer` and drained incrementally by
//! `control::build_snapshot` into `Snapshot::new_log_lines` -- lets
//! `mlvpn-tui`'s Logs tab tail the daemon's own log output without a
//! separate `journalctl -f` window.
//!
//! Filtered to INFO and above, independent of whatever verbosity the
//! operator's own `[logging].level`/`RUST_LOG` sets for the primary
//! fmt/journald output (`main.rs::init_logging`) -- a debug/trace run
//! must not flood this ring, or the control socket it's streamed over,
//! with every trace-level line.

use crate::ipc::LogEntry;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::field::{Field, Visit};
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// How many recent log lines to keep. Generous enough to cover several
/// `control::SNAPSHOT_INTERVAL_MS` ticks' worth of output even on a
/// busy tunnel without needing much memory; a client that's fallen far
/// enough behind to miss entries just sees a gap in `seq` (monotonic,
/// never reused) rather than a wrong answer.
const LOG_RING_CAPACITY: usize = 500;

/// Shared between `LogRingLayer::on_event` (writer, one per logged
/// event) and `control::build_snapshot` (reader, once per connected
/// client per tick). A plain `std::sync::Mutex`, not the async one used
/// elsewhere in this codebase -- `on_event` runs on whatever thread
/// emitted the log line, entirely outside the tokio runtime, so an
/// async mutex isn't an option here regardless.
pub struct LogRing {
    entries: Mutex<VecDeque<LogEntry>>,
    next_seq: AtomicU64,
}

impl LogRing {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(LOG_RING_CAPACITY)),
            // Starts at 1, not 0: `entries_since(0)` is how a freshly
            // connected client (which has never seen any seq) asks for
            // everything currently in the ring. If real seqs started
            // at 0 too, that first entry would be indistinguishable
            // from "already seen" and would never be delivered. See
            // `control::serve_client`, whose cursor starts at 0 for
            // exactly this reason.
            next_seq: AtomicU64::new(1),
        }
    }

    fn push(&self, level: &str, target: Option<String>, message: String) {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let unix_ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut entries = self.entries.lock().unwrap();
        if entries.len() == LOG_RING_CAPACITY {
            entries.pop_front();
        }
        entries.push_back(LogEntry {
            seq,
            unix_ts_ms,
            level: level.to_string(),
            target,
            message,
        });
    }

    /// Every entry with `seq > since` -- `since` is the cursor value a
    /// connected client last saw, or 0 for a client that hasn't seen
    /// any lines yet. Real `seq`s start at 1 (see `LogRing::new`'s doc
    /// comment) specifically so `since = 0` naturally means "everything
    /// currently in the ring" without needing an `Option<u64>` sentinel.
    /// Cloned, not drained: multiple concurrently connected clients
    /// each track their own cursor independently, so no single
    /// client's poll can consume entries out from under another.
    pub fn entries_since(&self, since: u64) -> Vec<LogEntry> {
        let entries = self.entries.lock().unwrap();
        entries.iter().filter(|e| e.seq > since).cloned().collect()
    }
}

impl Default for LogRing {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracts just an event's formatted `message` field, the same field
/// `tracing_subscriber::fmt` renders as the free-text portion of its
/// own output -- ignoring span context and other structured fields,
/// since the Logs tab is meant as a compact tail, not a full
/// structured-log viewer.
#[derive(Default)]
struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write;
            let _ = write!(self.0, "{value:?}");
        }
    }
}

/// The `tracing_subscriber::Layer` that actually feeds a `LogRing`.
/// Composed alongside the existing `fmt` layer via
/// `tracing_subscriber::registry()` in `main.rs::init_logging` -- see
/// that function's updated doc comment for why this is a `Registry` of
/// two layers now instead of the single `fmt()...init()` call it used
/// to be.
pub struct LogRingLayer {
    ring: Arc<LogRing>,
}

impl LogRingLayer {
    pub fn new(ring: Arc<LogRing>) -> Self {
        Self { ring }
    }
}

impl<S: Subscriber> Layer<S> for LogRingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        // tracing::Level's Ord is deliberately inverted from its
        // underlying discriminant (see tracing_core::metadata's own
        // comment on this) so that TRACE > DEBUG > INFO > WARN > ERROR
        // -- "greater" means "more verbose". This skips exactly
        // DEBUG/TRACE, regardless of what the primary fmt layer's own
        // filter is configured to allow through.
        if *event.metadata().level() > tracing::Level::INFO {
            return;
        }
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        self.ring.push(
            event.metadata().level().as_str(),
            Some(event.metadata().target().to_string()),
            visitor.0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    #[test]
    fn entries_since_zero_returns_everything_when_nothing_consumed_yet() {
        let ring = LogRing::new();
        ring.push("INFO", Some("mlvpn::tunnel".to_string()), "one".to_string());
        ring.push("WARN", Some("mlvpn::tunnel".to_string()), "two".to_string());
        let entries = ring.entries_since(0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "one");
        assert_eq!(entries[1].message, "two");
    }

    #[test]
    fn entries_since_returns_only_the_delta() {
        let ring = LogRing::new();
        ring.push("INFO", None, "one".to_string());
        ring.push("INFO", None, "two".to_string());
        ring.push("INFO", None, "three".to_string());
        let entries = ring.entries_since(2);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "three");
    }

    #[test]
    fn seq_numbers_start_at_one_and_are_monotonic() {
        let ring = LogRing::new();
        for i in 0..5 {
            ring.push("INFO", None, format!("line {i}"));
        }
        let entries = ring.entries_since(0);
        let seqs: Vec<u64> = entries.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn ring_evicts_oldest_entries_past_capacity() {
        let ring = LogRing::new();
        for i in 0..(LOG_RING_CAPACITY + 10) {
            ring.push("INFO", None, format!("line {i}"));
        }
        let entries = ring.entries_since(0);
        assert_eq!(entries.len(), LOG_RING_CAPACITY);
        // The oldest surviving entry should be #10 (0..10 evicted).
        assert_eq!(entries[0].message, "line 10");
        assert_eq!(
            entries.last().unwrap().message,
            format!("line {}", LOG_RING_CAPACITY + 9)
        );
    }

    /// Drives a real `tracing::Event` through `LogRingLayer` (rather
    /// than calling `LogRing::push` directly, as the tests above do) to
    /// verify the `Visit` implementation actually extracts a message
    /// and the level filter behaves as documented.
    #[test]
    fn a_real_tracing_event_reaches_the_ring_with_its_message_and_level() {
        let ring = Arc::new(LogRing::new());
        let layer = LogRingLayer::new(ring.clone());
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(some_field = 42, "hello from a test event");
            tracing::debug!("this should never reach the ring");
        });
        let entries = ring.entries_since(0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].level, "INFO");
        assert_eq!(entries[0].message, "hello from a test event");
    }
}
