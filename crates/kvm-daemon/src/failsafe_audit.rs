//! Bounded in-memory failsafe audit trail.
//!
//! Every daemon failsafe tripwire — the emergency chord, native capture
//! discontinuation, the process panic hook, and the routing budget watchdog —
//! records one event here. The trail is a bounded ring buffer (newest last,
//! oldest evicted) exposed read-only for diagnostics, plus an optional
//! best-effort JSONL sink with a hard size cap and rotation-by-truncation.
//! Ring recording is synchronous; sink lines are only queued by `record` and
//! written by `flush_sink` on the manager's periodic service tick, so the
//! synchronous capture callback never touches the filesystem.
//!
//! The panic hook itself cannot record: hooks must stay lock-free
//! (see [`crate::failsafe_hook`]). Its event is recorded by the manager when
//! it first observes the tripped flag, which is also the moment cleanup is
//! requested — so the audit entry and the release always agree.
//!
//! The JSONL line is formatted by hand (`std::format!`) rather than a JSON
//! serializer: the daemon's runtime dependencies deliberately exclude
//! `serde_json`, and every field is a number or a fixed `kebab-case`-free
//! static tag, so no escaping rules apply. A test pins the hand-formatted
//! line to `serde_json`'s rendering of the same event.

use std::collections::VecDeque;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Maximum failsafe events retained in memory.
pub const FAILSAFE_AUDIT_CAPACITY: usize = 256;
/// Maximum size of the JSONL sink before it is truncated and restarted.
pub const FAILSAFE_AUDIT_FILE_CAP_BYTES: u64 = 1024 * 1024;
/// Conventional file name for the sink inside the daemon's data directory
/// (the same directory that holds the `kvm-config` store file).
pub const FAILSAFE_AUDIT_FILENAME: &str = "failsafe-audit.jsonl";

/// Why one failsafe event was recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailsafeEventCause {
    /// The emergency chord activated during a capture routing decision.
    ChordActivated,
    /// Native capture reported a hook/tap discontinuity.
    CaptureDiscontinuity,
    /// The process panic failsafe flag was observed tripped.
    PanicHookTripped,
    /// A routing call exceeded the configured budget.
    RoutingBudgetExceeded,
}

impl FailsafeEventCause {
    /// Fixed wire tag matching the serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChordActivated => "chord_activated",
            Self::CaptureDiscontinuity => "capture_discontinuity",
            Self::PanicHookTripped => "panic_hook_tripped",
            Self::RoutingBudgetExceeded => "routing_budget_exceeded",
        }
    }
}

/// One recorded failsafe event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FailsafeAuditEvent {
    /// Manager clock at which the event was recorded, in nanoseconds.
    pub timestamp_ns: u64,
    /// Why the failsafe tripped.
    pub cause: FailsafeEventCause,
    /// Monotonic per-trail sequence number (wraps only after u64 exhaustion).
    pub sequence: u64,
}

/// The manager-owned failsafe trail: ring buffer plus optional JSONL sink.
///
/// All mutation happens through the manager's serialized authority; no locks
/// are taken here. The in-memory ring records synchronously; JSONL sink lines
/// are only *queued* by [`FailsafeAuditLog::record`] — the actual file I/O
/// happens on [`FailsafeAuditLog::flush_sink`], driven by the manager's
/// periodic service tick, so the synchronous capture callback never touches
/// the filesystem.
#[derive(Default)]
pub(crate) struct FailsafeAuditLog {
    entries: VecDeque<FailsafeAuditEvent>,
    next_sequence: u64,
    sink: Option<PathBuf>,
    pending_sink_lines: VecDeque<String>,
}

impl fmt::Debug for FailsafeAuditLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailsafeAuditLog")
            .field("retained", &self.entries.len())
            .field("has_sink", &self.sink.is_some())
            .field("pending_sink_lines", &self.pending_sink_lines.len())
            .finish_non_exhaustive()
    }
}

impl FailsafeAuditLog {
    /// Records one event: pushes it onto the ring (evicting the oldest entry
    /// beyond [`FAILSAFE_AUDIT_CAPACITY`]) and, when a JSONL sink is
    /// configured, queues its line for the next [`Self::flush_sink`] instead
    /// of writing from the caller's context — `record` runs on the capture
    /// path, which must stay free of file I/O. The queue carries at most
    /// [`FAILSAFE_AUDIT_CAPACITY`] lines (one per ring event); the oldest
    /// queued line is dropped on overflow, mirroring the ring.
    pub(crate) fn record(&mut self, cause: FailsafeEventCause, now_ns: u64) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let event = FailsafeAuditEvent {
            timestamp_ns: now_ns,
            cause,
            sequence,
        };
        self.entries.push_back(event);
        while self.entries.len() > FAILSAFE_AUDIT_CAPACITY {
            self.entries.pop_front();
        }
        if self.sink.is_some() {
            self.pending_sink_lines.push_back(format_jsonl_line(&event));
            while self.pending_sink_lines.len() > FAILSAFE_AUDIT_CAPACITY {
                self.pending_sink_lines.pop_front();
            }
        }
    }

    /// Configures the best-effort JSONL sink. The parent directory must exist.
    pub(crate) fn set_sink(&mut self, path: PathBuf) {
        self.sink = Some(path);
    }

    /// Newest-last copy of the retained events.
    #[must_use]
    pub(crate) fn snapshot(&self) -> Vec<FailsafeAuditEvent> {
        self.entries.iter().copied().collect()
    }

    /// Drains the queued sink lines into the JSONL file with a hard size cap
    /// and rotation-by-truncation. Best-effort: the first I/O failure disables
    /// the sink for the remainder of the trail (and drops its queued lines)
    /// without failing the safety path.
    pub(crate) fn flush_sink(&mut self) {
        let Some(path) = self.sink.clone() else {
            self.pending_sink_lines.clear();
            return;
        };
        while let Some(line) = self.pending_sink_lines.pop_front() {
            if append_capped(&path, &line, FAILSAFE_AUDIT_FILE_CAP_BYTES).is_err() {
                self.sink = None;
                self.pending_sink_lines.clear();
                return;
            }
        }
    }
}

/// Hand-formats one JSONL line for [`FailsafeAuditEvent`].
fn format_jsonl_line(event: &FailsafeAuditEvent) -> String {
    format!(
        "{{\"timestamp_ns\":{},\"cause\":\"{}\",\"sequence\":{}}}\n",
        event.timestamp_ns,
        event.cause.as_str(),
        event.sequence
    )
}

/// Appends one line, truncating (rotating) the file first when the cap would
/// be exceeded. Rotation-by-truncation discards history rather than growing
/// without bound; the just-recorded event always survives the rotation.
fn append_capped(path: &Path, line: &str, cap_bytes: u64) -> std::io::Result<()> {
    let line_len = u64::try_from(line.len()).unwrap_or(u64::MAX);
    let current = std::fs::metadata(path).map_or(0u64, |metadata| metadata.len());
    if current.saturating_add(line_len) > cap_bytes {
        // Rotation: recreate the file empty. A create failure surfaces to the
        // caller, which disables the sink.
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_bounded_to_capacity_keeping_newest_last() {
        let mut log = FailsafeAuditLog::default();
        let total = FAILSAFE_AUDIT_CAPACITY * 2 + 7;
        for i in 0..total {
            log.record(
                FailsafeEventCause::ChordActivated,
                u64::try_from(i).unwrap_or(0),
            );
        }
        let snapshot = log.snapshot();
        assert_eq!(snapshot.len(), FAILSAFE_AUDIT_CAPACITY);
        // Newest last: the final retained event is the last recorded one.
        let last = snapshot.last().copied().expect("ring is full");
        assert_eq!(
            last.sequence,
            u64::try_from(total - 1).unwrap_or(u64::MAX),
            "the newest event must be retained"
        );
        // Oldest retained is exactly capacity events before the newest.
        let first = snapshot.first().copied().expect("ring is full");
        assert_eq!(
            first.sequence,
            u64::try_from(total - FAILSAFE_AUDIT_CAPACITY).unwrap_or(0),
            "exactly the oldest events are evicted"
        );
        for pair in snapshot.windows(2) {
            assert!(pair[0].sequence < pair[1].sequence, "order is monotonic");
        }
    }

    #[test]
    fn causes_render_fixed_snake_case_tags() {
        assert_eq!(
            FailsafeEventCause::ChordActivated.as_str(),
            "chord_activated"
        );
        assert_eq!(
            FailsafeEventCause::CaptureDiscontinuity.as_str(),
            "capture_discontinuity"
        );
        assert_eq!(
            FailsafeEventCause::PanicHookTripped.as_str(),
            "panic_hook_tripped"
        );
        assert_eq!(
            FailsafeEventCause::RoutingBudgetExceeded.as_str(),
            "routing_budget_exceeded"
        );
    }

    #[test]
    fn hand_formatted_line_matches_serde_json_and_parses_back() {
        let event = FailsafeAuditEvent {
            timestamp_ns: 42,
            cause: FailsafeEventCause::RoutingBudgetExceeded,
            sequence: 7,
        };
        let line = format_jsonl_line(&event);
        let trimmed = line.trim_end();
        let serialized = serde_json::to_string(&event).expect("serde_json serializes the event");
        assert_eq!(trimmed, serialized);
        let parsed: FailsafeAuditEvent = serde_json::from_str(trimmed).expect("line parses back");
        assert_eq!(parsed, event);
    }

    #[test]
    fn jsonl_sink_appends_then_rotates_by_truncation() {
        let directory = std::env::temp_dir().join(format!(
            "kvm-failsafe-audit-{}",
            std::process::id().wrapping_mul(3)
        ));
        std::fs::create_dir_all(&directory).expect("temp directory is created");
        let path = directory.join(FAILSAFE_AUDIT_FILENAME);
        let _ = std::fs::remove_file(&path);

        let mut log = FailsafeAuditLog::default();
        log.set_sink(path.clone());
        // Drive rotation through the internal capped append with a tiny cap so
        // the production const does not need a megabyte of fixture writes.
        let line = format_jsonl_line(&FailsafeAuditEvent {
            timestamp_ns: 1,
            cause: FailsafeEventCause::PanicHookTripped,
            sequence: 0,
        });
        let tiny_cap = u64::try_from(line.len()).expect("line length fits u64");
        append_capped(&path, &line, tiny_cap).expect("first append succeeds");
        append_capped(&path, &line, tiny_cap).expect("second append succeeds");
        let contents = std::fs::read_to_string(&path).expect("sink is readable");
        assert_eq!(
            contents.lines().count(),
            1,
            "the cap-sized file must rotate to exactly the newest line"
        );
        let parsed: FailsafeAuditEvent =
            serde_json::from_str(contents.lines().next().unwrap_or("")).expect("parses back");
        assert_eq!(parsed.cause, FailsafeEventCause::PanicHookTripped);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn ring_records_immediately_and_the_sink_writes_only_on_flush() {
        let directory = std::env::temp_dir().join(format!(
            "kvm-failsafe-audit-flush-{}",
            std::process::id().wrapping_mul(5)
        ));
        std::fs::create_dir_all(&directory).expect("temp directory is created");
        let path = directory.join(FAILSAFE_AUDIT_FILENAME);
        let _ = std::fs::remove_file(&path);

        let mut log = FailsafeAuditLog::default();
        log.set_sink(path.clone());
        // Recording from the capture callback context is synchronous for the
        // ring only: the event is observable immediately, the file is not
        // touched until the service-tick flush.
        log.record(FailsafeEventCause::RoutingBudgetExceeded, 11);
        log.record(FailsafeEventCause::PanicHookTripped, 12);
        assert_eq!(log.snapshot().len(), 2);
        assert!(!path.exists(), "no file I/O may happen on record");

        log.flush_sink();
        let contents = std::fs::read_to_string(&path).expect("sink is readable after flush");
        assert_eq!(contents.lines().count(), 2);
        let first: FailsafeAuditEvent = serde_json::from_str(contents.lines().next().unwrap_or(""))
            .expect("first line parses back");
        assert_eq!(first.cause, FailsafeEventCause::RoutingBudgetExceeded);
        let second: FailsafeAuditEvent =
            serde_json::from_str(contents.lines().nth(1).unwrap_or(""))
                .expect("second line parses back");
        assert_eq!(second.cause, FailsafeEventCause::PanicHookTripped);

        // A later record starts a fresh queue; flushing again appends only it.
        log.record(FailsafeEventCause::ChordActivated, 13);
        assert_eq!(log.snapshot().len(), 3);
        log.flush_sink();
        let contents = std::fs::read_to_string(&path).expect("sink is readable after flush");
        assert_eq!(contents.lines().count(), 3);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn failing_sink_is_disabled_after_first_error() {
        // A sink whose parent directory vanished cannot be appended to; the
        // audit must drop it silently instead of failing the record path.
        let mut log = FailsafeAuditLog::default();
        log.set_sink(PathBuf::from("/nonexistent-kvm-audit-dir/failsafe.jsonl"));
        log.record(FailsafeEventCause::ChordActivated, 5);
        assert_eq!(log.snapshot().len(), 1);
        assert!(
            log.sink.is_some(),
            "record queues without touching the file"
        );
        log.flush_sink();
        assert!(log.sink.is_none(), "the broken sink is disabled");
        assert!(
            log.pending_sink_lines.is_empty(),
            "queued lines are dropped"
        );
    }
}
