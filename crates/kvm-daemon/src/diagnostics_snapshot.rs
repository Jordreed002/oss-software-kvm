//! Unified diagnostics snapshot (spec §35 + §36).
//!
//! Cycles 14/16/18/20/22 made the individual §35/§36 collectors live on the
//! daemon hot path and wire-ready (serde-derivable): the §35 input-event-rate
//! meter, the §36 capture→injection latency history, and the §35 dropped-packets
//! counters. Each ships its own serializable snapshot.
//!
//! The local control IPC surface (spec §31, still unimplemented) needs a single
//! read — not three — to serve a control-panel Diagnostics page (§32-34). This
//! module composes the three already-serializable snapshots into one
//! `DiagnosticsSnapshot`, so the future transport carries one versioned object.
//!
//! Like the collectors it wraps, this entire module is compiled only behind the
//! off-by-default `diagnostics` feature: release builds pay nothing.

use serde::{Deserialize, Serialize};

/// One wire-ready read of the daemon's §35/§36 diagnostics state.
///
/// `injection_latency` is `Option` because the §36 capture→injection span is
/// only recorded once an inbound event has actually been injected at a
/// destination peer; before the first such event (or when no peer is connected)
/// there is no latency distribution to report. `event_rate` and
/// `dropped_packets` are always present — they default to zero.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticsSnapshot {
    /// §35 input-event rate as observed on this host's capture hot path.
    pub event_rate: kvm_input::EventRateSnapshot,
    /// §36 capture→injection latency distribution (the headline software-KVM
    /// quality metric). `None` until the first inbound event is injected.
    pub injection_latency: Option<kvm_input::LatencyStats>,
    /// §35 "dropped packets": cumulative outbound-queue backpressure rejections,
    /// per traffic lane.
    pub dropped_packets: kvm_network::DropCounters,
}

impl DiagnosticsSnapshot {
    /// Assembles a snapshot from its three independently-owned collectors.
    ///
    /// The collectors live on different owners (the §35 meter on `DaemonCore`,
    /// the §36 history on a peer session coordinator, the §35 drop counters on
    /// the outbound queue), so the IPC orchestrator reads each and hands them
    /// here. [`DaemonCore::diagnostics_snapshot`] fills the event-rate portion
    /// from the core and forwards the other two.
    #[must_use]
    pub fn from_parts(
        event_rate: kvm_input::EventRateSnapshot,
        injection_latency: Option<kvm_input::LatencyStats>,
        dropped_packets: kvm_network::DropCounters,
    ) -> Self {
        Self {
            event_rate,
            injection_latency,
            dropped_packets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_input::{EventRateSnapshot, LatencyStats};
    use kvm_network::{DropCounters, TrafficClass};

    fn sample_event_rate() -> EventRateSnapshot {
        EventRateSnapshot {
            window_events: 42,
            total_events: 1_000,
            window_seconds: 6.0,
            events_per_second: 7.0,
        }
    }

    fn sample_latency() -> LatencyStats {
        // A 1–4ms capture→injection distribution.
        LatencyStats {
            count: 4,
            min_ns: 1_000_000,
            max_ns: 4_000_000,
            mean_ns: 2_500_000,
            p50_ns: 2_000_000,
            p95_ns: 3_800_000,
        }
    }

    #[test]
    fn snapshot_assembles_three_collectors() {
        let mut drops = DropCounters::default();
        drops.bump(TrafficClass::Input);
        drops.bump(TrafficClass::Input);
        drops.bump(TrafficClass::Control);

        let snapshot = DiagnosticsSnapshot::from_parts(
            sample_event_rate(),
            Some(sample_latency()),
            drops,
        );
        assert_eq!(snapshot.event_rate.window_events, 42);
        assert_eq!(
            snapshot.injection_latency.expect("latency present").max_ns,
            4_000_000
        );
        assert_eq!(snapshot.dropped_packets.input, 2);
        assert_eq!(snapshot.dropped_packets.control, 1);
        assert_eq!(snapshot.dropped_packets.total(), 3);
    }

    #[test]
    fn injection_latency_is_optional_before_first_event() {
        // No peer has injected yet → no §36 distribution.
        let snapshot =
            DiagnosticsSnapshot::from_parts(sample_event_rate(), None, DropCounters::default());
        assert!(snapshot.injection_latency.is_none());
    }

    #[test]
    fn snapshot_round_trips_through_serde() {
        // The §31 IPC surface ships this object, so the wire shape must be
        // stable and round-trip exactly. Pin the three top-level field names.
        let mut drops = DropCounters::default();
        drops.bump(TrafficClass::Background);
        let snapshot =
            DiagnosticsSnapshot::from_parts(sample_event_rate(), Some(sample_latency()), drops);

        let json = serde_json::to_string(&snapshot).expect("serialize");
        let back: DiagnosticsSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snapshot, back);

        assert!(json.contains("\"event_rate\""));
        assert!(json.contains("\"injection_latency\""));
        assert!(json.contains("\"dropped_packets\""));
    }
}
