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
/// Fields are ordered to group the two §35 throughput counters (captured rate
/// then injected count), then the two §36 latency distributions, then drops.
/// The two latency fields are `Option`. `source_latency` is `None` until the
/// first captured event reaches a routing decision. `injection_latency` is
/// `None` until the first inbound event is injected at a destination peer. The
/// counters are always present and default to zero.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticsSnapshot {
    /// §35 input-event rate as observed on this host's capture hot path.
    pub event_rate: kvm_input::EventRateSnapshot,
    /// §35 cumulative count of inbound events injected at this peer. Pairs with
    /// `event_rate.total_events` to expose one-way delivery asymmetry (captured
    /// but not injected).
    pub injected_events: u64,
    /// §36 source-side capture→routing-decision latency distribution. `None`
    /// until the first event is processed.
    pub source_latency: Option<kvm_input::LatencyStats>,
    /// §36 source-side capture→network-send latency distribution (capture to
    /// the frame being handed to the outbound channel). `None` until the first
    /// remotely-dispatched event. Together with `source_latency` it isolates
    /// dispatch/queue latency (routing→send = capture→send − capture→routing).
    pub network_send_latency: Option<kvm_input::LatencyStats>,
    /// §36 capture→injection latency distribution (the headline software-KVM
    /// quality metric). `None` until the first inbound event is injected at a
    /// destination peer.
    pub injection_latency: Option<kvm_input::LatencyStats>,
    /// §35 "dropped packets": cumulative outbound-queue backpressure rejections,
    /// per traffic lane.
    pub dropped_packets: kvm_network::DropCounters,
    /// §23 throughput signal: cumulative same-source `PointerMove` frames folded
    /// into a preceding frame on the outbound queue. Pairs with `event_rate` to
    /// show how much input burst pressure coalescing absorbed at this peer.
    pub coalesced_moves: u64,
}

impl DiagnosticsSnapshot {
    /// Assembles a snapshot from its independently-owned collectors.
    ///
    /// The collectors live on different owners: the §35 meter and §36
    /// source-side capture→routing history on `DaemonCore`, the §35
    /// injected-event count, the §36 capture→network-send history and the §36
    /// injection history on a peer session coordinator, and the §35 drop
    /// counters on the outbound queue. [`DaemonCore::diagnostics_snapshot`]
    /// fills the two core-owned portions and forwards the rest.
    #[must_use]
    pub fn from_parts(
        event_rate: kvm_input::EventRateSnapshot,
        injected_events: u64,
        source_latency: Option<kvm_input::LatencyStats>,
        network_send_latency: Option<kvm_input::LatencyStats>,
        injection_latency: Option<kvm_input::LatencyStats>,
        dropped_packets: kvm_network::DropCounters,
        coalesced_moves: u64,
    ) -> Self {
        Self {
            event_rate,
            injected_events,
            source_latency,
            network_send_latency,
            injection_latency,
            dropped_packets,
            coalesced_moves,
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
    fn snapshot_assembles_five_collectors() {
        let mut drops = DropCounters::default();
        drops.bump(TrafficClass::Input);
        drops.bump(TrafficClass::Input);
        drops.bump(TrafficClass::Control);

        let snapshot = DiagnosticsSnapshot::from_parts(
            sample_event_rate(),
            7,
            Some(sample_latency()),
            Some(sample_latency()),
            Some(sample_latency()),
            drops,
            12,
        );
        assert_eq!(snapshot.event_rate.window_events, 42);
        assert_eq!(snapshot.injected_events, 7);
        assert_eq!(
            snapshot
                .source_latency
                .expect("source latency present")
                .max_ns,
            4_000_000
        );
        assert_eq!(
            snapshot
                .network_send_latency
                .expect("network-send latency present")
                .max_ns,
            4_000_000
        );
        assert_eq!(
            snapshot
                .injection_latency
                .expect("injection latency present")
                .max_ns,
            4_000_000
        );
        assert_eq!(snapshot.dropped_packets.input, 2);
        assert_eq!(snapshot.dropped_packets.control, 1);
        assert_eq!(snapshot.dropped_packets.total(), 3);
        assert_eq!(snapshot.coalesced_moves, 12);
    }

    #[test]
    fn latency_fields_are_optional_before_first_event() {
        // No event processed locally and no peer has injected yet → all three
        // §36 latency distributions are absent.
        let snapshot = DiagnosticsSnapshot::from_parts(
            sample_event_rate(),
            0,
            None,
            None,
            None,
            DropCounters::default(),
            0,
        );
        assert!(snapshot.source_latency.is_none());
        assert!(snapshot.network_send_latency.is_none());
        assert!(snapshot.injection_latency.is_none());
        assert_eq!(snapshot.injected_events, 0);
    }

    #[test]
    fn snapshot_round_trips_through_serde() {
        // The §31 IPC surface ships this object, so the wire shape must be
        // stable and round-trip exactly. Pin the six top-level field names.
        let mut drops = DropCounters::default();
        drops.bump(TrafficClass::Background);
        let snapshot = DiagnosticsSnapshot::from_parts(
            sample_event_rate(),
            99,
            Some(sample_latency()),
            None,
            Some(sample_latency()),
            drops,
            250,
        );

        let json = serde_json::to_string(&snapshot).expect("serialize");
        let back: DiagnosticsSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snapshot, back);

        assert!(json.contains("\"event_rate\""));
        assert!(json.contains("\"injected_events\":99"));
        assert!(json.contains("\"source_latency\""));
        assert!(json.contains("\"network_send_latency\""));
        assert!(json.contains("\"injection_latency\""));
        assert!(json.contains("\"dropped_packets\""));
        assert!(json.contains("\"coalesced_moves\":250"));
        // A None latency serializes to null, not omitted.
        assert!(json.contains("\"network_send_latency\":null"));
    }
}
