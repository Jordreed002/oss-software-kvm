//! Development-only latency instrumentation for the input pipeline (spec §36).
//!
//! Enabled by the `latency` Cargo feature (off by default). When enabled, call
//! sites can stamp a single input event at five lifecycle stages — physical
//! capture, routing decision, network send, network receive, injection request —
//! and compute the end-to-end **capture → injection latency**, the metric the
//! software-KVM domain treats as the primary quality benchmark.
//!
//! Hard constraints honoured (spec §36):
//! - **Development-only.** The whole module is compiled only with `--features
//!   latency`; release builds pay nothing.
//! - **No disk I/O on the real-time input path.** [`LatencyHistory`] is a plain
//!   in-memory ring buffer; it never writes a file per event.
//! - **Monotonic time.** Every timestamp is a nanosecond reading from a single
//!   monotonic clock origin (the same origin as [`crate::InputEvent::timestamp_ns`]),
//!   never wall-clock time, so it is immune to clock adjustments.
//!
//! This module provides the data structures and statistics only. Wiring the
//! stamps into the capture/router/network/injector call sites is a separate,
//! deliberately later step so this slice carries zero hot-path risk.

/// The five lifecycle stages a single input event passes through (spec §36).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LatencyStage {
    /// Physical capture on the source host (== `InputEvent::timestamp_ns`).
    Capture,
    /// The router decided where the event goes.
    RoutingDecision,
    /// The event was handed to the network for inter-host delivery.
    NetworkSend,
    /// The destination host received the event from the network.
    NetworkReceive,
    /// The event was handed to the platform injector on the destination.
    InjectionRequest,
}

/// Stage timestamps recorded for one input event's journey from physical
/// capture to injection (spec §36).
///
/// Each stage is optional: a host records only the stages it observes. The
/// sending host stamps capture → routing → send; the receiving host stamps
/// receive → injection. [`LatencyStamps::capture_to_injection_ns`] is available
/// only once both endpoints have been stitched together (i.e. a combined record
/// with both `capture` and `injection` present).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
// Every field is a nanosecond stage reading; the `_ns` postfix documents the
// unit at the call site and is more valuable than satisfying the linter.
#[allow(clippy::struct_field_names)]
pub struct LatencyStamps {
    capture_ns: Option<u64>,
    routed_ns: Option<u64>,
    sent_ns: Option<u64>,
    received_ns: Option<u64>,
    injected_ns: Option<u64>,
}

impl LatencyStamps {
    /// An empty probe with no stages recorded.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            capture_ns: None,
            routed_ns: None,
            sent_ns: None,
            received_ns: None,
            injected_ns: None,
        }
    }

    /// Records `timestamp_ns` at `stage`. Keeps the earliest sample if a stage
    /// is recorded more than once, so re-entrancy cannot shrink a measured span.
    pub fn record(&mut self, stage: LatencyStage, timestamp_ns: u64) {
        let slot = match stage {
            LatencyStage::Capture => &mut self.capture_ns,
            LatencyStage::RoutingDecision => &mut self.routed_ns,
            LatencyStage::NetworkSend => &mut self.sent_ns,
            LatencyStage::NetworkReceive => &mut self.received_ns,
            LatencyStage::InjectionRequest => &mut self.injected_ns,
        };
        if slot.is_none() {
            *slot = Some(timestamp_ns);
        }
    }

    /// Returns the timestamp recorded at `stage`, if any.
    #[must_use]
    pub fn get(self, stage: LatencyStage) -> Option<u64> {
        match stage {
            LatencyStage::Capture => self.capture_ns,
            LatencyStage::RoutingDecision => self.routed_ns,
            LatencyStage::NetworkSend => self.sent_ns,
            LatencyStage::NetworkReceive => self.received_ns,
            LatencyStage::InjectionRequest => self.injected_ns,
        }
    }

    /// End-to-end capture → injection latency (spec §36), or `None` until both
    /// the capture and injection stages have been recorded. Saturates to `0` if
    /// timestamps are non-monotonic (injection before capture).
    #[must_use]
    pub fn capture_to_injection_ns(self) -> Option<u64> {
        Some(self.injected_ns?.saturating_sub(self.capture_ns?))
    }

    /// Latency between two stages, or `None` if either is unrecorded. Saturates
    /// to `0` for non-monotonic input (`to` before `from`).
    #[must_use]
    pub fn span_ns(self, from: LatencyStage, to: LatencyStage) -> Option<u64> {
        Some(self.get(to)?.saturating_sub(self.get(from)?))
    }

    /// Whether all five stages have been recorded.
    #[must_use]
    pub fn is_complete(self) -> bool {
        self.capture_ns.is_some()
            && self.routed_ns.is_some()
            && self.sent_ns.is_some()
            && self.received_ns.is_some()
            && self.injected_ns.is_some()
    }
}

impl LatencyStamps {
    /// Builder: set the capture stage.
    #[must_use]
    pub fn with_capture(mut self, timestamp_ns: u64) -> Self {
        self.capture_ns = Some(timestamp_ns);
        self
    }
    /// Builder: set the routing-decision stage.
    #[must_use]
    pub fn with_routing_decision(mut self, timestamp_ns: u64) -> Self {
        self.routed_ns = Some(timestamp_ns);
        self
    }
    /// Builder: set the network-send stage.
    #[must_use]
    pub fn with_network_send(mut self, timestamp_ns: u64) -> Self {
        self.sent_ns = Some(timestamp_ns);
        self
    }
    /// Builder: set the network-receive stage.
    #[must_use]
    pub fn with_network_receive(mut self, timestamp_ns: u64) -> Self {
        self.received_ns = Some(timestamp_ns);
        self
    }
    /// Builder: set the injection-request stage.
    #[must_use]
    pub fn with_injection_request(mut self, timestamp_ns: u64) -> Self {
        self.injected_ns = Some(timestamp_ns);
        self
    }
}

/// Aggregate latency statistics over a window of samples (spec §36). All values
/// are nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LatencyStats {
    /// Number of samples in the window.
    pub count: usize,
    pub min_ns: u64,
    pub max_ns: u64,
    /// Integer mean (rounded down).
    pub mean_ns: u64,
    /// Nearest-rank 50th percentile.
    pub p50_ns: u64,
    /// Nearest-rank 95th percentile.
    pub p95_ns: u64,
}

/// Bounded in-memory ring buffer of recent capture→injection latencies for
/// development-only statistics (spec §36).
///
/// Keeps at most `capacity` samples; the oldest is overwritten once full. Never
/// touches disk. Statistics are computed on demand over the current window via
/// [`LatencyHistory::stats`] or [`LatencyHistory::percentile`].
#[derive(Debug)]
pub struct LatencyHistory {
    samples: Vec<u64>,
    /// Next write index; wraps modulo `capacity`.
    head: usize,
    /// Number of valid samples currently stored.
    len: usize,
    capacity: usize,
}

impl LatencyHistory {
    /// Creates an empty history holding the `capacity` most recent samples.
    ///
    /// # Panics
    /// Panics if `capacity == 0`.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "LatencyHistory capacity must be positive");
        Self {
            samples: Vec::with_capacity(capacity),
            head: 0,
            len: 0,
            capacity,
        }
    }

    /// Maximum number of samples retained.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of samples currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no samples are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Records one capture→injection latency. Overwrites the oldest sample when
    /// the buffer is full (ring semantics).
    pub fn push(&mut self, latency_ns: u64) {
        if self.len < self.capacity {
            self.samples.push(latency_ns);
            self.head = (self.head + 1) % self.capacity;
            self.len += 1;
        } else {
            self.samples[self.head] = latency_ns;
            self.head = (self.head + 1) % self.capacity;
        }
    }

    /// Records the capture→injection latency extracted from `stamps`, if both
    /// stages are present. A no-op for stamps that have no complete span yet.
    pub fn push_stamps(&mut self, stamps: LatencyStamps) {
        if let Some(latency_ns) = stamps.capture_to_injection_ns() {
            self.push(latency_ns);
        }
    }

    /// Clears all samples.
    pub fn clear(&mut self) {
        self.samples.clear();
        self.head = 0;
        self.len = 0;
    }

    /// Nearest-rank percentile (0..=100) over the current window, or `None` if
    /// empty or `pct > 100`.
    #[must_use]
    pub fn percentile(&self, pct: u8) -> Option<u64> {
        if pct > 100 || self.len == 0 {
            return None;
        }
        let mut sorted: Vec<u64> = self.samples.clone();
        sorted.sort_unstable();
        // Nearest-rank: rank = ceil(pct/100 * n), index = rank - 1.
        let rank = (usize::from(pct) * self.len).div_ceil(100);
        let idx = rank.clamp(1, self.len) - 1;
        Some(sorted[idx])
    }

    /// Aggregate statistics over the current window, or `None` if empty.
    #[must_use]
    pub fn stats(&self) -> Option<LatencyStats> {
        if self.len == 0 {
            return None;
        }
        let mut sorted: Vec<u64> = self.samples.clone();
        sorted.sort_unstable();
        let count = self.len;
        let sum: u64 = sorted.iter().sum();
        // Nearest-rank index helper (guarded above: count >= 1, pct <= 100).
        let rank_index = |pct: u8| -> usize {
            let rank = (usize::from(pct) * count).div_ceil(100);
            rank.clamp(1, count) - 1
        };
        // `count >= 1` is guaranteed by the empty-check above.
        let last = count - 1;
        Some(LatencyStats {
            count,
            min_ns: sorted[0],
            max_ns: sorted[last],
            mean_ns: sum / u64::try_from(count).unwrap_or(u64::MAX),
            p50_ns: sorted[rank_index(50)],
            p95_ns: sorted[rank_index(95)],
        })
    }
}

impl Default for LatencyHistory {
    fn default() -> Self {
        // A modest default window; callers with stronger needs pick explicitly.
        Self::new(256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stamps_have_no_stages_and_are_incomplete() {
        let stamps = LatencyStamps::new();
        assert_eq!(stamps.get(LatencyStage::Capture), None);
        assert!(!stamps.is_complete());
        assert_eq!(stamps.capture_to_injection_ns(), None);
    }

    #[test]
    fn record_sets_each_stage() {
        let mut stamps = LatencyStamps::new();
        stamps.record(LatencyStage::Capture, 1_000);
        stamps.record(LatencyStage::RoutingDecision, 1_100);
        stamps.record(LatencyStage::NetworkSend, 1_150);
        stamps.record(LatencyStage::NetworkReceive, 1_400);
        stamps.record(LatencyStage::InjectionRequest, 1_430);
        assert_eq!(stamps.get(LatencyStage::Capture), Some(1_000));
        assert_eq!(stamps.get(LatencyStage::InjectionRequest), Some(1_430));
        assert!(stamps.is_complete());
    }

    #[test]
    fn record_keeps_earliest_sample_on_re_record() {
        let mut stamps = LatencyStamps::new();
        stamps.record(LatencyStage::Capture, 1_000);
        stamps.record(LatencyStage::Capture, 999); // ignored
        assert_eq!(stamps.get(LatencyStage::Capture), Some(1_000));
    }

    #[test]
    fn capture_to_injection_uses_saturating_sub() {
        let stamps = LatencyStamps::new()
            .with_capture(1_000)
            .with_injection_request(1_430);
        assert_eq!(stamps.capture_to_injection_ns(), Some(430));
        assert_eq!(stamps.span_ns(LatencyStage::Capture, LatencyStage::RoutingDecision), None);

        // Non-monotonic timestamps saturate to zero rather than wrapping.
        let inverted = LatencyStamps::new().with_capture(2_000).with_injection_request(1_000);
        assert_eq!(inverted.capture_to_injection_ns(), Some(0));
    }

    #[test]
    fn span_measures_any_two_recorded_stages() {
        let stamps = LatencyStamps::new()
            .with_capture(1_000)
            .with_routing_decision(1_100)
            .with_network_send(1_150)
            .with_network_receive(1_400)
            .with_injection_request(1_430);
        assert_eq!(stamps.span_ns(LatencyStage::NetworkSend, LatencyStage::NetworkReceive), Some(250));
        assert_eq!(
            stamps.span_ns(LatencyStage::RoutingDecision, LatencyStage::InjectionRequest),
            Some(330)
        );
        // Reverse direction saturates to zero.
        assert_eq!(stamps.span_ns(LatencyStage::InjectionRequest, LatencyStage::Capture), Some(0));
    }

    #[test]
    fn history_push_and_capacity_respected() {
        let mut history = LatencyHistory::new(3);
        assert!(history.is_empty());
        history.push(10);
        history.push(20);
        history.push(30);
        assert_eq!(history.len(), 3);
        // Fourth write overwrites the oldest (10) via the ring.
        history.push(40);
        assert_eq!(history.len(), 3);
        let stats = history.stats().expect("non-empty");
        assert_eq!(stats.count, 3);
        assert_eq!(stats.min_ns, 20);
        assert_eq!(stats.max_ns, 40);
    }

    #[test]
    fn history_percentile_nearest_rank() {
        // Samples 0..=99 (100 values). p50 nearest-rank index = 49 (value 49),
        // p95 index = 94 (value 94), min 0, max 99.
        let mut history = LatencyHistory::new(128);
        for v in 0..100u64 {
            history.push(v);
        }
        assert_eq!(history.percentile(0), Some(0));
        assert_eq!(history.percentile(50), Some(49));
        assert_eq!(history.percentile(95), Some(94));
        assert_eq!(history.percentile(100), Some(99));
        assert!(history.percentile(101).is_none());
    }

    #[test]
    fn history_stats_match_manual_computation() {
        let mut history = LatencyHistory::new(64);
        for &v in &[7u64, 1, 3, 9, 5] {
            history.push(v);
        }
        let stats = history.stats().expect("non-empty");
        assert_eq!(stats.count, 5);
        assert_eq!(stats.min_ns, 1);
        assert_eq!(stats.max_ns, 9);
        assert_eq!(stats.mean_ns, 5); // (7+1+3+9+5)/5 = 25/5
        // Sorted: [1,3,5,7,9]. rank50 = ceil(0.5*5)=3 -> idx2 -> 5; rank95 = ceil(4.75)=5 -> idx4 -> 9.
        assert_eq!(stats.p50_ns, 5);
        assert_eq!(stats.p95_ns, 9);
    }

    #[test]
    fn empty_history_reports_none() {
        let history = LatencyHistory::new(8);
        assert!(history.is_empty());
        assert!(history.stats().is_none());
        assert!(history.percentile(50).is_none());
    }

    #[test]
    fn push_stamps_records_only_complete_spans() {
        let mut history = LatencyHistory::new(8);
        // Incomplete: no injection stage -> not recorded.
        history.push_stamps(LatencyStamps::new().with_capture(100));
        assert!(history.is_empty());
        // Complete span -> recorded.
        history.push_stamps(LatencyStamps::new().with_capture(100).with_injection_request(160));
        assert_eq!(history.len(), 1);
        assert_eq!(history.stats().unwrap().max_ns, 60);
    }

    #[test]
    fn clear_empties_the_window() {
        let mut history = LatencyHistory::new(4);
        history.push(1);
        history.push(2);
        history.clear();
        assert!(history.is_empty());
        assert!(history.stats().is_none());
    }

    #[test]
    #[should_panic(expected = "capacity must be positive")]
    fn zero_capacity_panics() {
        let _ = LatencyHistory::new(0);
    }

    #[test]
    fn default_capacity_is_reasonable() {
        let history = LatencyHistory::default();
        assert!(history.capacity() > 0);
        assert!(history.is_empty());
    }
}
