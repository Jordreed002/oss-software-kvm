use kvm_protocol::{MessageType, WireDeviceId, WireHostId, WireInputPayloadV1, WireMessage};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Conceptual transport lane. Ordering is FIFO within each lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficClass {
    /// Ordered input, releases, pointer handoffs, and device inventory.
    Input,
    /// Connection setup and liveness traffic.
    Control,
    /// Clipboard and display-topology state transfer.
    Background,
}

impl TrafficClass {
    pub const fn for_message(message: &WireMessage) -> Self {
        match message.message_type() {
            MessageType::Input
            | MessageType::DeviceSnapshot
            | MessageType::DeviceAdded
            | MessageType::DeviceRemoved
            | MessageType::PointerEnter
            | MessageType::PointerLeave
            | MessageType::PointerTransitionAck
            | MessageType::PointerTransitionCommit
            | MessageType::ReleaseInput
            | MessageType::ReleaseInputV2
            | MessageType::ReleaseAppliedAckV2 => Self::Input,
            MessageType::Hello
            | MessageType::Authenticate
            | MessageType::Ping
            | MessageType::Pong => Self::Control,
            MessageType::DisplaySnapshot | MessageType::DisplayUpdated | MessageType::Clipboard => {
                Self::Background
            }
        }
    }
}

/// Hard capacities for each outbound lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueConfig {
    pub input: usize,
    pub control: usize,
    pub background: usize,
    /// Maximum input frames sent while liveness control is waiting.
    pub maximum_input_burst: usize,
    /// Coalesces consecutive same-source `PointerMove` input frames in the
    /// input lane (spec §23). When enabled, a `PointerMove` arriving while the
    /// newest pending input frame is already a `PointerMove` from the same
    /// source host and device is folded into it: the deltas are summed and the
    /// later sequence/timestamp wins. This collapses a high-rate move burst
    /// (high-poll mice, 175 Hz display driven pointer motion) into one frame
    /// that always reflects the current accumulated motion, so the queue drains
    /// at once instead of accumulating per-frame latency. Button, key, release,
    /// and inventory frames are never coalesced, so their ordering is exact.
    pub coalesce_pointer_moves: bool,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            input: 1_024,
            control: 128,
            background: 32,
            maximum_input_burst: 64,
            // Spec §23 permits mouse-move coalescing; it is order-preserving,
            // position-correct, and monotonic-sequence-safe (the receiver only
            // rejects regressions, not gaps), so it is on by default.
            coalesce_pointer_moves: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueConfigError;

impl fmt::Display for QueueConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("all queue capacities and maximum input burst must be positive")
    }
}

impl Error for QueueConfigError {}

impl QueueConfig {
    /// Validates every hard capacity and the control fairness bound.
    ///
    /// # Errors
    ///
    /// Returns an error when any value is zero.
    pub fn validate(&self) -> Result<(), QueueConfigError> {
        if self.input == 0
            || self.control == 0
            || self.background == 0
            || self.maximum_input_burst == 0
        {
            Err(QueueConfigError)
        } else {
            Ok(())
        }
    }
}

/// A lossless backpressure signal. The rejected message is returned so the
/// caller can retry, coalesce it deliberately, or trigger a safety response.
pub struct EnqueueError {
    class: TrafficClass,
    capacity: usize,
    message: Box<WireMessage>,
}

impl fmt::Debug for EnqueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnqueueError")
            .field("class", &self.class)
            .field("capacity", &self.capacity)
            .field("message_type", &self.message.message_type())
            .finish_non_exhaustive()
    }
}

impl EnqueueError {
    pub const fn class(&self) -> TrafficClass {
        self.class
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn into_message(self) -> WireMessage {
        *self.message
    }
}

impl fmt::Display for EnqueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} outbound queue reached its capacity of {}",
            self.class, self.capacity
        )
    }
}

impl Error for EnqueueError {}

/// Cumulative count of messages rejected by [`OutboundQueue::try_push`] because
/// their lane was full (spec §35 "dropped packets").
///
/// The queue never silently drops a message — a rejected frame is returned in
/// [`EnqueueError`] so the caller can retry, coalesce, or trigger a safety
/// response. These counters tally those backpressure rejections per traffic
/// class, giving the diagnostics surface a queue-pressure signal. Plain
/// integers suffice because [`OutboundQueue`] methods take `&mut self`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DropCounters {
    /// Input-lane rejections: input events, releases, pointer handoffs, device inventory.
    pub input: u64,
    /// Control-lane rejections: hello, authenticate, ping, pong.
    pub control: u64,
    /// Background-lane rejections: clipboard, display topology.
    pub background: u64,
}

impl DropCounters {
    /// Total rejections across all lanes.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.input + self.control + self.background
    }

    /// Increments the counter for `class` by one (saturating, so a runaway
    /// counter never overflows in a long-running session).
    pub fn bump(&mut self, class: TrafficClass) {
        match class {
            TrafficClass::Input => self.input = self.input.saturating_add(1),
            TrafficClass::Control => self.control = self.control.saturating_add(1),
            TrafficClass::Background => self.background = self.background.saturating_add(1),
        }
    }
}

/// Session-total outbound-queue diagnostics, snapshotted from the queue when a
/// session ends so the burst pressure that preceded a disconnect is observable
/// rather than discarded with the private queue.
///
/// `dropped` is the §35 "dropped packets" signal (per-lane capacity rejections);
/// `coalesced_moves` is the §23 throughput signal (same-source `PointerMove`
/// frames folded into a preceding frame, deltas preserved). The two together
/// characterize how the queue behaved under load: a high coalescing count with
/// zero drops means a 175 Hz burst was absorbed cleanly; a rising drop count
/// means the lane capacities are too small for the offered rate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionStats {
    /// Per-lane rejections because the bounded lane was full (spec §35).
    pub dropped: DropCounters,
    /// Same-source `PointerMove` frames coalesced into a preceding frame. The
    /// deltas are preserved, so this is a throughput signal, not a loss signal
    /// (spec §23).
    pub coalesced_moves: u64,
}

/// Shared, lock-free observable mirror of a session's cumulative
/// [`SessionStats`], so the pull-model diagnostics surface can read *live*
/// coalescing/drop counters during sustained streaming without owning the
/// session's private queue.
///
/// The session publishes on its heartbeat tick; any reader (e.g.
/// `diagnostics_snapshot`) snapshots atomically. `Relaxed` ordering suffices:
/// these are advisory counters, not synchronization signals. The four counters
/// are published independently, so a concurrent read may observe a torn
/// combination across two publishes — acceptable for advisory diagnostics of
/// monotonically non-decreasing counters.
#[derive(Debug, Default)]
pub struct ObservableSessionStats {
    dropped_input: AtomicU64,
    dropped_control: AtomicU64,
    dropped_background: AtomicU64,
    coalesced_moves: AtomicU64,
}

impl ObservableSessionStats {
    /// Publishes `stats` so readers observe the current cumulative counters.
    pub fn publish(&self, stats: SessionStats) {
        self.dropped_input
            .store(stats.dropped.input, Ordering::Relaxed);
        self.dropped_control
            .store(stats.dropped.control, Ordering::Relaxed);
        self.dropped_background
            .store(stats.dropped.background, Ordering::Relaxed);
        self.coalesced_moves
            .store(stats.coalesced_moves, Ordering::Relaxed);
    }

    /// Snapshots the currently published counters.
    #[must_use]
    pub fn snapshot(&self) -> SessionStats {
        SessionStats {
            dropped: DropCounters {
                input: self.dropped_input.load(Ordering::Relaxed),
                control: self.dropped_control.load(Ordering::Relaxed),
                background: self.dropped_background.load(Ordering::Relaxed),
            },
            coalesced_moves: self.coalesced_moves.load(Ordering::Relaxed),
        }
    }

    /// Resets every counter to zero. Called at the start of each connection so
    /// the observable reports the current connection's burst pressure rather
    /// than a total across reconnects.
    pub fn reset(&self) {
        self.publish(SessionStats::default());
    }
}

/// Bounded, priority-aware outbound queue.
///
/// Input is normally selected first, but one waiting liveness-control frame is
/// selected after the configured maximum input burst. Background never blocks
/// either lane. No lane silently drops messages.
pub struct OutboundQueue {
    config: QueueConfig,
    input: VecDeque<WireMessage>,
    control: VecDeque<WireMessage>,
    background: VecDeque<WireMessage>,
    consecutive_input: usize,
    dropped: DropCounters,
    /// Count of `PointerMove` frames folded into a preceding same-source frame
    /// (spec §23). Not a drop: the deltas are preserved. Tracked for the
    /// diagnostics surface alongside [`DropCounters`].
    coalesced_moves: u64,
}

impl fmt::Debug for OutboundQueue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundQueue")
            .field("config", &self.config)
            .field("input_len", &self.input.len())
            .field("control_len", &self.control.len())
            .field("background_len", &self.background.len())
            .field("consecutive_input", &self.consecutive_input)
            .field("dropped", &self.dropped)
            .field("coalesced_moves", &self.coalesced_moves)
            .finish()
    }
}

impl OutboundQueue {
    /// Creates a queue, panicking when a bound is zero.
    ///
    /// Prefer [`Self::try_new`] for externally supplied configuration.
    ///
    /// # Panics
    ///
    /// Panics when the queue configuration is invalid.
    pub fn new(config: QueueConfig) -> Self {
        assert!(
            config.validate().is_ok(),
            "invalid outbound queue configuration"
        );
        Self::new_validated(config)
    }

    /// Creates a queue after fallible bound validation.
    ///
    /// # Errors
    ///
    /// Returns an error when any queue capacity or burst bound is zero.
    pub fn try_new(config: QueueConfig) -> Result<Self, QueueConfigError> {
        config.validate()?;
        Ok(Self::new_validated(config))
    }

    fn new_validated(config: QueueConfig) -> Self {
        Self {
            input: VecDeque::with_capacity(config.input),
            control: VecDeque::with_capacity(config.control),
            background: VecDeque::with_capacity(config.background),
            consecutive_input: 0,
            dropped: DropCounters::default(),
            coalesced_moves: 0,
            config,
        }
    }

    /// Enqueues without waiting or dropping.
    ///
    /// When [`QueueConfig::coalesce_pointer_moves`] is enabled and `message` is
    /// a `PointerMove` whose source host and device match the newest pending
    /// input frame, the move is folded into that frame (deltas summed, later
    /// sequence/timestamp kept) instead of occupying a new queue slot. This
    /// keeps a high-rate move burst at a single drain-able frame so latency
    /// does not accumulate per event (spec §23).
    ///
    /// # Errors
    ///
    /// Returns the original message when its bounded lane is full.
    pub fn try_push(&mut self, message: WireMessage) -> Result<(), EnqueueError> {
        let class = TrafficClass::for_message(&message);
        if class == TrafficClass::Input
            && self.config.coalesce_pointer_moves
            && self.try_coalesce_pointer_move(&message)
        {
            return Ok(());
        }
        let (queue, capacity) = match class {
            TrafficClass::Input => (&mut self.input, self.config.input),
            TrafficClass::Control => (&mut self.control, self.config.control),
            TrafficClass::Background => (&mut self.background, self.config.background),
        };
        if queue.len() >= capacity {
            self.dropped.bump(class);
            return Err(EnqueueError {
                class,
                capacity,
                message: Box::new(message),
            });
        }
        queue.push_back(message);
        Ok(())
    }

    /// Returns a message to the front of its lane, preserving FIFO order.
    ///
    /// This is the inverse of [`Self::pop_next`] for the rare case where a
    /// caller pops optimistically (e.g. to fill a write batch) and then decides
    /// a popped frame must wait for the next batch. It bypasses coalescing,
    /// which only applies to [`Self::try_push`] at the back of a lane.
    pub(crate) fn unpop(&mut self, message: WireMessage) {
        match TrafficClass::for_message(&message) {
            TrafficClass::Input => self.input.push_front(message),
            TrafficClass::Control => self.control.push_front(message),
            TrafficClass::Background => self.background.push_front(message),
        }
    }

    /// Folds `message` into the newest pending input frame when both are
    /// same-source `PointerMove`s. Returns `true` when a fold happened (the
    /// caller must not then enqueue `message`).
    fn try_coalesce_pointer_move(&mut self, message: &WireMessage) -> bool {
        let Some(incoming) = pointer_move_view(message) else {
            return false;
        };
        // Read-only check first so the immutable borrow of the tail ends here.
        let foldable = self
            .input
            .back()
            .and_then(pointer_move_view)
            .is_some_and(|tail| {
                tail.source_host == incoming.source_host
                    && tail.source_device == incoming.source_device
            });
        if !foldable {
            return false;
        }
        let Some(WireMessage::Input(tail)) = self.input.back_mut() else {
            return false;
        };
        let WireInputPayloadV1::PointerMove { dx, dy } = &mut tail.payload else {
            return false;
        };
        *dx += incoming.dx;
        *dy += incoming.dy;
        tail.sequence = incoming.sequence;
        tail.timestamp_ns = incoming.timestamp_ns;
        self.coalesced_moves = self.coalesced_moves.saturating_add(1);
        true
    }

    pub fn pop_next(&mut self) -> Option<WireMessage> {
        if !self.control.is_empty() && self.consecutive_input >= self.config.maximum_input_burst {
            self.consecutive_input = 0;
            return self.control.pop_front();
        }
        if let Some(message) = self.input.pop_front() {
            self.consecutive_input = self.consecutive_input.saturating_add(1);
            return Some(message);
        }
        self.consecutive_input = 0;
        self.control
            .pop_front()
            .or_else(|| self.background.pop_front())
    }

    pub fn len(&self) -> usize {
        self.input.len() + self.control.len() + self.background.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len_for(&self, class: TrafficClass) -> usize {
        match class {
            TrafficClass::Input => self.input.len(),
            TrafficClass::Control => self.control.len(),
            TrafficClass::Background => self.background.len(),
        }
    }

    /// Cumulative per-lane rejection counts (spec §35 "dropped packets").
    ///
    /// Counts messages returned as [`EnqueueError`] because their lane was full.
    /// The queue itself never silently drops a frame; this is the backpressure
    /// signal for the diagnostics surface.
    #[must_use]
    pub const fn drop_counters(&self) -> DropCounters {
        self.dropped
    }

    /// Cumulative count of `PointerMove` frames coalesced into a preceding
    /// same-source frame (spec §23). Unlike [`Self::drop_counters`], the deltas
    /// of coalesced moves are preserved — this is a throughput signal, not a
    /// loss signal.
    #[must_use]
    pub const fn coalesced_moves(&self) -> u64 {
        self.coalesced_moves
    }

    /// Snapshot of this queue's cumulative diagnostics for the diagnostics
    /// surface: per-lane drops (spec §35) and coalesced moves (spec §23).
    /// Captured when a session ends so the queue's behaviour under load is
    /// observable rather than discarded with the private queue.
    #[must_use]
    pub const fn session_stats(&self) -> SessionStats {
        SessionStats {
            dropped: self.dropped,
            coalesced_moves: self.coalesced_moves,
        }
    }
}

/// A borrowed view of a `PointerMove` input frame used for coalescing.
#[derive(Clone, Copy)]
struct PointerMoveView {
    source_host: WireHostId,
    source_device: WireDeviceId,
    sequence: u64,
    timestamp_ns: u64,
    dx: f64,
    dy: f64,
}

/// Returns the move's coalescable fields when `message` is an input frame
/// carrying a `PointerMove` payload, otherwise `None`.
fn pointer_move_view(message: &WireMessage) -> Option<PointerMoveView> {
    let WireMessage::Input(event) = message else {
        return None;
    };
    let WireInputPayloadV1::PointerMove { dx, dy } = event.payload else {
        return None;
    };
    Some(PointerMoveView {
        source_host: event.source_host,
        source_device: event.source_device,
        sequence: event.sequence,
        timestamp_ns: event.timestamp_ns,
        dx,
        dy,
    })
}

impl Default for OutboundQueue {
    fn default() -> Self {
        Self::new(QueueConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_protocol::{
        ClipboardV1, DeviceAddedV1, DeviceRemovedV1, DeviceSnapshotV1, InputEventV1, PingV1,
        PointerTransitionCommitV1, ReleaseAppliedAckV2, ReleaseInputV1, ReleaseInputV2,
        ReleaseReasonV1, ReleaseReasonV2, WireClipboardId, WireDeviceCapabilities, WireDeviceId,
        WireDeviceKind, WireDisplayId, WireHostId, WireInputDeviceV1, WireInputPayloadV1,
    };

    fn clipboard(sequence: u64) -> WireMessage {
        WireMessage::Clipboard(ClipboardV1 {
            update_id: WireClipboardId([0; 16]),
            origin_host: WireHostId([0; 16]),
            sequence,
            text: sequence.to_string(),
        })
    }

    fn input(sequence: u64) -> WireMessage {
        WireMessage::Input(InputEventV1 {
            sequence,
            timestamp_ns: sequence,
            source_host: WireHostId([1; 16]),
            source_device: WireDeviceId([2; 16]),
            payload: WireInputPayloadV1::PointerMove { dx: 1.0, dy: 0.0 },
        })
    }

    fn release(sequence: u64) -> WireMessage {
        WireMessage::ReleaseInput(ReleaseInputV1 {
            sequence,
            source_host: WireHostId([1; 16]),
            source_device: Some(WireDeviceId([2; 16])),
            reason: ReleaseReasonV1::RouteChanged,
            keys: Vec::new(),
            buttons: Vec::new(),
        })
    }

    fn release_v2(sequence: u64) -> WireMessage {
        WireMessage::ReleaseInputV2(ReleaseInputV2 {
            transaction_id: sequence,
            release_token: [4; 32],
            old_session_id: [5; 32],
            sequence,
            covered_input_sequence: sequence.saturating_sub(1),
            source_host: WireHostId([1; 16]),
            applying_host: WireHostId([2; 16]),
            source_device: Some(WireDeviceId([3; 16])),
            reason: ReleaseReasonV2::RouteChanged,
            keys: Vec::new(),
            buttons: Vec::new(),
        })
    }

    fn release_ack_v2(sequence: u64) -> WireMessage {
        WireMessage::ReleaseAppliedAckV2(ReleaseAppliedAckV2 {
            transaction_id: sequence,
            release_token: [4; 32],
            old_session_id: [5; 32],
            sequence,
            release_sequence: sequence.saturating_sub(1),
            covered_input_sequence: sequence.saturating_sub(2),
            source_host: WireHostId([1; 16]),
            applying_host: WireHostId([2; 16]),
        })
    }

    fn wire_device(id: u8) -> WireInputDeviceV1 {
        WireInputDeviceV1 {
            id: WireDeviceId([id; 16]),
            host_id: WireHostId([1; 16]),
            name: "test keyboard".to_owned(),
            vendor_id: None,
            product_id: None,
            kind: WireDeviceKind::Keyboard,
            capabilities: WireDeviceCapabilities {
                keyboard: true,
                ..WireDeviceCapabilities::default()
            },
        }
    }

    fn device_snapshot(revision: u64) -> WireMessage {
        WireMessage::DeviceSnapshot(DeviceSnapshotV1 {
            revision,
            host_id: WireHostId([1; 16]),
            devices: vec![wire_device(2)],
        })
    }

    fn commit(sequence: u64) -> WireMessage {
        WireMessage::PointerTransitionCommit(PointerTransitionCommitV1 {
            transition_id: sequence,
            workspace_epoch: 1,
            sequence,
            source_host: WireHostId([1; 16]),
            destination_host: WireHostId([2; 16]),
            source_display: WireDisplayId([3; 16]),
            destination_display: WireDisplayId([4; 16]),
        })
    }

    /// A default-configured queue with pointer-move coalescing disabled, for
    /// tests that assert exact per-frame ordering of consecutive same-device
    /// moves (the behaviour coalescing deliberately collapses).
    fn plain_queue() -> OutboundQueue {
        OutboundQueue::new(QueueConfig {
            coalesce_pointer_moves: false,
            ..QueueConfig::default()
        })
    }

    #[test]
    fn prioritizes_input_then_control_over_background_and_keeps_lane_order() {
        let mut queue = plain_queue();
        queue.try_push(clipboard(1)).unwrap();
        queue
            .try_push(WireMessage::Ping(PingV1 {
                nonce: 2,
                sent_at_ns: 2,
            }))
            .unwrap();
        queue.try_push(input(3)).unwrap();
        queue.try_push(input(4)).unwrap();

        assert_eq!(queue.pop_next(), Some(input(3)));
        assert_eq!(queue.pop_next(), Some(input(4)));
        assert!(matches!(queue.pop_next(), Some(WireMessage::Ping(_))));
        assert_eq!(queue.pop_next(), Some(clipboard(1)));
    }

    #[test]
    fn full_lane_returns_message_without_disturbing_other_lanes() {
        let mut queue = OutboundQueue::new(QueueConfig {
            input: 1,
            control: 1,
            background: 1,
            maximum_input_burst: 8,
            coalesce_pointer_moves: false,
        });
        queue.try_push(input(1)).unwrap();
        queue.try_push(clipboard(2)).unwrap();

        let error = queue.try_push(input(3)).unwrap_err();
        assert_eq!(error.class(), TrafficClass::Input);
        assert_eq!(error.capacity(), 1);
        assert_eq!(error.into_message(), input(3));
        assert_eq!(queue.len_for(TrafficClass::Background), 1);
    }

    #[test]
    fn liveness_control_cannot_starve_behind_sustained_input() {
        let mut queue = OutboundQueue::new(QueueConfig {
            maximum_input_burst: 2,
            coalesce_pointer_moves: false,
            ..QueueConfig::default()
        });
        queue
            .try_push(WireMessage::Ping(PingV1 {
                nonce: 9,
                sent_at_ns: 9,
            }))
            .unwrap();
        queue.try_push(input(1)).unwrap();
        queue.try_push(input(2)).unwrap();
        queue.try_push(input(3)).unwrap();

        assert_eq!(queue.pop_next(), Some(input(1)));
        assert_eq!(queue.pop_next(), Some(input(2)));
        assert!(matches!(queue.pop_next(), Some(WireMessage::Ping(_))));
        assert_eq!(queue.pop_next(), Some(input(3)));
    }

    #[test]
    fn transition_commit_stays_ahead_of_later_input_in_the_same_fifo_lane() {
        let mut queue = OutboundQueue::default();
        queue.try_push(commit(7)).unwrap();
        queue.try_push(input(8)).unwrap();

        assert_eq!(queue.pop_next(), Some(commit(7)));
        assert_eq!(queue.pop_next(), Some(input(8)));
    }

    #[test]
    fn device_inventory_uses_the_ordered_input_lane() {
        let messages = [
            device_snapshot(1),
            WireMessage::DeviceAdded(DeviceAddedV1 {
                revision: 2,
                device: wire_device(3),
            }),
            WireMessage::DeviceRemoved(DeviceRemovedV1 {
                revision: 3,
                host_id: WireHostId([1; 16]),
                device_id: WireDeviceId([3; 16]),
            }),
        ];

        for message in messages {
            assert_eq!(TrafficClass::for_message(&message), TrafficClass::Input);
        }
    }

    #[test]
    fn release_inventory_and_later_input_preserve_exact_fifo_order() {
        let mut queue = OutboundQueue::default();
        queue.try_push(release(10)).unwrap();
        queue.try_push(device_snapshot(11)).unwrap();
        queue.try_push(input(12)).unwrap();

        assert_eq!(queue.len_for(TrafficClass::Input), 3);
        assert_eq!(queue.pop_next(), Some(release(10)));
        assert_eq!(queue.pop_next(), Some(device_snapshot(11)));
        assert_eq!(queue.pop_next(), Some(input(12)));
        assert!(queue.is_empty());
    }

    #[test]
    fn v2_release_and_ack_share_exact_order_with_input() {
        let mut queue = OutboundQueue::default();
        queue.try_push(input(8)).unwrap();
        queue.try_push(release_v2(9)).unwrap();
        queue.try_push(release_ack_v2(10)).unwrap();
        queue.try_push(input(11)).unwrap();

        assert_eq!(queue.pop_next(), Some(input(8)));
        assert_eq!(queue.pop_next(), Some(release_v2(9)));
        assert_eq!(queue.pop_next(), Some(release_ack_v2(10)));
        assert_eq!(queue.pop_next(), Some(input(11)));
    }

    #[test]
    fn fallible_constructor_rejects_zero_capacity() {
        let invalid = QueueConfig {
            input: 0,
            ..QueueConfig::default()
        };
        assert!(OutboundQueue::try_new(invalid).is_err());
    }

    #[test]
    fn drop_counters_tally_full_lane_rejections_per_class() {
        let mut queue = OutboundQueue::new(QueueConfig {
            input: 1,
            control: 1,
            background: 1,
            maximum_input_burst: 8,
            coalesce_pointer_moves: false,
        });
        // A fresh queue has rejected nothing.
        assert_eq!(queue.drop_counters(), DropCounters::default());
        assert_eq!(queue.drop_counters().total(), 0);

        // Fill the input lane; the next input is rejected and counted as an Input drop.
        queue.try_push(input(1)).unwrap();
        assert!(queue.try_push(input(2)).is_err());
        assert_eq!(queue.drop_counters().input, 1);
        assert_eq!(queue.drop_counters().control, 0);
        assert_eq!(queue.drop_counters().background, 0);
        assert_eq!(queue.drop_counters().total(), 1);

        // A second rejection of the same lane keeps tallying.
        assert!(queue.try_push(input(3)).is_err());
        assert_eq!(queue.drop_counters().input, 2);
        assert_eq!(queue.drop_counters().total(), 2);

        // Rejections in other lanes are counted against their own class.
        queue.try_push(clipboard(10)).unwrap();
        assert!(queue.try_push(clipboard(11)).is_err());
        assert_eq!(queue.drop_counters().background, 1);
        assert_eq!(queue.drop_counters().input, 2);

        queue
            .try_push(WireMessage::Ping(PingV1 {
                nonce: 20,
                sent_at_ns: 20,
            }))
            .unwrap();
        assert!(queue
            .try_push(WireMessage::Ping(PingV1 {
                nonce: 21,
                sent_at_ns: 21,
            }))
            .is_err());
        assert_eq!(queue.drop_counters().control, 1);
        assert_eq!(
            queue.drop_counters().total(),
            2 + 1 + 1 // input + background + control
        );
    }

    #[test]
    fn successful_push_does_not_increment_drop_counters() {
        let mut queue = OutboundQueue::new(QueueConfig {
            input: 4,
            control: 4,
            background: 4,
            maximum_input_burst: 8,
            coalesce_pointer_moves: false,
        });
        queue.try_push(input(1)).unwrap();
        queue.try_push(clipboard(2)).unwrap();
        queue
            .try_push(WireMessage::Ping(PingV1 {
                nonce: 3,
                sent_at_ns: 3,
            }))
            .unwrap();
        // All pushes succeeded under capacity → no drops recorded.
        assert_eq!(queue.drop_counters(), DropCounters::default());
    }

    #[test]
    fn drop_counters_round_trip_through_serde() {
        // §35 "dropped packets" ships over the diagnostics surface, so the wire
        // representation must be stable and round-trip exactly.
        let counters = DropCounters {
            input: 12,
            control: 3,
            background: 0,
        };
        let json = serde_json::to_string(&counters).expect("serialize");
        let back: DropCounters = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(counters, back);
        assert_eq!(back.total(), 15);
        // Pin the per-lane field names.
        assert!(json.contains("\"input\":12"));
        assert!(json.contains("\"control\":3"));
        assert!(json.contains("\"background\":0"));
    }

    // --- pointer-move coalescing (spec §23) ---

    fn move_from(device: u8, sequence: u64, dx: f64, dy: f64) -> WireMessage {
        WireMessage::Input(InputEventV1 {
            sequence,
            timestamp_ns: sequence.saturating_mul(1_000_000),
            source_host: WireHostId([1; 16]),
            source_device: WireDeviceId([device; 16]),
            payload: WireInputPayloadV1::PointerMove { dx, dy },
        })
    }

    fn scroll_from(device: u8, sequence: u64, vertical: f64) -> WireMessage {
        WireMessage::Input(InputEventV1 {
            sequence,
            timestamp_ns: sequence.saturating_mul(1_000_000),
            source_host: WireHostId([1; 16]),
            source_device: WireDeviceId([device; 16]),
            payload: WireInputPayloadV1::Scroll {
                horizontal: 0.0,
                vertical,
            },
        })
    }

    /// Extracts the `(sequence, timestamp_ns, dx, dy)` of a coalescable move.
    fn move_fields(message: WireMessage) -> (u64, u64, f64, f64) {
        let WireMessage::Input(event) = message else {
            panic!("expected an input frame, got {:?}", message.message_type());
        };
        let WireInputPayloadV1::PointerMove { dx, dy } = event.payload else {
            panic!("expected a pointer move payload");
        };
        (event.sequence, event.timestamp_ns, dx, dy)
    }

    #[test]
    fn same_source_moves_coalesce_summing_deltas_and_latest_wins() {
        let mut queue = OutboundQueue::default();
        queue.try_push(move_from(2, 1, 10.0, 0.0)).unwrap();
        queue.try_push(move_from(2, 2, 5.0, 3.0)).unwrap();
        queue.try_push(move_from(2, 3, -2.0, 1.0)).unwrap();

        // Three same-source moves collapse to a single pending frame.
        assert_eq!(queue.len_for(TrafficClass::Input), 1);
        assert_eq!(queue.coalesced_moves(), 2);

        let (seq, ts, dx, dy) = move_fields(queue.pop_next().unwrap());
        assert_eq!(seq, 3); // latest sequence wins → monotonic gap, no duplicate
        assert_eq!(ts, 3 * 1_000_000); // latest timestamp wins → fresh latency signal
        assert!((dx - 13.0).abs() < 1e-9); // 10 + 5 - 2
        assert!((dy - 4.0).abs() < 1e-9); // 0 + 3 + 1
        assert!(queue.is_empty());
    }

    #[test]
    fn moves_from_distinct_sources_stay_separate() {
        let mut queue = OutboundQueue::default();
        queue.try_push(move_from(2, 1, 10.0, 0.0)).unwrap();
        queue.try_push(move_from(3, 2, 4.0, 4.0)).unwrap(); // different device

        assert_eq!(queue.len_for(TrafficClass::Input), 2);
        assert_eq!(queue.coalesced_moves(), 0);
    }

    #[test]
    fn a_non_move_input_frame_between_moves_blocks_coalescing() {
        // Keyboard/button/release/transition frames share the input lane but are
        // never coalesced, so they preserve exact ordering between moves.
        let mut queue = OutboundQueue::default();
        queue.try_push(move_from(2, 1, 1.0, 1.0)).unwrap();
        queue.try_push(commit(2)).unwrap(); // PointerTransitionCommit: Input lane, not a move
        queue.try_push(move_from(2, 3, 2.0, 2.0)).unwrap();

        assert_eq!(queue.len_for(TrafficClass::Input), 3);
        assert_eq!(queue.coalesced_moves(), 0);
        assert!(matches!(queue.pop_next(), Some(WireMessage::Input(_))));
        assert!(matches!(
            queue.pop_next(),
            Some(WireMessage::PointerTransitionCommit(_))
        ));
        assert!(matches!(queue.pop_next(), Some(WireMessage::Input(_))));
    }

    #[test]
    fn scroll_frames_are_not_coalesced() {
        let mut queue = OutboundQueue::default();
        queue.try_push(scroll_from(2, 1, 3.0)).unwrap();
        queue.try_push(scroll_from(2, 2, 4.0)).unwrap();

        assert_eq!(queue.len_for(TrafficClass::Input), 2);
        assert_eq!(queue.coalesced_moves(), 0);
    }

    #[test]
    fn disabling_coalescing_preserves_every_move_frame() {
        let mut queue = plain_queue();
        queue.try_push(move_from(2, 1, 1.0, 0.0)).unwrap();
        queue.try_push(move_from(2, 2, 1.0, 0.0)).unwrap();
        queue.try_push(move_from(2, 3, 1.0, 0.0)).unwrap();

        assert_eq!(queue.len_for(TrafficClass::Input), 3);
        assert_eq!(queue.coalesced_moves(), 0);
    }

    #[test]
    fn high_rate_burst_collapses_to_one_drainable_frame() {
        // Models a high-poll mouse / 175 Hz display driving many moves before
        // the drain task runs: the queue must not accumulate per-frame latency.
        let mut queue = OutboundQueue::default();
        for i in 1..=200 {
            queue.try_push(move_from(2, i, 0.5, 0.25)).unwrap();
        }

        assert_eq!(queue.len_for(TrafficClass::Input), 1);
        assert_eq!(queue.coalesced_moves(), 199);

        let (seq, _, dx, dy) = move_fields(queue.pop_next().unwrap());
        assert_eq!(seq, 200);
        assert!((dx - 100.0).abs() < 1e-9); // 200 * 0.5
        assert!((dy - 50.0).abs() < 1e-9); // 200 * 0.25
    }

    #[test]
    fn coalescing_affects_diagnostics_counter_not_drop_counters() {
        let mut queue = OutboundQueue::default();
        queue.try_push(move_from(2, 1, 1.0, 0.0)).unwrap();
        queue.try_push(move_from(2, 2, 1.0, 0.0)).unwrap();

        assert_eq!(queue.coalesced_moves(), 1);
        // Coalescing preserves deltas — it is never counted as a drop.
        assert_eq!(queue.drop_counters(), DropCounters::default());
    }

    #[test]
    fn session_stats_snapshots_both_coalescing_and_drops() {
        // A fresh queue reports a clean slate.
        let mut queue = OutboundQueue::new(QueueConfig {
            input: 1,
            control: 1,
            background: 1,
            maximum_input_burst: 8,
            coalesce_pointer_moves: true,
        });
        assert_eq!(
            queue.session_stats(),
            SessionStats {
                dropped: DropCounters::default(),
                coalesced_moves: 0,
            }
        );

        // Same-source moves coalesce into one pending frame; a following
        // different-source move is rejected because the capacity-1 input lane
        // is full, tallying one input drop.
        queue.try_push(move_from(2, 1, 1.0, 0.0)).unwrap();
        queue.try_push(move_from(2, 2, 1.0, 0.0)).unwrap();
        assert!(queue.try_push(move_from(3, 3, 1.0, 0.0)).is_err());

        let stats = queue.session_stats();
        assert_eq!(stats.coalesced_moves, 1);
        assert_eq!(stats.dropped.input, 1);
        assert_eq!(stats.dropped.total(), 1);

        // Draining the queue does not reset the cumulative counters: a session
        // that bursted and then quiesced still reports what happened.
        while queue.pop_next().is_some() {}
        assert_eq!(queue.session_stats(), stats);
    }

    #[test]
    fn observable_session_stats_publishes_snapshots_and_resets() {
        let observable = ObservableSessionStats::default();
        // A fresh observable reports a clean slate.
        assert_eq!(observable.snapshot(), SessionStats::default());

        // Publish reflects the cumulative counters exactly.
        observable.publish(SessionStats {
            dropped: DropCounters {
                input: 7,
                control: 2,
                background: 0,
            },
            coalesced_moves: 199,
        });
        let snapshot = observable.snapshot();
        assert_eq!(snapshot.dropped.input, 7);
        assert_eq!(snapshot.dropped.control, 2);
        assert_eq!(snapshot.dropped.total(), 9);
        assert_eq!(snapshot.coalesced_moves, 199);

        // A second publish overwrites (counters are cumulative, not additive).
        observable.publish(SessionStats {
            dropped: DropCounters {
                input: 8,
                control: 2,
                background: 1,
            },
            coalesced_moves: 201,
        });
        assert_eq!(observable.snapshot().dropped.input, 8);
        assert_eq!(observable.snapshot().coalesced_moves, 201);

        // Reset zeroes every counter, modelling the start of a fresh connection.
        observable.reset();
        assert_eq!(observable.snapshot(), SessionStats::default());
    }
}
