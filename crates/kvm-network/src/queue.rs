use kvm_protocol::{MessageType, WireMessage};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;

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
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            input: 1_024,
            control: 128,
            background: 32,
            maximum_input_burst: 64,
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
            config,
        }
    }

    /// Enqueues without waiting or dropping.
    ///
    /// # Errors
    ///
    /// Returns the original message when its bounded lane is full.
    pub fn try_push(&mut self, message: WireMessage) -> Result<(), EnqueueError> {
        let class = TrafficClass::for_message(&message);
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

    #[test]
    fn prioritizes_input_then_control_over_background_and_keeps_lane_order() {
        let mut queue = OutboundQueue::default();
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
}
