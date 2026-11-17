//! Compact physical input event values.
//!
//! The types in this module describe what a capture layer observed: a key or
//! pointer-button transition, pointer movement, or scrolling, from one physical
//! device at one host-local time. They are plain data. They carry no routing
//! authority and do not imply that capture succeeded or that injection anywhere
//! is authorized. Interpreting, validating or acting on these values is the job
//! of the future session owner and the platform layers, not of this crate.

/// Identifies the physical input device an event came from.
///
/// Identifiers are assigned by the capture layer and are opaque here: this
/// crate never mints, orders or interprets them, and `0` has no special
/// meaning.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(u32);

impl DeviceId {
    /// Wraps a capture-layer device identifier.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the capture-layer device identifier.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// A host-local monotonic timestamp in nanoseconds, read from the capturing
/// host's capture clock at an arbitrary epoch.
///
/// Timestamps are **host-local**: they are meaningful only in comparison with
/// other timestamps from the same host and the same clock. Subtracting or
/// ordering timestamps taken on different hosts cannot establish cross-host
/// latency, ordering or age; there is no shared epoch and no clock
/// synchronization behind this type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Builds a timestamp from a nanosecond reading of the host-local clock.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Returns the nanosecond reading of the host-local clock.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

/// A physical key code as reported by the capture layer.
///
/// The value is an opaque platform key code carried uninterpreted; this crate
/// defines no mapping tables and no key names.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyCode(u16);

impl core::fmt::Debug for KeyCode {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeyCode([REDACTED])")
    }
}

impl KeyCode {
    /// Wraps a platform key code.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the platform key code.
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

/// A physical transition of a key or a pointer button.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Transition {
    /// The key or button went down.
    Down,
    /// The key or button came up.
    Up,
}

/// A physical pointer button.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PointerButton {
    /// The primary (usually left) button.
    Primary,
    /// The secondary (usually right) button.
    Secondary,
    /// The middle (center) button.
    Middle,
    /// The back button.
    Back,
    /// The forward button.
    Forward,
}

/// What was physically observed on a device.
///
/// Movement and scroll deltas are carried uninterpreted: units and sign
/// conventions belong to the reporting capture layer, and finiteness must be
/// validated at the external capture boundary before a value is built. This
/// type does not re-check or normalize them.
#[derive(Clone, Copy, PartialEq)]
pub enum EventKind {
    /// A key transitioned.
    Key {
        /// The key that transitioned.
        code: KeyCode,
        /// The direction of the transition.
        transition: Transition,
    },
    /// The pointer moved by a relative delta.
    PointerMove {
        /// Horizontal movement.
        dx: f32,
        /// Vertical movement.
        dy: f32,
    },
    /// A pointer button transitioned.
    PointerButton {
        /// The button that transitioned.
        button: PointerButton,
        /// The direction of the transition.
        transition: Transition,
    },
    /// A scroll surface reported movement.
    Scroll {
        /// Horizontal scroll movement.
        dx: f32,
        /// Vertical scroll movement.
        dy: f32,
    },
}

/// One observed physical input event from one device at one host-local time.
///
/// Event values are observations only: holding an [`InputEvent`] confers no
/// routing authority and does not imply that capture succeeded or that
/// injection anywhere is authorized. The timestamp is local to the host that
/// observed the event and cannot be compared against timestamps from another
/// host.
#[derive(Clone, Copy, PartialEq)]
pub struct InputEvent {
    /// The device the event was observed on.
    pub device: DeviceId,
    /// What was observed. Rust layout is unspecified; compactness is tested,
    /// not inferred from source field order or machine word size.
    pub kind: EventKind,
    /// When the event was observed, on the observing host's local clock.
    pub timestamp: Timestamp,
}

impl core::fmt::Debug for EventKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Key { .. } => "Key([REDACTED])",
            Self::PointerMove { .. } => "PointerMove([REDACTED])",
            Self::PointerButton { .. } => "PointerButton([REDACTED])",
            Self::Scroll { .. } => "Scroll([REDACTED])",
        })
    }
}

impl core::fmt::Debug for InputEvent {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InputEvent")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl InputEvent {
    /// Builds an event from its device, observed kind and host-local
    /// timestamp.
    #[must_use]
    pub const fn new(device: DeviceId, timestamp: Timestamp, kind: EventKind) -> Self {
        Self {
            device,
            kind,
            timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    fn key_event(device: u32, code: u16, transition: Transition, nanos: u64) -> InputEvent {
        InputEvent::new(
            DeviceId::from_raw(device),
            Timestamp::from_nanos(nanos),
            EventKind::Key {
                code: KeyCode::from_raw(code),
                transition,
            },
        )
    }

    #[test]
    fn raw_accessors_round_trip() {
        let device = DeviceId::from_raw(0xABCD_1234);
        let timestamp = Timestamp::from_nanos(1_234_567_890);
        let code = KeyCode::from_raw(0x001E);

        assert_eq!(device.raw(), 0xABCD_1234);
        assert_eq!(timestamp.as_nanos(), 1_234_567_890);
        assert_eq!(code.raw(), 0x001E);
    }

    #[test]
    fn events_compare_by_value_and_copies_are_independent() {
        let original = key_event(1, 30, Transition::Down, 500);

        let mut copy = original;
        copy.timestamp = Timestamp::from_nanos(501);

        assert_eq!(original, key_event(1, 30, Transition::Down, 500));
        assert_ne!(original, copy);
        assert_ne!(
            original,
            key_event(1, 30, Transition::Up, 500),
            "transition direction must matter"
        );
        assert_ne!(
            original,
            key_event(2, 30, Transition::Down, 500),
            "device identity must matter"
        );
    }

    #[test]
    fn kinds_distinguish_all_physical_families() {
        let device = DeviceId::from_raw(1);
        let timestamp = Timestamp::from_nanos(1);
        let kinds = [
            EventKind::Key {
                code: KeyCode::from_raw(1),
                transition: Transition::Down,
            },
            EventKind::PointerMove { dx: 1.0, dy: -2.5 },
            EventKind::PointerButton {
                button: PointerButton::Middle,
                transition: Transition::Up,
            },
            EventKind::Scroll { dx: 0.0, dy: 1.0 },
        ];

        for (index, kind) in kinds.iter().enumerate() {
            for (other_index, other) in kinds.iter().enumerate() {
                let event = InputEvent::new(device, timestamp, *kind);
                let other = InputEvent::new(device, timestamp, *other);
                assert_eq!(event == other, index == other_index);
            }
        }
    }

    #[test]
    fn event_values_stay_compact() {
        // Compactness is a foundation contract: a value past this bound should
        // be a deliberate, reviewed layout decision, not accidental growth.
        assert!(
            size_of::<InputEvent>() <= 24,
            "InputEvent grew to {}",
            size_of::<InputEvent>()
        );
        assert!(size_of::<DeviceId>() <= 4);
        assert!(size_of::<Timestamp>() <= 8);
        assert!(size_of::<KeyCode>() <= 2);
    }

    #[test]
    fn debug_output_identifies_the_family() {
        let event = key_event(3, 30, Transition::Down, 42);
        let text = format!("{event:?}");
        assert!(text.contains("Key"), "unexpected debug output: {text}");
        assert!(!text.contains("30"));
        assert!(!text.contains("42"));
        assert!(!text.contains("Down"));
        assert_eq!(
            format!("{:?}", KeyCode::from_raw(30)),
            "KeyCode([REDACTED])"
        );
    }
}
