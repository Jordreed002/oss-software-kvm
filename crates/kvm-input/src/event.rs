use std::fmt;

use kvm_types::{DeviceId, HostId};
use serde::{Deserialize, Serialize};

use crate::KeyCode;

/// State transition for a keyboard key.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Pressed,
    Repeated,
    Released,
}

impl fmt::Debug for KeyState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyState([REDACTED])")
    }
}

/// State transition for a pointer button.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ButtonState {
    Pressed,
    Released,
}

impl fmt::Debug for ButtonState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ButtonState([REDACTED])")
    }
}

/// A conventional pointer button or an additional numbered button.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
    Other(u16),
}

impl fmt::Debug for PointerButton {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PointerButton([REDACTED])")
    }
}

/// A canonical input action. Pointer deltas and scroll amounts remain relative.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputPayload {
    Key {
        code: KeyCode,
        state: KeyState,
    },
    PointerMove {
        dx: f64,
        dy: f64,
    },
    PointerButton {
        button: PointerButton,
        state: ButtonState,
    },
    Scroll {
        horizontal: f64,
        vertical: f64,
    },
}

impl fmt::Debug for InputPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Key { .. } => "Key",
            Self::PointerMove { .. } => "PointerMove",
            Self::PointerButton { .. } => "PointerButton",
            Self::Scroll { .. } => "Scroll",
        };
        formatter
            .debug_struct("InputPayload")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl InputPayload {
    /// Whether all numeric values in the event are finite.
    #[must_use]
    pub fn is_finite(self) -> bool {
        match self {
            Self::PointerMove { dx, dy } => dx.is_finite() && dy.is_finite(),
            Self::Scroll {
                horizontal,
                vertical,
            } => horizontal.is_finite() && vertical.is_finite(),
            Self::Key { .. } | Self::PointerButton { .. } => true,
        }
    }
}

/// A sequenced input event from one physical source.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct InputEvent {
    pub sequence: u64,
    /// Monotonic source timestamp in nanoseconds; not wall-clock time.
    pub timestamp_ns: u64,
    pub source_host: HostId,
    pub source_device: DeviceId,
    pub payload: InputPayload,
}

impl fmt::Debug for InputEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InputEvent")
            .field("payload", &self.payload)
            .field("source", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl InputEvent {
    #[must_use]
    pub const fn new(
        sequence: u64,
        timestamp_ns: u64,
        source_host: HostId,
        source_device: DeviceId,
        payload: InputPayload,
    ) -> Self {
        Self {
            sequence,
            timestamp_ns,
            source_host,
            source_device,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_events_reject_non_finite_values() {
        assert!(InputPayload::PointerMove { dx: -2.5, dy: 8.0 }.is_finite());
        assert!(!InputPayload::PointerMove {
            dx: f64::NAN,
            dy: 0.0
        }
        .is_finite());
        assert!(!InputPayload::Scroll {
            horizontal: 0.0,
            vertical: f64::INFINITY
        }
        .is_finite());
    }

    #[test]
    fn constructor_preserves_ordering_metadata_and_source() {
        let host = HostId::from_bytes([9; 16]);
        let device = DeviceId::from_bytes([8; 16]);
        let event = InputEvent::new(
            42,
            1_000_000,
            host,
            device,
            InputPayload::Key {
                code: KeyCode::KeyA,
                state: KeyState::Pressed,
            },
        );

        assert_eq!(event.sequence, 42);
        assert_eq!(event.timestamp_ns, 1_000_000);
        assert_eq!(event.source_host, host);
        assert_eq!(event.source_device, device);
    }

    #[test]
    fn canonical_event_round_trips_through_serde() {
        let event = InputEvent::new(
            7,
            99,
            HostId::from_bytes([7; 16]),
            DeviceId::from_bytes([6; 16]),
            InputPayload::PointerButton {
                button: PointerButton::Other(8),
                state: ButtonState::Pressed,
            },
        );

        let json = serde_json::to_string(&event).unwrap();
        let decoded: InputEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn input_diagnostics_hide_payload_identity_and_ordering_details() {
        let host = HostId::from_bytes([0x41; 16]);
        let device = DeviceId::from_bytes([0x42; 16]);
        let event = InputEvent::new(
            987_654_321,
            123_456_789,
            host,
            device,
            InputPayload::Scroll {
                horizontal: 12_345.678_9,
                vertical: -98_765.432_1,
            },
        );
        let rendered = format!("{event:?} {:?}", event.payload);

        assert!(rendered.contains("Scroll"));
        for secret in [
            host.to_string(),
            device.to_string(),
            event.sequence.to_string(),
            event.timestamp_ns.to_string(),
            "12345.6789".to_owned(),
            "-98765.4321".to_owned(),
        ] {
            assert!(!rendered.contains(&secret));
        }
    }

    #[test]
    fn state_and_button_diagnostics_hide_exact_controls() {
        let rendered = format!(
            "{:?} {:?} {:?} {:?} {:?}",
            KeyState::Pressed,
            KeyState::Repeated,
            KeyState::Released,
            ButtonState::Pressed,
            PointerButton::Other(54_321)
        );
        for secret in ["Pressed", "Repeated", "Released", "Other", "54321"] {
            assert!(!rendered.contains(secret));
        }
    }
}
