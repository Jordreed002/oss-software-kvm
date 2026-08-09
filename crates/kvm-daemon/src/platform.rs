use std::error::Error;
use std::fmt;
use std::sync::Arc;

use kvm_input::InputEvent;
use kvm_types::{Display, InputDevice, Point};

/// Error boundary shared by platform implementations without exposing native
/// SDK error types to the daemon.
pub type PlatformError = Box<dyn Error + Send + Sync + 'static>;

/// Trust classification assigned before an event enters routing logic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventClassification {
    Physical,
    InjectedByKvm,
    Unknown,
}

/// Canonical event plus the backend's trust classification.
#[derive(Clone, Copy, PartialEq)]
pub struct CapturedInput {
    pub event: InputEvent,
    pub classification: EventClassification,
    native_pointer_position: Option<Point>,
}

impl fmt::Debug for CapturedInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedInput")
            .field("classification", &self.classification)
            .field("event", &"[REDACTED]")
            .field(
                "has_native_pointer_position",
                &self.native_pointer_position.is_some(),
            )
            .finish()
    }
}

impl CapturedInput {
    #[must_use]
    pub const fn new(event: InputEvent, classification: EventClassification) -> Self {
        Self {
            event,
            classification,
            native_pointer_position: None,
        }
    }

    /// Attaches the native host cursor position observed with a pointer-motion
    /// record. The value is routing metadata only; it is never serialized or
    /// accepted as remote authority.
    #[must_use]
    pub fn with_native_pointer_position(mut self, position: Point) -> Self {
        if position.x.is_finite() && position.y.is_finite() {
            self.native_pointer_position = Some(position);
        }
        self
    }

    /// Returns the native host cursor position captured with this record.
    #[must_use]
    pub const fn native_pointer_position(self) -> Option<Point> {
        self.native_pointer_position
    }
}

/// Immediate response required by a native suppression callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureDisposition {
    AllowLocal,
    SuppressLocal,
}

/// Coarse lifecycle state of a native capture owner.
///
/// A runtime must treat [`CaptureLifecycleState::Faulted`] as an immediate
/// routing gate and begin exact held-input cleanup. `Unknown` exists for
/// observation-only or legacy adapters and is never sufficient to enable a
/// suppressible runtime profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CaptureLifecycleState {
    /// The adapter does not provide a reviewed lifecycle signal.
    #[default]
    Unknown,
    /// No capture generation is installed.
    Idle,
    /// The current capture generation is active.
    Running,
    /// Capture stopped normally and no suppression remains installed.
    Stopped,
    /// Capture ended unexpectedly or lost state continuity.
    Faulted,
}

/// Callback invoked synchronously on the platform capture thread.
pub type CaptureCallback = Arc<dyn Fn(CapturedInput) -> CaptureDisposition + Send + Sync>;

/// Enumerates physical devices and owns the platform input-capture lifecycle.
pub trait InputCaptureBackend: Send {
    /// Returns the physical input devices currently visible to the backend.
    ///
    /// # Errors
    ///
    /// Returns a platform-specific error when enumeration fails.
    fn enumerate_devices(&self) -> Result<Vec<InputDevice>, PlatformError>;

    /// Starts capture using a synchronous suppression callback.
    ///
    /// # Errors
    ///
    /// Returns a platform-specific error when capture cannot be installed.
    fn start_capture(&mut self, callback: CaptureCallback) -> Result<(), PlatformError>;

    /// Stops capture and removes all local suppression.
    ///
    /// # Errors
    ///
    /// Returns a platform-specific error when capture teardown fails.
    fn stop_capture(&mut self) -> Result<(), PlatformError>;

    /// Returns a coarse, non-blocking snapshot of capture lifecycle health.
    ///
    /// Suppressible backends must override this method. It must not wait for a
    /// native thread, acquire a callback-owned blocking lock, or expose input
    /// payloads/native identifiers through diagnostics.
    fn capture_lifecycle(&self) -> CaptureLifecycleState {
        CaptureLifecycleState::Unknown
    }

    /// Shows or hides the local system cursor for pointer-authority changes.
    ///
    /// Suppressible whole-host backends should override this operation and
    /// must restore visibility during capture teardown, including failed or
    /// partial teardown. Observation-only adapters may use the default
    /// implementation, which supports the safe visible state only.
    ///
    /// # Errors
    ///
    /// Returns a platform error when the requested visibility cannot be
    /// established.
    fn set_cursor_visible(&mut self, visible: bool) -> Result<(), PlatformError> {
        if visible {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cursor hiding is unavailable",
            )
            .into())
        }
    }

    /// Places the local cursor at a trusted native screen coordinate before
    /// pointer authority becomes visible on this host.
    ///
    /// # Errors
    ///
    /// Returns a platform error when the coordinate cannot be established.
    fn set_cursor_position(&mut self, _position: Point) -> Result<(), PlatformError> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "cursor positioning is unavailable",
        )
        .into())
    }
}

/// Injects canonical input received from an authenticated remote peer.
pub trait OutputInjectionBackend: Send {
    /// Injects one event and tags it for later loop-prevention classification.
    ///
    /// # Errors
    ///
    /// Returns a platform-specific error when injection fails.
    fn inject(&mut self, event: &InputEvent) -> Result<(), PlatformError>;
}

/// Reports the host's current display configuration.
pub trait DisplayBackend: Send + Sync {
    /// Enumerates every attached display in native logical coordinates.
    ///
    /// # Errors
    ///
    /// Returns a platform-specific error when display enumeration fails.
    fn enumerate_displays(&self) -> Result<Vec<Display>, PlatformError>;
}

/// Classifies a native event before it is translated into routing work.
pub trait EventClassifier: Send + Sync {
    type NativeEvent: ?Sized;

    fn classify(&self, event: &Self::NativeEvent) -> EventClassification;
}

#[cfg(test)]
mod tests {
    use kvm_input::{InputEvent, InputPayload};
    use kvm_types::{DeviceId, HostId};

    use super::*;

    #[test]
    fn captured_input_debug_redacts_identity_payload_and_timing() {
        let host = HostId::from_bytes([0x71; 16]);
        let device = DeviceId::from_bytes([0x72; 16]);
        let captured = CapturedInput::new(
            InputEvent::new(
                7_171,
                8_282,
                host,
                device,
                InputPayload::PointerMove {
                    dx: 91_919.25,
                    dy: -82_828.5,
                },
            ),
            EventClassification::Physical,
        );
        let rendered = format!("{captured:?}");

        for marker in [
            "7171",
            "8282",
            "91919.25",
            "-82828.5",
            &host.to_string(),
            &device.to_string(),
        ] {
            assert!(!rendered.contains(marker), "leaked marker: {marker}");
        }
        assert!(rendered.contains("Physical"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn capture_lifecycle_debug_is_coarse() {
        assert_eq!(format!("{:?}", CaptureLifecycleState::Faulted), "Faulted");
    }
}
