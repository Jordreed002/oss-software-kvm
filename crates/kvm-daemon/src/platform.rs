use std::error::Error;
use std::sync::Arc;

use kvm_input::InputEvent;
use kvm_types::{Display, InputDevice};

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
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CapturedInput {
    pub event: InputEvent,
    pub classification: EventClassification,
}

impl CapturedInput {
    #[must_use]
    pub const fn new(event: InputEvent, classification: EventClassification) -> Self {
        Self {
            event,
            classification,
        }
    }
}

/// Immediate response required by a native suppression callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureDisposition {
    AllowLocal,
    SuppressLocal,
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
