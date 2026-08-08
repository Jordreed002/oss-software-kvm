//! macOS platform boundary for Software KVM.
//!
//! Device enumeration uses IOHID so built-in and external devices retain their
//! physical identity. Quartz injection is tagged with [`KVM_EVENT_TAG`] for a
//! future event tap to classify and discard looped-back events. IOHID capture
//! is observable through a bounded queue and never suppresses local input.
//! Proven hardware elements are classified physical; virtual or insufficiently
//! attributed IOHID observations remain unknown.
//! Selective suppression remains unavailable until IOHID identity can be
//! correlated with a suppressible `CGEvent` without guessing.

mod capture;
mod identity;
mod keymap;

#[cfg(target_os = "macos")]
mod native;
#[cfg(not(target_os = "macos"))]
mod unsupported;

pub use capture::classify_quartz_user_data;
pub use identity::{derive_device_id, DeviceIdentityMaterial, IdentityStability};
pub use keymap::mac_virtual_key;

#[cfg(target_os = "macos")]
pub use native::{probe_permissions, MacDisplayBackend, MacInputBackend, MacOutputBackend};
#[cfg(not(target_os = "macos"))]
pub use unsupported::{probe_permissions, MacDisplayBackend, MacInputBackend, MacOutputBackend};

use thiserror::Error;

/// Marker stored in Quartz's `kCGEventSourceUserData` field on injected events.
///
/// Event-tap capture must compare this exact value before routing an event.
pub const KVM_EVENT_TAG: i64 = 0x4f53_534b_564d_0001;

/// macOS privacy grants required by the production backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionStatus {
    /// Permission to control the computer through Quartz event injection.
    pub accessibility: bool,
    /// Permission to observe global keyboard and pointer input.
    pub input_monitoring: bool,
}

/// Snapshot of the bounded observation pipeline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureStatistics {
    /// Events dequeued and offered to the daemon callback.
    pub delivered_events: u64,
    /// Motion/scroll events dropped because the bounded queue was full.
    pub dropped_events: u64,
    /// Sessions terminated because a key/button transition could not be queued.
    pub transition_discontinuities: u64,
    /// Sessions terminated because the delivery worker disconnected.
    pub delivery_disconnects: u64,
    /// Requests to suppress locally that this observation-only backend ignored.
    pub ignored_suppression_requests: u64,
    /// Current or terminal health of the observation pipeline.
    pub health: CaptureHealth,
}

/// Observable lifecycle and terminal state of macOS input observation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum CaptureHealth {
    /// No observation session has started.
    #[default]
    Idle = 0,
    /// IOHID capture and bounded delivery are active.
    Running = 1,
    /// Observation stopped normally.
    Stopped = 2,
    /// A key/button transition could not be queued; input state is unreliable.
    TransitionDiscontinuity = 3,
    /// The callback delivery worker disconnected unexpectedly.
    DeliveryDisconnected = 4,
}

/// Failures at the platform boundary.
#[derive(Debug, Error)]
pub enum MacBackendError {
    #[error("the macOS backend is unavailable on this operating system")]
    UnsupportedPlatform,
    #[error("{feature} is not implemented: {reason}")]
    NotImplemented {
        feature: &'static str,
        reason: &'static str,
    },
    #[error("macOS API {operation} failed with status {code}")]
    NativeStatus { operation: &'static str, code: i32 },
    #[error("macOS API {operation} returned no value")]
    NullResult { operation: &'static str },
    #[error("macOS API {operation} returned a value outside the supported range")]
    NativeValueOutOfRange { operation: &'static str },
    #[error("macOS permission is required: {0}")]
    PermissionDenied(&'static str),
    #[error("input event cannot be injected by the current macOS backend: {0}")]
    UnsupportedInput(&'static str),
    #[error("macOS input capture is already running")]
    CaptureAlreadyRunning,
    #[error("macOS input capture thread terminated during startup")]
    CaptureStartupTerminated,
    #[error("macOS input capture did not become ready before the startup deadline")]
    CaptureStartupTimedOut,
    #[error("macOS input capture {0} thread panicked")]
    CaptureThreadPanicked(&'static str),
    #[error("macOS input capture lost a key/button transition; input state is discontinuous")]
    CaptureDiscontinuity,
    #[error("macOS input capture delivery worker disconnected unexpectedly")]
    CaptureDeliveryDisconnected,
    #[error("macOS input capture {0} did not stop before the shutdown deadline")]
    CaptureStopTimedOut(&'static str),
}
