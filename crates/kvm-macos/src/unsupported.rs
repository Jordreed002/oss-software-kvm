use kvm_daemon::{
    CaptureCallback, CaptureLifecycleState, DisplayBackend, InputCaptureBackend,
    OutputInjectionBackend, PlatformError,
};
use kvm_input::InputEvent;
use kvm_types::{Display, HostId, InputDevice};

use crate::{
    CaptureHealth, CaptureStatistics, MacBackendError, MacCaptureMode, PermissionStatus,
    SuppressionScope,
};

/// Safe placeholder compiled on non-macOS hosts.
#[derive(Debug)]
pub struct MacInputBackend {
    host_id: HostId,
    capture_mode: MacCaptureMode,
}

impl MacInputBackend {
    #[must_use]
    pub const fn new(host_id: HostId) -> Self {
        Self {
            host_id,
            capture_mode: MacCaptureMode::IoHidObservation,
        }
    }

    #[must_use]
    pub const fn new_whole_host_alpha(host_id: HostId) -> Self {
        Self {
            host_id,
            capture_mode: MacCaptureMode::WholeHostAlpha,
        }
    }

    #[must_use]
    pub const fn capture_mode(&self) -> MacCaptureMode {
        self.capture_mode
    }

    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn suppression_scope(&self) -> SuppressionScope {
        SuppressionScope::UnsupportedPlatform
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    /// Selective macOS suppression is unavailable on this operating system.
    #[must_use]
    pub const fn selective_suppression_supported() -> bool {
        false
    }

    /// No capture session can run on this operating system.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn capture_statistics(&self) -> CaptureStatistics {
        CaptureStatistics {
            delivered_events: 0,
            dropped_events: 0,
            transition_discontinuities: 0,
            delivery_disconnects: 0,
            ignored_suppression_requests: 0,
            suppressed_events: 0,
            untranslated_events: 0,
            callback_panics: 0,
            callback_overruns: 0,
            tap_disables: 0,
            health: CaptureHealth::Idle,
        }
    }
}

impl InputCaptureBackend for MacInputBackend {
    fn enumerate_devices(&self) -> Result<Vec<InputDevice>, PlatformError> {
        Err(MacBackendError::UnsupportedPlatform.into())
    }

    fn start_capture(&mut self, _callback: CaptureCallback) -> Result<(), PlatformError> {
        Err(MacBackendError::UnsupportedPlatform.into())
    }

    fn stop_capture(&mut self) -> Result<(), PlatformError> {
        Err(MacBackendError::UnsupportedPlatform.into())
    }

    fn capture_lifecycle(&self) -> CaptureLifecycleState {
        CaptureLifecycleState::Idle
    }
}

/// Safe placeholder compiled on non-macOS hosts.
#[derive(Debug, Default)]
pub struct MacOutputBackend;

impl MacOutputBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub const fn new_from_windows() -> Self {
        Self
    }
}

impl OutputInjectionBackend for MacOutputBackend {
    fn inject(&mut self, _event: &InputEvent) -> Result<(), PlatformError> {
        Err(MacBackendError::UnsupportedPlatform.into())
    }
}

/// Safe placeholder compiled on non-macOS hosts.
#[derive(Debug)]
pub struct MacDisplayBackend {
    host_id: HostId,
}

impl MacDisplayBackend {
    #[must_use]
    pub const fn new(host_id: HostId) -> Self {
        Self { host_id }
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }
}

impl DisplayBackend for MacDisplayBackend {
    fn enumerate_displays(&self) -> Result<Vec<Display>, PlatformError> {
        Err(MacBackendError::UnsupportedPlatform.into())
    }
}

/// Returns an error on non-macOS hosts rather than inventing permission state.
///
/// # Errors
///
/// Always returns [`MacBackendError::UnsupportedPlatform`].
pub fn probe_permissions() -> Result<PermissionStatus, MacBackendError> {
    Err(MacBackendError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stubs_preserve_configuration_but_fail_explicitly() {
        let host = HostId::from_bytes([4; 16]);
        let input = MacInputBackend::new(host);
        let display = MacDisplayBackend::new(host);

        assert_eq!(input.host_id(), host);
        assert_eq!(display.host_id(), host);
        assert!(!MacInputBackend::selective_suppression_supported());
        assert_eq!(input.capture_mode(), MacCaptureMode::IoHidObservation);
        assert_eq!(
            input.suppression_scope(),
            SuppressionScope::UnsupportedPlatform
        );
        assert_eq!(input.capture_lifecycle(), CaptureLifecycleState::Idle);
        assert_eq!(input.capture_statistics(), CaptureStatistics::default());
        assert!(input.enumerate_devices().is_err());
        assert!(display.enumerate_displays().is_err());
        assert!(probe_permissions().is_err());
    }
}
