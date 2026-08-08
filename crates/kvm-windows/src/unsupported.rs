use kvm_daemon::{
    CaptureCallback, DisplayBackend, InputCaptureBackend, OutputInjectionBackend, PlatformError,
};
use kvm_input::InputEvent;
use kvm_types::{Display, HostId, InputDevice};

use crate::{
    CapabilityState, CaptureStatistics, SuppressionScope, WindowsBackendError, WindowsCapabilities,
    WindowsCaptureMode,
};

#[derive(Debug)]
pub struct WindowsInputBackend {
    host_id: HostId,
    capture_mode: WindowsCaptureMode,
    statistics: CaptureStatistics,
}

impl WindowsInputBackend {
    #[must_use]
    pub const fn new(host_id: HostId) -> Self {
        Self {
            host_id,
            capture_mode: WindowsCaptureMode::RawInputObservation,
            statistics: CaptureStatistics {
                captured_events: 0,
                dropped_events: 0,
                untranslated_packets: 0,
                keyboard_packets: 0,
                mouse_packets: 0,
                untranslated_keyboard_packets: 0,
                untranslated_mouse_packets: 0,
                callback_panics: 0,
                suppression_requests_ignored: 0,
                suppressed_events: 0,
                capture_discontinuities: 0,
            },
        }
    }

    #[must_use]
    pub const fn new_whole_host_alpha(host_id: HostId) -> Self {
        Self {
            host_id,
            capture_mode: WindowsCaptureMode::WholeHostAlpha,
            statistics: CaptureStatistics {
                captured_events: 0,
                dropped_events: 0,
                untranslated_packets: 0,
                keyboard_packets: 0,
                mouse_packets: 0,
                untranslated_keyboard_packets: 0,
                untranslated_mouse_packets: 0,
                callback_panics: 0,
                suppression_requests_ignored: 0,
                suppressed_events: 0,
                capture_discontinuities: 0,
            },
        }
    }

    #[must_use]
    pub const fn capture_mode(&self) -> WindowsCaptureMode {
        self.capture_mode
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub const fn capture_statistics(&self) -> CaptureStatistics {
        self.statistics
    }
}

#[derive(Debug, Default)]
pub struct WindowsOutputBackend;

impl WindowsOutputBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Debug)]
pub struct WindowsDisplayBackend {
    host_id: HostId,
}

impl WindowsDisplayBackend {
    #[must_use]
    pub const fn new(host_id: HostId) -> Self {
        Self { host_id }
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }
}

#[must_use]
pub fn probe_capabilities() -> WindowsCapabilities {
    WindowsCapabilities {
        device_enumeration: CapabilityState::UnsupportedPlatform,
        input_injection: CapabilityState::UnsupportedPlatform,
        display_enumeration: CapabilityState::UnsupportedPlatform,
        device_aware_capture: CapabilityState::UnsupportedPlatform,
        per_device_suppression: CapabilityState::UnsupportedPlatform,
        suppression_scope: SuppressionScope::UnsupportedPlatform,
        diagnostics: vec!["Windows APIs are unavailable on this operating system".into()],
    }
}

fn unsupported() -> PlatformError {
    Box::new(WindowsBackendError::UnsupportedPlatform)
}

impl InputCaptureBackend for WindowsInputBackend {
    fn enumerate_devices(&self) -> Result<Vec<InputDevice>, PlatformError> {
        Err(unsupported())
    }

    fn start_capture(&mut self, _callback: CaptureCallback) -> Result<(), PlatformError> {
        Err(unsupported())
    }

    fn stop_capture(&mut self) -> Result<(), PlatformError> {
        Err(unsupported())
    }
}

impl OutputInjectionBackend for WindowsOutputBackend {
    fn inject(&mut self, _event: &InputEvent) -> Result<(), PlatformError> {
        Err(unsupported())
    }
}

impl DisplayBackend for WindowsDisplayBackend {
    fn enumerate_displays(&self) -> Result<Vec<Display>, PlatformError> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_windows_probe_never_claims_native_support() {
        let capabilities = probe_capabilities();
        assert_eq!(
            capabilities.device_enumeration,
            CapabilityState::UnsupportedPlatform
        );
        assert_eq!(
            capabilities.per_device_suppression,
            CapabilityState::UnsupportedPlatform
        );
    }
}
