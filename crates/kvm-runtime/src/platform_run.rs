//! Target-selected native inventory, capture, injection, and runtime ownership.

use std::fmt;
use std::path::Path;

#[cfg(any(target_os = "macos", windows))]
use kvm_daemon::{DisplayBackend, InputCaptureBackend};

#[cfg(any(target_os = "macos", windows))]
use crate::prepare;

/// Coarse category for a foreground native runtime failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRuntimeErrorKind {
    UnsupportedPlatform,
    Preparation,
    Inventory,
    Composition,
    Capture,
    Transport,
    Task,
}

/// Path-, identity-, endpoint-, native-detail-, and payload-redacted runtime
/// activation failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NativeRuntimeError {
    kind: NativeRuntimeErrorKind,
}

impl NativeRuntimeError {
    const fn new(kind: NativeRuntimeErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> NativeRuntimeErrorKind {
        self.kind
    }
}

impl fmt::Debug for NativeRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeRuntimeError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for NativeRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            NativeRuntimeErrorKind::UnsupportedPlatform => {
                "the native alpha supports Windows and macOS only"
            }
            NativeRuntimeErrorKind::Preparation => "secure runtime preparation failed",
            NativeRuntimeErrorKind::Inventory => "native display or input inventory failed",
            NativeRuntimeErrorKind::Composition => "runtime authority composition failed",
            NativeRuntimeErrorKind::Capture => "native capture lifecycle failed",
            NativeRuntimeErrorKind::Transport => "authenticated transport service failed",
            NativeRuntimeErrorKind::Task => "runtime service task failed",
        })
    }
}

impl std::error::Error for NativeRuntimeError {}

/// Securely prepares and runs the foreground native alpha until shutdown.
///
/// # Errors
///
/// Returns a coarse platform, preparation, inventory, composition, or service
/// failure without exposing paths, identities, endpoints, or native details.
pub async fn run_native_profile(
    profile_path: &Path,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), NativeRuntimeError> {
    #[cfg(target_os = "macos")]
    {
        run_macos(profile_path, shutdown).await
    }

    #[cfg(windows)]
    {
        run_windows(profile_path, shutdown).await
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (profile_path, shutdown);
        Err(NativeRuntimeError::new(
            NativeRuntimeErrorKind::UnsupportedPlatform,
        ))
    }
}

#[cfg(windows)]
async fn run_windows(
    profile_path: &Path,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), NativeRuntimeError> {
    use kvm_windows::{WindowsDisplayBackend, WindowsInputBackend, WindowsOutputBackend};

    let prepared = prepare(profile_path)
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Preparation))?;
    let local_host = prepared.local_host_id();
    let input = WindowsInputBackend::new_whole_host_alpha(local_host);
    let devices = input
        .enumerate_devices()
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Inventory))?;
    let displays = WindowsDisplayBackend::new(local_host)
        .enumerate_displays()
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Inventory))?;
    let runtime = prepared
        .compose(WindowsOutputBackend::new(), displays, devices)
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Composition))?;
    runtime
        .run_with_capture(input, shutdown)
        .await
        .map_err(native_service_error)
}

#[cfg(target_os = "macos")]
async fn run_macos(
    profile_path: &Path,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), NativeRuntimeError> {
    use kvm_macos::{MacDisplayBackend, MacInputBackend, MacOutputBackend};

    let prepared = prepare(profile_path)
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Preparation))?;
    let local_host = prepared.local_host_id();
    let input = MacInputBackend::new_whole_host_alpha(local_host);
    let devices = input
        .enumerate_devices()
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Inventory))?;
    let displays = MacDisplayBackend::new(local_host)
        .enumerate_displays()
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Inventory))?;
    let runtime = prepared
        .compose(MacOutputBackend::new(), displays, devices)
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Composition))?;
    runtime
        .run_with_capture(input, shutdown)
        .await
        .map_err(native_service_error)
}

#[cfg(any(target_os = "macos", windows))]
fn native_service_error(error: crate::active::RuntimeServiceError) -> NativeRuntimeError {
    use crate::active::RuntimeServiceErrorKind;

    let kind = match error.kind() {
        RuntimeServiceErrorKind::Capture => NativeRuntimeErrorKind::Capture,
        RuntimeServiceErrorKind::Transport => NativeRuntimeErrorKind::Transport,
        RuntimeServiceErrorKind::Task => NativeRuntimeErrorKind::Task,
    };
    NativeRuntimeError::new(kind)
}
