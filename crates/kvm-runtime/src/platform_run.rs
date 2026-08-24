//! Target-selected native inventory, capture, injection, and runtime ownership.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

#[cfg(any(target_os = "macos", windows))]
use kvm_daemon::{DisplayBackend, InputCaptureBackend};
#[cfg(any(target_os = "macos", windows))]
use kvm_types::{Display, HostId, InputDevice};

#[cfg(any(target_os = "macos", windows))]
use crate::active::{developer_event, LocalInventoryHint, LocalInventoryWatch};
#[cfg(any(target_os = "macos", windows))]
use crate::prepare;
#[cfg(any(target_os = "macos", windows))]
use crate::runtime_status::RuntimeStatusPublisher;

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
    use kvm_config::ModifierRoleMapping;
    use kvm_windows::{WindowsDisplayBackend, WindowsInputBackend, WindowsOutputBackend};

    let prepared = prepare(profile_path).map_err(|error| {
        eprintln!("preparation failed: {:?}", error.kind());
        NativeRuntimeError::new(NativeRuntimeErrorKind::Preparation)
    })?;
    let local_host = prepared.local_host_id();
    let output = if prepared.selected_peer_platform() == Some(kvm_types::Platform::MacOS) {
        match prepared.selected_modifier_role_mapping() {
            ModifierRoleMapping::Functional => WindowsOutputBackend::new_from_macos_functional(),
            ModifierRoleMapping::Positional => WindowsOutputBackend::new_from_macos(),
            ModifierRoleMapping::Identity => WindowsOutputBackend::new(),
        }
    } else {
        WindowsOutputBackend::new()
    };
    let input = WindowsInputBackend::new_whole_host_alpha(local_host);
    let devices = input
        .enumerate_devices()
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Inventory))?;
    let displays = WindowsDisplayBackend::new(local_host)
        .enumerate_displays()
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Inventory))?;
    let watch = windows_local_inventory_watch(local_host);
    let runtime = prepared
        .compose(output, displays, devices)
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Composition))?;
    runtime
        .run_with_capture_status(
            input,
            shutdown,
            Some(RuntimeStatusPublisher::for_profile(profile_path)),
            watch,
        )
        .await
        .map_err(native_service_error)
}

#[cfg(target_os = "macos")]
async fn run_macos(
    profile_path: &Path,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), NativeRuntimeError> {
    use kvm_config::ModifierRoleMapping;
    use kvm_macos::{MacDisplayBackend, MacInputBackend, MacOutputBackend};

    let prepared = prepare(profile_path).map_err(|error| {
        eprintln!("preparation failed: {:?}", error.kind());
        NativeRuntimeError::new(NativeRuntimeErrorKind::Preparation)
    })?;
    let local_host = prepared.local_host_id();
    let output = if prepared.selected_peer_platform() == Some(kvm_types::Platform::Windows) {
        match prepared.selected_modifier_role_mapping() {
            ModifierRoleMapping::Functional => MacOutputBackend::new_from_windows_functional(),
            ModifierRoleMapping::Positional => MacOutputBackend::new_from_windows(),
            ModifierRoleMapping::Identity => MacOutputBackend::new(),
        }
    } else {
        MacOutputBackend::new()
    };
    let input = MacInputBackend::new_whole_host_alpha(local_host);
    let devices = input
        .enumerate_devices()
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Inventory))?;
    let displays = MacDisplayBackend::new(local_host)
        .enumerate_displays()
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Inventory))?;
    let watch = macos_local_inventory_watch(local_host);
    let runtime = prepared
        .compose(output, displays, devices)
        .map_err(|_| NativeRuntimeError::new(NativeRuntimeErrorKind::Composition))?;
    runtime
        .run_with_capture_status(
            input,
            shutdown,
            Some(RuntimeStatusPublisher::for_profile(profile_path)),
            watch,
        )
        .await
        .map_err(native_service_error)
}

/// Builds the macOS hotplug watch or degrades to the boot-time snapshot.
///
/// The watcher is a monitoring capability, not an authority gate: when it
/// cannot start, the runtime keeps running with the pre-remediation behavior
/// (one enumeration at startup) rather than failing the whole service.
#[cfg(target_os = "macos")]
fn macos_local_inventory_watch(local_host: HostId) -> Option<LocalInventoryWatch> {
    use kvm_macos::{MacDisplayBackend, MacHotplugWatcher, MacInputBackend};

    let Ok(watcher) = MacHotplugWatcher::start() else {
        developer_event("hotplug=watch_unavailable platform:macos");
        return None;
    };
    // The refresh closures mirror the startup enumeration exactly (stateless
    // backends; the whole-host device inventory matches the capture mode the
    // runtime composes) so a refreshed snapshot is comparable to the initial
    // one.
    let refresh_displays: Arc<dyn Fn() -> Option<Vec<Display>> + Send + Sync> =
        Arc::new(move || MacDisplayBackend::new(local_host).enumerate_displays().ok());
    let refresh_devices: Arc<dyn Fn() -> Option<Vec<InputDevice>> + Send + Sync> =
        Arc::new(move || {
            MacInputBackend::new_whole_host_alpha(local_host)
                .enumerate_devices()
                .ok()
        });
    Some(LocalInventoryWatch::new(
        Box::new(move || watcher.poll().map(mac_inventory_hint)),
        refresh_displays,
        refresh_devices,
    ))
}

#[cfg(target_os = "macos")]
fn mac_inventory_hint(change: kvm_macos::InventoryChange) -> LocalInventoryHint {
    match change {
        kvm_macos::InventoryChange::DisplayChanged => LocalInventoryHint::DisplaysChanged,
        kvm_macos::InventoryChange::DeviceAdded | kvm_macos::InventoryChange::DeviceRemoved => {
            LocalInventoryHint::DevicesChanged
        }
    }
}

/// Builds the Windows hotplug watch or degrades to the boot-time snapshot.
#[cfg(windows)]
fn windows_local_inventory_watch(local_host: HostId) -> Option<LocalInventoryWatch> {
    use kvm_windows::{WindowsDisplayBackend, WindowsHotplugWatcher, WindowsInputBackend};

    let Ok(watcher) = WindowsHotplugWatcher::start() else {
        developer_event("hotplug=watch_unavailable platform:windows");
        return None;
    };
    let refresh_displays: Arc<dyn Fn() -> Option<Vec<Display>> + Send + Sync> =
        Arc::new(move || {
            WindowsDisplayBackend::new(local_host)
                .enumerate_displays()
                .ok()
        });
    let refresh_devices: Arc<dyn Fn() -> Option<Vec<InputDevice>> + Send + Sync> =
        Arc::new(move || {
            WindowsInputBackend::new_whole_host_alpha(local_host)
                .enumerate_devices()
                .ok()
        });
    Some(LocalInventoryWatch::new(
        Box::new(move || watcher.poll().map(windows_inventory_hint)),
        refresh_displays,
        refresh_devices,
    ))
}

#[cfg(windows)]
fn windows_inventory_hint(change: kvm_windows::InventoryChange) -> LocalInventoryHint {
    match change {
        kvm_windows::InventoryChange::DisplayChanged => LocalInventoryHint::DisplaysChanged,
        kvm_windows::InventoryChange::DeviceAdded | kvm_windows::InventoryChange::DeviceRemoved => {
            LocalInventoryHint::DevicesChanged
        }
    }
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
