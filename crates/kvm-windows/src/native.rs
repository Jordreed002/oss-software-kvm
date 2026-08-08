// Win32 bindings necessarily cross an FFI boundary. Keep the workspace-wide
// unsafe prohibition intact everywhere else and audit each block in this file.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use kvm_daemon::{
    CaptureCallback, CaptureDisposition, CapturedInput, DisplayBackend, EventClassification,
    InputCaptureBackend, OutputInjectionBackend, PlatformError,
};
use kvm_input::{InputEvent, InputPayload};
use kvm_types::{
    DeviceCapabilities, DeviceKind, Display, DisplayId, HostId, InputDevice, Rect, Size,
};
use windows::core::{w, BOOL};
use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO, MONITORINFOEXW,
};
use windows::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
    MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
    MOUSEEVENTF_XUP, MOUSEINPUT, VIRTUAL_KEY,
};
use windows::Win32::UI::Input::{
    GetCurrentInputMessageSource, GetRawInputData, GetRawInputDeviceInfoW, GetRawInputDeviceList,
    RegisterRawInputDevices, HRAWINPUT, IMO_HARDWARE, IMO_INJECTED, IMO_SYSTEM,
    INPUT_MESSAGE_SOURCE, RAWINPUT, RAWINPUTDEVICE, RAWINPUTDEVICELIST, RIDEV_DEVNOTIFY,
    RIDEV_INPUTSINK, RIDEV_REMOVE, RIDI_DEVICEINFO, RIDI_DEVICENAME, RID_DEVICE_INFO, RID_INPUT,
    RIM_TYPEKEYBOARD, RIM_TYPEMOUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    GetWindowThreadProcessId, PostMessageW, PostThreadMessageW, TranslateMessage, HWND_MESSAGE,
    MONITORINFOF_PRIMARY, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_INPUT,
    WM_INPUT_DEVICE_CHANGE, WM_QUIT,
};

use crate::capture::{
    classify_raw_input, is_state_transition, translate_keyboard, translate_mouse, MessageOrigin,
    RawKeyboardPacket, RawMousePacket,
};
use crate::identity::usb_ids_from_device_path;
use crate::mapping::{key_is_released, mouse_action, scan_code, MouseAction, WHEEL_DELTA};
use crate::ownership::{ClaimError, RegistrationState};
use crate::{
    derive_device_id, CapabilityState, CaptureStatistics, WindowsBackendError, WindowsCapabilities,
    CAPTURE_QUEUE_CAPACITY, KVM_INJECTION_TAG,
};

const UINT_ERROR: u32 = u32::MAX;
const CAPTURE_STOP_MESSAGE: u32 = WM_APP + 0x4b;
const CAPTURE_START_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_STOP_TIMEOUT: Duration = Duration::from_secs(2);
static RAW_INPUT_OWNERSHIP: Mutex<RegistrationState> = Mutex::new(RegistrationState::new());

#[derive(Debug, Default)]
struct CaptureCounters {
    captured_events: AtomicU64,
    dropped_events: AtomicU64,
    untranslated_packets: AtomicU64,
    callback_panics: AtomicU64,
    suppression_requests_ignored: AtomicU64,
    capture_discontinuities: AtomicU64,
}

impl CaptureCounters {
    fn snapshot(&self) -> CaptureStatistics {
        CaptureStatistics {
            captured_events: self.captured_events.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            untranslated_packets: self.untranslated_packets.load(Ordering::Relaxed),
            callback_panics: self.callback_panics.load(Ordering::Relaxed),
            suppression_requests_ignored: self.suppression_requests_ignored.load(Ordering::Relaxed),
            capture_discontinuities: self.capture_discontinuities.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
struct RegistrationClaim {
    generation: u64,
    release_on_drop: bool,
}

impl RegistrationClaim {
    fn is_current(&self) -> bool {
        registration_state().is_owner(self.generation)
    }

    fn release(&mut self) {
        let _ = registration_state().release(self.generation);
        self.release_on_drop = false;
    }

    /// Leaves the generation claimed after native unregister failure. A new
    /// generation must not replace process-global registrations in that state.
    fn hold_after_cleanup_failure(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for RegistrationClaim {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.release();
        }
    }
}

#[derive(Debug)]
struct NativeCaptureRegistration {
    claim: RegistrationClaim,
    window: Option<HWND>,
    registered: bool,
}

#[derive(Debug)]
struct CaptureSession {
    window: isize,
    thread_id: u32,
    message_thread: Option<JoinHandle<Result<(), WindowsBackendError>>>,
    callback_thread: Option<JoinHandle<()>>,
    message_done: Receiver<()>,
    callback_done: Receiver<()>,
}

#[derive(Clone, Copy, Debug)]
struct CaptureReady {
    window: isize,
    thread_id: u32,
}

impl NativeCaptureRegistration {
    fn new(claim: RegistrationClaim, window: HWND) -> Self {
        Self {
            claim,
            window: Some(window),
            registered: false,
        }
    }

    fn mark_registered(&mut self) {
        self.registered = true;
    }

    fn cleanup(&mut self) -> Result<(), WindowsBackendError> {
        let mut first_error = None;
        if self.registered && self.claim.is_current() {
            match unregister_raw_input() {
                Ok(()) => self.registered = false,
                Err(error) => {
                    // Do not let another backend overwrite a registration that
                    // this generation failed to remove.
                    self.claim.hold_after_cleanup_failure();
                    first_error = Some(error);
                }
            }
        }

        if let Some(window) = self.window.take() {
            // SAFETY: capture registration is created, used, and destroyed on
            // this same message thread, and the handle is consumed only once.
            if let Err(error) = unsafe { DestroyWindow(window) } {
                first_error.get_or_insert_with(|| binding_error("DestroyWindow(capture)", &error));
            }
        }

        if !self.registered {
            self.claim.release();
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for NativeCaptureRegistration {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn registration_state() -> std::sync::MutexGuard<'static, RegistrationState> {
    RAW_INPUT_OWNERSHIP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn claim_raw_input_registration() -> Result<RegistrationClaim, WindowsBackendError> {
    match registration_state().claim() {
        Ok(generation) => Ok(RegistrationClaim {
            generation,
            release_on_drop: true,
        }),
        Err(ClaimError::AlreadyOwned) => Err(WindowsBackendError::CaptureRegistrationOwned),
        Err(ClaimError::GenerationExhausted) => Err(WindowsBackendError::CaptureRuntime(
            "Raw Input registration generation exhausted u64".into(),
        )),
    }
}

#[derive(Debug)]
pub struct WindowsInputBackend {
    host_id: HostId,
    capture: Option<CaptureSession>,
    counters: Arc<CaptureCounters>,
}

impl WindowsInputBackend {
    #[must_use]
    pub fn new(host_id: HostId) -> Self {
        Self {
            host_id,
            capture: None,
            counters: Arc::new(CaptureCounters::default()),
        }
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub fn capture_statistics(&self) -> CaptureStatistics {
        self.counters.snapshot()
    }

    /// Enumerates keyboard and mouse collections exposed by Raw Input.
    ///
    /// The Raw Input device-interface path is used as the durable identity.
    /// When Windows returns an empty path, the native handle is used as an
    /// explicit last-resort fallback; that fallback is unique only for the
    /// current login session and can change after restart or reconnect.
    ///
    /// # Errors
    ///
    /// Returns an error when Raw Input device-list, name, or information
    /// queries fail.
    pub fn enumerate_raw_input_devices(&self) -> Result<Vec<InputDevice>, WindowsBackendError> {
        raw_device_entries()?
            .into_iter()
            .filter_map(|entry| self.input_device(entry).transpose())
            .collect()
    }

    fn input_device(
        &self,
        entry: RAWINPUTDEVICELIST,
    ) -> Result<Option<InputDevice>, WindowsBackendError> {
        if entry.dwType != RIM_TYPEKEYBOARD && entry.dwType != RIM_TYPEMOUSE {
            return Ok(None);
        }

        let raw_path = raw_device_name(entry.hDevice)?;
        let info = raw_device_info(entry.hDevice)?;
        let (kind, capabilities, fallback_label) = if entry.dwType == RIM_TYPEKEYBOARD {
            (
                DeviceKind::Keyboard,
                DeviceCapabilities::KEYBOARD,
                "Raw Input keyboard",
            )
        } else {
            // SAFETY: `dwType` was checked as `RIM_TYPEMOUSE`, so the mouse
            // member is the initialized arm of `RID_DEVICE_INFO::Anonymous`.
            let mouse = unsafe { info.Anonymous.mouse };
            (
                DeviceKind::Mouse,
                DeviceCapabilities {
                    pointer: true,
                    keyboard: false,
                    vertical_scroll: true,
                    horizontal_scroll: mouse.fHasHorizontalWheel.as_bool(),
                    extra_buttons: mouse.dwNumberOfButtons > 3,
                },
                "Raw Input mouse",
            )
        };

        let durable_identity = if raw_path.is_empty() {
            format!("session-handle:{}:{:p}", fallback_label, entry.hDevice.0)
        } else {
            raw_path.clone()
        };
        let (vendor_id, product_id) = usb_ids_from_device_path(&raw_path);
        let mut device = InputDevice::new(
            derive_device_id(&durable_identity),
            self.host_id,
            if raw_path.is_empty() {
                fallback_label.to_owned()
            } else {
                raw_path
            },
            kind,
            capabilities,
        );
        device.vendor_id = vendor_id;
        device.product_id = product_id;
        Ok(Some(device))
    }

    /// Starts observation-only Raw Input capture.
    ///
    /// The callback runs on a dedicated dispatcher thread. Raw Input delivery
    /// uses a bounded, non-blocking queue; overflow is counted rather than
    /// blocking the Windows message loop. Any `SuppressLocal` result is ignored
    /// because Raw Input cannot suppress the corresponding legacy event.
    ///
    /// # Errors
    ///
    /// Returns an error when capture is already active, a worker cannot be
    /// spawned, process-global registration is owned by another backend, the
    /// startup handshake times out, the hidden message window cannot be
    /// created, or Raw Input registration fails.
    pub fn start_observing(
        &mut self,
        callback: CaptureCallback,
    ) -> Result<(), WindowsBackendError> {
        if self.capture.is_some() {
            return Err(WindowsBackendError::CaptureAlreadyRunning);
        }
        let registration_claim = claim_raw_input_registration()?;

        let (event_sender, event_receiver) = mpsc::sync_channel(CAPTURE_QUEUE_CAPACITY);
        let (callback_done_sender, callback_done) = mpsc::sync_channel(1);
        let callback_counters = Arc::clone(&self.counters);
        let callback_thread = thread::Builder::new()
            .name("kvm-windows-callback".into())
            .spawn(move || {
                callback_dispatch_loop(&event_receiver, &callback, &callback_counters);
                let _ = callback_done_sender.send(());
            })
            .map_err(|error| {
                WindowsBackendError::CaptureRuntime(format!(
                    "could not spawn callback dispatcher: {error}"
                ))
            })?;

        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (ready_ack_sender, ready_ack_receiver) = mpsc::sync_channel(1);
        let (message_done_sender, message_done) = mpsc::sync_channel(1);
        let capture_counters = Arc::clone(&self.counters);
        let host_id = self.host_id;
        let message_thread = match thread::Builder::new()
            .name("kvm-windows-raw-input".into())
            .spawn(move || {
                let result = raw_input_thread(
                    host_id,
                    &event_sender,
                    &capture_counters,
                    &ready_sender,
                    &ready_ack_receiver,
                    registration_claim,
                );
                let _ = message_done_sender.send(());
                result
            }) {
            Ok(thread) => thread,
            Err(error) => {
                let _ = callback_thread.join();
                return Err(WindowsBackendError::CaptureRuntime(format!(
                    "could not spawn Raw Input thread: {error}"
                )));
            }
        };

        match ready_receiver.recv_timeout(CAPTURE_START_TIMEOUT) {
            Ok(Ok(ready)) => {
                ready_ack_sender.send(()).map_err(|_| {
                    WindowsBackendError::CaptureRuntime(
                        "Raw Input thread ended before startup acknowledgement".into(),
                    )
                })?;
                self.capture = Some(CaptureSession {
                    window: ready.window,
                    thread_id: ready.thread_id,
                    message_thread: Some(message_thread),
                    callback_thread: Some(callback_thread),
                    message_done,
                    callback_done,
                });
                Ok(())
            }
            Ok(Err(error)) => {
                drop(message_thread);
                drop(callback_thread);
                Err(error)
            }
            Err(RecvTimeoutError::Timeout) => {
                drop(message_thread);
                drop(callback_thread);
                Err(WindowsBackendError::CaptureRuntime(format!(
                    "Raw Input startup exceeded {} seconds",
                    CAPTURE_START_TIMEOUT.as_secs()
                )))
            }
            Err(RecvTimeoutError::Disconnected) => {
                drop(message_thread);
                drop(callback_thread);
                Err(WindowsBackendError::CaptureRuntime(
                    "Raw Input thread ended before startup completed".into(),
                ))
            }
        }
    }

    /// Stops capture and joins both worker threads. Calling this while stopped
    /// is a successful no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if both stop-message paths fail and capture does not
    /// exit before the timeout, a worker panics, capture became discontinuous,
    /// or the Raw Input thread reports a native failure during shutdown.
    pub fn stop_observing(&mut self) -> Result<(), WindowsBackendError> {
        let Some(session) = self.capture.as_mut() else {
            return Ok(());
        };
        let mut thread_error = None;

        if session.message_thread.is_some() {
            let signal_error = signal_capture_stop(session).err();
            match session.message_done.recv_timeout(CAPTURE_STOP_TIMEOUT) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    if let Some(handle) = session.message_thread.take() {
                        match handle.join() {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => thread_error = Some(error),
                            Err(_) => {
                                thread_error = Some(WindowsBackendError::CaptureRuntime(
                                    "Raw Input thread panicked".into(),
                                ));
                            }
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(signal_error.unwrap_or_else(|| {
                        WindowsBackendError::CaptureRuntime(format!(
                            "Raw Input shutdown exceeded {} seconds",
                            CAPTURE_STOP_TIMEOUT.as_secs()
                        ))
                    }));
                }
            }
        }

        if session.callback_thread.is_some() {
            match session.callback_done.recv_timeout(CAPTURE_STOP_TIMEOUT) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    if let Some(handle) = session.callback_thread.take() {
                        if handle.join().is_err() && thread_error.is_none() {
                            thread_error = Some(WindowsBackendError::CaptureRuntime(
                                "callback dispatcher thread panicked".into(),
                            ));
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(WindowsBackendError::CaptureRuntime(format!(
                        "callback shutdown exceeded {} seconds",
                        CAPTURE_STOP_TIMEOUT.as_secs()
                    )));
                }
            }
        }

        self.capture = None;
        thread_error.map_or(Ok(()), Err)
    }
}

impl Drop for WindowsInputBackend {
    fn drop(&mut self) {
        let _ = self.stop_observing();
    }
}

#[derive(Debug, Default)]
pub struct WindowsOutputBackend {
    pointer_remainder_x: f64,
    pointer_remainder_y: f64,
    horizontal_wheel_remainder: f64,
    vertical_wheel_remainder: f64,
}

impl WindowsOutputBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pointer_remainder_x: 0.0,
            pointer_remainder_y: 0.0,
            horizontal_wheel_remainder: 0.0,
            vertical_wheel_remainder: 0.0,
        }
    }

    fn inject_payload(&mut self, payload: InputPayload) -> Result<(), WindowsBackendError> {
        if !payload.is_finite() {
            return Err(WindowsBackendError::InvalidInput(
                "pointer and scroll values must be finite",
            ));
        }

        match payload {
            InputPayload::Key { code, state } => {
                let mapping = scan_code(code).ok_or_else(|| {
                    WindowsBackendError::UnsupportedInput(format!(
                        "key {code:?} has no reliable SendInput scan-code mapping"
                    ))
                })?;
                let mut flags = KEYEVENTF_SCANCODE;
                if mapping.extended {
                    flags |= KEYEVENTF_EXTENDEDKEY;
                }
                if key_is_released(state) {
                    flags |= KEYEVENTF_KEYUP;
                }
                send_inputs(&[INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: mapping.code,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: KVM_INJECTION_TAG as usize,
                        },
                    },
                }])
            }
            InputPayload::PointerMove { dx, dy } => {
                let x = take_integral_delta(dx, &mut self.pointer_remainder_x)?;
                let y = take_integral_delta(dy, &mut self.pointer_remainder_y)?;
                if x == 0 && y == 0 {
                    return Ok(());
                }
                send_inputs(&[mouse_input(x, y, 0, MOUSEEVENTF_MOVE)])
            }
            InputPayload::PointerButton { button, state } => {
                let action = mouse_action(button, state).ok_or_else(|| {
                    WindowsBackendError::UnsupportedInput(format!(
                        "pointer button {button:?} is not representable by SendInput"
                    ))
                })?;
                let (flags, data) = match action {
                    MouseAction::LeftDown => (MOUSEEVENTF_LEFTDOWN, 0),
                    MouseAction::LeftUp => (MOUSEEVENTF_LEFTUP, 0),
                    MouseAction::RightDown => (MOUSEEVENTF_RIGHTDOWN, 0),
                    MouseAction::RightUp => (MOUSEEVENTF_RIGHTUP, 0),
                    MouseAction::MiddleDown => (MOUSEEVENTF_MIDDLEDOWN, 0),
                    MouseAction::MiddleUp => (MOUSEEVENTF_MIDDLEUP, 0),
                    MouseAction::XDown(value) => (MOUSEEVENTF_XDOWN, u32::from(value)),
                    MouseAction::XUp(value) => (MOUSEEVENTF_XUP, u32::from(value)),
                };
                send_inputs(&[mouse_input(0, 0, data, flags)])
            }
            InputPayload::Scroll {
                horizontal,
                vertical,
            } => {
                let horizontal = take_integral_delta(
                    horizontal * WHEEL_DELTA,
                    &mut self.horizontal_wheel_remainder,
                )?;
                let vertical = take_integral_delta(
                    vertical * WHEEL_DELTA,
                    &mut self.vertical_wheel_remainder,
                )?;
                let mut inputs = Vec::with_capacity(2);
                if horizontal != 0 {
                    inputs.push(mouse_input(
                        0,
                        0,
                        u32::from_ne_bytes(horizontal.to_ne_bytes()),
                        MOUSEEVENTF_HWHEEL,
                    ));
                }
                if vertical != 0 {
                    inputs.push(mouse_input(
                        0,
                        0,
                        u32::from_ne_bytes(vertical.to_ne_bytes()),
                        MOUSEEVENTF_WHEEL,
                    ));
                }
                if inputs.is_empty() {
                    Ok(())
                } else {
                    send_inputs(&inputs)
                }
            }
        }
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

    /// Enumerates monitors in the current Windows desktop coordinate space.
    ///
    /// # Errors
    ///
    /// Returns an error when monitor enumeration or metadata lookup fails, or
    /// when Windows reports invalid monitor bounds.
    pub fn enumerate_native_displays(&self) -> Result<Vec<Display>, WindowsBackendError> {
        enumerate_monitors(self.host_id)
    }
}

/// Probes non-destructively; it never synthesizes an input event.
#[must_use]
pub fn probe_capabilities() -> WindowsCapabilities {
    let mut diagnostics = Vec::new();
    let device_enumeration = match raw_device_entries() {
        Ok(_) => CapabilityState::Available,
        Err(error) => {
            diagnostics.push(error.to_string());
            CapabilityState::Unavailable
        }
    };
    let display_enumeration = match enumerate_monitors(HostId::from_bytes([0; 16])) {
        Ok(_) => CapabilityState::Available,
        Err(error) => {
            diagnostics.push(error.to_string());
            CapabilityState::Unavailable
        }
    };

    WindowsCapabilities {
        device_enumeration,
        input_injection: CapabilityState::TargetDependent,
        display_enumeration,
        device_aware_capture: if device_enumeration == CapabilityState::Available {
            CapabilityState::Available
        } else {
            CapabilityState::Unavailable
        },
        per_device_suppression: CapabilityState::NotImplemented,
        diagnostics,
    }
}

impl InputCaptureBackend for WindowsInputBackend {
    fn enumerate_devices(&self) -> Result<Vec<InputDevice>, PlatformError> {
        self.enumerate_raw_input_devices()
            .map_err(|error| Box::new(error) as PlatformError)
    }

    fn start_capture(&mut self, callback: CaptureCallback) -> Result<(), PlatformError> {
        self.start_observing(callback)
            .map_err(|error| Box::new(error) as PlatformError)
    }

    fn stop_capture(&mut self) -> Result<(), PlatformError> {
        self.stop_observing()
            .map_err(|error| Box::new(error) as PlatformError)
    }
}

impl OutputInjectionBackend for WindowsOutputBackend {
    fn inject(&mut self, event: &InputEvent) -> Result<(), PlatformError> {
        self.inject_payload(event.payload)
            .map_err(|error| Box::new(error) as PlatformError)
    }
}

impl DisplayBackend for WindowsDisplayBackend {
    fn enumerate_displays(&self) -> Result<Vec<Display>, PlatformError> {
        self.enumerate_native_displays()
            .map_err(|error| Box::new(error) as PlatformError)
    }
}

fn callback_dispatch_loop(
    receiver: &Receiver<CapturedInput>,
    callback: &CaptureCallback,
    counters: &CaptureCounters,
) {
    while let Ok(captured) = receiver.recv() {
        let result = catch_unwind(AssertUnwindSafe(|| callback(captured)));
        match result {
            Ok(CaptureDisposition::SuppressLocal) => {
                counters
                    .suppression_requests_ignored
                    .fetch_add(1, Ordering::Relaxed);
            }
            Ok(CaptureDisposition::AllowLocal) => {}
            Err(_) => {
                counters.callback_panics.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn raw_input_thread(
    host_id: HostId,
    event_sender: &SyncSender<CapturedInput>,
    counters: &CaptureCounters,
    ready_sender: &SyncSender<Result<CaptureReady, WindowsBackendError>>,
    ready_ack_receiver: &Receiver<()>,
    registration_claim: RegistrationClaim,
) -> Result<(), WindowsBackendError> {
    let window = match create_capture_window() {
        Ok(window) => window,
        Err(error) => {
            let _ = ready_sender.send(Err(error));
            return Ok(());
        }
    };
    let mut registration = NativeCaptureRegistration::new(registration_claim, window);
    // Mark first so even an ambiguous partial native failure takes the guarded
    // unregister path before process-global ownership can be released.
    registration.mark_registered();
    if let Err(error) = register_raw_input(window) {
        let _ = ready_sender.send(Err(error));
        return Ok(());
    }
    // SAFETY: `window` is live. Passing no process-ID pointer requests only the
    // ID of the thread that owns the window.
    let thread_id = unsafe { GetWindowThreadProcessId(window, None) };
    if thread_id == 0 {
        let error = last_api_error("GetWindowThreadProcessId(capture)");
        let _ = ready_sender.send(Err(error));
        return registration.cleanup();
    }
    let ready = CaptureReady {
        window: window.0 as isize,
        thread_id,
    };
    if ready_sender.send(Ok(ready)).is_err() {
        let cleanup_result = registration.cleanup();
        cleanup_result?;
        return Err(WindowsBackendError::CaptureRuntime(
            "capture owner disappeared during startup".into(),
        ));
    }
    if ready_ack_receiver
        .recv_timeout(CAPTURE_START_TIMEOUT)
        .is_err()
    {
        let cleanup_result = registration.cleanup();
        cleanup_result?;
        return Err(WindowsBackendError::CaptureRuntime(
            "capture owner did not acknowledge startup".into(),
        ));
    }

    let loop_result = raw_input_message_loop(host_id, event_sender, counters);
    let cleanup_result = registration.cleanup();
    match (loop_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(capture_error), Err(cleanup_error)) => Err(WindowsBackendError::CaptureRuntime(
            format!("{capture_error}; native cleanup also failed: {cleanup_error}"),
        )),
    }
}

fn signal_capture_stop(session: &CaptureSession) -> Result<(), WindowsBackendError> {
    let window = HWND(session.window as *mut c_void);
    // SAFETY: the handle and thread ID were returned by the capture thread after
    // its queue and window were initialized. Posting borrows neither value.
    let window_error =
        match unsafe { PostMessageW(Some(window), CAPTURE_STOP_MESSAGE, WPARAM(0), LPARAM(0)) } {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };

    // SAFETY: `thread_id` owns the capture message queue. WM_QUIT provides a
    // second wake path if the window was concurrently destroyed or invalidated.
    unsafe { PostThreadMessageW(session.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) }.map_err(
        |thread_error| {
            WindowsBackendError::CaptureRuntime(format!(
                "both capture stop signals failed: window={window_error}; thread={thread_error}"
            ))
        },
    )
}

fn create_capture_window() -> Result<HWND, WindowsBackendError> {
    // SAFETY: both class and title are static, null-terminated UTF-16 strings.
    // `STATIC` is a system class, and the message-only parent keeps the window
    // invisible while providing a queue target for `RIDEV_INPUTSINK`.
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("STATIC"),
            w!("Software KVM Raw Input"),
            WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            None,
            None,
        )
    }
    .map_err(|error| binding_error("CreateWindowExW(capture)", &error))
}

fn register_raw_input(window: HWND) -> Result<(), WindowsBackendError> {
    let flags = RIDEV_INPUTSINK | RIDEV_DEVNOTIFY;
    let registrations = [
        RAWINPUTDEVICE {
            usUsagePage: 0x01,
            usUsage: 0x02,
            dwFlags: flags,
            hwndTarget: window,
        },
        RAWINPUTDEVICE {
            usUsagePage: 0x01,
            usUsage: 0x06,
            dwFlags: flags,
            hwndTarget: window,
        },
    ];
    let struct_size =
        u32::try_from(size_of::<RAWINPUTDEVICE>()).expect("RAWINPUTDEVICE always fits in u32");
    // SAFETY: both registration records are initialized and remain alive for
    // the call; `window` is a live message-only window on this thread.
    unsafe { RegisterRawInputDevices(&registrations, struct_size) }
        .map_err(|error| binding_error("RegisterRawInputDevices(capture)", &error))
}

fn unregister_raw_input() -> Result<(), WindowsBackendError> {
    let registrations = [
        RAWINPUTDEVICE {
            usUsagePage: 0x01,
            usUsage: 0x02,
            dwFlags: RIDEV_REMOVE,
            hwndTarget: HWND::default(),
        },
        RAWINPUTDEVICE {
            usUsagePage: 0x01,
            usUsage: 0x06,
            dwFlags: RIDEV_REMOVE,
            hwndTarget: HWND::default(),
        },
    ];
    let struct_size =
        u32::try_from(size_of::<RAWINPUTDEVICE>()).expect("RAWINPUTDEVICE always fits in u32");
    // SAFETY: the records use the documented `RIDEV_REMOVE` form with a null
    // target and remain alive for the duration of the call.
    unsafe { RegisterRawInputDevices(&registrations, struct_size) }
        .map_err(|error| binding_error("RegisterRawInputDevices(remove)", &error))
}

fn raw_input_message_loop(
    host_id: HostId,
    sender: &SyncSender<CapturedInput>,
    counters: &CaptureCounters,
) -> Result<(), WindowsBackendError> {
    let mut devices = build_capture_device_cache();
    let started = Instant::now();
    let mut sequence = 0_u64;
    let mut message = MSG::default();

    loop {
        // SAFETY: `message` is valid writable storage. A null HWND and zero
        // filters request every message for this capture thread.
        let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) };
        if result.0 == -1 {
            return Err(last_api_error("GetMessageW(capture)"));
        }
        if result.0 == 0 || message.message == CAPTURE_STOP_MESSAGE {
            break;
        }

        if message.message == WM_INPUT {
            let origin = current_message_origin();
            let raw_result = read_raw_input(HRAWINPUT(message.lParam.0 as *mut c_void));
            let dispatch_result = if let Ok(raw) = raw_result {
                dispatch_raw_input(
                    &raw,
                    origin,
                    host_id,
                    &mut devices,
                    &started,
                    &mut sequence,
                    sender,
                    counters,
                )
            } else {
                counters
                    .untranslated_packets
                    .fetch_add(1, Ordering::Relaxed);
                Ok(())
            };
            // SAFETY: the message and HWND were returned by `GetMessageW`.
            // Raw Input documentation requires `DefWindowProc` for cleanup.
            let _ = unsafe {
                DefWindowProcW(
                    message.hwnd,
                    message.message,
                    message.wParam,
                    message.lParam,
                )
            };
            dispatch_result?;
            continue;
        }

        if message.message == WM_INPUT_DEVICE_CHANGE {
            devices = build_capture_device_cache();
        }

        // SAFETY: `message` was initialized by `GetMessageW`; dispatch is
        // synchronous and the pointed-to record remains alive for both calls.
        unsafe {
            let _ = TranslateMessage(&raw const message);
            let _ = DispatchMessageW(&raw const message);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn dispatch_raw_input(
    raw: &RAWINPUT,
    origin: MessageOrigin,
    host_id: HostId,
    devices: &mut HashMap<usize, kvm_types::DeviceId>,
    started: &Instant,
    sequence: &mut u64,
    sender: &SyncSender<CapturedInput>,
    counters: &CaptureCounters,
) -> Result<(), WindowsBackendError> {
    let source_device = capture_device_id(raw.header.hDevice, devices);
    let has_device_handle = !raw.header.hDevice.0.is_null();
    let timestamp_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);

    if raw.header.dwType == RIM_TYPEKEYBOARD.0 {
        // SAFETY: `dwType` selects the keyboard arm of the RAWINPUT union.
        let keyboard = unsafe { raw.data.keyboard };
        let classification =
            classify_raw_input(keyboard.ExtraInformation, origin, has_device_handle);
        let Some(payload) = translate_keyboard(RawKeyboardPacket {
            scan_code: keyboard.MakeCode,
            flags: keyboard.Flags,
            virtual_key: keyboard.VKey,
        }) else {
            counters
                .untranslated_packets
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        enqueue_captured(
            payload,
            classification,
            host_id,
            source_device,
            timestamp_ns,
            sequence,
            sender,
            counters,
        )?;
    } else if raw.header.dwType == RIM_TYPEMOUSE.0 {
        // SAFETY: `dwType` selects the mouse arm of the RAWINPUT union.
        let mouse = unsafe { raw.data.mouse };
        // SAFETY: Raw Input documents the button flag/data pair as the active
        // nested union view for ordinary mouse packets.
        let buttons = unsafe { mouse.Anonymous.Anonymous };
        let classification =
            classify_raw_input(mouse.ulExtraInformation, origin, has_device_handle);
        let payloads = translate_mouse(RawMousePacket {
            state_flags: mouse.usFlags.0,
            button_flags: buttons.usButtonFlags,
            button_data: buttons.usButtonData,
            dx: mouse.lLastX,
            dy: mouse.lLastY,
        });
        if payloads.is_empty() {
            counters
                .untranslated_packets
                .fetch_add(1, Ordering::Relaxed);
        }
        for payload in payloads {
            enqueue_captured(
                payload,
                classification,
                host_id,
                source_device,
                timestamp_ns,
                sequence,
                sender,
                counters,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn enqueue_captured(
    payload: InputPayload,
    classification: EventClassification,
    host_id: HostId,
    source_device: kvm_types::DeviceId,
    timestamp_ns: u64,
    sequence: &mut u64,
    sender: &SyncSender<CapturedInput>,
    counters: &CaptureCounters,
) -> Result<(), WindowsBackendError> {
    let event = InputEvent::new(*sequence, timestamp_ns, host_id, source_device, payload);
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        WindowsBackendError::CaptureRuntime("input sequence exhausted u64".into())
    })?;
    counters.captured_events.fetch_add(1, Ordering::Relaxed);
    match sender.try_send(CapturedInput::new(event, classification)) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => {
            counters.dropped_events.fetch_add(1, Ordering::Relaxed);
            if is_state_transition(payload) {
                counters
                    .capture_discontinuities
                    .fetch_add(1, Ordering::Relaxed);
                Err(WindowsBackendError::CaptureRuntime(
                    "capture discontinuity: bounded queue rejected a key/button transition".into(),
                ))
            } else {
                Ok(())
            }
        }
        Err(TrySendError::Disconnected(_)) => Err(WindowsBackendError::CaptureRuntime(
            "callback dispatcher disconnected".into(),
        )),
    }
}

fn current_message_origin() -> MessageOrigin {
    let mut source = INPUT_MESSAGE_SOURCE::default();
    // SAFETY: `source` is writable and this is called immediately after
    // `GetMessageW` returned the current WM_INPUT message on the same thread.
    if unsafe { GetCurrentInputMessageSource(&raw mut source) }.is_err() {
        return MessageOrigin::Unavailable;
    }
    if source.originId == IMO_HARDWARE {
        MessageOrigin::Hardware
    } else if source.originId == IMO_INJECTED {
        MessageOrigin::Injected
    } else if source.originId == IMO_SYSTEM {
        MessageOrigin::System
    } else {
        MessageOrigin::Unavailable
    }
}

fn read_raw_input(handle: HRAWINPUT) -> Result<RAWINPUT, WindowsBackendError> {
    let header_size = u32::try_from(size_of::<windows::Win32::UI::Input::RAWINPUTHEADER>())
        .expect("RAWINPUTHEADER always fits in u32");
    let mut byte_count = 0_u32;
    // SAFETY: this is the documented null-buffer size query; `byte_count` is
    // writable and the HRAWINPUT came directly from WM_INPUT.
    let first =
        unsafe { GetRawInputData(handle, RID_INPUT, None, &raw mut byte_count, header_size) };
    if first == UINT_ERROR {
        return Err(last_api_error("GetRawInputData(size query)"));
    }
    if byte_count < u32::try_from(size_of::<RAWINPUT>()).expect("RAWINPUT always fits in u32") {
        return Err(WindowsBackendError::CaptureRuntime(
            "Raw Input packet was smaller than RAWINPUT".into(),
        ));
    }

    let unit_size = size_of::<RAWINPUT>();
    let units = (byte_count as usize).div_ceil(unit_size);
    let mut storage = vec![MaybeUninit::<RAWINPUT>::uninit(); units];
    // SAFETY: `storage` is correctly aligned and spans at least `byte_count`
    // writable bytes. It is not read until the API reports a complete packet.
    let returned = unsafe {
        GetRawInputData(
            handle,
            RID_INPUT,
            Some(storage.as_mut_ptr().cast::<c_void>()),
            &raw mut byte_count,
            header_size,
        )
    };
    if returned == UINT_ERROR {
        return Err(last_api_error("GetRawInputData"));
    }
    if returned < u32::try_from(size_of::<RAWINPUT>()).expect("RAWINPUT always fits in u32") {
        return Err(WindowsBackendError::CaptureRuntime(
            "GetRawInputData returned a truncated packet".into(),
        ));
    }
    // SAFETY: the API wrote at least one complete RAWINPUT record, verified by
    // `returned`, into storage aligned for RAWINPUT.
    Ok(unsafe { storage[0].assume_init_read() })
}

fn build_capture_device_cache() -> HashMap<usize, kvm_types::DeviceId> {
    let Ok(entries) = raw_device_entries() else {
        return HashMap::new();
    };
    entries
        .into_iter()
        .filter(|entry| entry.dwType == RIM_TYPEKEYBOARD || entry.dwType == RIM_TYPEMOUSE)
        .map(|entry| {
            let key = entry.hDevice.0 as usize;
            let id = capture_device_id(entry.hDevice, &mut HashMap::new());
            (key, id)
        })
        .collect()
}

fn capture_device_id(
    handle: HANDLE,
    devices: &mut HashMap<usize, kvm_types::DeviceId>,
) -> kvm_types::DeviceId {
    if handle.0.is_null() {
        return derive_device_id("synthetic:raw-input-without-device-handle");
    }
    let key = handle.0 as usize;
    if let Some(id) = devices.get(&key) {
        return *id;
    }
    let path = raw_device_name(handle).unwrap_or_default();
    let identity = if path.is_empty() {
        format!("session-handle:raw-input:{:p}", handle.0)
    } else {
        path
    };
    let id = derive_device_id(&identity);
    devices.insert(key, id);
    id
}

fn raw_device_entries() -> Result<Vec<RAWINPUTDEVICELIST>, WindowsBackendError> {
    let element_size = u32::try_from(size_of::<RAWINPUTDEVICELIST>())
        .expect("RAWINPUTDEVICELIST always fits in u32");
    let mut count = 0_u32;
    // SAFETY: the null first-pass buffer is permitted by the Win32 API; count
    // points to valid writable storage and `element_size` matches the binding.
    let first = unsafe { GetRawInputDeviceList(None, &raw mut count, element_size) };
    if first == UINT_ERROR {
        return Err(last_api_error("GetRawInputDeviceList(size query)"));
    }
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut entries = vec![RAWINPUTDEVICELIST::default(); count as usize];
    // SAFETY: `entries` has capacity for `count` initialized records and the
    // API receives the exact ABI element size.
    let returned =
        unsafe { GetRawInputDeviceList(Some(entries.as_mut_ptr()), &raw mut count, element_size) };
    if returned == UINT_ERROR {
        return Err(last_api_error("GetRawInputDeviceList"));
    }
    entries.truncate(returned as usize);
    Ok(entries)
}

fn raw_device_name(device: HANDLE) -> Result<String, WindowsBackendError> {
    let mut characters = 0_u32;
    // SAFETY: this is the documented size-query form; the device handle comes
    // directly from `GetRawInputDeviceList` and `characters` is writable.
    let first =
        unsafe { GetRawInputDeviceInfoW(Some(device), RIDI_DEVICENAME, None, &raw mut characters) };
    if first == UINT_ERROR {
        return Err(last_api_error("GetRawInputDeviceInfoW(name size)"));
    }
    if characters == 0 {
        return Ok(String::new());
    }

    let mut buffer = vec![0_u16; characters as usize + 1];
    // SAFETY: `buffer` is writable for at least `characters` UTF-16 code units
    // and the Win32 API receives its pointer only for this call.
    let returned = unsafe {
        GetRawInputDeviceInfoW(
            Some(device),
            RIDI_DEVICENAME,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            &raw mut characters,
        )
    };
    if returned == UINT_ERROR {
        return Err(last_api_error("GetRawInputDeviceInfoW(name)"));
    }
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..end]))
}

fn raw_device_info(device: HANDLE) -> Result<RID_DEVICE_INFO, WindowsBackendError> {
    let struct_size =
        u32::try_from(size_of::<RID_DEVICE_INFO>()).expect("RID_DEVICE_INFO always fits in u32");
    let mut byte_count = struct_size;
    let mut info = RID_DEVICE_INFO {
        cbSize: struct_size,
        ..RID_DEVICE_INFO::default()
    };
    // SAFETY: `info` is initialized with the required `cbSize`, its storage is
    // writable for `byte_count`, and the handle came from Raw Input.
    let returned = unsafe {
        GetRawInputDeviceInfoW(
            Some(device),
            RIDI_DEVICEINFO,
            Some((&raw mut info).cast::<c_void>()),
            &raw mut byte_count,
        )
    };
    if returned == UINT_ERROR {
        Err(last_api_error("GetRawInputDeviceInfoW(info)"))
    } else {
        Ok(info)
    }
}

fn mouse_input(
    dx: i32,
    dy: i32,
    mouse_data: u32,
    flags: windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS,
) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: mouse_data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: KVM_INJECTION_TAG as usize,
            },
        },
    }
}

fn send_inputs(inputs: &[INPUT]) -> Result<(), WindowsBackendError> {
    let input_size = i32::try_from(size_of::<INPUT>()).expect("INPUT always fits in i32");
    // SAFETY: every record in the slice has the `INPUT` ABI and an initialized
    // union arm matching `r#type`; the slice remains alive for the call.
    let sent = unsafe { SendInput(inputs, input_size) };
    if sent as usize == inputs.len() {
        Ok(())
    } else {
        Err(last_api_error("SendInput (possibly blocked by UIPI)"))
    }
}

#[allow(clippy::cast_possible_truncation)] // Bounds and finiteness are checked immediately above.
fn take_integral_delta(value: f64, remainder: &mut f64) -> Result<i32, WindowsBackendError> {
    let total = value + *remainder;
    if !total.is_finite() || total < f64::from(i32::MIN) || total > f64::from(i32::MAX) {
        return Err(WindowsBackendError::InvalidInput(
            "relative input delta is outside the Windows i32 range",
        ));
    }
    let integral = total.trunc() as i32;
    *remainder = total - f64::from(integral);
    Ok(integral)
}

struct MonitorCollector {
    host_id: HostId,
    displays: Vec<Display>,
    error: Option<WindowsBackendError>,
}

fn enumerate_monitors(host_id: HostId) -> Result<Vec<Display>, WindowsBackendError> {
    let mut collector = MonitorCollector {
        host_id,
        displays: Vec::new(),
        error: None,
    };
    let parameter = LPARAM((&raw mut collector) as isize);
    // SAFETY: `parameter` points to `collector` for the duration of the
    // synchronous enumeration. The callback uses the documented ABI.
    let succeeded = unsafe { EnumDisplayMonitors(None, None, Some(monitor_callback), parameter) };
    if !succeeded.as_bool() {
        return Err(collector
            .error
            .unwrap_or_else(|| last_api_error("EnumDisplayMonitors")));
    }
    Ok(collector.displays)
}

unsafe extern "system" fn monitor_callback(
    monitor: HMONITOR,
    _dc: HDC,
    _bounds: *mut RECT,
    parameter: LPARAM,
) -> BOOL {
    // SAFETY: `parameter` was created from a unique, live `MonitorCollector`
    // immediately before the synchronous `EnumDisplayMonitors` call.
    let collector = unsafe { &mut *(parameter.0 as *mut MonitorCollector) };
    match display_from_monitor(monitor, collector.host_id) {
        Ok(display) => {
            collector.displays.push(display);
            BOOL(1)
        }
        Err(error) => {
            collector.error = Some(error);
            BOOL(0)
        }
    }
}

fn display_from_monitor(
    monitor: HMONITOR,
    host_id: HostId,
) -> Result<Display, WindowsBackendError> {
    let mut info = MONITORINFOEXW::default();
    info.monitorInfo.cbSize =
        u32::try_from(size_of::<MONITORINFOEXW>()).expect("MONITORINFOEXW always fits in u32");
    // SAFETY: `MONITORINFOEXW` starts with a `MONITORINFO` per Win32 ABI, its
    // `cbSize` announces the extended buffer, and `monitor` came from the enum.
    let succeeded = unsafe { GetMonitorInfoW(monitor, (&raw mut info).cast::<MONITORINFO>()) };
    if !succeeded.as_bool() {
        return Err(last_api_error("GetMonitorInfoW"));
    }

    let name_end = info
        .szDevice
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(info.szDevice.len());
    let name = String::from_utf16_lossy(&info.szDevice[..name_end]);
    let bounds = info.monitorInfo.rcMonitor;
    let width = bounds.right - bounds.left;
    let height = bounds.bottom - bounds.top;
    if width <= 0 || height <= 0 {
        return Err(WindowsBackendError::InvalidInput(
            "Windows returned non-positive display bounds",
        ));
    }

    let mut dpi_x = 96_u32;
    let mut dpi_y = 96_u32;
    // SAFETY: both DPI pointers are writable and `monitor` is valid during
    // enumeration. Failure is non-fatal because 96 DPI is Windows' base scale.
    let _ = unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &raw mut dpi_x, &raw mut dpi_y) };
    let scale_factor = (f64::from(dpi_x) + f64::from(dpi_y)) / (2.0 * 96.0);
    let identity = format!("display:{name}");

    Ok(Display {
        id: DisplayId::from_bytes(derive_device_id(&identity).into_bytes()),
        host_id,
        name,
        logical_size: Size::new(f64::from(width), f64::from(height)),
        // GDI monitor bounds are affected by the process DPI-awareness mode;
        // do not claim independent physical dimensions without DisplayConfig.
        physical_size: None,
        scale_factor,
        refresh_rate: None,
        native_bounds: Rect::new(
            f64::from(bounds.left),
            f64::from(bounds.top),
            f64::from(width),
            f64::from(height),
        ),
        primary: info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0,
    })
}

fn last_api_error(operation: &'static str) -> WindowsBackendError {
    WindowsBackendError::WindowsApi {
        operation,
        source: std::io::Error::last_os_error(),
    }
}

fn binding_error(operation: &'static str, error: &windows::core::Error) -> WindowsBackendError {
    WindowsBackendError::WindowsApi {
        operation,
        source: std::io::Error::other(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractional_pointer_delta_is_carried_forward() {
        let mut remainder = 0.0;
        assert_eq!(take_integral_delta(0.6, &mut remainder).unwrap(), 0);
        assert_eq!(take_integral_delta(0.6, &mut remainder).unwrap(), 1);
        assert!((remainder - 0.2).abs() < f64::EPSILON * 2.0);
    }

    #[test]
    fn out_of_range_delta_is_rejected() {
        let mut remainder = 0.0;
        assert!(take_integral_delta(f64::MAX, &mut remainder).is_err());
    }
}
