// Win32 bindings necessarily cross an FFI boundary. Keep the workspace-wide
// unsafe prohibition intact everywhere else and audit each block in this file.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use kvm_daemon::{
    CaptureCallback, CaptureDisposition, CaptureLifecycleState, CapturedInput, DisplayBackend,
    EventClassification, InputCaptureBackend, OutputInjectionBackend, PlatformError,
};
use kvm_input::{ButtonState, InputEvent, InputPayload, KeyState, PointerButton};
use kvm_types::{
    DeviceCapabilities, DeviceId, DeviceKind, Display, DisplayId, HostId, InputDevice, Point, Rect,
    Size,
};
use windows::core::{w, BOOL, GUID, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_Device_Interface_PropertyW, CR_SUCCESS,
};
use windows::Win32::Devices::Properties::{
    DEVPKEY_Device_ContainerId, DEVPROPTYPE, DEVPROP_TYPE_GUID,
};
use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO, MONITORINFOEXW,
};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::HiDpi::{
    GetDpiForMonitor, SetThreadDpiAwarenessContext, DPI_AWARENESS_CONTEXT,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, MDT_EFFECTIVE_DPI,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
    MOUSEEVENTF_MOVE_NOCOALESCE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_WHEEL,
    MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, VIRTUAL_KEY,
};
use windows::Win32::UI::Input::{
    GetCurrentInputMessageSource, GetRawInputData, GetRawInputDeviceInfoW, GetRawInputDeviceList,
    RegisterRawInputDevices, HRAWINPUT, IMO_HARDWARE, IMO_INJECTED, IMO_SYSTEM,
    INPUT_MESSAGE_SOURCE, RAWINPUT, RAWINPUTDEVICE, RAWINPUTDEVICELIST, RAWKEYBOARD, RAWMOUSE,
    RIDEV_DEVNOTIFY, RIDEV_INPUTSINK, RIDEV_REMOVE, RIDI_DEVICEINFO, RIDI_DEVICENAME,
    RID_DEVICE_INFO, RID_INPUT, RIM_TYPEKEYBOARD, RIM_TYPEMOUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetCursorPos,
    GetMessageW, GetWindowThreadProcessId, PeekMessageW, PostMessageW, PostThreadMessageW,
    SetCursorPos, SetWindowsHookExW, ShowCursor, TranslateMessage, UnhookWindowsHookEx, HHOOK,
    HWND_MESSAGE, KBDLLHOOKSTRUCT, LLKHF_EXTENDED, LLKHF_INJECTED, LLKHF_UP, MONITORINFOF_PRIMARY,
    MSG, MSLLHOOKSTRUCT, PM_NOREMOVE, WH_KEYBOARD_LL, WH_MOUSE_LL, WINDOW_EX_STYLE, WINDOW_STYLE,
    WM_APP, WM_INPUT, WM_INPUT_DEVICE_CHANGE, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDBLCLK,
    WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDBLCLK, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEHWHEEL,
    WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_QUIT, WM_RBUTTONDBLCLK, WM_RBUTTONDOWN, WM_RBUTTONUP,
    WM_SYSKEYDOWN, WM_SYSKEYUP, WM_XBUTTONDBLCLK, WM_XBUTTONDOWN, WM_XBUTTONUP,
};

use crate::capture::{
    classify_low_level, classify_raw_input, hooks_can_release_callback_state, is_state_transition,
    translate_keyboard, translate_low_level_keyboard, translate_mouse,
    whole_host_keyboard_device_id, whole_host_pointer_device_id, whole_host_should_suppress,
    MessageOrigin, RawKeyboardPacket, RawMousePacket, LOW_LEVEL_KEY_EXTENDED,
    LOW_LEVEL_KEY_INJECTED, LOW_LEVEL_KEY_UP, LOW_LEVEL_MOUSE_INJECTED,
};
use crate::identity::{container_scoped_raw_input_identity, usb_ids_from_device_path};
use crate::mapping::{key_is_released, mouse_action, scan_code, MouseAction, WHEEL_DELTA};
use crate::ownership::{ClaimError, RegistrationState};
use crate::{
    derive_device_id, CapabilityState, CaptureStatistics, SuppressionScope, WindowsBackendError,
    WindowsCapabilities, WindowsCaptureMode, CAPTURE_QUEUE_CAPACITY, KVM_INJECTION_TAG,
};

const UINT_ERROR: u32 = u32::MAX;
const CAPTURE_STOP_MESSAGE: u32 = WM_APP + 0x4b;
const WHOLE_HOST_STOP_MESSAGE: u32 = WM_APP + 0x4c;
const WHOLE_HOST_HIDE_CURSOR_MESSAGE: u32 = WM_APP + 0x4d;
const WHOLE_HOST_SHOW_CURSOR_MESSAGE: u32 = WM_APP + 0x4e;
const CAPTURE_START_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const WHOLE_HOST_CALLBACK_DEADLINE: Duration = Duration::from_millis(100);
static RAW_INPUT_OWNERSHIP: Mutex<RegistrationState> = Mutex::new(RegistrationState::new());
static WHOLE_HOST_HOOK_STATE: RwLock<Option<Arc<WholeHostCallbackState>>> = RwLock::new(None);
static NEXT_WHOLE_HOST_GENERATION: AtomicU32 = AtomicU32::new(1);

const WHOLE_HOST_IDLE: u8 = 0;
const WHOLE_HOST_RUNNING: u8 = 1;
const WHOLE_HOST_STOPPED: u8 = 2;
const WHOLE_HOST_FAULTED: u8 = 3;

#[derive(Debug, Default)]
struct CaptureCounters {
    captured_events: AtomicU64,
    dropped_events: AtomicU64,
    untranslated_packets: AtomicU64,
    keyboard_packets: AtomicU64,
    mouse_packets: AtomicU64,
    untranslated_keyboard_packets: AtomicU64,
    untranslated_mouse_packets: AtomicU64,
    callback_panics: AtomicU64,
    suppression_requests_ignored: AtomicU64,
    suppressed_events: AtomicU64,
    capture_discontinuities: AtomicU64,
}

impl CaptureCounters {
    fn snapshot(&self) -> CaptureStatistics {
        CaptureStatistics {
            captured_events: self.captured_events.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            untranslated_packets: self.untranslated_packets.load(Ordering::Relaxed),
            keyboard_packets: self.keyboard_packets.load(Ordering::Relaxed),
            mouse_packets: self.mouse_packets.load(Ordering::Relaxed),
            untranslated_keyboard_packets: self
                .untranslated_keyboard_packets
                .load(Ordering::Relaxed),
            untranslated_mouse_packets: self.untranslated_mouse_packets.load(Ordering::Relaxed),
            callback_panics: self.callback_panics.load(Ordering::Relaxed),
            suppression_requests_ignored: self.suppression_requests_ignored.load(Ordering::Relaxed),
            suppressed_events: self.suppressed_events.load(Ordering::Relaxed),
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

struct WholeHostCaptureSession {
    thread_id: u32,
    generation: u32,
    state: Arc<WholeHostCallbackState>,
    hook_thread: Option<JoinHandle<Result<(), WindowsBackendError>>>,
    thread_done: Receiver<()>,
}

impl std::fmt::Debug for WholeHostCaptureSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WholeHostCaptureSession")
            .field("generation", &"[REDACTED]")
            .field("lifecycle", &self.state.lifecycle())
            .field(
                "thread_finished",
                &self
                    .hook_thread
                    .as_ref()
                    .is_none_or(JoinHandle::is_finished),
            )
            .finish_non_exhaustive()
    }
}

struct WholeHostCallbackState {
    active: AtomicBool,
    lifecycle: AtomicU8,
    callback: CaptureCallback,
    counters: Arc<CaptureCounters>,
    host_id: HostId,
    keyboard_device: DeviceId,
    pointer_device: DeviceId,
    started: Instant,
    sequence: AtomicU64,
    key_bits: [AtomicU64; 8],
    button_bits: AtomicU8,
    pointer_initialized: AtomicBool,
    pointer_x: AtomicI32,
    pointer_y: AtomicI32,
}

impl WholeHostCallbackState {
    fn new(host_id: HostId, callback: CaptureCallback, counters: Arc<CaptureCounters>) -> Self {
        Self {
            active: AtomicBool::new(false),
            lifecycle: AtomicU8::new(WHOLE_HOST_IDLE),
            callback,
            counters,
            host_id,
            keyboard_device: whole_host_keyboard_device_id(host_id),
            pointer_device: whole_host_pointer_device_id(host_id),
            started: Instant::now(),
            sequence: AtomicU64::new(1),
            key_bits: std::array::from_fn(|_| AtomicU64::new(0)),
            button_bits: AtomicU8::new(0),
            pointer_initialized: AtomicBool::new(false),
            pointer_x: AtomicI32::new(0),
            pointer_y: AtomicI32::new(0),
        }
    }

    fn activate(&self) {
        self.lifecycle.store(WHOLE_HOST_RUNNING, Ordering::Release);
        self.active.store(true, Ordering::Release);
    }

    fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = self
            .lifecycle
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current != WHOLE_HOST_FAULTED).then_some(WHOLE_HOST_STOPPED)
            });
    }

    fn fault(&self) {
        self.active.store(false, Ordering::Release);
        if self.lifecycle.swap(WHOLE_HOST_FAULTED, Ordering::AcqRel) != WHOLE_HOST_FAULTED {
            self.counters
                .capture_discontinuities
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn lifecycle(&self) -> CaptureLifecycleState {
        match self.lifecycle.load(Ordering::Acquire) {
            WHOLE_HOST_RUNNING => CaptureLifecycleState::Running,
            WHOLE_HOST_STOPPED => CaptureLifecycleState::Stopped,
            WHOLE_HOST_FAULTED => CaptureLifecycleState::Faulted,
            _ => CaptureLifecycleState::Idle,
        }
    }

    fn key_was_held(&self, scan_code: u32, extended: bool, released: bool) -> bool {
        let slot = usize::try_from(scan_code & 0xff).expect("masked scan code fits usize")
            | (usize::from(extended) << 8);
        let word = slot / u64::BITS as usize;
        let mask = 1_u64 << (slot % u64::BITS as usize);
        let previous = if released {
            self.key_bits[word].fetch_and(!mask, Ordering::Relaxed)
        } else {
            self.key_bits[word].fetch_or(mask, Ordering::Relaxed)
        };
        previous & mask != 0
    }

    fn track_button(&self, button: PointerButton, state: ButtonState) {
        let bit = match button {
            PointerButton::Left => 1 << 0,
            PointerButton::Right => 1 << 1,
            PointerButton::Middle => 1 << 2,
            PointerButton::Back => 1 << 3,
            PointerButton::Forward => 1 << 4,
            PointerButton::Other(_) => return,
        };
        match state {
            ButtonState::Pressed => {
                self.button_bits.fetch_or(bit, Ordering::Relaxed);
            }
            ButtonState::Released => {
                self.button_bits.fetch_and(!bit, Ordering::Relaxed);
            }
        }
    }

    fn pointer_delta(&self, x: i32, y: i32) -> Option<InputPayload> {
        let old_x = self.pointer_x.load(Ordering::Relaxed);
        let old_y = self.pointer_y.load(Ordering::Relaxed);
        if !self.pointer_initialized.swap(true, Ordering::Relaxed) {
            self.pointer_x.store(x, Ordering::Relaxed);
            self.pointer_y.store(y, Ordering::Relaxed);
            return None;
        }
        let dx = x.saturating_sub(old_x);
        let dy = y.saturating_sub(old_y);
        if dx == 0 && dy == 0 {
            None
        } else {
            Some(InputPayload::PointerMove {
                dx: f64::from(dx),
                dy: f64::from(dy),
            })
        }
    }

    fn commit_pointer_position(&self, x: i32, y: i32) {
        self.pointer_x.store(x, Ordering::Relaxed);
        self.pointer_y.store(y, Ordering::Relaxed);
        self.pointer_initialized.store(true, Ordering::Release);
    }

    fn seed_pointer(&self, x: i32, y: i32) {
        self.pointer_x.store(x, Ordering::Relaxed);
        self.pointer_y.store(y, Ordering::Relaxed);
        self.pointer_initialized.store(true, Ordering::Release);
    }

    fn dispatch(
        &self,
        payload: InputPayload,
        classification: EventClassification,
        source_device: DeviceId,
        native_pointer_position: Option<Point>,
    ) -> bool {
        let Ok(sequence) =
            self.sequence
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
        else {
            self.fault();
            return false;
        };
        let timestamp_ns = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let pointer_motion = matches!(payload, InputPayload::PointerMove { .. });
        let event = InputEvent::new(sequence, timestamp_ns, self.host_id, source_device, payload);
        self.counters
            .captured_events
            .fetch_add(1, Ordering::Relaxed);
        let callback_started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut captured = CapturedInput::new(event, classification);
            if pointer_motion {
                if let Some(position) = native_pointer_position {
                    captured = captured.with_native_pointer_position(position);
                }
            }
            (self.callback)(captured)
        }));
        let deadline_exceeded = callback_started.elapsed() > WHOLE_HOST_CALLBACK_DEADLINE;
        match result {
            Ok(disposition)
                if self.active.load(Ordering::Acquire)
                    && whole_host_should_suppress(classification, disposition) =>
            {
                self.counters
                    .suppressed_events
                    .fetch_add(1, Ordering::Relaxed);
                if deadline_exceeded {
                    // The exact remote frame is already queued, so this event
                    // remains suppressed to avoid duplicate delivery. Future
                    // input fails open while runtime health drives cleanup.
                    self.fault();
                }
                true
            }
            Ok(_) => {
                if deadline_exceeded {
                    self.fault();
                }
                false
            }
            Err(_) => {
                self.counters
                    .callback_panics
                    .fetch_add(1, Ordering::Relaxed);
                self.fault();
                false
            }
        }
    }
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
    capture_mode: WindowsCaptureMode,
    raw_capture: Option<CaptureSession>,
    whole_host_capture: Option<WholeHostCaptureSession>,
    last_lifecycle: CaptureLifecycleState,
    counters: Arc<CaptureCounters>,
}

impl WindowsInputBackend {
    #[must_use]
    pub fn new(host_id: HostId) -> Self {
        Self {
            host_id,
            capture_mode: WindowsCaptureMode::RawInputObservation,
            raw_capture: None,
            whole_host_capture: None,
            last_lifecycle: CaptureLifecycleState::Idle,
            counters: Arc::new(CaptureCounters::default()),
        }
    }

    /// Creates an explicitly opted-in aggregate low-level-hook backend.
    ///
    /// This mode can suppress all translated physical keyboard and pointer
    /// input. It cannot attribute hook events to individual Raw Input devices.
    #[must_use]
    pub fn new_whole_host_alpha(host_id: HostId) -> Self {
        Self {
            host_id,
            capture_mode: WindowsCaptureMode::WholeHostAlpha,
            raw_capture: None,
            whole_host_capture: None,
            last_lifecycle: CaptureLifecycleState::Idle,
            counters: Arc::new(CaptureCounters::default()),
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

    /// Returns the two aggregate devices emitted by whole-host alpha hooks.
    #[must_use]
    pub fn enumerate_whole_host_alpha_devices(&self) -> Vec<InputDevice> {
        vec![
            InputDevice::new(
                whole_host_keyboard_device_id(self.host_id),
                self.host_id,
                "Whole-host keyboard (alpha)",
                DeviceKind::Keyboard,
                DeviceCapabilities::KEYBOARD,
            ),
            InputDevice::new(
                whole_host_pointer_device_id(self.host_id),
                self.host_id,
                "Whole-host pointer (alpha)",
                DeviceKind::Mouse,
                DeviceCapabilities {
                    pointer: true,
                    keyboard: false,
                    vertical_scroll: true,
                    horizontal_scroll: true,
                    extra_buttons: true,
                },
            ),
        ]
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

        let durable_identity =
            durable_raw_input_identity(&raw_path, entry.dwType.0, entry.hDevice.0);
        let public_name = fallback_label.to_owned();
        let (vendor_id, product_id) = usb_ids_from_device_path(&raw_path);
        let mut device = InputDevice::new(
            derive_device_id(&durable_identity),
            self.host_id,
            public_name,
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
        if self.raw_capture.is_some() || self.whole_host_capture.is_some() {
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
                self.last_lifecycle = CaptureLifecycleState::Running;
                self.raw_capture = Some(CaptureSession {
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
        let Some(session) = self.raw_capture.as_mut() else {
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

        self.raw_capture = None;
        self.last_lifecycle = if thread_error.is_some() {
            CaptureLifecycleState::Faulted
        } else {
            CaptureLifecycleState::Stopped
        };
        thread_error.map_or(Ok(()), Err)
    }

    /// Starts the explicitly opted-in aggregate whole-host alpha hooks.
    ///
    /// The callback executes synchronously on the hook thread. Only translated
    /// physical events may honor `SuppressLocal`; injected, untrusted, unknown,
    /// panicking, and untranslatable paths always remain local.
    ///
    /// # Errors
    ///
    /// Returns an error when another capture is running, another whole-host
    /// owner exists, the hook thread cannot start, or either hook cannot be
    /// installed.
    #[allow(clippy::too_many_lines)] // Startup keeps its affine cancellation branches together.
    pub fn start_whole_host_alpha(
        &mut self,
        callback: CaptureCallback,
    ) -> Result<(), WindowsBackendError> {
        if self.raw_capture.is_some() || self.whole_host_capture.is_some() {
            return Err(WindowsBackendError::CaptureAlreadyRunning);
        }
        let generation = NEXT_WHOLE_HOST_GENERATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                WindowsBackendError::CaptureRuntime(
                    "whole-host capture generation space is exhausted".into(),
                )
            })?;
        let state = Arc::new(WholeHostCallbackState::new(
            self.host_id,
            callback,
            Arc::clone(&self.counters),
        ));

        let (thread_id_sender, thread_id_receiver) = mpsc::sync_channel(1);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (ready_ack_sender, ready_ack_receiver) = mpsc::sync_channel(1);
        let (thread_done_sender, thread_done) = mpsc::sync_channel(1);
        let thread_state = Arc::clone(&state);
        let hook_thread = thread::Builder::new()
            .name("kvm-windows-whole-host-alpha".into())
            .spawn(move || {
                let result = whole_host_hook_thread(
                    generation,
                    &thread_state,
                    &thread_id_sender,
                    &ready_sender,
                    &ready_ack_receiver,
                );
                let _ = thread_done_sender.send(());
                result
            })
            .map_err(|error| {
                WindowsBackendError::CaptureRuntime(format!(
                    "could not spawn whole-host hook thread: {error}"
                ))
            })?;

        let thread_id = match thread_id_receiver.recv_timeout(CAPTURE_START_TIMEOUT) {
            Ok(thread_id) => thread_id,
            Err(RecvTimeoutError::Timeout) => {
                // The hook thread publishes its ID before allocating state or
                // installing either hook. A dropped receiver makes it return.
                drop(hook_thread);
                return Err(WindowsBackendError::CaptureRuntime(format!(
                    "whole-host hook thread startup exceeded {} seconds",
                    CAPTURE_START_TIMEOUT.as_secs()
                )));
            }
            Err(RecvTimeoutError::Disconnected) => {
                let _ = hook_thread.join();
                return Err(WindowsBackendError::CaptureRuntime(
                    "whole-host hook thread ended before publishing its thread ID".into(),
                ));
            }
        };

        match ready_receiver.recv_timeout(CAPTURE_START_TIMEOUT) {
            Ok(Ok(())) => {
                // Publish Running before the native thread is allowed to leave
                // its startup barrier. It can therefore never exit and clear
                // the hooks while the owner subsequently reports Running.
                state.activate();
                if ready_ack_sender.send(()).is_err() {
                    state.fault();
                    let _ = hook_thread.join();
                    return Err(WindowsBackendError::CaptureRuntime(
                        "whole-host hook thread ended before startup acknowledgement".into(),
                    ));
                }
                self.last_lifecycle = CaptureLifecycleState::Running;
                self.whole_host_capture = Some(WholeHostCaptureSession {
                    thread_id,
                    generation,
                    state,
                    hook_thread: Some(hook_thread),
                    thread_done,
                });
                Ok(())
            }
            Ok(Err(error)) => {
                let _ = hook_thread.join();
                Err(error)
            }
            Err(RecvTimeoutError::Timeout) => {
                self.whole_host_capture = Some(WholeHostCaptureSession {
                    thread_id,
                    generation,
                    state,
                    hook_thread: Some(hook_thread),
                    thread_done,
                });
                // Disconnecting the acknowledgement forces any late native
                // install to tear itself down before entering its message loop.
                drop(ready_ack_sender);
                drop(ready_receiver);
                let cleanup = self.stop_whole_host_alpha();
                Err(WindowsBackendError::CaptureRuntime(match cleanup {
                    Ok(()) => format!(
                        "whole-host hook installation exceeded {} seconds and was cancelled",
                        CAPTURE_START_TIMEOUT.as_secs()
                    ),
                    Err(error) => format!(
                        "whole-host hook installation exceeded {} seconds; cancellation: {error}",
                        CAPTURE_START_TIMEOUT.as_secs()
                    ),
                }))
            }
            Err(RecvTimeoutError::Disconnected) => {
                let _ = hook_thread.join();
                Err(WindowsBackendError::CaptureRuntime(
                    "whole-host hook thread ended before startup completed".into(),
                ))
            }
        }
    }

    /// Stops and removes the aggregate whole-host hooks.
    ///
    /// # Errors
    ///
    /// Returns an error when the hook queue cannot be woken, teardown exceeds
    /// the bounded wait, the thread panics, or native unhook fails.
    pub fn stop_whole_host_alpha(&mut self) -> Result<(), WindowsBackendError> {
        let Some(session) = self.whole_host_capture.as_mut() else {
            return Ok(());
        };
        session.state.stop();
        // Queue restoration ahead of stop on the same native message thread.
        // The message loop also restores visibility unconditionally on exit.
        let _ = unsafe {
            PostThreadMessageW(
                session.thread_id,
                WHOLE_HOST_SHOW_CURSOR_MESSAGE,
                WPARAM(session.generation as usize),
                LPARAM(0),
            )
        };
        // A private generation-checked message cannot terminate a replacement
        // or unrelated thread if Windows has already reused the numeric ID.
        let signal_result = unsafe {
            PostThreadMessageW(
                session.thread_id,
                WHOLE_HOST_STOP_MESSAGE,
                WPARAM(session.generation as usize),
                LPARAM(0),
            )
        }
        .map_err(|error| binding_error("PostThreadMessageW(whole-host stop)", &error));

        match session.thread_done.recv_timeout(CAPTURE_STOP_TIMEOUT) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                let join_result = session.hook_thread.take().map(JoinHandle::join);
                let result = match join_result {
                    Some(Ok(result)) => result,
                    Some(Err(_)) => {
                        session.state.fault();
                        Err(WindowsBackendError::CaptureRuntime(
                            "whole-host hook thread panicked".into(),
                        ))
                    }
                    None => Ok(()),
                };
                if result.is_err() {
                    session.state.fault();
                }
                self.last_lifecycle = session.state.lifecycle();
                self.whole_host_capture = None;
                result
            }
            Err(RecvTimeoutError::Timeout) => {
                session.state.fault();
                self.last_lifecycle = CaptureLifecycleState::Faulted;
                Err(signal_result.err().unwrap_or_else(|| {
                    WindowsBackendError::CaptureRuntime(format!(
                        "whole-host hook shutdown exceeded {} seconds",
                        CAPTURE_STOP_TIMEOUT.as_secs()
                    ))
                }))
            }
        }
    }

    fn stop_active_capture(&mut self) -> Result<(), WindowsBackendError> {
        if self.whole_host_capture.is_some() {
            self.stop_whole_host_alpha()
        } else {
            self.stop_observing()
        }
    }

    fn update_cursor_visibility(&mut self, visible: bool) -> Result<(), WindowsBackendError> {
        let Some(session) = self.whole_host_capture.as_ref() else {
            return if visible {
                Ok(())
            } else {
                Err(WindowsBackendError::NotImplemented {
                    feature: "cursor visibility",
                    reason: "requires active whole-host capture",
                })
            };
        };
        let message = if visible {
            WHOLE_HOST_SHOW_CURSOR_MESSAGE
        } else {
            WHOLE_HOST_HIDE_CURSOR_MESSAGE
        };
        // SAFETY: The private message is generation-checked by the exact hook
        // thread and carries no pointer-valued payload.
        unsafe {
            PostThreadMessageW(
                session.thread_id,
                message,
                WPARAM(session.generation as usize),
                LPARAM(0),
            )
        }
        .map_err(|error| binding_error("PostThreadMessageW(cursor visibility)", &error))
    }
}

fn durable_raw_input_identity(
    raw_path: &str,
    device_type: u32,
    native_handle: *mut c_void,
) -> String {
    if raw_path.is_empty() {
        return format!(
            "session-handle:{}:{native_handle:p}",
            raw_input_type_label(device_type)
        );
    }
    if let Some(identity) = device_container_id(raw_path)
        .and_then(|container| container_scoped_raw_input_identity(container, raw_path))
    {
        return identity;
    }
    raw_path.to_owned()
}

fn raw_input_type_label(device_type: u32) -> &'static str {
    if device_type == RIM_TYPEKEYBOARD.0 {
        "keyboard"
    } else if device_type == RIM_TYPEMOUSE.0 {
        "mouse"
    } else {
        "other"
    }
}

fn device_container_id(raw_path: &str) -> Option<u128> {
    let wide_path = raw_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut property_type = DEVPROPTYPE::default();
    let mut container = GUID::zeroed();
    let property_key = DEVPKEY_Device_ContainerId;
    let mut byte_count =
        u32::try_from(size_of::<GUID>()).expect("a Windows GUID always fits in u32");
    // SAFETY: the path is null-terminated UTF-16, every output pointer refers
    // to initialized writable storage of the advertised size, and no buffer is
    // retained by Configuration Manager.
    let result = unsafe {
        CM_Get_Device_Interface_PropertyW(
            PCWSTR(wide_path.as_ptr()),
            &raw const property_key,
            &raw mut property_type,
            Some((&raw mut container).cast::<u8>()),
            &raw mut byte_count,
            0,
        )
    };
    (result == CR_SUCCESS
        && property_type == DEVPROP_TYPE_GUID
        && byte_count as usize == size_of::<GUID>()
        && container != GUID::zeroed())
    .then(|| container.to_u128())
}

impl Drop for WindowsInputBackend {
    fn drop(&mut self) {
        let _ = self.stop_active_capture();
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
                send_inputs(&[mouse_input(
                    x,
                    y,
                    0,
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_MOVE_NOCOALESCE,
                )])
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
        suppression_scope: SuppressionScope::WholeHostAlpha,
        diagnostics,
    }
}

impl InputCaptureBackend for WindowsInputBackend {
    fn enumerate_devices(&self) -> Result<Vec<InputDevice>, PlatformError> {
        match self.capture_mode {
            WindowsCaptureMode::RawInputObservation => self
                .enumerate_raw_input_devices()
                .map_err(|error| Box::new(error) as PlatformError),
            WindowsCaptureMode::WholeHostAlpha => Ok(self.enumerate_whole_host_alpha_devices()),
        }
    }

    fn start_capture(&mut self, callback: CaptureCallback) -> Result<(), PlatformError> {
        match self.capture_mode {
            WindowsCaptureMode::RawInputObservation => self.start_observing(callback),
            WindowsCaptureMode::WholeHostAlpha => self.start_whole_host_alpha(callback),
        }
        .map_err(|error| Box::new(error) as PlatformError)
    }

    fn stop_capture(&mut self) -> Result<(), PlatformError> {
        self.stop_active_capture()
            .map_err(|error| Box::new(error) as PlatformError)
    }

    fn capture_lifecycle(&self) -> CaptureLifecycleState {
        match self.capture_mode {
            WindowsCaptureMode::RawInputObservation => {
                if let Some(session) = self.raw_capture.as_ref() {
                    let message_ended = session
                        .message_thread
                        .as_ref()
                        .is_none_or(JoinHandle::is_finished);
                    let callback_ended = session
                        .callback_thread
                        .as_ref()
                        .is_none_or(JoinHandle::is_finished);
                    if message_ended || callback_ended {
                        CaptureLifecycleState::Faulted
                    } else {
                        CaptureLifecycleState::Running
                    }
                } else {
                    self.last_lifecycle
                }
            }
            WindowsCaptureMode::WholeHostAlpha => {
                if let Some(session) = self.whole_host_capture.as_ref() {
                    if session
                        .hook_thread
                        .as_ref()
                        .is_none_or(JoinHandle::is_finished)
                        && session.state.lifecycle() == CaptureLifecycleState::Running
                    {
                        session.state.fault();
                    }
                    session.state.lifecycle()
                } else {
                    self.last_lifecycle
                }
            }
        }
    }

    fn set_cursor_visible(&mut self, visible: bool) -> Result<(), PlatformError> {
        self.update_cursor_visibility(visible)
            .map_err(|error| Box::new(error) as PlatformError)
    }

    fn set_cursor_position(&mut self, position: Point) -> Result<(), PlatformError> {
        if !position.x.is_finite()
            || !position.y.is_finite()
            || position.x < f64::from(i32::MIN)
            || position.x > f64::from(i32::MAX)
            || position.y < f64::from(i32::MIN)
            || position.y > f64::from(i32::MAX)
        {
            return Err(Box::new(WindowsBackendError::InvalidInput(
                "cursor position is outside the Windows coordinate range",
            )) as PlatformError);
        }
        #[allow(clippy::cast_possible_truncation)]
        let (x, y) = (position.x.round() as i32, position.y.round() as i32);
        unsafe { SetCursorPos(x, y) }
            .map_err(|error| Box::new(binding_error("SetCursorPos", &error)) as PlatformError)
    }

    fn cursor_position(&self) -> Result<Option<Point>, PlatformError> {
        let mut position = POINT::default();
        unsafe { GetCursorPos(&raw mut position) }
            .map_err(|error| Box::new(binding_error("GetCursorPos", &error)) as PlatformError)?;
        Ok(Some(Point::new(
            f64::from(position.x),
            f64::from(position.y),
        )))
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

fn whole_host_state_snapshot() -> Option<Arc<WholeHostCallbackState>> {
    WHOLE_HOST_HOOK_STATE
        .try_read()
        .ok()
        .and_then(|slot| slot.as_ref().map(Arc::clone))
}

fn claim_whole_host_state(state: &Arc<WholeHostCallbackState>) -> Result<(), WindowsBackendError> {
    let mut slot = WHOLE_HOST_HOOK_STATE
        .try_write()
        .map_err(|_| WindowsBackendError::WholeHostCaptureOwned)?;
    if slot.is_some() {
        return Err(WindowsBackendError::WholeHostCaptureOwned);
    }
    *slot = Some(Arc::clone(state));
    Ok(())
}

fn release_whole_host_state(state: &Arc<WholeHostCallbackState>) {
    let mut slot = WHOLE_HOST_HOOK_STATE
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if slot
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, state))
    {
        *slot = None;
    }
}

unsafe extern "system" fn low_level_keyboard_hook(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if code != 0 {
        // SAFETY: forwarding the unmodified hook arguments is required for all
        // non-action hook notifications.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    let Some(state) = whole_host_state_snapshot() else {
        // SAFETY: there is no active owner; forwarding is the fail-open path.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    };
    if !state.active.load(Ordering::Acquire) {
        // SAFETY: inactive teardown state must never suppress local input.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    // SAFETY: Windows supplies a live KBDLLHOOKSTRUCT for HC_ACTION callbacks.
    let record = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
    let native_flags = record.flags.0;
    let flags = (u32::from(record.flags.contains(LLKHF_EXTENDED)) * LOW_LEVEL_KEY_EXTENDED)
        | (u32::from(record.flags.contains(LLKHF_INJECTED)) * LOW_LEVEL_KEY_INJECTED)
        | (u32::from(record.flags.contains(LLKHF_UP)) * LOW_LEVEL_KEY_UP);
    let classification =
        classify_low_level(record.dwExtraInfo, native_flags, LOW_LEVEL_KEY_INJECTED);
    let released = matches!(u32::try_from(wparam.0), Ok(WM_KEYUP | WM_SYSKEYUP))
        || flags & LOW_LEVEL_KEY_UP != 0;
    let pressed = matches!(u32::try_from(wparam.0), Ok(WM_KEYDOWN | WM_SYSKEYDOWN));
    if !released && !pressed {
        // SAFETY: unknown keyboard messages are explicitly fail-open.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }

    let initial = translate_low_level_keyboard(record.scanCode, record.vkCode, flags, false);
    let Some(mut payload) = initial else {
        state
            .counters
            .untranslated_packets
            .fetch_add(1, Ordering::Relaxed);
        state
            .counters
            .untranslated_keyboard_packets
            .fetch_add(1, Ordering::Relaxed);
        // SAFETY: untranslatable input remains local.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    };
    state
        .counters
        .keyboard_packets
        .fetch_add(1, Ordering::Relaxed);
    if classification == EventClassification::Physical {
        let was_held = state.key_was_held(
            record.scanCode,
            flags & LOW_LEVEL_KEY_EXTENDED != 0,
            released,
        );
        if !released && was_held {
            if let InputPayload::Key { code, .. } = payload {
                payload = InputPayload::Key {
                    code,
                    state: KeyState::Repeated,
                };
            }
        }
    }
    if state.dispatch(payload, classification, state.keyboard_device, None) {
        LRESULT(1)
    } else {
        // SAFETY: forwarding is required whenever the callback did not
        // synchronously suppress a proven physical event.
        unsafe { CallNextHookEx(None, code, wparam, lparam) }
    }
}

unsafe extern "system" fn low_level_mouse_hook(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if code != 0 {
        // SAFETY: forwarding the unmodified non-action notification.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    let Some(state) = whole_host_state_snapshot() else {
        // SAFETY: no owner means fail open.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    };
    if !state.active.load(Ordering::Acquire) {
        // SAFETY: teardown is always fail open.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    // SAFETY: Windows supplies a live MSLLHOOKSTRUCT for HC_ACTION callbacks.
    let record = unsafe { &*(lparam.0 as *const MSLLHOOKSTRUCT) };
    let classification =
        classify_low_level(record.dwExtraInfo, record.flags, LOW_LEVEL_MOUSE_INJECTED);
    let Ok(message) = u32::try_from(wparam.0) else {
        // SAFETY: an out-of-range message value is unknown and fail-open.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    };
    let payload = match message {
        WM_MOUSEMOVE => state.pointer_delta(record.pt.x, record.pt.y),
        WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => Some(InputPayload::PointerButton {
            button: PointerButton::Left,
            state: ButtonState::Pressed,
        }),
        WM_LBUTTONUP => Some(InputPayload::PointerButton {
            button: PointerButton::Left,
            state: ButtonState::Released,
        }),
        WM_RBUTTONDOWN | WM_RBUTTONDBLCLK => Some(InputPayload::PointerButton {
            button: PointerButton::Right,
            state: ButtonState::Pressed,
        }),
        WM_RBUTTONUP => Some(InputPayload::PointerButton {
            button: PointerButton::Right,
            state: ButtonState::Released,
        }),
        WM_MBUTTONDOWN | WM_MBUTTONDBLCLK => Some(InputPayload::PointerButton {
            button: PointerButton::Middle,
            state: ButtonState::Pressed,
        }),
        WM_MBUTTONUP => Some(InputPayload::PointerButton {
            button: PointerButton::Middle,
            state: ButtonState::Released,
        }),
        WM_XBUTTONDOWN | WM_XBUTTONDBLCLK => low_level_x_button(record, ButtonState::Pressed),
        WM_XBUTTONUP => low_level_x_button(record, ButtonState::Released),
        WM_MOUSEWHEEL => Some(low_level_wheel(record.mouseData, false)),
        WM_MOUSEHWHEEL => Some(low_level_wheel(record.mouseData, true)),
        _ => None,
    };
    let Some(payload) = payload else {
        if message != WM_MOUSEMOVE {
            state
                .counters
                .untranslated_packets
                .fetch_add(1, Ordering::Relaxed);
            state
                .counters
                .untranslated_mouse_packets
                .fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: first/zero motion and unknown mouse messages remain local.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    };
    state.counters.mouse_packets.fetch_add(1, Ordering::Relaxed);
    if classification == EventClassification::Physical {
        if let InputPayload::PointerButton {
            button,
            state: value,
        } = payload
        {
            state.track_button(button, value);
        }
    }
    let suppressed = state.dispatch(
        payload,
        classification,
        state.pointer_device,
        Some(Point::new(f64::from(record.pt.x), f64::from(record.pt.y))),
    );
    if message == WM_MOUSEMOVE && !suppressed {
        // A suppressed low-level movement never advances the Windows cursor.
        // Keep the baseline at the last OS-applied position so successive
        // physical packets continue producing relative movement remotely.
        state.commit_pointer_position(record.pt.x, record.pt.y);
    }
    if suppressed {
        LRESULT(1)
    } else {
        // SAFETY: all non-suppressed paths must remain in the local hook chain.
        unsafe { CallNextHookEx(None, code, wparam, lparam) }
    }
}

fn low_level_x_button(record: &MSLLHOOKSTRUCT, state: ButtonState) -> Option<InputPayload> {
    let button = match (record.mouseData >> 16) as u16 {
        1 => PointerButton::Back,
        2 => PointerButton::Forward,
        _ => return None,
    };
    Some(InputPayload::PointerButton { button, state })
}

fn low_level_wheel(mouse_data: u32, horizontal: bool) -> InputPayload {
    let raw = (mouse_data >> 16) as u16;
    let delta = f64::from(i16::from_ne_bytes(raw.to_ne_bytes())) / WHEEL_DELTA;
    if horizontal {
        InputPayload::Scroll {
            horizontal: delta,
            vertical: 0.0,
        }
    } else {
        InputPayload::Scroll {
            horizontal: 0.0,
            vertical: delta,
        }
    }
}

fn whole_host_hook_thread(
    generation: u32,
    state: &Arc<WholeHostCallbackState>,
    thread_id_sender: &SyncSender<u32>,
    ready_sender: &SyncSender<Result<(), WindowsBackendError>>,
    ready_ack_receiver: &Receiver<()>,
) -> Result<(), WindowsBackendError> {
    let mut message = MSG::default();
    // SAFETY: a benign peek creates the hook thread's message queue before its
    // ID is published to the owner for PostThreadMessageW shutdown.
    let _ = unsafe { PeekMessageW(&raw mut message, None, 0, 0, PM_NOREMOVE) };
    let thread_id = unsafe { GetCurrentThreadId() };
    if thread_id_sender.send(thread_id).is_err() {
        return Ok(());
    }

    if let Err(error) = claim_whole_host_state(state) {
        let _ = ready_sender.send(Err(error));
        return Ok(());
    }
    // SAFETY: low-level global hooks execute these callbacks on this installing
    // thread; no DLL module handle is required for WH_*_LL callbacks.
    let keyboard_hook = match unsafe {
        SetWindowsHookExW(WH_KEYBOARD_LL, Some(low_level_keyboard_hook), None, 0)
    } {
        Ok(hook) => hook,
        Err(error) => {
            release_whole_host_state(state);
            let _ = ready_sender.send(Err(binding_error(
                "SetWindowsHookExW(WH_KEYBOARD_LL)",
                &error,
            )));
            return Ok(());
        }
    };
    // SAFETY: same lifetime/thread contract as the keyboard hook above.
    let mouse_hook = match unsafe {
        SetWindowsHookExW(WH_MOUSE_LL, Some(low_level_mouse_hook), None, 0)
    } {
        Ok(hook) => hook,
        Err(error) => {
            state.stop();
            // SAFETY: this thread owns the successfully installed hook.
            let removed = unsafe { UnhookWindowsHookEx(keyboard_hook) };
            if removed.is_ok() {
                release_whole_host_state(state);
            } else {
                state.fault();
            }
            let _ = ready_sender.send(Err(binding_error("SetWindowsHookExW(WH_MOUSE_LL)", &error)));
            return Ok(());
        }
    };

    let mut pointer = POINT::default();
    // SAFETY: `pointer` is writable and the query retains no pointer.
    if let Err(error) = unsafe { GetCursorPos(&raw mut pointer) } {
        state.fault();
        let cleanup = remove_whole_host_hooks(keyboard_hook, mouse_hook, state);
        let startup = binding_error("GetCursorPos(whole-host baseline)", &error);
        let combined = match cleanup {
            Ok(()) => startup,
            Err(cleanup) => WindowsBackendError::CaptureRuntime(format!(
                "{startup}; native hook cleanup also failed: {cleanup}"
            )),
        };
        let _ = ready_sender.send(Err(combined));
        return Ok(());
    }
    state.seed_pointer(pointer.x, pointer.y);

    if ready_sender.send(Ok(())).is_err()
        || ready_ack_receiver
            .recv_timeout(CAPTURE_START_TIMEOUT)
            .is_err()
    {
        state.stop();
        return remove_whole_host_hooks(keyboard_hook, mouse_hook, state).and_then(|()| {
            Err(WindowsBackendError::CaptureRuntime(
                "whole-host capture owner did not acknowledge startup".into(),
            ))
        });
    }

    let loop_result = whole_host_message_loop(generation);
    if state.lifecycle() == CaptureLifecycleState::Running {
        state.fault();
    }
    let cleanup_result = remove_whole_host_hooks(keyboard_hook, mouse_hook, state);
    match (loop_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(loop_error), Err(cleanup_error)) => Err(WindowsBackendError::CaptureRuntime(format!(
            "{loop_error}; native hook cleanup also failed: {cleanup_error}"
        ))),
    }
}

fn whole_host_message_loop(generation: u32) -> Result<(), WindowsBackendError> {
    let mut message = MSG::default();
    let mut cursor_hide_adjustments = 0_u32;
    let result = loop {
        // SAFETY: message is writable and this thread owns the hook queue.
        let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) };
        if result.0 == -1 {
            break Err(last_api_error("GetMessageW(whole-host hooks)"));
        }
        if result.0 == 0 {
            break Ok(());
        }
        if message.message == WHOLE_HOST_STOP_MESSAGE && message.wParam.0 == generation as usize {
            break Ok(());
        }
        if message.wParam.0 == generation as usize {
            if message.message == WHOLE_HOST_HIDE_CURSOR_MESSAGE {
                hide_thread_cursor(&mut cursor_hide_adjustments);
                continue;
            }
            if message.message == WHOLE_HOST_SHOW_CURSOR_MESSAGE {
                show_thread_cursor(&mut cursor_hide_adjustments);
                continue;
            }
        }
        // SAFETY: initialized message remains alive for synchronous dispatch.
        unsafe {
            let _ = TranslateMessage(&raw const message);
            let _ = DispatchMessageW(&raw const message);
        }
    };
    show_thread_cursor(&mut cursor_hide_adjustments);
    result
}

fn hide_thread_cursor(adjustments: &mut u32) {
    if *adjustments != 0 {
        return;
    }
    // SAFETY: The hook thread owns this input queue. Decrement until Windows
    // reports the cursor hidden, remembering the exact balancing call count.
    loop {
        *adjustments = adjustments.saturating_add(1);
        if unsafe { ShowCursor(false) } < 0 {
            break;
        }
    }
}

fn show_thread_cursor(adjustments: &mut u32) {
    for _ in 0..*adjustments {
        // SAFETY: Each call balances one successful hide adjustment made on
        // this same native input thread.
        let _ = unsafe { ShowCursor(true) };
    }
    *adjustments = 0;
}

fn remove_whole_host_hooks(
    keyboard_hook: HHOOK,
    mouse_hook: HHOOK,
    state: &Arc<WholeHostCallbackState>,
) -> Result<(), WindowsBackendError> {
    state.active.store(false, Ordering::Release);
    // SAFETY: both handles were installed and are owned by this hook thread.
    let mouse_result = unsafe { UnhookWindowsHookEx(mouse_hook) };
    // SAFETY: same ownership guarantee for the keyboard handle.
    let keyboard_result = unsafe { UnhookWindowsHookEx(keyboard_hook) };
    if hooks_can_release_callback_state(keyboard_result.is_ok(), mouse_result.is_ok()) {
        release_whole_host_state(state);
        Ok(())
    } else {
        state.fault();
        // State deliberately remains allocated, inactive, and globally owned.
        // A replacement could otherwise race an orphaned callback.
        Err(WindowsBackendError::CaptureRuntime(format!(
            "low-level hook removal failed: keyboard={keyboard_result:?}, mouse={mouse_result:?}"
        )))
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
    let source_device = capture_device_id(raw.header.hDevice, raw.header.dwType, devices);
    let has_device_handle = !raw.header.hDevice.0.is_null();
    let timestamp_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);

    if raw.header.dwType == RIM_TYPEKEYBOARD.0 {
        counters.keyboard_packets.fetch_add(1, Ordering::Relaxed);
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
            counters
                .untranslated_keyboard_packets
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
        counters.mouse_packets.fetch_add(1, Ordering::Relaxed);
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
            counters
                .untranslated_mouse_packets
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
    let native_header_size = size_of::<windows::Win32::UI::Input::RAWINPUTHEADER>();
    let header_size = u32::try_from(native_header_size).expect("RAWINPUTHEADER always fits in u32");
    let mut byte_count = 0_u32;
    // SAFETY: this is the documented null-buffer size query; `byte_count` is
    // writable and the HRAWINPUT came directly from WM_INPUT.
    let first =
        unsafe { GetRawInputData(handle, RID_INPUT, None, &raw mut byte_count, header_size) };
    if first == UINT_ERROR {
        return Err(last_api_error("GetRawInputData(size query)"));
    }
    if byte_count < header_size {
        return Err(WindowsBackendError::CaptureRuntime(
            "Raw Input packet was smaller than RAWINPUTHEADER".into(),
        ));
    }

    let unit_size = size_of::<RAWINPUT>();
    let units = (byte_count as usize).div_ceil(unit_size);
    // Keyboard packets can be smaller than the largest RAWINPUT union member.
    // Zero-initialize the aligned tail so returning the fixed Rust binding is
    // sound after Windows writes only the active packet variant.
    let mut storage = (0..units).map(|_| RAWINPUT::default()).collect::<Vec<_>>();
    // SAFETY: `storage` is correctly aligned and spans at least `byte_count`
    // writable bytes.
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
    if returned < header_size {
        return Err(WindowsBackendError::CaptureRuntime(
            "GetRawInputData returned a truncated Raw Input header".into(),
        ));
    }
    let raw = storage
        .into_iter()
        .next()
        .expect("a non-empty Raw Input packet allocates at least one unit");
    let required = minimum_raw_input_size(raw.header.dwType);
    if (returned as usize) < required || (raw.header.dwSize as usize) < required {
        return Err(WindowsBackendError::CaptureRuntime(
            "GetRawInputData returned a truncated typed packet".into(),
        ));
    }
    Ok(raw)
}

fn minimum_raw_input_size(device_type: u32) -> usize {
    let header = size_of::<windows::Win32::UI::Input::RAWINPUTHEADER>();
    if device_type == RIM_TYPEKEYBOARD.0 {
        header + size_of::<RAWKEYBOARD>()
    } else if device_type == RIM_TYPEMOUSE.0 {
        header + size_of::<RAWMOUSE>()
    } else {
        header
    }
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
            let id = capture_device_id(entry.hDevice, entry.dwType.0, &mut HashMap::new());
            (key, id)
        })
        .collect()
}

fn capture_device_id(
    handle: HANDLE,
    device_type: u32,
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
    let identity = durable_raw_input_identity(&path, device_type, handle.0);
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
    // F-30: device-interface paths are short (a few hundred UTF-16 units). The
    // size query returns a hostile `u32` directly from the Win32 API, so cap it
    // before allocating — this bounds the worst case to ~2 KiB instead of a
    // near-`u32::MAX` (~8 GiB on 64-bit) allocation, and removes the unguarded
    // `+ 1` overflow on 32-bit targets. A path this long is malformed anyway.
    const MAX_DEVICE_NAME_CHARS: u32 = 1024;
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
    if characters > MAX_DEVICE_NAME_CHARS {
        return Err(WindowsBackendError::CaptureRuntime(format!(
            "GetRawInputDeviceInfoW reported a {characters}-char device name, \
             exceeding the {MAX_DEVICE_NAME_CHARS}-char sanity cap"
        )));
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

struct ThreadDpiAwarenessGuard {
    previous: DPI_AWARENESS_CONTEXT,
}

impl ThreadDpiAwarenessGuard {
    fn enter_per_monitor_v2() -> Result<Self, WindowsBackendError> {
        // SAFETY: this changes only the calling thread's DPI context and the
        // returned prior context is restored by Drop on every exit path.
        let previous =
            unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        if previous.0.is_null() {
            Err(last_api_error("SetThreadDpiAwarenessContext(enumeration)"))
        } else {
            Ok(Self { previous })
        }
    }
}

impl Drop for ThreadDpiAwarenessGuard {
    fn drop(&mut self) {
        // SAFETY: `previous` was returned by the successful context change in
        // `enter_per_monitor_v2` and belongs to this same thread.
        let _ = unsafe { SetThreadDpiAwarenessContext(self.previous) };
    }
}

fn enumerate_monitors(host_id: HostId) -> Result<Vec<Display>, WindowsBackendError> {
    let _dpi_awareness = ThreadDpiAwarenessGuard::enter_per_monitor_v2()?;
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
    let width = bounds.right.saturating_sub(bounds.left);
    let height = bounds.bottom.saturating_sub(bounds.top);
    if width <= 0 || height <= 0 {
        return Err(WindowsBackendError::InvalidInput(
            "Windows returned non-positive display bounds",
        ));
    }

    let mut dpi_x = 0_u32;
    let mut dpi_y = 0_u32;
    // SAFETY: both DPI pointers are writable, `monitor` is valid during
    // enumeration, and the caller established a per-monitor-aware context.
    unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &raw mut dpi_x, &raw mut dpi_y) }
        .map_err(|error| binding_error("GetDpiForMonitor", &error))?;
    if dpi_x == 0 || dpi_y == 0 {
        return Err(WindowsBackendError::InvalidInput(
            "Windows returned zero effective display DPI",
        ));
    }
    let scale_factor = (f64::from(dpi_x) + f64::from(dpi_y)) / (2.0 * 96.0);
    let physical_width = f64::from(width);
    let physical_height = f64::from(height);
    let identity = format!("display:{name}");

    Ok(Display {
        id: DisplayId::from_bytes(derive_device_id(&identity).into_bytes()),
        host_id,
        name,
        logical_size: Size::new(
            physical_width / scale_factor,
            physical_height / scale_factor,
        ),
        physical_size: Some(Size::new(physical_width, physical_height)),
        scale_factor,
        refresh_rate: None,
        // Per-monitor-v2 Win32 virtual-screen coordinates are physical pixels.
        // They preserve the real adjacency of mixed-DPI displays; logical size
        // remains available separately for normalized workspace mapping.
        native_bounds: Rect::new(
            f64::from(bounds.left),
            f64::from(bounds.top),
            physical_width,
            physical_height,
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
    fn suppressed_pointer_motion_keeps_the_os_applied_baseline() {
        let state = WholeHostCallbackState::new(
            HostId::from_bytes([1; 16]),
            Arc::new(|_| CaptureDisposition::SuppressLocal),
            Arc::new(CaptureCounters::default()),
        );
        state.seed_pointer(100, 100);

        assert_eq!(
            state.pointer_delta(105, 100),
            Some(InputPayload::PointerMove { dx: 5.0, dy: 0.0 })
        );
        assert_eq!(
            state.pointer_delta(105, 100),
            Some(InputPayload::PointerMove { dx: 5.0, dy: 0.0 })
        );

        state.commit_pointer_position(105, 100);
        assert_eq!(state.pointer_delta(105, 100), None);
    }

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

    #[test]
    fn missing_raw_input_path_uses_type_specific_session_identity() {
        let handle = 42_usize as *mut c_void;
        let keyboard = durable_raw_input_identity("", RIM_TYPEKEYBOARD.0, handle);
        let mouse = durable_raw_input_identity("", RIM_TYPEMOUSE.0, handle);

        assert!(keyboard.starts_with("session-handle:keyboard:"));
        assert!(mouse.starts_with("session-handle:mouse:"));
        assert_ne!(keyboard, mouse);
    }

    #[test]
    fn keyboard_packet_size_is_validated_against_its_active_variant() {
        let keyboard_size = minimum_raw_input_size(RIM_TYPEKEYBOARD.0);

        assert!(keyboard_size < size_of::<RAWINPUT>());
        assert_eq!(
            keyboard_size,
            size_of::<windows::Win32::UI::Input::RAWINPUTHEADER>() + size_of::<RAWKEYBOARD>()
        );
    }

    #[test]
    fn physical_pixels_convert_to_logical_size_at_recommended_scale() {
        let scale = 144.0 / 96.0;

        assert!((3840.0 / scale - 2560.0_f64).abs() < f64::EPSILON);
        assert!((2160.0 / scale - 1440.0_f64).abs() < f64::EPSILON);
    }
}
