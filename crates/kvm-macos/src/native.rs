use std::collections::{BTreeSet, HashMap};
use std::ffi::{c_char, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use kvm_daemon::{
    CaptureCallback, CaptureDisposition, CaptureLifecycleState, CapturedInput, DisplayBackend,
    EventClassification, InputCaptureBackend, OutputInjectionBackend, PlatformError,
};
use kvm_input::{ButtonState, InputEvent, InputPayload, PointerButton};
use kvm_types::{
    DeviceCapabilities, DeviceId, DeviceKind, Display, DisplayId, HostId, InputDevice, Point, Rect,
    Size,
};

use crate::{
    capture::{
        classify_iohid_observation, classify_quartz_capture, device_accepts_hid_value,
        mach_timestamp_ns, overflow_may_drop, physical_device_evidence, quartz_key_is_down,
        quartz_modifier_pressed, translate_hid_value, translate_quartz_keyboard,
        translate_quartz_pointer, translate_quartz_scroll, CG_EVENT_FLAGS_CHANGED,
        CG_EVENT_KEY_DOWN, CG_EVENT_KEY_UP, CG_EVENT_SCROLL_WHEEL,
        CG_EVENT_TAP_DISABLED_BY_TIMEOUT, CG_EVENT_TAP_DISABLED_BY_USER_INPUT,
    },
    derive_device_id,
    identity::{derive_whole_host_device_id, WholeHostDeviceKind},
    mac_virtual_key, CaptureHealth, CaptureStatistics, DeviceIdentityMaterial, MacBackendError,
    MacCaptureMode, PermissionStatus, SuppressionScope, KVM_EVENT_TAG,
};

type CFIndex = isize;
type CFTypeId = usize;
type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFSetRef = *const c_void;
type IOHIDManagerRef = *mut c_void;
type IOHIDDeviceRef = *mut c_void;
type IOHIDElementRef = *mut c_void;
type IOHIDValueRef = *mut c_void;
type CFRunLoopRef = *mut c_void;
type CFRunLoopSourceRef = *mut c_void;
type CFMachPortRef = *mut c_void;
type CGEventRef = *mut c_void;
type CGEventTapProxy = *mut c_void;
type CGDisplayModeRef = *const c_void;

const UTF8_ENCODING: u32 = 0x0800_0100;
const NUMBER_SINT64_TYPE: i32 = 4;
const IO_OPTION_NONE: u32 = 0;
const CG_ERROR_SUCCESS: i32 = 0;
const CG_HID_EVENT_TAP: u32 = 0;
const CG_EVENT_SOURCE_USER_DATA: u32 = 42;
const CG_SCROLL_EVENT_UNIT_PIXEL: u32 = 0;
const CG_SESSION_EVENT_TAP: u32 = 1;
const CG_HEAD_INSERT_EVENT_TAP: u32 = 0;
const CG_EVENT_TAP_OPTION_DEFAULT: u32 = 0;
const CG_KEYBOARD_EVENT_AUTOREPEAT: u32 = 8;
const CG_KEYBOARD_EVENT_KEYCODE: u32 = 9;
const CG_MOUSE_EVENT_BUTTON_NUMBER: u32 = 3;
const CG_MOUSE_EVENT_DELTA_X: u32 = 4;
const CG_MOUSE_EVENT_DELTA_Y: u32 = 5;
const CG_SCROLL_FIXED_DELTA_AXIS_1: u32 = 93;
const CG_SCROLL_FIXED_DELTA_AXIS_2: u32 = 94;
const CG_EVENT_SOURCE_STATE_ID: u32 = 45;

const CG_EVENT_LEFT_MOUSE_DOWN: u32 = 1;
const CG_EVENT_LEFT_MOUSE_UP: u32 = 2;
const CG_EVENT_RIGHT_MOUSE_DOWN: u32 = 3;
const CG_EVENT_RIGHT_MOUSE_UP: u32 = 4;
const CG_EVENT_MOUSE_MOVED: u32 = 5;
const CG_EVENT_LEFT_MOUSE_DRAGGED: u32 = 6;
const CG_EVENT_RIGHT_MOUSE_DRAGGED: u32 = 7;
const CG_EVENT_OTHER_MOUSE_DOWN: u32 = 25;
const CG_EVENT_OTHER_MOUSE_UP: u32 = 26;
const CG_EVENT_OTHER_MOUSE_DRAGGED: u32 = 27;
const CAPTURE_QUEUE_CAPACITY: usize = 4_096;
const CAPTURE_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_STOP_TIMEOUT: Duration = Duration::from_secs(2);
static WHOLE_HOST_CAPTURE_OWNED: AtomicBool = AtomicBool::new(false);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct CGPoint {
    x: f64,
    y: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct CGSize {
    width: f64,
    height: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct CGRect {
    origin: CGPoint,
    size: CGSize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct MachTimebaseInfo {
    numerator: u32,
    denominator: u32,
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRetain(value: CFTypeRef) -> CFTypeRef;
    fn CFRelease(value: CFTypeRef);
    fn CFGetTypeID(value: CFTypeRef) -> CFTypeId;
    fn CFStringGetTypeID() -> CFTypeId;
    fn CFNumberGetTypeID() -> CFTypeId;
    fn CFBooleanGetTypeID() -> CFTypeId;
    fn CFStringCreateWithCString(
        allocator: *const c_void,
        value: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
    fn CFStringGetCString(
        value: CFStringRef,
        buffer: *mut c_char,
        buffer_size: CFIndex,
        encoding: u32,
    ) -> u8;
    fn CFNumberGetValue(value: CFTypeRef, number_type: i32, output: *mut c_void) -> u8;
    fn CFBooleanGetValue(value: CFTypeRef) -> u8;
    fn CFSetGetCount(set: CFSetRef) -> CFIndex;
    fn CFSetGetValues(set: CFSetRef, values: *mut *const c_void);
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopRunInMode(mode: CFStringRef, seconds: f64, return_after_source_handled: u8) -> i32;
    fn CFRunLoopStop(run_loop: CFRunLoopRef);
    fn CFRunLoopWakeUp(run_loop: CFRunLoopRef);
    fn CFRunLoopAddSource(run_loop: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFRunLoopRemoveSource(run_loop: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFMachPortCreateRunLoopSource(
        allocator: *const c_void,
        port: CFMachPortRef,
        order: CFIndex,
    ) -> CFRunLoopSourceRef;
    fn CFMachPortInvalidate(port: CFMachPortRef);
    fn CFMachPortIsValid(port: CFMachPortRef) -> u8;

    #[allow(non_upper_case_globals)]
    static kCFRunLoopDefaultMode: CFStringRef;
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOHIDManagerCreate(allocator: *const c_void, options: u32) -> IOHIDManagerRef;
    fn IOHIDManagerSetDeviceMatching(manager: IOHIDManagerRef, matching: CFTypeRef);
    fn IOHIDManagerOpen(manager: IOHIDManagerRef, options: u32) -> i32;
    fn IOHIDManagerClose(manager: IOHIDManagerRef, options: u32) -> i32;
    fn IOHIDManagerCopyDevices(manager: IOHIDManagerRef) -> CFSetRef;
    fn IOHIDManagerRegisterInputValueCallback(
        manager: IOHIDManagerRef,
        callback: Option<extern "C" fn(*mut c_void, i32, *mut c_void, IOHIDValueRef)>,
        context: *mut c_void,
    );
    fn IOHIDManagerRegisterDeviceMatchingCallback(
        manager: IOHIDManagerRef,
        callback: Option<extern "C" fn(*mut c_void, i32, *mut c_void, IOHIDDeviceRef)>,
        context: *mut c_void,
    );
    fn IOHIDManagerRegisterDeviceRemovalCallback(
        manager: IOHIDManagerRef,
        callback: Option<extern "C" fn(*mut c_void, i32, *mut c_void, IOHIDDeviceRef)>,
        context: *mut c_void,
    );
    fn IOHIDManagerScheduleWithRunLoop(
        manager: IOHIDManagerRef,
        run_loop: CFRunLoopRef,
        run_loop_mode: CFStringRef,
    );
    fn IOHIDManagerUnscheduleFromRunLoop(
        manager: IOHIDManagerRef,
        run_loop: CFRunLoopRef,
        run_loop_mode: CFStringRef,
    );
    fn IOHIDDeviceGetProperty(device: IOHIDDeviceRef, key: CFStringRef) -> CFTypeRef;
    fn IOHIDDeviceGetService(device: IOHIDDeviceRef) -> u32;
    fn IOHIDValueGetElement(value: IOHIDValueRef) -> IOHIDElementRef;
    fn IOHIDValueGetTimeStamp(value: IOHIDValueRef) -> u64;
    fn IOHIDValueGetIntegerValue(value: IOHIDValueRef) -> CFIndex;
    fn IOHIDElementGetDevice(element: IOHIDElementRef) -> IOHIDDeviceRef;
    fn IOHIDElementGetUsagePage(element: IOHIDElementRef) -> u32;
    fn IOHIDElementGetUsage(element: IOHIDElementRef) -> u32;
    fn IOHIDElementIsRelative(element: IOHIDElementRef) -> u8;
    fn IOHIDElementIsVirtual(element: IOHIDElementRef) -> u8;
    fn IORegistryEntryGetRegistryEntryID(entry: u32, entry_id: *mut u64) -> i32;
}

#[link(name = "System")]
extern "C" {
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrusted() -> u8;
}

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGPreflightListenEventAccess() -> bool;

    fn CGEventCreate(source: *const c_void) -> CGEventRef;
    fn CGEventCreateKeyboardEvent(
        source: *const c_void,
        virtual_key: u16,
        key_down: bool,
    ) -> CGEventRef;
    fn CGEventCreateMouseEvent(
        source: *const c_void,
        mouse_type: u32,
        mouse_cursor_position: CGPoint,
        mouse_button: u32,
    ) -> CGEventRef;
    fn CGEventCreateScrollWheelEvent2(
        source: *const c_void,
        units: u32,
        wheel_count: u32,
        wheel_1: i32,
        wheel_2: i32,
        wheel_3: i32,
    ) -> CGEventRef;
    fn CGEventGetLocation(event: CGEventRef) -> CGPoint;
    fn CGEventGetTimestamp(event: CGEventRef) -> u64;
    fn CGEventGetFlags(event: CGEventRef) -> u64;
    fn CGEventGetIntegerValueField(event: CGEventRef, field: u32) -> i64;
    fn CGEventGetDoubleValueField(event: CGEventRef, field: u32) -> f64;
    fn CGEventSetIntegerValueField(event: CGEventRef, field: u32, value: i64);
    fn CGEventPost(tap: u32, event: CGEventRef);
    fn CGEventTapCreate(
        tap: u32,
        place: u32,
        options: u32,
        events_of_interest: u64,
        callback: Option<
            extern "C" fn(CGEventTapProxy, u32, CGEventRef, *mut c_void) -> CGEventRef,
        >,
        user_info: *mut c_void,
    ) -> CFMachPortRef;
    fn CGEventTapEnable(tap: CFMachPortRef, enable: bool);
    fn CGEventTapIsEnabled(tap: CFMachPortRef) -> bool;

    fn CGGetActiveDisplayList(max_displays: u32, displays: *mut u32, count: *mut u32) -> i32;
    fn CGDisplayBounds(display: u32) -> CGRect;
    fn CGDisplayPixelsWide(display: u32) -> usize;
    fn CGDisplayPixelsHigh(display: u32) -> usize;
    fn CGDisplayIsMain(display: u32) -> u32;
    fn CGDisplayCopyDisplayMode(display: u32) -> CGDisplayModeRef;
    fn CGDisplayModeGetRefreshRate(mode: CGDisplayModeRef) -> f64;
}

#[derive(Debug)]
struct OwnedCF(CFTypeRef);

impl OwnedCF {
    fn new(value: CFTypeRef, operation: &'static str) -> Result<Self, MacBackendError> {
        if value.is_null() {
            Err(MacBackendError::NullResult { operation })
        } else {
            Ok(Self(value))
        }
    }
}

impl Drop for OwnedCF {
    fn drop(&mut self) {
        // SAFETY: `OwnedCF` is only constructed from create/copy functions that
        // return an owned +1 Core Foundation reference, and it releases once.
        unsafe { CFRelease(self.0) };
    }
}

#[derive(Debug, Default)]
struct CaptureCounters {
    delivered_events: AtomicU64,
    dropped_events: AtomicU64,
    transition_discontinuities: AtomicU64,
    delivery_disconnects: AtomicU64,
    ignored_suppression_requests: AtomicU64,
    suppressed_events: AtomicU64,
    untranslated_events: AtomicU64,
    callback_panics: AtomicU64,
    tap_disables: AtomicU64,
    health: AtomicU8,
}

impl CaptureCounters {
    fn set_health(&self, health: CaptureHealth) {
        self.health.store(health as u8, Ordering::Release);
    }

    fn health(&self) -> CaptureHealth {
        match self.health.load(Ordering::Acquire) {
            1 => CaptureHealth::Running,
            2 => CaptureHealth::Stopped,
            3 => CaptureHealth::TransitionDiscontinuity,
            4 => CaptureHealth::DeliveryDisconnected,
            5 => CaptureHealth::TapDisabled,
            6 => CaptureHealth::TapInvalidated,
            7 => CaptureHealth::CallbackPanicked,
            _ => CaptureHealth::Idle,
        }
    }

    fn snapshot(&self) -> CaptureStatistics {
        CaptureStatistics {
            delivered_events: self.delivered_events.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            transition_discontinuities: self.transition_discontinuities.load(Ordering::Relaxed),
            delivery_disconnects: self.delivery_disconnects.load(Ordering::Relaxed),
            ignored_suppression_requests: self.ignored_suppression_requests.load(Ordering::Relaxed),
            suppressed_events: self.suppressed_events.load(Ordering::Relaxed),
            untranslated_events: self.untranslated_events.load(Ordering::Relaxed),
            callback_panics: self.callback_panics.load(Ordering::Relaxed),
            tap_disables: self.tap_disables.load(Ordering::Relaxed),
            health: self.health(),
        }
    }
}

#[derive(Debug)]
struct CaptureSession {
    run_loop: Option<Arc<RetainedRunLoop>>,
    stop_requested: Arc<AtomicBool>,
    capture_thread: Option<JoinHandle<Result<(), MacBackendError>>>,
    delivery_thread: Option<JoinHandle<()>>,
    capture_done: Receiver<()>,
    delivery_done: Receiver<()>,
    capture_outcome: Option<Result<(), MacBackendError>>,
}

#[derive(Debug)]
struct WholeHostCaptureSession {
    controller: Option<Arc<WholeHostController>>,
    capture_thread: Option<JoinHandle<Result<(), MacBackendError>>>,
    capture_done: Receiver<()>,
    capture_outcome: Option<Result<(), MacBackendError>>,
}

#[derive(Debug)]
struct WholeHostController {
    run_loop: usize,
    tap: usize,
    active: Arc<AtomicBool>,
}

impl WholeHostController {
    fn run_loop(&self) -> CFRunLoopRef {
        self.run_loop as CFRunLoopRef
    }

    fn tap(&self) -> CFMachPortRef {
        self.tap as CFMachPortRef
    }

    fn deactivate(&self) {
        self.active.store(false, Ordering::Release);
        // SAFETY: Both references are retained for this controller. Quartz
        // permits disabling a tap and stopping/waking a run loop cross-thread.
        unsafe {
            CGEventTapEnable(self.tap(), false);
            CFRunLoopStop(self.run_loop());
            CFRunLoopWakeUp(self.run_loop());
        }
    }
}

impl Drop for WholeHostController {
    fn drop(&mut self) {
        // SAFETY: Construction performs one CFRetain for each non-null
        // reference and this controller uniquely balances those retains.
        unsafe {
            CFRelease(self.tap().cast());
            CFRelease(self.run_loop().cast());
        }
    }
}

#[derive(Debug)]
struct WholeHostOwnershipClaim;

impl WholeHostOwnershipClaim {
    fn acquire() -> Result<Self, MacBackendError> {
        WHOLE_HOST_CAPTURE_OWNED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| MacBackendError::CaptureRegistrationOwned)
    }
}

impl Drop for WholeHostOwnershipClaim {
    fn drop(&mut self) {
        WHOLE_HOST_CAPTURE_OWNED.store(false, Ordering::Release);
    }
}

struct WholeHostCallbackContext {
    host_id: HostId,
    keyboard_device: DeviceId,
    pointer_device: DeviceId,
    callback: CaptureCallback,
    counters: Arc<CaptureCounters>,
    active: Arc<AtomicBool>,
    run_loop: CFRunLoopRef,
    sequence: AtomicU64,
}

#[derive(Debug)]
struct RetainedRunLoop(usize);

impl RetainedRunLoop {
    fn as_ptr(&self) -> CFRunLoopRef {
        self.0 as CFRunLoopRef
    }
}

impl Drop for RetainedRunLoop {
    fn drop(&mut self) {
        // SAFETY: This object is constructed immediately after one CFRetain
        // and is the unique owner of balancing that +1 reference. Arc extends
        // the ownership across detached-timeout paths without double release.
        unsafe { CFRelease(self.as_ptr().cast()) };
    }
}

#[derive(Clone, Copy, Debug)]
struct CaptureDevice {
    id: kvm_types::DeviceId,
    kind: DeviceKind,
    capabilities: DeviceCapabilities,
    physical_evidence: bool,
}

#[derive(Debug)]
struct CaptureContext {
    host_id: HostId,
    devices: HashMap<usize, CaptureDevice>,
    sender: SyncSender<CapturedInput>,
    sequence: AtomicU64,
    counters: Arc<CaptureCounters>,
    stop_requested: Arc<AtomicBool>,
    timebase: MachTimebaseInfo,
}

/// macOS input discovery, observation, and explicit whole-host alpha capture.
///
/// The default IOHID mode is deliberately non-suppressing: IOHID identifies
/// the source device but cannot prevent the corresponding event from reaching
/// macOS. Returning [`CaptureDisposition::SuppressLocal`] in that mode is
/// counted and ignored until device-attributed suppression is validated.
/// Only non-virtual elements on built-in or known physical transports are
/// classified [`kvm_daemon::EventClassification::Physical`]; all other
/// observations are conservatively unknown.
#[derive(Debug)]
pub struct MacInputBackend {
    host_id: HostId,
    capture_mode: MacCaptureMode,
    capture: Option<CaptureSession>,
    whole_host_capture: Option<WholeHostCaptureSession>,
    counters: Arc<CaptureCounters>,
}

impl MacInputBackend {
    #[must_use]
    pub fn new(host_id: HostId) -> Self {
        Self {
            host_id,
            capture_mode: MacCaptureMode::IoHidObservation,
            capture: None,
            whole_host_capture: None,
            counters: Arc::new(CaptureCounters::default()),
        }
    }

    /// Creates an explicitly opted-in aggregate Quartz suppression backend.
    ///
    /// This mode cannot attribute input to individual IOHID devices. It emits
    /// one stable host-scoped keyboard ID and one stable host-scoped pointer ID.
    #[must_use]
    pub fn new_whole_host_alpha(host_id: HostId) -> Self {
        Self {
            host_id,
            capture_mode: MacCaptureMode::WholeHostAlpha,
            capture: None,
            whole_host_capture: None,
            counters: Arc::new(CaptureCounters::default()),
        }
    }

    #[must_use]
    pub const fn capture_mode(&self) -> MacCaptureMode {
        self.capture_mode
    }

    #[must_use]
    pub const fn suppression_scope(&self) -> SuppressionScope {
        match self.capture_mode {
            MacCaptureMode::IoHidObservation => SuppressionScope::None,
            MacCaptureMode::WholeHostAlpha => SuppressionScope::WholeHostAlpha,
        }
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    /// Per-device suppression remains unavailable in both capture modes.
    #[must_use]
    pub const fn selective_suppression_supported() -> bool {
        false
    }

    /// Returns counters for the current or most recently stopped session.
    #[must_use]
    pub fn capture_statistics(&self) -> CaptureStatistics {
        self.counters.snapshot()
    }

    #[allow(clippy::too_many_lines)] // Startup/timeout ownership paths stay explicit.
    fn start_observation(&mut self, callback: CaptureCallback) -> Result<(), PlatformError> {
        if self.capture.is_some() || self.whole_host_capture.is_some() {
            return Err(MacBackendError::CaptureAlreadyRunning.into());
        }

        let counters = Arc::new(CaptureCounters::default());
        let (event_sender, event_receiver) = sync_channel(CAPTURE_QUEUE_CAPACITY);
        let (delivery_done_sender, delivery_done) = sync_channel(1);
        let worker_counters = Arc::clone(&counters);
        let delivery_thread = thread::Builder::new()
            .name("kvm-macos-delivery".to_owned())
            .spawn(move || {
                while let Ok(event) = event_receiver.recv() {
                    worker_counters
                        .delivered_events
                        .fetch_add(1, Ordering::Relaxed);
                    let disposition = catch_unwind(AssertUnwindSafe(|| callback(event)))
                        .unwrap_or_else(|_| {
                            worker_counters
                                .callback_panics
                                .fetch_add(1, Ordering::Relaxed);
                            CaptureDisposition::AllowLocal
                        });
                    if disposition == CaptureDisposition::SuppressLocal {
                        worker_counters
                            .ignored_suppression_requests
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                let _ = delivery_done_sender.send(());
            })?;

        let (ready_sender, ready_receiver) = sync_channel(1);
        let (activation_sender, activation_receiver) = sync_channel(1);
        let (capture_done_sender, capture_done) = sync_channel(1);
        let host_id = self.host_id;
        let capture_counters = Arc::clone(&counters);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = Arc::clone(&stop_requested);
        let capture_thread = match thread::Builder::new()
            .name("kvm-macos-iohid".to_owned())
            .spawn(move || {
                let result = run_capture_thread(
                    host_id,
                    event_sender,
                    capture_counters,
                    &ready_sender,
                    &activation_receiver,
                    Arc::clone(&thread_stop_requested),
                );
                let _ = capture_done_sender.send(());
                result
            }) {
            Ok(thread) => thread,
            Err(error) => {
                delivery_thread.join().map_err(|_| {
                    MacBackendError::CaptureThreadPanicked("delivery startup cleanup")
                })?;
                return Err(error.into());
            }
        };

        let run_loop = match ready_receiver.recv_timeout(CAPTURE_STARTUP_TIMEOUT) {
            Ok(Ok(run_loop)) => run_loop,
            Ok(Err(error)) => {
                capture_thread.join().map_err(|_| {
                    MacBackendError::CaptureThreadPanicked("IOHID startup cleanup")
                })??;
                delivery_thread.join().map_err(|_| {
                    MacBackendError::CaptureThreadPanicked("delivery startup cleanup")
                })?;
                return Err(error.into());
            }
            Err(RecvTimeoutError::Disconnected) => {
                capture_thread.join().map_err(|_| {
                    MacBackendError::CaptureThreadPanicked("IOHID startup cleanup")
                })??;
                delivery_thread.join().map_err(|_| {
                    MacBackendError::CaptureThreadPanicked("delivery startup cleanup")
                })?;
                return Err(MacBackendError::CaptureStartupTerminated.into());
            }
            Err(RecvTimeoutError::Timeout) => {
                // Dropping these join handles detaches the threads. When native
                // startup returns, the capture thread observes the dropped
                // readiness or activation channel, skips CFRunLoopRun, and
                // performs full native cleanup. Delivery then observes closure.
                drop(capture_thread);
                drop(delivery_thread);
                return Err(MacBackendError::CaptureStartupTimedOut.into());
            }
        };

        counters.set_health(CaptureHealth::Running);
        if activation_sender.send(()).is_err() {
            capture_thread
                .join()
                .map_err(|_| MacBackendError::CaptureThreadPanicked("IOHID activation"))??;
            delivery_thread
                .join()
                .map_err(|_| MacBackendError::CaptureThreadPanicked("delivery activation"))?;
            return Err(MacBackendError::CaptureStartupTerminated.into());
        }

        self.counters = counters;
        self.capture = Some(CaptureSession {
            run_loop: Some(run_loop),
            stop_requested,
            capture_thread: Some(capture_thread),
            delivery_thread: Some(delivery_thread),
            capture_done,
            delivery_done,
            capture_outcome: None,
        });
        Ok(())
    }

    fn stop_observation(&mut self) -> Result<(), PlatformError> {
        let Some(mut session) = self.capture.take() else {
            return Ok(());
        };
        session.stop_requested.store(true, Ordering::Release);
        if let Some(run_loop) = &session.run_loop {
            // SAFETY: `RetainedRunLoop` keeps the native object live. Stopping
            // and waking a run loop from another thread is supported by CF.
            unsafe {
                CFRunLoopStop(run_loop.as_ptr());
                CFRunLoopWakeUp(run_loop.as_ptr());
            }
        }

        if session.capture_thread.is_some() {
            match session.capture_done.recv_timeout(CAPTURE_STOP_TIMEOUT) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    let capture_thread = session
                        .capture_thread
                        .take()
                        .expect("capture thread presence checked");
                    session.capture_outcome = Some(
                        capture_thread
                            .join()
                            .map_err(|_| MacBackendError::CaptureThreadPanicked("IOHID"))
                            .and_then(|result| result),
                    );
                    // The capture thread no longer needs the native run loop;
                    // release the controller's Arc now rather than at backend
                    // destruction.
                    session.run_loop.take();
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.capture = Some(session);
                    return Err(MacBackendError::CaptureStopTimedOut("IOHID").into());
                }
            }
        }

        if session.delivery_thread.is_some() {
            match session.delivery_done.recv_timeout(CAPTURE_STOP_TIMEOUT) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    let delivery_thread = session
                        .delivery_thread
                        .take()
                        .expect("delivery thread presence checked");
                    delivery_thread
                        .join()
                        .map_err(|_| MacBackendError::CaptureThreadPanicked("delivery"))?;
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.capture = Some(session);
                    return Err(MacBackendError::CaptureStopTimedOut("delivery").into());
                }
            }
        }

        if self.counters.health() == CaptureHealth::Running {
            self.counters.set_health(CaptureHealth::Stopped);
        }
        session
            .capture_outcome
            .take()
            .unwrap_or(Ok(()))
            .map_err(Into::into)
    }

    fn start_whole_host_alpha(&mut self, callback: CaptureCallback) -> Result<(), PlatformError> {
        if self.capture.is_some() || self.whole_host_capture.is_some() {
            return Err(MacBackendError::CaptureAlreadyRunning.into());
        }
        let permissions = probe_permissions()?;
        if !permissions.input_monitoring {
            return Err(MacBackendError::PermissionDenied("Input Monitoring").into());
        }
        if !permissions.accessibility {
            return Err(MacBackendError::PermissionDenied("Accessibility").into());
        }
        let ownership = WholeHostOwnershipClaim::acquire()?;
        let counters = Arc::new(CaptureCounters::default());
        let active = Arc::new(AtomicBool::new(false));
        let (ready_sender, ready_receiver) = sync_channel(1);
        let (activation_sender, activation_receiver) = sync_channel(1);
        let (capture_done_sender, capture_done) = sync_channel(1);
        let host_id = self.host_id;
        let thread_counters = Arc::clone(&counters);
        let thread_active = Arc::clone(&active);
        let capture_thread = thread::Builder::new()
            .name("kvm-macos-whole-host-alpha".to_owned())
            .spawn(move || {
                let result = run_whole_host_capture_thread(
                    host_id,
                    callback,
                    &thread_counters,
                    &thread_active,
                    &ready_sender,
                    &activation_receiver,
                    ownership,
                );
                let _ = capture_done_sender.send(());
                result
            })?;

        let controller = match ready_receiver.recv_timeout(CAPTURE_STARTUP_TIMEOUT) {
            Ok(Ok(controller)) => controller,
            Ok(Err(error)) => {
                capture_thread.join().map_err(|_| {
                    MacBackendError::CaptureThreadPanicked("Quartz startup cleanup")
                })??;
                return Err(error.into());
            }
            Err(RecvTimeoutError::Disconnected) => {
                capture_thread.join().map_err(|_| {
                    MacBackendError::CaptureThreadPanicked("Quartz startup cleanup")
                })??;
                return Err(MacBackendError::CaptureStartupTerminated.into());
            }
            Err(RecvTimeoutError::Timeout) => {
                // The activation sender is dropped on return. A late native
                // setup therefore remains inactive, removes the tap, and only
                // then releases process-global ownership.
                drop(capture_thread);
                return Err(MacBackendError::CaptureStartupTimedOut.into());
            }
        };

        counters.set_health(CaptureHealth::Running);
        activation_sender
            .send(())
            .map_err(|_| MacBackendError::CaptureThreadPanicked("Quartz startup activation"))?;
        self.counters = counters;
        self.whole_host_capture = Some(WholeHostCaptureSession {
            controller: Some(controller),
            capture_thread: Some(capture_thread),
            capture_done,
            capture_outcome: None,
        });
        Ok(())
    }

    fn stop_whole_host_alpha(&mut self) -> Result<(), PlatformError> {
        let Some(mut session) = self.whole_host_capture.take() else {
            return Ok(());
        };
        if let Some(controller) = &session.controller {
            controller.deactivate();
        }

        if session.capture_thread.is_some() {
            match session.capture_done.recv_timeout(CAPTURE_STOP_TIMEOUT) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    let thread = session
                        .capture_thread
                        .take()
                        .expect("capture thread presence checked");
                    session.capture_outcome = Some(
                        thread
                            .join()
                            .map_err(|_| MacBackendError::CaptureThreadPanicked("Quartz"))
                            .and_then(|result| result),
                    );
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.whole_host_capture = Some(session);
                    return Err(MacBackendError::CaptureStopTimedOut("Quartz").into());
                }
            }
        }
        session.controller.take();
        if self.counters.health() == CaptureHealth::Running {
            self.counters.set_health(CaptureHealth::Stopped);
        }
        session
            .capture_outcome
            .take()
            .unwrap_or(Ok(()))
            .map_err(Into::into)
    }

    fn lifecycle_state(&self) -> CaptureLifecycleState {
        match self.counters.health() {
            CaptureHealth::TransitionDiscontinuity
            | CaptureHealth::DeliveryDisconnected
            | CaptureHealth::TapDisabled
            | CaptureHealth::TapInvalidated
            | CaptureHealth::CallbackPanicked => CaptureLifecycleState::Faulted,
            CaptureHealth::Running => CaptureLifecycleState::Running,
            CaptureHealth::Stopped => CaptureLifecycleState::Stopped,
            CaptureHealth::Idle => CaptureLifecycleState::Idle,
        }
    }
}

impl Drop for MacInputBackend {
    fn drop(&mut self) {
        let _ = self.stop_observation();
        let _ = self.stop_whole_host_alpha();
    }
}

impl InputCaptureBackend for MacInputBackend {
    fn enumerate_devices(&self) -> Result<Vec<InputDevice>, PlatformError> {
        match self.capture_mode {
            MacCaptureMode::IoHidObservation => {
                enumerate_iohid_devices(self.host_id).map_err(Into::into)
            }
            MacCaptureMode::WholeHostAlpha => Ok(whole_host_devices(self.host_id)),
        }
    }

    fn start_capture(&mut self, callback: CaptureCallback) -> Result<(), PlatformError> {
        match self.capture_mode {
            MacCaptureMode::IoHidObservation => self.start_observation(callback),
            MacCaptureMode::WholeHostAlpha => self.start_whole_host_alpha(callback),
        }
    }

    fn stop_capture(&mut self) -> Result<(), PlatformError> {
        match self.capture_mode {
            MacCaptureMode::IoHidObservation => self.stop_observation(),
            MacCaptureMode::WholeHostAlpha => self.stop_whole_host_alpha(),
        }
    }

    fn capture_lifecycle(&self) -> CaptureLifecycleState {
        self.lifecycle_state()
    }
}

/// Quartz output injector with button state needed to emit drag events.
#[derive(Debug, Default)]
pub struct MacOutputBackend {
    pressed_buttons: BTreeSet<PointerButton>,
}

impl MacOutputBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pressed_buttons: BTreeSet::new(),
        }
    }

    fn ensure_accessibility() -> Result<(), MacBackendError> {
        // SAFETY: Pure process-level permission query with no pointers.
        if unsafe { AXIsProcessTrusted() } != 0 {
            Ok(())
        } else {
            Err(MacBackendError::PermissionDenied("Accessibility"))
        }
    }

    fn inject_payload(&mut self, payload: InputPayload) -> Result<(), MacBackendError> {
        if !payload.is_finite() {
            return Err(MacBackendError::UnsupportedInput(
                "non-finite pointer or scroll value",
            ));
        }

        match payload {
            InputPayload::Key { code, state } => {
                let key = mac_virtual_key(code).ok_or(MacBackendError::UnsupportedInput(
                    "key has no Quartz virtual-key mapping",
                ))?;
                // SAFETY: Null selects the default event source; the returned
                // owned event is checked before any Quartz operation.
                let event = unsafe {
                    CGEventCreateKeyboardEvent(ptr::null(), key, quartz_key_is_down(state))
                };
                post_owned_event(event, "CGEventCreateKeyboardEvent")
            }
            InputPayload::PointerMove { dx, dy } => {
                let location = current_pointer_location()?;
                let destination = CGPoint {
                    x: location.x + dx,
                    y: location.y + dy,
                };
                if !destination.x.is_finite() || !destination.y.is_finite() {
                    return Err(MacBackendError::UnsupportedInput(
                        "pointer destination is outside finite coordinate space",
                    ));
                }
                let (event_type, button) = drag_event(&self.pressed_buttons);
                // SAFETY: The point is finite due to payload validation and a
                // Quartz-provided current location; button/type are valid enums.
                let event = unsafe {
                    CGEventCreateMouseEvent(ptr::null(), event_type, destination, button)
                };
                post_owned_event(event, "CGEventCreateMouseEvent")
            }
            InputPayload::PointerButton { button, state } => {
                let location = current_pointer_location()?;
                let (event_type, native_button) = button_event(button, state);
                // SAFETY: Location comes from Quartz and event/button constants
                // follow the public CoreGraphics ABI.
                let event = unsafe {
                    CGEventCreateMouseEvent(ptr::null(), event_type, location, native_button)
                };
                post_owned_event(event, "CGEventCreateMouseEvent")?;
                match state {
                    ButtonState::Pressed => {
                        self.pressed_buttons.insert(button);
                    }
                    ButtonState::Released => {
                        self.pressed_buttons.remove(&button);
                    }
                }
                Ok(())
            }
            InputPayload::Scroll {
                horizontal,
                vertical,
            } => {
                let vertical = rounded_i32(vertical);
                let horizontal = rounded_i32(horizontal);
                // SAFETY: CoreGraphics defines the non-variadic `...Event2`
                // entry point with three fixed wheel values. `wheel_count`
                // selects the two populated pixel-unit axes; the third is zero.
                let event = unsafe {
                    CGEventCreateScrollWheelEvent2(
                        ptr::null(),
                        CG_SCROLL_EVENT_UNIT_PIXEL,
                        2,
                        vertical,
                        horizontal,
                        0,
                    )
                };
                post_owned_event(event, "CGEventCreateScrollWheelEvent2")
            }
        }
    }
}

impl OutputInjectionBackend for MacOutputBackend {
    fn inject(&mut self, event: &InputEvent) -> Result<(), PlatformError> {
        Self::ensure_accessibility()?;
        self.inject_payload(event.payload).map_err(Into::into)
    }
}

/// CoreGraphics display enumerator.
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
        enumerate_core_graphics_displays(self.host_id).map_err(Into::into)
    }
}

/// Probes grants without prompting or changing system state.
///
/// # Errors
///
/// The macOS implementation currently has no failing code path. The result is
/// retained to keep this public API identical to the explicit unsupported
/// result provided on other operating systems.
#[allow(clippy::unnecessary_wraps)]
pub fn probe_permissions() -> Result<PermissionStatus, MacBackendError> {
    // SAFETY: Both functions are pure process-level permission queries and
    // accept no pointers. They are available on the supported macOS baseline.
    let (accessibility, input_monitoring) =
        unsafe { (AXIsProcessTrusted() != 0, CGPreflightListenEventAccess()) };
    Ok(PermissionStatus {
        accessibility,
        input_monitoring,
    })
}

fn whole_host_event_mask() -> u64 {
    [
        CG_EVENT_LEFT_MOUSE_DOWN,
        CG_EVENT_LEFT_MOUSE_UP,
        CG_EVENT_RIGHT_MOUSE_DOWN,
        CG_EVENT_RIGHT_MOUSE_UP,
        CG_EVENT_MOUSE_MOVED,
        CG_EVENT_LEFT_MOUSE_DRAGGED,
        CG_EVENT_RIGHT_MOUSE_DRAGGED,
        CG_EVENT_KEY_DOWN,
        CG_EVENT_KEY_UP,
        CG_EVENT_FLAGS_CHANGED,
        CG_EVENT_SCROLL_WHEEL,
        CG_EVENT_OTHER_MOUSE_DOWN,
        CG_EVENT_OTHER_MOUSE_UP,
        CG_EVENT_OTHER_MOUSE_DRAGGED,
    ]
    .into_iter()
    .fold(0_u64, |mask, event_type| mask | (1_u64 << event_type))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_whole_host_capture_thread(
    host_id: HostId,
    callback: CaptureCallback,
    counters: &Arc<CaptureCounters>,
    active: &Arc<AtomicBool>,
    ready: &SyncSender<Result<Arc<WholeHostController>, MacBackendError>>,
    activation: &Receiver<()>,
    ownership: WholeHostOwnershipClaim,
) -> Result<(), MacBackendError> {
    // SAFETY: The current run loop is borrowed for this thread. It is retained
    // before publication and remains live through source removal below.
    let run_loop = unsafe { CFRunLoopGetCurrent() };
    if run_loop.is_null() {
        let _ = ready.send(Err(MacBackendError::NullResult {
            operation: "CFRunLoopGetCurrent(Quartz)",
        }));
        return Ok(());
    }

    let mut context = Box::new(WholeHostCallbackContext {
        host_id,
        keyboard_device: derive_whole_host_device_id(host_id, WholeHostDeviceKind::Keyboard),
        pointer_device: derive_whole_host_device_id(host_id, WholeHostDeviceKind::Pointer),
        callback,
        counters: Arc::clone(counters),
        active: Arc::clone(active),
        run_loop,
        sequence: AtomicU64::new(1),
    });
    let context_ptr = (&raw mut *context).cast::<c_void>();
    // SAFETY: The callback context remains boxed until after this tap is
    // disabled, removed from the run loop, invalidated, and released.
    let tap_ptr = unsafe {
        CGEventTapCreate(
            CG_SESSION_EVENT_TAP,
            CG_HEAD_INSERT_EVENT_TAP,
            CG_EVENT_TAP_OPTION_DEFAULT,
            whole_host_event_mask(),
            Some(quartz_event_tap_callback),
            context_ptr,
        )
    };
    let tap = match OwnedCF::new(tap_ptr.cast_const(), "CGEventTapCreate") {
        Ok(tap) => tap,
        Err(error) => {
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    // Creation enables the tap, but the callback cannot run until this thread
    // enters the run loop below. Do not disable it during setup: Quartz queues
    // that deliberate disable through the same terminal callback used for a
    // system-disabled tap, which would make a healthy generation fault as soon
    // as the run loop starts. `active` remains false until owner activation, so
    // even an unexpected callback before then is fail-open.
    // SAFETY: The tap is live and the returned create-rule source is checked.
    let source_ptr = unsafe { CFMachPortCreateRunLoopSource(ptr::null(), tap_ptr, 0) };
    let source = match OwnedCF::new(source_ptr.cast_const(), "CFMachPortCreateRunLoopSource") {
        Ok(source) => source,
        Err(error) => {
            unsafe { CFMachPortInvalidate(tap_ptr) };
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    // SAFETY: All objects are live on this run-loop thread. Adding the source
    // does not transfer ownership.
    unsafe { CFRunLoopAddSource(run_loop, source_ptr, kCFRunLoopDefaultMode) };

    // SAFETY: Both references are non-null and live. The controller owns these
    // two +1 retains independently of the thread's create-rule objects.
    unsafe {
        CFRetain(run_loop.cast());
        CFRetain(tap_ptr.cast());
    }
    let controller = Arc::new(WholeHostController {
        run_loop: run_loop.addr(),
        tap: tap_ptr.addr(),
        active: Arc::clone(active),
    });

    if ready.send(Ok(Arc::clone(&controller))).is_ok() && activation.recv().is_ok() {
        active.store(true, Ordering::Release);
        while active.load(Ordering::Acquire) {
            // SAFETY: The tap source is installed on this live run loop. The
            // bounded interval also detects invalidation without relying on an
            // unreviewed CFMachPort invalidation callback.
            unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.10, 0) };
            if active.load(Ordering::Acquire) && unsafe { CFMachPortIsValid(tap_ptr) } == 0 {
                counters.set_health(CaptureHealth::TapInvalidated);
                active.store(false, Ordering::Release);
            } else if active.load(Ordering::Acquire) && !unsafe { CGEventTapIsEnabled(tap_ptr) } {
                counters.tap_disables.fetch_add(1, Ordering::Relaxed);
                counters.set_health(CaptureHealth::TapDisabled);
                active.store(false, Ordering::Release);
            }
        }
    }

    active.store(false, Ordering::Release);
    // SAFETY: Callback authority is revoked before teardown. Removing the
    // source and invalidating the tap prevents any callback after `context`
    // is dropped. Releases are handled by OwnedCF/controller RAII.
    unsafe {
        CGEventTapEnable(tap_ptr, false);
        CFRunLoopRemoveSource(run_loop, source_ptr, kCFRunLoopDefaultMode);
        CFMachPortInvalidate(tap_ptr);
    }
    drop(controller);
    drop(source);
    drop(tap);
    drop(context);
    // Keep process-global ownership through native teardown and callback-context
    // destruction so another tap generation cannot overlap this one.
    drop(ownership);

    match counters.health() {
        CaptureHealth::TransitionDiscontinuity => Err(MacBackendError::CaptureDiscontinuity),
        CaptureHealth::TapDisabled
        | CaptureHealth::TapInvalidated
        | CaptureHealth::CallbackPanicked => Err(MacBackendError::CaptureTapTerminated),
        _ => Ok(()),
    }
}

extern "C" fn quartz_event_tap_callback(
    _proxy: CGEventTapProxy,
    event_type: u32,
    event: CGEventRef,
    user_info: *mut c_void,
) -> CGEventRef {
    if user_info.is_null() {
        return event;
    }
    // SAFETY: `user_info` points to the boxed context owned by the tap thread.
    // Quartz serializes this callback on that thread's run loop, and teardown
    // removes/invalidates the source before freeing the box.
    let context = unsafe { &mut *user_info.cast::<WholeHostCallbackContext>() };
    if matches!(
        event_type,
        CG_EVENT_TAP_DISABLED_BY_TIMEOUT | CG_EVENT_TAP_DISABLED_BY_USER_INPUT
    ) {
        // Owner-initiated shutdown revokes callback authority before disabling
        // the tap. Quartz may still deliver that expected disable notification;
        // it is not a lifecycle fault.
        if !context.active.load(Ordering::Acquire) {
            return event;
        }
        context
            .counters
            .tap_disables
            .fetch_add(1, Ordering::Relaxed);
        context.counters.set_health(CaptureHealth::TapDisabled);
        terminally_deactivate_whole_host(context);
        return event;
    }
    if event.is_null() || !context.active.load(Ordering::Acquire) {
        return event;
    }

    let suppress = catch_unwind(AssertUnwindSafe(|| {
        dispatch_quartz_event(context, event_type, event)
    }))
    .unwrap_or_else(|_| {
        context
            .counters
            .callback_panics
            .fetch_add(1, Ordering::Relaxed);
        context.counters.set_health(CaptureHealth::CallbackPanicked);
        terminally_deactivate_whole_host(context);
        false
    });
    if suppress && context.active.load(Ordering::Acquire) {
        ptr::null_mut()
    } else {
        event
    }
}

fn terminally_deactivate_whole_host(context: &WholeHostCallbackContext) {
    context.active.store(false, Ordering::Release);
    // SAFETY: The run loop remains live for the complete callback lifetime.
    unsafe {
        CFRunLoopStop(context.run_loop);
        CFRunLoopWakeUp(context.run_loop);
    }
}

#[allow(clippy::too_many_lines)] // Native fields stay explicit for ABI review.
fn dispatch_quartz_event(
    context: &WholeHostCallbackContext,
    event_type: u32,
    event: CGEventRef,
) -> bool {
    // SAFETY: All field accessors are pure reads of the callback-owned event.
    let (user_data, source_state_id) = unsafe {
        (
            CGEventGetIntegerValueField(event, CG_EVENT_SOURCE_USER_DATA),
            CGEventGetIntegerValueField(event, CG_EVENT_SOURCE_STATE_ID),
        )
    };
    let classification = classify_quartz_capture(user_data, source_state_id);
    let payload = if matches!(
        event_type,
        CG_EVENT_KEY_DOWN | CG_EVENT_KEY_UP | CG_EVENT_FLAGS_CHANGED
    ) {
        let key = unsafe { CGEventGetIntegerValueField(event, CG_KEYBOARD_EVENT_KEYCODE) };
        u16::try_from(key).ok().and_then(|key| {
            let autorepeat =
                unsafe { CGEventGetIntegerValueField(event, CG_KEYBOARD_EVENT_AUTOREPEAT) } != 0;
            let modifier_pressed = (event_type == CG_EVENT_FLAGS_CHANGED)
                .then(|| quartz_modifier_pressed(key, unsafe { CGEventGetFlags(event) }))
                .flatten();
            translate_quartz_keyboard(event_type, key, autorepeat, modifier_pressed)
        })
    } else if event_type == CG_EVENT_SCROLL_WHEEL {
        translate_quartz_scroll(
            unsafe { CGEventGetDoubleValueField(event, CG_SCROLL_FIXED_DELTA_AXIS_2) },
            unsafe { CGEventGetDoubleValueField(event, CG_SCROLL_FIXED_DELTA_AXIS_1) },
        )
    } else {
        let button = unsafe { CGEventGetIntegerValueField(event, CG_MOUSE_EVENT_BUTTON_NUMBER) };
        let delta_x =
            i32::try_from(unsafe { CGEventGetIntegerValueField(event, CG_MOUSE_EVENT_DELTA_X) })
                .ok()
                .map(f64::from);
        let delta_y =
            i32::try_from(unsafe { CGEventGetIntegerValueField(event, CG_MOUSE_EVENT_DELTA_Y) })
                .ok()
                .map(f64::from);
        delta_x.zip(delta_y).and_then(|(delta_x, delta_y)| {
            translate_quartz_pointer(event_type, button, delta_x, delta_y)
        })
    };
    let Some(payload) = payload else {
        context
            .counters
            .untranslated_events
            .fetch_add(1, Ordering::Relaxed);
        return false;
    };
    let source_device = if matches!(payload, InputPayload::Key { .. }) {
        context.keyboard_device
    } else {
        context.pointer_device
    };
    let Ok(sequence) =
        context
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
    else {
        context
            .counters
            .transition_discontinuities
            .fetch_add(1, Ordering::Relaxed);
        context
            .counters
            .set_health(CaptureHealth::TransitionDiscontinuity);
        terminally_deactivate_whole_host(context);
        return false;
    };
    let pointer_motion = matches!(payload, InputPayload::PointerMove { .. });
    let mut captured = CapturedInput::new(
        InputEvent::new(
            sequence,
            unsafe { CGEventGetTimestamp(event) },
            context.host_id,
            source_device,
            payload,
        ),
        classification,
    );
    if pointer_motion {
        // SAFETY: the callback owns a live event for the complete dispatch.
        let location = unsafe { CGEventGetLocation(event) };
        captured = captured.with_native_pointer_position(Point::new(location.x, location.y));
    }
    context
        .counters
        .delivered_events
        .fetch_add(1, Ordering::Relaxed);
    let disposition = (context.callback)(captured);
    if disposition == CaptureDisposition::SuppressLocal
        && classification == EventClassification::Physical
        && context.active.load(Ordering::Acquire)
    {
        context
            .counters
            .suppressed_events
            .fetch_add(1, Ordering::Relaxed);
        true
    } else {
        if disposition == CaptureDisposition::SuppressLocal {
            context
                .counters
                .ignored_suppression_requests
                .fetch_add(1, Ordering::Relaxed);
        }
        false
    }
}

fn run_capture_thread(
    host_id: HostId,
    sender: SyncSender<CapturedInput>,
    counters: Arc<CaptureCounters>,
    ready: &SyncSender<Result<Arc<RetainedRunLoop>, MacBackendError>>,
    activation: &Receiver<()>,
    stop_requested: Arc<AtomicBool>,
) -> Result<(), MacBackendError> {
    let terminal_counters = Arc::clone(&counters);
    let loop_stop_requested = Arc::clone(&stop_requested);
    let manager_ptr = unsafe { IOHIDManagerCreate(ptr::null(), IO_OPTION_NONE) };
    let manager = match OwnedCF::new(manager_ptr.cast_const(), "IOHIDManagerCreate") {
        Ok(manager) => manager,
        Err(error) => {
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };

    let mut timebase = MachTimebaseInfo::default();
    // SAFETY: `timebase` is valid writable storage for the fixed C structure.
    let timebase_status = unsafe { mach_timebase_info(&raw mut timebase) };
    if timebase_status != 0 || timebase.denominator == 0 {
        let _ = ready.send(Err(MacBackendError::NativeStatus {
            operation: "mach_timebase_info",
            code: timebase_status,
        }));
        return Ok(());
    }

    let mut context = Box::new(CaptureContext {
        host_id,
        devices: HashMap::new(),
        sender,
        sequence: AtomicU64::new(0),
        counters,
        stop_requested,
        timebase,
    });
    let context_ptr = (&raw mut *context).cast::<c_void>();

    // SAFETY: The manager and boxed callback context remain live until after
    // the manager is unscheduled and closed below. Null matching selects every
    // HID collection; translation filters unsupported values cheaply.
    unsafe {
        IOHIDManagerSetDeviceMatching(manager_ptr, ptr::null());
        IOHIDManagerRegisterDeviceMatchingCallback(
            manager_ptr,
            Some(iohid_device_matched),
            context_ptr,
        );
        IOHIDManagerRegisterDeviceRemovalCallback(
            manager_ptr,
            Some(iohid_device_removed),
            context_ptr,
        );
        IOHIDManagerRegisterInputValueCallback(manager_ptr, Some(iohid_input_value), context_ptr);
    }

    // SAFETY: This runs on the dedicated capture thread. The borrowed current
    // run loop is retained for the controller before its address is published.
    let run_loop = unsafe { CFRunLoopGetCurrent() };
    if run_loop.is_null() {
        let _ = ready.send(Err(MacBackendError::NullResult {
            operation: "CFRunLoopGetCurrent",
        }));
        return Ok(());
    }
    // SAFETY: `run_loop` is non-null. The resulting +1 reference is immediately
    // placed under Arc-backed RAII ownership for every startup/timeout path.
    unsafe { CFRetain(run_loop.cast()) };
    let retained_run_loop = Arc::new(RetainedRunLoop(run_loop.addr()));

    // SAFETY: Manager, run loop, mode, and context are all live. Registering
    // before opening ensures matching callbacks cannot race context setup.
    unsafe {
        IOHIDManagerScheduleWithRunLoop(manager_ptr, run_loop, kCFRunLoopDefaultMode);
    }
    // SAFETY: The scheduled manager remains live for the open/run/close cycle.
    let open_status = unsafe { IOHIDManagerOpen(manager_ptr, IO_OPTION_NONE) };
    if open_status != 0 {
        // SAFETY: This reverses scheduling on the same thread before the
        // callback context is destroyed. RAII balances the run-loop retain.
        unsafe { IOHIDManagerUnscheduleFromRunLoop(manager_ptr, run_loop, kCFRunLoopDefaultMode) };
        let _ = ready.send(Err(MacBackendError::NativeStatus {
            operation: "IOHIDManagerOpen",
            code: open_status,
        }));
        return Ok(());
    }

    populate_capture_device_ids(manager_ptr, &mut context);
    if ready.send(Ok(Arc::clone(&retained_run_loop))).is_err() || activation.recv().is_err() {
        // The owner disappeared during startup, so do not enter an orphaned
        // run loop. The activation handshake closes the race where readiness
        // was queued just as the caller's deadline expired. Arc ownership
        // releases the retained run loop after native cleanup.
    } else {
        while !loop_stop_requested.load(Ordering::Acquire) {
            // SAFETY: The manager is a scheduled input source on this thread's
            // run loop. A bounded interval plus the stop flag closes the race
            // where teardown is requested immediately before entering the run
            // loop; stop/wake makes an active interval return promptly.
            unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.25, 0) };
        }
    }

    // SAFETY: Run-loop delivery has stopped. Unscheduling and closing prevents
    // any later callback from observing the soon-to-be-dropped boxed context.
    unsafe {
        IOHIDManagerUnscheduleFromRunLoop(manager_ptr, run_loop, kCFRunLoopDefaultMode);
    }
    // SAFETY: The manager was successfully opened above.
    let close_status = unsafe { IOHIDManagerClose(manager_ptr, IO_OPTION_NONE) };
    drop(context);
    drop(manager);
    drop(retained_run_loop);

    match counters_terminal_error(&terminal_counters) {
        Some(error) => Err(error),
        None if close_status == 0 => Ok(()),
        None => Err(MacBackendError::NativeStatus {
            operation: "IOHIDManagerClose",
            code: close_status,
        }),
    }
}

fn populate_capture_device_ids(manager: IOHIDManagerRef, context: &mut CaptureContext) {
    // SAFETY: Manager is live and open. A null set means no current devices.
    let set_ptr = unsafe { IOHIDManagerCopyDevices(manager) };
    let Ok(set) = OwnedCF::new(set_ptr.cast(), "IOHIDManagerCopyDevices") else {
        return;
    };
    for device in device_refs_from_set(set.0.cast()) {
        register_capture_device(context, device);
    }
}

fn register_capture_device(context: &mut CaptureContext, device: IOHIDDeviceRef) {
    let Ok(material) = device_identity_material(device) else {
        return;
    };
    let Some(kind) = device_kind(material.primary_usage_page, material.primary_usage) else {
        return;
    };
    let (device_id, _) = derive_device_id(context.host_id, &material);
    context.devices.insert(
        device.addr(),
        CaptureDevice {
            id: device_id,
            kind,
            capabilities: capabilities_for(kind),
            physical_evidence: physical_device_evidence(
                material.built_in,
                material.transport.as_deref(),
            ),
        },
    );
}

fn counters_terminal_error(counters: &CaptureCounters) -> Option<MacBackendError> {
    match counters.health() {
        CaptureHealth::TransitionDiscontinuity => Some(MacBackendError::CaptureDiscontinuity),
        CaptureHealth::DeliveryDisconnected => Some(MacBackendError::CaptureDeliveryDisconnected),
        _ => None,
    }
}

extern "C" fn iohid_device_matched(
    context: *mut c_void,
    result: i32,
    _sender: *mut c_void,
    device: IOHIDDeviceRef,
) {
    if context.is_null() || device.is_null() || result != 0 {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The pointer refers to the boxed context owned by the capture
        // thread and callbacks are unregistered before it is dropped. All
        // manager callbacks run serially on this dedicated CFRunLoop.
        let context = unsafe { &mut *context.cast::<CaptureContext>() };
        register_capture_device(context, device);
    }));
}

extern "C" fn iohid_device_removed(
    context: *mut c_void,
    result: i32,
    _sender: *mut c_void,
    device: IOHIDDeviceRef,
) {
    if context.is_null() || device.is_null() || result != 0 {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: See `iohid_device_matched`; removal uses the same serialized
        // callback and context lifetime contract.
        let context = unsafe { &mut *context.cast::<CaptureContext>() };
        context.devices.remove(&device.addr());
    }));
}

extern "C" fn iohid_input_value(
    context: *mut c_void,
    result: i32,
    _sender: *mut c_void,
    value: IOHIDValueRef,
) {
    if context.is_null() || value.is_null() || result != 0 {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Context and IOHID value are valid for the duration of this
        // callback, and all manager callbacks are serialized on this CFRunLoop.
        let context = unsafe { &mut *context.cast::<CaptureContext>() };
        if context.stop_requested.load(Ordering::Acquire) {
            return;
        }
        // SAFETY: `value` is a valid callback argument.
        let element = unsafe { IOHIDValueGetElement(value) };
        if element.is_null() {
            return;
        }
        // SAFETY: `element` is borrowed from the live value callback argument.
        let device = unsafe { IOHIDElementGetDevice(element) };
        if device.is_null() {
            return;
        }
        let capture_device = context.devices.get(&device.addr()).copied();
        let Some(capture_device) = capture_device else {
            return;
        };

        // SAFETY: Element/value accessors are pure reads of callback-owned
        // objects. CFIndex is signed and fits i64 on supported 64-bit macOS.
        let (usage_page, usage, raw_value, raw_timestamp, is_relative, element_is_virtual) = unsafe {
            (
                IOHIDElementGetUsagePage(element),
                IOHIDElementGetUsage(element),
                IOHIDValueGetIntegerValue(value),
                IOHIDValueGetTimeStamp(value),
                IOHIDElementIsRelative(element) != 0,
                IOHIDElementIsVirtual(element) != 0,
            )
        };
        if !device_accepts_hid_value(
            capture_device.kind,
            capture_device.capabilities,
            usage_page,
            usage,
        ) {
            return;
        }
        let Ok(raw_value) = i64::try_from(raw_value) else {
            return;
        };
        let Some(payload) = translate_hid_value(usage_page, usage, raw_value, is_relative) else {
            return;
        };
        let sequence = context.sequence.fetch_add(1, Ordering::Relaxed);
        let timestamp_ns = mach_timestamp_ns(
            raw_timestamp,
            context.timebase.numerator,
            context.timebase.denominator,
        );
        let captured = CapturedInput::new(
            InputEvent::new(
                sequence,
                timestamp_ns,
                context.host_id,
                capture_device.id,
                payload,
            ),
            classify_iohid_observation(element_is_virtual, capture_device.physical_evidence),
        );
        match context.sender.try_send(captured) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) if overflow_may_drop(payload) => {
                context
                    .counters
                    .dropped_events
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) => {
                context
                    .counters
                    .transition_discontinuities
                    .fetch_add(1, Ordering::Relaxed);
                context
                    .counters
                    .set_health(CaptureHealth::TransitionDiscontinuity);
                context.stop_requested.store(true, Ordering::Release);
            }
            Err(TrySendError::Disconnected(_)) => {
                context
                    .counters
                    .delivery_disconnects
                    .fetch_add(1, Ordering::Relaxed);
                context
                    .counters
                    .set_health(CaptureHealth::DeliveryDisconnected);
                context.stop_requested.store(true, Ordering::Release);
            }
        }
    }));
}

fn enumerate_iohid_devices(host_id: HostId) -> Result<Vec<InputDevice>, MacBackendError> {
    // SAFETY: Null selects the default allocator, and zero is the documented
    // option set. The returned create-rule reference is checked and owned.
    let manager_ptr = unsafe { IOHIDManagerCreate(ptr::null(), IO_OPTION_NONE) };
    let manager = OwnedCF::new(manager_ptr.cast_const(), "IOHIDManagerCreate")?;

    // SAFETY: `manager` is a live IOHIDManager. Null matching selects all HID
    // devices, including built-in keyboard/trackpad collections.
    unsafe { IOHIDManagerSetDeviceMatching(manager_ptr, ptr::null()) };
    // SAFETY: Manager remains live for the complete open/copy/close sequence.
    let open_status = unsafe { IOHIDManagerOpen(manager_ptr, IO_OPTION_NONE) };
    if open_status != 0 {
        return Err(MacBackendError::NativeStatus {
            operation: "IOHIDManagerOpen",
            code: open_status,
        });
    }

    // SAFETY: A live, open manager may copy its current device set.
    let set_ptr = unsafe { IOHIDManagerCopyDevices(manager_ptr) };
    let result = if set_ptr.is_null() {
        Ok(Vec::new())
    } else {
        match OwnedCF::new(set_ptr.cast(), "IOHIDManagerCopyDevices") {
            Ok(set) => devices_from_set(host_id, set.0.cast()),
            Err(error) => Err(error),
        }
    };

    // SAFETY: The manager was opened above and has not yet been closed.
    let close_status = unsafe { IOHIDManagerClose(manager_ptr, IO_OPTION_NONE) };
    drop(manager);
    if close_status != 0 {
        return Err(MacBackendError::NativeStatus {
            operation: "IOHIDManagerClose",
            code: close_status,
        });
    }
    result
}

fn whole_host_devices(host_id: HostId) -> Vec<InputDevice> {
    vec![
        InputDevice::new(
            derive_whole_host_device_id(host_id, WholeHostDeviceKind::Keyboard),
            host_id,
            "macOS whole-host keyboard (alpha)",
            DeviceKind::Keyboard,
            DeviceCapabilities::KEYBOARD,
        ),
        InputDevice::new(
            derive_whole_host_device_id(host_id, WholeHostDeviceKind::Pointer),
            host_id,
            "macOS whole-host pointer (alpha)",
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

fn devices_from_set(host_id: HostId, set: CFSetRef) -> Result<Vec<InputDevice>, MacBackendError> {
    let mut devices = Vec::new();
    for device in device_refs_from_set(set) {
        if let Some(input) = input_device_from_hid(host_id, device)? {
            devices.push(input);
        }
    }
    devices.sort_by_key(|device| device.id);
    devices.dedup_by_key(|device| device.id);
    Ok(devices)
}

fn device_refs_from_set(set: CFSetRef) -> Vec<IOHIDDeviceRef> {
    // SAFETY: `set` is a live CFSet copied from IOHIDManager.
    let count = unsafe { CFSetGetCount(set) };
    let count = usize::try_from(count).unwrap_or_default();
    let mut values = vec![ptr::null(); count];
    // SAFETY: The vector has exactly `CFSetGetCount` slots; Core Foundation
    // writes borrowed device pointers that remain live while the set is owned.
    unsafe { CFSetGetValues(set, values.as_mut_ptr()) };
    values.into_iter().map(<*const c_void>::cast_mut).collect()
}

fn input_device_from_hid(
    host_id: HostId,
    device: IOHIDDeviceRef,
) -> Result<Option<InputDevice>, MacBackendError> {
    let material = device_identity_material(device)?;
    let usage_page = material.primary_usage_page;
    let usage = material.primary_usage;
    let Some(kind) = device_kind(usage_page, usage) else {
        return Ok(None);
    };

    let manufacturer = hid_string(device, "Manufacturer")?;
    let name = match (manufacturer.as_deref(), material.product_name.as_deref()) {
        (Some(maker), Some(product)) if !product.starts_with(maker) => format!("{maker} {product}"),
        (_, Some(product)) => product.to_owned(),
        (Some(maker), None) => maker.to_owned(),
        (None, None) => match kind {
            DeviceKind::Keyboard => "macOS Keyboard".to_owned(),
            DeviceKind::Mouse => "macOS Mouse".to_owned(),
            DeviceKind::Trackpad => "macOS Trackpad".to_owned(),
            _ => "macOS HID Device".to_owned(),
        },
    };

    let (id, _stability) = derive_device_id(host_id, &material);
    let capabilities = capabilities_for(kind);
    let mut input = InputDevice::new(id, host_id, name, kind, capabilities);
    input.vendor_id = material.vendor_id;
    input.product_id = material.product_id;
    Ok(Some(input))
}

fn device_identity_material(
    device: IOHIDDeviceRef,
) -> Result<DeviceIdentityMaterial, MacBackendError> {
    Ok(DeviceIdentityMaterial {
        vendor_id: hid_u64(device, "VendorID")?.and_then(|v| u16::try_from(v).ok()),
        product_id: hid_u64(device, "ProductID")?.and_then(|v| u16::try_from(v).ok()),
        serial_number: hid_string(device, "SerialNumber")?,
        location_id: hid_u64(device, "LocationID")?.and_then(|v| u32::try_from(v).ok()),
        registry_entry_id: registry_entry_id(device),
        transport: hid_string(device, "Transport")?,
        product_name: hid_string(device, "Product")?,
        built_in: hid_bool(device, "Built-In")?.unwrap_or(false),
        primary_usage_page: hid_u64(device, "PrimaryUsagePage")?
            .and_then(|v| u16::try_from(v).ok()),
        primary_usage: hid_u64(device, "PrimaryUsage")?.and_then(|v| u16::try_from(v).ok()),
    })
}

fn hid_property(device: IOHIDDeviceRef, key: &str) -> Result<CFTypeRef, MacBackendError> {
    let key = CString::new(key).expect("static IOHID property keys contain no NUL");
    // SAFETY: CString is NUL terminated and lives through this call. Null uses
    // the default allocator; the create-rule string is owned locally.
    let key_ref = unsafe { CFStringCreateWithCString(ptr::null(), key.as_ptr(), UTF8_ENCODING) };
    let key_ref = OwnedCF::new(key_ref.cast(), "CFStringCreateWithCString")?;
    // SAFETY: Both device and key are live. IOHID returns a borrowed property
    // retained by the device, and callers consume it before returning.
    Ok(unsafe { IOHIDDeviceGetProperty(device, key_ref.0.cast()) })
}

fn hid_u64(device: IOHIDDeviceRef, key: &str) -> Result<Option<u64>, MacBackendError> {
    let value = hid_property(device, key)?;
    if value.is_null() {
        return Ok(None);
    }
    // SAFETY: `value` is a live borrowed CF object for the duration of this call.
    if unsafe { CFGetTypeID(value) != CFNumberGetTypeID() } {
        return Ok(None);
    }
    let mut output = 0_i64;
    // SAFETY: Type ID was checked and `output` is valid writable i64 storage.
    if unsafe {
        CFNumberGetValue(
            value,
            NUMBER_SINT64_TYPE,
            (&raw mut output).cast::<c_void>(),
        )
    } != 0
    {
        Ok(u64::try_from(output).ok())
    } else {
        Ok(None)
    }
}

fn hid_bool(device: IOHIDDeviceRef, key: &str) -> Result<Option<bool>, MacBackendError> {
    let value = hid_property(device, key)?;
    if value.is_null() {
        return Ok(None);
    }
    // SAFETY: `value` is a live borrowed CF object for the duration of this call.
    if unsafe { CFGetTypeID(value) != CFBooleanGetTypeID() } {
        return Ok(None);
    }
    // SAFETY: Type ID was checked immediately above.
    Ok(Some(unsafe { CFBooleanGetValue(value) } != 0))
}

fn hid_string(device: IOHIDDeviceRef, key: &str) -> Result<Option<String>, MacBackendError> {
    let value = hid_property(device, key)?;
    if value.is_null() {
        return Ok(None);
    }
    // SAFETY: `value` is a live borrowed CF object for the duration of this call.
    if unsafe { CFGetTypeID(value) != CFStringGetTypeID() } {
        return Ok(None);
    }

    // HID product strings are small in practice. If a malicious/invalid device
    // exceeds this bound, omit the cosmetic property rather than allocate on an
    // untrusted length and compromise enumeration.
    let mut buffer = vec![0_i8; 4096];
    // SAFETY: Type ID is CFString, and the mutable buffer length matches the
    // advertised size. Core Foundation always NUL terminates on success.
    let copied = unsafe {
        CFStringGetCString(
            value.cast(),
            buffer.as_mut_ptr(),
            CFIndex::try_from(buffer.len()).unwrap_or(CFIndex::MAX),
            UTF8_ENCODING,
        )
    };
    if copied == 0 {
        return Ok(None);
    }
    // SAFETY: Successful CFStringGetCString guarantees NUL termination within
    // the supplied buffer.
    let value = unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .trim()
        .to_owned();
    Ok((!value.is_empty()).then_some(value))
}

fn registry_entry_id(device: IOHIDDeviceRef) -> Option<u64> {
    // SAFETY: Device is live and IOHID exposes its borrowed registry service ID.
    let service = unsafe { IOHIDDeviceGetService(device) };
    if service == 0 {
        return None;
    }
    let mut entry_id = 0_u64;
    // SAFETY: Service is returned by IOHID and output points to writable u64.
    let status = unsafe { IORegistryEntryGetRegistryEntryID(service, &raw mut entry_id) };
    (status == 0).then_some(entry_id)
}

const fn device_kind(page: Option<u16>, usage: Option<u16>) -> Option<DeviceKind> {
    match (page, usage) {
        (Some(0x01), Some(0x06 | 0x07)) => Some(DeviceKind::Keyboard),
        (Some(0x01), Some(0x02)) => Some(DeviceKind::Mouse),
        (Some(0x0d), Some(0x05)) => Some(DeviceKind::Trackpad),
        _ => None,
    }
}

const fn capabilities_for(kind: DeviceKind) -> DeviceCapabilities {
    match kind {
        DeviceKind::Keyboard => DeviceCapabilities::KEYBOARD,
        DeviceKind::Mouse => DeviceCapabilities {
            pointer: true,
            vertical_scroll: true,
            horizontal_scroll: true,
            extra_buttons: true,
            keyboard: false,
        },
        DeviceKind::Trackpad => DeviceCapabilities {
            pointer: true,
            vertical_scroll: true,
            horizontal_scroll: true,
            extra_buttons: false,
            keyboard: false,
        },
        _ => DeviceCapabilities::NONE,
    }
}

fn current_pointer_location() -> Result<CGPoint, MacBackendError> {
    // SAFETY: Null selects the default event source and returns an owned event.
    let event = unsafe { CGEventCreate(ptr::null()) };
    let event = OwnedCF::new(event.cast(), "CGEventCreate")?;
    // SAFETY: `event` is a live CGEvent for the duration of the call.
    Ok(unsafe { CGEventGetLocation(event.0.cast_mut()) })
}

fn post_owned_event(event: CGEventRef, operation: &'static str) -> Result<(), MacBackendError> {
    let event = OwnedCF::new(event.cast(), operation)?;
    // SAFETY: The event is live. User-data is a signed 64-bit field intended for
    // application tagging, and posting does not transfer ownership.
    unsafe {
        CGEventSetIntegerValueField(event.0.cast_mut(), CG_EVENT_SOURCE_USER_DATA, KVM_EVENT_TAG);
        CGEventPost(CG_HID_EVENT_TAP, event.0.cast_mut());
    }
    Ok(())
}

const fn button_event(button: PointerButton, state: ButtonState) -> (u32, u32) {
    match (button, state) {
        (PointerButton::Left, ButtonState::Pressed) => (CG_EVENT_LEFT_MOUSE_DOWN, 0),
        (PointerButton::Left, ButtonState::Released) => (CG_EVENT_LEFT_MOUSE_UP, 0),
        (PointerButton::Right, ButtonState::Pressed) => (CG_EVENT_RIGHT_MOUSE_DOWN, 1),
        (PointerButton::Right, ButtonState::Released) => (CG_EVENT_RIGHT_MOUSE_UP, 1),
        (button, ButtonState::Pressed) => (CG_EVENT_OTHER_MOUSE_DOWN, other_button_number(button)),
        (button, ButtonState::Released) => (CG_EVENT_OTHER_MOUSE_UP, other_button_number(button)),
    }
}

fn drag_event(pressed: &BTreeSet<PointerButton>) -> (u32, u32) {
    if pressed.contains(&PointerButton::Left) {
        (CG_EVENT_LEFT_MOUSE_DRAGGED, 0)
    } else if pressed.contains(&PointerButton::Right) {
        (CG_EVENT_RIGHT_MOUSE_DRAGGED, 1)
    } else if let Some(button) = pressed.first() {
        (CG_EVENT_OTHER_MOUSE_DRAGGED, other_button_number(*button))
    } else {
        (CG_EVENT_MOUSE_MOVED, 0)
    }
}

const fn other_button_number(button: PointerButton) -> u32 {
    match button {
        PointerButton::Middle => 2,
        PointerButton::Back => 3,
        PointerButton::Forward => 4,
        PointerButton::Other(number) => number as u32,
        PointerButton::Left => 0,
        PointerButton::Right => 1,
    }
}

#[allow(clippy::cast_possible_truncation)]
fn rounded_i32(value: f64) -> i32 {
    value
        .round()
        .clamp(f64::from(i32::MIN), f64::from(i32::MAX)) as i32
}

fn enumerate_core_graphics_displays(host_id: HostId) -> Result<Vec<Display>, MacBackendError> {
    let mut count = 0_u32;
    // SAFETY: Null display storage with max=0 requests the active count only.
    let status = unsafe { CGGetActiveDisplayList(0, ptr::null_mut(), &raw mut count) };
    check_cg_status("CGGetActiveDisplayList(count)", status)?;

    let mut ids = vec![0_u32; usize::try_from(count).unwrap_or_default()];
    // SAFETY: `ids` has `count` writable entries and `count` remains valid.
    let status = unsafe { CGGetActiveDisplayList(count, ids.as_mut_ptr(), &raw mut count) };
    check_cg_status("CGGetActiveDisplayList", status)?;
    ids.truncate(usize::try_from(count).unwrap_or(ids.len()));

    ids.into_iter()
        .map(|native_id| display_from_id(host_id, native_id))
        .collect()
}

fn display_from_id(host_id: HostId, native_id: u32) -> Result<Display, MacBackendError> {
    // SAFETY: The ID came from CGGetActiveDisplayList and is valid for these
    // snapshot queries. Values may become stale after this function returns,
    // which is why the daemon refreshes display snapshots on change events.
    let (bounds, pixels_wide, pixels_high, primary, mode_ref) = unsafe {
        (
            CGDisplayBounds(native_id),
            CGDisplayPixelsWide(native_id),
            CGDisplayPixelsHigh(native_id),
            CGDisplayIsMain(native_id) != 0,
            CGDisplayCopyDisplayMode(native_id),
        )
    };
    let mode = (!mode_ref.is_null()).then(|| OwnedCF(mode_ref.cast()));
    let refresh_rate = mode.as_ref().and_then(|mode| {
        // SAFETY: `mode` is a live copied CGDisplayMode reference.
        let value = unsafe { CGDisplayModeGetRefreshRate(mode.0.cast()) };
        (value.is_finite() && value > 0.0).then_some(value)
    });

    let logical_width = bounds.size.width.abs();
    let logical_height = bounds.size.height.abs();
    let pixels_wide =
        u32::try_from(pixels_wide).map_err(|_| MacBackendError::NativeValueOutOfRange {
            operation: "CGDisplayPixelsWide",
        })?;
    let pixels_high =
        u32::try_from(pixels_high).map_err(|_| MacBackendError::NativeValueOutOfRange {
            operation: "CGDisplayPixelsHigh",
        })?;
    let pixels_wide = f64::from(pixels_wide);
    let pixels_high = f64::from(pixels_high);
    let scale_x = pixels_wide / logical_width;
    let scale_y = pixels_high / logical_height;
    let scale_factor = if scale_x.is_finite() && scale_y.is_finite() {
        scale_x.midpoint(scale_y)
    } else {
        1.0
    };

    Ok(Display {
        id: display_id(host_id, native_id),
        host_id,
        name: format!("macOS Display {native_id}"),
        logical_size: Size::new(logical_width, logical_height),
        physical_size: Some(Size::new(pixels_wide, pixels_high)),
        scale_factor,
        refresh_rate,
        native_bounds: Rect::new(
            bounds.origin.x,
            bounds.origin.y,
            logical_width,
            logical_height,
        ),
        primary,
    })
}

fn display_id(host_id: HostId, native_id: u32) -> DisplayId {
    let mut bytes = host_id.into_bytes();
    for (target, source) in bytes[12..].iter_mut().zip(native_id.to_be_bytes()) {
        *target ^= source;
    }
    bytes[0] ^= b'D';
    bytes[1] ^= b'S';
    bytes[2] ^= b'P';
    bytes[3] ^= b'L';
    DisplayId::from_bytes(bytes)
}

fn check_cg_status(operation: &'static str, status: i32) -> Result<(), MacBackendError> {
    if status == CG_ERROR_SUCCESS {
        Ok(())
    } else {
        Err(MacBackendError::NativeStatus {
            operation,
            code: status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_built_in_hid_collection_usages() {
        assert_eq!(device_kind(Some(1), Some(6)), Some(DeviceKind::Keyboard));
        assert_eq!(device_kind(Some(0x0d), Some(5)), Some(DeviceKind::Trackpad));
        assert_eq!(device_kind(Some(0x0c), Some(1)), None);
    }

    #[test]
    fn pointer_mapping_preserves_extra_button_numbers() {
        assert_eq!(
            button_event(PointerButton::Forward, ButtonState::Pressed),
            (CG_EVENT_OTHER_MOUSE_DOWN, 4)
        );
        assert_eq!(
            button_event(PointerButton::Other(9), ButtonState::Released),
            (CG_EVENT_OTHER_MOUSE_UP, 9)
        );
    }

    #[test]
    fn display_identity_is_host_scoped_and_repeatable() {
        let host = HostId::from_bytes([8; 16]);
        assert_eq!(display_id(host, 12), display_id(host, 12));
        assert_ne!(display_id(host, 12), display_id(host, 13));
    }

    #[test]
    fn whole_host_inventory_matches_callback_aggregate_ids() {
        let host = HostId::from_bytes([0x64; 16]);
        let backend = MacInputBackend::new_whole_host_alpha(host);
        let devices = backend.enumerate_devices().expect("aggregate inventory");

        assert_eq!(backend.capture_mode(), MacCaptureMode::WholeHostAlpha);
        assert_eq!(
            backend.suppression_scope(),
            SuppressionScope::WholeHostAlpha
        );
        assert!(!MacInputBackend::selective_suppression_supported());
        assert_eq!(devices.len(), 2);
        assert_eq!(
            devices[0].id,
            derive_whole_host_device_id(host, WholeHostDeviceKind::Keyboard)
        );
        assert_eq!(
            devices[1].id,
            derive_whole_host_device_id(host, WholeHostDeviceKind::Pointer)
        );
        assert!(devices[0].capabilities.keyboard);
        assert!(devices[1].capabilities.pointer);
    }

    #[test]
    fn whole_host_mask_excludes_out_of_band_disable_sentinels() {
        assert_eq!(whole_host_event_mask(), 0x0e40_1cfe);
    }

    #[test]
    fn whole_host_owner_is_exclusive_and_recoverable() {
        let first = WholeHostOwnershipClaim::acquire().expect("first owner");
        assert!(matches!(
            WholeHostOwnershipClaim::acquire(),
            Err(MacBackendError::CaptureRegistrationOwned)
        ));
        drop(first);
        let replacement = WholeHostOwnershipClaim::acquire().expect("replacement owner");
        drop(replacement);
    }

    #[test]
    fn terminal_tap_health_maps_to_shared_faulted_state() {
        let backend = MacInputBackend::new_whole_host_alpha(HostId::from_bytes([0x65; 16]));
        assert_eq!(backend.capture_lifecycle(), CaptureLifecycleState::Idle);
        backend.counters.set_health(CaptureHealth::TapDisabled);
        assert_eq!(backend.capture_lifecycle(), CaptureLifecycleState::Faulted);
    }
}
