//! Local display and input-device hotplug detection.
//!
//! One dedicated message thread owns a hidden **top-level** window (not the
//! message-only capture window: message-only windows do not receive system
//! broadcasts) and receives:
//!
//! - `WM_DISPLAYCHANGE` — the system broadcast for any display
//!   add/remove/reconfiguration, and
//! - `WM_DEVICECHANGE` with `DBT_DEVICEARRIVAL` / `DBT_DEVICEREMOVECOMPLETE`
//!   after `RegisterDeviceNotificationW` filters delivery to the HID device
//!   interface class.
//!
//! The thread never registers its own Raw Input devices: `RegisterRawInputDevices`
//! replaces the process-wide registration, so an independent `RIDEV_INPUTSINK`
//! registration here would silently steal `WM_INPUT` delivery from the active
//! capture session. The HID device-interface notification covers the same
//! attach/detach transitions without touching that ownership.
//!
//! Recognized messages are coalesced (a single dock/undock can fire several
//! messages) into at most one hint per quiet window per kind before being
//! offered to the caller-visible bounded channel; a `WM_TIMER` tick drives the
//! trailing edge.

#[cfg(any(windows, test))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(any(windows, test))]
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::Duration;
#[cfg(any(windows, test))]
use std::time::Instant;

/// Quiet window used to coalesce a message burst into at most one hint per
/// change kind (leading edge plus at most one trailing edge).
pub const HOTPLUG_COALESCE_WINDOW: Duration = Duration::from_millis(200);

/// Maximum number of coalesced hints waiting for the consumer.
///
/// The watcher thread uses a non-blocking send; a full consumer drops the hint
/// (the next physical change produces a fresh one) and counts it in
/// [`HotplugStatistics`] rather than ever blocking.
pub const HOTPLUG_EVENT_CAPACITY: usize = 16;

// Internal machinery below is exercised by the Windows watcher and by unit
// tests; on other hosts without tests it would be dead code, so it is compiled
// only where it has a caller (mirroring the crate's capture/ownership gating).
#[cfg(any(windows, test))]
const CHANGE_KINDS: usize = 3;

// Message and event values used by the classification logic. They are declared
// locally (rather than imported from the `windows` crate) so the logic compiles
// and is unit-tested on every host; the const assertions under cfg(windows)
// pin them to the `windows` crate constants.
#[cfg(any(windows, test))]
const WM_DISPLAYCHANGE_VALUE: u32 = 0x007E;
#[cfg(any(windows, test))]
const WM_DEVICECHANGE_VALUE: u32 = 0x0219;
#[cfg(any(windows, test))]
const WM_TIMER_VALUE: u32 = 0x0113;
#[cfg(any(windows, test))]
const DBT_DEVICEARRIVAL_VALUE: u32 = 0x8000;
#[cfg(any(windows, test))]
const DBT_DEVICEREMOVECOMPLETE_VALUE: u32 = 0x8004;
#[cfg(any(windows, test))]
const DBT_DEVTYP_DEVICEINTERFACE_VALUE: u32 = 0x0005;

#[cfg(windows)]
const _: () = {
    use windows::Win32::UI::WindowsAndMessaging as wam;
    assert!(WM_DISPLAYCHANGE_VALUE == wam::WM_DISPLAYCHANGE);
    assert!(WM_DEVICECHANGE_VALUE == wam::WM_DEVICECHANGE);
    assert!(WM_TIMER_VALUE == wam::WM_TIMER);
    assert!(DBT_DEVICEARRIVAL_VALUE == wam::DBT_DEVICEARRIVAL);
    assert!(DBT_DEVICEREMOVECOMPLETE_VALUE == wam::DBT_DEVICEREMOVECOMPLETE);
    assert!(DBT_DEVTYP_DEVICEINTERFACE_VALUE == wam::DBT_DEVTYP_DEVICEINTERFACE.0);
};

/// Coalesced inventory-change hint.
///
/// Hints are directional for devices and coarse for displays: a single
/// `DisplayChanged` covers add, remove, move, resolution, and scale changes
/// because the consumer always answers with a full re-enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryChange {
    /// A display was added, removed, or reconfigured.
    DisplayChanged,
    /// An HID device interface arrived.
    DeviceAdded,
    /// An HID device interface was removed.
    DeviceRemoved,
}

impl InventoryChange {
    /// Every kind, in [`InventoryChange::index`] order.
    #[cfg(any(windows, test))]
    const KINDS: [Self; CHANGE_KINDS] =
        [Self::DisplayChanged, Self::DeviceAdded, Self::DeviceRemoved];

    /// Returns whether this hint should refresh the device inventory.
    #[must_use]
    pub const fn is_device_change(self) -> bool {
        matches!(self, Self::DeviceAdded | Self::DeviceRemoved)
    }

    #[cfg(any(windows, test))]
    const fn index(self) -> usize {
        match self {
            Self::DisplayChanged => 0,
            Self::DeviceAdded => 1,
            Self::DeviceRemoved => 2,
        }
    }
}

/// Monotonic hotplug counters used by diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HotplugStatistics {
    /// Messages recognized and offered to coalescing.
    pub raw_events: u64,
    /// Hints accepted into the caller-visible channel after coalescing.
    pub coalesced_events: u64,
    /// Coalesced hints dropped because the caller-visible channel was full.
    pub coalesced_events_dropped: u64,
    /// Sends that observed an already-disconnected consumer.
    pub channel_disconnects: u64,
    /// Whether HID attach/detach notifications are registered. Registering a
    /// device notification can fail on stripped-down sessions; the watcher
    /// then still reports display changes.
    pub device_watch_active: bool,
}

#[cfg(any(windows, test))]
#[derive(Debug, Default)]
struct HotplugCounters {
    raw_events: AtomicU64,
    coalesced_events: AtomicU64,
    coalesced_events_dropped: AtomicU64,
    channel_disconnects: AtomicU64,
    device_watch_active: AtomicBool,
}

#[cfg(any(windows, test))]
impl HotplugCounters {
    fn snapshot(&self) -> HotplugStatistics {
        HotplugStatistics {
            raw_events: self.raw_events.load(Ordering::Relaxed),
            coalesced_events: self.coalesced_events.load(Ordering::Relaxed),
            coalesced_events_dropped: self.coalesced_events_dropped.load(Ordering::Relaxed),
            channel_disconnects: self.channel_disconnects.load(Ordering::Relaxed),
            device_watch_active: self.device_watch_active.load(Ordering::Acquire),
        }
    }
}

/// Classifies one thread message into a hint.
///
/// `event` is the `WPARAM`-derived device-change event code for
/// `WM_DEVICECHANGE` messages and is ignored otherwise. Undirected device
/// broadcasts (for example `DBT_DEVNODES_CHANGED`) carry no direction and are
/// ignored: the registered HID interface filter already delivers precise
/// arrival/removal events.
#[cfg(any(windows, test))]
#[must_use]
const fn classify_hotplug_message(message: u32, event: Option<u32>) -> Option<InventoryChange> {
    match message {
        WM_DISPLAYCHANGE_VALUE => Some(InventoryChange::DisplayChanged),
        WM_DEVICECHANGE_VALUE => match event {
            Some(DBT_DEVICEARRIVAL_VALUE) => Some(InventoryChange::DeviceAdded),
            Some(DBT_DEVICEREMOVECOMPLETE_VALUE) => Some(InventoryChange::DeviceRemoved),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(any(windows, test))]
fn offer_coalesced(
    public: &SyncSender<InventoryChange>,
    counters: &HotplugCounters,
    change: InventoryChange,
) {
    match public.try_send(change) {
        Ok(()) => {
            counters.coalesced_events.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Full(_)) => {
            counters
                .coalesced_events_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Disconnected(_)) => {
            counters.channel_disconnects.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Per-kind leading-edge rate limit with a pending trailing edge.
///
/// The first observation after a quiet window is emitted immediately; further
/// observations inside the window are coalesced and re-emitted once (by
/// [`ChangeCoalescer::poll_window`], driven by the watcher's timer tick) after
/// the window expires. A continuous stream is therefore bounded to one
/// emission per window per kind.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug)]
struct KindWindow {
    last_emission: Option<Instant>,
    pending: bool,
}

#[cfg(any(windows, test))]
impl KindWindow {
    const fn idle() -> Self {
        Self {
            last_emission: None,
            pending: false,
        }
    }

    fn observe(&mut self, window: Duration, now: Instant) -> bool {
        if self
            .last_emission
            .is_some_and(|last| now.saturating_duration_since(last) < window)
        {
            self.pending = true;
            false
        } else {
            self.last_emission = Some(now);
            self.pending = false;
            true
        }
    }

    fn poll(&mut self, window: Duration, now: Instant) -> bool {
        if !self.pending {
            return false;
        }
        let due = self
            .last_emission
            .is_none_or(|last| now.saturating_duration_since(last) >= window);
        if due {
            self.last_emission = Some(now);
            self.pending = false;
            true
        } else {
            false
        }
    }
}

/// Burst coalescer over every [`InventoryChange`] kind.
#[cfg(any(windows, test))]
#[derive(Debug)]
struct ChangeCoalescer {
    window: Duration,
    kinds: [KindWindow; CHANGE_KINDS],
}

#[cfg(any(windows, test))]
impl ChangeCoalescer {
    fn new(window: Duration) -> Self {
        Self {
            window,
            kinds: [KindWindow::idle(); CHANGE_KINDS],
        }
    }

    fn observe(&mut self, change: InventoryChange, now: Instant) -> Option<InventoryChange> {
        self.kinds[change.index()]
            .observe(self.window, now)
            .then_some(change)
    }

    fn poll_window(&mut self, now: Instant) -> Vec<InventoryChange> {
        InventoryChange::KINDS
            .into_iter()
            .filter(|change| self.kinds[change.index()].poll(self.window, now))
            .collect()
    }
}

/// Records one recognized message observation through the coalescer and
/// offers the surviving hint without ever blocking the message thread.
#[cfg(any(windows, test))]
fn note_observation(
    coalescer: &mut ChangeCoalescer,
    public: &SyncSender<InventoryChange>,
    counters: &HotplugCounters,
    change: InventoryChange,
    now: Instant,
) {
    counters.raw_events.fetch_add(1, Ordering::Relaxed);
    if let Some(emitted) = coalescer.observe(change, now) {
        offer_coalesced(public, counters, emitted);
    }
}

#[cfg(windows)]
mod watch {
    // Win32 bindings necessarily cross an FFI boundary. Keep the workspace-wide
    // unsafe prohibition intact everywhere else and audit each block here.
    #![allow(unsafe_code)]

    use std::ffi::c_void;
    use std::mem::size_of;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use windows::core::{w, GUID};
    use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, DispatchMessageW, GetMessageW, GetWindowThreadProcessId,
        KillTimer, PostThreadMessageW, RegisterDeviceNotificationW, SetTimer, TranslateMessage,
        UnregisterDeviceNotification, DBT_DEVTYP_DEVICEINTERFACE, DEVICE_NOTIFY_WINDOW_HANDLE,
        DEV_BROADCAST_DEVICEINTERFACE_W, DEV_BROADCAST_HDR, HDEVNOTIFY, MSG, WM_APP, WM_QUIT,
        WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_POPUP,
    };

    use super::{
        classify_hotplug_message, note_observation, offer_coalesced, ChangeCoalescer,
        HotplugCounters, HotplugStatistics, InventoryChange, DBT_DEVICEARRIVAL_VALUE,
        DBT_DEVICEREMOVECOMPLETE_VALUE, DBT_DEVTYP_DEVICEINTERFACE_VALUE, HOTPLUG_COALESCE_WINDOW,
        HOTPLUG_EVENT_CAPACITY, WM_DEVICECHANGE_VALUE, WM_TIMER_VALUE,
    };
    use crate::native::{binding_error, last_api_error};
    use crate::WindowsBackendError;

    const HOTPLUG_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
    const HOTPLUG_STOP_TIMEOUT: Duration = Duration::from_secs(2);
    /// Private, generation-checked stop message for the watcher thread.
    const HOTPLUG_STOP_MESSAGE: u32 = WM_APP + 0x4f;
    const HOTPLUG_TIMER_ID: usize = 1;
    /// Timer tick driving the coalescer's trailing edge (well under the
    /// 200 ms quiet window).
    const HOTPLUG_POLL_INTERVAL_MS: u32 = 50;
    /// `GUID_DEVINTERFACE_HID` — the device-interface class covering HID
    /// collections exposed by keyboards and mice.
    const GUID_DEVINTERFACE_HID: GUID = GUID::from_values(
        0x4D1E_55B2,
        0xF16F,
        0x11CF,
        [0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30],
    );

    static HOTPLUG_WATCH_OWNED: AtomicBool = AtomicBool::new(false);
    static NEXT_HOTPLUG_GENERATION: AtomicU32 = AtomicU32::new(1);

    /// Process-global single-watcher claim so two watchers cannot double-report
    /// the same native burst.
    #[derive(Debug)]
    struct HotplugWatchOwnership;

    impl HotplugWatchOwnership {
        fn acquire() -> Result<Self, WindowsBackendError> {
            HOTPLUG_WATCH_OWNED
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map(|_| Self)
                .map_err(|_| WindowsBackendError::HotplugAlreadyRunning)
        }
    }

    impl Drop for HotplugWatchOwnership {
        fn drop(&mut self) {
            HOTPLUG_WATCH_OWNED.store(false, Ordering::Release);
        }
    }

    fn next_generation() -> Result<u32, WindowsBackendError> {
        NEXT_HOTPLUG_GENERATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                WindowsBackendError::HotplugRuntime(
                    "hotplug watcher generation space is exhausted".into(),
                )
            })
    }

    /// Native resources owned by the watcher thread, torn down in reverse
    /// order on every exit path.
    #[derive(Debug)]
    struct HotplugWindow {
        window: HWND,
        notification: Option<HDEVNOTIFY>,
        timer: usize,
    }

    impl HotplugWindow {
        fn teardown(&mut self) -> Result<(), WindowsBackendError> {
            let mut first_error = None;
            if self.timer != 0 {
                // SAFETY: the timer was created by this thread for this window.
                if let Err(error) = unsafe { KillTimer(Some(self.window), self.timer) } {
                    first_error.get_or_insert(binding_error("KillTimer(hotplug)", &error));
                }
                self.timer = 0;
            }
            if let Some(notification) = self.notification.take() {
                // SAFETY: the handle was returned by RegisterDeviceNotificationW.
                if let Err(error) = unsafe { UnregisterDeviceNotification(notification) } {
                    first_error.get_or_insert_with(|| {
                        binding_error("UnregisterDeviceNotification(hotplug)", &error)
                    });
                }
            }
            // SAFETY: the window was created and is owned by this thread.
            if let Err(error) = unsafe { DestroyWindow(self.window) } {
                first_error.get_or_insert(binding_error("DestroyWindow(hotplug)", &error));
            }
            first_error.map_or(Ok(()), Err)
        }
    }

    impl Drop for HotplugWindow {
        fn drop(&mut self) {
            let _ = self.teardown();
        }
    }

    #[derive(Debug)]
    struct HotplugWatchSession {
        thread_id: u32,
        generation: u32,
        thread: Option<JoinHandle<Result<(), WindowsBackendError>>>,
        done: Receiver<()>,
        outcome: Option<Result<(), WindowsBackendError>>,
    }

    /// Watches for local display and HID device hotplug and exposes one
    /// bounded, coalesced channel of [`InventoryChange`] hints.
    ///
    /// The watcher owns a dedicated message thread with a hidden top-level
    /// window. Drop (or [`WindowsHotplugWatcher::stop`]) unregisters the
    /// device notification, kills its timer, destroys the window, and joins
    /// the thread with a bounded deadline.
    #[derive(Debug)]
    pub struct WindowsHotplugWatcher {
        session: Option<HotplugWatchSession>,
        events: Receiver<InventoryChange>,
        counters: Arc<HotplugCounters>,
    }

    impl WindowsHotplugWatcher {
        /// Starts the watcher with the default 200 ms coalescing window.
        ///
        /// Display watching needs only a window on an interactive desktop.
        /// Device attach/detach watching additionally registers the HID
        /// device-interface notification; if that registration fails, the
        /// watcher still starts and reports display hints, and
        /// [`WindowsHotplugWatcher::statistics`] shows
        /// `device_watch_active: false`.
        ///
        /// # Errors
        ///
        /// Returns an error when a watcher is already running in this
        /// process, the thread cannot be spawned, or the hidden window cannot
        /// be created.
        pub fn start() -> Result<Self, WindowsBackendError> {
            let ownership = HotplugWatchOwnership::acquire()?;
            let generation = next_generation()?;
            let (event_sender, event_receiver) = sync_channel(HOTPLUG_EVENT_CAPACITY);
            let counters = Arc::new(HotplugCounters::default());
            let (ready_sender, ready_receiver) = sync_channel(1);
            let (done_sender, done_receiver) = sync_channel(1);

            let thread_counters = Arc::clone(&counters);
            let thread = thread::Builder::new()
                .name("kvm-windows-hotplug".into())
                .spawn(move || {
                    let result = run_hotplug_watch_thread(
                        generation,
                        &event_sender,
                        &thread_counters,
                        &ready_sender,
                        ownership,
                    );
                    let _ = done_sender.send(());
                    result
                })
                .map_err(|error| {
                    WindowsBackendError::HotplugRuntime(format!(
                        "could not spawn hotplug watcher thread: {error}"
                    ))
                })?;

            let thread_id = match ready_receiver.recv_timeout(HOTPLUG_STARTUP_TIMEOUT) {
                Ok(Ok(thread_id)) => thread_id,
                Ok(Err(error)) => {
                    let _ = thread.join();
                    return Err(error);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let _ = thread.join();
                    return Err(WindowsBackendError::HotplugRuntime(
                        "hotplug watcher thread ended before publishing its thread ID".into(),
                    ));
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Detach: the dropped ready receiver makes the thread tear
                    // itself down and release process-global ownership.
                    drop(thread);
                    return Err(WindowsBackendError::HotplugRuntime(format!(
                        "hotplug watcher startup exceeded {} seconds",
                        HOTPLUG_STARTUP_TIMEOUT.as_secs()
                    )));
                }
            };

            Ok(Self {
                session: Some(HotplugWatchSession {
                    thread_id,
                    generation,
                    thread: Some(thread),
                    done: done_receiver,
                    outcome: None,
                }),
                events: event_receiver,
                counters,
            })
        }

        /// Returns the next coalesced hint without blocking.
        #[must_use]
        pub fn poll(&self) -> Option<InventoryChange> {
            self.events.try_recv().ok()
        }

        /// Returns counters for the current or most recent watcher.
        #[must_use]
        pub fn statistics(&self) -> HotplugStatistics {
            self.counters.snapshot()
        }

        /// Stops the watcher and joins its thread. Stopping a stopped watcher
        /// is an idempotent success.
        ///
        /// # Errors
        ///
        /// Returns an error when both stop signals fail, teardown exceeds the
        /// bounded deadline, or the thread reports a native teardown failure.
        pub fn stop(&mut self) -> Result<(), WindowsBackendError> {
            let Some(mut session) = self.session.take() else {
                return Ok(());
            };
            let signal_error = signal_hotplug_stop(&session).err();
            match session.done.recv_timeout(HOTPLUG_STOP_TIMEOUT) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    if let Some(thread) = session.thread.take() {
                        session.outcome = Some(
                            thread
                                .join()
                                .map_err(|_| {
                                    WindowsBackendError::HotplugRuntime(
                                        "hotplug watcher thread panicked".into(),
                                    )
                                })
                                .and_then(|result| result),
                        );
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.session = Some(session);
                    return Err(signal_error.unwrap_or_else(|| {
                        WindowsBackendError::HotplugRuntime(format!(
                            "hotplug watcher shutdown exceeded {} seconds",
                            HOTPLUG_STOP_TIMEOUT.as_secs()
                        ))
                    }));
                }
            }
            session.outcome.take().unwrap_or(Ok(()))
        }
    }

    impl Drop for WindowsHotplugWatcher {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }

    fn signal_hotplug_stop(session: &HotplugWatchSession) -> Result<(), WindowsBackendError> {
        // SAFETY: the thread owns a live message queue (it published its ID
        // after creating the window and timer). The generation-checked
        // wParam prevents a stale stop from ending a replacement watcher when
        // Windows later reuses the numeric thread ID.
        let generation = WPARAM(session.generation as usize);
        match unsafe {
            PostThreadMessageW(
                session.thread_id,
                HOTPLUG_STOP_MESSAGE,
                generation,
                LPARAM(0),
            )
        } {
            Ok(()) => Ok(()),
            Err(stop_error) => {
                // SAFETY: WM_QUIT is the documented second wake path.
                unsafe { PostThreadMessageW(session.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) }
                    .map_err(|quit_error| {
                        WindowsBackendError::HotplugRuntime(format!(
                            "both hotplug stop signals failed: stop={stop_error}; quit={quit_error}"
                        ))
                    })
            }
        }
    }

    fn run_hotplug_watch_thread(
        generation: u32,
        public_sender: &SyncSender<InventoryChange>,
        counters: &Arc<HotplugCounters>,
        ready: &SyncSender<Result<u32, WindowsBackendError>>,
        ownership: HotplugWatchOwnership,
    ) -> Result<(), WindowsBackendError> {
        let window = match create_hotplug_window() {
            Ok(window) => window,
            Err(error) => {
                let _ = ready.send(Err(error));
                return Ok(());
            }
        };
        let mut native = HotplugWindow {
            window,
            notification: None,
            timer: 0,
        };

        if let Ok(notification) = register_hid_interface_notifications(native.window) {
            native.notification = Some(notification);
            counters.device_watch_active.store(true, Ordering::Release);
        }
        // A failed HID interface registration degrades the watcher to
        // display-only watching rather than failing display hotplug detection
        // too; statistics report `device_watch_active: false`.

        if let Err(error) = register_timer(&mut native) {
            let _ = ready.send(Err(error));
            return Ok(());
        }
        // SAFETY: `native.window` is live. Passing no process-ID pointer
        // requests only the owning thread's ID.
        let thread_id = unsafe { GetWindowThreadProcessId(native.window, None) };
        if thread_id == 0 {
            let _ = ready.send(Err(last_api_error("GetWindowThreadProcessId(hotplug)")));
            return native.teardown();
        }

        if ready.send(Ok(thread_id)).is_err() {
            let teardown = native.teardown();
            teardown?;
            return Err(WindowsBackendError::HotplugRuntime(
                "hotplug watcher owner disappeared during startup".into(),
            ));
        }

        let loop_result = hotplug_message_loop(generation, public_sender, counters);
        let teardown_result = native.teardown();
        // Keep process-global ownership through native teardown so a
        // replacement watcher cannot overlap this one's window.
        drop(ownership);
        match (loop_result, teardown_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(loop_error), Err(teardown_error)) => Err(WindowsBackendError::HotplugRuntime(
                format!("{loop_error}; native teardown also failed: {teardown_error}"),
            )),
        }
    }

    fn create_hotplug_window() -> Result<HWND, WindowsBackendError> {
        // SAFETY: static, null-terminated UTF-16 class and title; `STATIC` is
        // a system class. The window is top-level (no parent) and never shown:
        // top-level windows receive system broadcasts such as
        // WM_DISPLAYCHANGE even while hidden, which message-only windows do
        // not. Recognized messages are consumed by the message loop before
        // dispatch, so the system window procedure is never relied upon.
        unsafe {
            CreateWindowExW(
                WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                w!("STATIC"),
                w!("Software KVM Hotplug Watch"),
                WS_POPUP,
                0,
                0,
                0,
                0,
                None,
                None,
                None,
                None,
            )
        }
        .map_err(|error| binding_error("CreateWindowExW(hotplug)", &error))
    }

    fn register_hid_interface_notifications(
        window: HWND,
    ) -> Result<HDEVNOTIFY, WindowsBackendError> {
        // The filter advertises only its fixed header (through
        // dbcc_classguid): dbcc_name is a zero-length tail for registration.
        #[allow(clippy::cast_possible_truncation)] // struct is far below u32::MAX
        const DEVICEINTERFACE_FILTER_BYTES: u32 =
            (size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>() - size_of::<u16>()) as u32;
        let filter = DEV_BROADCAST_DEVICEINTERFACE_W {
            dbcc_size: DEVICEINTERFACE_FILTER_BYTES,
            dbcc_devicetype: DBT_DEVTYP_DEVICEINTERFACE_VALUE,
            dbcc_reserved: 0,
            dbcc_classguid: GUID_DEVINTERFACE_HID,
            dbcc_name: [0; 1],
        };
        // SAFETY: `window` was created on this thread; the filter advertises
        // exactly its header size and remains alive for the call.
        unsafe {
            RegisterDeviceNotificationW(
                HANDLE(window.0),
                (&raw const filter).cast::<c_void>(),
                DEVICE_NOTIFY_WINDOW_HANDLE,
            )
        }
        .map_err(|error| binding_error("RegisterDeviceNotificationW(hotplug)", &error))
    }

    fn register_timer(native: &mut HotplugWindow) -> Result<(), WindowsBackendError> {
        // SAFETY: the window belongs to this thread; no callback procedure is
        // requested, so WM_TIMER is delivered through the message queue.
        let timer = unsafe {
            SetTimer(
                Some(native.window),
                HOTPLUG_TIMER_ID,
                HOTPLUG_POLL_INTERVAL_MS,
                None,
            )
        };
        if timer == 0 {
            return Err(last_api_error("SetTimer(hotplug)"));
        }
        native.timer = timer;
        Ok(())
    }

    fn hotplug_message_loop(
        generation: u32,
        public_sender: &SyncSender<InventoryChange>,
        counters: &HotplugCounters,
    ) -> Result<(), WindowsBackendError> {
        let mut coalescer = ChangeCoalescer::new(HOTPLUG_COALESCE_WINDOW);
        let mut message = MSG::default();
        loop {
            // SAFETY: `message` is valid writable storage. A null HWND and
            // zero filters request every message for this watcher thread.
            let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) };
            if result.0 == -1 {
                return Err(last_api_error("GetMessageW(hotplug)"));
            }
            if result.0 == 0
                || (message.message == HOTPLUG_STOP_MESSAGE
                    && message.wParam.0 == generation as usize)
            {
                return Ok(());
            }
            let event = u32::try_from(message.wParam.0).ok();
            if message.message == WM_TIMER_VALUE {
                // Timer tick: drive the coalescer's trailing edge.
                for change in coalescer.poll_window(Instant::now()) {
                    offer_coalesced(public_sender, counters, change);
                }
                continue;
            }
            if message.message == WM_DEVICECHANGE_VALUE
                && matches!(
                    event,
                    Some(DBT_DEVICEARRIVAL_VALUE | DBT_DEVICEREMOVECOMPLETE_VALUE)
                )
                && !device_interface_event(&message)
            {
                // Directional event without a matching device-interface
                // header: not from our HID registration; ignore it.
                continue;
            }
            if let Some(change) = classify_hotplug_message(message.message, event) {
                note_observation(
                    &mut coalescer,
                    public_sender,
                    counters,
                    change,
                    Instant::now(),
                );
                continue;
            }
            // Unrecognized messages take the ordinary dispatch path; the
            // system STATIC window procedure ignores them.
            // SAFETY: `message` was initialized by GetMessageW; both calls are
            // synchronous and the record stays alive for them.
            unsafe {
                let _ = TranslateMessage(&raw const message);
                let _ = DispatchMessageW(&raw const message);
            }
        }
    }

    fn device_interface_event(message: &MSG) -> bool {
        if message.lParam.0 == 0 {
            return false;
        }
        // SAFETY: Win32 supplies a live DEV_BROADCAST_HDR for WM_DEVICECHANGE
        // lParam; the header is read once and no pointer is retained.
        let header = message.lParam.0 as *const DEV_BROADCAST_HDR;
        unsafe { (*header).dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE }
    }
}

#[cfg(windows)]
pub use watch::WindowsHotplugWatcher;

/// Safe placeholder compiled on non-Windows hosts.
#[cfg(not(windows))]
#[derive(Debug)]
pub struct WindowsHotplugWatcher {
    _private: (),
}

#[cfg(not(windows))]
impl WindowsHotplugWatcher {
    /// No hotplug source exists on this operating system.
    ///
    /// # Errors
    ///
    /// Always returns [`crate::WindowsBackendError::UnsupportedPlatform`].
    pub fn start() -> Result<Self, crate::WindowsBackendError> {
        Err(crate::WindowsBackendError::UnsupportedPlatform)
    }

    /// Never produces a hint on this operating system.
    #[must_use]
    #[allow(clippy::unused_self)] // keeps the platform API uniform
    pub fn poll(&self) -> Option<InventoryChange> {
        None
    }

    /// Returns zeroed counters on this operating system.
    #[must_use]
    #[allow(clippy::unused_self)] // keeps the platform API uniform
    pub fn statistics(&self) -> HotplugStatistics {
        HotplugStatistics::default()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{sync_channel, Receiver};

    use super::*;

    const WINDOW: Duration = Duration::from_millis(200);

    fn drain(receiver: &Receiver<InventoryChange>) -> Vec<InventoryChange> {
        let mut events = Vec::new();
        while let Ok(change) = receiver.try_recv() {
            events.push(change);
        }
        events
    }

    #[test]
    fn message_classification_covers_both_sources() {
        assert_eq!(
            classify_hotplug_message(WM_DISPLAYCHANGE_VALUE, None),
            Some(InventoryChange::DisplayChanged)
        );
        assert_eq!(
            classify_hotplug_message(WM_DEVICECHANGE_VALUE, Some(DBT_DEVICEARRIVAL_VALUE)),
            Some(InventoryChange::DeviceAdded)
        );
        assert_eq!(
            classify_hotplug_message(WM_DEVICECHANGE_VALUE, Some(DBT_DEVICEREMOVECOMPLETE_VALUE)),
            Some(InventoryChange::DeviceRemoved)
        );
        assert_eq!(DBT_DEVTYP_DEVICEINTERFACE_VALUE, 5);
        // Undirected device broadcasts carry no direction and are ignored.
        assert_eq!(
            classify_hotplug_message(WM_DEVICECHANGE_VALUE, Some(7)),
            None
        );
        assert_eq!(classify_hotplug_message(WM_DEVICECHANGE_VALUE, None), None);
        assert_eq!(classify_hotplug_message(WM_TIMER_VALUE, None), None);
        assert_eq!(classify_hotplug_message(0x0102, None), None);
    }

    #[test]
    fn coalescer_emits_leading_edge_and_suppresses_burst() {
        let mut coalescer = ChangeCoalescer::new(WINDOW);
        let start = Instant::now();

        assert_eq!(
            coalescer.observe(InventoryChange::DisplayChanged, start),
            Some(InventoryChange::DisplayChanged)
        );
        for offset in [10, 40, 80, 150] {
            assert_eq!(
                coalescer.observe(
                    InventoryChange::DisplayChanged,
                    start + Duration::from_millis(offset)
                ),
                None,
                "burst members inside the quiet window must be coalesced"
            );
        }
        assert!(
            coalescer
                .poll_window(start + Duration::from_millis(150))
                .is_empty(),
            "no trailing emission before the quiet window expires"
        );
    }

    #[test]
    fn coalescer_emits_one_trailing_edge_after_the_quiet_window() {
        let mut coalescer = ChangeCoalescer::new(WINDOW);
        let start = Instant::now();

        assert!(coalescer
            .observe(InventoryChange::DeviceAdded, start)
            .is_some());
        assert!(coalescer
            .observe(
                InventoryChange::DeviceAdded,
                start + Duration::from_millis(50)
            )
            .is_none());

        assert_eq!(
            coalescer.poll_window(start + WINDOW),
            vec![InventoryChange::DeviceAdded]
        );
        assert!(
            coalescer.poll_window(start + WINDOW * 4).is_empty(),
            "the trailing edge fires exactly once"
        );
    }

    #[test]
    fn coalescer_bounds_a_continuous_stream_to_one_emission_per_window() {
        let mut coalescer = ChangeCoalescer::new(WINDOW);
        let start = Instant::now();

        let mut emissions = 0_usize;
        for step in 0..1000 {
            let now = start + Duration::from_millis(step * 10);
            emissions += usize::from(
                coalescer
                    .observe(InventoryChange::DeviceRemoved, now)
                    .is_some(),
            );
            emissions += coalescer.poll_window(now).len();
        }
        // Ten seconds of continuous activity at most one emission per 200 ms
        // window (50 windows) plus the leading edge.
        assert!(
            emissions <= 51,
            "a continuous stream must stay bounded: {emissions} emissions"
        );
        assert!(
            emissions >= 50,
            "at least one emission per window: {emissions}"
        );
    }

    #[test]
    fn note_observation_coalesces_a_dock_burst_and_never_blocks() {
        let (sender, receiver) = sync_channel(HOTPLUG_EVENT_CAPACITY);
        let counters = HotplugCounters::default();
        let mut coalescer = ChangeCoalescer::new(WINDOW);
        let start = Instant::now();

        // One dock: a display burst plus a device arrival, as the message
        // loop would observe them.
        for _ in 0..8 {
            note_observation(
                &mut coalescer,
                &sender,
                &counters,
                InventoryChange::DisplayChanged,
                start,
            );
        }
        note_observation(
            &mut coalescer,
            &sender,
            &counters,
            InventoryChange::DeviceAdded,
            start,
        );
        assert_eq!(
            drain(&receiver),
            vec![
                InventoryChange::DisplayChanged,
                InventoryChange::DeviceAdded
            ]
        );
        assert_eq!(counters.snapshot().raw_events, 9);
        assert_eq!(counters.snapshot().coalesced_events, 2);

        // The trailing edge lands after the quiet window expires.
        note_observation(
            &mut coalescer,
            &sender,
            &counters,
            InventoryChange::DisplayChanged,
            start + Duration::from_millis(50),
        );
        for change in coalescer.poll_window(start + WINDOW + Duration::from_millis(5)) {
            offer_coalesced(&sender, &counters, change);
        }
        assert_eq!(drain(&receiver), vec![InventoryChange::DisplayChanged]);
    }

    #[test]
    fn note_observation_drops_rather_than_blocks_on_a_full_channel() {
        let (sender, receiver) = sync_channel(1);
        let counters = HotplugCounters::default();
        let mut coalescer = ChangeCoalescer::new(Duration::ZERO);

        let mut delivered = 0_u64;
        for _ in 0..4 {
            note_observation(
                &mut coalescer,
                &sender,
                &counters,
                InventoryChange::DeviceAdded,
                Instant::now(),
            );
            note_observation(
                &mut coalescer,
                &sender,
                &counters,
                InventoryChange::DeviceRemoved,
                Instant::now(),
            );
            // Free the single slot between rounds like a slow consumer would.
            while receiver.try_recv().is_ok() {
                delivered += 1;
            }
        }

        let statistics = counters.snapshot();
        assert!(statistics.coalesced_events_dropped > 0);
        assert_eq!(statistics.coalesced_events, delivered);
        assert_eq!(
            statistics.coalesced_events + statistics.coalesced_events_dropped,
            8
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_watcher_fails_explicitly() {
        assert!(matches!(
            WindowsHotplugWatcher::start(),
            Err(crate::WindowsBackendError::UnsupportedPlatform)
        ));
    }
}
