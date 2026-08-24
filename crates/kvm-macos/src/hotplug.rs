//! Local display and input-device hotplug detection.
//!
//! Two native sources feed one bounded, coalesced hint channel:
//!
//! - `CGDisplayRegisterReconfigurationCallback` (Core Graphics) for any
//!   display add/remove/move/resolution/DPI change, and
//! - `IOHIDManager` device-matching/removal callbacks for HID attach/detach.
//!
//! Native callbacks run on a Carbon/CG or run-loop thread and therefore do no
//! work of their own: each performs exactly one non-blocking `try_send` into a
//! small bounded raw channel. A dedicated watcher thread owns the `CFRunLoop`,
//! drains the raw channel, and coalesces bursts (a single dock/undock fires
//! many callbacks) into at most one hint per quiet window per kind before
//! offering it to the caller-visible bounded channel.

#[cfg(any(target_os = "macos", test))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(any(target_os = "macos", test))]
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
#[cfg(any(target_os = "macos", test))]
use std::sync::Arc;
use std::time::Duration;
#[cfg(any(target_os = "macos", test))]
use std::time::Instant;

/// Quiet window used to coalesce a native reconfiguration burst into at most
/// one hint per change kind (leading edge plus at most one trailing edge).
pub const HOTPLUG_COALESCE_WINDOW: Duration = Duration::from_millis(200);

/// Maximum number of coalesced hints waiting for the consumer.
///
/// The watcher thread uses a non-blocking send; a full consumer drops the hint
/// (the next physical change produces a fresh one) and counts it in
/// [`HotplugStatistics`] rather than ever blocking.
pub const HOTPLUG_EVENT_CAPACITY: usize = 16;

/// Maximum number of raw observations waiting to be coalesced.
#[cfg(any(target_os = "macos", test))]
const RAW_EVENT_CAPACITY: usize = 64;

/// Number of distinct change kinds tracked by [`ChangeCoalescer`].
#[cfg(any(target_os = "macos", test))]
const CHANGE_KINDS: usize = 3;

/// Coalesced inventory-change hint.
///
/// Hints are directional for devices and coarse for displays: a single
/// `DisplayChanged` covers add, remove, move, resolution, and scale changes
/// because the consumer always answers with a full re-enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryChange {
    /// A display was added, removed, or reconfigured.
    DisplayChanged,
    /// An HID device was attached.
    DeviceAdded,
    /// An HID device was detached.
    DeviceRemoved,
}

impl InventoryChange {
    /// Every kind, in [`InventoryChange::index`] order.
    #[cfg(any(target_os = "macos", test))]
    const KINDS: [Self; CHANGE_KINDS] =
        [Self::DisplayChanged, Self::DeviceAdded, Self::DeviceRemoved];

    /// Returns whether this hint should refresh the device inventory.
    #[must_use]
    pub const fn is_device_change(self) -> bool {
        matches!(self, Self::DeviceAdded | Self::DeviceRemoved)
    }

    #[cfg(any(target_os = "macos", test))]
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
    /// Native observations offered to the bounded raw channel.
    pub raw_events: u64,
    /// Raw observations dropped because the raw channel was full.
    pub raw_events_dropped: u64,
    /// Hints accepted into the caller-visible channel after coalescing.
    pub coalesced_events: u64,
    /// Coalesced hints dropped because the caller-visible channel was full.
    pub coalesced_events_dropped: u64,
    /// Sends that observed an already-disconnected consumer.
    pub channel_disconnects: u64,
    /// Whether IOHID device attach/detach watching is active. Opening the
    /// IOHID manager requires the Input Monitoring grant; without it the
    /// watcher degrades to display-only rather than failing.
    pub device_watch_active: bool,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Default)]
struct HotplugCounters {
    raw_events: AtomicU64,
    raw_events_dropped: AtomicU64,
    coalesced_events: AtomicU64,
    coalesced_events_dropped: AtomicU64,
    channel_disconnects: AtomicU64,
    device_watch_active: AtomicBool,
}

#[cfg(any(target_os = "macos", test))]
impl HotplugCounters {
    fn snapshot(&self) -> HotplugStatistics {
        HotplugStatistics {
            raw_events: self.raw_events.load(Ordering::Relaxed),
            raw_events_dropped: self.raw_events_dropped.load(Ordering::Relaxed),
            coalesced_events: self.coalesced_events.load(Ordering::Relaxed),
            coalesced_events_dropped: self.coalesced_events_dropped.load(Ordering::Relaxed),
            channel_disconnects: self.channel_disconnects.load(Ordering::Relaxed),
            device_watch_active: self.device_watch_active.load(Ordering::Acquire),
        }
    }
}

/// Non-blocking raw dispatch performed by native callbacks.
///
/// `try_send` is the only operation: a full channel counts a drop and returns,
/// so a native callback thread can never block or allocate.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug)]
struct HotplugDispatch {
    sender: SyncSender<InventoryChange>,
    counters: Arc<HotplugCounters>,
}

#[cfg(any(target_os = "macos", test))]
impl HotplugDispatch {
    fn dispatch(&self, change: InventoryChange) {
        self.counters.raw_events.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(change) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.counters
                    .raw_events_dropped
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.counters
                    .channel_disconnects
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(any(target_os = "macos", test))]
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
/// [`ChangeCoalescer::poll_window`]) after the window expires. A continuous
/// stream is therefore bounded to one emission per window per kind.
#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug)]
struct KindWindow {
    last_emission: Option<Instant>,
    pending: bool,
}

#[cfg(any(target_os = "macos", test))]
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
#[cfg(any(target_os = "macos", test))]
#[derive(Debug)]
struct ChangeCoalescer {
    window: Duration,
    kinds: [KindWindow; CHANGE_KINDS],
}

#[cfg(any(target_os = "macos", test))]
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

/// Drains every raw observation, applies coalescing, and offers the surviving
/// hints to the caller-visible channel. Runs only on the watcher thread.
#[cfg(any(target_os = "macos", test))]
fn forward_drained_changes(
    coalescer: &mut ChangeCoalescer,
    raw: &Receiver<InventoryChange>,
    public: &SyncSender<InventoryChange>,
    counters: &HotplugCounters,
    now: Instant,
) {
    while let Ok(change) = raw.try_recv() {
        if let Some(emitted) = coalescer.observe(change, now) {
            offer_coalesced(public, counters, emitted);
        }
    }
    for emitted in coalescer.poll_window(now) {
        offer_coalesced(public, counters, emitted);
    }
}

/// Returns whether a detached startup generation's process-global watcher
/// claim may be reclaimed by a later `start()`.
///
/// A reclaim is honored only while the wedged generation still owns the
/// claim and the grace deadline published when `start()` detached from it
/// has passed. A healthy running watcher has no published reclaim, so it
/// stays exclusive forever.
#[cfg(any(target_os = "macos", test))]
#[must_use]
const fn hotplug_reclaim_expired(
    owner_generation: u32,
    reclaim_generation: u32,
    reclaim_after_ms: u64,
    now_ms: u64,
) -> bool {
    reclaim_after_ms != 0
        && reclaim_generation != 0
        && owner_generation == reclaim_generation
        && now_ms >= reclaim_after_ms
}

#[cfg(target_os = "macos")]
mod watch {
    use std::ffi::c_void;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant, SystemTime};

    use super::{
        forward_drained_changes, hotplug_reclaim_expired, ChangeCoalescer, HotplugCounters,
        HotplugDispatch, HotplugStatistics, InventoryChange, HOTPLUG_COALESCE_WINDOW,
        HOTPLUG_EVENT_CAPACITY, RAW_EVENT_CAPACITY,
    };
    use crate::native::{
        kCFRunLoopDefaultMode, CFRetain, CFRunLoopGetCurrent, CFRunLoopRef, CFRunLoopRunInMode,
        CFRunLoopStop, CFRunLoopWakeUp, CGDisplayRegisterReconfigurationCallback,
        CGDisplayRemoveReconfigurationCallback, IOHIDDeviceRef, IOHIDManagerClose,
        IOHIDManagerCreate, IOHIDManagerOpen, IOHIDManagerRef,
        IOHIDManagerRegisterDeviceMatchingCallback, IOHIDManagerRegisterDeviceRemovalCallback,
        IOHIDManagerScheduleWithRunLoop, IOHIDManagerSetDeviceMatching,
        IOHIDManagerUnscheduleFromRunLoop, OwnedCF, RetainedRunLoop, CG_ERROR_SUCCESS,
        IO_OPTION_NONE,
    };
    use crate::MacBackendError;

    const HOTPLUG_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
    const HOTPLUG_STOP_TIMEOUT: Duration = Duration::from_secs(2);
    /// Bounded `CFRunLoop` interval. It bounds how long a stop request can wait
    /// and provides the coalescer's poll granularity (well under the 200 ms
    /// quiet window).
    const RUN_LOOP_TICK: Duration = Duration::from_millis(50);
    /// Grace after a startup was detached on timeout before its
    /// process-global claim may be reclaimed by a later `start()`.
    const HOTPLUG_OWNERSHIP_RECLAIM_GRACE: Duration = Duration::from_secs(5);

    /// Process-global owner generation of the single-watcher claim; `0`
    /// means unowned. Encoding ownership in one atomic makes every claim
    /// and release a single generation compare-and-swap, so a wedged
    /// startup's late release can never free a replacement watcher's claim.
    static HOTPLUG_WATCH_OWNER_GENERATION: AtomicU32 = AtomicU32::new(0);
    /// Generation a detached (timed-out) startup published as reclaimable.
    static HOTPLUG_WATCH_RECLAIM_GENERATION: AtomicU32 = AtomicU32::new(0);
    /// Epoch milliseconds after which that generation's claim may be
    /// reclaimed; `0` means no reclaim is pending.
    static HOTPLUG_WATCH_RECLAIM_AFTER_MS: AtomicU64 = AtomicU64::new(0);
    static NEXT_HOTPLUG_GENERATION: AtomicU32 = AtomicU32::new(1);

    fn epoch_millis() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            })
    }

    fn next_generation() -> Result<u32, MacBackendError> {
        NEXT_HOTPLUG_GENERATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                MacBackendError::HotplugRuntime(
                    "hotplug watcher generation space is exhausted".into(),
                )
            })
    }

    /// Process-global single-watcher claim so two watchers cannot double-report
    /// the same native burst.
    ///
    /// Invariant: the claim never wedges. `start()` publishes a reclaim
    /// entry for a startup generation it detached from after the bounded
    /// ready timeout, so if that thread stays blocked inside a native call
    /// (and therefore never drops its token), a later `start()` reclaims
    /// the claim once the grace deadline passes. The wedged thread's stale
    /// token then no-ops on release instead of releasing the replacement
    /// watcher's claim, and because the ready receiver was dropped it skips
    /// its run loop, tears down natively, and exits when it eventually
    /// unblocks.
    #[derive(Debug)]
    struct HotplugWatchOwnership {
        generation: u32,
    }

    impl HotplugWatchOwnership {
        fn acquire(generation: u32) -> Result<Self, MacBackendError> {
            loop {
                let owner = HOTPLUG_WATCH_OWNER_GENERATION.load(Ordering::Acquire);
                if owner == 0 {
                    if HOTPLUG_WATCH_OWNER_GENERATION
                        .compare_exchange(0, generation, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return Ok(Self { generation });
                    }
                    // Raced with another starter; re-read the owner.
                    continue;
                }
                let reclaim_generation = HOTPLUG_WATCH_RECLAIM_GENERATION.load(Ordering::Acquire);
                let reclaim_after_ms = HOTPLUG_WATCH_RECLAIM_AFTER_MS.load(Ordering::Acquire);
                if !hotplug_reclaim_expired(
                    owner,
                    reclaim_generation,
                    reclaim_after_ms,
                    epoch_millis(),
                ) {
                    return Err(MacBackendError::HotplugAlreadyRunning);
                }
                // One-shot deadline consumption keeps concurrent starters
                // from double-reclaiming.
                if HOTPLUG_WATCH_RECLAIM_AFTER_MS
                    .compare_exchange(reclaim_after_ms, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    continue;
                }
                if HOTPLUG_WATCH_OWNER_GENERATION
                    .compare_exchange(owner, generation, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Ok(Self { generation });
                }
                // The wedged thread released concurrently; retry normally.
            }
        }
    }

    impl Drop for HotplugWatchOwnership {
        fn drop(&mut self) {
            // Generation-checked release: if this token's generation still
            // owns the claim, free it and drop any reclaim published for it.
            // A token whose claim was reclaimed is stale and must not
            // release the replacement watcher's claim.
            if HOTPLUG_WATCH_OWNER_GENERATION
                .compare_exchange(self.generation, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                && HOTPLUG_WATCH_RECLAIM_GENERATION.load(Ordering::Acquire) == self.generation
            {
                HOTPLUG_WATCH_RECLAIM_GENERATION.store(0, Ordering::Release);
                HOTPLUG_WATCH_RECLAIM_AFTER_MS.store(0, Ordering::Release);
            }
        }
    }

    /// Publishes a bounded reclaim entry so a later `start()` can take the
    /// process-global claim back from a startup thread that stayed blocked
    /// inside a native call past the ready timeout.
    fn publish_reclaim_deadline(generation: u32) {
        let grace_ms =
            u64::try_from(HOTPLUG_OWNERSHIP_RECLAIM_GRACE.as_millis()).unwrap_or(u64::MAX);
        HOTPLUG_WATCH_RECLAIM_GENERATION.store(generation, Ordering::Release);
        HOTPLUG_WATCH_RECLAIM_AFTER_MS
            .store(epoch_millis().saturating_add(grace_ms), Ordering::Release);
    }

    #[derive(Debug)]
    pub(super) struct HotplugCallbackContext {
        /// Revocation flag published before the cross-thread CG display
        /// callback is removed: a callback that observes it returns without
        /// touching the dispatch state. Only the CG display path needs
        /// this — IOHID callbacks are delivered on the watcher's own run
        /// loop, which has stopped by the time the flag matters.
        detached: AtomicBool,
        dispatch: HotplugDispatch,
    }

    impl HotplugCallbackContext {
        #[cfg(test)]
        pub(super) fn new(dispatch: HotplugDispatch) -> Self {
            Self {
                detached: AtomicBool::new(false),
                dispatch,
            }
        }

        /// Revokes callback authority ahead of native callback removal.
        pub(super) fn detach(&self) {
            self.detached.store(true, Ordering::Release);
        }

        fn is_detached(&self) -> bool {
            self.detached.load(Ordering::Acquire)
        }
    }

    #[derive(Debug)]
    struct HotplugWatchSession {
        run_loop: Option<Arc<RetainedRunLoop>>,
        stop_requested: Arc<AtomicBool>,
        thread: Option<JoinHandle<Result<(), MacBackendError>>>,
        done: Receiver<()>,
        outcome: Option<Result<(), MacBackendError>>,
    }

    /// Watches for local display and HID device hotplug and exposes one
    /// bounded, coalesced channel of [`InventoryChange`] hints.
    ///
    /// The watcher owns a dedicated thread with its own `CFRunLoop`. Drop (or
    /// [`MacHotplugWatcher::stop`]) unregisters every native callback, closes
    /// the IOHID manager, and joins the thread with a bounded deadline.
    #[derive(Debug)]
    pub struct MacHotplugWatcher {
        session: Option<HotplugWatchSession>,
        events: Receiver<InventoryChange>,
        counters: Arc<HotplugCounters>,
    }

    impl MacHotplugWatcher {
        /// Starts the watcher with the default 200 ms coalescing window.
        ///
        /// Display watching needs no macOS grant. Device attach/detach
        /// watching requires the Input Monitoring grant; without it the
        /// watcher still starts and reports display hints, and
        /// [`MacHotplugWatcher::statistics`] shows
        /// `device_watch_active: false`.
        ///
        /// # Errors
        ///
        /// Returns an error when a watcher is already running in this process,
        /// the thread cannot be spawned, or the Core Graphics display
        /// reconfiguration registration fails.
        pub fn start() -> Result<Self, MacBackendError> {
            Self::start_with_window(HOTPLUG_COALESCE_WINDOW)
        }

        fn start_with_window(window: Duration) -> Result<Self, MacBackendError> {
            let generation = next_generation()?;
            let ownership = HotplugWatchOwnership::acquire(generation)?;
            let (event_sender, event_receiver) = sync_channel(HOTPLUG_EVENT_CAPACITY);
            let (raw_sender, raw_receiver) = sync_channel(RAW_EVENT_CAPACITY);
            let counters = Arc::new(HotplugCounters::default());
            let (ready_sender, ready_receiver) = sync_channel(1);
            let (done_sender, done_receiver) = sync_channel(1);
            let stop_requested = Arc::new(AtomicBool::new(false));

            let thread_counters = Arc::clone(&counters);
            let thread_stop = Arc::clone(&stop_requested);
            let thread = thread::Builder::new()
                .name("kvm-macos-hotplug".to_owned())
                .spawn(move || {
                    let result = run_hotplug_watch_thread(
                        window,
                        raw_sender,
                        &raw_receiver,
                        &event_sender,
                        &thread_counters,
                        &thread_stop,
                        &ready_sender,
                        ownership,
                    );
                    let _ = done_sender.send(());
                    result
                })
                .map_err(|error| {
                    MacBackendError::HotplugRuntime(format!(
                        "could not spawn hotplug watcher thread: {error}"
                    ))
                })?;

            let run_loop = match ready_receiver.recv_timeout(HOTPLUG_STARTUP_TIMEOUT) {
                Ok(Ok(run_loop)) => run_loop,
                Ok(Err(error)) => {
                    let _ = thread.join();
                    return Err(error);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let _ = thread.join();
                    return Err(MacBackendError::HotplugStartupTerminated);
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Detach: the dropped ready receiver makes the thread skip
                    // its run loop, perform full native cleanup, and release
                    // the claim once it unblocks. If it stays wedged inside a
                    // native call instead, publish a bounded reclaim so a
                    // later `start()` can take the claim back rather than
                    // every start failing forever.
                    publish_reclaim_deadline(generation);
                    drop(thread);
                    return Err(MacBackendError::HotplugStartupTimedOut);
                }
            };

            Ok(Self {
                session: Some(HotplugWatchSession {
                    run_loop: Some(run_loop),
                    stop_requested,
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
        /// Returns an error when teardown exceeds the bounded deadline or the
        /// thread reports a native teardown failure.
        pub fn stop(&mut self) -> Result<(), MacBackendError> {
            let Some(mut session) = self.session.take() else {
                return Ok(());
            };
            session.stop_requested.store(true, Ordering::Release);
            if let Some(run_loop) = &session.run_loop {
                // SAFETY: `RetainedRunLoop` keeps the native object live. CF
                // explicitly supports stopping/waking a run loop cross-thread.
                unsafe {
                    CFRunLoopStop(run_loop.as_ptr());
                    CFRunLoopWakeUp(run_loop.as_ptr());
                }
            }

            if session.thread.is_some() {
                match session.done.recv_timeout(HOTPLUG_STOP_TIMEOUT) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                        if let Some(thread) = session.thread.take() {
                            session.outcome = Some(
                                thread
                                    .join()
                                    .map_err(|_| MacBackendError::HotplugStartupTerminated)
                                    .and_then(|result| result),
                            );
                        }
                        // The thread no longer needs the native run loop;
                        // release the retained reference now.
                        session.run_loop.take();
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        self.session = Some(session);
                        return Err(MacBackendError::HotplugStopTimedOut);
                    }
                }
            }

            session.outcome.take().unwrap_or(Ok(()))
        }
    }

    impl Drop for MacHotplugWatcher {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "startup/registration/teardown paths stay explicit for review"
    )]
    fn run_hotplug_watch_thread(
        window: Duration,
        raw_sender: SyncSender<InventoryChange>,
        raw_receiver: &Receiver<InventoryChange>,
        public_sender: &SyncSender<InventoryChange>,
        counters: &Arc<HotplugCounters>,
        stop_requested: &AtomicBool,
        ready: &SyncSender<Result<Arc<RetainedRunLoop>, MacBackendError>>,
        ownership: HotplugWatchOwnership,
    ) -> Result<(), MacBackendError> {
        // SAFETY: Returns this thread's run loop; null is checked before use.
        let run_loop: CFRunLoopRef = unsafe { CFRunLoopGetCurrent() };
        if run_loop.is_null() {
            let _ = ready.send(Err(MacBackendError::NullResult {
                operation: "CFRunLoopGetCurrent(hotplug)",
            }));
            return Ok(());
        }
        // SAFETY: `run_loop` is non-null. The +1 reference is immediately
        // placed under RAII ownership for every startup/timeout path.
        unsafe { CFRetain(run_loop.cast()) };
        let retained = Arc::new(RetainedRunLoop(run_loop.addr()));

        // SAFETY: Null allocator/options are the documented defaults; the
        // create-rule reference is checked and owned by RAII.
        let manager_ptr: IOHIDManagerRef =
            unsafe { IOHIDManagerCreate(ptr::null(), IO_OPTION_NONE) };
        let manager = match OwnedCF::new(manager_ptr.cast_const(), "IOHIDManagerCreate") {
            Ok(manager) => manager,
            Err(error) => {
                let _ = ready.send(Err(error));
                return Ok(());
            }
        };

        let mut context = Box::new(HotplugCallbackContext {
            detached: AtomicBool::new(false),
            dispatch: HotplugDispatch {
                sender: raw_sender,
                counters: Arc::clone(counters),
            },
        });
        let context_ptr = ptr::from_mut(&mut *context).cast::<c_void>();

        // SAFETY: The manager and boxed context stay live until after the
        // manager is unscheduled/closed and the CG callback is removed below.
        // Null matching selects every HID collection; callbacks perform only
        // one bounded try_send each.
        unsafe {
            IOHIDManagerSetDeviceMatching(manager_ptr, ptr::null());
            IOHIDManagerRegisterDeviceMatchingCallback(
                manager_ptr,
                Some(hotplug_device_matched),
                context_ptr,
            );
            IOHIDManagerRegisterDeviceRemovalCallback(
                manager_ptr,
                Some(hotplug_device_removed),
                context_ptr,
            );
            IOHIDManagerScheduleWithRunLoop(manager_ptr, run_loop, kCFRunLoopDefaultMode);
        }
        // SAFETY: The scheduled manager remains live for the open/run/close
        // cycle on this thread.
        let open_status = unsafe { IOHIDManagerOpen(manager_ptr, IO_OPTION_NONE) };
        // Opening the IOHID manager requires the Input Monitoring grant. A
        // denied or revoked grant degrades the watcher to display-only rather
        // than failing display hotplug detection as well; the manager was
        // never opened, so it is only unscheduled here and released by RAII.
        let device_watch_open = open_status == CG_ERROR_SUCCESS;
        if device_watch_open {
            counters.device_watch_active.store(true, Ordering::Release);
        } else {
            // SAFETY: Reverses the scheduling performed above on this thread.
            unsafe {
                IOHIDManagerUnscheduleFromRunLoop(manager_ptr, run_loop, kCFRunLoopDefaultMode);
            }
        }
        // SAFETY: The boxed context stays live until after this callback is
        // removed below; the returned status is checked.
        let register_status = unsafe {
            CGDisplayRegisterReconfigurationCallback(
                Some(hotplug_display_reconfigured),
                context_ptr,
            )
        };
        if register_status != CG_ERROR_SUCCESS {
            // SAFETY: Reverses scheduling before the context is dropped.
            if device_watch_open {
                unsafe {
                    IOHIDManagerUnscheduleFromRunLoop(manager_ptr, run_loop, kCFRunLoopDefaultMode);
                }
                // SAFETY: The manager was successfully opened above.
                let close_status = unsafe { IOHIDManagerClose(manager_ptr, IO_OPTION_NONE) };
                let _ = ready.send(Err(MacBackendError::NativeStatus {
                    operation: "CGDisplayRegisterReconfigurationCallback",
                    code: register_status,
                }));
                if close_status != CG_ERROR_SUCCESS {
                    return Err(MacBackendError::NativeStatus {
                        operation: "IOHIDManagerClose(hotplug)",
                        code: close_status,
                    });
                }
                return Ok(());
            }
            let _ = ready.send(Err(MacBackendError::NativeStatus {
                operation: "CGDisplayRegisterReconfigurationCallback",
                code: register_status,
            }));
            return Ok(());
        }

        if ready.send(Ok(Arc::clone(&retained))).is_ok() {
            let mut coalescer = ChangeCoalescer::new(window);
            while !stop_requested.load(Ordering::Acquire) {
                // SAFETY: All scheduled sources belong to this live run loop.
                // The bounded interval also detects stop requests made just
                // before entering the run loop; stop/wake makes an active
                // interval return promptly.
                unsafe {
                    CFRunLoopRunInMode(kCFRunLoopDefaultMode, RUN_LOOP_TICK.as_secs_f64(), 0)
                };
                forward_drained_changes(
                    &mut coalescer,
                    raw_receiver,
                    public_sender,
                    counters,
                    Instant::now(),
                );
            }
        }

        // Teardown: revoke callback authority before freeing the context.
        // Unlike the IOHID callbacks (delivered on this thread's run loop,
        // which is no longer running), the CG display callback is delivered
        // on arbitrary threads, so a callback that began just before
        // removal may still be executing when we get here. The order below
        // makes that safe: mark the context detached first (any callback
        // that observes the flag no-ops without touching dispatch state),
        // then remove the registration (after it returns no new callback
        // may start), then — right before the box is freed — wait one
        // bounded grace so an in-flight callback can finish its single
        // non-blocking try_send.
        context.detach();
        let mut teardown_error = None;
        // SAFETY: Removes exactly the (proc, user_info) pair registered
        // above; the boxed context is still live and stays live through the
        // grace period below, so an in-flight callback's reference is valid.
        let remove_status = unsafe {
            CGDisplayRemoveReconfigurationCallback(Some(hotplug_display_reconfigured), context_ptr)
        };
        if remove_status != CG_ERROR_SUCCESS {
            teardown_error.get_or_insert(MacBackendError::NativeStatus {
                operation: "CGDisplayRemoveReconfigurationCallback",
                code: remove_status,
            });
        }
        // SAFETY: Run-loop delivery has stopped; unscheduling prevents any
        // later manager callback from observing the soon-dropped context.
        // A degraded (never-opened) manager was already unscheduled above.
        if device_watch_open {
            // SAFETY: Run-loop delivery has stopped; unscheduling prevents any
            // later manager callback from observing the soon-dropped context.
            unsafe {
                IOHIDManagerUnscheduleFromRunLoop(manager_ptr, run_loop, kCFRunLoopDefaultMode);
            }
            // SAFETY: The manager was successfully opened above.
            let close_status = unsafe { IOHIDManagerClose(manager_ptr, IO_OPTION_NONE) };
            if close_status != CG_ERROR_SUCCESS {
                teardown_error.get_or_insert(MacBackendError::NativeStatus {
                    operation: "IOHIDManagerClose(hotplug)",
                    code: close_status,
                });
            }
        }
        // Bounded grace for an in-flight cross-thread CG callback: one
        // run-loop tick (50 ms) is orders of magnitude longer than the
        // callback's single non-blocking try_send, so a callback that
        // passed the detached check just before removal has returned by
        // the time the sleep ends. IOHID callbacks need no grace: they are
        // delivered on this very thread's run loop, which is no longer
        // running.
        thread::sleep(RUN_LOOP_TICK);
        drop(context);
        drop(manager);
        drop(retained);
        // Keep process-global ownership through native teardown so a
        // replacement watcher cannot overlap this one's callbacks; the
        // release itself is generation-checked (see `HotplugWatchOwnership`).
        drop(ownership);

        teardown_error.map_or(Ok(()), Err)
    }

    pub(super) extern "C" fn hotplug_display_reconfigured(
        _display: u32,
        _flags: u32,
        user_info: *mut c_void,
    ) {
        if user_info.is_null() {
            return;
        }
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: `user_info` is the boxed context owned by the watcher
            // thread. The watcher keeps the box alive until after
            // `CGDisplayRemoveReconfigurationCallback` returns plus a
            // bounded grace sleep, and publishes `detached` before that
            // removal, so this reference — and, when the flag is clear, the
            // single non-blocking try_send below — happen while the box is
            // alive. A callback that observes `detached` returns without
            // touching the dispatch state at all. This callback performs
            // no other native work.
            let context = unsafe { &*user_info.cast::<HotplugCallbackContext>() };
            if context.is_detached() {
                return;
            }
            context.dispatch.dispatch(InventoryChange::DisplayChanged);
        }));
    }

    pub(super) extern "C" fn hotplug_device_matched(
        context: *mut c_void,
        result: i32,
        _sender: *mut c_void,
        _device: IOHIDDeviceRef,
    ) {
        dispatch_hid_change(context, result, InventoryChange::DeviceAdded);
    }

    pub(super) extern "C" fn hotplug_device_removed(
        context: *mut c_void,
        result: i32,
        _sender: *mut c_void,
        _device: IOHIDDeviceRef,
    ) {
        dispatch_hid_change(context, result, InventoryChange::DeviceRemoved);
    }

    fn dispatch_hid_change(context: *mut c_void, result: i32, change: InventoryChange) {
        if context.is_null() || result != 0 {
            return;
        }
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: The pointer refers to the boxed context owned by the
            // watcher thread. Unlike the CG display callback, IOHID
            // callbacks are delivered on the watcher's own run loop, which
            // has stopped and been unscheduled before the box is dropped,
            // so no such callback can race teardown.
            let context = unsafe { &*context.cast::<HotplugCallbackContext>() };
            context.dispatch.dispatch(change);
        }));
    }
}

#[cfg(target_os = "macos")]
pub use watch::MacHotplugWatcher;

/// Safe placeholder compiled on non-macOS hosts.
#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
pub struct MacHotplugWatcher {
    _private: (),
}

#[cfg(not(target_os = "macos"))]
impl MacHotplugWatcher {
    /// No hotplug source exists on this operating system.
    ///
    /// # Errors
    ///
    /// Always returns [`crate::MacBackendError::UnsupportedPlatform`].
    pub fn start() -> Result<Self, crate::MacBackendError> {
        Err(crate::MacBackendError::UnsupportedPlatform)
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
    use std::sync::mpsc::sync_channel;

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
            .observe(InventoryChange::DisplayChanged, start)
            .is_some());
        assert!(coalescer
            .observe(
                InventoryChange::DisplayChanged,
                start + Duration::from_millis(50)
            )
            .is_none());

        let trailing = coalescer.poll_window(start + WINDOW);
        assert_eq!(trailing, vec![InventoryChange::DisplayChanged]);

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
                    .observe(InventoryChange::DeviceAdded, now)
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
    fn coalescer_tracks_kinds_independently() {
        let mut coalescer = ChangeCoalescer::new(WINDOW);
        let start = Instant::now();

        assert_eq!(
            coalescer.observe(InventoryChange::DisplayChanged, start),
            Some(InventoryChange::DisplayChanged)
        );
        assert_eq!(
            coalescer.observe(InventoryChange::DeviceAdded, start),
            Some(InventoryChange::DeviceAdded)
        );
        assert_eq!(
            coalescer.observe(InventoryChange::DeviceRemoved, start),
            Some(InventoryChange::DeviceRemoved)
        );
        // An observation of one kind must not suppress an unrelated kind.
        assert_eq!(
            coalescer.observe(InventoryChange::DeviceAdded, start),
            None,
            "a repeat of the same kind at the same instant is coalesced"
        );
        assert_eq!(
            coalescer.observe(
                InventoryChange::DisplayChanged,
                start + Duration::from_millis(10)
            ),
            None
        );
        assert_eq!(
            coalescer.observe(
                InventoryChange::DeviceAdded,
                start + Duration::from_millis(10)
            ),
            None
        );
        // The suppressed repeats leave exactly one pending trailing edge for
        // the two affected kinds; DeviceRemoved never went pending.
        assert_eq!(
            coalescer.poll_window(start + Duration::from_millis(250)),
            vec![
                InventoryChange::DisplayChanged,
                InventoryChange::DeviceAdded
            ]
        );
        assert!(
            coalescer
                .poll_window(start + Duration::from_millis(400))
                .is_empty(),
            "each trailing edge fires exactly once"
        );
    }

    #[test]
    fn dispatch_never_blocks_or_panics_on_a_full_channel() {
        let capacity = 4_usize;
        let (sender, receiver) = sync_channel(capacity);
        let counters = Arc::new(HotplugCounters::default());
        let dispatch = HotplugDispatch {
            sender,
            counters: Arc::clone(&counters),
        };

        // Fill the raw channel, then keep dispatching well beyond capacity.
        for _ in 0..(capacity * 8) {
            dispatch.dispatch(InventoryChange::DisplayChanged);
        }

        let statistics = counters.snapshot();
        assert_eq!(statistics.raw_events, u64::try_from(capacity * 8).unwrap());
        assert_eq!(
            statistics.raw_events_dropped,
            u64::try_from(capacity * 7).unwrap()
        );
        assert_eq!(
            drain(&receiver).len(),
            capacity,
            "exactly the channel capacity survives"
        );
    }

    #[test]
    fn dispatch_counts_a_disconnected_consumer() {
        let (sender, receiver) = sync_channel(1);
        let counters = Arc::new(HotplugCounters::default());
        let dispatch = HotplugDispatch {
            sender,
            counters: Arc::clone(&counters),
        };
        drop(receiver);

        dispatch.dispatch(InventoryChange::DeviceAdded);
        assert_eq!(counters.snapshot().channel_disconnects, 1);
    }

    #[test]
    fn forward_drained_changes_coalesces_a_full_dock_burst() {
        let (raw_sender, raw_receiver) = sync_channel(RAW_EVENT_CAPACITY);
        let (public_sender, public_receiver) = sync_channel(HOTPLUG_EVENT_CAPACITY);
        let counters = HotplugCounters::default();
        let mut coalescer = ChangeCoalescer::new(WINDOW);
        let start = Instant::now();

        // One physical dock: many display reconfig callbacks plus a device
        // attach, all queued before the watcher thread drains.
        for _ in 0..10 {
            raw_sender
                .try_send(InventoryChange::DisplayChanged)
                .unwrap();
        }
        raw_sender.try_send(InventoryChange::DeviceAdded).unwrap();

        forward_drained_changes(
            &mut coalescer,
            &raw_receiver,
            &public_sender,
            &counters,
            start,
        );
        assert_eq!(
            drain(&public_receiver),
            vec![
                InventoryChange::DisplayChanged,
                InventoryChange::DeviceAdded
            ],
            "the burst collapses to one leading hint per kind"
        );

        // A late settle callback inside the window is re-emitted once, as a
        // single trailing edge, after the quiet window expires.
        raw_sender
            .try_send(InventoryChange::DisplayChanged)
            .unwrap();
        forward_drained_changes(
            &mut coalescer,
            &raw_receiver,
            &public_sender,
            &counters,
            start + Duration::from_millis(50),
        );
        assert!(drain(&public_receiver).is_empty());

        forward_drained_changes(
            &mut coalescer,
            &raw_receiver,
            &public_sender,
            &counters,
            start + WINDOW + Duration::from_millis(10),
        );
        assert_eq!(
            drain(&public_receiver),
            vec![InventoryChange::DisplayChanged]
        );

        let statistics = counters.snapshot();
        assert_eq!(statistics.coalesced_events, 3);
    }

    #[test]
    fn forward_drained_changes_drops_rather_than_blocks_on_a_full_public_channel() {
        let (raw_sender, raw_receiver) = sync_channel(RAW_EVENT_CAPACITY);
        let (public_sender, public_receiver) = sync_channel(1);
        let counters = HotplugCounters::default();
        let mut coalescer = ChangeCoalescer::new(Duration::ZERO);

        let mut delivered = 0_u64;
        for _ in 0..4 {
            raw_sender.try_send(InventoryChange::DeviceAdded).unwrap();
            raw_sender.try_send(InventoryChange::DeviceRemoved).unwrap();
            // A zero window makes every observation immediately eligible, so
            // each round tries to emit into a single-slot channel.
            forward_drained_changes(
                &mut coalescer,
                &raw_receiver,
                &public_sender,
                &counters,
                Instant::now(),
            );
            // Free the slot between rounds like a slow consumer would.
            while public_receiver.try_recv().is_ok() {
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

    #[test]
    fn wedged_startups_release_the_claim_only_after_the_reclaim_grace() {
        // No reclaim published: a healthy watcher stays exclusive forever.
        assert!(!hotplug_reclaim_expired(7, 0, 0, u64::MAX));
        // Published for another generation: not honored against this owner.
        assert!(!hotplug_reclaim_expired(7, 8, 1, u64::MAX));
        // Published for the owner but the grace deadline has not passed.
        assert!(!hotplug_reclaim_expired(7, 7, 5_000, 4_999));
        // Published for the owner and expired: reclaimable.
        assert!(hotplug_reclaim_expired(7, 7, 5_000, 5_000));
    }

    #[cfg(target_os = "macos")]
    mod native_tests {
        use std::ffi::c_void;
        use std::ptr;
        use std::sync::mpsc::sync_channel;
        use std::sync::Arc;

        use super::super::{watch, HotplugCounters, HotplugDispatch, InventoryChange};
        use crate::{MacBackendError, MacHotplugWatcher};

        #[test]
        fn callback_dispatch_rejects_null_or_failed_native_arguments() {
            // Direct invocation of the extern callback bodies with rejected
            // arguments must return without touching any pointer.
            watch::hotplug_display_reconfigured(1, 0, ptr::null_mut());
            watch::hotplug_device_matched(ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut());
            watch::hotplug_device_removed(ptr::null_mut(), 1, ptr::null_mut(), ptr::null_mut());

            let counters = Arc::new(HotplugCounters::default());
            let (sender, receiver) = sync_channel(1);
            let context = watch::HotplugCallbackContext::new(HotplugDispatch {
                sender,
                counters: Arc::clone(&counters),
            });
            let mut boxed = Box::new(context);
            let context_ptr = ptr::from_mut(&mut *boxed).cast::<c_void>();

            watch::hotplug_display_reconfigured(1, 0, context_ptr);
            watch::hotplug_device_matched(context_ptr, 0, ptr::null_mut(), ptr::null_mut());
            watch::hotplug_device_removed(context_ptr, 0, ptr::null_mut(), ptr::null_mut());
            // A non-zero IOKit result is rejected before dispatch.
            watch::hotplug_device_removed(context_ptr, 1, ptr::null_mut(), ptr::null_mut());

            let statistics = counters.snapshot();
            assert_eq!(statistics.raw_events, 3);
            // The capacity-1 raw channel kept exactly one observation; the
            // callbacks themselves never drain it.
            assert_eq!(receiver.try_recv(), Ok(InventoryChange::DisplayChanged));
            assert_eq!(statistics.raw_events_dropped, 2);
            assert!(receiver.try_recv().is_err());
        }

        #[test]
        fn detached_display_callback_no_ops_without_dispatching() {
            // After `detach()`, a late cross-thread CG callback must return
            // before touching the dispatch state: no counter changes and no
            // observation reaches the raw channel.
            let counters = Arc::new(HotplugCounters::default());
            let (sender, receiver) = sync_channel(1);
            let context = watch::HotplugCallbackContext::new(HotplugDispatch {
                sender,
                counters: Arc::clone(&counters),
            });
            let mut boxed = Box::new(context);
            boxed.detach();
            let context_ptr = ptr::from_mut(&mut *boxed).cast::<c_void>();

            watch::hotplug_display_reconfigured(1, 0, context_ptr);

            let statistics = counters.snapshot();
            assert_eq!(statistics.raw_events, 0);
            assert!(receiver.try_recv().is_err());
        }

        #[test]
        fn watcher_starts_stops_and_is_exclusive() {
            let mut watcher = MacHotplugWatcher::start().expect("watcher starts");
            assert!(
                matches!(
                    MacHotplugWatcher::start(),
                    Err(MacBackendError::HotplugAlreadyRunning)
                ),
                "a second watcher in one process is rejected"
            );

            watcher.stop().expect("watcher stops cleanly");
            watcher.stop().expect("stopping twice is idempotent");

            // Ownership is released by teardown, so a replacement may start.
            assert!(MacHotplugWatcher::start().is_ok());
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_watcher_fails_explicitly() {
        assert!(matches!(
            MacHotplugWatcher::start(),
            Err(MacBackendError::UnsupportedPlatform)
        ));
    }
}
