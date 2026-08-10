//! Fail-open native capture callback bridge and fail-closed lifecycle owner.

use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use kvm_daemon::{
    CaptureCallback, CaptureDisposition, CaptureLifecycleState, CapturedInput, InputCaptureBackend,
    OutboundPeer, OutputInjectionBackend, PeerManager, PeerManagerError,
};
use kvm_types::Point;

/// Serialized routing authority used by the native callback bridge.
///
/// A `kvm-daemon::PeerManager` adapter can forward these operations to
/// `route_selected_capture`, `native_capture_discontinued`, and
/// `rearm_native_capture`, supplying the passed monotonic timestamp.
pub trait NativeCaptureRouter: Send {
    type Error;

    /// Routes exactly one captured input record synchronously.
    fn route_capture(&mut self, captured: CapturedInput, now_ns: u64) -> CaptureDisposition;

    /// Closes the manager-side capture gate and performs discontinuity cleanup.
    ///
    /// Implementations must publish their gate before doing fallible cleanup,
    /// including when this operation returns an error.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined, caller-redacted cleanup failure.
    fn gate_capture(&mut self, now_ns: u64) -> Result<(), Self::Error>;

    /// Opens the manager-side capture gate for a verified native generation.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined, caller-redacted rearm failure.
    fn rearm_capture(
        &mut self,
        lifecycle: CaptureLifecycleState,
        now_ns: u64,
    ) -> Result<(), Self::Error>;

    /// Returns whether the local host owns current pointer authority.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined, caller-redacted observation error.
    fn local_pointer_authority(&self) -> Result<bool, Self::Error>;

    /// Returns the trusted native landing coordinate for local authority.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined observation error.
    fn local_pointer_position(&self) -> Result<Option<Point>, Self::Error> {
        Ok(None)
    }

    /// Observes a native cursor coordinate for destination-side portal
    /// detection without routing or suppressing an input event.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined coordination error.
    fn observe_pointer_position(
        &mut self,
        _position: Point,
        _now_ns: u64,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

impl<I, O> NativeCaptureRouter for PeerManager<I, O>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    type Error = PeerManagerError;

    fn route_capture(&mut self, captured: CapturedInput, now_ns: u64) -> CaptureDisposition {
        self.route_selected_capture(captured, now_ns).disposition()
    }

    fn gate_capture(&mut self, now_ns: u64) -> Result<(), Self::Error> {
        self.native_capture_discontinued(now_ns)
    }

    fn rearm_capture(
        &mut self,
        lifecycle: CaptureLifecycleState,
        _now_ns: u64,
    ) -> Result<(), Self::Error> {
        self.rearm_native_capture(lifecycle)
    }

    fn local_pointer_authority(&self) -> Result<bool, Self::Error> {
        self.local_pointer_authority()
    }

    fn local_pointer_position(&self) -> Result<Option<Point>, Self::Error> {
        self.local_pointer_position()
    }

    fn observe_pointer_position(
        &mut self,
        position: Point,
        now_ns: u64,
    ) -> Result<bool, Self::Error> {
        self.observe_native_pointer(position, now_ns)
    }
}

/// Coarse runtime-owned native capture state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCaptureState {
    /// The callback is forced to pass all input through locally.
    LocalOnly,
    /// Native lifecycle and manager routing gates are both armed.
    Armed,
    /// A lifecycle or teardown fault occurred; routing remains gated.
    Degraded,
    /// Capture teardown completed and routing remains gated.
    Stopped,
}

/// Coarse, redacted supervisor failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCaptureErrorKind {
    InvalidState,
    Gate,
    Start,
    Lifecycle,
    Rearm,
    Stop,
    Cursor,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeCaptureMetrics {
    pub(crate) observed: u64,
    pub(crate) suppressed: u64,
    pub(crate) allowed_local: u64,
    pub(crate) lock_contention: u64,
    pub(crate) callback_panics: u64,
    pub(crate) pointer_observations: u64,
    pub(crate) pointer_transitions: u64,
    pub(crate) pointer_observation_failures: u64,
    pub(crate) cursor_hides: u64,
    pub(crate) cursor_shows: u64,
    pub(crate) cursor_warps: u64,
}

#[derive(Default)]
struct SharedCaptureMetrics {
    observed: AtomicU64,
    suppressed: AtomicU64,
    allowed_local: AtomicU64,
    lock_contention: AtomicU64,
    callback_panics: AtomicU64,
}

/// Native-error-, input-, identity-, and timing-redacted supervisor failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NativeCaptureError {
    kind: NativeCaptureErrorKind,
}

impl NativeCaptureError {
    const fn new(kind: NativeCaptureErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> NativeCaptureErrorKind {
        self.kind
    }
}

impl fmt::Debug for NativeCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeCaptureError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for NativeCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            NativeCaptureErrorKind::InvalidState => {
                "native capture state does not permit this operation"
            }
            NativeCaptureErrorKind::Gate => "native capture routing could not be gated",
            NativeCaptureErrorKind::Start => "native capture could not be started",
            NativeCaptureErrorKind::Lifecycle => "native capture lifecycle is not running",
            NativeCaptureErrorKind::Rearm => "native capture routing could not be rearmed",
            NativeCaptureErrorKind::Stop => "native capture could not be stopped",
            NativeCaptureErrorKind::Cursor => "native cursor visibility could not be updated",
        })
    }
}

impl std::error::Error for NativeCaptureError {}

/// Owns one native backend and its serialized, non-blocking callback bridge.
pub struct NativeCaptureSupervisor<B: InputCaptureBackend, R> {
    backend: B,
    router: Arc<Mutex<R>>,
    callback_armed: Arc<AtomicBool>,
    metrics: Arc<SharedCaptureMetrics>,
    state: NativeCaptureState,
    cursor_visible: bool,
    local_warp_pending: bool,
    pointer_observations: u64,
    pointer_transitions: u64,
    pointer_observation_failures: u64,
    cursor_hides: u64,
    cursor_shows: u64,
    cursor_warps: u64,
}

impl<B: InputCaptureBackend, R> Drop for NativeCaptureSupervisor<B, R> {
    fn drop(&mut self) {
        // A native backend may retain its callback while teardown is delayed or
        // fails. Revoke suppression authority before any backend field is
        // dropped so that such a callback can only fail open.
        self.callback_armed.store(false, Ordering::Release);
        // F-07: fail-closed. If the supervisor is dropped while native capture may
        // still be installed (Armed, or Degraded from a prior failed teardown),
        // attempt a best-effort backend stop so the CGEventTap / low-level keyboard
        // hook is not left armed for the process lifetime. The normal exit path is
        // expected to call shutdown(); this is its backstop. stop_capture is
        // best-effort here — Drop cannot propagate errors.
        if matches!(
            self.state,
            NativeCaptureState::Armed | NativeCaptureState::Degraded
        ) {
            let _ = self.backend.stop_capture();
        }
    }
}

impl<B: InputCaptureBackend, R> fmt::Debug for NativeCaptureSupervisor<B, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeCaptureSupervisor")
            .field("state", &self.state)
            .field(
                "callback_armed",
                &self.callback_armed.load(Ordering::Acquire),
            )
            .finish_non_exhaustive()
    }
}

impl<B, R> NativeCaptureSupervisor<B, R>
where
    B: InputCaptureBackend,
    R: NativeCaptureRouter + 'static,
{
    #[must_use]
    pub fn new(backend: B, router: Arc<Mutex<R>>) -> Self {
        Self {
            backend,
            router,
            callback_armed: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(SharedCaptureMetrics::default()),
            state: NativeCaptureState::LocalOnly,
            cursor_visible: true,
            local_warp_pending: false,
            pointer_observations: 0,
            pointer_transitions: 0,
            pointer_observation_failures: 0,
            cursor_hides: 0,
            cursor_shows: 0,
            cursor_warps: 0,
        }
    }

    #[must_use]
    pub const fn state(&self) -> NativeCaptureState {
        self.state
    }

    #[must_use]
    pub(crate) fn metrics(&self) -> NativeCaptureMetrics {
        NativeCaptureMetrics {
            observed: self.metrics.observed.load(Ordering::Relaxed),
            suppressed: self.metrics.suppressed.load(Ordering::Relaxed),
            allowed_local: self.metrics.allowed_local.load(Ordering::Relaxed),
            lock_contention: self.metrics.lock_contention.load(Ordering::Relaxed),
            callback_panics: self.metrics.callback_panics.load(Ordering::Relaxed),
            pointer_observations: self.pointer_observations,
            pointer_transitions: self.pointer_transitions,
            pointer_observation_failures: self.pointer_observation_failures,
            cursor_hides: self.cursor_hides,
            cursor_shows: self.cursor_shows,
            cursor_warps: self.cursor_warps,
        }
    }

    /// Starts a fresh native generation, verifies it, then opens routing.
    ///
    /// The callback remains pass-through throughout backend startup. Any start,
    /// health, or rearm failure gates and attempts to stop capture before
    /// returning. A completed rollback is `LocalOnly`; failed native teardown
    /// remains `Degraded` and can only be retried through [`Self::shutdown`].
    ///
    /// # Errors
    ///
    /// Returns a coarse gate, native start, lifecycle, rearm, or state error.
    pub fn start(&mut self, now_ns: u64) -> Result<(), NativeCaptureError> {
        if self.state != NativeCaptureState::LocalOnly {
            return Err(NativeCaptureError::new(
                NativeCaptureErrorKind::InvalidState,
            ));
        }
        self.callback_armed.store(false, Ordering::Release);
        self.gate_router(now_ns)?;

        let callback = capture_callback(
            Arc::clone(&self.router),
            Arc::clone(&self.callback_armed),
            Arc::clone(&self.metrics),
            now_ns,
            Instant::now(),
        );
        if self.backend.start_capture(callback).is_err() {
            self.state = if self.backend.stop_capture().is_ok() {
                NativeCaptureState::LocalOnly
            } else {
                NativeCaptureState::Degraded
            };
            return Err(NativeCaptureError::new(NativeCaptureErrorKind::Start));
        }

        let lifecycle = self.backend.capture_lifecycle();
        if lifecycle != CaptureLifecycleState::Running {
            self.rollback_start(now_ns);
            return Err(NativeCaptureError::new(NativeCaptureErrorKind::Lifecycle));
        }

        if self.rearm_router(lifecycle, now_ns).is_err() {
            self.rollback_start(now_ns);
            return Err(NativeCaptureError::new(NativeCaptureErrorKind::Rearm));
        }

        self.callback_armed.store(true, Ordering::Release);
        self.state = NativeCaptureState::Armed;
        Ok(())
    }

    /// Polls native health without opening a closed gate.
    ///
    /// A non-running state after arming first closes the callback gate, then
    /// discontinues manager routing, and only then attempts native teardown.
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle` when an armed generation is no longer running.
    pub fn poll_lifecycle(
        &mut self,
        now_ns: u64,
    ) -> Result<NativeCaptureState, NativeCaptureError> {
        if self.state != NativeCaptureState::Armed {
            return Ok(self.state);
        }
        if self.backend.capture_lifecycle() == CaptureLifecycleState::Running {
            self.sync_cursor_visibility(now_ns)?;
            self.observe_cursor_position(now_ns);
            return Ok(self.state);
        }

        self.callback_armed.store(false, Ordering::Release);
        let _ = self.gate_router(now_ns);
        if !self.cursor_visible {
            let _ = self.backend.set_cursor_visible(true);
        }
        self.cursor_visible = true;
        self.local_warp_pending = false;
        let _ = self.backend.stop_capture();
        self.state = NativeCaptureState::Degraded;
        Err(NativeCaptureError::new(NativeCaptureErrorKind::Lifecycle))
    }

    fn observe_cursor_position(&mut self, now_ns: u64) {
        let position = match self.backend.cursor_position() {
            Ok(Some(position)) => position,
            Ok(None) => return,
            Err(_) => {
                self.pointer_observation_failures =
                    self.pointer_observation_failures.saturating_add(1);
                return;
            }
        };
        self.pointer_observations = self.pointer_observations.saturating_add(1);
        let Ok(mut router) = self.router.try_lock() else {
            return;
        };
        match router.observe_pointer_position(position, now_ns) {
            Ok(true) => {
                self.pointer_transitions = self.pointer_transitions.saturating_add(1);
            }
            Ok(false) => {}
            Err(_) => {
                self.pointer_observation_failures =
                    self.pointer_observation_failures.saturating_add(1);
            }
        }
    }

    /// Gates routing before attempting native teardown.
    ///
    /// Successful shutdown is idempotent. A stop failure remains gated and
    /// degraded so a later call can retry teardown.
    ///
    /// # Errors
    ///
    /// Returns a coarse gate or native stop error while preserving the gate.
    pub fn shutdown(&mut self, now_ns: u64) -> Result<(), NativeCaptureError> {
        if self.state == NativeCaptureState::Stopped {
            return Ok(());
        }

        self.callback_armed.store(false, Ordering::Release);
        let gate_result = self.gate_router(now_ns);
        if !self.cursor_visible {
            let _ = self.backend.set_cursor_visible(true);
        }
        self.cursor_visible = true;
        self.local_warp_pending = false;
        let stop_result = self.backend.stop_capture();
        if stop_result.is_err() {
            self.state = NativeCaptureState::Degraded;
            return Err(NativeCaptureError::new(NativeCaptureErrorKind::Stop));
        }

        self.state = NativeCaptureState::Stopped;
        gate_result
    }

    fn rollback_start(&mut self, now_ns: u64) {
        self.callback_armed.store(false, Ordering::Release);
        let _ = self.gate_router(now_ns);
        self.state = if self.backend.stop_capture().is_ok() {
            NativeCaptureState::LocalOnly
        } else {
            NativeCaptureState::Degraded
        };
    }

    fn gate_router(&self, now_ns: u64) -> Result<(), NativeCaptureError> {
        let mut router = self
            .router
            .lock()
            .map_err(|_| NativeCaptureError::new(NativeCaptureErrorKind::Gate))?;
        router
            .gate_capture(now_ns)
            .map_err(|_| NativeCaptureError::new(NativeCaptureErrorKind::Gate))
    }

    fn rearm_router(
        &self,
        lifecycle: CaptureLifecycleState,
        now_ns: u64,
    ) -> Result<(), NativeCaptureError> {
        let mut router = self
            .router
            .lock()
            .map_err(|_| NativeCaptureError::new(NativeCaptureErrorKind::Rearm))?;
        router
            .rearm_capture(lifecycle, now_ns)
            .map_err(|_| NativeCaptureError::new(NativeCaptureErrorKind::Rearm))
    }

    fn sync_cursor_visibility(&mut self, now_ns: u64) -> Result<(), NativeCaptureError> {
        let (local_authority, local_position) = {
            let router = self
                .router
                .lock()
                .map_err(|_| NativeCaptureError::new(NativeCaptureErrorKind::Cursor))?;
            let local_authority = router
                .local_pointer_authority()
                .map_err(|_| NativeCaptureError::new(NativeCaptureErrorKind::Cursor))?;
            let local_position = if local_authority {
                router
                    .local_pointer_position()
                    .map_err(|_| NativeCaptureError::new(NativeCaptureErrorKind::Cursor))?
            } else {
                None
            };
            (local_authority, local_position)
        };
        if local_authority && local_position.is_none() {
            // Effective authority fails open locally while an inbound handoff
            // is still settling, before the committed landing point is
            // available. Remember that the visible cursor still needs its
            // destination warp once the coordinator publishes that point.
            self.local_warp_pending = true;
        }
        let should_warp = local_authority
            && local_position.is_some()
            && (!self.cursor_visible || self.local_warp_pending);
        if self.cursor_visible == local_authority && !should_warp {
            return Ok(());
        }
        let position_result = if should_warp {
            local_position.map_or(Ok(()), |position| {
                self.backend.set_cursor_position(position)
            })
        } else {
            Ok(())
        };
        if position_result.is_ok() && local_authority && local_position.is_some() {
            self.cursor_warps = self.cursor_warps.saturating_add(1);
            self.local_warp_pending = false;
        }
        let visibility_changed = self.cursor_visible != local_authority;
        let visibility_result = if position_result.is_ok() && visibility_changed {
            self.backend.set_cursor_visible(local_authority)
        } else {
            position_result
        };
        if visibility_result.is_err() {
            self.callback_armed.store(false, Ordering::Release);
            let _ = self.gate_router(now_ns);
            let _ = self.backend.set_cursor_visible(true);
            self.cursor_visible = true;
            self.local_warp_pending = false;
            let _ = self.backend.stop_capture();
            self.state = NativeCaptureState::Degraded;
            return Err(NativeCaptureError::new(NativeCaptureErrorKind::Cursor));
        }
        if visibility_changed {
            if local_authority {
                self.cursor_shows = self.cursor_shows.saturating_add(1);
            } else {
                self.cursor_hides = self.cursor_hides.saturating_add(1);
            }
        }
        self.cursor_visible = local_authority;
        if !local_authority {
            self.local_warp_pending = false;
        }
        Ok(())
    }
}

fn capture_callback<R>(
    router: Arc<Mutex<R>>,
    armed: Arc<AtomicBool>,
    metrics: Arc<SharedCaptureMetrics>,
    clock_base_ns: u64,
    clock_started: Instant,
) -> CaptureCallback
where
    R: NativeCaptureRouter + 'static,
{
    Arc::new(move |captured| {
        increment(&metrics.observed);
        if !armed.load(Ordering::Acquire) {
            increment(&metrics.allowed_local);
            return CaptureDisposition::AllowLocal;
        }
        let Ok(mut router) = router.try_lock() else {
            increment(&metrics.lock_contention);
            increment(&metrics.allowed_local);
            return CaptureDisposition::AllowLocal;
        };
        if !armed.load(Ordering::Acquire) {
            increment(&metrics.allowed_local);
            return CaptureDisposition::AllowLocal;
        }

        // Native event timestamps are not portable clock values: macOS uses
        // mach-absolute time since boot while the service lifecycle uses time
        // since this runtime started. Sampling the runtime-owned clock only
        // after acquiring serialized authority keeps capture and lifecycle
        // operations in one monotonic domain and prevents a later service tick
        // from appearing to move backwards.
        let elapsed_ns = u64::try_from(clock_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let route_now_ns = clock_base_ns.saturating_add(elapsed_ns);
        let disposition = catch_unwind(AssertUnwindSafe(|| {
            router.route_capture(captured, route_now_ns)
        }));
        match disposition {
            Ok(CaptureDisposition::SuppressLocal) => {
                increment(&metrics.suppressed);
                CaptureDisposition::SuppressLocal
            }
            Ok(CaptureDisposition::AllowLocal) => {
                increment(&metrics.allowed_local);
                CaptureDisposition::AllowLocal
            }
            Err(_) => {
                increment(&metrics.callback_panics);
                increment(&metrics.allowed_local);
                CaptureDisposition::AllowLocal
            }
        }
    })
}

fn increment(counter: &AtomicU64) {
    // Advisory capture-path counters, hit ~twice per captured event on the
    // capture thread. `fetch_add` is a single RMW op versus the load + CAS of
    // `fetch_update`; the previous `saturating_add` only guarded against u64
    // wraparound, which is unreachable for counters incremented at most a few
    // thousand times per second (u64 overflow would take ~10^11 years at
    // 175 Hz). `Relaxed` is the correct ordering for independent best-effort
    // diagnostics.
    counter.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::MutexGuard;

    use kvm_daemon::{EventClassification, PlatformError};
    use kvm_input::{InputEvent, InputPayload, KeyCode, KeyState};
    use kvm_types::{DeviceId, HostId, InputDevice};

    use super::*;

    #[derive(Debug)]
    struct FakeError;

    impl fmt::Display for FakeError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("fake failure")
        }
    }

    impl Error for FakeError {}

    #[derive(Default)]
    struct BackendControl {
        callback: Option<CaptureCallback>,
        lifecycle: CaptureLifecycleState,
        fail_start: bool,
        fail_stop: bool,
        start_disposition: Option<CaptureDisposition>,
        cursor_visible: bool,
        cursor_position: Option<Point>,
    }

    struct FakeBackend {
        control: Arc<Mutex<BackendControl>>,
        events: Arc<Mutex<Vec<&'static str>>>,
        captured: CapturedInput,
    }

    impl InputCaptureBackend for FakeBackend {
        fn enumerate_devices(&self) -> Result<Vec<InputDevice>, PlatformError> {
            Ok(Vec::new())
        }

        fn start_capture(&mut self, callback: CaptureCallback) -> Result<(), PlatformError> {
            let should_fail = {
                let mut control = lock(&self.control);
                control.callback = Some(Arc::clone(&callback));
                control.fail_start
            };
            lock(&self.events).push("start");
            if should_fail {
                return Err(Box::new(FakeError));
            }
            let disposition = callback(self.captured);
            lock(&self.control).start_disposition = Some(disposition);
            Ok(())
        }

        fn stop_capture(&mut self) -> Result<(), PlatformError> {
            let mut control = lock(&self.control);
            lock(&self.events).push("stop");
            if control.fail_stop {
                Err(Box::new(FakeError))
            } else {
                control.lifecycle = CaptureLifecycleState::Stopped;
                Ok(())
            }
        }

        fn capture_lifecycle(&self) -> CaptureLifecycleState {
            lock(&self.control).lifecycle
        }

        fn set_cursor_visible(&mut self, visible: bool) -> Result<(), PlatformError> {
            lock(&self.events).push(if visible {
                "cursor_show"
            } else {
                "cursor_hide"
            });
            lock(&self.control).cursor_visible = visible;
            Ok(())
        }

        fn set_cursor_position(&mut self, position: Point) -> Result<(), PlatformError> {
            lock(&self.events).push("cursor_warp");
            lock(&self.control).cursor_position = Some(position);
            Ok(())
        }

        fn cursor_position(&self) -> Result<Option<Point>, PlatformError> {
            Ok(lock(&self.control).cursor_position)
        }
    }

    struct FakeRouter {
        events: Arc<Mutex<Vec<&'static str>>>,
        disposition: CaptureDisposition,
        fail_gate: bool,
        fail_rearm: bool,
        last_route_now_ns: Option<u64>,
        local_authority: bool,
        local_position: Option<Point>,
        observed_position: Option<Point>,
    }

    impl NativeCaptureRouter for FakeRouter {
        type Error = FakeError;

        fn route_capture(&mut self, _captured: CapturedInput, now_ns: u64) -> CaptureDisposition {
            self.events.lock().unwrap().push("route");
            self.last_route_now_ns = Some(now_ns);
            self.disposition
        }

        fn gate_capture(&mut self, _now_ns: u64) -> Result<(), Self::Error> {
            self.events.lock().unwrap().push("gate");
            if self.fail_gate {
                Err(FakeError)
            } else {
                Ok(())
            }
        }

        fn rearm_capture(
            &mut self,
            lifecycle: CaptureLifecycleState,
            _now_ns: u64,
        ) -> Result<(), Self::Error> {
            assert_eq!(lifecycle, CaptureLifecycleState::Running);
            self.events.lock().unwrap().push("rearm");
            if self.fail_rearm {
                Err(FakeError)
            } else {
                Ok(())
            }
        }

        fn local_pointer_authority(&self) -> Result<bool, Self::Error> {
            Ok(self.local_authority)
        }

        fn local_pointer_position(&self) -> Result<Option<Point>, Self::Error> {
            Ok(self.local_position)
        }

        fn observe_pointer_position(
            &mut self,
            position: Point,
            _now_ns: u64,
        ) -> Result<bool, Self::Error> {
            self.observed_position = Some(position);
            Ok(self.local_position.is_some() && position.y <= 1.0)
        }
    }

    fn captured() -> CapturedInput {
        CapturedInput::new(
            InputEvent::new(
                1,
                42,
                HostId::from_bytes([1; 16]),
                DeviceId::from_bytes([2; 16]),
                InputPayload::Key {
                    code: KeyCode::KeyA,
                    state: KeyState::Pressed,
                },
            ),
            EventClassification::Physical,
        )
    }

    type Fixture = (
        NativeCaptureSupervisor<FakeBackend, FakeRouter>,
        Arc<Mutex<BackendControl>>,
        Arc<Mutex<FakeRouter>>,
        Arc<Mutex<Vec<&'static str>>>,
    );

    fn fixture(disposition: CaptureDisposition) -> Fixture {
        let backend_control = Arc::new(Mutex::new(BackendControl {
            lifecycle: CaptureLifecycleState::Running,
            cursor_visible: true,
            ..BackendControl::default()
        }));
        let router_events = Arc::new(Mutex::new(Vec::new()));
        let router = Arc::new(Mutex::new(FakeRouter {
            events: Arc::clone(&router_events),
            disposition,
            fail_gate: false,
            fail_rearm: false,
            last_route_now_ns: None,
            local_authority: true,
            local_position: None,
            observed_position: None,
        }));
        let backend = FakeBackend {
            control: Arc::clone(&backend_control),
            events: Arc::clone(&router_events),
            captured: captured(),
        };
        (
            NativeCaptureSupervisor::new(backend, Arc::clone(&router)),
            backend_control,
            router,
            router_events,
        )
    }

    fn callback(control: &Arc<Mutex<BackendControl>>) -> CaptureCallback {
        Arc::clone(lock(control).callback.as_ref().unwrap())
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn startup_passes_through_until_running_rearm_completes() {
        let (mut supervisor, backend, _, router_events) =
            fixture(CaptureDisposition::SuppressLocal);
        supervisor.start(10).unwrap();

        assert_eq!(
            lock(&backend).start_disposition,
            Some(CaptureDisposition::AllowLocal)
        );
        assert_eq!(*lock(&router_events), vec!["gate", "start", "rearm"]);
        assert_eq!(supervisor.state(), NativeCaptureState::Armed);
    }

    #[test]
    fn suppresses_exactly_the_armed_router_outcome() {
        for disposition in [
            CaptureDisposition::AllowLocal,
            CaptureDisposition::SuppressLocal,
        ] {
            let (mut supervisor, backend, _, _) = fixture(disposition);
            supervisor.start(10).unwrap();
            assert_eq!(callback(&backend)(captured()), disposition);
        }
    }

    #[test]
    fn native_timestamp_never_becomes_the_routing_clock() {
        let (mut supervisor, backend, router, _) = fixture(CaptureDisposition::AllowLocal);
        supervisor.start(10).unwrap();
        let mut event = captured();
        event.event.timestamp_ns = u64::MAX;

        assert_eq!(callback(&backend)(event), CaptureDisposition::AllowLocal);
        let routed_at = lock(&router).last_route_now_ns.unwrap();
        assert!(routed_at >= 10);
        assert_ne!(routed_at, u64::MAX);
    }

    #[test]
    fn cursor_visibility_tracks_pointer_authority_and_restores_on_shutdown() {
        let (mut supervisor, backend, router, events) = fixture(CaptureDisposition::AllowLocal);
        supervisor.start(10).unwrap();
        lock(&events).clear();

        lock(&router).local_authority = false;
        supervisor.poll_lifecycle(20).unwrap();
        assert!(!lock(&backend).cursor_visible);
        assert_eq!(*lock(&events), vec!["cursor_hide"]);

        supervisor.shutdown(30).unwrap();
        assert!(lock(&backend).cursor_visible);
        assert_eq!(
            *lock(&events),
            vec!["cursor_hide", "gate", "cursor_show", "stop"]
        );
    }

    #[test]
    fn returning_authority_warps_before_revealing_the_cursor() {
        let (mut supervisor, backend, router, events) = fixture(CaptureDisposition::AllowLocal);
        supervisor.start(10).unwrap();
        lock(&events).clear();

        lock(&router).local_authority = false;
        supervisor.poll_lifecycle(20).unwrap();
        {
            let mut router = lock(&router);
            router.local_authority = true;
            router.local_position = Some(Point::new(1922.0, 540.0));
        }
        supervisor.poll_lifecycle(30).unwrap();

        assert!(lock(&backend).cursor_visible);
        assert_eq!(
            *lock(&events),
            vec!["cursor_hide", "cursor_warp", "cursor_show"]
        );
    }

    #[test]
    fn delayed_return_warp_precedes_portal_observation() {
        let (mut supervisor, backend, router, events) = fixture(CaptureDisposition::AllowLocal);
        supervisor.start(10).unwrap();
        lock(&events).clear();

        lock(&router).local_authority = false;
        supervisor.poll_lifecycle(20).unwrap();
        lock(&backend).cursor_position = Some(Point::new(960.0, 0.0));

        // An inbound handoff fails open locally while its committed landing
        // position is not published yet. The visible cursor remains at the
        // stale portal coordinate, so the supervisor must remember to warp it.
        lock(&router).local_authority = true;
        supervisor.poll_lifecycle(30).unwrap();
        assert!(lock(&backend).cursor_visible);
        assert_eq!(supervisor.metrics().pointer_transitions, 0);

        lock(&router).local_position = Some(Point::new(960.0, 2.0));
        supervisor.poll_lifecycle(40).unwrap();

        assert_eq!(lock(&backend).cursor_position, Some(Point::new(960.0, 2.0)));
        assert_eq!(
            lock(&router).observed_position,
            Some(Point::new(960.0, 2.0))
        );
        assert_eq!(supervisor.metrics().pointer_transitions, 0);
        assert_eq!(
            *lock(&events),
            vec!["cursor_hide", "cursor_show", "cursor_warp"]
        );

        supervisor.poll_lifecycle(50).unwrap();
        assert_eq!(supervisor.metrics().cursor_warps, 1);
    }

    #[test]
    fn lifecycle_poll_observes_injected_destination_cursor_motion() {
        let (mut supervisor, backend, router, _) = fixture(CaptureDisposition::AllowLocal);
        supervisor.start(10).unwrap();
        lock(&backend).cursor_position = Some(Point::new(1919.0, 540.0));

        supervisor.poll_lifecycle(20).unwrap();

        assert_eq!(
            lock(&router).observed_position,
            Some(Point::new(1919.0, 540.0))
        );
    }

    #[test]
    fn callback_contention_fails_open_without_routing() {
        let (mut supervisor, backend, router, router_events) =
            fixture(CaptureDisposition::SuppressLocal);
        supervisor.start(10).unwrap();
        lock(&router_events).clear();

        let _held = lock(&router);
        assert_eq!(
            callback(&backend)(captured()),
            CaptureDisposition::AllowLocal
        );
        assert!(lock(&router_events).is_empty());
    }

    #[test]
    fn callback_poison_fails_open_without_routing() {
        let (mut supervisor, backend, router, router_events) =
            fixture(CaptureDisposition::SuppressLocal);
        supervisor.start(10).unwrap();
        lock(&router_events).clear();

        let poison_target = Arc::clone(&router);
        let _ = std::thread::spawn(move || {
            let _held = poison_target.lock().unwrap();
            panic!("poison fake router");
        })
        .join();

        assert_eq!(
            callback(&backend)(captured()),
            CaptureDisposition::AllowLocal
        );
        assert!(lock(&router_events).is_empty());
    }

    #[test]
    fn start_failure_attempts_stop_and_stays_local_only() {
        let (mut supervisor, backend, _, events) = fixture(CaptureDisposition::SuppressLocal);
        lock(&backend).fail_start = true;

        let error = supervisor.start(10).unwrap_err();
        assert_eq!(error.kind(), NativeCaptureErrorKind::Start);
        assert_eq!(supervisor.state(), NativeCaptureState::LocalOnly);
        assert_eq!(*lock(&events), vec!["gate", "start", "stop"]);
        assert_eq!(
            callback(&backend)(captured()),
            CaptureDisposition::AllowLocal
        );
    }

    #[test]
    fn failed_start_with_failed_teardown_stays_degraded_and_gated() {
        let (mut supervisor, backend, _, events) = fixture(CaptureDisposition::SuppressLocal);
        {
            let mut control = lock(&backend);
            control.fail_start = true;
            control.fail_stop = true;
        }

        let error = supervisor.start(10).unwrap_err();
        assert_eq!(error.kind(), NativeCaptureErrorKind::Start);
        assert_eq!(supervisor.state(), NativeCaptureState::Degraded);
        assert_eq!(*lock(&events), vec!["gate", "start", "stop"]);
        assert_eq!(
            callback(&backend)(captured()),
            CaptureDisposition::AllowLocal
        );
    }

    #[test]
    fn lifecycle_fault_gates_before_native_stop() {
        let (mut supervisor, backend, _, router_events) =
            fixture(CaptureDisposition::SuppressLocal);
        supervisor.start(10).unwrap();
        lock(&router_events).clear();
        lock(&backend).lifecycle = CaptureLifecycleState::Faulted;

        let error = supervisor.poll_lifecycle(20).unwrap_err();
        assert_eq!(error.kind(), NativeCaptureErrorKind::Lifecycle);
        assert_eq!(supervisor.state(), NativeCaptureState::Degraded);
        assert_eq!(*lock(&router_events), vec!["gate", "stop"]);
        assert_eq!(
            callback(&backend)(captured()),
            CaptureDisposition::AllowLocal
        );
    }

    #[test]
    fn rearm_failure_rolls_back_to_local_only_and_stops() {
        let (mut supervisor, backend, router, router_events) =
            fixture(CaptureDisposition::SuppressLocal);
        lock(&router).fail_rearm = true;

        let error = supervisor.start(10).unwrap_err();
        assert_eq!(error.kind(), NativeCaptureErrorKind::Rearm);
        assert_eq!(supervisor.state(), NativeCaptureState::LocalOnly);
        assert_eq!(
            *lock(&router_events),
            vec!["gate", "start", "rearm", "gate", "stop"]
        );
        assert_eq!(
            callback(&backend)(captured()),
            CaptureDisposition::AllowLocal
        );
    }

    #[test]
    fn rearm_rollback_with_failed_teardown_stays_degraded_and_gated() {
        let (mut supervisor, backend, router, router_events) =
            fixture(CaptureDisposition::SuppressLocal);
        lock(&router).fail_rearm = true;
        lock(&backend).fail_stop = true;

        let error = supervisor.start(10).unwrap_err();
        assert_eq!(error.kind(), NativeCaptureErrorKind::Rearm);
        assert_eq!(supervisor.state(), NativeCaptureState::Degraded);
        assert_eq!(
            *lock(&router_events),
            vec!["gate", "start", "rearm", "gate", "stop"]
        );
        assert_eq!(
            callback(&backend)(captured()),
            CaptureDisposition::AllowLocal
        );
    }

    #[test]
    fn stop_failure_remains_gated_and_can_be_retried() {
        let (mut supervisor, backend, _, router_events) =
            fixture(CaptureDisposition::SuppressLocal);
        supervisor.start(10).unwrap();
        lock(&router_events).clear();
        lock(&backend).fail_stop = true;

        let error = supervisor.shutdown(20).unwrap_err();
        assert_eq!(error.kind(), NativeCaptureErrorKind::Stop);
        assert_eq!(supervisor.state(), NativeCaptureState::Degraded);
        assert_eq!(
            callback(&backend)(captured()),
            CaptureDisposition::AllowLocal
        );
        assert_eq!(*lock(&router_events), vec!["gate", "stop"]);

        lock(&backend).fail_stop = false;
        supervisor.shutdown(30).unwrap();
        assert_eq!(supervisor.state(), NativeCaptureState::Stopped);
    }

    #[test]
    fn successful_shutdown_is_gate_first_and_idempotent() {
        let (mut supervisor, _backend, _, router_events) =
            fixture(CaptureDisposition::SuppressLocal);
        supervisor.start(10).unwrap();
        lock(&router_events).clear();

        supervisor.shutdown(20).unwrap();
        let events_after_first = lock(&router_events).clone();
        supervisor.shutdown(30).unwrap();

        assert_eq!(events_after_first, vec!["gate", "stop"]);
        assert_eq!(*lock(&router_events), events_after_first);
    }

    #[test]
    fn callback_router_panic_is_caught_and_fails_open() {
        struct PanickingRouter;

        impl NativeCaptureRouter for PanickingRouter {
            type Error = FakeError;

            fn route_capture(
                &mut self,
                _captured: CapturedInput,
                _now_ns: u64,
            ) -> CaptureDisposition {
                panic!("router panic")
            }

            fn gate_capture(&mut self, _now_ns: u64) -> Result<(), Self::Error> {
                Ok(())
            }

            fn rearm_capture(
                &mut self,
                _lifecycle: CaptureLifecycleState,
                _now_ns: u64,
            ) -> Result<(), Self::Error> {
                Ok(())
            }

            fn local_pointer_authority(&self) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        let armed = Arc::new(AtomicBool::new(true));
        let callback = capture_callback(
            Arc::new(Mutex::new(PanickingRouter)),
            Arc::clone(&armed),
            Arc::new(SharedCaptureMetrics::default()),
            10,
            Instant::now(),
        );
        assert_eq!(callback(captured()), CaptureDisposition::AllowLocal);
    }

    #[test]
    fn dropping_an_armed_supervisor_revokes_a_retained_callback() {
        let (mut supervisor, backend, _, router_events) =
            fixture(CaptureDisposition::SuppressLocal);
        supervisor.start(10).unwrap();
        let retained_callback = callback(&backend);
        lock(&router_events).clear();

        drop(supervisor);

        assert_eq!(
            retained_callback(captured()),
            CaptureDisposition::AllowLocal
        );
        // F-07: dropping an Armed supervisor is fail-closed — Drop best-effort
        // stops the native backend so the CGEventTap / low-level hook is not left
        // installed for the process lifetime. That records exactly one "stop"; the
        // retained callback is still revoked (fails open to AllowLocal) and Drop
        // performs no routing.
        assert_eq!(*lock(&router_events), vec!["stop"]);
    }

    #[test]
    fn callback_metrics_are_count_only_and_track_suppression() {
        let (mut supervisor, backend, _, _) = fixture(CaptureDisposition::SuppressLocal);
        supervisor.start(10).unwrap();
        let before = supervisor.metrics();
        assert_eq!(
            callback(&backend)(captured()),
            CaptureDisposition::SuppressLocal
        );
        let after = supervisor.metrics();
        assert_eq!(after.observed, before.observed + 1);
        assert_eq!(after.suppressed, before.suppressed + 1);
        assert_eq!(after.allowed_local, before.allowed_local);
        assert_eq!(after.lock_contention, before.lock_contention);
        assert_eq!(after.callback_panics, before.callback_panics);
    }
}
