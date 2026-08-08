//! Fail-open native capture callback bridge and fail-closed lifecycle owner.

use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kvm_daemon::{
    CaptureCallback, CaptureDisposition, CaptureLifecycleState, CapturedInput, InputCaptureBackend,
    OutboundPeer, OutputInjectionBackend, PeerManager, PeerManagerError,
};

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
        })
    }
}

impl std::error::Error for NativeCaptureError {}

/// Owns one native backend and its serialized, non-blocking callback bridge.
pub struct NativeCaptureSupervisor<B, R> {
    backend: B,
    router: Arc<Mutex<R>>,
    callback_armed: Arc<AtomicBool>,
    state: NativeCaptureState,
}

impl<B, R> Drop for NativeCaptureSupervisor<B, R> {
    fn drop(&mut self) {
        // A native backend may retain its callback while teardown is delayed or
        // fails. Revoke suppression authority before any backend field is
        // dropped so that such a callback can only fail open.
        self.callback_armed.store(false, Ordering::Release);
    }
}

impl<B, R> fmt::Debug for NativeCaptureSupervisor<B, R> {
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
            state: NativeCaptureState::LocalOnly,
        }
    }

    #[must_use]
    pub const fn state(&self) -> NativeCaptureState {
        self.state
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

        let callback = capture_callback(Arc::clone(&self.router), Arc::clone(&self.callback_armed));
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
            return Ok(self.state);
        }

        self.callback_armed.store(false, Ordering::Release);
        let _ = self.gate_router(now_ns);
        let _ = self.backend.stop_capture();
        self.state = NativeCaptureState::Degraded;
        Err(NativeCaptureError::new(NativeCaptureErrorKind::Lifecycle))
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
}

fn capture_callback<R>(router: Arc<Mutex<R>>, armed: Arc<AtomicBool>) -> CaptureCallback
where
    R: NativeCaptureRouter + 'static,
{
    Arc::new(move |captured| {
        if !armed.load(Ordering::Acquire) {
            return CaptureDisposition::AllowLocal;
        }
        let Ok(mut router) = router.try_lock() else {
            return CaptureDisposition::AllowLocal;
        };
        if !armed.load(Ordering::Acquire) {
            return CaptureDisposition::AllowLocal;
        }

        catch_unwind(AssertUnwindSafe(|| {
            router.route_capture(captured, captured.event.timestamp_ns)
        }))
        .unwrap_or(CaptureDisposition::AllowLocal)
    })
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
    }

    struct FakeRouter {
        events: Arc<Mutex<Vec<&'static str>>>,
        disposition: CaptureDisposition,
        fail_gate: bool,
        fail_rearm: bool,
    }

    impl NativeCaptureRouter for FakeRouter {
        type Error = FakeError;

        fn route_capture(&mut self, _captured: CapturedInput, _now_ns: u64) -> CaptureDisposition {
            self.events.lock().unwrap().push("route");
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
            ..BackendControl::default()
        }));
        let router_events = Arc::new(Mutex::new(Vec::new()));
        let router = Arc::new(Mutex::new(FakeRouter {
            events: Arc::clone(&router_events),
            disposition,
            fail_gate: false,
            fail_rearm: false,
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
        }

        let armed = Arc::new(AtomicBool::new(true));
        let callback = capture_callback(Arc::new(Mutex::new(PanickingRouter)), Arc::clone(&armed));
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
        assert!(lock(&router_events).is_empty());
    }
}
