//! Side-effect-free assembly of the selected two-host runtime authority.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kvm_config::Config;
use kvm_daemon::{
    DaemonCore, DisplayInventory, DisplayInventoryConfig, InputCaptureBackend,
    InstalledPeerSessionParts, ManagedPairedPeer, ManagedSessionOutbound, OutboundDialTask,
    OutputInjectionBackend, PeerManager, PeerManagerConfig, PeerManagerSnapshot,
    PeerSessionCoordinator, PeerSessionSupervisor, PointerHandoffConfig, SealedPeerSessionStart,
    SupervisorEventOutcome, WorkspaceControlPlane,
};
use kvm_network::{
    empty_capture_cell, spawn_diagnostics_server, AuthenticatedLanConnector, BoundedLanListener,
    CaptureDiagnostics, CaptureDiagnosticsCell, ConnectionGenerationGate, ConnectionRole,
    DiagnosticsPublisher, DiagnosticsReport, LanListenerConfig, LanListenerEvent,
    LanListenerReport, LanPeerAddress, NetworkDiagnostics, PersistentPeerConfig, RustlsPeerStream,
    RustlsTcpConnector, SecurePeerStream, SessionTelemetry, DEFAULT_DIAGNOSTICS_PORT,
    DIAGNOSTICS_SCHEMA_VERSION,
};
use kvm_protocol::WirePeerId;
use kvm_security::PairedPeer;
use kvm_topology::{WorkspaceLink, WorkspacePlacement};
use kvm_types::{Display, InputDevice, LogicalPointer, Point, WorkspaceState};

use crate::preparation::{PreparedAcceptor, PreparedAdmissionFactory};
use crate::runtime_status::{
    RuntimeInputOwner, RuntimeRoutingState, RuntimeStatusPublisher, RuntimeStatusSnapshot,
};
use crate::{NativeCaptureSupervisor, PreparedTwoHostAlpha};

const INITIAL_DISPLAY_REVISION: u64 = 1;
const INITIAL_DEVICE_REVISION: u64 = 2;
const INITIAL_NOW_NS: u64 = 1;
const POINTER_HANDOFF_TIMEOUT: Duration = Duration::from_secs(2);
// Poll cursor authority at 250 Hz. Native input packets still route directly
// from their callbacks; this cadence only bounds cursor visibility, landing
// warps, handoff observation, and transport lifecycle work. Four milliseconds
// keeps those operations below one frame on high-refresh displays without
// turning the manager mutex into a continuous capture-path contender.
const CAPTURE_POLL_TICK: Duration = Duration::from_millis(4);
// Transport maintenance does not carry pointer samples. Keep it at the prior
// cadence so doubling cursor polling does not also double manager-lock
// contention against the synchronous native capture callback.
const TRANSPORT_SERVICE_TICK: Duration = Duration::from_millis(8);
const SHUTDOWN_SETTLE_TIMEOUT: Duration = Duration::from_secs(3);

struct PreparedWorkspace {
    inventory: DisplayInventory,
    initial_state: WorkspaceState,
    pointer: LogicalPointer,
    placements: Vec<WorkspacePlacement>,
    links: Vec<WorkspaceLink>,
}

/// Coarse category for a side-effect-free runtime composition failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCompositionErrorKind {
    Disabled,
    LocalInventory,
    Topology,
    Authority,
}

/// Coarse category for an active authenticated transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeTransportErrorKind {
    Bind,
    Authority,
    Admission,
    Task,
}

/// Coarse category for the combined native-capture and transport owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeServiceErrorKind {
    Capture,
    Transport,
    Task,
}

/// Payload- and platform-detail-redacted active service failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RuntimeServiceError {
    kind: RuntimeServiceErrorKind,
}

impl RuntimeServiceError {
    const fn new(kind: RuntimeServiceErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RuntimeServiceErrorKind {
        self.kind
    }
}

impl fmt::Debug for RuntimeServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeServiceError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RuntimeServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RuntimeServiceErrorKind::Capture => "native capture lifecycle failed",
            RuntimeServiceErrorKind::Transport => "authenticated transport service failed",
            RuntimeServiceErrorKind::Task => "runtime service task failed",
        })
    }
}

impl std::error::Error for RuntimeServiceError {}

/// Address-, identity-, credential-, generation-, and payload-redacted runtime
/// transport failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RuntimeTransportError {
    kind: RuntimeTransportErrorKind,
}

impl RuntimeTransportError {
    const fn new(kind: RuntimeTransportErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RuntimeTransportErrorKind {
        self.kind
    }
}

impl fmt::Debug for RuntimeTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTransportError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RuntimeTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RuntimeTransportErrorKind::Bind => "authenticated LAN listener could not start",
            RuntimeTransportErrorKind::Authority => "runtime authority reconciliation failed",
            RuntimeTransportErrorKind::Admission => "authenticated peer admission failed",
            RuntimeTransportErrorKind::Task => "runtime transport task failed",
        })
    }
}

impl std::error::Error for RuntimeTransportError {}

/// Identity-, topology-, inventory-, and credential-redacted composition error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RuntimeCompositionError {
    kind: RuntimeCompositionErrorKind,
}

impl RuntimeCompositionError {
    const fn new(kind: RuntimeCompositionErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RuntimeCompositionErrorKind {
        self.kind
    }
}

impl fmt::Debug for RuntimeCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeCompositionError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RuntimeCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RuntimeCompositionErrorKind::Disabled => "the runtime profile is disabled",
            RuntimeCompositionErrorKind::LocalInventory => {
                "local native inventory is unavailable or inconsistent"
            }
            RuntimeCompositionErrorKind::Topology => {
                "configured topology does not cover the current local displays"
            }
            RuntimeCompositionErrorKind::Authority => {
                "selected two-host runtime authority could not be assembled"
            }
        })
    }
}

impl std::error::Error for RuntimeCompositionError {}

/// Fully assembled but inactive selected two-host runtime.
///
/// Construction installs no hooks, binds no socket, and starts no task. The
/// private fields keep the manager, credentials, and session factories under
/// one ownership boundary for the active runtime loop.
pub struct TwoHostAlphaRuntime<I>
where
    I: OutputInjectionBackend,
{
    pub(crate) manager: Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    pub(crate) connector: RustlsTcpConnector,
    pub(crate) acceptor: PreparedAcceptor,
    pub(crate) admission_factory: PreparedAdmissionFactory,
    pub(crate) listen_addresses: Vec<std::net::SocketAddr>,
    pub(crate) host_identity: LocalHostIdentity,
}

/// The local host's identity, carried from composition into the active runtime
/// so the separate diagnostics channel (spec §31) can stamp every published
/// [`DiagnosticsReport`] with the reporting host without re-reading credentials.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LocalHostIdentity {
    pub host_id: kvm_types::HostId,
    pub peer_id: kvm_types::PeerId,
    pub platform: kvm_types::Platform,
}

/// The platform this crate was compiled for. The runtime only goes active on
/// Windows or macOS; the neutral fallback only applies to host-neutral builds
/// (unit tests) that never bind a real diagnostics socket.
#[cfg(windows)]
const LOCAL_PLATFORM: kvm_types::Platform = kvm_types::Platform::Windows;
#[cfg(target_os = "macos")]
const LOCAL_PLATFORM: kvm_types::Platform = kvm_types::Platform::MacOS;
#[cfg(not(any(windows, target_os = "macos")))]
const LOCAL_PLATFORM: kvm_types::Platform = kvm_types::Platform::Windows;

/// Shared, read-only context for spawning session tasks inside the transport
/// loop, so the inbound-accept and dial-finish branches do not repeat the six
/// shared arguments to [`drive_session`]. Built once per transport run.
struct SessionSpawnCtx<'a, I>
where
    I: OutputInjectionBackend,
{
    manager: &'a Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    receiver: tokio::sync::watch::Receiver<bool>,
    started: Instant,
    publisher: DiagnosticsPublisher,
    identity: LocalHostIdentity,
    capture: CaptureDiagnosticsCell,
}

impl<I> SessionSpawnCtx<'_, I>
where
    I: OutputInjectionBackend + 'static,
{
    /// Spawns one session-driving task that shares the diagnostics publisher so
    /// every active session publishes telemetry onto the separate channel.
    fn spawn<S, A>(
        &self,
        tasks: &mut tokio::task::JoinSet<Result<(), RuntimeTransportError>>,
        installed: InstalledPeerSessionParts<S, A>,
    ) where
        S: SecurePeerStream + 'static,
        A: kvm_network::SessionAdmission + 'static,
    {
        tasks.spawn(drive_session(
            Arc::clone(self.manager),
            installed,
            self.receiver.clone(),
            self.started,
            self.publisher.clone(),
            self.identity,
            Arc::clone(&self.capture),
        ));
    }
}

impl<I> fmt::Debug for TwoHostAlphaRuntime<I>
where
    I: OutputInjectionBackend,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwoHostAlphaRuntime")
            .field("manager", &"[SERIALIZED AUTHORITY]")
            .field(
                "prepared_component_count",
                &[
                    std::mem::size_of_val(&self.connector),
                    std::mem::size_of_val(&self.acceptor),
                    std::mem::size_of_val(&self.admission_factory),
                ]
                .into_iter()
                .filter(|size| *size != 0)
                .count(),
            )
            .field("listen_address_count", &self.listen_addresses.len())
            .finish_non_exhaustive()
    }
}

impl<I> TwoHostAlphaRuntime<I>
where
    I: OutputInjectionBackend + 'static,
{
    /// Returns count-only manager state without exposing mutable authority.
    #[must_use]
    pub fn snapshot(&self) -> Option<PeerManagerSnapshot> {
        self.manager.lock().ok().map(|manager| manager.snapshot())
    }

    /// Runs the authenticated listener, canonical dialer, and exact session
    /// pumps until shutdown is requested.
    ///
    /// Native capture is not started here. The manager remains capture-gated,
    /// so transport-only operation cannot suppress local input.
    ///
    /// # Errors
    ///
    /// Returns a coarse listener, authority, admission, or owned-task failure.
    pub async fn run_transport(
        self,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), RuntimeTransportError> {
        self.run_transport_ready(shutdown, None, Instant::now(), None, empty_capture_cell())
            .await
    }

    /// Runs authenticated transport and one suppressible native capture owner.
    ///
    /// The listener must bind before capture starts. Shutdown and every fault
    /// revoke native suppression and gate manager routing before transport is
    /// asked to close.
    ///
    /// # Errors
    ///
    /// Returns a coarse capture, transport, or task failure.
    pub async fn run_with_capture<B>(
        self,
        backend: B,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), RuntimeServiceError>
    where
        B: InputCaptureBackend + 'static,
    {
        self.run_with_capture_status(backend, shutdown, None).await
    }

    /// Awaits transport readiness, surfacing an early transport-task failure as
    /// a coarse task/transport error. Extracted from `run_with_capture_status`
    /// to keep that method within the clippy line budget.
    async fn await_transport_ready(
        transport_task: &mut tokio::task::JoinHandle<Result<(), RuntimeTransportError>>,
        ready_receiver: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), RuntimeServiceError> {
        let ready_ok = tokio::select! {
            ready = ready_receiver => ready.is_ok(),
            result = &mut *transport_task => return coarse_join_outcome(result),
        };
        if ready_ok {
            Ok(())
        } else {
            coarse_join_outcome(transport_task.await)
        }
    }

    pub(crate) async fn run_with_capture_status<B>(
        self,
        backend: B,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        status: Option<RuntimeStatusPublisher>,
    ) -> Result<(), RuntimeServiceError>
    where
        B: InputCaptureBackend + 'static,
    {
        developer_event("service=starting");
        publish_status(status.as_ref(), RuntimeStatusSnapshot::starting());
        let manager = Arc::clone(&self.manager);
        let started = Instant::now();
        let (transport_shutdown, transport_receiver) = tokio::sync::watch::channel(false);
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
        let capture_cell = empty_capture_cell();
        let mut transport_task = tokio::spawn(self.run_transport_ready(
            transport_receiver,
            Some(ready_sender),
            started,
            status.clone(),
            Arc::clone(&capture_cell),
        ));
        Self::await_transport_ready(&mut transport_task, ready_receiver).await?;
        if *shutdown.borrow() {
            developer_event("service=stopped_before_capture");
            let _ = transport_shutdown.send(true);
            return coarse_join_outcome(transport_task.await);
        }

        let mut capture = NativeCaptureSupervisor::new(backend, manager);
        if capture.start(now_ns(started)).is_err() {
            developer_event("capture=start_failed");
            let _ = transport_shutdown.send(true);
            let _ = transport_task.await;
            return Err(RuntimeServiceError::new(RuntimeServiceErrorKind::Capture));
        }
        developer_event("capture=armed");
        developer_event("pointer=pipeline samples:individual cursor_poll_hz:250");
        let mut lifecycle_tick = tokio::time::interval(CAPTURE_POLL_TICK);
        let mut last_capture_metrics = capture.metrics();
        let mut next_capture_report = Instant::now() + Duration::from_secs(1);
        let mut transport_finished = false;
        let service_result = loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break Ok(());
                    }
                }
                result = &mut transport_task => {
                    transport_finished = true;
                    break result
                        .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Task))?
                        .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Transport));
                }
                _ = lifecycle_tick.tick() => {
                    if capture.poll_lifecycle(now_ns(started)).is_err() {
                        developer_event("capture=lifecycle_fault");
                        break Err(RuntimeServiceError::new(RuntimeServiceErrorKind::Capture));
                    }
                    if Instant::now() >= next_capture_report {
                        let metrics = capture.metrics();
                        update_capture_cell(&capture_cell, &metrics);
                        report_capture_metrics(
                            metrics,
                            &mut last_capture_metrics,
                            &mut next_capture_report,
                        );
                    }
                }
            }
        };

        let capture_result = capture
            .shutdown(now_ns(started))
            .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Capture));
        let _ = transport_shutdown.send(true);
        developer_event("service=stopping");
        publish_status(status.as_ref(), RuntimeStatusSnapshot::stopping());
        let transport_result = if transport_finished {
            Ok(())
        } else {
            tokio::time::timeout(SHUTDOWN_SETTLE_TIMEOUT * 2, transport_task)
                .await
                .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Task))?
                .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Task))?
                .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Transport))
        };
        let result = service_result.and(capture_result).and(transport_result);
        if result.is_err() {
            publish_status(status.as_ref(), RuntimeStatusSnapshot::faulted());
        }
        result
    }

    #[allow(
        clippy::too_many_lines,
        reason = "transport select loop is clearest inline"
    )]
    async fn run_transport_ready(
        self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        ready: Option<tokio::sync::oneshot::Sender<()>>,
        started: Instant,
        status: Option<RuntimeStatusPublisher>,
        capture_cell: CaptureDiagnosticsCell,
    ) -> Result<(), RuntimeTransportError> {
        // Bind diagnostics before the KVM listener consumes `listen_addresses`.
        let diagnostics_publisher =
            bind_diagnostics_server(&self.listen_addresses, self.host_identity, started);
        let (listener, mut accepted) = BoundedLanListener::bind(
            self.acceptor,
            self.listen_addresses,
            LanListenerConfig::default(),
        )
        .await
        .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Bind))?;
        announce_listener_ready(ready);
        let (internal_shutdown, internal_receiver) = tokio::sync::watch::channel(false);
        let listener_task = tokio::spawn(listener.run(internal_receiver.clone()));
        let connector = Arc::new(tokio::sync::Mutex::new(self.connector));
        let mut dial_tasks = tokio::task::JoinSet::new();
        let mut session_tasks = tokio::task::JoinSet::new();
        let mut tick = tokio::time::interval(TRANSPORT_SERVICE_TICK);
        let mut last_manager_snapshot = None;
        let session_ctx = SessionSpawnCtx {
            manager: &self.manager,
            receiver: internal_receiver.clone(),
            started,
            publisher: diagnostics_publisher.clone(),
            identity: self.host_identity,
            capture: Arc::clone(&capture_cell),
        };

        let run_result = async {
            loop {
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return Ok(());
                        }
                    }
                    event = accepted.recv() => {
                        let Some(LanListenerEvent::Accepted { stream }) = event else {
                            developer_event("transport=listener_events_closed");
                            return Err(RuntimeTransportError::new(RuntimeTransportErrorKind::Task));
                        };
                        developer_event("transport=inbound_tcp_accepted");
                        if let Some(installed) = prepare_inbound(
                                &self.manager,
                                &self.admission_factory,
                                stream,
                                now_ns(started),
                            )? {
                                session_ctx.spawn(&mut session_tasks, installed);
                        }
                    }
                    joined = dial_tasks.join_next(), if !dial_tasks.is_empty() => {
                        let dial = settled_dial_task(joined)?;
                        if let Some(installed) = finish_dial(
                            &self.manager,
                            &self.admission_factory,
                            dial,
                            now_duration(started),
                        )? {
                            session_ctx.spawn(&mut session_tasks, installed);
                        }
                    }
                    joined = session_tasks.join_next(), if !session_tasks.is_empty() => {
                        settle_session_task(joined)?;
                        developer_event("session=task_finished");
                    }
                    _ = tick.tick() => {
                        service_manager_and_publish(
                            &self.manager,
                            started,
                            &diagnostics_publisher,
                            &capture_cell,
                        )?;
                        let previous = &mut last_manager_snapshot;
                        report_manager_snapshot(&self.manager, previous, status.as_ref());
                        if dial_tasks.is_empty() {
                            if let Some(task) = poll_dial(&self.manager, now_duration(started))? {
                                developer_event("transport=outbound_dial_started");
                                let connector = Arc::clone(&connector);
                                dial_tasks.spawn(async move {
                                    let address = task.address();
                                    let result = connector.lock().await.connect_lan(address).await;
                                    DialResult { task, result }
                                });
                            }
                        }
                    }
                }
            }
        }
        .await;

        report_transport_failure(run_result);

        let cleanup_result = finish_transport_tasks(
            &self.manager,
            started,
            internal_shutdown,
            dial_tasks,
            session_tasks,
            listener_task,
        )
        .await;
        run_result.and(cleanup_result)
    }
}

fn announce_listener_ready(ready: Option<tokio::sync::oneshot::Sender<()>>) {
    developer_event("listener=ready");
    if let Some(ready) = ready {
        let _ = ready.send(());
    }
}

fn report_manager_snapshot<I>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    previous: &mut Option<ManagerDiagnosticSnapshot>,
    status: Option<&RuntimeStatusPublisher>,
) where
    I: OutputInjectionBackend,
{
    // R-1: this is a best-effort diagnostic read and status publish. A failure
    // here reads no pressed-key state, so it must never propagate and tear down
    // the transport loop — log and return instead.
    let (manager_snapshot, routing) = {
        let Ok(manager) = lock_manager(manager) else {
            developer_event("transport=manager_snapshot_failed detail:lock");
            return;
        };
        let manager_snapshot = manager.snapshot();
        let routing = if let Ok(handle) = manager.selected_routing_handle() {
            handle.load()
        } else {
            developer_event("transport=manager_snapshot_failed detail:authority");
            return;
        };
        (manager_snapshot, routing)
    };
    let routing_state = if routing.enabled {
        RoutingDiagnosticState::Enabled
    } else if routing.workspace_ready {
        RoutingDiagnosticState::Gated
    } else {
        RoutingDiagnosticState::WaitingForWorkspace
    };
    let snapshot = ManagerDiagnosticSnapshot {
        manager: manager_snapshot,
        routing: routing_state,
        handoff: if routing.handoff_pending {
            HandoffDiagnosticState::Pending
        } else {
            HandoffDiagnosticState::Settled
        },
        authority: if routing.workspace.active_host == routing.workspace.local_host {
            AuthorityDiagnosticState::Local
        } else {
            AuthorityDiagnosticState::Remote
        },
    };
    publish_running_status(&snapshot, snapshot.manager.session_tasks != 0, status);
    if *previous != Some(snapshot) {
        developer_event(&format!(
            "manager=state candidates:{} connecting:{} sessions:{} routing:{} handoff:{} authority:{}",
            snapshot.manager.peers_with_candidates,
            snapshot.manager.connecting_tasks,
            snapshot.manager.session_tasks,
            snapshot.routing.as_str(),
            snapshot.handoff.as_str(),
            snapshot.authority.as_str(),
        ));
        *previous = Some(snapshot);
    }
}

/// Derives the active input owner from a manager snapshot and publishes the
/// running status to the UI/control panel. Extracted from
/// `report_manager_snapshot` to keep that helper under the line budget; it is
/// part of the R-1 best-effort status path and performs no fallible I/O.
fn publish_running_status(
    snapshot: &ManagerDiagnosticSnapshot,
    has_sessions: bool,
    status: Option<&RuntimeStatusPublisher>,
) {
    let input_owner = if snapshot.handoff == HandoffDiagnosticState::Pending {
        RuntimeInputOwner::Transitioning
    } else if snapshot.routing == RoutingDiagnosticState::Enabled
        && has_sessions
        && snapshot.authority == AuthorityDiagnosticState::Remote
    {
        RuntimeInputOwner::Peer
    } else {
        RuntimeInputOwner::Local
    };
    let routing_state = match snapshot.routing {
        RoutingDiagnosticState::Enabled => RuntimeRoutingState::Enabled,
        RoutingDiagnosticState::Gated => RuntimeRoutingState::Gated,
        RoutingDiagnosticState::WaitingForWorkspace => RuntimeRoutingState::WaitingForWorkspace,
    };
    if let Some(status) = status {
        status.publish(RuntimeStatusSnapshot::running(
            input_owner,
            routing_state,
            has_sessions,
        ));
    }
}

fn report_capture_metrics(
    metrics: crate::native_capture::NativeCaptureMetrics,
    previous: &mut crate::native_capture::NativeCaptureMetrics,
    next_report: &mut Instant,
) {
    if metrics != *previous {
        developer_event(&format!(
            "capture=activity observed:{} suppressed:{} local:{} contention:{} panics:{} pointer_polls:{} portal_transitions:{} pointer_failures:{} cursor_hide:{} cursor_show:{} cursor_warp:{}",
            metrics.observed,
            metrics.suppressed,
            metrics.allowed_local,
            metrics.lock_contention,
            metrics.callback_panics,
            metrics.pointer_observations,
            metrics.pointer_transitions,
            metrics.pointer_observation_failures,
            metrics.cursor_hides,
            metrics.cursor_shows,
            metrics.cursor_warps,
        ));
        *previous = metrics;
    }
    *next_report = Instant::now() + Duration::from_secs(1);
}

fn publish_status(publisher: Option<&RuntimeStatusPublisher>, snapshot: RuntimeStatusSnapshot) {
    if let Some(publisher) = publisher {
        publisher.publish(snapshot);
    }
}

struct DialResult {
    task: OutboundDialTask,
    result: std::io::Result<RustlsPeerStream>,
}

fn settled_dial_task(
    joined: Option<Result<DialResult, tokio::task::JoinError>>,
) -> Result<DialResult, RuntimeTransportError> {
    let Some(joined) = joined else {
        developer_event("transport=dial_set_closed");
        return Err(RuntimeTransportError::new(RuntimeTransportErrorKind::Task));
    };
    let Ok(dial) = joined else {
        developer_event("transport=dial_task_failed");
        return Err(RuntimeTransportError::new(RuntimeTransportErrorKind::Task));
    };
    Ok(dial)
}

fn report_transport_failure(result: Result<(), RuntimeTransportError>) {
    if let Err(error) = result {
        developer_event(&format!("transport=loop_failed detail:{error:?}"));
    }
}

fn settle_session_task(
    joined: Option<Result<Result<(), RuntimeTransportError>, tokio::task::JoinError>>,
) -> Result<(), RuntimeTransportError> {
    let Some(joined) = joined else {
        developer_event("transport=session_set_closed");
        return Err(RuntimeTransportError::new(RuntimeTransportErrorKind::Task));
    };
    match joined {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            developer_event(&format!("transport=session_task_failed detail:{error:?}"));
            Err(error)
        }
        Err(_) => {
            developer_event("transport=session_task_panicked");
            Err(RuntimeTransportError::new(RuntimeTransportErrorKind::Task))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManagerDiagnosticSnapshot {
    manager: PeerManagerSnapshot,
    routing: RoutingDiagnosticState,
    handoff: HandoffDiagnosticState,
    authority: AuthorityDiagnosticState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RoutingDiagnosticState {
    Enabled,
    Gated,
    WaitingForWorkspace,
}

impl RoutingDiagnosticState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Gated => "gated",
            Self::WaitingForWorkspace => "waiting_for_workspace",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandoffDiagnosticState {
    Pending,
    Settled,
}

impl HandoffDiagnosticState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityDiagnosticState {
    Local,
    Remote,
}

impl AuthorityDiagnosticState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }
}

async fn finish_transport_tasks<I>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    started: Instant,
    internal_shutdown: tokio::sync::watch::Sender<bool>,
    mut dial_tasks: tokio::task::JoinSet<DialResult>,
    mut session_tasks: tokio::task::JoinSet<Result<(), RuntimeTransportError>>,
    mut listener_task: tokio::task::JoinHandle<LanListenerReport>,
) -> Result<(), RuntimeTransportError>
where
    I: OutputInjectionBackend,
{
    let settle_result = settle_shutdown(manager, started).await;
    let _ = internal_shutdown.send(true);
    dial_tasks.abort_all();
    while dial_tasks.join_next().await.is_some() {}
    let sessions_drained = tokio::time::timeout(SHUTDOWN_SETTLE_TIMEOUT, async {
        while session_tasks.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    if !sessions_drained {
        session_tasks.abort_all();
        while session_tasks.join_next().await.is_some() {}
    }
    match tokio::time::timeout(SHUTDOWN_SETTLE_TIMEOUT, &mut listener_task).await {
        Ok(Ok(report)) => developer_event(&format!("listener=stopped report:{report:?}")),
        Ok(Err(_)) => developer_event("listener=task_failed"),
        Err(_) => {
            developer_event("listener=shutdown_timed_out");
            listener_task.abort();
        }
    }
    settle_result.and(if sessions_drained {
        Ok(())
    } else {
        Err(RuntimeTransportError::new(RuntimeTransportErrorKind::Task))
    })
}

fn prepare_inbound<I, S>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    admission_factory: &PreparedAdmissionFactory,
    stream: S,
    now_ns: u64,
) -> Result<
    Option<InstalledPeerSessionParts<S, crate::preparation::PreparedAdmission>>,
    RuntimeTransportError,
>
where
    I: OutputInjectionBackend + 'static,
    S: SecurePeerStream,
{
    let start = {
        let mut manager = lock_manager(manager)?;
        if let Ok(start) = manager.inbound_accepted(stream) {
            start
        } else {
            developer_event("transport=inbound_rejected");
            return Ok(None);
        }
    };
    prepare_session(manager, admission_factory, start, now_ns).map(Some)
}

fn finish_dial<I>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    admission_factory: &PreparedAdmissionFactory,
    dial: DialResult,
    now: Duration,
) -> Result<
    Option<InstalledPeerSessionParts<RustlsPeerStream, crate::preparation::PreparedAdmission>>,
    RuntimeTransportError,
>
where
    I: OutputInjectionBackend + 'static,
{
    if let Ok(stream) = dial.result {
        developer_event("transport=outbound_tls_connected");
        let start = {
            let mut manager = lock_manager(manager)?;
            manager
                .outbound_connected(dial.task, stream, now)
                .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Authority))?
        };
        prepare_session(manager, admission_factory, start, duration_ns(now)).map(Some)
    } else {
        developer_event("transport=outbound_connect_failed");
        lock_manager(manager)?
            .outbound_failed(dial.task, now)
            .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Authority))?;
        Ok(None)
    }
}

fn prepare_session<I, S>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    admission_factory: &PreparedAdmissionFactory,
    start: SealedPeerSessionStart<S>,
    now_ns: u64,
) -> Result<
    InstalledPeerSessionParts<S, crate::preparation::PreparedAdmission>,
    RuntimeTransportError,
>
where
    I: OutputInjectionBackend + 'static,
    S: SecurePeerStream,
{
    let peer_id = start.peer_id();
    let Ok(admission) = admission_factory.build() else {
        developer_event("session=admission_factory_failed");
        lock_manager(manager)?
            .cancel_established(start, Duration::from_nanos(now_ns))
            .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Authority))?;
        return Err(RuntimeTransportError::new(
            RuntimeTransportErrorKind::Admission,
        ));
    };
    let prepared = match start.build(admission, alpha_peer_config()) {
        Ok(prepared) => prepared,
        Err(error) => {
            developer_event("session=admission_failed");
            let cancellation = error.into_cancellation();
            lock_manager(manager)?
                .handle_bound_event(peer_id, cancellation, now_ns)
                .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Authority))?;
            return Err(RuntimeTransportError::new(
                RuntimeTransportErrorKind::Admission,
            ));
        }
    };
    let generation = prepared.generation();
    // Bind the manager guard to a block scope so it is dropped at the block's
    // closing brace, *before* the `match` runs. Otherwise the match-scrutinee
    // temporary keeps the non-reentrant std Mutex locked for the whole match,
    // and the `Err` arm's `lock_manager(manager)?` would self-deadlock (F-01).
    let install_outcome = {
        let mut manager_guard = lock_manager(manager)?;
        manager_guard.install_prepared_session(prepared)
    };
    match install_outcome {
        Ok(installed) => {
            developer_event("session=installed");
            Ok(installed)
        }
        Err(rejected) => {
            developer_event("session=install_rejected");
            drop(rejected);
            lock_manager(manager)?
                .connection_task_lost(peer_id, generation, now_ns)
                .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Authority))?;
            Err(RuntimeTransportError::new(
                RuntimeTransportErrorKind::Admission,
            ))
        }
    }
}

fn alpha_peer_config() -> PersistentPeerConfig {
    let mut config = PersistentPeerConfig::default();
    // The selected two-host alpha runs on a bounded private-LAN session whose
    // transport can comfortably carry individual pointer samples. Folding a
    // burst into one larger delta is position-correct, but Quartz then receives
    // fewer updates and renders visible steps. Preserve each sample here for a
    // smoother destination cursor; the fixed queue/channel capacities and TLS
    // write batching continue to bound memory and syscall overhead.
    config.queue.coalesce_pointer_moves = false;
    config
}

async fn drive_session<I, S, A>(
    manager: Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    installed: InstalledPeerSessionParts<S, A>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    started: Instant,
    publisher: DiagnosticsPublisher,
    identity: LocalHostIdentity,
    capture_cell: CaptureDiagnosticsCell,
) -> Result<(), RuntimeTransportError>
where
    I: OutputInjectionBackend + 'static,
    S: SecurePeerStream + 'static,
    A: kvm_network::SessionAdmission + 'static,
{
    developer_event("session=runner_started");
    let peer_id = installed.runner.peer_id();
    let generation = installed.runner.generation();
    let observable_stats = installed.runner.observable_stats();
    let (session_shutdown, session_receiver) = tokio::sync::watch::channel(false);
    let runner = tokio::spawn(installed.runner.run(session_receiver));
    let mut events = installed.events;
    let telemetry_enabled = developer_logging_enabled();
    let mut telemetry_tick = tokio::time::interval(Duration::from_secs(1));
    telemetry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    telemetry_tick.tick().await;
    let mut telemetry_baseline = (Instant::now(), observable_stats.telemetry_snapshot());

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    let _ = session_shutdown.send(true);
                    break;
                }
            }
            event = events.recv() => {
                let Some(event) = event else { break; };
                let event_diagnostic = developer_logging_enabled().then(|| format!("{event:?}"));
                match lock_manager(&manager)?
                    .handle_bound_event(peer_id, event, now_ns(started))
                {
                    Ok(outcome) => {
                        if matches!(
                            outcome,
                            SupervisorEventOutcome::Retired(_)
                                | SupervisorEventOutcome::StaleIgnored
                                | SupervisorEventOutcome::PendingCancelled
                        ) {
                            developer_event(&format!(
                                "session=event_retired event:{} outcome:{outcome:?}",
                                event_diagnostic.as_deref().unwrap_or("[REDACTED]")
                            ));
                            let _ = session_shutdown.send(true);
                        }
                    }
                    Err(error) => {
                        developer_event(&format!(
                            "session=event_rejected event:{} error:{error:?}",
                            event_diagnostic.as_deref().unwrap_or("[REDACTED]")
                        ));
                        let _ = session_shutdown.send(true);
                    }
                }
            }
            _ = telemetry_tick.tick() => {
                let telemetry = observable_stats.telemetry_snapshot();
                // Publish over the separate diagnostics channel on every tick so
                // the control panel always has fresh data, independent of dev
                // logging. The dev log line is an additional, opt-in surface.
                publisher.publish(build_diagnostics_report(
                    identity,
                    Some(telemetry),
                    read_capture_cell(&capture_cell),
                    started,
                ));
                if telemetry_enabled {
                    report_session_telemetry(telemetry, &mut telemetry_baseline);
                }
            }
        }
    }

    match runner.await {
        Ok(Ok(end)) => developer_event(&format!("session=runner_ended end:{:?}", end.end)),
        Err(_) => developer_event("session=runner_task_failed"),
        Ok(Err(error)) => {
            developer_event(&format!("session=runner_failed detail:{error:?}"));
            if let Some(terminal) = error.into_terminal_event() {
                let _ =
                    lock_manager(&manager)?.handle_bound_event(peer_id, terminal, now_ns(started));
            }
        }
    }
    let _ = lock_manager(&manager)?.connection_task_lost(peer_id, generation, now_ns(started));
    developer_event("session=runner_stopped");
    Ok(())
}

/// Binds the separate diagnostics server on the local LAN IP derived from the
/// KVM listener addresses, and returns the shared publisher the session tasks
/// update on each telemetry tick.
///
/// The seed report carries no network section (no session is active yet at bind
/// time). The server thread is detached: it dies with the process on shutdown,
/// which is acceptable because the diagnostics channel is advisory and never
/// gates input safety.
fn bind_diagnostics_server(
    listen_addresses: &[std::net::SocketAddr],
    identity: LocalHostIdentity,
    started: Instant,
) -> DiagnosticsPublisher {
    let publisher =
        DiagnosticsPublisher::new(build_diagnostics_report(identity, None, None, started));
    let Some(bind_addr) = listen_addresses
        .first()
        .map(|addr| std::net::SocketAddr::new(addr.ip(), DEFAULT_DIAGNOSTICS_PORT))
    else {
        developer_event("diagnostics=server_skipped detail:no_listen_address");
        return publisher;
    };
    match spawn_diagnostics_server(bind_addr, publisher.clone()) {
        Ok((bound, _handle)) => {
            developer_event(&format!("diagnostics=server_ready addr:{bound}"));
        }
        Err(error) => developer_event(&format!(
            "diagnostics=server_bind_failed addr:{bind_addr} detail:{error:?}"
        )),
    }
    publisher
}

/// Stamps one redacted, versioned diagnostics report for the local host. The
/// network section is `None` until the first session telemetry tick supplies a
/// live [`SessionTelemetry`]; the capture section is `None` until the capture
/// supervisor publishes its first counter snapshot.
fn build_diagnostics_report(
    identity: LocalHostIdentity,
    telemetry: Option<SessionTelemetry>,
    capture: Option<CaptureDiagnostics>,
    started: Instant,
) -> DiagnosticsReport {
    DiagnosticsReport {
        schema_version: DIAGNOSTICS_SCHEMA_VERSION,
        host_id: identity.host_id,
        peer_id: Some(identity.peer_id),
        platform: identity.platform,
        // Host name is layered in once the control-panel profile carries one.
        host_name: None,
        captured_at_unix_ms: DiagnosticsReport::now_unix_ms(),
        uptime_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        network: telemetry.map(NetworkDiagnostics::from_telemetry),
        capture,
    }
}

/// Flattens a joined transport-task outcome into the coarse task/transport
/// error used by the service entrypoints. Extracted so the long service method
/// stays within the clippy line budget.
fn coarse_join_outcome(
    outcome: Result<Result<(), RuntimeTransportError>, tokio::task::JoinError>,
) -> Result<(), RuntimeServiceError> {
    let inner = outcome.map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Task))?;
    inner.map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Transport))
}

/// Copies the native capture supervisor's aggregate counters into the
/// serializable diagnostics DTO. Every field is an aggregate counter; no input
/// payload, key value, coordinate, or peer address is carried across.
fn capture_diagnostics_from(
    metrics: crate::native_capture::NativeCaptureMetrics,
) -> CaptureDiagnostics {
    CaptureDiagnostics {
        observed: metrics.observed,
        suppressed: metrics.suppressed,
        allowed_local: metrics.allowed_local,
        lock_contention: metrics.lock_contention,
        callback_panics: metrics.callback_panics,
        pointer_observations: metrics.pointer_observations,
        pointer_transitions: metrics.pointer_transitions,
        pointer_observation_failures: metrics.pointer_observation_failures,
        cursor_hides: metrics.cursor_hides,
        cursor_shows: metrics.cursor_shows,
        cursor_warps: metrics.cursor_warps,
    }
}

/// Publishes the latest capture counters into the shared cell so the network
/// session task can fold them into the next diagnostics report. Best-effort and
/// non-blocking: a contended write is dropped rather than stalling capture.
fn update_capture_cell(
    cell: &CaptureDiagnosticsCell,
    metrics: &crate::native_capture::NativeCaptureMetrics,
) {
    if let Ok(mut guard) = cell.write() {
        *guard = Some(capture_diagnostics_from(*metrics));
    }
}

/// Reads the latest capture snapshot. Returns `None` on a contended lock rather
/// than blocking the diagnostics publish path.
fn read_capture_cell(cell: &CaptureDiagnosticsCell) -> Option<CaptureDiagnostics> {
    cell.read().ok().and_then(|guard| *guard)
}

/// Refreshes capture diagnostics independently of session telemetry. This keeps
/// capture counters visible while the transport is idle, while preserving the
/// most recent network section when a session is active.
fn publish_capture_snapshot(
    publisher: &DiagnosticsPublisher,
    capture_cell: &CaptureDiagnosticsCell,
    started: Instant,
) {
    publisher.publish_capture(
        read_capture_cell(capture_cell),
        DiagnosticsReport::now_unix_ms(),
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    );
}

fn report_session_telemetry(current: SessionTelemetry, baseline: &mut (Instant, SessionTelemetry)) {
    let now = Instant::now();
    let elapsed = now.saturating_duration_since(baseline.0);
    if elapsed.is_zero() {
        return;
    }
    let previous = baseline.1;
    let tx_bytes = current
        .outbound_bytes
        .saturating_sub(previous.outbound_bytes);
    let rx_bytes = current.inbound_bytes.saturating_sub(previous.inbound_bytes);
    let tx_frames = current
        .outbound_frames
        .saturating_sub(previous.outbound_frames);
    let rx_frames = current
        .inbound_frames
        .saturating_sub(previous.inbound_frames);
    let rtt_ms = current.last_rtt.map_or_else(
        || "pending".to_owned(),
        |rtt| format!("{:.2}", rtt.as_secs_f64() * 1_000.0),
    );
    developer_event(&format!(
        "network=telemetry rtt_ms:{rtt_ms} tx_bps:{} rx_bps:{} tx_fps:{} rx_fps:{} tx_total:{} rx_total:{} queue_drop_input:{} queue_drop_control:{} queue_drop_background:{} channel_full_input:{} channel_full_control:{} channel_full_background:{} coalesced:{}",
        rate_per_second(tx_bytes, elapsed),
        rate_per_second(rx_bytes, elapsed),
        rate_per_second(tx_frames, elapsed),
        rate_per_second(rx_frames, elapsed),
        current.outbound_bytes,
        current.inbound_bytes,
        current.queue.dropped.input,
        current.queue.dropped.control,
        current.queue.dropped.background,
        current.channel_rejections.input,
        current.channel_rejections.control,
        current.channel_rejections.background,
        current.queue.coalesced_moves,
    ));
    *baseline = (now, current);
}

fn rate_per_second(value: u64, elapsed: Duration) -> u64 {
    let elapsed_ms = elapsed.as_millis().max(1);
    let rate = u128::from(value).saturating_mul(1_000) / elapsed_ms;
    u64::try_from(rate).unwrap_or(u64::MAX)
}

fn poll_dial<I>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    now: Duration,
) -> Result<Option<OutboundDialTask>, RuntimeTransportError>
where
    I: OutputInjectionBackend,
{
    lock_manager(manager)?
        .poll_outbound(now)
        .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Authority))
}

fn service_manager<I>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    started: Instant,
) -> Result<(), RuntimeTransportError>
where
    I: OutputInjectionBackend,
{
    let mut manager = lock_manager(manager)?;
    let now = now_ns(started);
    manager
        .selected_lifecycle_tick(now)
        .map(|_| ())
        .map_err(|error| {
            developer_event(&format!("manager=lifecycle_rejected detail:{error:?}"));
            RuntimeTransportError::new(RuntimeTransportErrorKind::Authority)
        })
}

fn service_manager_and_publish<I>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    started: Instant,
    diagnostics_publisher: &DiagnosticsPublisher,
    capture_cell: &CaptureDiagnosticsCell,
) -> Result<(), RuntimeTransportError>
where
    I: OutputInjectionBackend,
{
    service_manager(manager, started)?;
    publish_capture_snapshot(diagnostics_publisher, capture_cell, started);
    Ok(())
}

async fn settle_shutdown<I>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    started: Instant,
) -> Result<(), RuntimeTransportError>
where
    I: OutputInjectionBackend,
{
    let deadline = Instant::now() + SHUTDOWN_SETTLE_TIMEOUT;
    loop {
        if lock_manager(manager)?.shutdown(now_ns(started)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(RuntimeTransportError::new(
                RuntimeTransportErrorKind::Authority,
            ));
        }
        tokio::time::sleep(TRANSPORT_SERVICE_TICK).await;
    }
}

fn lock_manager<I>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
) -> Result<std::sync::MutexGuard<'_, PeerManager<I, ManagedSessionOutbound>>, RuntimeTransportError>
where
    I: OutputInjectionBackend,
{
    manager
        .lock()
        .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Authority))
}

fn now_duration(started: Instant) -> Duration {
    started.elapsed().saturating_add(Duration::from_nanos(1))
}

fn now_ns(started: Instant) -> u64 {
    duration_ns(now_duration(started))
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn developer_event(message: &str) {
    if developer_logging_enabled() {
        eprintln!("[dev] {message}");
    }
}

fn developer_logging_enabled() -> bool {
    std::env::var_os("SOFTWARE_KVM_DEV_LOG").is_some()
}

impl PreparedTwoHostAlpha {
    /// Assembles one inactive selected-peer manager from authenticated static
    /// preparation plus current native display/device inventories.
    ///
    /// No socket, task, capture hook, or injected input is created here.
    ///
    /// # Errors
    ///
    /// Rejects a disabled profile, invalid native inventory, topology that
    /// does not cover every current local display, or inconsistent authority.
    pub fn compose<I>(
        self,
        injection: I,
        local_displays: Vec<Display>,
        local_devices: Vec<InputDevice>,
    ) -> Result<TwoHostAlphaRuntime<I>, RuntimeCompositionError>
    where
        I: OutputInjectionBackend,
    {
        let parts = self.into_parts();
        if !parts.enabled {
            return Err(RuntimeCompositionError::new(
                RuntimeCompositionErrorKind::Disabled,
            ));
        }

        let local_host = parts.local_identity.host_id();
        let local_peer = parts.local_identity.peer_id();
        let remote_peer = parts.remote_identity.peer_id();
        let prepared_workspace = prepare_workspace(&parts.config, local_host, local_displays)?;

        let core = DaemonCore::new(parts.config.clone(), prepared_workspace.initial_state)
            .map_err(|_| RuntimeCompositionError::new(RuntimeCompositionErrorKind::Authority))?;
        let coordinator = PeerSessionCoordinator::new(
            core,
            parts.remote_identity.clone(),
            injection,
            ManagedSessionOutbound::detached(),
        )
        .map_err(|_| RuntimeCompositionError::new(RuntimeCompositionErrorKind::Authority))?;
        let gate = ConnectionGenerationGate::new(
            WirePeerId(local_peer.into_bytes()),
            WirePeerId(remote_peer.into_bytes()),
        )
        .map_err(|_| RuntimeCompositionError::new(RuntimeCompositionErrorKind::Authority))?;
        let role = gate.role();
        let supervisor = PeerSessionSupervisor::new(gate, coordinator);
        let paired = PairedPeer::from_persisted_public_identity(parts.remote_identity.clone());
        let managed_peer = ManagedPairedPeer::new(&paired, supervisor);
        // F-08: pin discovery-derived dial candidates to this host's service
        // port so a malicious LAN peer can't induce internal connects by
        // advertising a paired PeerId with a forged mDNS SRV port. All listen
        // addresses share one port (validated at profile load), so the first
        // suffices; `None` only if no address is configured.
        let manager_config = PeerManagerConfig {
            expected_service_port: parts
                .listen_addresses
                .first()
                .map(std::net::SocketAddr::port),
            ..PeerManagerConfig::default()
        };
        let mut manager = PeerManager::new(local_peer, [managed_peer], manager_config)
            .map_err(|_| RuntimeCompositionError::new(RuntimeCompositionErrorKind::Authority))?;
        let workspace = WorkspaceControlPlane::new(
            remote_peer,
            prepared_workspace.inventory,
            PointerHandoffConfig::new(POINTER_HANDOFF_TIMEOUT).map_err(|_| {
                RuntimeCompositionError::new(RuntimeCompositionErrorKind::Authority)
            })?,
            prepared_workspace.initial_state,
            prepared_workspace.pointer,
            prepared_workspace.placements,
            prepared_workspace.links,
        )
        .map_err(|_| RuntimeCompositionError::new(RuntimeCompositionErrorKind::Topology))?;
        manager
            .attach_workspace_control(workspace)
            .map_err(|_| RuntimeCompositionError::new(RuntimeCompositionErrorKind::Authority))?;
        manager
            .replace_local_device_inventory(INITIAL_DEVICE_REVISION, local_devices, INITIAL_NOW_NS)
            .map_err(|_| {
                RuntimeCompositionError::new(RuntimeCompositionErrorKind::LocalInventory)
            })?;
        if role == ConnectionRole::Dialer {
            let address = LanPeerAddress::new(parts.selected_address).map_err(|_| {
                RuntimeCompositionError::new(RuntimeCompositionErrorKind::Authority)
            })?;
            manager
                .replace_selected_outbound_candidate(remote_peer, address)
                .map_err(|_| {
                    RuntimeCompositionError::new(RuntimeCompositionErrorKind::Authority)
                })?;
        }

        Ok(TwoHostAlphaRuntime {
            manager: Arc::new(Mutex::new(manager)),
            connector: parts.connector,
            acceptor: parts.acceptor,
            admission_factory: parts.admission_factory,
            listen_addresses: parts.listen_addresses,
            host_identity: LocalHostIdentity {
                host_id: local_host,
                peer_id: local_peer,
                platform: LOCAL_PLATFORM,
            },
        })
    }
}

fn prepare_workspace(
    config: &Config,
    local_host: kvm_types::HostId,
    local_displays: Vec<Display>,
) -> Result<PreparedWorkspace, RuntimeCompositionError> {
    let primary = local_primary(&local_displays, local_host)?;
    let local_display_ids = local_displays
        .iter()
        .map(|display| display.id)
        .collect::<std::collections::BTreeSet<_>>();
    let pointer_display = config
        .topology
        .links
        .iter()
        .find(|link| {
            local_display_ids.contains(&link.from_display)
                && !local_display_ids.contains(&link.to_display)
        })
        .and_then(|link| {
            local_displays
                .iter()
                .find(|display| display.id == link.from_display)
        })
        .unwrap_or(primary);
    let placements: Vec<_> = config
        .topology
        .displays
        .iter()
        .map(|placement| {
            WorkspacePlacement::new(placement.display_id, Point::new(placement.x, placement.y))
        })
        .collect();
    if local_displays.iter().any(|display| {
        !placements
            .iter()
            .any(|placement| placement.display_id() == display.id)
    }) {
        return Err(RuntimeCompositionError::new(
            RuntimeCompositionErrorKind::Topology,
        ));
    }
    let links = config
        .topology
        .links
        .iter()
        .map(|link| {
            WorkspaceLink::new(
                link.from_display,
                link.from_edge,
                link.to_display,
                link.to_edge,
            )
        })
        .collect();
    let pointer = LogicalPointer::new(
        pointer_display.id,
        pointer_display.logical_size.width / 2.0,
        pointer_display.logical_size.height / 2.0,
    );
    let initial_state = WorkspaceState::new(local_host, local_host, pointer);
    let mut inventory = DisplayInventory::new(local_host, DisplayInventoryConfig::default())
        .map_err(|_| RuntimeCompositionError::new(RuntimeCompositionErrorKind::LocalInventory))?;
    inventory
        .apply_local_snapshot(INITIAL_DISPLAY_REVISION, local_displays)
        .map_err(|_| RuntimeCompositionError::new(RuntimeCompositionErrorKind::LocalInventory))?;
    Ok(PreparedWorkspace {
        inventory,
        initial_state,
        pointer,
        placements,
        links,
    })
}

fn local_primary(
    displays: &[Display],
    local_host: kvm_types::HostId,
) -> Result<&Display, RuntimeCompositionError> {
    if displays.is_empty()
        || displays
            .iter()
            .any(|display| display.host_id != local_host || !display.is_valid())
    {
        return Err(RuntimeCompositionError::new(
            RuntimeCompositionErrorKind::LocalInventory,
        ));
    }
    let mut primary = displays.iter().filter(|display| display.primary);
    let selected = primary
        .next()
        .ok_or_else(|| RuntimeCompositionError::new(RuntimeCompositionErrorKind::LocalInventory))?;
    if primary.next().is_some() {
        return Err(RuntimeCompositionError::new(
            RuntimeCompositionErrorKind::LocalInventory,
        ));
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use kvm_config::{DisplayPlacement, TopologyConfig, TopologyLink};
    use kvm_types::{DisplayId, Edge, HostId, Rect, Size};

    use super::*;

    const LOCAL_HOST: HostId = HostId::from_bytes([0x11; 16]);
    const OTHER_HOST: HostId = HostId::from_bytes([0x22; 16]);
    const DISPLAY: DisplayId = DisplayId::from_bytes([0x33; 16]);
    const SECONDARY_DISPLAY: DisplayId = DisplayId::from_bytes([0x44; 16]);
    const REMOTE_DISPLAY: DisplayId = DisplayId::from_bytes([0x55; 16]);

    fn display(host_id: HostId, primary: bool) -> Display {
        Display {
            id: DISPLAY,
            host_id,
            name: "local".into(),
            logical_size: Size::new(200.0, 100.0),
            physical_size: Some(Size::new(400.0, 200.0)),
            scale_factor: 2.0,
            refresh_rate: Some(60.0),
            native_bounds: Rect::new(0.0, 0.0, 200.0, 100.0),
            primary,
        }
    }

    fn secondary_display() -> Display {
        let mut display = display(LOCAL_HOST, false);
        display.id = SECONDARY_DISPLAY;
        display.native_bounds = Rect::new(-200.0, 0.0, 200.0, 100.0);
        display
    }

    fn config_with_local_placement() -> Config {
        Config {
            topology: TopologyConfig {
                displays: vec![DisplayPlacement {
                    display_id: DISPLAY,
                    x: 40.0,
                    y: 20.0,
                }],
                links: Vec::new(),
            },
            ..Config::default()
        }
    }

    #[test]
    fn current_local_inventory_seeds_pointer_in_display_local_coordinates() {
        let prepared = prepare_workspace(
            &config_with_local_placement(),
            LOCAL_HOST,
            vec![display(LOCAL_HOST, true)],
        )
        .unwrap();

        assert_eq!(prepared.initial_state.local_host, LOCAL_HOST);
        assert_eq!(prepared.initial_state.active_host, LOCAL_HOST);
        assert_eq!(prepared.pointer.display_id, DISPLAY);
        assert!((prepared.pointer.x - 100.0).abs() < f64::EPSILON);
        assert!((prepared.pointer.y - 50.0).abs() < f64::EPSILON);
        assert_eq!(prepared.inventory.snapshot().display_count(), 1);
    }

    #[test]
    fn current_local_display_must_have_a_configured_placement() {
        let error = prepare_workspace(
            &Config::default(),
            LOCAL_HOST,
            vec![display(LOCAL_HOST, true)],
        )
        .err()
        .unwrap();

        assert_eq!(error.kind(), RuntimeCompositionErrorKind::Topology);
    }

    #[test]
    fn linked_outer_monitor_seeds_pointer_authority_with_multiple_local_displays() {
        let mut config = config_with_local_placement();
        config.topology.displays.extend([
            DisplayPlacement {
                display_id: SECONDARY_DISPLAY,
                x: -200.0,
                y: 20.0,
            },
            DisplayPlacement {
                display_id: REMOTE_DISPLAY,
                x: -400.0,
                y: 20.0,
            },
        ]);
        config.topology.links.push(TopologyLink {
            from_display: SECONDARY_DISPLAY,
            from_edge: Edge::Left,
            to_display: REMOTE_DISPLAY,
            to_edge: Edge::Right,
        });

        let prepared = prepare_workspace(
            &config,
            LOCAL_HOST,
            vec![display(LOCAL_HOST, true), secondary_display()],
        )
        .unwrap();

        assert_eq!(prepared.pointer.display_id, SECONDARY_DISPLAY);
        assert_eq!(prepared.initial_state.active_display, SECONDARY_DISPLAY);
    }

    #[test]
    fn local_inventory_rejects_wrong_owner_or_primary_count() {
        let wrong_owner = prepare_workspace(
            &config_with_local_placement(),
            LOCAL_HOST,
            vec![display(OTHER_HOST, true)],
        )
        .err()
        .unwrap();
        let no_primary = prepare_workspace(
            &config_with_local_placement(),
            LOCAL_HOST,
            vec![display(LOCAL_HOST, false)],
        )
        .err()
        .unwrap();

        assert_eq!(
            wrong_owner.kind(),
            RuntimeCompositionErrorKind::LocalInventory
        );
        assert_eq!(
            no_primary.kind(),
            RuntimeCompositionErrorKind::LocalInventory
        );
    }

    #[test]
    fn alpha_transport_preserves_individual_pointer_updates() {
        let config = alpha_peer_config();

        assert!(!config.queue.coalesce_pointer_moves);
        assert!(config.validate().is_ok());
        assert_eq!(CAPTURE_POLL_TICK, Duration::from_millis(4));
        assert_eq!(TRANSPORT_SERVICE_TICK, Duration::from_millis(8));
    }

    #[test]
    fn telemetry_rate_is_bounded_and_uses_the_observation_window() {
        assert_eq!(rate_per_second(2_048, Duration::from_secs(2)), 1_024);
        assert_eq!(rate_per_second(7, Duration::from_millis(500)), 14);
        assert_eq!(rate_per_second(u64::MAX, Duration::from_nanos(1)), u64::MAX);
    }
}
