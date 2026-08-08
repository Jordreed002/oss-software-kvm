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
    WorkspaceControlPlane,
};
use kvm_network::{
    AuthenticatedLanConnector, BoundedLanListener, ConnectionGenerationGate, ConnectionRole,
    LanListenerConfig, LanListenerEvent, LanListenerReport, LanPeerAddress, PersistentPeerConfig,
    RustlsPeerStream, RustlsTcpConnector, SecurePeerStream,
};
use kvm_protocol::WirePeerId;
use kvm_security::PairedPeer;
use kvm_topology::{WorkspaceLink, WorkspacePlacement};
use kvm_types::{Display, InputDevice, LogicalPointer, Point, WorkspaceState};

use crate::preparation::{PreparedAcceptor, PreparedAdmissionFactory};
use crate::{NativeCaptureSupervisor, PreparedTwoHostAlpha};

const INITIAL_DISPLAY_REVISION: u64 = 1;
const INITIAL_DEVICE_REVISION: u64 = 2;
const INITIAL_NOW_NS: u64 = 1;
const POINTER_HANDOFF_TIMEOUT: Duration = Duration::from_secs(2);
const SERVICE_TICK: Duration = Duration::from_millis(20);
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
        self.run_transport_ready(shutdown, None, Instant::now())
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
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), RuntimeServiceError>
    where
        B: InputCaptureBackend + 'static,
    {
        let manager = Arc::clone(&self.manager);
        let started = Instant::now();
        let (transport_shutdown, transport_receiver) = tokio::sync::watch::channel(false);
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
        let mut transport_task =
            tokio::spawn(self.run_transport_ready(transport_receiver, Some(ready_sender), started));
        tokio::select! {
            ready = ready_receiver => {
                if ready.is_err() {
                    return transport_task.await
                        .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Task))?
                        .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Transport));
                }
            }
            result = &mut transport_task => {
                return result
                    .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Task))?
                    .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Transport));
            }
        }

        if *shutdown.borrow() {
            let _ = transport_shutdown.send(true);
            return transport_task
                .await
                .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Task))?
                .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Transport));
        }

        let mut capture = NativeCaptureSupervisor::new(backend, manager);
        if capture.start(now_ns(started)).is_err() {
            let _ = transport_shutdown.send(true);
            let _ = transport_task.await;
            return Err(RuntimeServiceError::new(RuntimeServiceErrorKind::Capture));
        }
        let mut lifecycle_tick = tokio::time::interval(SERVICE_TICK);
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
                        break Err(RuntimeServiceError::new(RuntimeServiceErrorKind::Capture));
                    }
                }
            }
        };

        let capture_result = capture
            .shutdown(now_ns(started))
            .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Capture));
        let _ = transport_shutdown.send(true);
        let transport_result = if transport_finished {
            Ok(())
        } else {
            tokio::time::timeout(SHUTDOWN_SETTLE_TIMEOUT * 2, transport_task)
                .await
                .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Task))?
                .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Task))?
                .map_err(|_| RuntimeServiceError::new(RuntimeServiceErrorKind::Transport))
        };
        service_result.and(capture_result).and(transport_result)
    }

    async fn run_transport_ready(
        self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        ready: Option<tokio::sync::oneshot::Sender<()>>,
        started: Instant,
    ) -> Result<(), RuntimeTransportError> {
        let (listener, mut accepted) = BoundedLanListener::bind(
            self.acceptor,
            self.listen_addresses,
            LanListenerConfig::default(),
        )
        .await
        .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Bind))?;
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        let (internal_shutdown, internal_receiver) = tokio::sync::watch::channel(false);
        let listener_task = tokio::spawn(listener.run(internal_receiver.clone()));
        let connector = Arc::new(tokio::sync::Mutex::new(self.connector));
        let mut dial_tasks = tokio::task::JoinSet::new();
        let mut session_tasks = tokio::task::JoinSet::new();
        let mut tick = tokio::time::interval(SERVICE_TICK);

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
                            return Err(RuntimeTransportError::new(RuntimeTransportErrorKind::Task));
                        };
                        if let Some(installed) = prepare_inbound(
                                &self.manager,
                                &self.admission_factory,
                                stream,
                                now_ns(started),
                            )? {
                                session_tasks.spawn(drive_session(
                                    Arc::clone(&self.manager),
                                    installed,
                                    internal_receiver.clone(),
                                    started,
                                ));
                        }
                    }
                    joined = dial_tasks.join_next(), if !dial_tasks.is_empty() => {
                        let dial = joined
                            .ok_or_else(|| RuntimeTransportError::new(RuntimeTransportErrorKind::Task))?
                            .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Task))?;
                        if let Some(installed) = finish_dial(
                            &self.manager,
                            &self.admission_factory,
                            dial,
                            now_duration(started),
                        )? {
                            session_tasks.spawn(drive_session(
                                Arc::clone(&self.manager),
                                installed,
                                internal_receiver.clone(),
                                started,
                            ));
                        }
                    }
                    joined = session_tasks.join_next(), if !session_tasks.is_empty() => {
                        joined
                            .ok_or_else(|| RuntimeTransportError::new(RuntimeTransportErrorKind::Task))?
                            .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Task))??;
                    }
                    _ = tick.tick() => {
                        service_manager(&self.manager, started)?;
                        if dial_tasks.is_empty() {
                            if let Some(task) = poll_dial(&self.manager, now_duration(started))? {
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

struct DialResult {
    task: OutboundDialTask,
    result: std::io::Result<RustlsPeerStream>,
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
    let _ = tokio::time::timeout(SHUTDOWN_SETTLE_TIMEOUT, &mut listener_task).await;
    if !listener_task.is_finished() {
        listener_task.abort();
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
        match manager.inbound_accepted(stream) {
            Ok(start) => start,
            Err(_) => return Ok(None),
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
        let start = {
            let mut manager = lock_manager(manager)?;
            manager
                .outbound_connected(dial.task, stream, now)
                .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Authority))?
        };
        prepare_session(manager, admission_factory, start, duration_ns(now)).map(Some)
    } else {
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
        lock_manager(manager)?
            .cancel_established(start, Duration::from_nanos(now_ns))
            .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Authority))?;
        return Err(RuntimeTransportError::new(
            RuntimeTransportErrorKind::Admission,
        ));
    };
    let prepared = match start.build(admission, PersistentPeerConfig::default()) {
        Ok(prepared) => prepared,
        Err(error) => {
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
    match lock_manager(manager)?.install_prepared_session(prepared) {
        Ok(installed) => Ok(installed),
        Err(rejected) => {
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

async fn drive_session<I, S, A>(
    manager: Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    installed: InstalledPeerSessionParts<S, A>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    started: Instant,
) -> Result<(), RuntimeTransportError>
where
    I: OutputInjectionBackend + 'static,
    S: SecurePeerStream + 'static,
    A: kvm_network::SessionAdmission + 'static,
{
    let peer_id = installed.runner.peer_id();
    let generation = installed.runner.generation();
    let (session_shutdown, session_receiver) = tokio::sync::watch::channel(false);
    let runner = tokio::spawn(installed.runner.run(session_receiver));
    let mut events = installed.events;

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
                if lock_manager(&manager)?
                    .handle_bound_event(peer_id, event, now_ns(started))
                    .is_err()
                {
                    let _ = session_shutdown.send(true);
                }
            }
        }
    }

    match runner.await {
        Ok(Ok(_)) | Err(_) => {}
        Ok(Err(error)) => {
            if let Some(terminal) = error.into_terminal_event() {
                let _ =
                    lock_manager(&manager)?.handle_bound_event(peer_id, terminal, now_ns(started));
            }
        }
    }
    let _ = lock_manager(&manager)?.connection_task_lost(peer_id, generation, now_ns(started));
    Ok(())
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
        .map_err(|_| RuntimeTransportError::new(RuntimeTransportErrorKind::Authority))
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
        tokio::time::sleep(SERVICE_TICK).await;
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
        let mut manager =
            PeerManager::new(local_peer, [managed_peer], PeerManagerConfig::default()).map_err(
                |_| RuntimeCompositionError::new(RuntimeCompositionErrorKind::Authority),
            )?;
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
        })
    }
}

fn prepare_workspace(
    config: &Config,
    local_host: kvm_types::HostId,
    local_displays: Vec<Display>,
) -> Result<PreparedWorkspace, RuntimeCompositionError> {
    let primary = local_primary(&local_displays, local_host)?;
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
    let primary_origin = placements
        .iter()
        .find(|placement| placement.display_id() == primary.id)
        .map(|placement| placement.origin())
        .ok_or_else(|| RuntimeCompositionError::new(RuntimeCompositionErrorKind::Topology))?;
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
        primary.id,
        primary_origin.x + primary.logical_size.width / 2.0,
        primary_origin.y + primary.logical_size.height / 2.0,
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
    use kvm_config::{DisplayPlacement, TopologyConfig};
    use kvm_types::{DisplayId, HostId, Rect, Size};

    use super::*;

    const LOCAL_HOST: HostId = HostId::from_bytes([0x11; 16]);
    const OTHER_HOST: HostId = HostId::from_bytes([0x22; 16]);
    const DISPLAY: DisplayId = DisplayId::from_bytes([0x33; 16]);

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
    fn current_local_inventory_seeds_local_pointer_authority() {
        let prepared = prepare_workspace(
            &config_with_local_placement(),
            LOCAL_HOST,
            vec![display(LOCAL_HOST, true)],
        )
        .unwrap();

        assert_eq!(prepared.initial_state.local_host, LOCAL_HOST);
        assert_eq!(prepared.initial_state.active_host, LOCAL_HOST);
        assert_eq!(prepared.pointer.display_id, DISPLAY);
        assert!((prepared.pointer.x - 140.0).abs() < f64::EPSILON);
        assert!((prepared.pointer.y - 70.0).abs() < f64::EPSILON);
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
}
