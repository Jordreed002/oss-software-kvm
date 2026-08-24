//! Side-effect-free assembly of the selected two-host runtime authority.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kvm_config::Config;
use kvm_daemon::control_service::{
    ControlCommand, ControlService, ControlServiceError, ControlServiceView, ControlViewSource,
    CONTROL_COMMAND_QUEUE_CAPACITY, CONTROL_EVENT_CHANNEL_CAPACITY,
};
use kvm_daemon::{
    CaptureLifecycleState, DaemonCore, DeviceInventorySnapshot, DisplayInventory,
    DisplayInventoryConfig, InputCaptureBackend, InstalledPeerSessionParts, ManagedPairedPeer,
    ManagedSessionOutbound, OutboundDialTask, OutputInjectionBackend, PeerManager,
    PeerManagerConfig, PeerManagerSnapshot, PeerSessionCoordinator, PeerSessionSupervisor,
    PeerState, PointerHandoffConfig, RoutingSnapshot, SealedPeerSessionStart,
    SupervisorEventOutcome, WorkspaceControlPlane,
};
use kvm_network::{
    empty_capture_cell, spawn_diagnostics_server, AuthenticatedLanConnector, BoundedLanListener,
    CaptureDiagnostics, CaptureDiagnosticsCell, ConnectionGenerationGate, ConnectionRole,
    DiagnosticsPublisher, DiagnosticsReport, LanListenerConfig, LanListenerEvent,
    LanListenerReport, LanPeerAddress, LocalControlServerConfig, NetworkDiagnostics,
    PersistentPeerConfig, RustlsPeerStream, RustlsTcpConnector, SecurePeerStream, SessionTelemetry,
    DEFAULT_DIAGNOSTICS_PORT, DIAGNOSTICS_SCHEMA_VERSION,
};
use kvm_protocol::{
    ControlDeviceKind, ControlDeviceRoute, ControlDeviceSummary, ControlDisplaySummary,
    ControlEdgeSide, ControlEvent, ControlPeerState, ControlPeerStatus, ControlStatus,
    ControlTopologyEdge, WireDeviceId, WireDisplayId, WireHostId, WirePeerId,
    CURRENT_PROTOCOL_VERSION, MAX_CONTROL_SNAPSHOT_ITEMS,
};
use kvm_security::PairedPeer;
use kvm_topology::{WorkspaceLink, WorkspacePlacement};
use kvm_types::{DeviceKind, Display, InputDevice, LogicalPointer, Point, WorkspaceState};

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

/// Coarse local inventory-change category surfaced by a platform hotplug
/// watcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalInventoryHint {
    /// The local display topology changed; re-enumerate displays.
    DisplaysChanged,
    /// The local input-device set changed; re-enumerate devices.
    DevicesChanged,
}

/// Platform-supplied hotplug watch feeding the runtime's local
/// inventory-refresh path.
///
/// `poll` drains a platform watcher's bounded, coalesced event channel
/// without blocking; the refresh closures re-enumerate the local inventories
/// (they construct fresh, stateless native backends and never touch the
/// capture-owned backend). Enumeration itself runs on the blocking pool; only
/// the already-serialized manager update happens on the async runtime.
pub(crate) struct LocalInventoryWatch {
    poll: Box<dyn FnMut() -> Option<LocalInventoryHint> + Send>,
    refresh_displays: Arc<dyn Fn() -> Option<Vec<Display>> + Send + Sync>,
    refresh_devices: Arc<dyn Fn() -> Option<Vec<InputDevice>> + Send + Sync>,
}

impl LocalInventoryWatch {
    pub(crate) fn new(
        poll: Box<dyn FnMut() -> Option<LocalInventoryHint> + Send>,
        refresh_displays: Arc<dyn Fn() -> Option<Vec<Display>> + Send + Sync>,
        refresh_devices: Arc<dyn Fn() -> Option<Vec<InputDevice>> + Send + Sync>,
    ) -> Self {
        Self {
            poll,
            refresh_displays,
            refresh_devices,
        }
    }

    fn poll_hint(&mut self) -> Option<LocalInventoryHint> {
        (self.poll)()
    }
}

impl fmt::Debug for LocalInventoryWatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalInventoryWatch")
            .finish_non_exhaustive()
    }
}

/// Inventory kinds demanded by coalesced hints and not yet refreshed.
#[derive(Debug, Default)]
struct InventoryRefreshDemand {
    displays: bool,
    devices: bool,
}

impl InventoryRefreshDemand {
    const fn any(&self) -> bool {
        self.displays || self.devices
    }
}

/// Fresh native inventories returned by one blocking refresh pass.
struct InventoryRefreshOutcome {
    displays: Option<Vec<Display>>,
    devices: Option<Vec<InputDevice>>,
}

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
    /// Local display inventory seed for the §31 control view, refreshed on
    /// every hotplug pass (see `update_control_displays`).
    pub(crate) control_displays: Vec<ControlDisplaySummary>,
    /// Configured topology edges for the §31 control view. Static in this
    /// alpha: `SetTopology` has no command ingress yet.
    pub(crate) control_edges: Vec<ControlTopologyEdge>,
}

/// The local host's identity, carried from composition into the active runtime
/// so the separate diagnostics channel (spec §31) can stamp every published
/// [`DiagnosticsReport`] with the reporting host without re-reading credentials.
#[derive(Clone, Debug)]
pub(crate) struct LocalHostIdentity {
    pub host_id: kvm_types::HostId,
    pub peer_id: kvm_types::PeerId,
    pub platform: kvm_types::Platform,
    /// The sole selected remote peer, for the §31 control view's peer list.
    pub selected_peer: SelectedPeerIdentity,
}

/// Remote identity slice retained for read-only §31 status responses.
#[derive(Clone, Debug)]
pub(crate) struct SelectedPeerIdentity {
    pub host_id: kvm_types::HostId,
    pub peer_id: kvm_types::PeerId,
    pub display_name: String,
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
            self.identity.clone(),
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
            .field("control_display_count", &self.control_displays.len())
            .field("control_edge_count", &self.control_edges.len())
            .finish_non_exhaustive()
    }
}

// --- §31 control plane --------------------------------------------------------

/// Adapter exposing the shared view cell as a [`ControlViewSource`].
///
/// Reads are short critical sections on a cell the capture path never
/// touches; a poisoned cell degrades to an empty (honest "nothing
/// published") view instead of failing the panel connection.
struct SharedControlView(Arc<Mutex<ControlServiceView>>);

impl ControlViewSource for SharedControlView {
    fn control_view(&self) -> ControlServiceView {
        self.0.lock().map(|cell| cell.clone()).unwrap_or_default()
    }
}

/// Best-effort §31 control-plane wiring owned by the transport loop.
///
/// Monitoring only, mirroring the diagnostics-thread pattern: a bind failure
/// logs and disables the plane, and a service-task failure can never gate
/// input — the runtime loop keeps running exactly as before. The view cell is
/// refreshed on the existing service tick (under the same manager lock the
/// diagnostics snapshot already takes), and mutating commands are drained on
/// that tick so the daemon's serialized authority stays the only executor.
struct ControlPlane {
    commands: tokio::sync::mpsc::Receiver<ControlCommand>,
    events: Option<tokio::sync::broadcast::Sender<ControlEvent>>,
    view: Arc<Mutex<ControlServiceView>>,
    identity: LocalHostIdentity,
    /// Owner-loop KVM gate commanded via §31 EnableKvm/DisableKvm. Closing it
    /// gates manager routing (input stays local, fail-open).
    kvm_gate: bool,
    service: Option<tokio::task::JoinHandle<Result<(), ControlServiceError>>>,
    /// Owns the service task's shutdown signal so transport cleanup can stop
    /// it deterministically, independent of the transport's own watch.
    service_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    last_peer_state: Option<ControlPeerState>,
    last_active_host: Option<WireHostId>,
}

impl ControlPlane {
    /// Binds and spawns the §31 control service at `endpoint`, seeding the
    /// view with the runtime-owned display and topology sections. Best-effort:
    /// a bind failure leaves a functioning plane with no service, and the
    /// runtime continues.
    fn start(
        identity: LocalHostIdentity,
        displays: Vec<ControlDisplaySummary>,
        edges: Vec<ControlTopologyEdge>,
        endpoint: LocalControlServerConfig,
    ) -> Self {
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(CONTROL_COMMAND_QUEUE_CAPACITY);
        let (event_tx, event_rx) = tokio::sync::broadcast::channel(CONTROL_EVENT_CHANNEL_CAPACITY);
        let (service_shutdown, service_receiver) = tokio::sync::watch::channel(false);
        let view = Arc::new(Mutex::new(ControlServiceView {
            displays,
            edges,
            ..ControlServiceView::default()
        }));
        let mut plane = Self {
            commands: command_rx,
            events: None,
            view: Arc::clone(&view),
            identity,
            kvm_gate: true,
            service: None,
            service_shutdown: None,
            last_peer_state: None,
            last_active_host: None,
        };
        match ControlService::bind(
            endpoint,
            Arc::new(SharedControlView(Arc::clone(&view))),
            command_tx,
            event_rx,
        ) {
            Ok(service) => {
                developer_event("control=service_ready");
                plane.service = Some(tokio::spawn(service.run(service_receiver)));
                plane.service_shutdown = Some(service_shutdown);
                plane.events = Some(event_tx);
            }
            Err(error) => {
                developer_event(&format!("control=service_bind_failed detail:{error:?}"));
            }
        }
        plane
    }

    /// Signals and settles the §31 service task. Best-effort: a timeout logs
    /// and abandons the task rather than stalling runtime teardown.
    async fn shutdown_service(&mut self) {
        if let Some(shutdown) = self.service_shutdown.take() {
            let _ = shutdown.send(true);
        }
        if let Some(service) = self.service.take() {
            match tokio::time::timeout(SHUTDOWN_SETTLE_TIMEOUT, service).await {
                Ok(Ok(Ok(()))) => {}
                _ => developer_event("control=service_shutdown_failed"),
            }
        }
    }

    /// Shared view cell, for runtime-owned section updates that happen
    /// outside this struct (hotplug display refreshes).
    fn cell(&self) -> Arc<Mutex<ControlServiceView>> {
        Arc::clone(&self.view)
    }

    /// Drains forwarded §31 commands through the serialized manager
    /// authority. Each command is rare and operator-initiated.
    fn drain_commands<I>(
        &mut self,
        manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
        now_ns: u64,
    ) where
        I: OutputInjectionBackend,
    {
        while let Ok(command) = self.commands.try_recv() {
            match command {
                ControlCommand::TriggerFailsafe => {
                    developer_event("control=failsafe_requested");
                    // The documented explicit-trip path: the armed manager
                    // observes the flag on its next capture or lifecycle tick
                    // and releases held input (fail-open). Gate immediately so
                    // no capture in flight is suppressed before then.
                    kvm_daemon::failsafe_hook::trip();
                    self.kvm_gate = false;
                    if let Ok(mut manager) = manager.lock() {
                        let _ = manager.native_capture_discontinued(now_ns);
                    }
                }
                ControlCommand::DisableKvm => {
                    developer_event("control=kvm_disabled");
                    self.kvm_gate = false;
                    if let Ok(mut manager) = manager.lock() {
                        if manager.native_capture_discontinued(now_ns).is_err() {
                            developer_event("control=kvm_disable_rejected");
                        }
                    }
                }
                ControlCommand::EnableKvm => {
                    developer_event("control=kvm_enabled");
                    self.kvm_gate = true;
                    if let Ok(mut manager) = manager.lock() {
                        if manager
                            .rearm_native_capture(CaptureLifecycleState::Running)
                            .is_err()
                        {
                            developer_event("control=kvm_enable_rejected");
                        }
                    }
                }
            }
        }
    }

    /// Rebuilds the read-only §31 view from one locked manager pass and
    /// publishes the §31 change events. The runtime-owned display/topology
    /// sections are carried across untouched.
    fn refresh(
        &mut self,
        manager_snapshot: PeerManagerSnapshot,
        routing: &RoutingSnapshot,
        devices: Option<Arc<DeviceInventorySnapshot>>,
    ) {
        self.refresh_parts(
            routing.workspace.active_host,
            routing.workspace.active_display,
            routing.enabled,
            routing
                .peers
                .get(&self.identity.selected_peer.host_id)
                .copied(),
            manager_snapshot,
            devices,
        );
    }

    /// View rebuild over extracted routing facts, split from [`Self::refresh`]
    /// so the mapping is testable without assembling a full routing table.
    fn refresh_parts(
        &mut self,
        active_host: kvm_types::HostId,
        active_display: kvm_types::DisplayId,
        routing_enabled: bool,
        peer_state: Option<PeerState>,
        manager_snapshot: PeerManagerSnapshot,
        devices: Option<Arc<DeviceInventorySnapshot>>,
    ) {
        let peer_state = peer_state.unwrap_or_else(|| peer_state_from_counts(&manager_snapshot));
        let mapped_peer_state = control_peer_state(peer_state);
        let active_host = WireHostId(active_host.into_bytes());
        let mut next = ControlServiceView {
            status: ControlStatus {
                active_host,
                active_display: WireDisplayId(active_display.into_bytes()),
                kvm_enabled: routing_enabled && self.kvm_gate,
                // No clipboard path exists in this daemon yet; false is the
                // honest value until one does.
                clipboard_enabled: false,
                protocol_version: CURRENT_PROTOCOL_VERSION,
                // Session RTT lives on the separate diagnostics channel; it
                // is not folded into the manager snapshot yet.
                round_trip_time_ms: None,
                peer_state: mapped_peer_state,
            },
            peers: vec![ControlPeerStatus {
                peer_id: WirePeerId(self.identity.selected_peer.peer_id.into_bytes()),
                host_id: WireHostId(self.identity.selected_peer.host_id.into_bytes()),
                host_name: self.identity.selected_peer.display_name.clone(),
                state: mapped_peer_state,
            }],
            devices: devices.map_or_else(Vec::new, |inventory| {
                inventory.devices().map(control_device_summary).collect()
            }),
            displays: Vec::new(),
            edges: Vec::new(),
        };
        if let Ok(mut cell) = self.view.lock() {
            next.displays = std::mem::take(&mut cell.displays);
            next.edges = std::mem::take(&mut cell.edges);
            *cell = next;
        }
        if let Some(events) = self.events.as_ref() {
            if self
                .last_peer_state
                .is_some_and(|state| state != mapped_peer_state)
            {
                let _ = events.send(ControlEvent::PeerChanged);
            }
            if self
                .last_active_host
                .is_some_and(|host| host != active_host)
            {
                let _ = events.send(ControlEvent::ActiveHostChanged { active_host });
            }
        }
        self.last_peer_state = Some(mapped_peer_state);
        self.last_active_host = Some(active_host);
    }
}

/// Derives the selected peer's connection state from count-only manager
/// snapshot when the routing table has no per-host entry yet.
fn peer_state_from_counts(snapshot: &PeerManagerSnapshot) -> PeerState {
    if snapshot.session_tasks > 0 {
        PeerState::Connected
    } else if snapshot.connecting_tasks > 0 {
        PeerState::Connecting
    } else if snapshot.peers_with_candidates > 0 {
        PeerState::Discovering
    } else {
        PeerState::Disconnected
    }
}

/// Maps the daemon's peer connection state onto the §31 control DTO.
const fn control_peer_state(state: PeerState) -> ControlPeerState {
    match state {
        PeerState::Disconnected => ControlPeerState::Disconnected,
        PeerState::Discovering => ControlPeerState::Discovering,
        PeerState::Connecting => ControlPeerState::Connecting,
        PeerState::Authenticating => ControlPeerState::Authenticating,
        PeerState::Connected => ControlPeerState::Connected,
        PeerState::Degraded => ControlPeerState::Degraded,
    }
}

/// Maps one inventory device onto the §31 control DTO. The inventory snapshot
/// does not carry per-device overrides, so every device reports the daemon's
/// default follow-active-host policy.
fn control_device_summary(device: &kvm_types::InputDevice) -> ControlDeviceSummary {
    ControlDeviceSummary {
        device_id: WireDeviceId(device.id.into_bytes()),
        host_id: WireHostId(device.host_id.into_bytes()),
        name: device.name.clone(),
        kind: control_device_kind(device.kind),
        route: ControlDeviceRoute::FollowActiveHost,
    }
}

const fn control_device_kind(kind: DeviceKind) -> ControlDeviceKind {
    match kind {
        DeviceKind::Keyboard => ControlDeviceKind::Keyboard,
        DeviceKind::Mouse => ControlDeviceKind::Mouse,
        DeviceKind::Trackpad => ControlDeviceKind::Trackpad,
        // `DeviceKind` is non-exhaustive upstream; unknown local classes
        // report the protocol's Other bucket.
        _ => ControlDeviceKind::Other,
    }
}

/// Maps one local display onto the §31 control DTO (logical units, scale in
/// whole percent).
fn control_display_summary(display: &Display) -> ControlDisplaySummary {
    ControlDisplaySummary {
        display_id: WireDisplayId(display.id.into_bytes()),
        host_id: WireHostId(display.host_id.into_bytes()),
        name: display.name.clone(),
        logical_width: logical_dimension(display.logical_size.width),
        logical_height: logical_dimension(display.logical_size.height),
        scale_factor_percent: logical_dimension(display.scale_factor * 100.0),
        primary: display.primary,
    }
}

/// Converts a logical display dimension to whole units for the control view.
/// Non-finite or negative values report zero rather than saturating.
fn logical_dimension(value: f64) -> u32 {
    let rounded = value.round();
    if rounded.is_finite() && rounded >= 0.0 && rounded <= f64::from(u32::MAX) {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "range-checked immediately above"
        )]
        {
            rounded as u32
        }
    } else {
        0
    }
}

const fn control_edge_side(edge: kvm_types::Edge) -> ControlEdgeSide {
    match edge {
        kvm_types::Edge::Left => ControlEdgeSide::Left,
        kvm_types::Edge::Right => ControlEdgeSide::Right,
        kvm_types::Edge::Top => ControlEdgeSide::Top,
        kvm_types::Edge::Bottom => ControlEdgeSide::Bottom,
    }
}

/// Maps the configured topology links onto §31 edges. Every bidirectional
/// link yields one edge per side so the panel can walk the map from either
/// display.
fn control_edges(config: &Config) -> Vec<ControlTopologyEdge> {
    let mut edges = Vec::new();
    for link in &config.topology.links {
        edges.push(ControlTopologyEdge {
            from: WireDisplayId(link.from_display.into_bytes()),
            side: control_edge_side(link.from_edge),
            to: WireDisplayId(link.to_display.into_bytes()),
        });
        edges.push(ControlTopologyEdge {
            from: WireDisplayId(link.to_display.into_bytes()),
            side: control_edge_side(link.to_edge),
            to: WireDisplayId(link.from_display.into_bytes()),
        });
    }
    edges.truncate(MAX_CONTROL_SNAPSHOT_ITEMS);
    edges
}

/// Publishes a freshly enumerated local display inventory into the shared
/// §31 view cell. Best-effort: the control view reports the observed
/// inventory while routing remains gated by the manager's own revisioned
/// acceptance of the same snapshot.
fn update_control_displays(cell: &Arc<Mutex<ControlServiceView>>, displays: &[Display]) {
    if let Ok(mut view) = cell.lock() {
        view.displays = displays.iter().map(control_display_summary).collect();
        view.displays.truncate(MAX_CONTROL_SNAPSHOT_ITEMS);
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
        mut self,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), RuntimeTransportError> {
        let identity = self.host_identity.clone();
        // Seed the control plane with the inventoried displays and topology so
        // §31 GetDisplays/GetDisplaysTopology answer real data, mirroring
        // `run_with_capture_status`.
        let control = ControlPlane::start(
            identity,
            std::mem::take(&mut self.control_displays),
            std::mem::take(&mut self.control_edges),
            LocalControlServerConfig::default(),
        );
        self.run_transport_ready(
            shutdown,
            None,
            Instant::now(),
            None,
            empty_capture_cell(),
            control,
        )
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
        self.run_with_capture_status(backend, shutdown, None, None)
            .await
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

    #[allow(
        clippy::too_many_lines,
        reason = "service select branches are clearer when kept together"
    )]
    pub(crate) async fn run_with_capture_status<B>(
        mut self,
        backend: B,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        status: Option<RuntimeStatusPublisher>,
        mut watch: Option<LocalInventoryWatch>,
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
        // Best-effort §31 control plane (spec §31): monitoring only, so its
        // startup cannot gate input. The shared view cell lets the hotplug
        // path below refresh the display section without touching the plane.
        let control = ControlPlane::start(
            self.host_identity.clone(),
            std::mem::take(&mut self.control_displays),
            std::mem::take(&mut self.control_edges),
            LocalControlServerConfig::default(),
        );
        let control_view_cell = control.cell();
        let mut transport_task = tokio::spawn(self.run_transport_ready(
            transport_receiver,
            Some(ready_sender),
            started,
            status.clone(),
            Arc::clone(&capture_cell),
            control,
        ));
        Self::await_transport_ready(&mut transport_task, ready_receiver).await?;
        if *shutdown.borrow() {
            developer_event("service=stopped_before_capture");
            let _ = transport_shutdown.send(true);
            return coarse_join_outcome(transport_task.await);
        }

        let mut capture = NativeCaptureSupervisor::new(backend, Arc::clone(&manager));
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
        // Local hotplug refresh state: hints accumulate as demand while a
        // refresh pass is in flight; each pass consumes the demand captured at
        // spawn time so late hints trigger a follow-up pass.
        let mut inventory_demand = InventoryRefreshDemand::default();
        let mut inventory_refresh: Option<tokio::task::JoinHandle<InventoryRefreshOutcome>> = None;
        let mut next_display_revision = INITIAL_DISPLAY_REVISION + 1;
        let mut next_device_revision = INITIAL_DEVICE_REVISION + 1;
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
                result = async {
                    match inventory_refresh.as_mut() {
                        Some(handle) => handle.await,
                        None => std::future::pending().await,
                    }
                }, if inventory_refresh.is_some() => {
                    inventory_refresh = None;
                    match result {
                        Ok(outcome) => {
                            // The §31 control view reports the observed
                            // display inventory even when the manager's own
                            // revisioned acceptance below is rejected.
                            if let Some(displays) = outcome.displays.as_ref() {
                                update_control_displays(&control_view_cell, displays);
                            }
                            apply_local_inventory_refresh(
                                &manager,
                                outcome,
                                &mut next_display_revision,
                                &mut next_device_revision,
                                now_ns(started),
                            );
                        }
                        Err(_) => developer_event("hotplug=refresh_task_failed"),
                    }
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
                    if let Some(watch) = watch.as_mut() {
                        while let Some(hint) = watch.poll_hint() {
                            match hint {
                                LocalInventoryHint::DisplaysChanged => {
                                    inventory_demand.displays = true;
                                }
                                LocalInventoryHint::DevicesChanged => {
                                    inventory_demand.devices = true;
                                }
                            }
                        }
                    }
                    if inventory_refresh.is_none() && inventory_demand.any() {
                        if let Some(watch) = watch.as_ref() {
                            let refresh_displays = Arc::clone(&watch.refresh_displays);
                            let refresh_devices = Arc::clone(&watch.refresh_devices);
                            let want_displays = inventory_demand.displays;
                            let want_devices = inventory_demand.devices;
                            inventory_demand = InventoryRefreshDemand::default();
                            developer_event("hotplug=refresh_started");
                            inventory_refresh = Some(tokio::task::spawn_blocking(move || {
                                InventoryRefreshOutcome {
                                    displays: want_displays
                                        .then(|| refresh_displays())
                                        .flatten(),
                                    devices: want_devices
                                        .then(|| refresh_devices())
                                        .flatten(),
                                }
                            }));
                        } else {
                            inventory_demand = InventoryRefreshDemand::default();
                        }
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
        reason = "transport select branches are clearer when kept together"
    )]
    async fn run_transport_ready(
        self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        ready: Option<tokio::sync::oneshot::Sender<()>>,
        started: Instant,
        status: Option<RuntimeStatusPublisher>,
        capture_cell: CaptureDiagnosticsCell,
        mut control: ControlPlane,
    ) -> Result<(), RuntimeTransportError> {
        // Bind diagnostics before the KVM listener consumes `listen_addresses`.
        let diagnostics_publisher =
            bind_diagnostics_server(&self.listen_addresses, &self.host_identity, started);
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
        let mut diagnostics_tick = tokio::time::interval(Duration::from_secs(1));
        diagnostics_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
                        if session_tasks.is_empty() {
                            diagnostics_publisher.clear_network();
                        }
                    }
                    _ = tick.tick() => {
                        service_manager(&self.manager, started)?;
                        control.drain_commands(&self.manager, now_ns(started));
                        let previous = &mut last_manager_snapshot;
                        report_manager_snapshot(&self.manager, previous, status.as_ref(), &mut control);
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
                    _ = diagnostics_tick.tick() => {
                        publish_capture_snapshot(&diagnostics_publisher, &capture_cell, started);
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
        // The §31 service owns its shutdown signal; settle it so the
        // endpoint file is released before the runtime exits.
        control.shutdown_service().await;
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
    control: &mut ControlPlane,
) where
    I: OutputInjectionBackend,
{
    // R-1: this is a best-effort diagnostic read and status publish. A failure
    // here reads no pressed-key state, so it must never propagate and tear down
    // the transport loop — log and return instead.
    let (manager_snapshot, routing, devices) = {
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
        let devices = manager.device_inventory_snapshot().ok();
        (manager_snapshot, routing, devices)
    };
    control.refresh(manager_snapshot, &routing, devices);
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
                    &identity,
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
    identity: &LocalHostIdentity,
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
    identity: &LocalHostIdentity,
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

/// Applies one fresh local inventory snapshot through the existing, already
/// revisioned manager paths. Best-effort by design: a rejected update (for
/// example a newly attached display with no configured topology placement, or
/// a busy pointer transition) is logged and abandoned — the next physical
/// change produces a fresh hint, and the daemon's own retry machinery
/// reconciles any partially staged device update.
fn apply_local_inventory_refresh<I>(
    manager: &Arc<Mutex<PeerManager<I, ManagedSessionOutbound>>>,
    outcome: InventoryRefreshOutcome,
    next_display_revision: &mut u64,
    next_device_revision: &mut u64,
    now_ns: u64,
) where
    I: OutputInjectionBackend,
{
    if let Some(displays) = outcome.displays {
        let revision = *next_display_revision;
        *next_display_revision = next_display_revision.saturating_add(1);
        match lock_manager(manager) {
            Ok(mut manager) => {
                if manager
                    .apply_local_display_snapshot(revision, displays, now_ns)
                    .is_ok()
                {
                    developer_event("hotplug=display_inventory_refreshed");
                } else {
                    developer_event("hotplug=display_inventory_refresh_rejected");
                }
            }
            Err(_) => developer_event("hotplug=refresh_manager_unavailable detail:display"),
        }
    }
    if let Some(devices) = outcome.devices {
        let revision = *next_device_revision;
        *next_device_revision = next_device_revision.saturating_add(1);
        match lock_manager(manager) {
            Ok(mut manager) => {
                if manager
                    .replace_local_device_inventory(revision, devices, now_ns)
                    .is_ok()
                {
                    developer_event("hotplug=device_inventory_refreshed");
                } else {
                    developer_event("hotplug=device_inventory_refresh_rejected");
                }
            }
            Err(_) => developer_event("hotplug=refresh_manager_unavailable detail:device"),
        }
    }
}

fn now_ns(started: Instant) -> u64 {
    duration_ns(now_duration(started))
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

pub(crate) fn developer_event(message: &str) {
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
        // Read-only §31 status slice, retained so the control service can
        // answer GetPeers without re-reading credentials.
        let selected_peer = SelectedPeerIdentity {
            host_id: parts.remote_identity.host_id(),
            peer_id: remote_peer,
            display_name: parts.remote_identity.display_name().to_owned(),
        };
        // §31 view sections owned by composition: the observed local display
        // inventory and the configured topology edges.
        let control_displays = local_displays
            .iter()
            .map(control_display_summary)
            .collect::<Vec<_>>();
        let control_edges = control_edges(&parts.config);
        let prepared_workspace = prepare_workspace(&parts.config, local_host, local_displays)?;

        // `LOCAL_PLATFORM` is the binding domain of the compiled-in native
        // backend, which is exactly what compose assembles here.
        let core = DaemonCore::new(
            parts.config.clone(),
            prepared_workspace.initial_state,
            LOCAL_PLATFORM,
        )
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
        // The daemon binary installs the process panic hook; this manager
        // must observe it so a panic anywhere fails open (release + gate).
        manager.arm_panic_failsafe();
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
                selected_peer,
            },
            control_displays,
            control_edges,
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

    #[test]
    fn control_peer_state_maps_every_daemon_variant() {
        let pairs = [
            (PeerState::Disconnected, ControlPeerState::Disconnected),
            (PeerState::Discovering, ControlPeerState::Discovering),
            (PeerState::Connecting, ControlPeerState::Connecting),
            (PeerState::Authenticating, ControlPeerState::Authenticating),
            (PeerState::Connected, ControlPeerState::Connected),
            (PeerState::Degraded, ControlPeerState::Degraded),
        ];
        for (daemon, control) in pairs {
            assert_eq!(control_peer_state(daemon), control);
        }
    }

    #[test]
    fn peer_state_from_counts_prefers_sessions_then_dials_then_discovery() {
        let base = PeerManagerSnapshot {
            paired_peers: 1,
            peers_with_candidates: 0,
            connecting_tasks: 0,
            session_tasks: 0,
            revoked_peers: 0,
        };
        assert_eq!(peer_state_from_counts(&base), PeerState::Disconnected);
        assert_eq!(
            peer_state_from_counts(&PeerManagerSnapshot {
                peers_with_candidates: 1,
                ..base
            }),
            PeerState::Discovering
        );
        assert_eq!(
            peer_state_from_counts(&PeerManagerSnapshot {
                peers_with_candidates: 1,
                connecting_tasks: 1,
                ..base
            }),
            PeerState::Connecting
        );
        assert_eq!(
            peer_state_from_counts(&PeerManagerSnapshot {
                peers_with_candidates: 1,
                connecting_tasks: 1,
                session_tasks: 1,
                ..base
            }),
            PeerState::Connected
        );
    }

    #[test]
    fn control_edges_map_each_configured_link_from_both_sides() {
        let mut config = config_with_local_placement();
        config.topology.links.push(TopologyLink {
            from_display: DISPLAY,
            from_edge: Edge::Right,
            to_display: REMOTE_DISPLAY,
            to_edge: Edge::Left,
        });

        let edges = control_edges(&config);

        assert_eq!(edges.len(), 2);
        assert!(edges.contains(&ControlTopologyEdge {
            from: WireDisplayId(DISPLAY.into_bytes()),
            side: ControlEdgeSide::Right,
            to: WireDisplayId(REMOTE_DISPLAY.into_bytes()),
        }));
        assert!(edges.contains(&ControlTopologyEdge {
            from: WireDisplayId(REMOTE_DISPLAY.into_bytes()),
            side: ControlEdgeSide::Left,
            to: WireDisplayId(DISPLAY.into_bytes()),
        }));
    }

    #[test]
    fn control_display_summary_uses_logical_units_and_percent_scale() {
        let summary = control_display_summary(&display(LOCAL_HOST, true));

        assert_eq!(summary.display_id, WireDisplayId(DISPLAY.into_bytes()));
        assert_eq!(summary.host_id, WireHostId(LOCAL_HOST.into_bytes()));
        assert_eq!(summary.name, "local");
        assert_eq!(summary.logical_width, 200);
        assert_eq!(summary.logical_height, 100);
        assert_eq!(summary.scale_factor_percent, 200);
        assert!(summary.primary);
    }

    #[test]
    fn logical_dimension_rounds_and_reports_zero_out_of_range() {
        assert_eq!(logical_dimension(1512.4), 1512);
        assert_eq!(logical_dimension(0.4), 0);
        assert_eq!(logical_dimension(-12.0), 0);
        assert_eq!(logical_dimension(f64::NAN), 0);
        assert_eq!(logical_dimension(f64::INFINITY), 0);
        assert_eq!(logical_dimension(f64::from(u32::MAX) + 16.0), 0);
    }

    // Unix-gated like the daemon crate's transport tests: the named-pipe
    // server on Windows rejects a filesystem socket path, so the bind
    // assertion below is only meaningful where UDS exists.
    #[cfg(unix)]
    #[tokio::test]
    async fn control_view_refresh_publishes_change_events_and_carries_display_sections() {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

        fn unique_socket_path() -> std::path::PathBuf {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
            std::env::temp_dir().join(format!(
                "skvm-control-plane-test-{}-{unique}.sock",
                std::process::id()
            ))
        }

        let identity = LocalHostIdentity {
            host_id: LOCAL_HOST,
            peer_id: kvm_types::PeerId::from_bytes([0x66; 16]),
            platform: kvm_types::Platform::MacOS,
            selected_peer: SelectedPeerIdentity {
                host_id: OTHER_HOST,
                peer_id: kvm_types::PeerId::from_bytes([0x77; 16]),
                display_name: "Office Windows".to_owned(),
            },
        };
        let displays = vec![control_display_summary(&display(LOCAL_HOST, true))];
        let edges = control_edges(&config_with_local_placement());
        let mut plane = ControlPlane::start(
            identity,
            displays.clone(),
            edges.clone(),
            LocalControlServerConfig::new(unique_socket_path()),
        );
        assert!(plane.events.is_some(), "the plane must bind in tests");

        let counts = PeerManagerSnapshot {
            paired_peers: 1,
            peers_with_candidates: 0,
            connecting_tasks: 0,
            session_tasks: 1,
            revoked_peers: 0,
        };
        plane.refresh_parts(
            LOCAL_HOST,
            DISPLAY,
            true,
            Some(PeerState::Connected),
            counts,
            None,
        );

        let view = SharedControlView(plane.cell()).control_view();
        assert!(view.status.kvm_enabled);
        assert_eq!(view.status.peer_state, ControlPeerState::Connected);
        assert_eq!(view.status.active_host, WireHostId(LOCAL_HOST.into_bytes()));
        assert!(!view.status.clipboard_enabled);
        assert_eq!(view.status.protocol_version, CURRENT_PROTOCOL_VERSION);
        assert_eq!(view.peers.len(), 1);
        assert_eq!(view.peers[0].host_name, "Office Windows");
        assert_eq!(view.peers[0].state, ControlPeerState::Connected);
        assert!(view.devices.is_empty());
        // Composition-owned sections survive the refresh.
        assert_eq!(view.displays, displays);
        assert_eq!(view.edges, edges);

        // A peer-state and authority change publishes §31 events.
        let mut events = plane.events.as_ref().expect("events present").subscribe();
        plane.refresh_parts(
            OTHER_HOST,
            REMOTE_DISPLAY,
            true,
            Some(PeerState::Degraded),
            counts,
            None,
        );
        let mut seen = Vec::new();
        while let Ok(event) = events.try_recv() {
            seen.push(event);
        }
        assert!(seen.contains(&ControlEvent::PeerChanged));
        assert!(seen.contains(&ControlEvent::ActiveHostChanged {
            active_host: WireHostId(OTHER_HOST.into_bytes()),
        }));

        // An owner-loop gate close is reflected in the status view.
        plane.kvm_gate = false;
        plane.refresh_parts(OTHER_HOST, REMOTE_DISPLAY, true, None, counts, None);
        let gated = SharedControlView(plane.cell()).control_view();
        assert!(!gated.status.kvm_enabled);
        // With no routing-table entry the count-derived state applies.
        assert_eq!(gated.status.peer_state, ControlPeerState::Connected);

        plane.shutdown_service().await;
    }
}
