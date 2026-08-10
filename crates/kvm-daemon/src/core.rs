use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use kvm_config::{Config, ConfigError, ShortcutKey};
use kvm_input::{ButtonState, InputEvent, InputPayload, KeyCode, KeyState, PointerButton};
use kvm_router::{Destination, InputRouter, RoutingTable, MAX_DEVICE_ROUTES};
use kvm_types::{DeviceId, DeviceRoute, HostId, WorkspaceState};
use thiserror::Error;
use tracing::{info, warn};

use crate::platform::{CaptureDisposition, CapturedInput, EventClassification};
use crate::session_endpoint::SessionEndpoint;

/// Maximum physical devices which may retain state at one time.
pub(crate) const MAX_PHYSICAL_HELD_DEVICES: usize = 64;
/// Maximum keys and buttons retained for one physical device.
pub(crate) const MAX_PHYSICAL_HELD_PER_DEVICE: usize = 256;
/// Maximum keys and buttons retained across all physical devices.
pub(crate) const MAX_PHYSICAL_HELD_TOTAL: usize = 1_024;
/// Maximum remotely held controls retained until release is confirmed.
pub(crate) const MAX_REMOTE_HELD_TOTAL: usize = 1_024;
/// Maximum retryable release effects retained by the core.
pub(crate) const MAX_PENDING_REMOTE_CLEANUP: usize = 1_024;
/// Maximum explicitly unavailable local devices retained across inventory
/// publication. Route-policy staging has its own independently bounded set.
pub(crate) const MAX_GATED_LOCAL_DEVICES: usize = MAX_DEVICE_ROUTES;

/// Operational connection state relevant to safe input routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerState {
    Disconnected,
    Discovering,
    Connecting,
    Authenticating,
    Connected,
    Degraded,
}

impl PeerState {
    const fn accepts_input(self) -> bool {
        matches!(self, Self::Connected)
    }
}

/// Read-only, internally consistent routing state for capture callbacks.
#[derive(Clone)]
pub struct RoutingSnapshot {
    pub workspace: WorkspaceState,
    pub routing: RoutingTable,
    pub peers: BTreeMap<HostId, PeerState>,
    pub enabled: bool,
    /// Fresh selected inventory and a healthy exact session have published a
    /// workspace which is eligible for routing.
    pub workspace_ready: bool,
    /// Pointer authority is between local and remote commit points. Capture
    /// must remain local while this fail-closed gate is set.
    pub handoff_pending: bool,
}

impl fmt::Debug for RoutingSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutingSnapshot")
            .field("peer_count", &self.peers.len())
            .field("enabled", &self.enabled)
            .field("workspace_ready", &self.workspace_ready)
            .field("handoff_pending", &self.handoff_pending)
            .field("workspace", &"[REDACTED]")
            .field("routing", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Lock-free reader for the latest immutable routing snapshot.
#[derive(Clone, Debug)]
pub struct RoutingSnapshotHandle {
    current: Arc<ArcSwap<RoutingSnapshot>>,
}

impl RoutingSnapshotHandle {
    /// Loads a stable snapshot that remains valid across concurrent updates.
    #[must_use]
    pub fn load(&self) -> Arc<RoutingSnapshot> {
        self.current.load_full()
    }
}

/// A release needed to clear remotely held input during recovery.
#[derive(Clone, Copy, PartialEq)]
pub struct RemoteRelease {
    pub target: HostId,
    pub source_device: DeviceId,
    pub payload: InputPayload,
}

impl fmt::Debug for RemoteRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteRelease([REDACTED])")
    }
}

/// Side effects for the transport layer. The daemon core performs no network
/// or native API calls itself.
#[derive(Clone, Copy, PartialEq)]
pub enum CoreAction {
    Forward { target: HostId, event: InputEvent },
    Release(RemoteRelease),
}

impl fmt::Debug for CoreAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Forward { .. } => "Forward",
            Self::Release(_) => "Release",
        };
        formatter
            .debug_struct("CoreAction")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

/// Complete result of handling one captured input event.
#[derive(Clone, PartialEq)]
pub struct ProcessResult {
    pub disposition: CaptureDisposition,
    pub actions: Vec<CoreAction>,
    pub failsafe_activated: bool,
}

impl fmt::Debug for ProcessResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessResult")
            .field("disposition", &self.disposition)
            .field("action_count", &self.actions.len())
            .field("failsafe_activated", &self.failsafe_activated)
            .finish_non_exhaustive()
    }
}

/// Coarse result category for one synchronous captured record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureRouteState {
    Local,
    Inert,
    RemoteQueued,
    Gated,
}

/// Compact result returned only after the required disposition is safe.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CaptureOutcome {
    disposition: CaptureDisposition,
    failsafe_activated: bool,
    state: CaptureRouteState,
}

impl CaptureOutcome {
    const fn local(failsafe_activated: bool, state: CaptureRouteState) -> Self {
        Self {
            disposition: CaptureDisposition::AllowLocal,
            failsafe_activated,
            state,
        }
    }

    const fn inert() -> Self {
        Self {
            disposition: CaptureDisposition::SuppressLocal,
            failsafe_activated: false,
            state: CaptureRouteState::Inert,
        }
    }

    pub(crate) const fn remote_queued() -> Self {
        Self {
            disposition: CaptureDisposition::SuppressLocal,
            failsafe_activated: false,
            state: CaptureRouteState::RemoteQueued,
        }
    }

    const fn gated_suppressed() -> Self {
        Self {
            disposition: CaptureDisposition::SuppressLocal,
            failsafe_activated: false,
            state: CaptureRouteState::Gated,
        }
    }

    #[must_use]
    pub const fn disposition(self) -> CaptureDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn failsafe_activated(self) -> bool {
        self.failsafe_activated
    }

    #[must_use]
    pub const fn state(self) -> CaptureRouteState {
        self.state
    }
}

impl fmt::Debug for CaptureOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureOutcome")
            .field("disposition", &self.disposition)
            .field("failsafe_activated", &self.failsafe_activated)
            .field("state", &self.state)
            .finish()
    }
}

/// A prepared remote input which has not yet entered the admitted FIFO.
#[must_use = "confirm FIFO acceptance or explicitly fail the prepared input"]
pub(crate) struct RemoteInputEffect {
    decision_id: u64,
    endpoint: SessionEndpoint,
    event: InputEvent,
    affine: AffineSeal,
}

impl RemoteInputEffect {
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn target(&self) -> HostId {
        self.endpoint.host_id()
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> SessionEndpoint {
        self.endpoint
    }

    #[must_use]
    pub(crate) const fn event(&self) -> InputEvent {
        self.event
    }
}

impl fmt::Debug for RemoteInputEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteInputEffect([REDACTED])")
    }
}

/// First phase of one synchronous routing decision.
#[must_use = "remote decisions must be confirmed or failed exactly once"]
pub(crate) enum CaptureDecision {
    Local(CaptureOutcome),
    Inert(CaptureOutcome),
    Remote(RemoteInputEffect),
    Fault {
        outcome: CaptureOutcome,
        error: CoreCaptureError,
    },
}

impl fmt::Debug for CaptureDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Local(_) => "Local",
            Self::Inert(_) => "Inert",
            Self::Remote(_) => "Remote",
            Self::Fault { .. } => "Fault",
        };
        formatter
            .debug_struct("CaptureDecision")
            .field("kind", &kind)
            .finish()
    }
}

/// One retryable cleanup release borrowed affinely from the queue front.
#[must_use = "confirm FIFO acceptance or return this release for retry"]
pub(crate) struct CleanupReleaseEffect {
    cleanup_id: u64,
    endpoint: SessionEndpoint,
    covered_input_sequence: u64,
    release: RemoteRelease,
    affine: AffineSeal,
}

impl CleanupReleaseEffect {
    #[must_use]
    pub(crate) const fn release(&self) -> RemoteRelease {
        self.release
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> SessionEndpoint {
        self.endpoint
    }

    #[must_use]
    pub(crate) const fn covered_input_sequence(&self) -> u64 {
        self.covered_input_sequence
    }
}

impl fmt::Debug for CleanupReleaseEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanupReleaseEffect([REDACTED])")
    }
}

/// Fail-closed routing-state failure. Details and stable identifiers are
/// deliberately unavailable to diagnostics.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CoreCaptureError {
    #[error("captured input routing is unavailable")]
    Unavailable,
    #[error("captured input state capacity was exceeded")]
    CapacityExceeded,
    #[error("captured input decision token is stale")]
    StaleDecision,
    #[error("remote cleanup token is stale")]
    StaleCleanup,
    #[error("remote cleanup must complete before this transition")]
    CleanupPending,
    #[error("captured input decision identifier space is exhausted")]
    IdentifierSpaceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PhysicalControl {
    Key(KeyCode),
    Button(PointerButton),
}

impl PhysicalControl {
    const fn from_payload(payload: InputPayload) -> Option<(Self, PhysicalTransition)> {
        match payload {
            InputPayload::Key { code, state } => Some((
                Self::Key(code),
                match state {
                    KeyState::Pressed => PhysicalTransition::Press,
                    KeyState::Repeated => PhysicalTransition::Repeat,
                    KeyState::Released => PhysicalTransition::Release,
                },
            )),
            InputPayload::PointerButton { button, state } => Some((
                Self::Button(button),
                match state {
                    ButtonState::Pressed => PhysicalTransition::Press,
                    ButtonState::Released => PhysicalTransition::Release,
                },
            )),
            InputPayload::PointerMove { .. } | InputPayload::Scroll { .. } => None,
        }
    }

    const fn release_payload(self) -> InputPayload {
        match self {
            Self::Key(code) => InputPayload::Key {
                code,
                state: KeyState::Released,
            },
            Self::Button(button) => InputPayload::PointerButton {
                button,
                state: ButtonState::Released,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhysicalTransition {
    Press,
    Repeat,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LatchedDestination {
    Local,
    Remote {
        endpoint: SessionEndpoint,
        route: DeviceRoute,
    },
    Quarantined,
}

#[derive(Clone, Copy)]
struct PendingRemoteDecision {
    id: u64,
    device: DeviceId,
    control: Option<PhysicalControl>,
    transition: Option<PhysicalTransition>,
    previous_latch: Option<LatchedDestination>,
    endpoint: SessionEndpoint,
}

struct CleanupEntry {
    id: u64,
    endpoint: SessionEndpoint,
    covered_input_sequence: u64,
    release: RemoteRelease,
    control: PhysicalControl,
}

#[derive(Clone, Copy)]
struct RemoteHeldState {
    route: DeviceRoute,
    last_input_sequence: u64,
}

#[derive(Clone, Copy)]
struct EndpointAvailability {
    endpoint: SessionEndpoint,
    state: PeerState,
}

struct PendingRoutePolicy {
    next_revision: u64,
    config: Config,
    routing: RoutingTable,
    affected_devices: BTreeSet<DeviceId>,
}

impl fmt::Debug for PendingRoutePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRoutePolicy")
            .field("affected_device_count", &self.affected_devices.len())
            .field("config", &"[REDACTED]")
            .field("routing", &"[REDACTED]")
            .field("revision", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Coarse progress for one retained route-policy candidate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RoutePolicyUpdateStatus {
    CleanupPending,
    ReadyToPersist,
}

impl fmt::Debug for RoutePolicyUpdateStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CleanupPending => "RoutePolicyUpdateStatus::CleanupPending",
            Self::ReadyToPersist => "RoutePolicyUpdateStatus::ReadyToPersist",
        })
    }
}

/// Coarse, identifier-free route-policy transaction failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RoutePolicyUpdateError {
    InvalidCandidate,
    StaleRevision,
    ConflictingUpdate,
    RevisionExhausted,
    CapturePending,
    CleanupUnavailable,
    NotReady,
}

impl fmt::Debug for RoutePolicyUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCandidate => "RoutePolicyUpdateError::InvalidCandidate",
            Self::StaleRevision => "RoutePolicyUpdateError::StaleRevision",
            Self::ConflictingUpdate => "RoutePolicyUpdateError::ConflictingUpdate",
            Self::RevisionExhausted => "RoutePolicyUpdateError::RevisionExhausted",
            Self::CapturePending => "RoutePolicyUpdateError::CapturePending",
            Self::CleanupUnavailable => "RoutePolicyUpdateError::CleanupUnavailable",
            Self::NotReady => "RoutePolicyUpdateError::NotReady",
        })
    }
}

impl fmt::Display for RoutePolicyUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCandidate => "route policy candidate is invalid",
            Self::StaleRevision => "route policy revision is stale",
            Self::ConflictingUpdate => "another route policy candidate is retained",
            Self::RevisionExhausted => "route policy revision space is exhausted",
            Self::CapturePending => "captured input reconciliation is pending",
            Self::CleanupUnavailable => "route policy cleanup is unavailable",
            Self::NotReady => "route policy candidate is not ready",
        })
    }
}

impl std::error::Error for RoutePolicyUpdateError {}

/// Read-only access to the exact retained durable payload. The view does not
/// implement `Clone` and its Debug output never renders policy or revision.
pub(crate) struct StagedRoutePolicy<'a> {
    pending: &'a PendingRoutePolicy,
}

impl StagedRoutePolicy<'_> {
    #[must_use]
    pub(crate) const fn revision(&self) -> u64 {
        self.pending.next_revision
    }

    #[must_use]
    pub(crate) const fn config(&self) -> &Config {
        &self.pending.config
    }
}

impl fmt::Debug for StagedRoutePolicy<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedRoutePolicy")
            .field("config", &"[REDACTED]")
            .field("revision", &"[REDACTED]")
            .finish()
    }
}

struct AffineSeal;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("invalid daemon configuration: {0}")]
    Config(#[from] ConfigError),
    #[error("workspace local host identity changed")]
    LocalHostChanged { expected: HostId, actual: HostId },
    #[error("initial workspace authority must be local and internally consistent")]
    InvalidInitialAuthority,
    #[error("runtime routing table construction failed")]
    InvalidRoutingTable,
    #[error("workspace transition is blocked by pending remote cleanup")]
    CleanupPending,
    #[error("workspace transition is blocked by an outstanding capture decision")]
    CapturePending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleState {
    Running { routing_requested: bool },
    ShuttingDown,
}

/// Authoritative mutable daemon state. Every mutating operation republishes a
/// single immutable view for platform callbacks.
pub struct DaemonCore {
    config: Config,
    workspace: WorkspaceState,
    routing: RoutingTable,
    peers: BTreeMap<HostId, PeerState>,
    endpoint_availability: BTreeMap<HostId, EndpointAvailability>,
    lifecycle: LifecycleState,
    suspended_until_ns: u64,
    drain_failsafe_keys: bool,
    physical_controls: BTreeMap<DeviceId, BTreeMap<PhysicalControl, LatchedDestination>>,
    physical_control_count: usize,
    remote_held: BTreeMap<(SessionEndpoint, DeviceId, PhysicalControl), RemoteHeldState>,
    cleanup: VecDeque<CleanupEntry>,
    cleanup_in_flight: Option<u64>,
    pending_remote: Option<PendingRemoteDecision>,
    pending_route_policy: Option<PendingRoutePolicy>,
    route_policy_revision: u64,
    gated_local_devices: BTreeSet<DeviceId>,
    next_effect_id: u64,
    workspace_ready: bool,
    handoff_pending: bool,
    snapshots: Arc<ArcSwap<RoutingSnapshot>>,
    /// §35 input-event-rate meter; present only with the `diagnostics` feature.
    #[cfg(feature = "diagnostics")]
    event_rate: kvm_input::EventRateMeter,
    /// §36 source-side capture→routing-decision latency history; present only
    /// with the `diagnostics` feature. The dest-side capture→injection span is
    /// owned by each peer session coordinator.
    #[cfg(feature = "diagnostics")]
    source_latency: kvm_input::LatencyHistory,
}

impl fmt::Debug for DaemonCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonCore")
            .field("lifecycle", &self.lifecycle)
            .field("peer_count", &self.peers.len())
            .field("draining_failsafe", &self.drain_failsafe_keys)
            .field("physical_control_count", &self.physical_control_count)
            .field("physical_device_count", &self.physical_controls.len())
            .field("remote_held_count", &self.remote_held.len())
            .field("pending_cleanup_count", &self.cleanup.len())
            .field(
                "route_policy_update_pending",
                &self.pending_route_policy.is_some(),
            )
            .field("gated_local_device_count", &self.gated_local_devices.len())
            .field("workspace_ready", &self.workspace_ready)
            .field("handoff_pending", &self.handoff_pending)
            .field("workspace", &"[REDACTED]")
            .field("routing", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl DaemonCore {
    /// Creates a running core after validating all durable configuration.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Config`] when configuration validation fails.
    pub fn new(config: Config, workspace: WorkspaceState) -> Result<Self, DaemonError> {
        config.validate()?;
        if workspace.local_host.into_bytes() == [0; 16]
            || workspace.active_host != workspace.local_host
            || workspace.active_display != workspace.pointer.display_id
        {
            return Err(DaemonError::InvalidInitialAuthority);
        }
        let routing = routing_from_config(&config)?;
        let peers: BTreeMap<HostId, PeerState> = config
            .paired_hosts
            .iter()
            .map(|peer| (peer.host_id, PeerState::Disconnected))
            .collect();
        let initial = RoutingSnapshot {
            workspace,
            routing: routing.clone(),
            peers: peers.clone(),
            enabled: false,
            workspace_ready: false,
            handoff_pending: false,
        };

        let route_policy_revision = config.device_route_revision;
        Ok(Self {
            config,
            workspace,
            routing,
            peers,
            endpoint_availability: BTreeMap::new(),
            lifecycle: LifecycleState::Running {
                routing_requested: true,
            },
            suspended_until_ns: 0,
            drain_failsafe_keys: false,
            physical_controls: BTreeMap::new(),
            physical_control_count: 0,
            remote_held: BTreeMap::new(),
            cleanup: VecDeque::new(),
            cleanup_in_flight: None,
            pending_remote: None,
            pending_route_policy: None,
            route_policy_revision,
            gated_local_devices: BTreeSet::new(),
            next_effect_id: 1,
            workspace_ready: false,
            handoff_pending: false,
            snapshots: Arc::new(ArcSwap::from_pointee(initial)),
            #[cfg(feature = "diagnostics")]
            event_rate: kvm_input::EventRateMeter::default(),
            #[cfg(feature = "diagnostics")]
            source_latency: kvm_input::LatencyHistory::default(),
        })
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// §35 input-event-rate snapshot for the diagnostics surface (spec §35).
    ///
    /// Only present when the daemon is built with the `diagnostics` feature;
    /// absent (like the meter itself) in release builds.
    #[cfg(feature = "diagnostics")]
    #[must_use]
    pub fn event_rate_snapshot(&self, now_ns: u64) -> kvm_input::EventRateSnapshot {
        self.event_rate.snapshot(now_ns)
    }

    /// §36 source-side capture→routing-decision latency statistics (spec §36).
    ///
    /// The capture→routing-decision span is the source-half of the input
    /// pipeline: how long after capture the daemon reached its routing
    /// decision. Returns `None` until the first event is processed. Only
    /// present when the daemon is built with the `diagnostics` feature.
    #[cfg(feature = "diagnostics")]
    #[must_use]
    pub fn source_latency_stats(&self) -> Option<kvm_input::LatencyStats> {
        self.source_latency.stats()
    }

    /// Unified §35/§36 diagnostics snapshot for the local control IPC surface
    /// (spec §31). Fills the §35 event-rate and §36 source-side latency portions
    /// from this core and composes the caller-supplied §35 injected-event count
    /// and §36 injection-latency stats (owned by a peer session coordinator) and
    /// §35 dropped-packets counters (owned by the outbound queue) into one
    /// wire-ready [`DiagnosticsSnapshot`].
    ///
    /// Only present when the daemon is built with the `diagnostics` feature.
    #[cfg(feature = "diagnostics")]
    #[must_use]
    pub fn diagnostics_snapshot(
        &self,
        now_ns: u64,
        injected_events: u64,
        injection_latency: Option<kvm_input::LatencyStats>,
        dropped_packets: kvm_network::DropCounters,
    ) -> crate::DiagnosticsSnapshot {
        crate::DiagnosticsSnapshot::from_parts(
            self.event_rate.snapshot(now_ns),
            injected_events,
            self.source_latency_stats(),
            injection_latency,
            dropped_packets,
        )
    }

    #[must_use]
    pub const fn workspace(&self) -> WorkspaceState {
        self.workspace
    }

    /// Returns whether routing is requested by configuration/lifecycle state.
    /// See [`Self::is_routing_active`] for callback-visible effective state.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        matches!(
            self.lifecycle,
            LifecycleState::Running {
                routing_requested: true
            }
        )
    }

    /// Returns whether suppression and remote forwarding are active in the
    /// most recently published callback snapshot. This can remain false after
    /// the requested state is enabled while a failsafe suspension is active.
    #[must_use]
    pub fn is_routing_active(&self) -> bool {
        self.snapshots.load().enabled
    }

    #[must_use]
    pub(crate) fn routing_handle(&self) -> RoutingSnapshotHandle {
        RoutingSnapshotHandle {
            current: Arc::clone(&self.snapshots),
        }
    }

    /// Prepares one captured record without reporting remote suppression.
    ///
    /// A returned remote effect is affine. The caller must enqueue its exact
    /// event on the selected admitted FIFO and then call
    /// [`Self::confirm_remote_input`], or call [`Self::fail_remote_input`] on
    /// every conversion, sequence, identity, or queue failure.
    ///
    /// # Errors
    ///
    /// Fails closed when bounded physical state or the checked decision space
    /// is exhausted, or another affine decision remains outstanding.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn prepare_captured(
        &mut self,
        captured: CapturedInput,
        now_ns: u64,
    ) -> Result<CaptureDecision, CoreCaptureError> {
        if self.pending_remote.is_some() {
            return Err(CoreCaptureError::Unavailable);
        }
        if captured.classification != EventClassification::Physical
            || captured.event.source_host != self.workspace.local_host
            || captured.event.source_device.into_bytes() == [0; 16]
            || !captured.event.payload.is_finite()
        {
            return Ok(CaptureDecision::Local(CaptureOutcome::local(
                false,
                CaptureRouteState::Local,
            )));
        }

        let device = captured.event.source_device;
        let stateful = PhysicalControl::from_payload(captured.event.payload);
        let (control, transition, previous_latch) = match stateful {
            Some((control, PhysicalTransition::Press)) => {
                let existing = self
                    .physical_controls
                    .get(&device)
                    .and_then(|controls| controls.get(&control))
                    .copied();
                if existing.is_none() {
                    if let Err(error) = self.ensure_physical_capacity(device) {
                        let _ = self.fail_closed(now_ns);
                        return Err(error);
                    }
                    self.physical_controls
                        .entry(device)
                        .or_default()
                        .insert(control, LatchedDestination::Local);
                    self.physical_control_count += 1;
                }
                (Some(control), Some(PhysicalTransition::Press), existing)
            }
            Some((control, PhysicalTransition::Repeat)) => {
                let existing = self
                    .physical_controls
                    .get(&device)
                    .and_then(|controls| controls.get(&control))
                    .copied();
                (Some(control), Some(PhysicalTransition::Repeat), existing)
            }
            Some((control, PhysicalTransition::Release)) => {
                let previous = self
                    .physical_controls
                    .get_mut(&device)
                    .and_then(|controls| controls.remove(&control));
                if previous.is_some() {
                    self.physical_control_count -= 1;
                    if self
                        .physical_controls
                        .get(&device)
                        .is_some_and(BTreeMap::is_empty)
                    {
                        self.physical_controls.remove(&device);
                    }
                }
                (Some(control), Some(PhysicalTransition::Release), previous)
            }
            None => (None, None, None),
        };

        if self.failsafe_matches() && !self.drain_failsafe_keys {
            self.drain_failsafe_keys = true;
            // The shortcut's local escape semantics take precedence over a
            // cleanup bookkeeping failure. `activate_failsafe` gates before
            // attempting cleanup, so this outcome remains safe and preserves
            // the activation signal for the platform callback.
            let outcome = CaptureOutcome::local(true, CaptureRouteState::Gated);
            return Ok(match self.activate_failsafe(now_ns) {
                Ok(()) => CaptureDecision::Local(outcome),
                Err(error) => CaptureDecision::Fault { outcome, error },
            });
        }
        if self.drain_failsafe_keys {
            if !self.any_failsafe_key_pressed() {
                self.drain_failsafe_keys = false;
            }
            self.publish(now_ns);
            return Ok(CaptureDecision::Local(CaptureOutcome::local(
                false,
                CaptureRouteState::Gated,
            )));
        }

        let route = self.routing.route_for(device);
        if matches!(
            transition,
            Some(PhysicalTransition::Repeat | PhysicalTransition::Release)
        ) && previous_latch.is_none()
        {
            return Ok(CaptureDecision::Local(CaptureOutcome::local(
                false,
                CaptureRouteState::Local,
            )));
        }
        let latch = previous_latch.or_else(|| {
            control.and_then(|value| {
                self.physical_controls
                    .get(&device)
                    .and_then(|controls| controls.get(&value))
                    .copied()
            })
        });
        match latch {
            Some(LatchedDestination::Local) if previous_latch.is_some() => {
                return Ok(CaptureDecision::Local(CaptureOutcome::local(
                    false,
                    CaptureRouteState::Local,
                )));
            }
            Some(LatchedDestination::Quarantined) => {
                return Ok(CaptureDecision::Inert(CaptureOutcome::inert()));
            }
            Some(LatchedDestination::Remote {
                endpoint,
                route: latched_route,
            }) => {
                if !self.remote_endpoint_available(endpoint, latched_route, now_ns) {
                    let outcome = CaptureOutcome::gated_suppressed();
                    return Ok(match self.fail_closed(now_ns) {
                        Ok(()) => CaptureDecision::Inert(outcome),
                        Err(error) => CaptureDecision::Fault { outcome, error },
                    });
                }
                return self.prepare_remote_effect(
                    captured.event,
                    endpoint,
                    control,
                    transition,
                    previous_latch,
                    now_ns,
                );
            }
            Some(LatchedDestination::Local) | None => {}
        }

        if self.device_route_is_gated(device) {
            return Ok(CaptureDecision::Local(CaptureOutcome::local(
                false,
                CaptureRouteState::Gated,
            )));
        }

        if self.handoff_pending && route == DeviceRoute::FollowActiveHost {
            if transition == Some(PhysicalTransition::Press) {
                if let Some(control) = control {
                    if let Some(latch) = self
                        .physical_controls
                        .get_mut(&device)
                        .and_then(|controls| controls.get_mut(&control))
                    {
                        *latch = LatchedDestination::Quarantined;
                    }
                }
            }
            return Ok(CaptureDecision::Inert(CaptureOutcome::inert()));
        }

        let destination = self.routing.destination(&captured.event, &self.workspace);
        let Destination::Remote(target) = destination else {
            return Ok(CaptureDecision::Local(CaptureOutcome::local(
                false,
                CaptureRouteState::Local,
            )));
        };
        let Some(endpoint) = self.remote_target_endpoint(target, route, now_ns) else {
            return Ok(CaptureDecision::Local(CaptureOutcome::local(
                false,
                CaptureRouteState::Gated,
            )));
        };
        self.prepare_remote_effect(
            captured.event,
            endpoint,
            control,
            transition,
            previous_latch,
            now_ns,
        )
    }

    /// Commits a prepared remote lifecycle mutation after exact FIFO success.
    ///
    /// # Errors
    ///
    /// Returns a coarse stale-token or capacity error and gates routing.
    pub(crate) fn confirm_remote_input(
        &mut self,
        effect: RemoteInputEffect,
        accepted_sequence: u64,
        now_ns: u64,
    ) -> Result<CaptureOutcome, CoreCaptureError> {
        let RemoteInputEffect {
            decision_id,
            endpoint: _,
            event: _,
            affine,
        } = effect;
        let AffineSeal = affine;
        let pending = self.take_matching_remote(decision_id, now_ns)?;
        match (pending.control, pending.transition) {
            (Some(control), Some(PhysicalTransition::Press)) => {
                let key = (pending.endpoint, pending.device, control);
                if !self.remote_held.contains_key(&key)
                    && self.remote_held.len() >= MAX_REMOTE_HELD_TOTAL
                {
                    self.fail_closed(now_ns)?;
                    return Err(CoreCaptureError::CapacityExceeded);
                }
                let route = pending.previous_latch.map_or(
                    self.routing.route_for(pending.device),
                    |latch| match latch {
                        LatchedDestination::Remote { route, .. } => route,
                        LatchedDestination::Local | LatchedDestination::Quarantined => {
                            self.routing.route_for(pending.device)
                        }
                    },
                );
                self.remote_held.insert(
                    key,
                    RemoteHeldState {
                        route,
                        last_input_sequence: accepted_sequence,
                    },
                );
                if let Some(latch) = self
                    .physical_controls
                    .get_mut(&pending.device)
                    .and_then(|controls| controls.get_mut(&control))
                {
                    *latch = LatchedDestination::Remote {
                        endpoint: pending.endpoint,
                        route,
                    };
                }
            }
            (Some(control), Some(PhysicalTransition::Release)) => {
                self.remote_held
                    .remove(&(pending.endpoint, pending.device, control));
            }
            (Some(control), Some(PhysicalTransition::Repeat)) => {
                let Some(held) =
                    self.remote_held
                        .get_mut(&(pending.endpoint, pending.device, control))
                else {
                    let _ = self.fail_closed(now_ns);
                    return Err(CoreCaptureError::StaleDecision);
                };
                held.last_input_sequence = accepted_sequence;
            }
            (Some(_) | None, None) | (None, Some(_)) => {}
        }
        self.publish(now_ns);
        Ok(CaptureOutcome::remote_queued())
    }

    /// Reconciles a prepared remote record which did not enter the FIFO.
    ///
    /// # Errors
    ///
    /// Returns a coarse stale-token or cleanup-capacity error after routing is
    /// gated and existing remote lifecycles are quarantined.
    pub(crate) fn fail_remote_input(
        &mut self,
        effect: RemoteInputEffect,
        now_ns: u64,
    ) -> Result<CaptureOutcome, CoreCaptureError> {
        let RemoteInputEffect {
            decision_id,
            endpoint: _,
            event: _,
            affine,
        } = effect;
        let AffineSeal = affine;
        let pending = self.take_matching_remote(decision_id, now_ns)?;
        if pending.transition == Some(PhysicalTransition::Press) && pending.previous_latch.is_none()
        {
            if let Some(control) = pending.control {
                if let Some(latch) = self
                    .physical_controls
                    .get_mut(&pending.device)
                    .and_then(|controls| controls.get_mut(&control))
                {
                    *latch = LatchedDestination::Local;
                }
            }
        }
        let suppress = matches!(
            pending.previous_latch,
            Some(LatchedDestination::Remote { .. })
        );
        // A cleanup capacity/counter failure must not erase the disposition:
        // an already-remote lifecycle remains suppressed until its physical
        // release, while a first press may safely fall back locally.
        let _ = self.fail_closed(now_ns);
        Ok(if suppress {
            CaptureOutcome::gated_suppressed()
        } else {
            CaptureOutcome::local(false, CaptureRouteState::Gated)
        })
    }

    /// Conservative compatibility entry point. It never exposes an
    /// undispatched remote action and therefore always fails remote decisions
    /// back to local control.
    #[must_use]
    pub fn process_captured(&mut self, captured: CapturedInput, now_ns: u64) -> ProcessResult {
        // §35 input-event-rate: record every captured event by its capture
        // timestamp (no extra clock read). Dev-only; absent without the feature.
        #[cfg(feature = "diagnostics")]
        self.event_rate.record(captured.event.timestamp_ns);
        // §36 source-side sub-span: capture→routing-decision. The capture
        // instant travels on the event; `now_ns` is the routing-decision
        // instant supplied by the caller, so this needs no extra clock read.
        // Dev-only; absent without the feature.
        #[cfg(feature = "diagnostics")]
        {
            let stamps = kvm_input::LatencyStamps::default()
                .with_capture(captured.event.timestamp_ns)
                .with_routing_decision(now_ns);
            if let Some(span) =
                stamps.span_ns(kvm_input::LatencyStage::Capture, kvm_input::LatencyStage::RoutingDecision)
            {
                self.source_latency.push(span);
            }
        }
        let decision = self.prepare_captured(captured, now_ns);
        let outcome = match decision {
            Ok(
                CaptureDecision::Local(outcome)
                | CaptureDecision::Inert(outcome)
                | CaptureDecision::Fault { outcome, .. },
            ) => outcome,
            Ok(CaptureDecision::Remote(effect)) => self
                .fail_remote_input(effect, now_ns)
                .unwrap_or_else(|_| CaptureOutcome::local(false, CaptureRouteState::Gated)),
            Err(_) => CaptureOutcome::local(false, CaptureRouteState::Gated),
        };
        ProcessResult {
            disposition: outcome.disposition(),
            actions: Vec::new(),
            failsafe_activated: outcome.failsafe_activated(),
        }
    }

    /// Publishes time-dependent state changes without adding allocation or
    /// synchronization work to ordinary input events.
    ///
    /// Returns true when the callback-visible routing state changed. Calling
    /// this from the daemon's lightweight lifecycle timer after a failsafe
    /// window expires re-enables routing conservatively.
    pub fn tick(&mut self, now_ns: u64) -> bool {
        if self.drain_failsafe_keys && !self.any_failsafe_key_pressed() {
            self.drain_failsafe_keys = false;
        }
        let should_be_active = self.routing_should_be_active(now_ns);
        if self.snapshots.load().enabled == should_be_active {
            return false;
        }
        self.publish(now_ns);
        true
    }

    /// Compatibility entry point for an in-memory route policy update.
    ///
    /// A cleanup-blocked candidate is retained. Retrying with a different
    /// candidate cannot replace it; callers which persist configuration must
    /// use the crate-private staged transaction API below.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Config`] for invalid settings.
    pub fn update_config(&mut self, config: Config, now_ns: u64) -> Result<(), DaemonError> {
        if config.device_routes == self.config.device_routes
            && config.device_route_revision == self.route_policy_revision
        {
            if self.pending_remote.is_some() {
                return Err(DaemonError::CapturePending);
            }
            if self.pending_route_policy.is_some() {
                return Err(DaemonError::CleanupPending);
            }
            config.validate()?;
            let routing = routing_from_config(&config)?;
            if self.cleanup_pending() {
                return Err(DaemonError::CleanupPending);
            }
            self.queue_remote_cleanup(|_, endpoint, _| {
                !config.paired_hosts.iter().any(|peer| {
                    peer.host_id == endpoint.host_id() && peer.peer_id == endpoint.peer_id()
                })
            })
            .map_err(|_| DaemonError::CleanupPending)?;
            if self.cleanup_pending() {
                self.publish(now_ns);
                return Err(DaemonError::CleanupPending);
            }
            self.peers
                .retain(|host, _| config.paired_hosts.iter().any(|peer| peer.host_id == *host));
            for peer in &config.paired_hosts {
                self.peers
                    .entry(peer.host_id)
                    .or_insert(PeerState::Disconnected);
            }
            if !self.peers.contains_key(&self.workspace.active_host)
                && self.workspace.active_host != self.workspace.local_host
            {
                self.workspace.active_host = self.workspace.local_host;
                self.workspace_ready = false;
                self.handoff_pending = false;
            }
            self.config = config;
            self.routing = routing;
            self.publish(now_ns);
            info!("daemon configuration changed without a route policy change");
            return Ok(());
        }
        let expected_revision = self.route_policy_revision;
        let status =
            self.prepare_route_policy_update(config, expected_revision, now_ns)
                .map_err(|error| match error {
                    RoutePolicyUpdateError::CapturePending => DaemonError::CapturePending,
                    RoutePolicyUpdateError::CleanupUnavailable
                    | RoutePolicyUpdateError::NotReady => DaemonError::CleanupPending,
                    RoutePolicyUpdateError::InvalidCandidate
                    | RoutePolicyUpdateError::StaleRevision
                    | RoutePolicyUpdateError::ConflictingUpdate
                    | RoutePolicyUpdateError::RevisionExhausted => DaemonError::InvalidRoutingTable,
                })?;
        if status == RoutePolicyUpdateStatus::CleanupPending {
            return Err(DaemonError::CleanupPending);
        }
        let next_revision = self
            .staged_route_policy()
            .map(|staged| staged.revision())
            .ok_or(DaemonError::InvalidRoutingTable)?;
        self.commit_route_policy_update(next_revision, now_ns)
            .map_err(|_| DaemonError::InvalidRoutingTable)?;
        Ok(())
    }

    /// Returns the committed durable route-policy revision.
    #[must_use]
    pub(crate) const fn route_policy_revision(&self) -> u64 {
        self.route_policy_revision
    }

    pub(crate) const fn route_policy_update_pending(&self) -> bool {
        self.pending_route_policy.is_some()
    }

    /// Validates and retains exactly one checked route-policy candidate.
    ///
    /// Only `device_routes` and the checked durable revision may differ from
    /// the committed configuration. Validation, table construction, revision
    /// allocation, cleanup-capacity checks, and affected-device calculation
    /// all complete before the candidate becomes observable.
    pub(crate) fn prepare_route_policy_update(
        &mut self,
        mut candidate: Config,
        expected_revision: u64,
        now_ns: u64,
    ) -> Result<RoutePolicyUpdateStatus, RoutePolicyUpdateError> {
        if self.pending_remote.is_some() {
            return Err(RoutePolicyUpdateError::CapturePending);
        }
        if self.handoff_pending {
            return Err(RoutePolicyUpdateError::CleanupUnavailable);
        }
        if let Some(pending) = &self.pending_route_policy {
            candidate.device_route_revision = pending.next_revision;
            return if expected_revision == self.route_policy_revision && candidate == pending.config
            {
                self.route_policy_update_status()
            } else if expected_revision != self.route_policy_revision {
                Err(RoutePolicyUpdateError::StaleRevision)
            } else {
                Err(RoutePolicyUpdateError::ConflictingUpdate)
            };
        }
        if expected_revision != self.route_policy_revision {
            return Err(RoutePolicyUpdateError::StaleRevision);
        }
        let next_revision = self
            .route_policy_revision
            .checked_add(1)
            .ok_or(RoutePolicyUpdateError::RevisionExhausted)?;
        candidate.device_route_revision = next_revision;
        candidate
            .validate()
            .map_err(|_| RoutePolicyUpdateError::InvalidCandidate)?;
        let routing = routing_from_config(&candidate)
            .map_err(|_| RoutePolicyUpdateError::InvalidCandidate)?;

        let mut expected_candidate = self.config.clone();
        expected_candidate
            .device_routes
            .clone_from(&candidate.device_routes);
        expected_candidate.device_route_revision = next_revision;
        if candidate != expected_candidate {
            return Err(RoutePolicyUpdateError::InvalidCandidate);
        }

        let affected_devices =
            affected_route_devices(&self.config, &candidate, &self.routing, &routing);
        if self.cleanup_pending() {
            return Err(RoutePolicyUpdateError::CleanupUnavailable);
        }
        let workspace = self.workspace;
        let endpoint_availability = self.endpoint_availability.clone();
        self.queue_remote_cleanup(|_, endpoint, device| {
            affected_devices.contains(&device)
                && !route_resolves_to_endpoint(
                    routing.route_for(device),
                    endpoint,
                    workspace,
                    &endpoint_availability,
                )
        })
        .map_err(|_| RoutePolicyUpdateError::CleanupUnavailable)?;
        self.pending_route_policy = Some(PendingRoutePolicy {
            next_revision,
            config: candidate,
            routing,
            affected_devices,
        });
        self.publish(now_ns);
        self.route_policy_update_status()
    }

    /// Reports progress for the retained candidate after cleanup retries or
    /// terminal transport invalidation. It never accepts a replacement.
    pub(crate) fn retry_route_policy_update(
        &mut self,
        now_ns: u64,
    ) -> Result<RoutePolicyUpdateStatus, RoutePolicyUpdateError> {
        if self.pending_remote.is_some() {
            return Err(RoutePolicyUpdateError::CapturePending);
        }
        if self.pending_route_policy.is_none() {
            return Err(RoutePolicyUpdateError::NotReady);
        }
        let pending = self
            .pending_route_policy
            .as_ref()
            .ok_or(RoutePolicyUpdateError::NotReady)?;
        let routing = pending.routing.clone();
        let affected_devices = pending.affected_devices.clone();
        let workspace = self.workspace;
        let endpoint_availability = self.endpoint_availability.clone();
        self.queue_remote_cleanup(|_, endpoint, device| {
            affected_devices.contains(&device)
                && !route_resolves_to_endpoint(
                    routing.route_for(device),
                    endpoint,
                    workspace,
                    &endpoint_availability,
                )
        })
        .map_err(|_| RoutePolicyUpdateError::CleanupUnavailable)?;
        self.publish(now_ns);
        self.route_policy_update_status()
    }

    /// Borrows the exact durable candidate for persistence. Callers must only
    /// persist this returned payload; cleanup-blocked candidates are not
    /// exposed through this API.
    #[must_use]
    pub(crate) fn staged_route_policy(&self) -> Option<StagedRoutePolicy<'_>> {
        let pending = self.pending_route_policy.as_ref()?;
        (!self.cleanup_pending() && !self.pending_route_has_unresolved_remote())
            .then_some(StagedRoutePolicy { pending })
    }

    /// Commits the exact persisted candidate. Once readiness has been checked,
    /// this path performs no validation, cleanup allocation, or fallible table
    /// construction.
    pub(crate) fn commit_route_policy_update(
        &mut self,
        next_revision: u64,
        now_ns: u64,
    ) -> Result<u64, RoutePolicyUpdateError> {
        if self.pending_remote.is_some() {
            return Err(RoutePolicyUpdateError::CapturePending);
        }
        if self.route_policy_update_status()? != RoutePolicyUpdateStatus::ReadyToPersist {
            return Err(RoutePolicyUpdateError::NotReady);
        }
        let pending = self
            .pending_route_policy
            .take()
            .ok_or(RoutePolicyUpdateError::NotReady)?;
        if pending.next_revision != next_revision {
            self.pending_route_policy = Some(pending);
            return Err(RoutePolicyUpdateError::ConflictingUpdate);
        }

        let endpoint_availability = self.endpoint_availability.clone();
        for ((endpoint, device, _), held) in &mut self.remote_held {
            let candidate_route = pending.routing.route_for(*device);
            debug_assert!(route_resolves_to_endpoint(
                candidate_route,
                *endpoint,
                self.workspace,
                &endpoint_availability,
            ));
            held.route = candidate_route;
        }
        for (device, controls) in &mut self.physical_controls {
            let candidate_route = pending.routing.route_for(*device);
            for latch in controls.values_mut() {
                if let LatchedDestination::Remote { route, .. } = latch {
                    *route = candidate_route;
                }
            }
        }
        self.config = pending.config;
        self.routing = pending.routing;
        self.route_policy_revision = next_revision;
        self.publish(now_ns);
        info!("input route policy changed");
        Ok(next_revision)
    }

    /// Aborts only the retained candidate. Releases already queued or sent
    /// remain owned by the ordinary cleanup ledger and are never discarded.
    pub(crate) fn abort_route_policy_update(
        &mut self,
        next_revision: u64,
        now_ns: u64,
    ) -> Result<(), RoutePolicyUpdateError> {
        let pending = self
            .pending_route_policy
            .as_ref()
            .ok_or(RoutePolicyUpdateError::NotReady)?;
        if pending.next_revision != next_revision {
            return Err(RoutePolicyUpdateError::ConflictingUpdate);
        }
        self.pending_route_policy = None;
        self.publish(now_ns);
        Ok(())
    }

    /// Gates one explicitly unplugged local device and owns releases for only
    /// that device without modifying its durable route policy.
    #[cfg(test)]
    pub(crate) fn gate_local_device(
        &mut self,
        device: DeviceId,
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        self.gate_local_devices(&[device], now_ns)
    }

    /// Atomically reserves bounded unplug gates for a complete inventory
    /// transaction before any cleanup entry is allocated.
    pub(crate) fn gate_local_devices(
        &mut self,
        devices: &[DeviceId],
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some()
            || devices.iter().any(|device| device.into_bytes() == [0; 16])
        {
            return Err(CoreCaptureError::Unavailable);
        }
        let requested = devices.iter().copied().collect::<BTreeSet<_>>();
        let added = requested
            .iter()
            .filter(|device| !self.gated_local_devices.contains(device))
            .count();
        if self.gated_local_devices.len().saturating_add(added) > MAX_GATED_LOCAL_DEVICES {
            return Err(CoreCaptureError::CapacityExceeded);
        }
        self.gated_local_devices.extend(requested.iter().copied());
        let queued =
            self.queue_remote_cleanup(|_, _, held_device| requested.contains(&held_device));
        self.publish(now_ns);
        queued
    }

    /// Restores an explicitly present device only after every remote lifecycle
    /// for that stable identifier has ended. The completed unplug is terminal
    /// proof for its old physical controls, which are discarded before the
    /// stable identifier can begin a new attachment lifecycle.
    pub(crate) fn restore_local_device(
        &mut self,
        device: DeviceId,
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        let lifecycle_pending = self
            .remote_held
            .keys()
            .any(|(_, held_device, _)| *held_device == device)
            || self
                .cleanup
                .iter()
                .any(|entry| entry.release.source_device == device);
        if lifecycle_pending {
            return Err(CoreCaptureError::CleanupPending);
        }
        if let Some(controls) = self.physical_controls.remove(&device) {
            self.physical_control_count =
                self.physical_control_count.saturating_sub(controls.len());
        }
        self.gated_local_devices.remove(&device);
        self.publish(now_ns);
        Ok(())
    }

    /// Updates the logical workspace, releasing held input before an active-host
    /// transition.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::LocalHostChanged`] if the immutable host identity
    /// differs from the one supplied at startup.
    pub fn update_workspace(
        &mut self,
        workspace: WorkspaceState,
        now_ns: u64,
    ) -> Result<(), DaemonError> {
        if self.pending_remote.is_some() {
            return Err(DaemonError::CapturePending);
        }
        if self.pending_route_policy.is_some() {
            return Err(DaemonError::CleanupPending);
        }
        if workspace.local_host != self.workspace.local_host {
            return Err(DaemonError::LocalHostChanged {
                expected: self.workspace.local_host,
                actual: workspace.local_host,
            });
        }
        if workspace.active_display != workspace.pointer.display_id {
            return Err(DaemonError::InvalidInitialAuthority);
        }
        if workspace.active_host != self.workspace.active_host {
            self.queue_remote_cleanup(|route, _, _| route == DeviceRoute::FollowActiveHost)
                .map_err(|_| DaemonError::CleanupPending)?;
            if self.cleanup_pending() {
                self.publish(now_ns);
                return Err(DaemonError::CleanupPending);
            }
        }
        let previous = self.workspace.active_host;
        self.workspace = workspace;
        self.publish(now_ns);
        if previous != workspace.active_host {
            info!(
                changed = previous != workspace.active_host,
                "active host changed"
            );
        }
        Ok(())
    }

    /// Publishes a fail-closed pointer handoff gate before a Commit can enter
    /// the transport FIFO and returns releases which must precede it.
    pub(crate) fn begin_pointer_handoff(&mut self, now_ns: u64) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some() || self.pending_route_policy.is_some() {
            return Err(CoreCaptureError::Unavailable);
        }
        self.handoff_pending = true;
        let queued =
            self.queue_remote_cleanup(|route, _, _| route == DeviceRoute::FollowActiveHost);
        self.publish(now_ns);
        queued
    }

    /// Rolls an uncommitted pointer handoff back to normal local routing.
    pub(crate) fn cancel_pointer_handoff(&mut self, now_ns: u64) {
        self.handoff_pending = false;
        self.workspace.active_host = self.workspace.local_host;
        self.publish(now_ns);
    }

    /// Aborts a destination-side pre-Ack barrier without changing the
    /// authority which existed before the inbound handoff proposal.
    pub(crate) fn abort_destination_handoff_barrier(&mut self, now_ns: u64) {
        self.handoff_pending = false;
        self.publish(now_ns);
    }

    /// Publishes the post-Commit workspace and re-enables effective routing.
    pub(crate) fn finish_pointer_handoff(
        &mut self,
        workspace: WorkspaceState,
        now_ns: u64,
    ) -> Result<(), DaemonError> {
        if self.pending_remote.is_some() {
            return Err(DaemonError::CapturePending);
        }
        if self.pending_route_policy.is_some() {
            return Err(DaemonError::CleanupPending);
        }
        if self.cleanup_pending() {
            return Err(DaemonError::CleanupPending);
        }
        self.update_workspace(workspace, now_ns)?;
        self.handoff_pending = false;
        self.publish(now_ns);
        Ok(())
    }

    /// Changes peer health. Any non-connected transition releases held input;
    /// losing the active peer immediately restores the local host.
    ///
    /// # Errors
    ///
    /// Fails when an affine capture decision is outstanding or bounded
    /// cleanup ownership cannot be established.
    pub fn set_peer_state(
        &mut self,
        host: HostId,
        state: PeerState,
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some() {
            return Err(CoreCaptureError::Unavailable);
        }
        if !self.peers.contains_key(&host) {
            warn!(?state, "ignored state for unconfigured peer");
            return Ok(());
        }
        if self.endpoint_availability.contains_key(&host) {
            return Err(CoreCaptureError::Unavailable);
        }
        self.peers.insert(host, state);
        self.publish(now_ns);
        info!(
            ?state,
            cleanup_count = self.cleanup.len(),
            "pre-admission peer state changed"
        );
        Ok(())
    }

    /// Installs the exact network-minted endpoint which alone may authorize
    /// remote routing for its configured host.
    pub(crate) fn install_session_endpoint(
        &mut self,
        endpoint: SessionEndpoint,
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some()
            || !self.config.paired_hosts.iter().any(|peer| {
                peer.host_id == endpoint.host_id() && peer.peer_id == endpoint.peer_id()
            })
        {
            return Err(CoreCaptureError::Unavailable);
        }
        if let Some(current) = self.endpoint_availability.get(&endpoint.host_id()).copied() {
            if current.endpoint != endpoint {
                return Err(CoreCaptureError::Unavailable);
            }
        }
        self.endpoint_availability.insert(
            endpoint.host_id(),
            EndpointAvailability {
                endpoint,
                state: PeerState::Connected,
            },
        );
        self.peers.insert(endpoint.host_id(), PeerState::Connected);
        self.publish(now_ns);
        Ok(())
    }

    /// Changes availability only for the exact currently installed endpoint.
    pub(crate) fn set_endpoint_state(
        &mut self,
        endpoint: SessionEndpoint,
        state: PeerState,
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some()
            || self
                .endpoint_availability
                .get(&endpoint.host_id())
                .is_none_or(|current| current.endpoint != endpoint)
        {
            return Err(CoreCaptureError::Unavailable);
        }
        if let Some(current) = self.endpoint_availability.get_mut(&endpoint.host_id()) {
            current.state = state;
        }
        self.peers.insert(endpoint.host_id(), state);
        let queued = if state.accepts_input() {
            Ok(())
        } else {
            if self.workspace.active_host == endpoint.host_id() {
                self.workspace.active_host = self.workspace.local_host;
            }
            self.handoff_pending = false;
            self.workspace_ready = false;
            self.queue_remote_cleanup(|_, held_endpoint, _| held_endpoint == endpoint)
        };
        self.publish(now_ns);
        queued
    }

    /// Retires a non-accepting endpoint only after every exact FIFO obligation
    /// for it has settled. Unlike terminal invalidation, this discards no held
    /// or cleanup state.
    pub(crate) fn retire_session_endpoint(
        &mut self,
        endpoint: SessionEndpoint,
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some()
            || self
                .endpoint_availability
                .get(&endpoint.host_id())
                .is_none_or(|current| current.endpoint != endpoint || current.state.accepts_input())
            || self.endpoint_has_obligations(endpoint)
        {
            return Err(CoreCaptureError::CleanupPending);
        }
        self.endpoint_availability.remove(&endpoint.host_id());
        self.peers
            .insert(endpoint.host_id(), PeerState::Disconnected);
        if self.workspace.active_host == endpoint.host_id() {
            self.workspace.active_host = self.workspace.local_host;
        }
        self.workspace_ready = false;
        self.handoff_pending = false;
        self.publish(now_ns);
        Ok(())
    }

    /// Enables routing unless shutdown has begun.
    pub fn enable(&mut self, now_ns: u64) {
        if let LifecycleState::Running { routing_requested } = &mut self.lifecycle {
            *routing_requested = true;
            self.publish(now_ns);
            info!("KVM routing enabled");
        }
    }

    /// Disables routing and deterministically releases all remote held state.
    ///
    /// # Errors
    ///
    /// Fails when an affine decision is outstanding or cleanup cannot be
    /// retained within its positive bound.
    pub fn disable(&mut self, now_ns: u64) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some() {
            return Err(CoreCaptureError::Unavailable);
        }
        if let LifecycleState::Running { routing_requested } = &mut self.lifecycle {
            *routing_requested = false;
        }
        self.workspace.active_host = self.workspace.local_host;
        self.handoff_pending = false;
        let queued = self.queue_remote_cleanup(|_, _, _| true);
        self.publish(now_ns);
        queued?;
        info!(cleanup_count = self.cleanup.len(), "KVM routing disabled");
        Ok(())
    }

    /// Activates the permanent local emergency path without requiring a
    /// captured shortcut event.
    ///
    /// # Errors
    ///
    /// Fails when an affine decision is outstanding or cleanup cannot be
    /// retained. Routing remains conservatively gated.
    pub fn trigger_emergency(&mut self, now_ns: u64) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some() {
            return Err(CoreCaptureError::Unavailable);
        }
        self.drain_failsafe_keys = true;
        self.activate_failsafe(now_ns)
    }

    /// Permanently stops this core and returns final cleanup actions.
    ///
    /// # Errors
    ///
    /// Fails when an affine decision is outstanding or cleanup cannot be
    /// retained for retry.
    pub fn shutdown(&mut self, now_ns: u64) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some() {
            return Err(CoreCaptureError::Unavailable);
        }
        self.lifecycle = LifecycleState::ShuttingDown;
        self.workspace.active_host = self.workspace.local_host;
        self.handoff_pending = false;
        let queued = self.queue_remote_cleanup(|_, _, _| true);
        self.publish(now_ns);
        queued?;
        info!(cleanup_count = self.cleanup.len(), "daemon core shut down");
        Ok(())
    }

    fn activate_failsafe(&mut self, now_ns: u64) -> Result<(), CoreCaptureError> {
        self.suspended_until_ns = now_ns.saturating_add(
            u64::from(self.config.failsafe.routing_suspend_seconds) * 1_000_000_000,
        );
        self.workspace.active_host = self.workspace.local_host;
        self.handoff_pending = false;
        let queued = self.queue_remote_cleanup(|_, _, _| true);
        if queued.is_err() {
            self.workspace_ready = false;
        }
        self.publish(now_ns);
        warn!(
            suspended_until_ns = self.suspended_until_ns,
            cleanup_count = self.cleanup.len(),
            "emergency failsafe triggered"
        );
        queued
    }

    fn failsafe_matches(&self) -> bool {
        self.config
            .failsafe
            .shortcut
            .iter()
            .all(|key| self.shortcut_key_pressed(*key))
    }

    fn any_failsafe_key_pressed(&self) -> bool {
        self.config
            .failsafe
            .shortcut
            .iter()
            .any(|key| self.shortcut_key_pressed(*key))
    }

    /// Immediately gates workspace routing and owns every required remote
    /// release until FIFO confirmation or terminal transport invalidation.
    pub(crate) fn clear_workspace_routing_ready(
        &mut self,
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some() {
            return Err(CoreCaptureError::Unavailable);
        }
        self.workspace_ready = false;
        self.workspace.active_host = self.workspace.local_host;
        self.handoff_pending = false;
        let queued = self.queue_remote_cleanup(|_, _, _| true);
        self.publish(now_ns);
        queued
    }

    /// Marks a freshly compiled selected workspace eligible for remote input.
    pub(crate) fn mark_workspace_routing_ready(
        &mut self,
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        if self.pending_remote.is_some()
            || self.cleanup_pending()
            || !self.remote_held.is_empty()
            || !self
                .endpoint_availability
                .values()
                .any(|availability| availability.state.accepts_input())
            || !matches!(self.lifecycle, LifecycleState::Running { .. })
        {
            return Err(CoreCaptureError::Unavailable);
        }
        self.workspace_ready = true;
        self.publish(now_ns);
        Ok(())
    }

    #[must_use]
    pub const fn workspace_routing_ready(&self) -> bool {
        self.workspace_ready
    }

    #[must_use]
    pub fn cleanup_pending(&self) -> bool {
        !self.cleanup.is_empty() || self.cleanup_in_flight.is_some()
    }

    /// Affinely borrows the exact cleanup queue front for one send attempt.
    pub(crate) fn take_next_cleanup_release(&mut self) -> Option<CleanupReleaseEffect> {
        if self.cleanup_in_flight.is_some() {
            return None;
        }
        let entry = self.cleanup.front()?;
        self.cleanup_in_flight = Some(entry.id);
        Some(CleanupReleaseEffect {
            cleanup_id: entry.id,
            endpoint: entry.endpoint,
            covered_input_sequence: entry.covered_input_sequence,
            release: entry.release,
            affine: AffineSeal,
        })
    }

    /// Removes the exact cleanup front only after its `ReleaseInput` entered the
    /// admitted FIFO.
    ///
    /// # Errors
    ///
    /// Returns a coarse stale-token error and gates routing.
    pub(crate) fn confirm_cleanup_release(
        &mut self,
        effect: CleanupReleaseEffect,
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        let CleanupReleaseEffect {
            cleanup_id,
            endpoint: _,
            covered_input_sequence: _,
            release: _,
            affine,
        } = effect;
        let AffineSeal = affine;
        if self.cleanup_in_flight != Some(cleanup_id)
            || self.cleanup.front().map(|entry| entry.id) != Some(cleanup_id)
        {
            self.workspace_ready = false;
            self.publish(now_ns);
            return Err(CoreCaptureError::StaleCleanup);
        }
        let entry = self
            .cleanup
            .pop_front()
            .ok_or(CoreCaptureError::StaleCleanup)?;
        self.cleanup_in_flight = None;
        self.remote_held
            .remove(&(entry.endpoint, entry.release.source_device, entry.control));
        self.publish(now_ns);
        Ok(())
    }

    /// Returns a failed cleanup send to the exact queue front.
    ///
    /// # Errors
    ///
    /// Returns a coarse stale-token error and gates routing.
    pub(crate) fn retry_cleanup_release(
        &mut self,
        effect: CleanupReleaseEffect,
        now_ns: u64,
    ) -> Result<(), CoreCaptureError> {
        let CleanupReleaseEffect {
            cleanup_id,
            endpoint: _,
            covered_input_sequence: _,
            release: _,
            affine,
        } = effect;
        let AffineSeal = affine;
        if self.cleanup_in_flight != Some(cleanup_id)
            || self.cleanup.front().map(|entry| entry.id) != Some(cleanup_id)
        {
            self.workspace_ready = false;
            self.publish(now_ns);
            return Err(CoreCaptureError::StaleCleanup);
        }
        self.cleanup_in_flight = None;
        self.workspace_ready = false;
        self.workspace.active_host = self.workspace.local_host;
        self.handoff_pending = false;
        self.publish(now_ns);
        Ok(())
    }

    /// Confirms that one terminal transport can no longer retain input. This
    /// is the only operation which may discard unqueued releases.
    pub(crate) fn confirm_transport_invalidated(&mut self, endpoint: SessionEndpoint, now_ns: u64) {
        let is_current = self
            .endpoint_availability
            .get(&endpoint.host_id())
            .is_some_and(|current| current.endpoint == endpoint);
        if is_current {
            self.endpoint_availability.remove(&endpoint.host_id());
            if let Some(state) = self.peers.get_mut(&endpoint.host_id()) {
                *state = PeerState::Disconnected;
            }
        }
        if is_current && self.workspace.active_host == endpoint.host_id() {
            self.workspace.active_host = self.workspace.local_host;
        }
        if is_current {
            self.workspace_ready = false;
            self.handoff_pending = false;
        }
        let in_flight_host = self
            .cleanup
            .front()
            .filter(|entry| Some(entry.id) == self.cleanup_in_flight)
            .map(|entry| entry.endpoint);
        self.cleanup.retain(|entry| entry.endpoint != endpoint);
        if in_flight_host == Some(endpoint) {
            self.cleanup_in_flight = None;
        }
        self.remote_held
            .retain(|(held_endpoint, _, _), _| *held_endpoint != endpoint);
        for controls in self.physical_controls.values_mut() {
            for latch in controls.values_mut() {
                if matches!(*latch, LatchedDestination::Remote { endpoint: held, .. } if held == endpoint)
                {
                    *latch = LatchedDestination::Quarantined;
                }
            }
        }
        self.publish(now_ns);
    }

    fn prepare_remote_effect(
        &mut self,
        event: InputEvent,
        endpoint: SessionEndpoint,
        control: Option<PhysicalControl>,
        transition: Option<PhysicalTransition>,
        previous_latch: Option<LatchedDestination>,
        now_ns: u64,
    ) -> Result<CaptureDecision, CoreCaptureError> {
        if transition == Some(PhysicalTransition::Press)
            && control.is_some()
            && previous_latch.is_none()
            && self.remote_held.len() >= MAX_REMOTE_HELD_TOTAL
        {
            let _ = self.fail_closed(now_ns);
            return Err(CoreCaptureError::CapacityExceeded);
        }
        let Ok(id) = self.allocate_effect_id() else {
            let cleanup_error = self.fail_closed(now_ns).err();
            let outcome = if matches!(previous_latch, Some(LatchedDestination::Remote { .. })) {
                CaptureOutcome::gated_suppressed()
            } else {
                CaptureOutcome::local(false, CaptureRouteState::Gated)
            };
            return Ok(CaptureDecision::Fault {
                outcome,
                error: cleanup_error.unwrap_or(CoreCaptureError::IdentifierSpaceExhausted),
            });
        };
        self.pending_remote = Some(PendingRemoteDecision {
            id,
            device: event.source_device,
            control,
            transition,
            previous_latch,
            endpoint,
        });
        Ok(CaptureDecision::Remote(RemoteInputEffect {
            decision_id: id,
            endpoint,
            event,
            affine: AffineSeal,
        }))
    }

    fn take_matching_remote(
        &mut self,
        decision_id: u64,
        now_ns: u64,
    ) -> Result<PendingRemoteDecision, CoreCaptureError> {
        if self.pending_remote.as_ref().map(|pending| pending.id) != Some(decision_id) {
            self.workspace_ready = false;
            self.workspace.active_host = self.workspace.local_host;
            self.handoff_pending = false;
            self.publish(now_ns);
            return Err(CoreCaptureError::StaleDecision);
        }
        self.pending_remote
            .take()
            .ok_or(CoreCaptureError::StaleDecision)
    }

    fn allocate_effect_id(&mut self) -> Result<u64, CoreCaptureError> {
        let id = self.next_effect_id;
        self.next_effect_id = id
            .checked_add(1)
            .ok_or(CoreCaptureError::IdentifierSpaceExhausted)?;
        Ok(id)
    }

    fn ensure_physical_capacity(&mut self, device: DeviceId) -> Result<(), CoreCaptureError> {
        let existing = self.physical_controls.get(&device);
        if existing.is_none() && self.physical_controls.len() >= MAX_PHYSICAL_HELD_DEVICES
            || existing.is_some_and(|controls| controls.len() >= MAX_PHYSICAL_HELD_PER_DEVICE)
            || self.physical_control_count >= MAX_PHYSICAL_HELD_TOTAL
        {
            self.workspace_ready = false;
            self.workspace.active_host = self.workspace.local_host;
            return Err(CoreCaptureError::CapacityExceeded);
        }
        Ok(())
    }

    fn remote_target_endpoint(
        &self,
        target: HostId,
        route: DeviceRoute,
        now_ns: u64,
    ) -> Option<SessionEndpoint> {
        let availability = self.endpoint_availability.get(&target)?;
        (self.routing_should_be_active(now_ns)
            && (!self.handoff_pending || route != DeviceRoute::FollowActiveHost)
            && availability.state.accepts_input())
        .then_some(availability.endpoint)
    }

    fn remote_endpoint_available(
        &self,
        endpoint: SessionEndpoint,
        route: DeviceRoute,
        now_ns: u64,
    ) -> bool {
        self.remote_target_endpoint(endpoint.host_id(), route, now_ns) == Some(endpoint)
    }

    fn fail_closed(&mut self, now_ns: u64) -> Result<(), CoreCaptureError> {
        self.workspace_ready = false;
        self.workspace.active_host = self.workspace.local_host;
        self.handoff_pending = false;
        let queued = self.queue_remote_cleanup(|_, _, _| true);
        self.publish(now_ns);
        queued
    }

    fn queue_remote_cleanup(
        &mut self,
        affected: impl Fn(DeviceRoute, SessionEndpoint, DeviceId) -> bool,
    ) -> Result<(), CoreCaptureError> {
        let existing: BTreeSet<_> = self
            .cleanup
            .iter()
            .map(|entry| (entry.endpoint, entry.release.source_device, entry.control))
            .collect();
        let candidates: Vec<_> = self
            .remote_held
            .iter()
            .filter_map(|(&(endpoint, device, control), held)| {
                (affected(held.route, endpoint, device)
                    && !existing.contains(&(endpoint, device, control)))
                .then_some((endpoint, device, control, held.last_input_sequence))
            })
            .collect();
        if self.cleanup.len().saturating_add(candidates.len()) > MAX_PENDING_REMOTE_CLEANUP {
            return Err(CoreCaptureError::CapacityExceeded);
        }
        let end = self
            .next_effect_id
            .checked_add(
                u64::try_from(candidates.len())
                    .map_err(|_| CoreCaptureError::IdentifierSpaceExhausted)?,
            )
            .ok_or(CoreCaptureError::IdentifierSpaceExhausted)?;
        for (endpoint, device, control, covered_input_sequence) in candidates {
            let id = self.next_effect_id;
            self.next_effect_id += 1;
            self.cleanup.push_back(CleanupEntry {
                id,
                endpoint,
                covered_input_sequence,
                release: RemoteRelease {
                    target: endpoint.host_id(),
                    source_device: device,
                    payload: control.release_payload(),
                },
                control,
            });
            if let Some(latch) = self
                .physical_controls
                .get_mut(&device)
                .and_then(|controls| controls.get_mut(&control))
            {
                if matches!(*latch, LatchedDestination::Remote { endpoint: held, .. } if held == endpoint)
                {
                    *latch = LatchedDestination::Quarantined;
                }
            }
        }
        debug_assert_eq!(self.next_effect_id, end);
        Ok(())
    }

    fn shortcut_key_pressed(&self, shortcut: ShortcutKey) -> bool {
        self.physical_controls.values().any(|controls| {
            controls.keys().any(|control| {
                let PhysicalControl::Key(key) = control else {
                    return false;
                };
                shortcut_matches_key(shortcut, *key)
            })
        })
    }

    fn publish(&self, now_ns: u64) {
        self.snapshots.store(Arc::new(RoutingSnapshot {
            workspace: self.workspace,
            routing: self.routing.clone(),
            peers: self.peers.clone(),
            enabled: self.routing_should_be_active(now_ns),
            workspace_ready: self.workspace_ready,
            handoff_pending: self.handoff_pending,
        }));
    }

    fn routing_should_be_active(&self, now_ns: u64) -> bool {
        self.is_enabled()
            && now_ns >= self.suspended_until_ns
            && !self.drain_failsafe_keys
            && self.workspace_ready
            // A retained route transaction owns a bounded per-device gate, so
            // its cleanup does not unnecessarily stop unrelated device routes.
            // Any transport retry failure clears `workspace_ready` and returns
            // to the ordinary global fail-closed path.
            && (!self.cleanup_pending() || self.pending_route_policy.is_some())
            && self.pending_remote.is_none()
    }

    fn route_policy_update_status(
        &self,
    ) -> Result<RoutePolicyUpdateStatus, RoutePolicyUpdateError> {
        if self.pending_route_policy.is_none() {
            return Err(RoutePolicyUpdateError::NotReady);
        }
        Ok(
            if self.cleanup_pending() || self.pending_route_has_unresolved_remote() {
                RoutePolicyUpdateStatus::CleanupPending
            } else {
                RoutePolicyUpdateStatus::ReadyToPersist
            },
        )
    }

    fn pending_route_has_unresolved_remote(&self) -> bool {
        let Some(pending) = &self.pending_route_policy else {
            return false;
        };
        self.remote_held.iter().any(|(&(endpoint, device, _), _)| {
            pending.affected_devices.contains(&device)
                && !route_resolves_to_endpoint(
                    pending.routing.route_for(device),
                    endpoint,
                    self.workspace,
                    &self.endpoint_availability,
                )
        })
    }

    fn device_route_is_gated(&self, device: DeviceId) -> bool {
        self.gated_local_devices.contains(&device)
            || self
                .pending_route_policy
                .as_ref()
                .is_some_and(|pending| pending.affected_devices.contains(&device))
    }

    fn endpoint_has_obligations(&self, endpoint: SessionEndpoint) -> bool {
        self.remote_held
            .keys()
            .any(|(held_endpoint, _, _)| *held_endpoint == endpoint)
            || self.cleanup.iter().any(|entry| entry.endpoint == endpoint)
            || self
                .pending_remote
                .as_ref()
                .is_some_and(|pending| pending.endpoint == endpoint)
    }
}

fn affected_route_devices(
    current_config: &Config,
    candidate_config: &Config,
    current: &RoutingTable,
    candidate: &RoutingTable,
) -> BTreeSet<DeviceId> {
    current_config
        .device_routes
        .iter()
        .map(|route| route.device_id)
        .chain(
            candidate_config
                .device_routes
                .iter()
                .map(|route| route.device_id),
        )
        .filter(|device| current.route_for(*device) != candidate.route_for(*device))
        .collect()
}

fn route_resolves_to_target(route: DeviceRoute, target: HostId, workspace: WorkspaceState) -> bool {
    match route {
        DeviceRoute::Local => target == workspace.local_host,
        DeviceRoute::FollowActiveHost => {
            target == workspace.active_host && target != workspace.local_host
        }
        DeviceRoute::Host(host) => host == target && target != workspace.local_host,
    }
}

fn route_resolves_to_endpoint(
    route: DeviceRoute,
    endpoint: SessionEndpoint,
    workspace: WorkspaceState,
    availability: &BTreeMap<HostId, EndpointAvailability>,
) -> bool {
    route_resolves_to_target(route, endpoint.host_id(), workspace)
        && availability
            .get(&endpoint.host_id())
            .is_some_and(|current| current.endpoint == endpoint)
}

fn routing_from_config(config: &Config) -> Result<RoutingTable, DaemonError> {
    RoutingTable::try_from_routes(
        config
            .device_routes
            .iter()
            .map(|route| (route.device_id, route.route.into())),
    )
    .map_err(|_| DaemonError::InvalidRoutingTable)
}

const fn shortcut_matches_key(shortcut: ShortcutKey, key: KeyCode) -> bool {
    match shortcut {
        ShortcutKey::Control => matches!(key, KeyCode::ControlLeft | KeyCode::ControlRight),
        ShortcutKey::Alt => matches!(key, KeyCode::AltLeft | KeyCode::AltRight),
        ShortcutKey::Shift => matches!(key, KeyCode::ShiftLeft | KeyCode::ShiftRight),
        ShortcutKey::Meta => matches!(key, KeyCode::MetaLeft | KeyCode::MetaRight),
        ShortcutKey::Backspace => matches!(key, KeyCode::Backspace),
        ShortcutKey::Escape => matches!(key, KeyCode::Escape),
        ShortcutKey::Physical { usage_page, usage } => matches!(
            key,
            KeyCode::Unidentified {
                usage_page: actual_page,
                usage_id: actual_usage,
            } if actual_page == usage_page && actual_usage == usage
        ),
    }
}

#[cfg(test)]
mod tests {
    use kvm_config::{ConfiguredDeviceRoute, DeviceRouteConfig, KeyboardMode, PairedHostConfig};
    use kvm_input::PointerButton;
    use kvm_network::{ConnectionGenerationGate, ConnectionRole};
    use kvm_protocol::{WirePeerId, PROTOCOL_VERSION_V2};
    use kvm_types::{DisplayId, LogicalPointer, PeerId, Platform};

    use super::*;

    const LOCAL: HostId = HostId::from_bytes([1; 16]);
    const REMOTE: HostId = HostId::from_bytes([2; 16]);
    const LOCAL_DISPLAY: DisplayId = DisplayId::from_bytes([3; 16]);
    const REMOTE_DISPLAY: DisplayId = DisplayId::from_bytes([4; 16]);
    const DEVICE: DeviceId = DeviceId::from_bytes([5; 16]);
    const SECOND_DEVICE: DeviceId = DeviceId::from_bytes([6; 16]);
    const REMOTE_PEER: PeerId = PeerId::from_bytes([7; 16]);

    fn endpoint() -> SessionEndpoint {
        let mut gate =
            ConnectionGenerationGate::new(WirePeerId([8; 16]), WirePeerId([9; 16])).unwrap();
        let pending = gate
            .begin_pending(ConnectionRole::Dialer.direction())
            .unwrap();
        SessionEndpoint::for_test(
            REMOTE_PEER,
            REMOTE,
            pending.generation(),
            PROTOCOL_VERSION_V2,
            [10; 32],
        )
        .unwrap()
    }

    fn config(routes: impl IntoIterator<Item = (DeviceId, ConfiguredDeviceRoute)>) -> Config {
        let mut config = Config::default();
        config.paired_hosts.push(PairedHostConfig {
            host_id: REMOTE,
            peer_id: REMOTE_PEER,
            name: "remote".into(),
            platform: Platform::MacOS,
            identity_fingerprint: "55".repeat(32),
            last_address: None,
        });
        config.device_routes = routes
            .into_iter()
            .map(|(device_id, route)| DeviceRouteConfig { device_id, route })
            .collect();
        config
    }

    fn workspace(active: HostId) -> WorkspaceState {
        let display = if active == LOCAL {
            LOCAL_DISPLAY
        } else {
            REMOTE_DISPLAY
        };
        WorkspaceState::new(LOCAL, active, LogicalPointer::new(display, 10.0, 20.0))
    }

    fn core_with_routes(
        routes: impl IntoIterator<Item = (DeviceId, ConfiguredDeviceRoute)>,
    ) -> DaemonCore {
        let mut core = DaemonCore::new(config(routes), workspace(LOCAL)).unwrap();
        core.install_session_endpoint(endpoint(), 0).unwrap();
        core.mark_workspace_routing_ready(0).unwrap();
        core
    }

    fn core() -> DaemonCore {
        core_with_routes([])
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn diagnostics_event_rate_counts_every_captured_event() {
        // §35 wiring smoke test: process_captured feeds the meter using the
        // event's own capture timestamp, so the snapshot reflects the capture rate.
        let mut core = core();
        for (seq, ts_ns) in [(1u64, 0u64), (2, 100_000_000), (3, 200_000_000)] {
            let _ = core.process_captured(
                CapturedInput::new(
                    InputEvent::new(
                        seq,
                        ts_ns,
                        LOCAL,
                        DEVICE,
                        InputPayload::Key {
                            code: KeyCode::KeyA,
                            state: KeyState::Pressed,
                        },
                    ),
                    EventClassification::Physical,
                ),
                ts_ns,
            );
        }
        let snap = core.event_rate_snapshot(200_000_000);
        assert!(
            snap.total_events >= 3,
            "meter should count captured events: {snap:?}"
        );
        assert!(snap.window_events >= 1, "window should be non-empty: {snap:?}");
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn diagnostics_source_latency_records_capture_to_routing_span() {
        // §36 source-side wiring: process_captured stamps capture (event ts) and
        // routing-decision (now_ns) and pushes their span. now_ns deliberately
        // trails the capture timestamp by 4ms so the span is observable.
        let mut core = core();
        for (seq, ts_ns, now_ns) in [
            (1u64, 0u64, 4_000_000u64),
            (2, 100_000_000, 104_000_000),
        ] {
            let _ = core.process_captured(
                CapturedInput::new(
                    InputEvent::new(
                        seq,
                        ts_ns,
                        LOCAL,
                        DEVICE,
                        InputPayload::Key {
                            code: KeyCode::KeyA,
                            state: KeyState::Pressed,
                        },
                    ),
                    EventClassification::Physical,
                ),
                now_ns,
            );
        }
        let stats = core
            .source_latency_stats()
            .expect("at least one span recorded");
        assert_eq!(stats.count, 2, "both events should produce a span");
        assert_eq!(stats.min_ns, 4_000_000);
        assert_eq!(stats.max_ns, 4_000_000);
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn diagnostics_source_latency_is_none_before_first_event() {
        let core = core();
        assert!(core.source_latency_stats().is_none());
    }

    fn installed_endpoint(core: &DaemonCore) -> SessionEndpoint {
        core.endpoint_availability.get(&REMOTE).unwrap().endpoint
    }

    fn captured(device: DeviceId, payload: InputPayload) -> CapturedInput {
        CapturedInput::new(
            InputEvent::new(1, 1, LOCAL, device, payload),
            EventClassification::Physical,
        )
    }

    fn key(device: DeviceId, code: KeyCode, state: KeyState) -> CapturedInput {
        captured(device, InputPayload::Key { code, state })
    }

    fn prepare_remote(core: &mut DaemonCore, captured: CapturedInput) -> RemoteInputEffect {
        let CaptureDecision::Remote(effect) = core.prepare_captured(captured, 1).unwrap() else {
            panic!("expected a prepared remote effect")
        };
        effect
    }

    fn queue(core: &mut DaemonCore, captured: CapturedInput) -> CaptureOutcome {
        let effect = prepare_remote(core, captured);
        core.confirm_remote_input(effect, 1, 1).unwrap()
    }

    fn assert_local_gate(core: &DaemonCore) {
        let snapshot = core.routing_handle().load();
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.workspace.active_host, LOCAL);
        assert_eq!(core.remote_held.len(), 1);
    }

    #[test]
    fn initial_authority_is_local_not_ready_and_remote_initial_state_is_rejected() {
        let core = DaemonCore::new(config([]), workspace(LOCAL)).unwrap();
        assert!(!core.workspace_routing_ready());
        assert!(!core.is_routing_active());
        assert!(!core.routing_handle().load().workspace_ready);

        assert!(matches!(
            DaemonCore::new(config([]), workspace(REMOTE)),
            Err(DaemonError::InvalidInitialAuthority)
        ));
    }

    #[test]
    fn readiness_requires_health_and_cleanup_barrier() {
        let mut core = DaemonCore::new(config([]), workspace(LOCAL)).unwrap();
        assert_eq!(
            core.mark_workspace_routing_ready(0),
            Err(CoreCaptureError::Unavailable)
        );
        core.install_session_endpoint(endpoint(), 0).unwrap();
        core.mark_workspace_routing_ready(0).unwrap();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));

        core.clear_workspace_routing_ready(2).unwrap();
        assert!(!core.workspace_routing_ready());
        assert!(core.cleanup_pending());
        assert_eq!(
            core.mark_workspace_routing_ready(2),
            Err(CoreCaptureError::Unavailable)
        );
    }

    #[test]
    fn remote_ledger_commits_only_after_fifo_confirmation() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        let effect = prepare_remote(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        assert!(core.remote_held.is_empty());
        assert_eq!(effect.target(), REMOTE);

        let outcome = core.confirm_remote_input(effect, 1, 2).unwrap();
        assert_eq!(outcome.disposition(), CaptureDisposition::SuppressLocal);
        assert_eq!(outcome.state(), CaptureRouteState::RemoteQueued);
        assert_eq!(core.remote_held.len(), 1);
    }

    #[test]
    fn first_press_failure_falls_local_but_repeat_and_release_failures_stay_suppressed() {
        let mut first = core();
        first.update_workspace(workspace(REMOTE), 1).unwrap();
        let effect = prepare_remote(&mut first, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        let outcome = first.fail_remote_input(effect, 2).unwrap();
        assert_eq!(outcome.disposition(), CaptureDisposition::AllowLocal);
        assert!(!first.workspace_routing_ready());

        for state in [KeyState::Pressed, KeyState::Repeated, KeyState::Released] {
            let mut core = core();
            core.update_workspace(workspace(REMOTE), 1).unwrap();
            queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
            let effect = prepare_remote(&mut core, key(DEVICE, KeyCode::KeyA, state));
            let outcome = core.fail_remote_input(effect, 2).unwrap();
            assert_eq!(outcome.disposition(), CaptureDisposition::SuppressLocal);
            assert_eq!(outcome.state(), CaptureRouteState::Gated);
            assert!(core.cleanup_pending());
            assert_eq!(core.workspace().active_host, LOCAL);
        }
    }

    #[test]
    fn local_and_remote_repeat_preserve_latch_until_physical_release() {
        let mut local = core_with_routes([(DEVICE, ConfiguredDeviceRoute::Local)]);
        for (state, expected_count) in [
            (KeyState::Pressed, 1),
            (KeyState::Repeated, 1),
            (KeyState::Released, 0),
        ] {
            let CaptureDecision::Local(_) = local
                .prepare_captured(key(DEVICE, KeyCode::KeyA, state), 1)
                .unwrap()
            else {
                panic!("local lifecycle did not remain local")
            };
            assert_eq!(local.physical_control_count, expected_count);
            assert!(local.remote_held.is_empty());
        }

        let mut remote = core();
        remote.update_workspace(workspace(REMOTE), 1).unwrap();
        for (state, expected_count) in [
            (KeyState::Pressed, 1),
            (KeyState::Repeated, 1),
            (KeyState::Released, 0),
        ] {
            queue(&mut remote, key(DEVICE, KeyCode::KeyA, state));
            assert_eq!(remote.physical_control_count, expected_count);
            assert_eq!(remote.remote_held.len(), expected_count);
        }
    }

    #[test]
    fn cleanup_failure_retains_exact_front_and_unsent_suffix() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        for code in [KeyCode::KeyA, KeyCode::KeyB] {
            queue(&mut core, key(DEVICE, code, KeyState::Pressed));
        }
        core.clear_workspace_routing_ready(2).unwrap();
        assert_eq!(core.cleanup.len(), 2);

        let first = core.take_next_cleanup_release().unwrap();
        let expected = first.release();
        core.retry_cleanup_release(first, 3).unwrap();
        assert_eq!(core.cleanup.len(), 2);
        let retry = core.take_next_cleanup_release().unwrap();
        assert_eq!(retry.release(), expected);
        core.confirm_cleanup_release(retry, 4).unwrap();
        assert_eq!(core.cleanup.len(), 1);
        assert_eq!(core.remote_held.len(), 1);
        let second = core.take_next_cleanup_release().unwrap();
        assert_ne!(second.release().payload, expected.payload);
        core.confirm_cleanup_release(second, 5).unwrap();
        assert!(!core.cleanup_pending());
        assert!(core.remote_held.is_empty());
    }

    #[test]
    fn terminal_transport_invalidation_is_the_only_discard_path() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        core.clear_workspace_routing_ready(2).unwrap();
        let _in_flight = core.take_next_cleanup_release().unwrap();
        let endpoint = installed_endpoint(&core);
        core.confirm_transport_invalidated(endpoint, 3);
        assert!(!core.cleanup_pending());
        assert!(core.remote_held.is_empty());
    }

    #[test]
    fn graceful_endpoint_retirement_preserves_exact_coverage_and_allows_replacement() {
        let mut core = core();
        let first = installed_endpoint(&core);
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        let effect = prepare_remote(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        assert_eq!(effect.endpoint(), first);
        core.confirm_remote_input(effect, 1, 1).unwrap();

        core.set_endpoint_state(first, PeerState::Disconnected, 2)
            .unwrap();
        assert_eq!(
            core.retire_session_endpoint(first, 2),
            Err(CoreCaptureError::CleanupPending)
        );
        let cleanup = core.take_next_cleanup_release().unwrap();
        assert_eq!(cleanup.endpoint(), first);
        assert_eq!(cleanup.covered_input_sequence(), 1);
        core.retry_cleanup_release(cleanup, 3).unwrap();
        let retry = core.take_next_cleanup_release().unwrap();
        assert_eq!(retry.endpoint(), first);
        assert_eq!(retry.covered_input_sequence(), 1);
        core.confirm_cleanup_release(retry, 4).unwrap();
        core.retire_session_endpoint(first, 5).unwrap();

        let second = endpoint();
        assert_ne!(second, first);
        core.install_session_endpoint(second, 6).unwrap();
        core.confirm_transport_invalidated(first, 7);
        let current = core.endpoint_availability.get(&REMOTE).unwrap();
        assert_eq!(current.endpoint, second);
        assert_eq!(current.state, PeerState::Connected);
    }

    #[test]
    fn terminal_invalidation_restores_authority_after_cleanup_id_exhaustion() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        core.next_effect_id = u64::MAX;
        assert_eq!(
            core.begin_pointer_handoff(2),
            Err(CoreCaptureError::IdentifierSpaceExhausted)
        );

        let endpoint = installed_endpoint(&core);
        core.confirm_transport_invalidated(endpoint, 3);
        assert_eq!(core.peers.get(&REMOTE), Some(&PeerState::Disconnected));
        assert!(core.remote_held.is_empty());
        assert!(!core.cleanup_pending());
        let snapshot = core.routing_handle().load();
        assert!(!snapshot.enabled);
        assert!(!snapshot.workspace_ready);
        assert!(!snapshot.handoff_pending);
        assert_eq!(snapshot.workspace.active_host, LOCAL);
    }

    #[test]
    fn local_lifecycle_stays_local_and_selected_pin_survives_handoff_gate() {
        let mut core = core_with_routes([
            (DEVICE, ConfiguredDeviceRoute::Local),
            (
                SECOND_DEVICE,
                ConfiguredDeviceRoute::Host { host_id: REMOTE },
            ),
        ]);
        let CaptureDecision::Local(_) = core
            .prepare_captured(key(DEVICE, KeyCode::KeyA, KeyState::Pressed), 1)
            .unwrap()
        else {
            panic!("local pin routed remotely")
        };
        core.begin_pointer_handoff(2).unwrap();
        for state in [KeyState::Pressed, KeyState::Released] {
            let CaptureDecision::Local(_) = core
                .prepare_captured(key(DEVICE, KeyCode::KeyA, state), 3)
                .unwrap()
            else {
                panic!("local lifecycle was overridden")
            };
        }

        let effect = prepare_remote(
            &mut core,
            key(SECOND_DEVICE, KeyCode::KeyB, KeyState::Pressed),
        );
        assert_eq!(effect.target(), REMOTE);
        core.confirm_remote_input(effect, 1, 4).unwrap();
        assert!(!core.cleanup_pending());
    }

    #[test]
    fn unchanged_exact_remote_pin_survives_config_publication() {
        let routes = [(DEVICE, ConfiguredDeviceRoute::Host { host_id: REMOTE })];
        let mut core = core_with_routes(routes);
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));

        core.update_config(config(routes), 2).unwrap();
        assert!(core.workspace_routing_ready());
        assert!(!core.cleanup_pending());
        let effect = prepare_remote(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        core.confirm_remote_input(effect, 1, 3).unwrap();
        assert_eq!(core.remote_held.len(), 1);
    }

    #[test]
    fn ordinary_config_updates_remain_separate_from_route_transactions() {
        let mut core = core();
        let mut ordinary = core.config().clone();
        ordinary.keyboard.mode = KeyboardMode::Semantic;
        core.update_config(ordinary, 1).unwrap();
        assert_eq!(core.config().keyboard.mode, KeyboardMode::Semantic);
        assert_eq!(core.route_policy_revision(), 0);
        assert!(core.staged_route_policy().is_none());

        let mut mixed = core.config().clone();
        mixed.keyboard.mode = KeyboardMode::Physical;
        mixed.device_routes.push(DeviceRouteConfig {
            device_id: DEVICE,
            route: ConfiguredDeviceRoute::Local,
        });
        assert_eq!(
            core.prepare_route_policy_update(mixed, 0, 2),
            Err(RoutePolicyUpdateError::InvalidCandidate)
        );
        assert_eq!(core.config().keyboard.mode, KeyboardMode::Semantic);
        assert_eq!(
            core.routing.route_for(DEVICE),
            DeviceRoute::FollowActiveHost
        );
        assert!(core.staged_route_policy().is_none());
    }

    #[test]
    fn route_policy_retains_exact_candidate_until_cleanup_and_checked_commit() {
        let routes = [(DEVICE, ConfiguredDeviceRoute::Host { host_id: REMOTE })];
        let mut core = core_with_routes(routes);
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));

        let candidate = config([(DEVICE, ConfiguredDeviceRoute::Local)]);
        assert_eq!(
            core.prepare_route_policy_update(candidate.clone(), 0, 2),
            Ok(RoutePolicyUpdateStatus::CleanupPending)
        );
        assert_eq!(core.route_policy_revision(), 0);
        assert!(core.staged_route_policy().is_none());
        assert_eq!(core.pending_route_policy.as_ref().unwrap().next_revision, 1);

        let conflicting = config([]);
        assert_eq!(
            core.prepare_route_policy_update(conflicting, 0, 3),
            Err(RoutePolicyUpdateError::ConflictingUpdate)
        );
        assert_eq!(
            core.prepare_route_policy_update(candidate.clone(), 1, 3),
            Err(RoutePolicyUpdateError::StaleRevision)
        );
        assert_eq!(
            core.prepare_route_policy_update(candidate, 0, 3),
            Ok(RoutePolicyUpdateStatus::CleanupPending)
        );

        let CaptureDecision::Inert(outcome) = core
            .prepare_captured(key(DEVICE, KeyCode::KeyA, KeyState::Repeated), 3)
            .unwrap()
        else {
            panic!("changed remote lifecycle escaped quarantine")
        };
        assert_eq!(outcome.disposition(), CaptureDisposition::SuppressLocal);
        let CaptureDecision::Local(outcome) = core
            .prepare_captured(key(DEVICE, KeyCode::KeyB, KeyState::Pressed), 3)
            .unwrap()
        else {
            panic!("new changed-device lifecycle escaped the route gate")
        };
        assert_eq!(outcome.state(), CaptureRouteState::Gated);

        let effect = core.take_next_cleanup_release().unwrap();
        core.confirm_cleanup_release(effect, 4).unwrap();
        assert_eq!(
            core.retry_route_policy_update(4),
            Ok(RoutePolicyUpdateStatus::ReadyToPersist)
        );
        let staged = core.staged_route_policy().unwrap();
        assert_eq!(staged.revision(), 1);
        assert_eq!(staged.config().device_route_revision, 1);
        assert_eq!(
            format!("{staged:?}"),
            "StagedRoutePolicy { config: \"[REDACTED]\", revision: \"[REDACTED]\" }"
        );
        assert_eq!(
            core.commit_route_policy_update(2, 5),
            Err(RoutePolicyUpdateError::ConflictingUpdate)
        );
        assert!(core.staged_route_policy().is_some());
        assert_eq!(core.commit_route_policy_update(1, 5), Ok(1));
        assert_eq!(core.route_policy_revision(), 1);
        assert_eq!(core.config().device_route_revision, 1);
        assert_eq!(core.routing.route_for(DEVICE), DeviceRoute::Local);
    }

    #[test]
    fn effective_exact_selected_target_preserves_existing_remote_lifecycle() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));

        let candidate = config([(DEVICE, ConfiguredDeviceRoute::Host { host_id: REMOTE })]);
        assert_eq!(
            core.prepare_route_policy_update(candidate, 0, 2),
            Ok(RoutePolicyUpdateStatus::ReadyToPersist)
        );
        assert!(!core.cleanup_pending());

        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Repeated));
        let CaptureDecision::Local(outcome) = core
            .prepare_captured(key(DEVICE, KeyCode::KeyB, KeyState::Pressed), 3)
            .unwrap()
        else {
            panic!("new lifecycle was not gated while policy was staged")
        };
        assert_eq!(outcome.state(), CaptureRouteState::Gated);

        core.commit_route_policy_update(1, 4).unwrap();
        assert!(core
            .remote_held
            .values()
            .all(|held| held.route == DeviceRoute::Host(REMOTE)));
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Released));
        assert!(core.remote_held.is_empty());
    }

    #[test]
    fn route_cleanup_retry_and_terminal_close_preserve_candidate() {
        let routes = [(DEVICE, ConfiguredDeviceRoute::Host { host_id: REMOTE })];
        let mut core = core_with_routes(routes);
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        let candidate = config([(DEVICE, ConfiguredDeviceRoute::Local)]);
        core.prepare_route_policy_update(candidate, 0, 2).unwrap();

        let first = core.take_next_cleanup_release().unwrap();
        let release = first.release();
        core.retry_cleanup_release(first, 3).unwrap();
        assert_eq!(
            core.retry_route_policy_update(3),
            Ok(RoutePolicyUpdateStatus::CleanupPending)
        );
        let retry = core.take_next_cleanup_release().unwrap();
        assert_eq!(retry.release(), release);
        core.retry_cleanup_release(retry, 4).unwrap();

        let endpoint = installed_endpoint(&core);
        core.confirm_transport_invalidated(endpoint, 5);
        assert_eq!(
            core.retry_route_policy_update(5),
            Ok(RoutePolicyUpdateStatus::ReadyToPersist)
        );
        assert_eq!(core.commit_route_policy_update(1, 6), Ok(1));
        assert!(core.remote_held.is_empty());
        assert!(!core.cleanup_pending());
    }

    #[test]
    fn route_cleanup_gate_is_scoped_to_affected_devices_until_fifo_failure() {
        let routes = [
            (DEVICE, ConfiguredDeviceRoute::Host { host_id: REMOTE }),
            (
                SECOND_DEVICE,
                ConfiguredDeviceRoute::Host { host_id: REMOTE },
            ),
        ];
        let mut core = core_with_routes(routes);
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        core.prepare_route_policy_update(
            config([
                (DEVICE, ConfiguredDeviceRoute::Local),
                (
                    SECOND_DEVICE,
                    ConfiguredDeviceRoute::Host { host_id: REMOTE },
                ),
            ]),
            0,
            2,
        )
        .unwrap();
        assert!(core.cleanup_pending());
        assert!(core.is_routing_active());

        queue(
            &mut core,
            key(SECOND_DEVICE, KeyCode::KeyB, KeyState::Pressed),
        );
        assert_eq!(core.remote_held.len(), 2);

        let cleanup = core.take_next_cleanup_release().unwrap();
        core.retry_cleanup_release(cleanup, 3).unwrap();
        assert!(!core.is_routing_active());
        let CaptureDecision::Local(outcome) = core
            .prepare_captured(key(SECOND_DEVICE, KeyCode::KeyC, KeyState::Pressed), 4)
            .unwrap()
        else {
            panic!("transport retry failure did not gate unrelated input")
        };
        assert_eq!(outcome.state(), CaptureRouteState::Gated);
    }

    #[test]
    fn route_prepare_failure_and_revision_exhaustion_are_transactional() {
        let routes = [(DEVICE, ConfiguredDeviceRoute::Host { host_id: REMOTE })];
        let mut core = core_with_routes(routes);
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        core.next_effect_id = u64::MAX;

        assert_eq!(
            core.prepare_route_policy_update(
                config([(DEVICE, ConfiguredDeviceRoute::Local)]),
                0,
                2,
            ),
            Err(RoutePolicyUpdateError::CleanupUnavailable)
        );
        assert!(core.staged_route_policy().is_none());
        assert!(!core.cleanup_pending());
        assert_eq!(core.routing.route_for(DEVICE), DeviceRoute::Host(REMOTE));
        assert!(matches!(
            core.physical_controls
                .get(&DEVICE)
                .and_then(|controls| controls.get(&PhysicalControl::Key(KeyCode::KeyA))),
            Some(LatchedDestination::Remote { .. })
        ));

        core.next_effect_id = 1;
        core.route_policy_revision = u64::MAX;
        core.config.device_route_revision = u64::MAX;
        assert_eq!(
            core.prepare_route_policy_update(config([]), u64::MAX, 3),
            Err(RoutePolicyUpdateError::RevisionExhausted)
        );
        assert!(core.staged_route_policy().is_none());
        assert_eq!(core.route_policy_revision(), u64::MAX);
    }

    #[test]
    fn abort_keeps_queued_releases_and_committed_policy() {
        let routes = [(DEVICE, ConfiguredDeviceRoute::Host { host_id: REMOTE })];
        let mut core = core_with_routes(routes);
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        core.prepare_route_policy_update(config([(DEVICE, ConfiguredDeviceRoute::Local)]), 0, 2)
            .unwrap();

        core.abort_route_policy_update(1, 3).unwrap();
        assert!(core.pending_route_policy.is_none());
        assert!(core.cleanup_pending());
        assert_eq!(core.route_policy_revision(), 0);
        assert_eq!(core.routing.route_for(DEVICE), DeviceRoute::Host(REMOTE));
    }

    #[test]
    fn unplug_gate_is_per_device_bounded_and_does_not_delete_policy() {
        let route_entries = [(DEVICE, ConfiguredDeviceRoute::Host { host_id: REMOTE })];
        let mut routed = core_with_routes(route_entries);
        queue(&mut routed, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));

        routed.gate_local_device(DEVICE, 2).unwrap();
        assert_eq!(routed.routing.route_for(DEVICE), DeviceRoute::Host(REMOTE));
        let CaptureDecision::Inert(_) = routed
            .prepare_captured(key(DEVICE, KeyCode::KeyA, KeyState::Repeated), 3)
            .unwrap()
        else {
            panic!("unplugged held lifecycle escaped quarantine")
        };
        let CaptureDecision::Local(outcome) = routed
            .prepare_captured(key(DEVICE, KeyCode::KeyB, KeyState::Pressed), 3)
            .unwrap()
        else {
            panic!("unplugged device was not gated")
        };
        assert_eq!(outcome.state(), CaptureRouteState::Gated);

        while let Some(effect) = routed.take_next_cleanup_release() {
            routed.confirm_cleanup_release(effect, 4).unwrap();
        }
        routed.restore_local_device(DEVICE, 5).unwrap();
        assert!(!routed.physical_controls.contains_key(&DEVICE));

        routed.update_workspace(workspace(REMOTE), 6).unwrap();
        let effect = prepare_remote(
            &mut routed,
            key(SECOND_DEVICE, KeyCode::KeyC, KeyState::Pressed),
        );
        assert_eq!(effect.target(), REMOTE);
        routed.fail_remote_input(effect, 7).unwrap();

        let mut bounded = core();
        for value in 1..=MAX_GATED_LOCAL_DEVICES {
            let mut bytes = [0; 16];
            bytes[14..].copy_from_slice(&u16::try_from(value).unwrap().to_be_bytes());
            bounded
                .gate_local_device(DeviceId::from_bytes(bytes), 1)
                .unwrap();
        }
        assert_eq!(
            bounded.gate_local_device(DeviceId::from_bytes([0xFF; 16]), 1),
            Err(CoreCaptureError::CapacityExceeded)
        );
    }

    #[test]
    fn follow_active_input_is_inert_during_handoff_and_quarantined_to_release() {
        let mut core = core();
        core.begin_pointer_handoff(1).unwrap();
        for state in [KeyState::Pressed, KeyState::Pressed, KeyState::Released] {
            let CaptureDecision::Inert(outcome) = core
                .prepare_captured(key(DEVICE, KeyCode::KeyA, state), 2)
                .unwrap()
            else {
                panic!("handoff input was not inert")
            };
            assert_eq!(outcome.disposition(), CaptureDisposition::SuppressLocal);
        }
        assert!(core.physical_controls.is_empty());
        assert!(core.remote_held.is_empty());
    }

    #[test]
    fn handoff_cleanup_identifier_exhaustion_publishes_follow_gate() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        core.next_effect_id = u64::MAX;

        assert_eq!(
            core.begin_pointer_handoff(2),
            Err(CoreCaptureError::IdentifierSpaceExhausted)
        );
        assert!(core.routing_handle().load().handoff_pending);
        let CaptureDecision::Fault { outcome, error } = core
            .prepare_captured(key(DEVICE, KeyCode::KeyA, KeyState::Repeated), 3)
            .unwrap()
        else {
            panic!("follow repeat escaped a failed handoff barrier")
        };
        assert_eq!(error, CoreCaptureError::IdentifierSpaceExhausted);
        assert_eq!(outcome.disposition(), CaptureDisposition::SuppressLocal);
    }

    #[test]
    fn destination_barrier_abort_preserves_preproposal_authority() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        core.begin_pointer_handoff(2).unwrap();
        assert!(core.routing_handle().load().handoff_pending);

        core.abort_destination_handoff_barrier(3);
        let snapshot = core.routing_handle().load();
        assert!(!snapshot.handoff_pending);
        assert_eq!(snapshot.workspace.active_host, REMOTE);
        assert!(snapshot.enabled);
    }

    #[test]
    fn lifecycle_cleanup_identifier_exhaustion_still_publishes_local_gate() {
        fn held_core() -> DaemonCore {
            let mut core = core();
            core.update_workspace(workspace(REMOTE), 1).unwrap();
            queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
            core.next_effect_id = u64::MAX;
            core
        }

        let mut peer = held_core();
        let endpoint = installed_endpoint(&peer);
        assert_eq!(
            peer.set_endpoint_state(endpoint, PeerState::Disconnected, 2),
            Err(CoreCaptureError::IdentifierSpaceExhausted)
        );
        assert_eq!(peer.peers.get(&REMOTE), Some(&PeerState::Disconnected));
        assert_local_gate(&peer);

        let mut disabled = held_core();
        assert_eq!(
            disabled.disable(2),
            Err(CoreCaptureError::IdentifierSpaceExhausted)
        );
        assert_local_gate(&disabled);

        let mut cleared = held_core();
        assert_eq!(
            cleared.clear_workspace_routing_ready(2),
            Err(CoreCaptureError::IdentifierSpaceExhausted)
        );
        assert_local_gate(&cleared);

        let mut shutdown = held_core();
        assert_eq!(
            shutdown.shutdown(2),
            Err(CoreCaptureError::IdentifierSpaceExhausted)
        );
        assert_local_gate(&shutdown);
    }

    #[test]
    fn aggregate_failsafe_tracks_same_modifier_on_independent_devices() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        for (device, code) in [
            (DEVICE, KeyCode::ControlLeft),
            (SECOND_DEVICE, KeyCode::ControlRight),
            (DEVICE, KeyCode::AltLeft),
            (DEVICE, KeyCode::ShiftLeft),
        ] {
            queue(&mut core, key(device, code, KeyState::Pressed));
        }
        let release_one = queue(
            &mut core,
            key(DEVICE, KeyCode::ControlLeft, KeyState::Released),
        );
        assert!(!release_one.failsafe_activated());
        assert!(core.shortcut_key_pressed(ShortcutKey::Control));

        let CaptureDecision::Local(outcome) = core
            .prepare_captured(key(SECOND_DEVICE, KeyCode::Backspace, KeyState::Pressed), 3)
            .unwrap()
        else {
            panic!("failsafe trigger was not local")
        };
        assert!(outcome.failsafe_activated());
        assert_eq!(outcome.disposition(), CaptureDisposition::AllowLocal);
        assert_eq!(core.workspace().active_host, LOCAL);
        assert!(core.cleanup_pending());

        while let Some(effect) = core.take_next_cleanup_release() {
            core.confirm_cleanup_release(effect, 4).unwrap();
        }
        for (device, code) in [
            (SECOND_DEVICE, KeyCode::ControlRight),
            (DEVICE, KeyCode::AltLeft),
            (DEVICE, KeyCode::ShiftLeft),
            (SECOND_DEVICE, KeyCode::Backspace),
        ] {
            assert!(matches!(
                core.prepare_captured(key(device, code, KeyState::Released), 5)
                    .unwrap(),
                CaptureDecision::Local(_)
            ));
        }
        assert!(!core.routing_handle().load().enabled);
        assert!(core.tick(core.suspended_until_ns));
        let recovered = core.routing_handle().load();
        assert!(recovered.enabled);
        assert_eq!(recovered.workspace.active_host, LOCAL);
    }

    #[test]
    fn invalid_and_stateless_records_allocate_no_ledgers() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        for captured in [
            CapturedInput::new(
                InputEvent::new(
                    1,
                    1,
                    LOCAL,
                    DeviceId::from_bytes([0; 16]),
                    InputPayload::Key {
                        code: KeyCode::KeyA,
                        state: KeyState::Pressed,
                    },
                ),
                EventClassification::Physical,
            ),
            CapturedInput::new(
                InputEvent::new(
                    1,
                    1,
                    REMOTE,
                    DEVICE,
                    InputPayload::Key {
                        code: KeyCode::KeyA,
                        state: KeyState::Pressed,
                    },
                ),
                EventClassification::Physical,
            ),
            CapturedInput::new(
                InputEvent::new(
                    1,
                    1,
                    LOCAL,
                    DEVICE,
                    InputPayload::PointerMove {
                        dx: f64::NAN,
                        dy: 0.0,
                    },
                ),
                EventClassification::Physical,
            ),
            CapturedInput::new(
                InputEvent::new(
                    1,
                    1,
                    LOCAL,
                    DEVICE,
                    InputPayload::Key {
                        code: KeyCode::KeyA,
                        state: KeyState::Pressed,
                    },
                ),
                EventClassification::InjectedByKvm,
            ),
        ] {
            assert!(matches!(
                core.prepare_captured(captured, 2).unwrap(),
                CaptureDecision::Local(_)
            ));
        }
        for state in [KeyState::Repeated, KeyState::Released] {
            assert!(matches!(
                core.prepare_captured(key(DEVICE, KeyCode::KeyA, state), 3)
                    .unwrap(),
                CaptureDecision::Local(_)
            ));
        }
        for payload in [
            InputPayload::PointerMove { dx: 1.0, dy: 2.0 },
            InputPayload::Scroll {
                horizontal: 1.0,
                vertical: -1.0,
            },
        ] {
            let effect = prepare_remote(&mut core, captured(DEVICE, payload));
            core.confirm_remote_input(effect, 1, 4).unwrap();
        }
        assert!(core.physical_controls.is_empty());
        assert!(core.remote_held.is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn physical_device_per_device_and_total_bounds_fail_transactionally() {
        let mut devices = core();
        for index in 1..=MAX_PHYSICAL_HELD_DEVICES {
            let mut id = [0_u8; 16];
            id[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
            assert!(matches!(
                devices
                    .prepare_captured(
                        key(DeviceId::from_bytes(id), KeyCode::KeyA, KeyState::Pressed,),
                        1,
                    )
                    .unwrap(),
                CaptureDecision::Local(_)
            ));
        }
        let before = devices.physical_control_count;
        assert!(matches!(
            devices.prepare_captured(
                key(
                    DeviceId::from_bytes([0x7f; 16]),
                    KeyCode::KeyA,
                    KeyState::Pressed,
                ),
                2,
            ),
            Err(CoreCaptureError::CapacityExceeded)
        ));
        assert_eq!(devices.physical_control_count, before);

        let mut per_device = core();
        for usage in 0..MAX_PHYSICAL_HELD_PER_DEVICE {
            let prepared = per_device.prepare_captured(
                key(
                    DEVICE,
                    KeyCode::Unidentified {
                        usage_page: 0xff00,
                        usage_id: u16::try_from(usage).unwrap(),
                    },
                    KeyState::Pressed,
                ),
                1,
            );
            assert!(prepared.is_ok());
        }
        let full_count = per_device.physical_control_count;
        for state in [KeyState::Pressed, KeyState::Repeated] {
            assert!(matches!(
                per_device
                    .prepare_captured(
                        key(
                            DEVICE,
                            KeyCode::Unidentified {
                                usage_page: 0xff00,
                                usage_id: 0,
                            },
                            state,
                        ),
                        2,
                    )
                    .unwrap(),
                CaptureDecision::Local(_)
            ));
            assert_eq!(per_device.physical_control_count, full_count);
        }
        assert!(matches!(
            per_device.prepare_captured(
                key(
                    DEVICE,
                    KeyCode::Unidentified {
                        usage_page: 0xff01,
                        usage_id: 0,
                    },
                    KeyState::Pressed,
                ),
                2,
            ),
            Err(CoreCaptureError::CapacityExceeded)
        ));

        let mut total = core();
        total.update_workspace(workspace(REMOTE), 1).unwrap();
        for device_index in 0..4_u8 {
            for usage in 0..MAX_PHYSICAL_HELD_PER_DEVICE {
                let mut id = [0_u8; 16];
                id[0] = device_index + 1;
                let effect = prepare_remote(
                    &mut total,
                    key(
                        DeviceId::from_bytes(id),
                        KeyCode::Unidentified {
                            usage_page: 0xff00,
                            usage_id: u16::try_from(usage).unwrap(),
                        },
                        KeyState::Pressed,
                    ),
                );
                total.confirm_remote_input(effect, 1, 1).unwrap();
            }
        }
        assert_eq!(total.physical_control_count, MAX_PHYSICAL_HELD_TOTAL);
        assert_eq!(total.remote_held.len(), MAX_REMOTE_HELD_TOTAL);
        assert!(matches!(
            total.prepare_captured(
                key(
                    DeviceId::from_bytes([9; 16]),
                    KeyCode::KeyA,
                    KeyState::Pressed,
                ),
                2,
            ),
            Err(CoreCaptureError::CapacityExceeded)
        ));
        assert_eq!(total.remote_held.len(), MAX_REMOTE_HELD_TOTAL);
        assert_eq!(total.cleanup.len(), MAX_PENDING_REMOTE_CLEANUP);
    }

    #[test]
    fn effect_identifier_exhaustion_gates_and_does_not_orphan_pending_state() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        core.next_effect_id = u64::MAX;
        let CaptureDecision::Fault { outcome, error } = core
            .prepare_captured(key(DEVICE, KeyCode::KeyA, KeyState::Pressed), 2)
            .unwrap()
        else {
            panic!("new press did not fall back locally")
        };
        assert_eq!(error, CoreCaptureError::IdentifierSpaceExhausted);
        assert_eq!(outcome.state(), CaptureRouteState::Gated);
        assert!(core.pending_remote.is_none());
        assert!(!core.workspace_routing_ready());
        assert_eq!(core.workspace().active_host, LOCAL);
    }

    #[test]
    fn effect_identifier_exhaustion_suppresses_existing_remote_lifecycle() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        queue(&mut core, key(DEVICE, KeyCode::KeyA, KeyState::Pressed));
        core.next_effect_id = u64::MAX;

        let CaptureDecision::Fault { outcome, error } = core
            .prepare_captured(key(DEVICE, KeyCode::KeyA, KeyState::Pressed), 2)
            .unwrap()
        else {
            panic!("remote repeat was not suppressed")
        };
        assert_eq!(error, CoreCaptureError::IdentifierSpaceExhausted);
        assert_eq!(outcome.disposition(), CaptureDisposition::SuppressLocal);
        assert_eq!(outcome.state(), CaptureRouteState::Gated);
        assert!(core.pending_remote.is_none());
        assert!(!core.workspace_routing_ready());
        assert_eq!(core.remote_held.len(), 1);
    }

    #[test]
    fn failsafe_activation_outcome_survives_cleanup_identifier_exhaustion() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        for code in [KeyCode::ControlLeft, KeyCode::AltLeft, KeyCode::ShiftLeft] {
            queue(&mut core, key(DEVICE, code, KeyState::Pressed));
        }
        core.next_effect_id = u64::MAX;

        let CaptureDecision::Fault { outcome, error } = core
            .prepare_captured(key(DEVICE, KeyCode::Backspace, KeyState::Pressed), 2)
            .unwrap()
        else {
            panic!("failsafe activation was not local")
        };
        assert_eq!(error, CoreCaptureError::IdentifierSpaceExhausted);
        assert!(outcome.failsafe_activated());
        assert_eq!(outcome.disposition(), CaptureDisposition::AllowLocal);
        assert_eq!(outcome.state(), CaptureRouteState::Gated);
        assert!(!core.workspace_routing_ready());
        assert_eq!(core.workspace().active_host, LOCAL);
        let snapshot = core.routing_handle().load();
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.workspace.active_host, LOCAL);
        assert_eq!(core.remote_held.len(), 3);
        assert!(!core.cleanup_pending());
    }

    #[test]
    fn diagnostics_redact_effects_controls_targets_and_payloads() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        let effect = prepare_remote(
            &mut core,
            captured(
                DEVICE,
                InputPayload::PointerMove {
                    dx: 987_654.125,
                    dy: -876_543.25,
                },
            ),
        );
        let decision = CaptureDecision::Remote(effect);
        let rendered = format!("{core:?} {decision:?}");
        for marker in [
            "987654.125",
            "-876543.25",
            &REMOTE.to_string(),
            &DEVICE.to_string(),
            "KeyA",
        ] {
            assert!(!rendered.contains(marker), "leaked marker: {marker}");
        }
        assert!(rendered.contains("remote_held_count"));
        assert!(rendered.contains("Remote"));
    }

    #[test]
    fn pointer_button_lifecycle_is_latched_and_cleanup_is_bounded() {
        let mut core = core();
        core.update_workspace(workspace(REMOTE), 1).unwrap();
        queue(
            &mut core,
            captured(
                DEVICE,
                InputPayload::PointerButton {
                    button: PointerButton::Left,
                    state: ButtonState::Pressed,
                },
            ),
        );
        core.clear_workspace_routing_ready(2).unwrap();
        assert_eq!(core.cleanup.len(), 1);
        assert!(core.cleanup.len() <= MAX_PENDING_REMOTE_CLEANUP);
    }
}
