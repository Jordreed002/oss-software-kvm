//! Generation-aware composition around one peer session coordinator.
//!
//! The supervisor contains no event queue. It owns exactly one bounded
//! connection-generation gate and delegates only opaque network-minted events
//! from its currently active generation.

use std::error::Error;
use std::fmt;

use kvm_config::Config;
use kvm_network::{
    ActiveConnection, AdmittedPeer, AppliedGenerationEvent, ConnectionDirection,
    ConnectionGeneration, ConnectionGenerationError, ConnectionGenerationGate, ConnectionRole,
    GenerationBoundEventClassification, GenerationBoundPeerEvent, PeerEvent, PeerSender,
    PendingConnection, TransportPeerIdentity,
};
use kvm_protocol::HelloV1;
use kvm_topology::{WorkspaceLink, WorkspacePlacement};
use kvm_types::{DeviceId, Edge, HostId};

use crate::core::{CaptureOutcome, RoutePolicyUpdateError, RoutePolicyUpdateStatus};
use crate::session::RoutePolicyCoordinatorError;
use crate::session::SessionRoutingContext;
use crate::session_endpoint::SessionEndpoint;
use crate::{
    CapturedInput, CoordinatorError, ManagedSessionOutbound, OutboundPeer, OutputInjectionBackend,
    PeerEventOutcome, PeerSessionCoordinator, RoutingSnapshotHandle, WorkspaceControlError,
    WorkspaceControlPlane,
};

pub(crate) struct SupervisorCaptureFailure {
    outcome: Option<CaptureOutcome>,
    error: PeerSessionSupervisorError,
}

impl SupervisorCaptureFailure {
    #[must_use]
    pub(crate) const fn outcome(&self) -> Option<CaptureOutcome> {
        self.outcome
    }

    #[must_use]
    pub(crate) fn into_error(self) -> PeerSessionSupervisorError {
        self.error
    }
}

impl fmt::Debug for SupervisorCaptureFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisorCaptureFailure")
            .field("has_safe_outcome", &self.outcome.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SupervisorLifecycle {
    Running,
    Revoked,
    ShuttingDown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceReconciliationPhase {
    GracefulSettled,
    TransportLost,
}

/// Exact, generation-bound projection of the current network-minted admission.
///
/// This capability is deliberately crate-private and has no visible
/// constructor. Sibling daemon composition may borrow this value to bind work
/// to the current admitted transport, but cannot retain it across a mutable
/// supervisor lifecycle transition.
#[derive(PartialEq)]
pub(crate) struct CurrentAdmittedSession {
    endpoint: SessionEndpoint,
    transport_identity: TransportPeerIdentity,
    local_hello: HelloV1,
    remote_hello: HelloV1,
}

impl Eq for CurrentAdmittedSession {}

impl CurrentAdmittedSession {
    fn from_admitted(generation: ConnectionGeneration, peer: &AdmittedPeer) -> Option<Self> {
        Some(Self {
            endpoint: SessionEndpoint::from_admitted(generation, peer)?,
            transport_identity: peer.transport_identity().clone(),
            local_hello: peer.local_hello().clone(),
            remote_hello: peer.hello().clone(),
        })
    }

    pub(crate) fn matches_admitted(
        &self,
        generation: ConnectionGeneration,
        peer: &AdmittedPeer,
    ) -> bool {
        SessionEndpoint::from_admitted(generation, peer)
            .is_some_and(|endpoint| endpoint == self.endpoint)
            && self.transport_identity == *peer.transport_identity()
            && self.local_hello == *peer.local_hello()
            && self.remote_hello == *peer.hello()
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> SessionEndpoint {
        self.endpoint
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> ConnectionGeneration {
        self.endpoint().generation()
    }

    #[must_use]
    pub(crate) const fn local_host_id(&self) -> HostId {
        HostId::from_bytes(self.local_hello.host_id.0)
    }

    #[must_use]
    pub(crate) const fn remote_host_id(&self) -> HostId {
        self.endpoint().host_id()
    }

    #[must_use]
    pub(crate) const fn transport_identity(&self) -> &TransportPeerIdentity {
        &self.transport_identity
    }

    #[must_use]
    pub(crate) const fn local_hello(&self) -> &HelloV1 {
        &self.local_hello
    }

    #[must_use]
    pub(crate) const fn remote_hello(&self) -> &HelloV1 {
        &self.remote_hello
    }
}

impl fmt::Debug for CurrentAdmittedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CurrentAdmittedSession([REDACTED])")
    }
}

/// Result of applying one generation-tagged operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorEventOutcome {
    /// The event was delegated to the current coordinator.
    Applied(PeerEventOutcome),
    /// The event completed and retired the active generation.
    Retired(PeerEventOutcome),
    /// The generation was not current, so its event was dropped untouched.
    StaleIgnored,
    /// A pre-admission state notification was intentionally not delegated.
    PendingIgnored,
    /// A pre-admission terminal event cancelled the exact pending token.
    PendingCancelled,
}

/// Fail-closed supervisor failure with payload-redacted diagnostics.
pub enum PeerSessionSupervisorError {
    /// The generation gate rejected a role or state transition.
    Generation(ConnectionGenerationError),
    /// The coordinator rejected the active session or failed reconciliation.
    Coordinator(CoordinatorError),
    /// New work is prohibited after revocation or shutdown begins.
    Unavailable,
    /// An operation required a current active generation.
    NoActiveGeneration,
    /// A network-minted wrapper had an internally inconsistent shape.
    InvalidBoundEvent,
    /// Mandatory workspace composition rejected the event.
    Workspace(WorkspaceControlError),
}

impl fmt::Debug for PeerSessionSupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Generation(_) => "Generation",
            Self::Coordinator(_) => "Coordinator",
            Self::Unavailable => "Unavailable",
            Self::NoActiveGeneration => "NoActiveGeneration",
            Self::InvalidBoundEvent => "InvalidBoundEvent",
            Self::Workspace(_) => "Workspace",
        };
        formatter
            .debug_struct("PeerSessionSupervisorError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for PeerSessionSupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generation(_) => formatter.write_str("connection generation was rejected"),
            Self::Coordinator(_) => formatter.write_str("supervised peer session failed"),
            Self::Unavailable => formatter.write_str("peer session supervisor is unavailable"),
            Self::NoActiveGeneration => {
                formatter.write_str("peer session supervisor has no active generation")
            }
            Self::InvalidBoundEvent => {
                formatter.write_str("generation-bound peer event is invalid")
            }
            Self::Workspace(_) => formatter.write_str("workspace session handling failed"),
        }
    }
}

impl Error for PeerSessionSupervisorError {}

impl From<ConnectionGenerationError> for PeerSessionSupervisorError {
    fn from(error: ConnectionGenerationError) -> Self {
        Self::Generation(error)
    }
}

impl From<CoordinatorError> for PeerSessionSupervisorError {
    fn from(error: CoordinatorError) -> Self {
        Self::Coordinator(error)
    }
}

struct SupervisorEngine<C> {
    coordinator: C,
    gate: ConnectionGenerationGate,
    active: Option<ActiveConnection>,
    lifecycle: SupervisorLifecycle,
}

impl<C> SupervisorEngine<C> {
    const fn new(gate: ConnectionGenerationGate, coordinator: C) -> Self {
        Self {
            coordinator,
            gate,
            active: None,
            lifecycle: SupervisorLifecycle::Running,
        }
    }

    fn begin_pending(
        &mut self,
        direction: ConnectionDirection,
    ) -> Result<PendingConnection, PeerSessionSupervisorError> {
        if self.lifecycle != SupervisorLifecycle::Running {
            return Err(PeerSessionSupervisorError::Unavailable);
        }
        self.gate.begin_pending(direction).map_err(Into::into)
    }

    fn cancel_pending(
        &mut self,
        pending: PendingConnection,
    ) -> Result<(), PeerSessionSupervisorError> {
        self.gate.cancel_pending(pending).map_err(Into::into)
    }

    fn accept_activation_with(
        &mut self,
        active: ActiveConnection,
        operation: impl FnOnce(&mut C) -> Result<PeerEventOutcome, CoordinatorError>,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if self.lifecycle != SupervisorLifecycle::Running {
            self.gate.finish_active(active)?;
            return Err(PeerSessionSupervisorError::Unavailable);
        }

        match operation(&mut self.coordinator) {
            Ok(outcome) => {
                self.active = Some(active);
                Ok(SupervisorEventOutcome::Applied(outcome))
            }
            Err(error) => {
                // Admission failed before a generation became externally
                // active. The coordinator reconciles admission failures.
                self.gate.finish_active(active)?;
                Err(PeerSessionSupervisorError::Coordinator(error))
            }
        }
    }

    fn handle_with(
        &mut self,
        generation: ConnectionGeneration,
        retires_generation: bool,
        operation: impl FnOnce(&mut C) -> Result<PeerEventOutcome, CoordinatorError>,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if !self.gate.is_active(generation) {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        if self.lifecycle != SupervisorLifecycle::Running {
            return Err(PeerSessionSupervisorError::Unavailable);
        }

        let outcome =
            operation(&mut self.coordinator).map_err(PeerSessionSupervisorError::Coordinator)?;
        if retires_generation {
            self.finish_active()?;
            Ok(SupervisorEventOutcome::Retired(outcome))
        } else {
            Ok(SupervisorEventOutcome::Applied(outcome))
        }
    }

    fn reconcile_with(
        &mut self,
        expected_generation: Option<ConnectionGeneration>,
        operation: impl FnOnce(&mut C) -> Result<(), CoordinatorError>,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if let Some(expected) = expected_generation {
            if !self.gate.is_active(expected) {
                return Ok(SupervisorEventOutcome::StaleIgnored);
            }
        }
        if self.active.is_none() {
            return Err(PeerSessionSupervisorError::NoActiveGeneration);
        }

        operation(&mut self.coordinator).map_err(PeerSessionSupervisorError::Coordinator)?;
        self.finish_active()?;
        Ok(SupervisorEventOutcome::Retired(PeerEventOutcome::Applied))
    }

    fn finish_active(&mut self) -> Result<(), PeerSessionSupervisorError> {
        let active = self
            .active
            .take()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        self.gate.finish_active(active).map_err(Into::into)
    }

    const fn active_generation(&self) -> Option<ConnectionGeneration> {
        self.gate.active_generation()
    }
}

/// Owns one generation gate and one daemon coordinator for a paired peer.
///
/// The caller passes the pending token minted by [`Self::begin_pending`] into a
/// `kvm_network::GenerationBoundPeerSession` and forwards its opaque events.
/// Stale events are consumed and dropped before they can mutate daemon state.
/// Failed cleanup retains the active gate token, preventing replacement until
/// [`Self::retry_reconciliation`] succeeds.
pub struct PeerSessionSupervisor<I, O> {
    engine: SupervisorEngine<PeerSessionCoordinator<I, O>>,
    current_session: Option<CurrentAdmittedSession>,
    workspace_reconciliation: Option<WorkspaceReconciliationPhase>,
}

impl<I, O> fmt::Debug for PeerSessionSupervisor<I, O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerSessionSupervisor")
            .field("role", &self.engine.gate.role())
            .field(
                "has_active_generation",
                &self.engine.active_generation().is_some(),
            )
            .field("admitted", &self.current_session.is_some())
            .field("workspace_reconciliation", &self.workspace_reconciliation)
            .field("lifecycle", &self.engine.lifecycle)
            .finish_non_exhaustive()
    }
}

impl<I, O> PeerSessionSupervisor<I, O>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    /// Creates an idle supervisor from a role-configured generation gate and
    /// the exact paired-peer coordinator it protects.
    #[must_use]
    pub const fn new(
        gate: ConnectionGenerationGate,
        coordinator: PeerSessionCoordinator<I, O>,
    ) -> Self {
        Self {
            engine: SupervisorEngine::new(gate, coordinator),
            current_session: None,
            workspace_reconciliation: None,
        }
    }

    /// Canonical role derived when the supplied gate was constructed.
    #[must_use]
    pub const fn role(&self) -> ConnectionRole {
        self.engine.gate.role()
    }

    /// Current generation accepted by daemon coordination, if any.
    #[must_use]
    pub const fn active_generation(&self) -> Option<ConnectionGeneration> {
        self.engine.active_generation()
    }

    pub(crate) fn validates_selected_workspace_attachment(
        &self,
        workspace: &WorkspaceControlPlane,
        selected_host: HostId,
    ) -> bool {
        let core = self.engine.coordinator.core();
        let initial = workspace.initial_state();
        core.workspace() == initial
            && initial.active_host == initial.local_host
            && self.engine.coordinator.expected_host_id() == selected_host
            && core
                .config()
                .device_routes
                .iter()
                .all(|route| match route.route {
                    kvm_config::ConfiguredDeviceRoute::FollowActiveHost
                    | kvm_config::ConfiguredDeviceRoute::Local => true,
                    kvm_config::ConfiguredDeviceRoute::Host { host_id } => {
                        host_id == initial.local_host || host_id == selected_host
                    }
                })
    }

    /// Reserves the sole pending slot after validating canonical direction.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical, duplicate, exhausted, revoked, or shutting-down
    /// attempts.
    pub fn begin_pending(
        &mut self,
        direction: ConnectionDirection,
    ) -> Result<PendingConnection, PeerSessionSupervisorError> {
        self.engine.begin_pending(direction)
    }

    /// Releases the exact pending token after bounded task shutdown.
    ///
    /// # Errors
    ///
    /// Rejects a stale token.
    pub fn cancel_pending(
        &mut self,
        pending: PendingConnection,
    ) -> Result<(), PeerSessionSupervisorError> {
        self.engine.cancel_pending(pending)
    }

    /// Applies and delegates one opaque network-minted event.
    ///
    /// The wrapper owns the affine pending capability on actual admission or
    /// pre-admission cancellation. Consequently no safe caller can attach an
    /// old cloned admitted peer to a fresh generation. Pre-admission state is
    /// ignored; post-admission events are delegated only while exactly current.
    ///
    /// # Errors
    ///
    /// Returns a redacted gate, lifecycle, wrapper, or coordinator error.
    pub fn handle_bound_event(
        &mut self,
        bound: GenerationBoundPeerEvent,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if bound.classification() == GenerationBoundEventClassification::Active
            && !self.engine.gate.is_active(bound.generation())
        {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        let applied = bound.apply(&mut self.engine.gate)?;
        self.handle_applied_event(applied, now_ns)
    }

    pub(crate) fn handle_bound_event_with_workspace(
        &mut self,
        bound: GenerationBoundPeerEvent,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if bound.classification() == GenerationBoundEventClassification::Active
            && !self.engine.gate.is_active(bound.generation())
        {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        let applied = bound.apply(&mut self.engine.gate)?;
        self.handle_applied_event_with_workspace(applied, workspace, now_ns)
    }

    fn handle_applied_event_with_workspace(
        &mut self,
        applied: AppliedGenerationEvent,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        let generation = applied.generation();
        match applied.classification() {
            GenerationBoundEventClassification::PendingIgnored => {
                Ok(SupervisorEventOutcome::PendingIgnored)
            }
            GenerationBoundEventClassification::Cancelled => {
                Ok(SupervisorEventOutcome::PendingCancelled)
            }
            GenerationBoundEventClassification::Activated => {
                let (active, event) = applied
                    .into_activation()
                    .ok_or(PeerSessionSupervisorError::InvalidBoundEvent)?;
                let PeerEvent::Admitted(peer) = event else {
                    self.engine.gate.finish_active(active)?;
                    return Err(PeerSessionSupervisorError::InvalidBoundEvent);
                };
                let Some(binding) = CurrentAdmittedSession::from_admitted(generation, &peer) else {
                    self.engine.gate.finish_active(active)?;
                    return Err(PeerSessionSupervisorError::InvalidBoundEvent);
                };
                let endpoint = binding.endpoint();
                let outcome = self
                    .engine
                    .accept_activation_with(active, move |coordinator| {
                        coordinator.activate_admitted_endpoint(endpoint, &peer, now_ns)
                    })?;
                self.current_session = Some(binding);
                self.workspace_reconciliation = None;
                let activation = (|| -> Result<(), WorkspaceControlError> {
                    let current = self
                        .current_session
                        .as_ref()
                        .ok_or(WorkspaceControlError::Unavailable)?;
                    let mut routing = SessionRoutingContext::new(
                        &mut self.engine.coordinator,
                        current.endpoint(),
                    )
                    .map_err(WorkspaceControlError::Coordinator)?;
                    workspace.activate(current, &mut routing, now_ns)
                })();
                if let Err(error) = activation {
                    self.reconcile_fatal_with_workspace(generation, workspace, now_ns)?;
                    return Err(PeerSessionSupervisorError::Workspace(error));
                }
                Ok(outcome)
            }
            GenerationBoundEventClassification::Active => {
                let event = applied
                    .into_event()
                    .ok_or(PeerSessionSupervisorError::InvalidBoundEvent)?;
                self.handle_active_event_with_workspace(generation, event, workspace, now_ns)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_active_event_with_workspace(
        &mut self,
        generation: ConnectionGeneration,
        event: PeerEvent,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if !self.engine.gate.is_active(generation) {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        if let Some(phase) = self.workspace_reconciliation {
            if matches!(event, PeerEvent::Disconnected { .. }) {
                return match phase {
                    WorkspaceReconciliationPhase::TransportLost => {
                        self.reconcile_transport_lost_with_workspace(generation, workspace, now_ns)
                    }
                    WorkspaceReconciliationPhase::GracefulSettled => {
                        self.workspace_reconciliation =
                            Some(WorkspaceReconciliationPhase::TransportLost);
                        self.reconcile_transport_lost_with_workspace(generation, workspace, now_ns)
                    }
                };
            }
            return Err(PeerSessionSupervisorError::Unavailable);
        }
        if matches!(event, PeerEvent::Disconnected { .. }) {
            // A detailed terminal event proves that transport-bound cleanup
            // may be discarded after the channel has ended.
            return self.reconcile_transport_lost_with_workspace(generation, workspace, now_ns);
        }
        let current = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::InvalidBoundEvent)?;
        let result: Result<PeerEventOutcome, WorkspaceControlError> = (|| match event {
            PeerEvent::Message { peer, message } => {
                let pointer_message = matches!(
                    &message,
                    kvm_protocol::WireMessage::PointerLeave(_)
                        | kvm_protocol::WireMessage::PointerEnter(_)
                        | kvm_protocol::WireMessage::PointerTransitionAck(_)
                        | kvm_protocol::WireMessage::PointerTransitionCommit(_)
                );
                if !current.matches_admitted(generation, &peer)
                    || (pointer_message && self.engine.coordinator.route_policy_update_pending())
                {
                    Err(WorkspaceControlError::Unavailable)
                } else if matches!(
                    message,
                    kvm_protocol::WireMessage::DeviceSnapshot(_)
                        | kvm_protocol::WireMessage::DeviceAdded(_)
                        | kvm_protocol::WireMessage::DeviceRemoved(_)
                        | kvm_protocol::WireMessage::DisplaySnapshot(_)
                        | kvm_protocol::WireMessage::DisplayUpdated(_)
                        | kvm_protocol::WireMessage::PointerLeave(_)
                        | kvm_protocol::WireMessage::PointerEnter(_)
                        | kvm_protocol::WireMessage::PointerTransitionAck(_)
                        | kvm_protocol::WireMessage::PointerTransitionCommit(_)
                ) {
                    self.engine
                        .coordinator
                        .validate_workspace_message(&peer, &message)
                        .map_err(WorkspaceControlError::Coordinator)?;
                    let mut routing = SessionRoutingContext::new(
                        &mut self.engine.coordinator,
                        current.endpoint(),
                    )
                    .map_err(WorkspaceControlError::Coordinator)?;
                    workspace.handle_message(current, message, &mut routing, now_ns)
                } else if let kvm_protocol::WireMessage::Input(input) = &message {
                    workspace.validate_remote_input(current, input)?;
                    self.engine
                        .coordinator
                        .handle_endpoint_message(current.endpoint(), &peer, message, now_ns)
                        .map_err(WorkspaceControlError::Coordinator)
                } else {
                    self.engine
                        .coordinator
                        .handle_endpoint_message(current.endpoint(), &peer, message, now_ns)
                        .map_err(WorkspaceControlError::Coordinator)
                }
            }
            PeerEvent::StateChanged(state) => {
                if state == kvm_network::ConnectionState::Connected {
                    let outcome = self
                        .engine
                        .coordinator
                        .handle_endpoint_state(current.endpoint(), state, now_ns)
                        .map_err(WorkspaceControlError::Coordinator)?;
                    {
                        let mut routing = SessionRoutingContext::new(
                            &mut self.engine.coordinator,
                            current.endpoint(),
                        )
                        .map_err(WorkspaceControlError::Coordinator)?;
                        workspace.connected(current, &mut routing)?;
                    }
                    Ok(outcome)
                } else {
                    match state {
                        kvm_network::ConnectionState::Degraded
                        | kvm_network::ConnectionState::Disconnected => {
                            let mut routing = SessionRoutingContext::new(
                                &mut self.engine.coordinator,
                                current.endpoint(),
                            )
                            .map_err(WorkspaceControlError::Coordinator)?;
                            workspace.degrade(current, &mut routing, now_ns)?;
                        }
                        kvm_network::ConnectionState::Connecting
                        | kvm_network::ConnectionState::Authenticating => {}
                        kvm_network::ConnectionState::Connected => unreachable!("handled above"),
                    }
                    let coordinator_state = if state == kvm_network::ConnectionState::Disconnected {
                        // A state hint is not terminal transport proof. Keep
                        // exact cleanup authority until the detailed terminal
                        // event or task-loss path confirms channel closure.
                        kvm_network::ConnectionState::Degraded
                    } else {
                        state
                    };
                    self.engine
                        .coordinator
                        .handle_endpoint_state(current.endpoint(), coordinator_state, now_ns)
                        .map_err(WorkspaceControlError::Coordinator)
                }
            }
            PeerEvent::Disconnected { .. } => unreachable!("handled above"),
            PeerEvent::ReconnectScheduled(delay) => self
                .engine
                .coordinator
                .handle_event(PeerEvent::ReconnectScheduled(delay), now_ns)
                .map_err(WorkspaceControlError::Coordinator),
            PeerEvent::Admitted(_) => Err(WorkspaceControlError::Unavailable),
        })();
        match result {
            Ok(outcome) => Ok(SupervisorEventOutcome::Applied(outcome)),
            Err(error) => {
                // Every non-idempotent workspace/protocol failure is fatal.
                let _ = current;
                self.reconcile_fatal_with_workspace(generation, workspace, now_ns)?;
                Err(PeerSessionSupervisorError::Workspace(error))
            }
        }
    }

    fn handle_applied_event(
        &mut self,
        applied: AppliedGenerationEvent,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        let generation = applied.generation();
        match applied.classification() {
            GenerationBoundEventClassification::PendingIgnored => {
                Ok(SupervisorEventOutcome::PendingIgnored)
            }
            GenerationBoundEventClassification::Cancelled => {
                Ok(SupervisorEventOutcome::PendingCancelled)
            }
            GenerationBoundEventClassification::Activated => {
                let (active, event) = applied
                    .into_activation()
                    .ok_or(PeerSessionSupervisorError::InvalidBoundEvent)?;
                let PeerEvent::Admitted(peer) = event else {
                    self.current_session = None;
                    self.engine.gate.finish_active(active)?;
                    return Err(PeerSessionSupervisorError::InvalidBoundEvent);
                };
                let Some(binding) = CurrentAdmittedSession::from_admitted(generation, &peer) else {
                    self.current_session = None;
                    self.engine.gate.finish_active(active)?;
                    return Err(PeerSessionSupervisorError::InvalidBoundEvent);
                };
                let endpoint = binding.endpoint();
                self.current_session = None;
                let result = self
                    .engine
                    .accept_activation_with(active, move |coordinator| {
                        coordinator.activate_admitted_endpoint(endpoint, &peer, now_ns)
                    });
                if result.is_ok() {
                    self.current_session = Some(binding);
                }
                result
            }
            GenerationBoundEventClassification::Active => {
                let event = applied
                    .into_event()
                    .ok_or(PeerSessionSupervisorError::InvalidBoundEvent)?;
                self.handle_active_event(generation, event, now_ns)
            }
        }
    }

    fn handle_active_event(
        &mut self,
        generation: ConnectionGeneration,
        event: PeerEvent,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        // StateChanged(Disconnected) performs immediate coordinator cleanup,
        // but the generation remains current until its following detailed
        // Disconnected inventory is consumed. If that event never arrives,
        // `connection_lost` closes the generation after the channel ends.
        let endpoint = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?
            .endpoint();
        let retires_generation = matches!(event, PeerEvent::Disconnected { .. });
        if retires_generation {
            self.current_session = None;
        }
        self.engine.handle_with(
            generation,
            retires_generation,
            move |coordinator| match event {
                PeerEvent::Message { peer, message } => {
                    coordinator.handle_endpoint_message(endpoint, &peer, message, now_ns)
                }
                PeerEvent::StateChanged(state) => {
                    coordinator.handle_endpoint_state(endpoint, state, now_ns)
                }
                PeerEvent::Disconnected { .. } => {
                    coordinator.channel_closed(now_ns)?;
                    Ok(PeerEventOutcome::Applied)
                }
                PeerEvent::ReconnectScheduled(_) => Ok(PeerEventOutcome::Ignored),
                PeerEvent::Admitted(_) => Err(CoordinatorError::IdentityMismatch),
            },
        )
    }

    /// Reconciles an active generation whose event channel closed or whose
    /// connection is being replaced.
    ///
    /// # Errors
    ///
    /// Cleanup failure retains the active token and blocks replacement.
    pub fn connection_lost(
        &mut self,
        generation: ConnectionGeneration,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if self.engine.gate.is_active(generation) {
            self.current_session = None;
        }
        self.engine.reconcile_with(Some(generation), |coordinator| {
            coordinator.channel_closed(now_ns)
        })
    }

    pub(crate) fn connection_lost_with_workspace(
        &mut self,
        generation: ConnectionGeneration,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if !self.engine.gate.is_active(generation) {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        self.reconcile_transport_lost_with_workspace(generation, workspace, now_ns)
    }

    /// Recovers a connection task lost to executor panic, abort, or channel
    /// closure.
    ///
    /// An exact pending generation is abandoned without authorization. An
    /// exact active generation is reconciled before retirement. Stale and
    /// cross-gate task reports are ignored without mutating current state.
    ///
    /// # Errors
    ///
    /// Returns a redacted coordinator error when active input reconciliation
    /// fails; the active generation remains occupied for retry.
    pub fn connection_task_lost(
        &mut self,
        generation: ConnectionGeneration,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if self.engine.gate.is_active(generation) {
            return self.connection_lost(generation, now_ns);
        }
        match self.engine.gate.abandon_pending(generation) {
            Ok(()) => Ok(SupervisorEventOutcome::PendingCancelled),
            Err(ConnectionGenerationError::StalePending) => {
                Ok(SupervisorEventOutcome::StaleIgnored)
            }
            Err(error) => Err(PeerSessionSupervisorError::Generation(error)),
        }
    }

    pub(crate) fn connection_task_lost_with_workspace(
        &mut self,
        generation: ConnectionGeneration,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if self.engine.gate.is_active(generation) {
            return self.connection_lost_with_workspace(generation, workspace, now_ns);
        }
        self.connection_task_lost(generation, now_ns)
    }

    pub(crate) fn revoke_with_workspace(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        if self.engine.lifecycle != SupervisorLifecycle::ShuttingDown {
            self.engine.lifecycle = SupervisorLifecycle::Revoked;
        }
        if let Some(generation) = self.active_generation() {
            self.reconcile_fatal_with_workspace(generation, workspace, now_ns)?;
            Ok(())
        } else {
            self.engine
                .coordinator
                .revoke(now_ns)
                .map_err(PeerSessionSupervisorError::Coordinator)
        }
    }

    pub(crate) fn shutdown_with_workspace(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        self.engine.lifecycle = SupervisorLifecycle::ShuttingDown;
        if let Some(generation) = self.active_generation() {
            self.reconcile_shutdown_with_workspace(generation, workspace, now_ns)?;
            Ok(())
        } else {
            self.engine
                .coordinator
                .shutdown(now_ns)
                .map_err(PeerSessionSupervisorError::Coordinator)
        }
    }

    pub(crate) fn retry_reconciliation_with_workspace(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        let generation = self
            .active_generation()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        match self.workspace_reconciliation {
            Some(WorkspaceReconciliationPhase::GracefulSettled) => {
                return self
                    .reconcile_gracefully_settled_with_workspace(generation, workspace, now_ns);
            }
            Some(WorkspaceReconciliationPhase::TransportLost) => {
                return self.reconcile_transport_lost_with_workspace(generation, workspace, now_ns);
            }
            None => {}
        }
        match self.engine.lifecycle {
            SupervisorLifecycle::Running | SupervisorLifecycle::Revoked => {
                self.reconcile_fatal_with_workspace(generation, workspace, now_ns)
            }
            SupervisorLifecycle::ShuttingDown => {
                self.reconcile_shutdown_with_workspace(generation, workspace, now_ns)
            }
        }
    }

    pub(crate) fn propose_pointer_handoff_with_workspace(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        edge: Edge,
        normalized_position: f64,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        let generation = self
            .active_generation()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let result = {
            let current = self
                .current_session
                .as_ref()
                .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
            let mut routing =
                SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
            workspace.propose_pointer_handoff(
                current,
                &mut routing,
                edge,
                normalized_position,
                now_ns,
            )
        };
        if let Err(error) = result {
            return self.fail_workspace_generation(workspace, generation, error, now_ns);
        }
        Ok(())
    }

    pub(crate) fn poll_pointer_timeout_with_workspace(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        let generation = self
            .active_generation()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let current = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let mut routing =
            SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
        if let Err(error) = workspace.poll_timeout(&mut routing, now_ns) {
            return self.fail_workspace_generation(workspace, generation, error, now_ns);
        }
        Ok(())
    }

    pub(crate) fn send_local_snapshot(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        snapshot: kvm_protocol::DisplaySnapshotV1,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        let generation = self
            .active_generation()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let current = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let mut routing =
            SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
        if let Err(error) =
            routing.try_send_control(kvm_protocol::WireMessage::DisplaySnapshot(snapshot))
        {
            self.reconcile_fatal_with_workspace(generation, workspace, now_ns)?;
            return Err(PeerSessionSupervisorError::Coordinator(error));
        }
        Ok(())
    }

    pub(crate) fn send_local_device_snapshot(
        &mut self,
        generation: ConnectionGeneration,
        workspace: &mut WorkspaceControlPlane,
        snapshot: kvm_protocol::DeviceSnapshotV1,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        if self.active_generation() != Some(generation) {
            return Err(PeerSessionSupervisorError::NoActiveGeneration);
        }
        let current = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let mut routing =
            SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
        if let Err(error) =
            routing.try_send_control(kvm_protocol::WireMessage::DeviceSnapshot(snapshot))
        {
            self.reconcile_fatal_with_workspace(generation, workspace, now_ns)?;
            return Err(PeerSessionSupervisorError::Coordinator(error));
        }
        Ok(())
    }

    pub(crate) fn prepare_local_inventory_change(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        let generation = self
            .active_generation()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let result = {
            let current = self
                .current_session
                .as_ref()
                .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
            let mut routing =
                SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
            workspace.prepare_local_change(current, &mut routing, now_ns)
        };
        if let Err(error) = result {
            return self.fail_workspace_generation(workspace, generation, error, now_ns);
        }
        Ok(())
    }

    pub(crate) fn refresh_selected_workspace(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        let generation = self
            .active_generation()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let result = {
            let current = self
                .current_session
                .as_ref()
                .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
            let mut routing =
                SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
            workspace.refresh_selected(current, &mut routing, now_ns)
        };
        if let Err(error) = result {
            return self.fail_workspace_generation(workspace, generation, error, now_ns);
        }
        Ok(())
    }

    pub(crate) fn replace_workspace_topology(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        placements: Vec<WorkspacePlacement>,
        links: Vec<WorkspaceLink>,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        let generation = self
            .active_generation()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let result = {
            let current = self
                .current_session
                .as_ref()
                .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
            let mut routing =
                SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
            workspace.replace_topology(current, &mut routing, placements, links, now_ns)
        };
        if let Err(
            error @ (WorkspaceControlError::InvalidConfiguration
            | WorkspaceControlError::Topology(_)),
        ) = result
        {
            return Err(PeerSessionSupervisorError::Workspace(error));
        }
        if let Err(error) = result {
            return self.fail_workspace_generation(workspace, generation, error, now_ns);
        }
        Ok(())
    }

    pub(crate) fn routing_handle(&self) -> RoutingSnapshotHandle {
        self.engine.coordinator.core().routing_handle()
    }

    pub(crate) fn route_policy_revision(
        &self,
        generation: Option<ConnectionGeneration>,
    ) -> Result<u64, RoutePolicyCoordinatorError> {
        self.require_route_authority(generation)?;
        Ok(self.engine.coordinator.route_policy_revision())
    }

    pub(crate) const fn route_policy_update_pending(&self) -> bool {
        self.engine.coordinator.route_policy_update_pending()
    }

    pub(crate) fn route_policy_config(
        &self,
        generation: Option<ConnectionGeneration>,
    ) -> Result<Config, RoutePolicyCoordinatorError> {
        self.require_route_authority(generation)?;
        Ok(self.engine.coordinator.route_policy_config())
    }

    pub(crate) fn prepare_route_policy_update(
        &mut self,
        generation: Option<ConnectionGeneration>,
        candidate: Config,
        expected_revision: u64,
        now_ns: u64,
    ) -> Result<RoutePolicyUpdateStatus, RoutePolicyCoordinatorError> {
        self.require_route_authority(generation)?;
        self.engine
            .coordinator
            .prepare_route_policy_update(candidate, expected_revision, now_ns)
    }

    pub(crate) fn retry_route_policy_update(
        &mut self,
        generation: Option<ConnectionGeneration>,
        now_ns: u64,
    ) -> Result<RoutePolicyUpdateStatus, RoutePolicyCoordinatorError> {
        self.require_route_authority(generation)?;
        self.engine.coordinator.retry_route_policy_update(now_ns)
    }

    pub(crate) fn staged_route_policy(
        &self,
        generation: Option<ConnectionGeneration>,
    ) -> Result<Option<(u64, Config)>, RoutePolicyCoordinatorError> {
        self.require_route_authority(generation)?;
        Ok(self.engine.coordinator.staged_route_policy())
    }

    pub(crate) fn commit_route_policy_update(
        &mut self,
        generation: Option<ConnectionGeneration>,
        revision: u64,
        now_ns: u64,
    ) -> Result<u64, RoutePolicyUpdateError> {
        if self.require_route_authority(generation).is_err() {
            return Err(RoutePolicyUpdateError::NotReady);
        }
        self.engine
            .coordinator
            .commit_route_policy_update(revision, now_ns)
    }

    pub(crate) fn abort_route_policy_update(
        &mut self,
        generation: Option<ConnectionGeneration>,
        revision: u64,
        now_ns: u64,
    ) -> Result<(), RoutePolicyUpdateError> {
        if self.require_route_authority(generation).is_err() {
            return Err(RoutePolicyUpdateError::NotReady);
        }
        self.engine
            .coordinator
            .abort_route_policy_update(revision, now_ns)
    }

    pub(crate) fn gate_local_devices(
        &mut self,
        generation: ConnectionGeneration,
        devices: &[DeviceId],
        now_ns: u64,
    ) -> Result<(), RoutePolicyCoordinatorError> {
        self.require_route_generation(generation)?;
        self.engine
            .coordinator
            .gate_local_devices(devices, now_ns)
            .map_err(|_| RoutePolicyCoordinatorError::Delivery)
    }

    pub(crate) fn gate_local_devices_offline(
        &mut self,
        devices: &[DeviceId],
        now_ns: u64,
    ) -> Result<(), RoutePolicyCoordinatorError> {
        if self.active_generation().is_some() || self.current_session.is_some() {
            return Err(RoutePolicyCoordinatorError::Delivery);
        }
        self.engine
            .coordinator
            .gate_local_devices(devices, now_ns)
            .map_err(|_| RoutePolicyCoordinatorError::Delivery)
    }

    pub(crate) fn restore_local_device(
        &mut self,
        generation: ConnectionGeneration,
        device: DeviceId,
        now_ns: u64,
    ) -> Result<(), RoutePolicyCoordinatorError> {
        self.require_route_generation(generation)?;
        self.engine
            .coordinator
            .restore_local_device(device, now_ns)
            .map_err(|_| RoutePolicyCoordinatorError::Delivery)
    }

    pub(crate) fn restore_local_device_offline(
        &mut self,
        device: DeviceId,
        now_ns: u64,
    ) -> Result<(), RoutePolicyCoordinatorError> {
        if self.active_generation().is_some() || self.current_session.is_some() {
            return Err(RoutePolicyCoordinatorError::Delivery);
        }
        self.engine
            .coordinator
            .restore_local_device(device, now_ns)
            .map_err(|_| RoutePolicyCoordinatorError::Delivery)
    }

    fn require_route_generation(
        &self,
        generation: ConnectionGeneration,
    ) -> Result<(), RoutePolicyCoordinatorError> {
        if self.engine.gate.is_active(generation) && self.current_session.is_some() {
            Ok(())
        } else {
            Err(RoutePolicyCoordinatorError::Delivery)
        }
    }

    fn require_route_authority(
        &self,
        generation: Option<ConnectionGeneration>,
    ) -> Result<(), RoutePolicyCoordinatorError> {
        match generation {
            Some(generation) => self.require_route_generation(generation),
            None if self.active_generation().is_none() && self.current_session.is_none() => Ok(()),
            None => Err(RoutePolicyCoordinatorError::Delivery),
        }
    }

    pub(crate) fn route_capture_with_workspace(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        captured: CapturedInput,
        now_ns: u64,
    ) -> Result<CaptureOutcome, SupervisorCaptureFailure> {
        if self.engine.active_generation().is_some() != self.current_session.is_some() {
            return Err(SupervisorCaptureFailure {
                outcome: None,
                error: PeerSessionSupervisorError::InvalidBoundEvent,
            });
        }
        match self.engine.coordinator.route_captured(captured, now_ns) {
            Ok(outcome) => {
                if outcome.failsafe_activated() {
                    let Some(generation) = self.active_generation() else {
                        return Ok(outcome);
                    };
                    let current = self
                        .current_session
                        .as_ref()
                        .ok_or(PeerSessionSupervisorError::InvalidBoundEvent)
                        .map_err(|error| SupervisorCaptureFailure {
                            outcome: Some(outcome),
                            error,
                        })?;
                    let result = (|| -> Result<(), WorkspaceControlError> {
                        let mut routing = SessionRoutingContext::new(
                            &mut self.engine.coordinator,
                            current.endpoint(),
                        )
                        .map_err(WorkspaceControlError::Coordinator)?;
                        workspace.cancel_handoff_for_failsafe(current, &mut routing, now_ns)
                    })();
                    if let Err(error) = result {
                        let fatal = self
                            .fail_workspace_generation::<()>(workspace, generation, error, now_ns);
                        let error = match fatal {
                            Err(error) => error,
                            Ok(()) => PeerSessionSupervisorError::InvalidBoundEvent,
                        };
                        return Err(SupervisorCaptureFailure {
                            outcome: Some(outcome),
                            error,
                        });
                    }
                }
                Ok(outcome)
            }
            Err(failure) => {
                let outcome = failure.outcome();
                let trigger = failure.into_error();
                let Some(generation) = self.engine.active_generation() else {
                    let _ = self
                        .engine
                        .coordinator
                        .clear_workspace_routing_ready(now_ns);
                    return Err(SupervisorCaptureFailure {
                        outcome,
                        error: PeerSessionSupervisorError::Coordinator(trigger),
                    });
                };
                let error = match self.reconcile_fatal_with_workspace(generation, workspace, now_ns)
                {
                    Ok(_) => PeerSessionSupervisorError::Coordinator(trigger),
                    Err(error) => error,
                };
                Err(SupervisorCaptureFailure { outcome, error })
            }
        }
    }

    pub(crate) fn native_capture_discontinued_with_workspace(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        let Some(generation) = self.active_generation() else {
            return Ok(());
        };
        let current = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::InvalidBoundEvent)?;
        let result = (|| -> Result<(), WorkspaceControlError> {
            let mut routing =
                SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())
                    .map_err(WorkspaceControlError::Coordinator)?;
            let cleanup = routing
                .trigger_capture_emergency(now_ns)
                .map_err(WorkspaceControlError::Coordinator);
            let pointer = workspace.cancel_handoff_for_failsafe(current, &mut routing, now_ns);
            cleanup.and(pointer)
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail_workspace_generation(workspace, generation, error, now_ns),
        }
    }

    pub(crate) fn selected_lifecycle_tick_with_workspace(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<bool, PeerSessionSupervisorError> {
        let changed = self.engine.coordinator.lifecycle_tick(now_ns);
        let Some(generation) = self.active_generation() else {
            return Ok(changed);
        };
        let current = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::InvalidBoundEvent)?;
        let mut routing =
            SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
        if let Err(error) = workspace.poll_timeout(&mut routing, now_ns) {
            return self.fail_workspace_generation(workspace, generation, error, now_ns);
        }
        Ok(changed)
    }

    #[cfg(test)]
    pub(crate) fn activate_workspace_test_session(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        transport_identity: TransportPeerIdentity,
        local_hello: HelloV1,
        remote_hello: HelloV1,
        now_ns: u64,
    ) -> Result<ConnectionGeneration, PeerSessionSupervisorError> {
        let pending = self.begin_pending(self.role().direction())?;
        let generation = pending.generation();
        let active = self.engine.gate.activate(pending)?;
        let endpoint = SessionEndpoint::for_test(
            kvm_types::PeerId::from_bytes(remote_hello.peer_id.0),
            HostId::from_bytes(remote_hello.host_id.0),
            generation,
            kvm_protocol::PROTOCOL_VERSION_V1,
            [0xa5; 32],
        )
        .ok_or(PeerSessionSupervisorError::InvalidBoundEvent)?;
        self.engine.coordinator.activate_workspace_test_binding(
            endpoint,
            transport_identity.clone(),
            local_hello.clone(),
            remote_hello.clone(),
            now_ns,
        )?;
        let current = CurrentAdmittedSession {
            endpoint,
            transport_identity,
            local_hello,
            remote_hello,
        };
        let mut routing =
            SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
        if let Err(error) = workspace.activate(&current, &mut routing, now_ns) {
            self.engine.coordinator.channel_closed(now_ns)?;
            self.engine.gate.finish_active(active)?;
            return Err(PeerSessionSupervisorError::Workspace(error));
        }
        self.engine.active = Some(active);
        self.current_session = Some(current);
        Ok(generation)
    }

    #[cfg(test)]
    pub(crate) fn apply_workspace_test_message(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        message: kvm_protocol::WireMessage,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, PeerSessionSupervisorError> {
        let generation = self
            .active_generation()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let result = {
            let current = self
                .current_session
                .as_ref()
                .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
            let mut routing =
                SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
            workspace.handle_message(current, message, &mut routing, now_ns)
        };
        match result {
            Ok(outcome) => Ok(outcome),
            Err(error) => self.fail_workspace_generation(workspace, generation, error, now_ns),
        }
    }

    #[cfg(test)]
    pub(crate) fn apply_workspace_test_state(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        state: kvm_network::ConnectionState,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        let generation = self
            .active_generation()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        self.handle_active_event_with_workspace(
            generation,
            PeerEvent::StateChanged(state),
            workspace,
            now_ns,
        )
    }

    #[cfg(test)]
    pub(crate) fn test_hold_inbound(
        &mut self,
        event: kvm_input::InputEvent,
        now_ns: u64,
    ) -> Result<(), PeerSessionSupervisorError> {
        self.engine
            .coordinator
            .test_hold_inbound(event, now_ns)
            .map_err(PeerSessionSupervisorError::Coordinator)
    }

    #[cfg(test)]
    pub(crate) fn test_injection_mut(&mut self) -> &mut I {
        self.engine.coordinator.test_injection_mut()
    }

    #[cfg(test)]
    pub(crate) fn apply_workspace_test_protocol_failure(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        message: kvm_protocol::WireMessage,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        let generation = self
            .active_generation()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        let trigger = self
            .engine
            .coordinator
            .test_handle_authorized_message(message, now_ns)
            .expect_err("test message must exercise a protocol failure");
        let outcome = self.reconcile_fatal_with_workspace(generation, workspace, now_ns)?;
        let _ = trigger;
        Ok(outcome)
    }

    fn fail_workspace_generation<T>(
        &mut self,
        workspace: &mut WorkspaceControlPlane,
        generation: ConnectionGeneration,
        error: WorkspaceControlError,
        now_ns: u64,
    ) -> Result<T, PeerSessionSupervisorError> {
        self.reconcile_fatal_with_workspace(generation, workspace, now_ns)?;
        Err(PeerSessionSupervisorError::Workspace(error))
    }

    fn reconcile_fatal_with_workspace(
        &mut self,
        generation: ConnectionGeneration,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if !self.engine.gate.is_active(generation) {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        match self.workspace_reconciliation {
            Some(WorkspaceReconciliationPhase::TransportLost) => {
                return self.reconcile_transport_lost_with_workspace(generation, workspace, now_ns);
            }
            Some(WorkspaceReconciliationPhase::GracefulSettled) => {
                return self
                    .reconcile_gracefully_settled_with_workspace(generation, workspace, now_ns);
            }
            None => {}
        }
        let current = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        if !self
            .engine
            .coordinator
            .authorizes_endpoint(current.endpoint())
        {
            self.workspace_reconciliation = Some(WorkspaceReconciliationPhase::GracefulSettled);
            return self.reconcile_gracefully_settled_with_workspace(generation, workspace, now_ns);
        }
        {
            let mut routing =
                SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
            workspace
                .retire(current, &mut routing, now_ns)
                .map_err(PeerSessionSupervisorError::Workspace)?;
        }
        self.engine
            .coordinator
            .session_fatal_cleanup(now_ns)
            .map_err(PeerSessionSupervisorError::Coordinator)?;
        self.current_session = None;
        self.workspace_reconciliation = None;
        self.engine.finish_active()?;
        Ok(SupervisorEventOutcome::Retired(PeerEventOutcome::Applied))
    }

    fn reconcile_transport_lost_with_workspace(
        &mut self,
        generation: ConnectionGeneration,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if !self.engine.gate.is_active(generation) {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        let current = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        self.workspace_reconciliation = Some(WorkspaceReconciliationPhase::TransportLost);
        self.engine
            .coordinator
            .channel_closed(now_ns)
            .map_err(PeerSessionSupervisorError::Coordinator)?;
        workspace
            .retire_after_transport_loss(current)
            .map_err(PeerSessionSupervisorError::Workspace)?;
        self.current_session = None;
        self.workspace_reconciliation = None;
        self.engine.finish_active()?;
        Ok(SupervisorEventOutcome::Retired(PeerEventOutcome::Applied))
    }

    fn reconcile_shutdown_with_workspace(
        &mut self,
        generation: ConnectionGeneration,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if !self.engine.gate.is_active(generation) {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        let current = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        if !self
            .engine
            .coordinator
            .authorizes_endpoint(current.endpoint())
        {
            self.workspace_reconciliation = Some(WorkspaceReconciliationPhase::GracefulSettled);
            return self.reconcile_gracefully_settled_with_workspace(generation, workspace, now_ns);
        }
        {
            let mut routing =
                SessionRoutingContext::new(&mut self.engine.coordinator, current.endpoint())?;
            workspace
                .retire(current, &mut routing, now_ns)
                .map_err(PeerSessionSupervisorError::Workspace)?;
        }
        self.engine
            .coordinator
            .shutdown(now_ns)
            .map_err(PeerSessionSupervisorError::Coordinator)?;
        self.current_session = None;
        self.workspace_reconciliation = None;
        self.engine.finish_active()?;
        Ok(SupervisorEventOutcome::Retired(PeerEventOutcome::Applied))
    }

    fn reconcile_gracefully_settled_with_workspace(
        &mut self,
        generation: ConnectionGeneration,
        workspace: &mut WorkspaceControlPlane,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        if !self.engine.gate.is_active(generation) {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        let current = self
            .current_session
            .as_ref()
            .ok_or(PeerSessionSupervisorError::NoActiveGeneration)?;
        workspace
            .retire_after_graceful_settlement(current)
            .map_err(PeerSessionSupervisorError::Workspace)?;
        if self.engine.lifecycle == SupervisorLifecycle::ShuttingDown {
            self.engine
                .coordinator
                .shutdown(now_ns)
                .map_err(PeerSessionSupervisorError::Coordinator)?;
        }
        self.current_session = None;
        self.workspace_reconciliation = None;
        self.engine.finish_active()?;
        Ok(SupervisorEventOutcome::Retired(PeerEventOutcome::Applied))
    }

    /// Immediately prevents future activation and reconciles an active peer.
    /// A pending task may only return its existing token for cancellation; it
    /// can no longer activate after this call.
    ///
    /// # Errors
    ///
    /// Cleanup failure leaves the generation occupied for a later retry.
    pub fn revoke(&mut self, now_ns: u64) -> Result<(), PeerSessionSupervisorError> {
        if self.engine.lifecycle != SupervisorLifecycle::ShuttingDown {
            self.engine.lifecycle = SupervisorLifecycle::Revoked;
        }
        if self.engine.active.is_some() {
            match self.engine.lifecycle {
                SupervisorLifecycle::ShuttingDown => {
                    self.engine
                        .reconcile_with(None, |coordinator| coordinator.shutdown(now_ns))?;
                }
                SupervisorLifecycle::Running | SupervisorLifecycle::Revoked => {
                    self.engine
                        .reconcile_with(None, |coordinator| coordinator.revoke(now_ns))?;
                }
            }
        } else {
            match self.engine.lifecycle {
                SupervisorLifecycle::ShuttingDown => self.engine.coordinator.shutdown(now_ns),
                SupervisorLifecycle::Running | SupervisorLifecycle::Revoked => {
                    self.engine.coordinator.revoke(now_ns)
                }
            }
            .map_err(PeerSessionSupervisorError::Coordinator)?;
        }
        self.current_session = None;
        Ok(())
    }

    /// Reconciles the active peer and permanently shuts down its daemon core.
    ///
    /// # Errors
    ///
    /// Cleanup failure leaves the generation occupied for a later retry.
    pub fn shutdown(&mut self, now_ns: u64) -> Result<(), PeerSessionSupervisorError> {
        self.engine.lifecycle = SupervisorLifecycle::ShuttingDown;
        if self.engine.active.is_some() {
            self.engine
                .reconcile_with(None, |coordinator| coordinator.shutdown(now_ns))?;
        } else {
            self.engine
                .coordinator
                .shutdown(now_ns)
                .map_err(PeerSessionSupervisorError::Coordinator)?;
        }
        self.current_session = None;
        Ok(())
    }

    /// Retries cleanup after a prior active-generation reconciliation failure.
    /// Replacement remains prohibited until this succeeds.
    ///
    /// # Errors
    ///
    /// Returns a redacted cleanup error and retains the generation on failure.
    pub fn retry_reconciliation(
        &mut self,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerSessionSupervisorError> {
        let result = match self.engine.lifecycle {
            SupervisorLifecycle::Running => self.engine.reconcile_with(None, |coordinator| {
                coordinator.session_fatal_cleanup(now_ns)
            }),
            SupervisorLifecycle::Revoked => self
                .engine
                .reconcile_with(None, |coordinator| coordinator.revoke(now_ns)),
            SupervisorLifecycle::ShuttingDown => self
                .engine
                .reconcile_with(None, |coordinator| coordinator.shutdown(now_ns)),
        };
        if result.is_ok() {
            self.current_session = None;
        }
        result
    }
}

impl<I> PeerSessionSupervisor<I, ManagedSessionOutbound>
where
    I: OutputInjectionBackend,
{
    pub(crate) fn install_session_outbound(
        &mut self,
        generation: ConnectionGeneration,
        sender: PeerSender,
    ) -> Result<(), PeerSender> {
        if self
            .active_generation()
            .is_some_and(|active| active != generation)
        {
            return Err(sender);
        }
        self.engine
            .coordinator
            .outbound_mut()
            .install(generation, sender)
    }

    #[cfg(test)]
    pub(crate) fn test_session_outbound(
        &mut self,
        message: kvm_protocol::WireMessage,
    ) -> Result<(), crate::OutboundPeerError> {
        self.engine.coordinator.outbound_mut().try_send(message)
    }
}

#[cfg(test)]
mod tests {
    use kvm_protocol::{HelloV1, WireHostId, WirePeerId, WirePlatform, PROTOCOL_VERSION_V2};
    use kvm_types::PeerId;

    use super::*;

    #[derive(Debug, Default)]
    struct FakeCoordinator {
        applied: usize,
        reconciled: usize,
        fail_operation: bool,
        payload_marker: Option<&'static str>,
    }

    impl FakeCoordinator {
        fn apply(&mut self) -> Result<PeerEventOutcome, CoordinatorError> {
            self.applied += 1;
            if self.fail_operation {
                Err(CoordinatorError::CleanupIncomplete)
            } else {
                Ok(PeerEventOutcome::Applied)
            }
        }

        fn reconcile(&mut self) -> Result<(), CoordinatorError> {
            self.reconciled += 1;
            if self.fail_operation {
                Err(CoordinatorError::CleanupIncomplete)
            } else {
                Ok(())
            }
        }
    }

    fn engine() -> SupervisorEngine<FakeCoordinator> {
        SupervisorEngine::new(
            ConnectionGenerationGate::new(WirePeerId([1; 16]), WirePeerId([2; 16])).unwrap(),
            FakeCoordinator::default(),
        )
    }

    fn activate(engine: &mut SupervisorEngine<FakeCoordinator>) -> ConnectionGeneration {
        let pending = engine.begin_pending(ConnectionDirection::Outbound).unwrap();
        let generation = pending.generation();
        let active = engine.gate.activate(pending).unwrap();
        engine
            .accept_activation_with(active, FakeCoordinator::apply)
            .unwrap();
        generation
    }

    #[test]
    fn canonical_direction_and_single_generation_are_enforced() {
        let mut engine = engine();
        assert!(matches!(
            engine.begin_pending(ConnectionDirection::Inbound),
            Err(PeerSessionSupervisorError::Generation(_))
        ));

        let generation = activate(&mut engine);
        assert_eq!(engine.active_generation(), Some(generation));
        let diagnostics = format!("{:?}", engine.gate);
        assert!(!diagnostics.contains("next_generation"));
        assert!(!diagnostics.contains("active: Some"));
        assert!(matches!(
            engine.begin_pending(ConnectionDirection::Outbound),
            Err(PeerSessionSupervisorError::Generation(
                ConnectionGenerationError::ActiveExists
            ))
        ));
    }

    #[test]
    fn stale_events_never_reach_coordinator_or_retire_current_generation() {
        let mut engine = engine();
        let stale_pending = engine.begin_pending(ConnectionDirection::Outbound).unwrap();
        let stale = stale_pending.generation();
        engine.cancel_pending(stale_pending).unwrap();
        let current = activate(&mut engine);
        let before = engine.coordinator.applied;

        assert!(matches!(
            engine.handle_with(stale, true, FakeCoordinator::apply),
            Ok(SupervisorEventOutcome::StaleIgnored)
        ));
        assert_eq!(engine.coordinator.applied, before);
        assert_eq!(engine.active_generation(), Some(current));
    }

    #[test]
    fn current_terminal_event_reconciles_then_allows_replacement() {
        let mut engine = engine();
        let current = activate(&mut engine);

        assert!(matches!(
            engine.handle_with(current, true, FakeCoordinator::apply),
            Ok(SupervisorEventOutcome::Retired(PeerEventOutcome::Applied))
        ));
        assert_eq!(engine.active_generation(), None);
        assert!(engine.begin_pending(ConnectionDirection::Outbound).is_ok());
    }

    #[test]
    fn late_message_or_disconnect_after_retirement_is_harmlessly_ignored() {
        for retires_late_event in [false, true] {
            let mut engine = engine();
            let current = activate(&mut engine);
            engine
                .handle_with(current, true, FakeCoordinator::apply)
                .unwrap();
            let before = engine.coordinator.applied;

            assert!(matches!(
                engine.handle_with(current, retires_late_event, FakeCoordinator::apply),
                Ok(SupervisorEventOutcome::StaleIgnored)
            ));
            assert_eq!(engine.coordinator.applied, before);
        }
    }

    #[test]
    fn late_active_event_after_revocation_is_ignored_before_lifecycle_check() {
        let mut engine = engine();
        let current = activate(&mut engine);
        engine
            .reconcile_with(Some(current), FakeCoordinator::reconcile)
            .unwrap();
        engine.lifecycle = SupervisorLifecycle::Revoked;
        let before = engine.coordinator.applied;

        assert!(matches!(
            engine.handle_with(current, false, FakeCoordinator::apply),
            Ok(SupervisorEventOutcome::StaleIgnored)
        ));
        assert_eq!(engine.coordinator.applied, before);
    }

    #[test]
    fn failed_reconciliation_blocks_replacement_until_retry_succeeds() {
        let mut engine = engine();
        let current = activate(&mut engine);
        engine.coordinator.fail_operation = true;

        assert!(matches!(
            engine.reconcile_with(Some(current), FakeCoordinator::reconcile),
            Err(PeerSessionSupervisorError::Coordinator(_))
        ));
        assert_eq!(engine.active_generation(), Some(current));
        assert!(matches!(
            engine.begin_pending(ConnectionDirection::Outbound),
            Err(PeerSessionSupervisorError::Generation(
                ConnectionGenerationError::ActiveExists
            ))
        ));

        engine.coordinator.fail_operation = false;
        assert!(matches!(
            engine.reconcile_with(Some(current), FakeCoordinator::reconcile),
            Ok(SupervisorEventOutcome::Retired(PeerEventOutcome::Applied))
        ));
        assert!(engine.begin_pending(ConnectionDirection::Outbound).is_ok());
    }

    #[test]
    fn revocation_cancels_late_activation_and_permanently_blocks_new_work() {
        let mut engine = engine();
        let pending = engine.begin_pending(ConnectionDirection::Outbound).unwrap();
        engine.lifecycle = SupervisorLifecycle::Revoked;
        let active = engine.gate.activate(pending).unwrap();

        assert!(matches!(
            engine.accept_activation_with(active, FakeCoordinator::apply),
            Err(PeerSessionSupervisorError::Unavailable)
        ));
        assert!(matches!(
            engine.begin_pending(ConnectionDirection::Outbound),
            Err(PeerSessionSupervisorError::Unavailable)
        ));
    }

    #[test]
    fn errors_and_debug_are_payload_redacted_and_bounded() {
        let mut engine = engine();
        engine.coordinator.payload_marker = Some("SECRET-INPUT-PAYLOAD");
        let generation = activate(&mut engine);
        engine.coordinator.fail_operation = true;
        let error = engine
            .handle_with(generation, false, FakeCoordinator::apply)
            .unwrap_err();
        let rendered = format!("{error:?} {error}");

        assert!(!rendered.contains("SECRET-INPUT-PAYLOAD"));
        assert!(rendered.len() < 160);
    }

    #[test]
    fn current_admission_retains_and_delegates_the_exact_endpoint() {
        let mut engine = engine();
        let generation = activate(&mut engine);
        let remote_host = HostId::from_bytes([31; 16]);
        let remote_peer = PeerId::from_bytes([32; 16]);
        let endpoint = SessionEndpoint::for_test(
            remote_peer,
            remote_host,
            generation,
            PROTOCOL_VERSION_V2,
            [77; 32],
        )
        .unwrap();
        let hello = |host: [u8; 16], peer: [u8; 16]| HelloV1 {
            host_id: WireHostId(host),
            peer_id: WirePeerId(peer),
            host_name: "endpoint-test".to_owned(),
            platform: WirePlatform::Linux,
            minimum_protocol_version: 1,
            maximum_protocol_version: PROTOCOL_VERSION_V2,
            daemon_version: "test".to_owned(),
            nonce: [55; 32],
        };
        let current = CurrentAdmittedSession {
            endpoint,
            transport_identity: TransportPeerIdentity {
                host_id: WireHostId(remote_host.into_bytes()),
                peer_id: WirePeerId(remote_peer.into_bytes()),
                credential_fingerprint: [66; 32],
            },
            local_hello: hello([30; 16], [29; 16]),
            remote_hello: hello(remote_host.into_bytes(), remote_peer.into_bytes()),
        };

        assert_eq!(current.endpoint(), endpoint);
        assert_eq!(current.generation(), generation);
        assert_eq!(current.remote_host_id(), remote_host);
        assert_eq!(format!("{current:?}"), "CurrentAdmittedSession([REDACTED])");
    }
}
