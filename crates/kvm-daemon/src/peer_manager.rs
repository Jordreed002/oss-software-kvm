//! Bounded, platform-neutral scheduling for paired LAN peers.
//!
//! Discovery values are reachability hints only. A task can reach daemon
//! coordination only after a sealed transport, exporter admission, an affine
//! generation-bound session, and the exact peer supervisor all agree.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use kvm_config::{ConfigStore, ConfigStoreAuthority, ConfiguredDeviceRoute, DeviceRouteConfig};
use kvm_discovery::DiscoverySnapshot;
use kvm_input::InputPayload;
use kvm_network::{
    ConnectionDirection, ConnectionGeneration, ConnectionRole, GenerationBoundEventClassification,
    GenerationBoundPeerEvent, GenerationBoundPeerSession, GenerationBoundSessionBuildError,
    GenerationBoundSessionError, LanPeerAddress, PeerSender, PersistentPeerConfig,
    ReconnectBackoff, ReconnectPolicy, SecurePeerStream, SessionAdmission, SessionEnd,
    SessionError, TransportPeerIdentity,
};
use kvm_protocol::{WireHostId, WirePeerId};
use kvm_security::{PairedPeer, PeerIdentity};
use kvm_topology::{WorkspaceLink, WorkspacePlacement};
use kvm_types::{DeviceId, DeviceRoute, Display, Edge, InputDevice, PeerId};
use thiserror::Error;
use tokio::sync::{mpsc, watch};

use crate::core::{CaptureRouteState, RoutePolicyUpdateError, RoutePolicyUpdateStatus};
use crate::device_inventory::DeviceInventorySnapshot;
use crate::session::RoutePolicyCoordinatorError;
use crate::{
    CaptureDisposition, CaptureLifecycleState, CapturedInput, ManagedSessionOutbound, OutboundPeer,
    OutputInjectionBackend, PeerSessionSupervisor, PeerSessionSupervisorError,
    RoutingSnapshotHandle, SupervisorEventOutcome, WorkspaceControlPlane,
};

pub const MAX_MANAGED_PEERS: usize = 256;
pub const MAX_CANDIDATES_PER_PEER: usize = 32;

static NEXT_MANAGER_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerManagerConfig {
    pub maximum_peers: usize,
    pub maximum_candidates_per_peer: usize,
    pub reconnect: ReconnectPolicy,
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        Self {
            maximum_peers: MAX_MANAGED_PEERS,
            maximum_candidates_per_peer: MAX_CANDIDATES_PER_PEER,
            reconnect: ReconnectPolicy::default(),
        }
    }
}

impl PeerManagerConfig {
    fn validate(self) -> Result<Self, PeerManagerError> {
        if self.maximum_peers == 0
            || self.maximum_peers > MAX_MANAGED_PEERS
            || self.maximum_candidates_per_peer == 0
            || self.maximum_candidates_per_peer > MAX_CANDIDATES_PER_PEER
            || self.reconnect.validate().is_err()
        {
            return Err(PeerManagerError::InvalidConfiguration);
        }
        Ok(self)
    }
}

/// One paired identity and the only supervisor permitted to coordinate it.
pub struct ManagedPairedPeer<I, O> {
    identity: PeerIdentity,
    supervisor: PeerSessionSupervisor<I, O>,
}

impl<I, O> ManagedPairedPeer<I, O> {
    #[must_use]
    pub fn new(peer: &PairedPeer, supervisor: PeerSessionSupervisor<I, O>) -> Self {
        Self {
            identity: peer.identity().clone(),
            supervisor,
        }
    }
}

impl<I, O> fmt::Debug for ManagedPairedPeer<I, O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedPairedPeer")
            .field("identity", &"[REDACTED]")
            .field("fingerprint", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerTaskSlot {
    Idle,
    Connecting { task_id: u64 },
    Session { generation: ConnectionGeneration },
}

struct ManagedPeerState<I, O> {
    identity: PeerIdentity,
    supervisor: PeerSessionSupervisor<I, O>,
    candidates: BTreeSet<LanPeerAddress>,
    candidate_cursor: usize,
    backoff: ReconnectBackoff,
    retry_not_before: Duration,
    task: PeerTaskSlot,
    revoked: bool,
    route_store_authority: Option<ConfigStoreAuthority>,
}

/// Count-only scheduler snapshot suitable for diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerManagerSnapshot {
    pub paired_peers: usize,
    pub peers_with_candidates: usize,
    pub connecting_tasks: usize,
    pub session_tasks: usize,
    pub revoked_peers: usize,
}

/// Coarse result category for the mandatory selected capture path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedCaptureState {
    Local,
    Inert,
    RemoteQueued,
    Gated,
    Rejected,
    SessionRetired,
    CleanupPending,
}

/// Redacted synchronous decision returned to a future native capture bridge.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SelectedCaptureOutcome {
    disposition: CaptureDisposition,
    failsafe_activated: bool,
    state: SelectedCaptureState,
}

impl SelectedCaptureOutcome {
    #[must_use]
    pub const fn disposition(self) -> CaptureDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn failsafe_activated(self) -> bool {
        self.failsafe_activated
    }

    #[must_use]
    pub const fn state(self) -> SelectedCaptureState {
        self.state
    }

    const fn rejected(state: SelectedCaptureState) -> Self {
        Self {
            disposition: CaptureDisposition::AllowLocal,
            failsafe_activated: false,
            state,
        }
    }
}

impl fmt::Debug for SelectedCaptureOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedCaptureOutcome")
            .field("disposition", &self.disposition)
            .field("failsafe_activated", &self.failsafe_activated)
            .field("state", &self.state)
            .finish()
    }
}

/// Coarse progress of one durable selected-device routing transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceRouteUpdateState {
    Committed,
    CleanupPending,
    PersistencePending,
}

/// Revisioned result with a payload-redacted Debug representation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeviceRouteUpdateOutcome {
    state: DeviceRouteUpdateState,
    committed_revision: u64,
}

/// Coarse progress of one runtime local-device inventory transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceInventoryUpdateState {
    Committed,
    CleanupPending,
}

/// Revisioned runtime inventory result with redacted diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeviceInventoryUpdateOutcome {
    state: DeviceInventoryUpdateState,
    committed_revision: u64,
}

impl DeviceInventoryUpdateOutcome {
    #[must_use]
    pub const fn state(self) -> DeviceInventoryUpdateState {
        self.state
    }

    #[must_use]
    pub const fn committed_revision(self) -> u64 {
        self.committed_revision
    }
}

impl fmt::Debug for DeviceInventoryUpdateOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceInventoryUpdateOutcome")
            .field("state", &self.state)
            .field("revision", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl DeviceRouteUpdateOutcome {
    #[must_use]
    pub const fn state(self) -> DeviceRouteUpdateState {
        self.state
    }

    #[must_use]
    pub const fn committed_revision(self) -> u64 {
        self.committed_revision
    }
}

impl fmt::Debug for DeviceRouteUpdateOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceRouteUpdateOutcome")
            .field("state", &self.state)
            .field("revision", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Deterministic scheduler for one immutable paired-peer snapshot.
pub struct PeerManager<I, O> {
    manager_id: u64,
    config: PeerManagerConfig,
    peers: BTreeMap<PeerId, ManagedPeerState<I, O>>,
    next_task_id: u64,
    shutting_down: bool,
    selected_capture_available: bool,
    workspace: Option<WorkspaceControlPlane>,
}

impl<I, O> fmt::Debug for PeerManager<I, O>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerManager")
            .field("snapshot", &self.snapshot())
            .field("shutting_down", &self.shutting_down)
            .field(
                "selected_capture_available",
                &self.selected_capture_available,
            )
            .finish_non_exhaustive()
    }
}

impl<I, O> PeerManager<I, O>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    /// Builds a bounded immutable paired-peer scheduler snapshot.
    ///
    /// # Errors
    ///
    /// Rejects nil, duplicate, colliding, oversized, role-inconsistent, or
    /// otherwise invalid public identity state.
    pub fn new(
        local_peer_id: PeerId,
        peers: impl IntoIterator<Item = ManagedPairedPeer<I, O>>,
        config: PeerManagerConfig,
    ) -> Result<Self, PeerManagerError> {
        let config = config.validate()?;
        if local_peer_id.into_bytes() == [0; 16] {
            return Err(PeerManagerError::InvalidIdentity);
        }
        let manager_id = NEXT_MANAGER_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| PeerManagerError::IdentifierSpaceExhausted)?;
        let mut states = BTreeMap::new();
        let mut hosts = BTreeSet::new();
        let mut fingerprints = BTreeSet::new();
        for (index, peer) in peers.into_iter().enumerate() {
            if index >= config.maximum_peers {
                return Err(PeerManagerError::CapacityExceeded);
            }
            let identity = peer.identity;
            if identity.peer_id().into_bytes() == [0; 16]
                || identity.host_id().into_bytes() == [0; 16]
                || identity.fingerprint().as_bytes() == &[0; 32]
                || identity.peer_id() == local_peer_id
            {
                return Err(PeerManagerError::InvalidIdentity);
            }
            let expected_role = kvm_network::ConnectionRole::for_peers(
                WirePeerId(local_peer_id.into_bytes()),
                WirePeerId(identity.peer_id().into_bytes()),
            )?;
            if peer.supervisor.role() != expected_role
                || !hosts.insert(identity.host_id())
                || !fingerprints.insert(*identity.fingerprint().as_bytes())
                || states.contains_key(&identity.peer_id())
            {
                return Err(PeerManagerError::InvalidIdentity);
            }
            states.insert(
                identity.peer_id(),
                ManagedPeerState {
                    identity,
                    supervisor: peer.supervisor,
                    candidates: BTreeSet::new(),
                    candidate_cursor: 0,
                    backoff: ReconnectBackoff::new(config.reconnect),
                    retry_not_before: Duration::ZERO,
                    task: PeerTaskSlot::Idle,
                    revoked: false,
                    route_store_authority: None,
                },
            );
        }
        Ok(Self {
            manager_id,
            config,
            peers: states,
            next_task_id: 1,
            shutting_down: false,
            selected_capture_available: false,
            workspace: None,
        })
    }

    /// Attaches the sole mandatory M06 workspace path. The selected pointer
    /// peer is immutable for the manager lifetime.
    ///
    /// # Errors
    ///
    /// Rejects duplicate attachment or a peer outside the paired snapshot.
    pub fn attach_workspace_control(
        &mut self,
        workspace: WorkspaceControlPlane,
    ) -> Result<(), PeerManagerError> {
        if self.workspace.is_some() {
            return Err(PeerManagerError::WorkspaceAlreadyAttached);
        }
        let selected = workspace.selected_pointer_peer();
        let selected_peer = self
            .peers
            .get(&selected)
            .ok_or(PeerManagerError::InvalidIdentity)?;
        if self.shutting_down
            || !selected_peer
                .supervisor
                .validates_selected_workspace_attachment(
                    &workspace,
                    selected_peer.identity.host_id(),
                )
            || self.peers.values().any(|peer| {
                peer.revoked
                    || peer.task != PeerTaskSlot::Idle
                    || peer.supervisor.active_generation().is_some()
            })
        {
            return Err(PeerManagerError::InvalidIdentity);
        }
        self.workspace = Some(workspace);
        Ok(())
    }

    /// Returns an observational snapshot handle for status presentation.
    /// Suppression and dispatch decisions must use the synchronous selected
    /// capture entry instead of this potentially historical view.
    ///
    /// # Errors
    ///
    /// Returns an error when workspace control is not attached or its immutable
    /// selected peer is absent from the paired snapshot.
    pub fn selected_routing_handle(&self) -> Result<RoutingSnapshotHandle, PeerManagerError> {
        let workspace = self
            .workspace
            .as_ref()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        self.peers
            .get(&workspace.selected_pointer_peer())
            .map(|peer| peer.supervisor.routing_handle())
            .ok_or(PeerManagerError::InvalidIdentity)
    }

    /// Reports whether this host currently owns visible pointer authority.
    ///
    /// This observation is intended for the runtime-owned native cursor
    /// visibility bridge. It grants no routing or dispatch capability.
    ///
    /// # Errors
    ///
    /// Returns an error until the selected workspace is attached.
    pub fn local_pointer_authority(&self) -> Result<bool, PeerManagerError> {
        let routing = self.selected_routing_handle()?.load();
        Ok(routing.workspace.active_host == routing.workspace.local_host)
    }

    /// Synchronously routes one trusted capture decision through the sole
    /// selected supervisor and its exact admitted FIFO.
    ///
    /// Remote suppression is reported only after queue acceptance. Every
    /// rejected or unavailable decision remains local; an `Inert` outcome is
    /// the core's explicit quarantine/handoff suppression decision.
    #[must_use]
    pub fn route_selected_capture(
        &mut self,
        captured: CapturedInput,
        now_ns: u64,
    ) -> SelectedCaptureOutcome {
        if self.shutting_down || !self.selected_capture_available {
            return SelectedCaptureOutcome::rejected(SelectedCaptureState::Rejected);
        }
        let boundary = if captured.classification == crate::EventClassification::Physical
            && matches!(captured.event.payload, InputPayload::PointerMove { .. })
        {
            captured.native_pointer_position().and_then(|position| {
                self.workspace
                    .as_ref()
                    .and_then(|workspace| workspace.native_pointer_boundary(position))
            })
        } else {
            None
        };
        if let Some((edge, normalized_position)) = boundary {
            if self
                .propose_pointer_handoff(edge, normalized_position, now_ns)
                .is_err()
            {
                return SelectedCaptureOutcome::rejected(SelectedCaptureState::Gated);
            }
        }
        let Some(workspace) = self.workspace.as_mut() else {
            return SelectedCaptureOutcome::rejected(SelectedCaptureState::Rejected);
        };
        let selected = workspace.selected_pointer_peer();
        let Some(peer) = self.peers.get_mut(&selected) else {
            return SelectedCaptureOutcome::rejected(SelectedCaptureState::Rejected);
        };
        if peer.revoked {
            return SelectedCaptureOutcome::rejected(SelectedCaptureState::Rejected);
        }
        if let Some(generation) = peer.supervisor.active_generation() {
            if peer.task != (PeerTaskSlot::Session { generation }) {
                let _ = peer
                    .supervisor
                    .connection_lost_with_workspace(generation, workspace, now_ns);
                return SelectedCaptureOutcome::rejected(
                    if peer.supervisor.active_generation().is_some() {
                        SelectedCaptureState::CleanupPending
                    } else {
                        SelectedCaptureState::SessionRetired
                    },
                );
            }
        } else if let PeerTaskSlot::Session { generation } = peer.task {
            if peer.supervisor.pending_generation() == Some(generation) {
                return SelectedCaptureOutcome::rejected(SelectedCaptureState::Gated);
            }
            peer.task = PeerTaskSlot::Idle;
            schedule_retry(peer, Duration::from_nanos(now_ns));
            return SelectedCaptureOutcome::rejected(SelectedCaptureState::SessionRetired);
        }

        match peer
            .supervisor
            .route_capture_with_workspace(workspace, captured, now_ns)
        {
            Ok(outcome) => SelectedCaptureOutcome {
                disposition: outcome.disposition(),
                failsafe_activated: outcome.failsafe_activated(),
                state: match (outcome.disposition(), outcome.state()) {
                    (CaptureDisposition::SuppressLocal, CaptureRouteState::RemoteQueued) => {
                        SelectedCaptureState::RemoteQueued
                    }
                    (CaptureDisposition::SuppressLocal, _) => SelectedCaptureState::Inert,
                    (CaptureDisposition::AllowLocal, CaptureRouteState::Local) => {
                        SelectedCaptureState::Local
                    }
                    (CaptureDisposition::AllowLocal, _) => SelectedCaptureState::Gated,
                },
            },
            Err(failure) => {
                let safe = failure.outcome();
                let _ = failure.into_error();
                let active = peer.supervisor.active_generation().is_some();
                if !active {
                    peer.task = PeerTaskSlot::Idle;
                    schedule_retry(peer, Duration::from_nanos(now_ns));
                }
                let disposition = safe.map_or(
                    CaptureDisposition::AllowLocal,
                    crate::core::CaptureOutcome::disposition,
                );
                let state = if disposition == CaptureDisposition::SuppressLocal {
                    // Only the core can mint this fallback, for a record whose
                    // remote lifecycle was already suppressed or quarantined.
                    SelectedCaptureState::Inert
                } else if active {
                    SelectedCaptureState::CleanupPending
                } else {
                    SelectedCaptureState::SessionRetired
                };
                SelectedCaptureOutcome {
                    disposition,
                    failsafe_activated: safe
                        .is_some_and(crate::core::CaptureOutcome::failsafe_activated),
                    state,
                }
            }
        }
    }

    /// Gates native capture after a hook/tap discontinuity and synchronously
    /// starts exact selected-session held-input cleanup.
    ///
    /// The gate is set before any fallible cleanup, so delayed callback work
    /// cannot resume remote suppression after native capture has failed.
    ///
    /// # Errors
    ///
    /// Returns a coarse reconciliation error while retaining the routing gate.
    pub fn native_capture_discontinued(&mut self, now_ns: u64) -> Result<(), PeerManagerError> {
        self.selected_capture_available = false;
        let workspace = self
            .workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let selected = workspace.selected_pointer_peer();
        let peer = self
            .peers
            .get_mut(&selected)
            .ok_or(PeerManagerError::InvalidIdentity)?;
        let result = peer
            .supervisor
            .native_capture_discontinued_with_workspace(workspace, now_ns);
        if result.is_err() && peer.supervisor.active_generation().is_none() {
            peer.task = PeerTaskSlot::Idle;
            schedule_retry(peer, Duration::from_nanos(now_ns));
        }
        result.map_err(Into::into)
    }

    /// Rearms the manager-side callback gate after a fresh native capture
    /// generation reports [`crate::CaptureLifecycleState::Running`].
    ///
    /// The runtime owns that health check. Existing core failsafe suspension
    /// and workspace readiness still apply after this coarse gate is opened.
    ///
    /// # Errors
    ///
    /// Rejects an unknown/non-running lifecycle or a manager in shutdown.
    pub fn rearm_native_capture(
        &mut self,
        lifecycle: CaptureLifecycleState,
    ) -> Result<(), PeerManagerError> {
        if self.shutting_down || lifecycle != CaptureLifecycleState::Running {
            return Err(PeerManagerError::PeerRejected);
        }
        self.selected_capture_available = true;
        Ok(())
    }

    /// Drives selected failsafe publication and pointer deadlines through the
    /// same serialized manager authority used by capture.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when a pointer expiry cannot be reconciled.
    pub fn selected_lifecycle_tick(&mut self, now_ns: u64) -> Result<bool, PeerManagerError> {
        let workspace = self
            .workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let selected = workspace.selected_pointer_peer();
        let peer = self
            .peers
            .get_mut(&selected)
            .ok_or(PeerManagerError::InvalidIdentity)?;
        let result = peer
            .supervisor
            .selected_lifecycle_tick_with_workspace(workspace, now_ns);
        if result.is_err() && peer.supervisor.active_generation().is_none() {
            peer.task = PeerTaskSlot::Idle;
            schedule_retry(peer, Duration::from_nanos(now_ns));
        }
        result.map_err(Into::into)
    }

    /// Returns the latest immutable authenticated device-inventory view.
    ///
    /// # Errors
    ///
    /// Returns an error until workspace control has been attached.
    pub fn device_inventory_snapshot(
        &self,
    ) -> Result<Arc<DeviceInventorySnapshot>, PeerManagerError> {
        self.workspace
            .as_ref()
            .map(|workspace| workspace.device_inventory().snapshot())
            .ok_or(PeerManagerError::WorkspaceRequired)
    }

    /// Transactionally replaces the complete local physical-device inventory.
    /// Devices removed or changed are gated and their exact remote holds are
    /// queued before the new revision is published or advertised.
    ///
    /// # Errors
    ///
    /// Rejects invalid, stale, conflicting, or excessive inventories and an
    /// unavailable selected-session reconciliation path.
    pub fn replace_local_device_inventory(
        &mut self,
        revision: u64,
        devices: Vec<InputDevice>,
        now_ns: u64,
    ) -> Result<DeviceInventoryUpdateOutcome, PeerManagerError> {
        if self.shutting_down {
            return Err(PeerManagerError::PeerRejected);
        }
        let workspace = self
            .workspace
            .as_ref()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let selected = workspace.selected_pointer_peer();
        if workspace.pointer_transition_pending()
            || self
                .peers
                .get(&selected)
                .is_some_and(|peer| peer.supervisor.route_policy_update_pending())
        {
            return Err(PeerManagerError::RoutePolicyBusy);
        }
        self.workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?
            .stage_local_device_snapshot(revision, devices)
            .map_err(|_| PeerManagerError::InvalidRoutePolicy)?;
        self.settle_local_device_inventory_update(now_ns)
    }

    /// Retries the exact retained local-device candidate and cleanup suffix.
    ///
    /// # Errors
    ///
    /// Returns an error when no candidate is staged or the selected session is
    /// stale. Queue backpressure remains an explicit `CleanupPending` outcome.
    pub fn retry_local_device_inventory_update(
        &mut self,
        now_ns: u64,
    ) -> Result<DeviceInventoryUpdateOutcome, PeerManagerError> {
        self.settle_local_device_inventory_update(now_ns)
    }

    /// Aborts the exact staged local-device candidate. Releases already queued
    /// remain ordered, while devices still present in the committed inventory
    /// are restored only after their cleanup barrier has drained.
    ///
    /// # Errors
    ///
    /// Returns an error when no candidate exists or safe device restoration is
    /// not currently possible.
    pub fn abort_local_device_inventory_update(
        &mut self,
        now_ns: u64,
    ) -> Result<DeviceInventoryUpdateOutcome, PeerManagerError> {
        let workspace = self
            .workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let pending = workspace
            .pending_local_device_update()
            .ok_or(PeerManagerError::RoutePolicyBusy)?;
        if pending.committed {
            return Err(PeerManagerError::RoutePolicyBusy);
        }
        let revision = pending.revision;
        let affected = pending.affected;
        let abort_restore = pending.abort_restore;
        let selected = workspace.selected_pointer_peer();
        let peer = self
            .peers
            .get_mut(&selected)
            .ok_or(PeerManagerError::PeerRejected)?;
        let generation = if peer.supervisor.active_generation().is_some() {
            Some(current_peer_generation(peer)?)
        } else {
            None
        };
        let gated = match generation {
            Some(generation) => peer
                .supervisor
                .gate_local_devices(generation, &affected, now_ns),
            None => peer
                .supervisor
                .gate_local_devices_offline(&affected, now_ns),
        };
        if gated.is_err() {
            return Ok(DeviceInventoryUpdateOutcome {
                state: DeviceInventoryUpdateState::CleanupPending,
                committed_revision: current_local_device_revision(workspace)?,
            });
        }
        for device in abort_restore {
            let restored = match generation {
                Some(generation) => peer
                    .supervisor
                    .restore_local_device(generation, device, now_ns),
                None => peer.supervisor.restore_local_device_offline(device, now_ns),
            };
            if restored.is_err() {
                return Ok(DeviceInventoryUpdateOutcome {
                    state: DeviceInventoryUpdateState::CleanupPending,
                    committed_revision: current_local_device_revision(workspace)?,
                });
            }
        }
        workspace
            .abort_local_device_snapshot(revision)
            .map_err(|_| PeerManagerError::RoutePolicyBusy)?;
        Ok(DeviceInventoryUpdateOutcome {
            state: DeviceInventoryUpdateState::Committed,
            committed_revision: current_local_device_revision(workspace)?,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn settle_local_device_inventory_update(
        &mut self,
        now_ns: u64,
    ) -> Result<DeviceInventoryUpdateOutcome, PeerManagerError> {
        let workspace = self
            .workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let pending = workspace
            .pending_local_device_update()
            .ok_or(PeerManagerError::RoutePolicyBusy)?;
        let revision = pending.revision;
        let affected = pending.affected;
        let restore = pending.restore;
        let committed = pending.committed;
        let selected_synced = pending.selected_synced;
        let selected = workspace.selected_pointer_peer();
        let selected_peer = self
            .peers
            .get_mut(&selected)
            .ok_or(PeerManagerError::PeerRejected)?;
        let selected_generation = if selected_peer.supervisor.active_generation().is_some() {
            Some(current_peer_generation(selected_peer)?)
        } else {
            None
        };
        if !committed {
            let gate_result = match selected_generation {
                Some(generation) => selected_peer
                    .supervisor
                    .gate_local_devices(generation, &affected, now_ns),
                None => selected_peer
                    .supervisor
                    .gate_local_devices_offline(&affected, now_ns),
            };
            if gate_result.is_err() {
                return Ok(DeviceInventoryUpdateOutcome {
                    state: DeviceInventoryUpdateState::CleanupPending,
                    committed_revision: current_local_device_revision(workspace)?,
                });
            }
        }

        let snapshot = workspace
            .commit_local_device_snapshot(revision)
            .map_err(|_| PeerManagerError::InvalidRoutePolicy)?;
        let mut failures = 0;
        if let Some(generation) = selected_generation {
            if !selected_synced {
                if selected_peer
                    .supervisor
                    .send_local_device_snapshot(generation, workspace, snapshot.clone(), now_ns)
                    .is_err()
                {
                    if selected_peer.supervisor.active_generation().is_none() {
                        selected_peer.task = PeerTaskSlot::Idle;
                        schedule_retry(selected_peer, Duration::from_nanos(now_ns));
                    }
                    return Ok(DeviceInventoryUpdateOutcome {
                        state: DeviceInventoryUpdateState::CleanupPending,
                        committed_revision: revision,
                    });
                }
                workspace
                    .mark_local_device_snapshot_selected_synced(revision)
                    .map_err(|_| PeerManagerError::RoutePolicyBusy)?;
            }
            for device in &restore {
                if selected_peer
                    .supervisor
                    .restore_local_device(generation, *device, now_ns)
                    .is_err()
                {
                    return Ok(DeviceInventoryUpdateOutcome {
                        state: DeviceInventoryUpdateState::CleanupPending,
                        committed_revision: revision,
                    });
                }
            }
        } else {
            for device in &restore {
                if selected_peer
                    .supervisor
                    .restore_local_device_offline(*device, now_ns)
                    .is_err()
                {
                    return Ok(DeviceInventoryUpdateOutcome {
                        state: DeviceInventoryUpdateState::CleanupPending,
                        committed_revision: revision,
                    });
                }
            }
        }
        workspace
            .complete_local_device_snapshot(revision)
            .map_err(|_| PeerManagerError::RoutePolicyBusy)?;
        for (peer_id, peer) in &mut self.peers {
            if *peer_id == selected || peer.supervisor.active_generation().is_none() {
                continue;
            }
            let Ok(generation) = current_peer_generation(peer) else {
                failures += 1;
                continue;
            };
            if peer
                .supervisor
                .send_local_device_snapshot(generation, workspace, snapshot.clone(), now_ns)
                .is_err()
            {
                failures += 1;
                if peer.supervisor.active_generation().is_none() {
                    peer.task = PeerTaskSlot::Idle;
                    schedule_retry(peer, Duration::from_nanos(now_ns));
                }
            }
        }
        if failures == 0 {
            Ok(DeviceInventoryUpdateOutcome {
                state: DeviceInventoryUpdateState::Committed,
                committed_revision: revision,
            })
        } else {
            Err(PeerManagerError::ReconciliationFailed { failures })
        }
    }

    /// Returns the committed selected-device routing policy revision.
    ///
    /// # Errors
    ///
    /// Requires the exact selected admitted generation and matching task slot.
    pub fn selected_device_route_revision(&self) -> Result<u64, PeerManagerError> {
        let workspace = self
            .workspace
            .as_ref()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        if workspace.local_device_update_pending() {
            return Err(PeerManagerError::RoutePolicyBusy);
        }
        let peer = self
            .peers
            .get(&workspace.selected_pointer_peer())
            .ok_or(PeerManagerError::PeerRejected)?;
        let generation = route_policy_authority(peer)?;
        peer.supervisor
            .route_policy_revision(generation)
            .map_err(map_route_coordinator_error)
    }

    /// Replaces the complete durable selected-device routing policy using an
    /// expected revision and the existing retryable release barrier.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions, unknown local devices, third-host targets,
    /// invalid candidates, unavailable sessions, and exhausted revision space.
    pub fn replace_selected_device_routes<S: ConfigStore>(
        &mut self,
        store: &S,
        expected_revision: u64,
        mut routes: Vec<DeviceRouteConfig>,
        now_ns: u64,
    ) -> Result<DeviceRouteUpdateOutcome, PeerManagerError> {
        if self.shutting_down {
            return Err(PeerManagerError::PeerRejected);
        }
        let workspace = self
            .workspace
            .as_ref()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let selected_peer = workspace.selected_pointer_peer();
        if workspace.local_device_update_pending() || workspace.pointer_transition_pending() {
            return Err(PeerManagerError::RoutePolicyBusy);
        }
        let local_host = workspace.initial_state().local_host;
        let peer = self
            .peers
            .get(&selected_peer)
            .ok_or(PeerManagerError::PeerRejected)?;
        let selected_host = peer.identity.host_id();
        let generation = route_policy_authority(peer)?;
        let current = peer
            .supervisor
            .route_policy_config(generation)
            .map_err(map_route_coordinator_error)?;
        let existing = current
            .device_routes
            .iter()
            .map(|route| (route.device_id, route.route))
            .collect::<BTreeMap<_, _>>();
        for route in &mut routes {
            if route.route
                == (ConfiguredDeviceRoute::Host {
                    host_id: local_host,
                })
            {
                route.route = ConfiguredDeviceRoute::Local;
            }
            if let ConfiguredDeviceRoute::Host { host_id } = route.route {
                if host_id != local_host && host_id != selected_host {
                    return Err(PeerManagerError::InvalidRoutePolicy);
                }
            }
            if existing.get(&route.device_id) != Some(&route.route)
                && !workspace
                    .device_inventory()
                    .contains_local_device(route.device_id)
            {
                return Err(PeerManagerError::UnknownLocalDevice);
            }
        }
        let mut candidate = current;
        candidate.device_routes = routes;

        let peer = self
            .peers
            .get_mut(&selected_peer)
            .ok_or(PeerManagerError::PeerRejected)?;
        require_route_store(peer, store)?;
        let status = match peer.supervisor.prepare_route_policy_update(
            generation,
            candidate,
            expected_revision,
            now_ns,
        ) {
            Ok(status) => status,
            Err(RoutePolicyCoordinatorError::Delivery) => {
                return Ok(DeviceRouteUpdateOutcome {
                    state: DeviceRouteUpdateState::CleanupPending,
                    committed_revision: expected_revision,
                });
            }
            Err(error) => return Err(map_route_coordinator_error(error)),
        };
        settle_route_policy_update(peer, generation, status, store, now_ns)
    }

    /// Sets one explicit route while retaining every other policy entry.
    ///
    /// # Errors
    ///
    /// Returns the same validation, revision, cleanup, and persistence errors
    /// as [`Self::replace_selected_device_routes`].
    pub fn set_selected_device_route<S: ConfigStore>(
        &mut self,
        store: &S,
        expected_revision: u64,
        device: DeviceId,
        route: DeviceRoute,
        now_ns: u64,
    ) -> Result<DeviceRouteUpdateOutcome, PeerManagerError> {
        let mut routes = self.selected_device_routes()?;
        let configured = ConfiguredDeviceRoute::from(route);
        if let Some(existing) = routes.iter_mut().find(|entry| entry.device_id == device) {
            existing.route = configured;
        } else {
            routes.push(DeviceRouteConfig {
                device_id: device,
                route: configured,
            });
        }
        self.replace_selected_device_routes(store, expected_revision, routes, now_ns)
    }

    /// Clears one explicit route, returning that device to `FollowActiveHost`.
    ///
    /// # Errors
    ///
    /// Returns the same validation, revision, cleanup, and persistence errors
    /// as [`Self::replace_selected_device_routes`].
    pub fn clear_selected_device_route<S: ConfigStore>(
        &mut self,
        store: &S,
        expected_revision: u64,
        device: DeviceId,
        now_ns: u64,
    ) -> Result<DeviceRouteUpdateOutcome, PeerManagerError> {
        let mut routes = self.selected_device_routes()?;
        routes.retain(|entry| entry.device_id != device);
        self.replace_selected_device_routes(store, expected_revision, routes, now_ns)
    }

    /// Retries the exact retained cleanup/persistence candidate without
    /// accepting replacement policy input.
    ///
    /// # Errors
    ///
    /// Returns an error when no exact candidate is retained, another
    /// administrative transaction is active, or its authority is stale.
    pub fn retry_selected_device_route_update<S: ConfigStore>(
        &mut self,
        store: &S,
        now_ns: u64,
    ) -> Result<DeviceRouteUpdateOutcome, PeerManagerError> {
        let workspace = self
            .workspace
            .as_ref()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        if workspace.local_device_update_pending() {
            return Err(PeerManagerError::RoutePolicyBusy);
        }
        let peer = self
            .peers
            .get_mut(&workspace.selected_pointer_peer())
            .ok_or(PeerManagerError::PeerRejected)?;
        require_route_store(peer, store)?;
        let generation = route_policy_authority(peer)?;
        let committed_revision = peer
            .supervisor
            .route_policy_revision(generation)
            .map_err(map_route_coordinator_error)?;
        let status = match peer
            .supervisor
            .retry_route_policy_update(generation, now_ns)
        {
            Ok(status) => status,
            Err(RoutePolicyCoordinatorError::Delivery) => {
                return Ok(DeviceRouteUpdateOutcome {
                    state: DeviceRouteUpdateState::CleanupPending,
                    committed_revision,
                });
            }
            Err(error) => return Err(map_route_coordinator_error(error)),
        };
        settle_route_policy_update(peer, generation, status, store, now_ns)
    }

    /// Aborts the exact retained route-policy candidate after draining its
    /// release barrier and durably restoring the committed configuration.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when no transaction exists, another
    /// administrative transaction is active, or the exact authority is stale.
    pub fn abort_selected_device_route_update<S: ConfigStore>(
        &mut self,
        store: &S,
        now_ns: u64,
    ) -> Result<DeviceRouteUpdateOutcome, PeerManagerError> {
        let workspace = self
            .workspace
            .as_ref()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        if workspace.local_device_update_pending() {
            return Err(PeerManagerError::RoutePolicyBusy);
        }
        let peer = self
            .peers
            .get_mut(&workspace.selected_pointer_peer())
            .ok_or(PeerManagerError::PeerRejected)?;
        require_route_store(peer, store)?;
        let authority = route_policy_authority(peer)?;
        let committed_revision = peer
            .supervisor
            .route_policy_revision(authority)
            .map_err(map_route_coordinator_error)?;
        let status = match peer.supervisor.retry_route_policy_update(authority, now_ns) {
            Ok(status) => status,
            Err(RoutePolicyCoordinatorError::Delivery) => {
                return Ok(DeviceRouteUpdateOutcome {
                    state: DeviceRouteUpdateState::CleanupPending,
                    committed_revision,
                });
            }
            Err(error) => return Err(map_route_coordinator_error(error)),
        };
        if status == RoutePolicyUpdateStatus::CleanupPending {
            return Ok(DeviceRouteUpdateOutcome {
                state: DeviceRouteUpdateState::CleanupPending,
                committed_revision,
            });
        }
        let (candidate_revision, _) = peer
            .supervisor
            .staged_route_policy(authority)
            .map_err(map_route_coordinator_error)?
            .ok_or(PeerManagerError::RoutePolicyBusy)?;
        let committed = peer
            .supervisor
            .route_policy_config(authority)
            .map_err(map_route_coordinator_error)?;
        if store.save(&committed).is_err() {
            return Ok(DeviceRouteUpdateOutcome {
                state: DeviceRouteUpdateState::PersistencePending,
                committed_revision,
            });
        }
        peer.supervisor
            .abort_route_policy_update(authority, candidate_revision, now_ns)
            .map_err(|error| {
                map_route_coordinator_error(RoutePolicyCoordinatorError::Policy(error))
            })?;
        Ok(DeviceRouteUpdateOutcome {
            state: DeviceRouteUpdateState::Committed,
            committed_revision,
        })
    }

    fn selected_device_routes(&self) -> Result<Vec<DeviceRouteConfig>, PeerManagerError> {
        let workspace = self
            .workspace
            .as_ref()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let peer = self
            .peers
            .get(&workspace.selected_pointer_peer())
            .ok_or(PeerManagerError::PeerRejected)?;
        let generation = route_policy_authority(peer)?;
        peer.supervisor
            .route_policy_config(generation)
            .map(|config| config.device_routes)
            .map_err(map_route_coordinator_error)
    }

    fn selected_admin_transaction_pending(&self) -> Result<bool, PeerManagerError> {
        let workspace = self
            .workspace
            .as_ref()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let peer = self
            .peers
            .get(&workspace.selected_pointer_peer())
            .ok_or(PeerManagerError::PeerRejected)?;
        Ok(
            workspace.local_device_update_pending()
                || peer.supervisor.route_policy_update_pending(),
        )
    }

    /// Initiates a pointer handoff only through the immutable selected peer.
    /// Any effect or protocol failure retires that exact session.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when no workspace/current selected session is
    /// available or when bounded dispatch/reconciliation fails.
    pub fn propose_pointer_handoff(
        &mut self,
        edge: Edge,
        normalized_position: f64,
        now_ns: u64,
    ) -> Result<(), PeerManagerError> {
        if self.selected_admin_transaction_pending()? {
            return Err(PeerManagerError::RoutePolicyBusy);
        }
        let workspace = self
            .workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let selected = workspace.selected_pointer_peer();
        let peer = self
            .peers
            .get_mut(&selected)
            .ok_or(PeerManagerError::InvalidIdentity)?;
        let result = peer.supervisor.propose_pointer_handoff_with_workspace(
            workspace,
            edge,
            normalized_position,
            now_ns,
        );
        if result.is_err() && peer.supervisor.active_generation().is_none() {
            peer.task = PeerTaskSlot::Idle;
            schedule_retry(peer, Duration::from_nanos(now_ns));
        }
        result.map_err(Into::into)
    }

    /// Polls the bounded selected-peer handoff deadline. Any expiry retires
    /// the exact session so both hosts converge through normal cleanup.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when no workspace/current selected session is
    /// available or an expiry cannot be reconciled safely.
    pub fn poll_pointer_handoff_timeout(&mut self, now_ns: u64) -> Result<(), PeerManagerError> {
        let workspace = self
            .workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let selected = workspace.selected_pointer_peer();
        let peer = self
            .peers
            .get_mut(&selected)
            .ok_or(PeerManagerError::InvalidIdentity)?;
        let result = peer
            .supervisor
            .poll_pointer_timeout_with_workspace(workspace, now_ns);
        if result.is_err() && peer.supervisor.active_generation().is_none() {
            peer.task = PeerTaskSlot::Idle;
            schedule_retry(peer, Duration::from_nanos(now_ns));
        }
        result.map_err(Into::into)
    }

    /// Transactionally replaces the bounded runtime workspace layout.
    /// Any in-flight pointer transition is cancelled before compilation. A
    /// rejected candidate restores the prior authoritative layout; failure to
    /// restore retires the exact selected session.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when the candidate is invalid, the selected
    /// session is unavailable, or safe restoration/reconciliation fails.
    pub fn replace_workspace_topology(
        &mut self,
        placements: Vec<WorkspacePlacement>,
        links: Vec<WorkspaceLink>,
        now_ns: u64,
    ) -> Result<(), PeerManagerError> {
        if self.selected_admin_transaction_pending()? {
            return Err(PeerManagerError::RoutePolicyBusy);
        }
        let workspace = self
            .workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let selected = workspace.selected_pointer_peer();
        let peer = self
            .peers
            .get_mut(&selected)
            .ok_or(PeerManagerError::InvalidIdentity)?;
        let result = peer
            .supervisor
            .replace_workspace_topology(workspace, placements, links, now_ns);
        if result.is_err() && peer.supervisor.active_generation().is_none() {
            peer.task = PeerTaskSlot::Idle;
            schedule_retry(peer, Duration::from_nanos(now_ns));
        }
        result.map_err(Into::into)
    }

    /// Applies a local inventory revision, atomically recompiles selected
    /// topology, and broadcasts the resulting full snapshot best-effort to
    /// every other active peer.
    ///
    /// # Errors
    ///
    /// Returns a coarse error for invalid revisions, topology failure, or one
    /// or more active sessions that cannot accept/reconcile the new snapshot.
    pub fn apply_local_display_snapshot(
        &mut self,
        revision: u64,
        displays: Vec<Display>,
        now_ns: u64,
    ) -> Result<(), PeerManagerError> {
        if self.selected_admin_transaction_pending()? {
            return Err(PeerManagerError::RoutePolicyBusy);
        }
        let workspace = self
            .workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let selected = workspace.selected_pointer_peer();
        let selected_peer = self
            .peers
            .get_mut(&selected)
            .ok_or(PeerManagerError::InvalidIdentity)?;
        let selected_active = selected_peer.supervisor.active_generation().is_some();
        if selected_active {
            let prepare = selected_peer
                .supervisor
                .prepare_local_inventory_change(workspace, now_ns);
            if let Err(error) = prepare {
                if selected_peer.supervisor.active_generation().is_none() {
                    selected_peer.task = PeerTaskSlot::Idle;
                    schedule_retry(selected_peer, Duration::from_nanos(now_ns));
                }
                return Err(error.into());
            }
        }
        if workspace
            .apply_local_snapshot_offline(revision, displays)
            .is_err()
        {
            if selected_active {
                if let Err(error) = selected_peer
                    .supervisor
                    .refresh_selected_workspace(workspace, now_ns)
                {
                    if selected_peer.supervisor.active_generation().is_none() {
                        selected_peer.task = PeerTaskSlot::Idle;
                        schedule_retry(selected_peer, Duration::from_nanos(now_ns));
                    }
                    return Err(error.into());
                }
            }
            return Err(PeerManagerError::PeerRejected);
        }
        let mut failures = 0;
        if selected_active
            && selected_peer
                .supervisor
                .refresh_selected_workspace(workspace, now_ns)
                .is_err()
        {
            failures += 1;
            if selected_peer.supervisor.active_generation().is_none() {
                selected_peer.task = PeerTaskSlot::Idle;
                schedule_retry(selected_peer, Duration::from_nanos(now_ns));
            }
        }
        let snapshot = workspace
            .local_snapshot_message()
            .map_err(|_| PeerManagerError::PeerRejected)?;
        for (peer_id, peer) in &mut self.peers {
            if *peer_id == selected || peer.supervisor.active_generation().is_none() {
                continue;
            }
            if peer
                .supervisor
                .send_local_snapshot(workspace, snapshot.clone(), now_ns)
                .is_err()
            {
                failures += 1;
                if peer.supervisor.active_generation().is_none() {
                    peer.task = PeerTaskSlot::Idle;
                    schedule_retry(peer, Duration::from_nanos(now_ns));
                }
            }
        }
        if failures == 0 {
            Ok(())
        } else {
            Err(PeerManagerError::ReconciliationFailed { failures })
        }
    }

    /// Applies the exact next local display update and broadcasts a fresh
    /// full snapshot so remote peers never depend on a lost delta.
    ///
    /// # Errors
    ///
    /// Returns a coarse error for an invalid revision/update, topology failure,
    /// or one or more sessions that cannot accept/reconcile the new snapshot.
    pub fn apply_local_display_update(
        &mut self,
        revision: u64,
        display: Display,
        now_ns: u64,
    ) -> Result<(), PeerManagerError> {
        if self.selected_admin_transaction_pending()? {
            return Err(PeerManagerError::RoutePolicyBusy);
        }
        let workspace = self
            .workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let selected = workspace.selected_pointer_peer();
        let selected_peer = self
            .peers
            .get_mut(&selected)
            .ok_or(PeerManagerError::InvalidIdentity)?;
        let selected_active = selected_peer.supervisor.active_generation().is_some();
        if selected_active {
            let prepare = selected_peer
                .supervisor
                .prepare_local_inventory_change(workspace, now_ns);
            if let Err(error) = prepare {
                if selected_peer.supervisor.active_generation().is_none() {
                    selected_peer.task = PeerTaskSlot::Idle;
                    schedule_retry(selected_peer, Duration::from_nanos(now_ns));
                }
                return Err(error.into());
            }
        }
        if workspace
            .apply_local_update_offline(revision, display)
            .is_err()
        {
            if selected_active {
                if let Err(error) = selected_peer
                    .supervisor
                    .refresh_selected_workspace(workspace, now_ns)
                {
                    if selected_peer.supervisor.active_generation().is_none() {
                        selected_peer.task = PeerTaskSlot::Idle;
                        schedule_retry(selected_peer, Duration::from_nanos(now_ns));
                    }
                    return Err(error.into());
                }
            }
            return Err(PeerManagerError::PeerRejected);
        }
        let mut failures = 0;
        if selected_active
            && selected_peer
                .supervisor
                .refresh_selected_workspace(workspace, now_ns)
                .is_err()
        {
            failures += 1;
            if selected_peer.supervisor.active_generation().is_none() {
                selected_peer.task = PeerTaskSlot::Idle;
                schedule_retry(selected_peer, Duration::from_nanos(now_ns));
            }
        }
        let snapshot = workspace
            .local_snapshot_message()
            .map_err(|_| PeerManagerError::PeerRejected)?;
        for (peer_id, peer) in &mut self.peers {
            if *peer_id == selected || peer.supervisor.active_generation().is_none() {
                continue;
            }
            if peer
                .supervisor
                .send_local_snapshot(workspace, snapshot.clone(), now_ns)
                .is_err()
            {
                failures += 1;
                if peer.supervisor.active_generation().is_none() {
                    peer.task = PeerTaskSlot::Idle;
                    schedule_retry(peer, Duration::from_nanos(now_ns));
                }
            }
        }
        if failures == 0 {
            Ok(())
        } else {
            Err(PeerManagerError::ReconciliationFailed { failures })
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> PeerManagerSnapshot {
        PeerManagerSnapshot {
            paired_peers: self.peers.len(),
            peers_with_candidates: self
                .peers
                .values()
                .filter(|peer| !peer.candidates.is_empty())
                .count(),
            connecting_tasks: self
                .peers
                .values()
                .filter(|peer| matches!(peer.task, PeerTaskSlot::Connecting { .. }))
                .count(),
            session_tasks: self
                .peers
                .values()
                .filter(|peer| matches!(peer.task, PeerTaskSlot::Session { .. }))
                .count(),
            revoked_peers: self.peers.values().filter(|peer| peer.revoked).count(),
        }
    }

    /// Replaces untrusted reachability hints from the bounded discovery model
    /// without affecting any live task.
    ///
    /// Unknown hints are ignored. Invalid or excessive candidates fail closed
    /// without partially replacing the previous snapshot.
    ///
    /// # Errors
    ///
    /// Rejects invalid LAN addresses or a per-peer candidate overflow.
    pub fn apply_discovery_snapshot(
        &mut self,
        snapshot: &DiscoverySnapshot,
    ) -> Result<(), PeerManagerError> {
        self.replace_candidates(
            snapshot
                .iter()
                .map(|candidate| (candidate.peer_id_hint(), candidate.address())),
        )
    }

    /// Replaces the sole selected dialer's reachability hint with one
    /// operator-provided, already validated LAN address.
    ///
    /// The address remains an untrusted routing hint: the resulting task still
    /// requires the existing sealed transport and exact identity admission.
    /// Replacement is permitted only while the immutable selected peer has no
    /// connecting, pending, or active session task.
    ///
    /// # Errors
    ///
    /// Rejects a missing workspace, a non-selected or unavailable peer, a
    /// listener role, shutdown, or an occupied exact peer task.
    pub fn replace_selected_outbound_candidate(
        &mut self,
        peer_id: PeerId,
        address: LanPeerAddress,
    ) -> Result<(), PeerManagerError> {
        let selected = self
            .workspace
            .as_ref()
            .ok_or(PeerManagerError::WorkspaceRequired)?
            .selected_pointer_peer();
        if self.shutting_down || peer_id != selected {
            return Err(PeerManagerError::PeerRejected);
        }
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerManagerError::PeerRejected)?;
        if peer.revoked
            || peer.supervisor.role() != ConnectionRole::Dialer
            || peer.task != PeerTaskSlot::Idle
            || peer.supervisor.active_generation().is_some()
        {
            return Err(PeerManagerError::PeerRejected);
        }

        peer.candidates = BTreeSet::from([address]);
        peer.candidate_cursor = 0;
        Ok(())
    }

    fn replace_candidates(
        &mut self,
        candidates: impl IntoIterator<Item = (PeerId, SocketAddr)>,
    ) -> Result<(), PeerManagerError> {
        let mut replacement: BTreeMap<PeerId, BTreeSet<LanPeerAddress>> = BTreeMap::new();
        for (peer_id, address) in candidates {
            let Some(peer) = self.peers.get(&peer_id) else {
                continue;
            };
            if peer.revoked {
                continue;
            }
            let address =
                LanPeerAddress::new(address).map_err(|_| PeerManagerError::InvalidCandidate)?;
            let values = replacement.entry(peer_id).or_default();
            values.insert(address);
            if values.len() > self.config.maximum_candidates_per_peer {
                return Err(PeerManagerError::CapacityExceeded);
            }
        }
        for (peer_id, peer) in &mut self.peers {
            peer.candidates = replacement.remove(peer_id).unwrap_or_default();
            if peer.candidates.is_empty() {
                peer.candidate_cursor = 0;
            } else {
                peer.candidate_cursor %= peer.candidates.len();
            }
        }
        Ok(())
    }

    /// Allocates the next canonical outbound connection task, if ready.
    ///
    /// Iteration and address selection are deterministic.
    ///
    /// # Errors
    ///
    /// Returns an error if bounded task identifier allocation is exhausted.
    pub fn poll_outbound(
        &mut self,
        now: Duration,
    ) -> Result<Option<OutboundDialTask>, PeerManagerError> {
        if self.workspace.is_none() {
            return Err(PeerManagerError::WorkspaceRequired);
        }
        if self.shutting_down {
            return Ok(None);
        }
        for (peer_id, peer) in &mut self.peers {
            if peer.revoked
                || peer.supervisor.role() != ConnectionRole::Dialer
                || peer.task != PeerTaskSlot::Idle
                || peer.candidates.is_empty()
                || now < peer.retry_not_before
            {
                continue;
            }
            let address = *peer
                .candidates
                .iter()
                .nth(peer.candidate_cursor)
                .ok_or(PeerManagerError::InvalidCandidate)?;
            let task_id = self.next_task_id;
            self.next_task_id = self
                .next_task_id
                .checked_add(1)
                .ok_or(PeerManagerError::IdentifierSpaceExhausted)?;
            peer.task = PeerTaskSlot::Connecting { task_id };
            return Ok(Some(OutboundDialTask {
                manager_id: self.manager_id,
                task_id,
                peer_id: *peer_id,
                address,
                expected_identity: transport_identity(&peer.identity),
            }));
        }
        Ok(None)
    }

    /// Returns a failed connect task to the scheduler and advances bounded
    /// candidate/backoff state.
    ///
    /// # Errors
    ///
    /// Rejects stale tasks or tasks created by another manager.
    #[allow(clippy::needless_pass_by_value)]
    pub fn outbound_failed(
        &mut self,
        task: OutboundDialTask,
        now: Duration,
    ) -> Result<(), PeerManagerError> {
        let peer = self.validate_connecting_task(&task)?;
        schedule_connect_failure(peer, now);
        Ok(())
    }

    /// Recovers a connect slot after its worker panics, is aborted, or drops
    /// without returning a transport result. Keep the non-clone task token
    /// outside the spawned worker and call this method after observing loss.
    ///
    /// # Errors
    ///
    /// Rejects stale task tokens or tokens issued by another manager without
    /// consuming them, so their owning manager can still recover exactly.
    pub fn outbound_task_lost(
        &mut self,
        task: &OutboundDialTask,
        now: Duration,
    ) -> Result<(), PeerManagerError> {
        let peer = self.validate_connecting_task(task)?;
        schedule_connect_failure(peer, now);
        Ok(())
    }

    /// Converts a completed outbound TLS stream into the sole pending session.
    ///
    /// # Errors
    ///
    /// Rejects stale tasks, unavailable peers, wrong direction, or any sealed
    /// identity mismatch.
    #[allow(clippy::needless_pass_by_value)]
    pub fn outbound_connected<S: SecurePeerStream>(
        &mut self,
        task: OutboundDialTask,
        stream: S,
        now: Duration,
    ) -> Result<SealedPeerSessionStart<S>, PeerManagerError> {
        if self.workspace.is_none() {
            return Err(PeerManagerError::WorkspaceRequired);
        }
        if self.shutting_down {
            return Err(PeerManagerError::PeerRejected);
        }
        let peer = self.validate_connecting_task(&task)?;
        if peer.revoked {
            return Err(PeerManagerError::PeerRejected);
        }
        if validate_stream(peer, &stream, ConnectionDirection::Outbound).is_err() {
            schedule_connect_failure(peer, now);
            return Err(PeerManagerError::PeerRejected);
        }
        let pending = match peer.supervisor.begin_pending(ConnectionDirection::Outbound) {
            Ok(pending) => pending,
            Err(error) => {
                schedule_connect_failure(peer, now);
                return Err(error.into());
            }
        };
        let generation = pending.generation();
        peer.task = PeerTaskSlot::Session { generation };
        Ok(SealedPeerSessionStart {
            manager_id: self.manager_id,
            peer_id: task.peer_id,
            stream,
            pending,
        })
    }

    /// Matches an accepted sealed stream only by its authenticated identity.
    ///
    /// # Errors
    ///
    /// Rejects unknown, revoked, duplicate, wrong-direction, or noncanonical
    /// authenticated peers.
    pub fn inbound_accepted<S: SecurePeerStream>(
        &mut self,
        stream: S,
    ) -> Result<SealedPeerSessionStart<S>, PeerManagerError> {
        if self.workspace.is_none() {
            return Err(PeerManagerError::WorkspaceRequired);
        }
        let authenticated = stream.authenticated_peer_identity();
        let peer_id = PeerId::from_bytes(authenticated.peer_id.0);
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerManagerError::PeerRejected)?;
        if self.shutting_down
            || peer.revoked
            || peer.supervisor.role() != ConnectionRole::Listener
            || peer.task != PeerTaskSlot::Idle
        {
            return Err(PeerManagerError::PeerRejected);
        }
        validate_stream(peer, &stream, ConnectionDirection::Inbound)?;
        let pending = peer
            .supervisor
            .begin_pending(ConnectionDirection::Inbound)?;
        let generation = pending.generation();
        peer.task = PeerTaskSlot::Session { generation };
        Ok(SealedPeerSessionStart {
            manager_id: self.manager_id,
            peer_id,
            stream,
            pending,
        })
    }

    /// Cancels an established stream before its generation-bound task is
    /// constructed and releases the exact pending capability.
    ///
    /// # Errors
    ///
    /// Rejects a stale start or propagates exact pending cancellation failure.
    pub fn cancel_established<S>(
        &mut self,
        start: SealedPeerSessionStart<S>,
        now: Duration,
    ) -> Result<(), PeerManagerError> {
        let SealedPeerSessionStart {
            manager_id: _,
            peer_id,
            stream: _,
            pending,
        } = start;
        let generation = pending.generation();
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerManagerError::StaleTask)?;
        if peer.task != (PeerTaskSlot::Session { generation }) {
            return Err(PeerManagerError::StaleTask);
        }
        peer.supervisor.cancel_pending(pending)?;
        peer.task = PeerTaskSlot::Idle;
        if !peer.revoked {
            let delay = peer.backoff.next_delay();
            peer.retry_not_before = now.checked_add(delay).unwrap_or(Duration::MAX);
        }
        Ok(())
    }

    /// Applies one opaque event from the peer's generation-bound session.
    ///
    /// # Errors
    ///
    /// Returns a redacted supervisor or coordinator failure.
    pub fn handle_bound_event(
        &mut self,
        peer_id: PeerId,
        event: GenerationBoundPeerEvent,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerManagerError> {
        let workspace = self
            .workspace
            .as_mut()
            .ok_or(PeerManagerError::WorkspaceRequired)?;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerManagerError::PeerRejected)?;
        let generation = event.generation();
        let classification = event.classification();
        if !matches!(peer.task, PeerTaskSlot::Session { generation: current } if current == generation)
        {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        let result = peer
            .supervisor
            .handle_bound_event_with_workspace(event, workspace, now_ns);
        settle_bound_event_result(peer, classification, result, now_ns)
    }

    /// Reconciles a task whose event channel disappeared without a terminal.
    ///
    /// # Errors
    ///
    /// Returns a redacted reconciliation failure; failed cleanup stays active.
    pub fn connection_lost(
        &mut self,
        peer_id: PeerId,
        generation: ConnectionGeneration,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerManagerError> {
        let workspace = self.workspace.as_mut();
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerManagerError::PeerRejected)?;
        let result = if let Some(workspace) = workspace {
            peer.supervisor
                .connection_lost_with_workspace(generation, workspace, now_ns)
        } else {
            peer.supervisor.connection_lost(generation, now_ns)
        };
        settle_connection_lost_result(peer, result, now_ns)
    }

    /// Recovers an exact pending or active task lost to panic, abort, or
    /// channel closure. Pending loss cannot authorize a session; active loss
    /// reconciles input before the slot becomes reusable.
    ///
    /// # Errors
    ///
    /// Returns a redacted active-session reconciliation failure.
    pub fn connection_task_lost(
        &mut self,
        peer_id: PeerId,
        generation: ConnectionGeneration,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerManagerError> {
        let workspace = self.workspace.as_mut();
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerManagerError::PeerRejected)?;
        if !matches!(peer.task, PeerTaskSlot::Session { generation: current } if current == generation)
        {
            return Ok(SupervisorEventOutcome::StaleIgnored);
        }
        let result = if let Some(workspace) = workspace {
            peer.supervisor
                .connection_task_lost_with_workspace(generation, workspace, now_ns)
        } else {
            peer.supervisor.connection_task_lost(generation, now_ns)
        };
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                if peer.supervisor.active_generation().is_none() {
                    peer.task = PeerTaskSlot::Idle;
                    if !peer.revoked {
                        schedule_retry(peer, Duration::from_nanos(now_ns));
                    }
                }
                return Err(error.into());
            }
        };
        if matches!(
            outcome,
            SupervisorEventOutcome::PendingCancelled | SupervisorEventOutcome::Retired(_)
        ) {
            peer.task = PeerTaskSlot::Idle;
            if !peer.revoked {
                let delay = peer.backoff.next_delay();
                peer.retry_not_before = Duration::from_nanos(now_ns)
                    .checked_add(delay)
                    .unwrap_or(Duration::MAX);
            }
        }
        Ok(outcome)
    }

    /// Retries a previously failed active-session cleanup. The occupied slot
    /// remains blocked until reconciliation succeeds.
    ///
    /// # Errors
    ///
    /// Returns a redacted reconciliation failure and keeps the slot occupied.
    pub fn retry_reconciliation(
        &mut self,
        peer_id: PeerId,
        now_ns: u64,
    ) -> Result<SupervisorEventOutcome, PeerManagerError> {
        let workspace = self.workspace.as_mut();
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerManagerError::PeerRejected)?;
        let result = if let Some(workspace) = workspace {
            peer.supervisor
                .retry_reconciliation_with_workspace(workspace, now_ns)
        } else {
            peer.supervisor.retry_reconciliation(now_ns)
        };
        settle_reconciliation_retry_result(peer, result, now_ns)
    }

    /// Revokes a peer and reconciles any active generation. Discovery removal
    /// never calls this method.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown peer or incomplete reconciliation.
    pub fn revoke(&mut self, peer_id: PeerId, now_ns: u64) -> Result<(), PeerManagerError> {
        let workspace = self.workspace.as_mut();
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerManagerError::PeerRejected)?;
        peer.revoked = true;
        peer.candidates.clear();
        if matches!(peer.task, PeerTaskSlot::Connecting { .. }) {
            peer.task = PeerTaskSlot::Idle;
        }
        if let PeerTaskSlot::Session { generation } = peer.task {
            if peer.supervisor.active_generation().is_none() {
                let outcome = peer.supervisor.connection_task_lost(generation, now_ns)?;
                if outcome == SupervisorEventOutcome::PendingCancelled {
                    peer.task = PeerTaskSlot::Idle;
                }
            }
        }
        let result = if let Some(workspace) = workspace {
            peer.supervisor.revoke_with_workspace(workspace, now_ns)
        } else {
            peer.supervisor.revoke(now_ns)
        };
        if peer.supervisor.active_generation().is_none() {
            peer.task = PeerTaskSlot::Idle;
        }
        result?;
        Ok(())
    }

    /// Reconciles every peer and permanently prevents new work.
    ///
    /// # Errors
    ///
    /// Reports only the count of peers whose cleanup failed.
    pub fn shutdown(&mut self, now_ns: u64) -> Result<(), PeerManagerError> {
        self.shutting_down = true;
        let mut failures = 0_usize;
        for peer in self.peers.values_mut() {
            peer.revoked = true;
            peer.candidates.clear();
            if matches!(peer.task, PeerTaskSlot::Connecting { .. }) {
                peer.task = PeerTaskSlot::Idle;
            }
            if let PeerTaskSlot::Session { generation } = peer.task {
                if peer.supervisor.active_generation().is_none() {
                    match peer.supervisor.connection_task_lost(generation, now_ns) {
                        Ok(SupervisorEventOutcome::PendingCancelled) => {
                            peer.task = PeerTaskSlot::Idle;
                        }
                        Ok(_) => {}
                        Err(_) => {
                            failures += 1;
                            continue;
                        }
                    }
                }
            }
            let result = if let Some(workspace) = self.workspace.as_mut() {
                peer.supervisor.shutdown_with_workspace(workspace, now_ns)
            } else {
                peer.supervisor.shutdown(now_ns)
            };
            if peer.supervisor.active_generation().is_none() {
                peer.task = PeerTaskSlot::Idle;
            }
            if result.is_err() {
                failures += 1;
            }
        }
        if let Some(workspace) = self.workspace.as_mut() {
            workspace.shutdown();
        }
        if failures == 0 {
            Ok(())
        } else {
            Err(PeerManagerError::ReconciliationFailed { failures })
        }
    }

    fn validate_connecting_task(
        &mut self,
        task: &OutboundDialTask,
    ) -> Result<&mut ManagedPeerState<I, O>, PeerManagerError> {
        if task.manager_id != self.manager_id {
            return Err(PeerManagerError::StaleTask);
        }
        let peer = self
            .peers
            .get_mut(&task.peer_id)
            .ok_or(PeerManagerError::StaleTask)?;
        if peer.task
            != (PeerTaskSlot::Connecting {
                task_id: task.task_id,
            })
        {
            return Err(PeerManagerError::StaleTask);
        }
        Ok(peer)
    }
}

/// One bounded outbound connect operation. Address and discovery never imply
/// trust; `expected_identity` must still be proven by the sealed connector.
#[must_use = "retain this token until connection completion or task-loss recovery"]
pub struct OutboundDialTask {
    manager_id: u64,
    task_id: u64,
    peer_id: PeerId,
    address: LanPeerAddress,
    expected_identity: TransportPeerIdentity,
}

impl OutboundDialTask {
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    #[must_use]
    pub const fn address(&self) -> LanPeerAddress {
        self.address
    }

    #[must_use]
    pub const fn expected_identity(&self) -> &TransportPeerIdentity {
        &self.expected_identity
    }
}

impl fmt::Debug for OutboundDialTask {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundDialTask")
            .field("peer_id", &"[REDACTED]")
            .field("task_id", &"[REDACTED]")
            .field("address", &"[UNTRUSTED LAN HINT]")
            .field("expected_identity", &"[SEALED IDENTITY]")
            .finish_non_exhaustive()
    }
}

/// Sealed stream plus the sole affine pending generation for that peer.
#[must_use = "cancel or build this pending session, or report its generation as task-lost"]
pub struct SealedPeerSessionStart<S> {
    manager_id: u64,
    peer_id: PeerId,
    stream: S,
    pending: kvm_network::PendingConnection,
}

impl<S> fmt::Debug for SealedPeerSessionStart<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedPeerSessionStart")
            .field("peer_id", &"[REDACTED]")
            .field("generation", &"[REDACTED]")
            .field("stream", &"[SEALED]")
            .finish_non_exhaustive()
    }
}

impl<S> SealedPeerSessionStart<S> {
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.pending.generation()
    }

    /// Builds the only generation-bound task and separates its bounded
    /// channels for the daemon event pump.
    ///
    /// # Errors
    ///
    /// Returns a network-minted cancellation event if resource or timing
    /// bounds are invalid.
    pub fn build<A: SessionAdmission>(
        self,
        admission: A,
        config: PersistentPeerConfig,
    ) -> Result<PreparedPeerSessionParts<S, A>, ManagedSessionBuildError> {
        let generation = self.pending.generation();
        let manager_id = self.manager_id;
        let (session, sender, events) =
            GenerationBoundPeerSession::new(admission, config, self.pending).map_err(|error| {
                ManagedSessionBuildError {
                    peer_id: self.peer_id,
                    generation,
                    error,
                }
            })?;
        Ok(PreparedPeerSessionParts {
            runner: PreparedPeerSession {
                manager_id,
                peer_id: self.peer_id,
                generation,
                stream: self.stream,
                session,
            },
            _sender: sender,
            events,
        })
    }
}

#[must_use = "run or cancel this session, or report its generation as task-lost"]
pub struct PreparedPeerSession<S, A> {
    manager_id: u64,
    peer_id: PeerId,
    generation: ConnectionGeneration,
    stream: S,
    session: GenerationBoundPeerSession<A>,
}

impl<S, A> fmt::Debug for PreparedPeerSession<S, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPeerSession")
            .field("peer_id", &"[REDACTED]")
            .field("generation", &"[REDACTED]")
            .field("stream", &"[SEALED]")
            .field("session", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<S, A> PreparedPeerSession<S, A> {
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.generation
    }
}

/// Independently owned session runner and bounded composition channels.
#[must_use = "spawn the runner and drain events, or recover its generation as task-lost"]
pub struct PreparedPeerSessionParts<S, A> {
    runner: PreparedPeerSession<S, A>,
    // Retain the bounded command channel without exposing an independent
    // cloneable routing authority outside the manager composition boundary.
    _sender: PeerSender,
    events: mpsc::Receiver<GenerationBoundPeerEvent>,
}

impl<S, A> PreparedPeerSessionParts<S, A> {
    /// Identifies which paired peer owns these still-uninstalled resources.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.runner.peer_id
    }

    /// Identifies the exact generation to report if installation is abandoned.
    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.runner.generation
    }
}

/// Prepared runner and event channel after its private outbound sender has
/// been installed into the exact manager generation.
#[must_use = "spawn the runner and drain events, or recover its generation as task-lost"]
pub struct InstalledPeerSessionParts<S, A> {
    pub runner: PreparedPeerSession<S, A>,
    pub events: mpsc::Receiver<GenerationBoundPeerEvent>,
}

impl<S, A> fmt::Debug for InstalledPeerSessionParts<S, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstalledPeerSessionParts")
            .field("runner", &self.runner)
            .field("events", &"[BOUNDED CHANNEL]")
            .finish_non_exhaustive()
    }
}

impl<S, A> fmt::Debug for PreparedPeerSessionParts<S, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPeerSessionParts")
            .field("runner", &self.runner)
            .field("sender", &"[BOUNDED CHANNEL]")
            .field("events", &"[BOUNDED CHANNEL]")
            .finish_non_exhaustive()
    }
}

impl<I> PeerManager<I, ManagedSessionOutbound>
where
    I: OutputInjectionBackend,
{
    /// Privately installs a network-minted sender into the exact manager and
    /// generation before returning the independently runnable task and event
    /// channel. A rejected install returns every affine resource unchanged.
    ///
    /// # Errors
    ///
    /// Returns the boxed prepared resources unchanged when their manager,
    /// peer, generation, or lifecycle no longer owns the pending task.
    pub fn install_prepared_session<S, A>(
        &mut self,
        prepared: PreparedPeerSessionParts<S, A>,
    ) -> Result<InstalledPeerSessionParts<S, A>, Box<PreparedPeerSessionParts<S, A>>> {
        let peer_id = prepared.runner.peer_id;
        let generation = prepared.runner.generation;
        if prepared.runner.manager_id != self.manager_id {
            return Err(Box::new(prepared));
        }
        let Some(peer) = self.peers.get_mut(&peer_id) else {
            return Err(Box::new(prepared));
        };
        if self.shutting_down
            || peer.revoked
            || peer.task != (PeerTaskSlot::Session { generation })
            || peer.supervisor.active_generation().is_some()
        {
            return Err(Box::new(prepared));
        }

        let PreparedPeerSessionParts {
            runner,
            _sender: sender,
            events,
        } = prepared;
        match peer.supervisor.install_session_outbound(generation, sender) {
            Ok(()) => Ok(InstalledPeerSessionParts { runner, events }),
            Err(sender) => Err(Box::new(PreparedPeerSessionParts {
                runner,
                _sender: sender,
                events,
            })),
        }
    }
}

impl<S: SecurePeerStream, A: SessionAdmission> PreparedPeerSession<S, A> {
    /// Runs this one-shot sealed session until shutdown or terminal failure.
    ///
    /// # Errors
    ///
    /// Preserves an unsent exact terminal event when bounded delivery fails.
    pub async fn run(
        self,
        shutdown: watch::Receiver<bool>,
    ) -> Result<ManagedSessionEnd, ManagedSessionError> {
        let peer_id = self.peer_id;
        let generation = self.generation;
        self.session
            .run(self.stream, shutdown)
            .await
            .map(|end| ManagedSessionEnd {
                peer_id,
                generation,
                end,
            })
            .map_err(|error| ManagedSessionError {
                peer_id,
                generation,
                error,
            })
    }

    /// Gracefully cancels a not-yet-admitted or active task. Its associated
    /// event receiver receives the network-minted terminal capability.
    ///
    /// # Errors
    ///
    /// Preserves an unsent exact terminal event when bounded delivery fails.
    pub async fn cancel(self) -> Result<ManagedSessionEnd, ManagedSessionError> {
        let (_shutdown, receiver) = watch::channel(true);
        self.run(receiver).await
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ManagedSessionEnd {
    pub peer_id: PeerId,
    pub generation: ConnectionGeneration,
    pub end: SessionEnd,
}

impl fmt::Debug for ManagedSessionEnd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSessionEnd")
            .field("peer_id", &"[REDACTED]")
            .field("generation", &"[REDACTED]")
            .field("end", &self.end)
            .finish()
    }
}

#[must_use = "apply its terminal event or report its exact generation as task-lost"]
pub struct ManagedSessionError {
    peer_id: PeerId,
    generation: ConnectionGeneration,
    error: GenerationBoundSessionError,
}

impl ManagedSessionError {
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    #[must_use]
    pub fn into_terminal_event(self) -> Option<GenerationBoundPeerEvent> {
        self.error.into_terminal_event()
    }
}

impl fmt::Debug for ManagedSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSessionError")
            .field("peer_id", &"[REDACTED]")
            .field("generation", &"[REDACTED]")
            .field("error", &CoarseSessionError(self.error.error()))
            .finish()
    }
}

#[must_use = "apply its exact cancellation or report its generation as task-lost"]
pub struct ManagedSessionBuildError {
    peer_id: PeerId,
    generation: ConnectionGeneration,
    error: GenerationBoundSessionBuildError,
}

impl ManagedSessionBuildError {
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    #[must_use]
    pub fn into_cancellation(self) -> GenerationBoundPeerEvent {
        self.error.into_cancellation()
    }
}

impl fmt::Debug for ManagedSessionBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSessionBuildError")
            .field("peer_id", &"[REDACTED]")
            .field("generation", &"[REDACTED]")
            .field("error", &self.error)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum PeerManagerError {
    #[error("peer manager configuration is invalid")]
    InvalidConfiguration,
    #[error("paired peer identity snapshot is invalid")]
    InvalidIdentity,
    #[error("peer manager capacity was exceeded")]
    CapacityExceeded,
    #[error("untrusted discovery candidate is invalid")]
    InvalidCandidate,
    #[error("peer connection was rejected")]
    PeerRejected,
    #[error("peer task is stale")]
    StaleTask,
    #[error("peer manager identifier space is exhausted")]
    IdentifierSpaceExhausted,
    #[error("workspace control is already attached")]
    WorkspaceAlreadyAttached,
    #[error("workspace control must be attached before peer work")]
    WorkspaceRequired,
    #[error("device routing policy is invalid for the selected workspace")]
    InvalidRoutePolicy,
    #[error("device routing policy refers to an unknown local device")]
    UnknownLocalDevice,
    #[error("device routing policy revision is stale")]
    StaleRoutePolicyRevision,
    #[error("another device routing policy transaction is pending")]
    RoutePolicyBusy,
    #[error("device routing policy persistence is unavailable")]
    RoutePolicyPersistence,
    #[error("peer reconciliation failed for {failures} managed peers")]
    ReconciliationFailed { failures: usize },
    #[error(transparent)]
    Role(#[from] kvm_network::ConnectionRoleError),
    #[error("peer supervisor rejected the operation")]
    Supervisor(#[from] PeerSessionSupervisorError),
}

fn validate_stream<I, O>(
    peer: &ManagedPeerState<I, O>,
    stream: &impl SecurePeerStream,
    direction: ConnectionDirection,
) -> Result<(), PeerManagerError> {
    let expected = transport_identity(&peer.identity);
    if stream.connection_direction() != direction
        || stream.authenticated_peer_identity() != &expected
    {
        return Err(PeerManagerError::PeerRejected);
    }
    Ok(())
}

fn transport_identity(identity: &PeerIdentity) -> TransportPeerIdentity {
    TransportPeerIdentity {
        host_id: WireHostId(identity.host_id().into_bytes()),
        peer_id: WirePeerId(identity.peer_id().into_bytes()),
        credential_fingerprint: *identity.fingerprint().as_bytes(),
    }
}

fn current_peer_generation<I, O>(
    peer: &ManagedPeerState<I, O>,
) -> Result<ConnectionGeneration, PeerManagerError>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    if peer.revoked {
        return Err(PeerManagerError::PeerRejected);
    }
    let generation = peer
        .supervisor
        .active_generation()
        .ok_or(PeerManagerError::PeerRejected)?;
    if peer.task == (PeerTaskSlot::Session { generation }) {
        Ok(generation)
    } else {
        Err(PeerManagerError::StaleTask)
    }
}

fn route_policy_authority<I, O>(
    peer: &ManagedPeerState<I, O>,
) -> Result<Option<ConnectionGeneration>, PeerManagerError>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    if peer.supervisor.active_generation().is_some() {
        return current_peer_generation(peer).map(Some);
    }
    if matches!(peer.task, PeerTaskSlot::Session { .. }) {
        Err(PeerManagerError::StaleTask)
    } else {
        Ok(None)
    }
}

fn require_route_store<I, O, S>(
    peer: &mut ManagedPeerState<I, O>,
    store: &S,
) -> Result<(), PeerManagerError>
where
    S: ConfigStore,
{
    let authority = store.authority();
    match peer.route_store_authority.as_ref() {
        Some(expected) if expected != &authority => Err(PeerManagerError::RoutePolicyBusy),
        Some(_) => Ok(()),
        None => {
            peer.route_store_authority = Some(authority);
            Ok(())
        }
    }
}

fn current_local_device_revision(
    workspace: &WorkspaceControlPlane,
) -> Result<u64, PeerManagerError> {
    workspace
        .device_inventory()
        .snapshot()
        .host(workspace.initial_state().local_host)
        .map(crate::device_inventory::HostDeviceInventorySnapshot::revision)
        .ok_or(PeerManagerError::InvalidRoutePolicy)
}

fn map_route_coordinator_error(error: RoutePolicyCoordinatorError) -> PeerManagerError {
    match error {
        RoutePolicyCoordinatorError::Delivery => PeerManagerError::RoutePolicyBusy,
        RoutePolicyCoordinatorError::Policy(error) => match error {
            RoutePolicyUpdateError::InvalidCandidate => PeerManagerError::InvalidRoutePolicy,
            RoutePolicyUpdateError::StaleRevision => PeerManagerError::StaleRoutePolicyRevision,
            RoutePolicyUpdateError::ConflictingUpdate
            | RoutePolicyUpdateError::CapturePending
            | RoutePolicyUpdateError::CleanupUnavailable
            | RoutePolicyUpdateError::NotReady => PeerManagerError::RoutePolicyBusy,
            RoutePolicyUpdateError::RevisionExhausted => PeerManagerError::IdentifierSpaceExhausted,
        },
    }
}

fn settle_route_policy_update<I, O, S>(
    peer: &mut ManagedPeerState<I, O>,
    generation: Option<ConnectionGeneration>,
    status: RoutePolicyUpdateStatus,
    store: &S,
    now_ns: u64,
) -> Result<DeviceRouteUpdateOutcome, PeerManagerError>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
    S: ConfigStore,
{
    let committed_revision = peer
        .supervisor
        .route_policy_revision(generation)
        .map_err(map_route_coordinator_error)?;
    if status == RoutePolicyUpdateStatus::CleanupPending {
        return Ok(DeviceRouteUpdateOutcome {
            state: DeviceRouteUpdateState::CleanupPending,
            committed_revision,
        });
    }
    let (revision, candidate) = peer
        .supervisor
        .staged_route_policy(generation)
        .map_err(map_route_coordinator_error)?
        .ok_or(PeerManagerError::RoutePolicyBusy)?;
    if store.save(&candidate).is_err() {
        return Ok(DeviceRouteUpdateOutcome {
            state: DeviceRouteUpdateState::PersistencePending,
            committed_revision,
        });
    }
    let committed = peer
        .supervisor
        .commit_route_policy_update(generation, revision, now_ns)
        .map_err(|error| map_route_coordinator_error(RoutePolicyCoordinatorError::Policy(error)))?;
    Ok(DeviceRouteUpdateOutcome {
        state: DeviceRouteUpdateState::Committed,
        committed_revision: committed,
    })
}

fn schedule_connect_failure<I, O>(peer: &mut ManagedPeerState<I, O>, now: Duration) {
    peer.task = PeerTaskSlot::Idle;
    if !peer.candidates.is_empty() {
        peer.candidate_cursor = (peer.candidate_cursor + 1) % peer.candidates.len();
    }
    let delay = peer.backoff.next_delay();
    peer.retry_not_before = now.checked_add(delay).unwrap_or(Duration::MAX);
}

fn settle_reconciliation_outcome<I, O>(
    peer: &mut ManagedPeerState<I, O>,
    outcome: SupervisorEventOutcome,
    now_ns: u64,
) {
    if matches!(outcome, SupervisorEventOutcome::Retired(_)) {
        peer.task = PeerTaskSlot::Idle;
        schedule_retry(peer, Duration::from_nanos(now_ns));
    }
}

fn settle_connection_lost_result<I, O>(
    peer: &mut ManagedPeerState<I, O>,
    result: Result<SupervisorEventOutcome, PeerSessionSupervisorError>,
    now_ns: u64,
) -> Result<SupervisorEventOutcome, PeerManagerError>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    settle_reconciliation_result(peer, result, now_ns)
}

fn settle_reconciliation_retry_result<I, O>(
    peer: &mut ManagedPeerState<I, O>,
    result: Result<SupervisorEventOutcome, PeerSessionSupervisorError>,
    now_ns: u64,
) -> Result<SupervisorEventOutcome, PeerManagerError>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    settle_reconciliation_result(peer, result, now_ns)
}

fn settle_reconciliation_result<I, O>(
    peer: &mut ManagedPeerState<I, O>,
    result: Result<SupervisorEventOutcome, PeerSessionSupervisorError>,
    now_ns: u64,
) -> Result<SupervisorEventOutcome, PeerManagerError>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    match result {
        Ok(outcome) => {
            settle_reconciliation_outcome(peer, outcome, now_ns);
            Ok(outcome)
        }
        Err(error) => {
            if peer.supervisor.active_generation().is_none() {
                peer.task = PeerTaskSlot::Idle;
                schedule_retry(peer, Duration::from_nanos(now_ns));
            }
            Err(error.into())
        }
    }
}

fn settle_bound_event_result<I, O>(
    peer: &mut ManagedPeerState<I, O>,
    classification: GenerationBoundEventClassification,
    result: Result<SupervisorEventOutcome, PeerSessionSupervisorError>,
    now_ns: u64,
) -> Result<SupervisorEventOutcome, PeerManagerError>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            if peer.supervisor.active_generation().is_none() {
                peer.task = PeerTaskSlot::Idle;
                schedule_retry(peer, Duration::from_nanos(now_ns));
            }
            return Err(error.into());
        }
    };
    match outcome {
        SupervisorEventOutcome::PendingCancelled | SupervisorEventOutcome::Retired(_) => {
            peer.task = PeerTaskSlot::Idle;
            schedule_retry(peer, Duration::from_nanos(now_ns));
        }
        SupervisorEventOutcome::Applied(_)
            if classification == GenerationBoundEventClassification::Activated =>
        {
            peer.backoff.reset();
            peer.retry_not_before = Duration::ZERO;
        }
        SupervisorEventOutcome::Applied(_)
        | SupervisorEventOutcome::StaleIgnored
        | SupervisorEventOutcome::PendingIgnored => {}
    }
    Ok(outcome)
}

fn schedule_retry<I, O>(peer: &mut ManagedPeerState<I, O>, now: Duration) {
    if !peer.revoked {
        let delay = peer.backoff.next_delay();
        peer.retry_not_before = now.checked_add(delay).unwrap_or(Duration::MAX);
    }
}

struct CoarseSessionError<'a>(&'a SessionError);

impl fmt::Debug for CoarseSessionError<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.0 {
            SessionError::Network(_) => "Network",
            SessionError::Admission(_) => "Admission",
            SessionError::TransportIdentityMismatch => "TransportIdentityMismatch",
            SessionError::LocalIdentityMismatch => "LocalIdentityMismatch",
            SessionError::PeerIdentityCollision => "PeerIdentityCollision",
            SessionError::NoncanonicalDirection => "NoncanonicalDirection",
            SessionError::NoCompatibleProtocolVersion => "NoCompatibleProtocolVersion",
            SessionError::InvalidSessionBinding => "InvalidSessionBinding",
            SessionError::PreAdmissionMessage(_) => "PreAdmissionMessage",
            SessionError::RepeatedHandshake(_) => "RepeatedHandshake",
            SessionError::MessageIdentityMismatch(_) => "MessageIdentityMismatch",
            SessionError::Heartbeat(_) => "Heartbeat",
            SessionError::HeartbeatTimeout => "HeartbeatTimeout",
            SessionError::AdmissionTimeout => "AdmissionTimeout",
            SessionError::QueueFull { .. } => "QueueFull",
            SessionError::EventChannelFull => "EventChannelFull",
            SessionError::EventChannelClosed => "EventChannelClosed",
        };
        formatter.write_str(kind)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    use kvm_config::{
        Config, ConfigError, ConfigStore, ConfiguredDeviceRoute, DeviceRouteConfig,
        MemoryConfigStore, PairedHostConfig,
    };
    use kvm_discovery::{
        DiscoveryCache, DiscoveryCacheConfig, RawDiscoveryRecord, RawTxtProperty,
        SOFTWARE_KVM_SERVICE_TYPE,
    };
    use kvm_input::{InputEvent, InputPayload, KeyCode, KeyState};
    use kvm_network::ConnectionGenerationGate;
    use kvm_protocol::{
        DeviceSnapshotV1, DisplaySnapshotV1, HelloV1, InputEventV1, PointerEnterV1, PointerLeaveV1,
        PointerTransitionAckV1, PointerTransitionCommitV1, PointerTransitionOutcomeV1,
        WireDeviceCapabilities, WireDeviceId, WireDeviceKind, WireDisplayId, WireDisplayV1,
        WireEdge, WireHostId, WireInputDeviceV1, WireInputPayloadV1, WireKeyState, WireMessage,
        WirePeerId, WirePlatform, WireRect, WireSize,
    };
    use kvm_security::IdentityFingerprint;
    use kvm_topology::{WorkspaceLink, WorkspacePlacement};
    use kvm_types::{
        DeviceCapabilities, DeviceId, DeviceKind, DisplayId, HostId, InputDevice, LogicalPointer,
        Platform, Point, Rect, Size, WorkspaceState,
    };

    use super::*;
    use crate::{
        CoordinatorError, DaemonCore, DisplayInventory, DisplayInventoryConfig, OutboundPeerError,
        PeerSessionCoordinator, PlatformError, PointerHandoffConfig, WorkspaceControlPlane,
    };

    const LOCAL_PEER: PeerId = PeerId::from_bytes([2; 16]);
    const DIAL_PEER: PeerId = PeerId::from_bytes([3; 16]);
    const LISTEN_PEER: PeerId = PeerId::from_bytes([1; 16]);
    const UNKNOWN_PEER: PeerId = PeerId::from_bytes([9; 16]);
    const LOCAL_HOST: HostId = HostId::from_bytes([10; 16]);
    const REMOTE_HOST: HostId = HostId::from_bytes([11; 16]);
    const DISPLAY: DisplayId = DisplayId::from_bytes([12; 16]);
    const REMOTE_DISPLAY: DisplayId = DisplayId::from_bytes([13; 16]);
    const DEVICE: DeviceId = DeviceId::from_bytes([14; 16]);

    #[derive(Debug, Default)]
    struct TestInjection {
        fail_remaining: usize,
    }

    impl TestInjection {
        fn fail_times(&mut self, count: usize) {
            self.fail_remaining = count;
        }
    }

    impl OutputInjectionBackend for TestInjection {
        fn inject(&mut self, _event: &InputEvent) -> Result<(), PlatformError> {
            if self.fail_remaining > 0 {
                self.fail_remaining -= 1;
                return Err(std::io::Error::other("simulated injection failure").into());
            }
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct TestOutboundState {
        messages: Vec<WireMessage>,
        fail_remaining: usize,
        successes_before_failure: usize,
        failure: Option<OutboundPeerError>,
    }

    #[derive(Clone, Debug, Default)]
    struct TestOutbound(Arc<Mutex<TestOutboundState>>);

    impl TestOutbound {
        fn messages(&self) -> Vec<WireMessage> {
            self.0.lock().unwrap().messages.clone()
        }

        fn clear(&self) {
            self.0.lock().unwrap().messages.clear();
        }

        fn fail_times(&self, count: usize, error: OutboundPeerError) {
            let mut state = self.0.lock().unwrap();
            state.fail_remaining = count;
            state.successes_before_failure = 0;
            state.failure = Some(error);
        }

        fn fail_after(&self, successes: usize, count: usize, error: OutboundPeerError) {
            let mut state = self.0.lock().unwrap();
            state.fail_remaining = count;
            state.successes_before_failure = successes;
            state.failure = Some(error);
        }
    }

    impl OutboundPeer for TestOutbound {
        fn try_send(&mut self, message: WireMessage) -> Result<(), OutboundPeerError> {
            let mut state = self.0.lock().unwrap();
            if state.successes_before_failure > 0 {
                state.successes_before_failure -= 1;
            } else if state.fail_remaining > 0 {
                state.fail_remaining -= 1;
                let error = state.failure.expect("failure count requires an error");
                return Err(error);
            }
            state.messages.push(message);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FailingConfigStore {
        inner: MemoryConfigStore,
        fail: AtomicBool,
    }

    impl Default for FailingConfigStore {
        fn default() -> Self {
            Self {
                inner: MemoryConfigStore::default(),
                fail: AtomicBool::new(true),
            }
        }
    }

    impl FailingConfigStore {
        fn set_failure(&self, fail: bool) {
            self.fail.store(fail, Ordering::Relaxed);
        }
    }

    impl ConfigStore for FailingConfigStore {
        fn authority(&self) -> ConfigStoreAuthority {
            self.inner.authority()
        }

        fn load(&self) -> Result<Option<Config>, ConfigError> {
            self.inner.load()
        }

        fn save(&self, config: &Config) -> Result<(), ConfigError> {
            self.inner.save(config)?;
            if self.fail.load(Ordering::Relaxed) {
                return Err(ConfigError::SizeLimit);
            }
            Ok(())
        }
    }

    fn identity(peer_id: PeerId, marker: u8) -> PeerIdentity {
        PeerIdentity::new(
            peer_id,
            HostId::from_bytes([marker; 16]),
            "paired peer",
            IdentityFingerprint::from_sha256([marker; 32]),
        )
        .unwrap()
    }

    fn managed_peer(
        local_peer_id: PeerId,
        remote_peer_id: PeerId,
        marker: u8,
    ) -> ManagedPairedPeer<TestInjection, TestOutbound> {
        managed_peer_with_outbound(
            local_peer_id,
            remote_peer_id,
            marker,
            TestOutbound::default(),
        )
    }

    fn managed_peer_with_outbound<O: OutboundPeer>(
        local_peer_id: PeerId,
        remote_peer_id: PeerId,
        marker: u8,
        outbound: O,
    ) -> ManagedPairedPeer<TestInjection, O> {
        let identity = identity(remote_peer_id, marker);
        let mut config = Config::default();
        config.paired_hosts.push(PairedHostConfig {
            host_id: identity.host_id(),
            peer_id: identity.peer_id(),
            name: "paired peer".into(),
            platform: Platform::Windows,
            identity_fingerprint: identity.fingerprint().to_string(),
            last_address: None,
        });
        let workspace = WorkspaceState::new(
            LOCAL_HOST,
            LOCAL_HOST,
            LogicalPointer::new(DISPLAY, 0.0, 0.0),
        );
        let coordinator = PeerSessionCoordinator::new(
            DaemonCore::new(config, workspace).unwrap(),
            identity.clone(),
            TestInjection::default(),
            outbound,
        )
        .unwrap();
        let gate = ConnectionGenerationGate::new(
            WirePeerId(local_peer_id.into_bytes()),
            WirePeerId(remote_peer_id.into_bytes()),
        )
        .unwrap();
        ManagedPairedPeer::new(
            &PairedPeer::from_persisted_public_identity(identity),
            PeerSessionSupervisor::new(gate, coordinator),
        )
    }

    fn manager(remote_peer_id: PeerId) -> PeerManager<TestInjection, TestOutbound> {
        manager_with_outbound(remote_peer_id, TestOutbound::default())
    }

    fn managed_outbound_manager() -> PeerManager<TestInjection, ManagedSessionOutbound> {
        let managed = managed_peer_with_outbound(
            LOCAL_PEER,
            DIAL_PEER,
            11,
            ManagedSessionOutbound::detached(),
        );
        let mut candidate =
            PeerManager::new(LOCAL_PEER, [managed], PeerManagerConfig::default()).unwrap();
        let workspace = manager(DIAL_PEER).workspace.unwrap();
        candidate.attach_workspace_control(workspace).unwrap();
        candidate
    }

    struct RejectingAdmission;

    impl SessionAdmission for RejectingAdmission {
        fn local_hello(&self) -> Result<HelloV1, kvm_network::AdmissionError> {
            Err(kvm_network::AdmissionError::Rejected)
        }

        fn authentication_message(
            &self,
            _transcript: &kvm_network::HandshakeTranscript,
        ) -> Result<kvm_protocol::AuthenticateV1, kvm_network::AdmissionError> {
            Err(kvm_network::AdmissionError::Rejected)
        }

        fn admit(
            &self,
            _transcript: &kvm_network::HandshakeTranscript,
            _authentication: &kvm_protocol::AuthenticateV1,
        ) -> Result<(), kvm_network::AdmissionError> {
            Err(kvm_network::AdmissionError::Rejected)
        }
    }

    fn manager_with_outbound(
        remote_peer_id: PeerId,
        outbound: TestOutbound,
    ) -> PeerManager<TestInjection, TestOutbound> {
        let mut manager = PeerManager::new(
            LOCAL_PEER,
            [managed_peer_with_outbound(
                LOCAL_PEER,
                remote_peer_id,
                11,
                outbound,
            )],
            PeerManagerConfig {
                reconnect: ReconnectPolicy {
                    initial_delay: Duration::from_secs(1),
                    maximum_delay: Duration::from_secs(8),
                    multiplier: 2,
                },
                ..PeerManagerConfig::default()
            },
        )
        .unwrap();
        let mut inventory =
            DisplayInventory::new(LOCAL_HOST, DisplayInventoryConfig::default()).unwrap();
        inventory
            .apply_local_snapshot(
                1,
                vec![kvm_types::Display {
                    id: DISPLAY,
                    host_id: LOCAL_HOST,
                    name: "local".into(),
                    logical_size: Size::new(100.0, 100.0),
                    physical_size: None,
                    scale_factor: 1.0,
                    refresh_rate: None,
                    native_bounds: Rect::new(0.0, 0.0, 100.0, 100.0),
                    primary: true,
                }],
            )
            .unwrap();
        let initial = WorkspaceState::new(
            LOCAL_HOST,
            LOCAL_HOST,
            LogicalPointer::new(DISPLAY, 0.0, 0.0),
        );
        let mut plane = WorkspaceControlPlane::new(
            remote_peer_id,
            inventory,
            PointerHandoffConfig::new(Duration::from_secs(1)).unwrap(),
            initial,
            LogicalPointer::new(DISPLAY, 0.0, 0.0),
            vec![
                WorkspacePlacement::new(DISPLAY, Point::new(0.0, 0.0)),
                WorkspacePlacement::new(REMOTE_DISPLAY, Point::new(100.0, 0.0)),
            ],
            vec![
                WorkspaceLink::new(DISPLAY, Edge::Right, REMOTE_DISPLAY, Edge::Left),
                WorkspaceLink::new(REMOTE_DISPLAY, Edge::Left, DISPLAY, Edge::Right),
            ],
        )
        .unwrap();
        plane
            .apply_local_device_snapshot_offline(
                2,
                vec![InputDevice::new(
                    DEVICE,
                    LOCAL_HOST,
                    "test keyboard",
                    DeviceKind::Keyboard,
                    DeviceCapabilities::KEYBOARD,
                )],
            )
            .unwrap();
        manager.attach_workspace_control(plane).unwrap();
        manager
            .rearm_native_capture(CaptureLifecycleState::Running)
            .unwrap();
        manager
    }

    fn manager_with_configured_route(
        route: ConfiguredDeviceRoute,
    ) -> (PeerManager<TestInjection, TestOutbound>, TestOutbound) {
        let outbound = TestOutbound::default();
        let selected_identity = identity(DIAL_PEER, 11);
        let mut config = Config::default();
        config.paired_hosts.push(PairedHostConfig {
            host_id: REMOTE_HOST,
            peer_id: DIAL_PEER,
            name: "selected".into(),
            platform: Platform::Windows,
            identity_fingerprint: selected_identity.fingerprint().to_string(),
            last_address: None,
        });
        config.device_routes.push(DeviceRouteConfig {
            device_id: DEVICE,
            route,
        });
        let initial = WorkspaceState::new(
            LOCAL_HOST,
            LOCAL_HOST,
            LogicalPointer::new(DISPLAY, 0.0, 0.0),
        );
        let coordinator = PeerSessionCoordinator::new(
            DaemonCore::new(config, initial).unwrap(),
            selected_identity.clone(),
            TestInjection::default(),
            outbound.clone(),
        )
        .unwrap();
        let gate = ConnectionGenerationGate::new(
            WirePeerId(LOCAL_PEER.into_bytes()),
            WirePeerId(DIAL_PEER.into_bytes()),
        )
        .unwrap();
        let managed = ManagedPairedPeer::new(
            &PairedPeer::from_persisted_public_identity(selected_identity),
            PeerSessionSupervisor::new(gate, coordinator),
        );
        let mut candidate =
            PeerManager::new(LOCAL_PEER, [managed], PeerManagerConfig::default()).unwrap();
        let plane = manager(DIAL_PEER).workspace.unwrap();
        candidate.attach_workspace_control(plane).unwrap();
        candidate
            .rearm_native_capture(CaptureLifecycleState::Running)
            .unwrap();
        (candidate, outbound)
    }

    fn hello(host_id: HostId, peer_id: PeerId, nonce: u8) -> HelloV1 {
        HelloV1 {
            host_id: WireHostId(host_id.into_bytes()),
            peer_id: WirePeerId(peer_id.into_bytes()),
            host_name: "test".into(),
            platform: WirePlatform::Linux,
            minimum_protocol_version: 1,
            maximum_protocol_version: 1,
            daemon_version: "test".into(),
            nonce: [nonce; 32],
        }
    }

    fn remote_snapshot() -> DisplaySnapshotV1 {
        DisplaySnapshotV1 {
            revision: 1,
            host_id: WireHostId(REMOTE_HOST.into_bytes()),
            displays: vec![WireDisplayV1 {
                id: WireDisplayId(REMOTE_DISPLAY.into_bytes()),
                host_id: WireHostId(REMOTE_HOST.into_bytes()),
                name: "remote".into(),
                logical_size: WireSize {
                    width: 100.0,
                    height: 100.0,
                },
                physical_size: None,
                scale_factor: 1.0,
                refresh_rate: None,
                native_bounds: WireRect {
                    x: 0.0,
                    y: 0.0,
                    width: 100.0,
                    height: 100.0,
                },
                primary: true,
            }],
        }
    }

    fn remote_device_snapshot() -> DeviceSnapshotV1 {
        DeviceSnapshotV1 {
            revision: 1,
            host_id: WireHostId(REMOTE_HOST.into_bytes()),
            devices: vec![WireInputDeviceV1 {
                id: WireDeviceId(DEVICE.into_bytes()),
                host_id: WireHostId(REMOTE_HOST.into_bytes()),
                name: "remote keyboard".into(),
                vendor_id: None,
                product_id: None,
                kind: WireDeviceKind::Keyboard,
                capabilities: WireDeviceCapabilities {
                    keyboard: true,
                    ..WireDeviceCapabilities::default()
                },
            }],
        }
    }

    fn local_display(name: &str) -> Display {
        Display {
            id: DISPLAY,
            host_id: LOCAL_HOST,
            name: name.into(),
            logical_size: Size::new(100.0, 100.0),
            physical_size: None,
            scale_factor: 1.0,
            refresh_rate: None,
            native_bounds: Rect::new(0.0, 0.0, 100.0, 100.0),
            primary: true,
        }
    }

    fn activate_selected(manager: &mut PeerManager<TestInjection, TestOutbound>) {
        let workspace = manager.workspace.as_mut().unwrap();
        let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
        let generation = peer
            .supervisor
            .activate_workspace_test_session(
                workspace,
                transport_identity(&peer.identity),
                hello(LOCAL_HOST, LOCAL_PEER, 1),
                hello(REMOTE_HOST, DIAL_PEER, 2),
                1,
            )
            .unwrap();
        peer.task = PeerTaskSlot::Session { generation };
        peer.supervisor
            .apply_workspace_test_message(
                workspace,
                WireMessage::DisplaySnapshot(remote_snapshot()),
                2,
            )
            .unwrap();
        peer.supervisor
            .apply_workspace_test_message(
                workspace,
                WireMessage::DeviceSnapshot(remote_device_snapshot()),
                3,
            )
            .unwrap();
    }

    fn captured_key(sequence: u64, code: KeyCode, state: KeyState) -> CapturedInput {
        CapturedInput::new(
            InputEvent::new(
                sequence,
                sequence,
                LOCAL_HOST,
                DEVICE,
                InputPayload::Key { code, state },
            ),
            crate::EventClassification::Physical,
        )
    }

    fn captured_pointer_at(sequence: u64, position: Point) -> CapturedInput {
        CapturedInput::new(
            InputEvent::new(
                sequence,
                sequence,
                LOCAL_HOST,
                DEVICE,
                InputPayload::PointerMove { dx: 2.0, dy: 0.0 },
            ),
            crate::EventClassification::Physical,
        )
        .with_native_pointer_position(position)
    }

    fn commit_selected_pointer(
        manager: &mut PeerManager<TestInjection, TestOutbound>,
        outbound: &TestOutbound,
        now_ns: u64,
    ) {
        manager
            .propose_pointer_handoff(Edge::Right, 0.5, now_ns)
            .unwrap();
        let enter = outbound
            .messages()
            .into_iter()
            .rev()
            .find_map(|message| match message {
                WireMessage::PointerEnter(enter) => Some(enter),
                _ => None,
            })
            .expect("outbound pointer proposal");
        let workspace = manager.workspace.as_mut().unwrap();
        let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
        peer.supervisor
            .apply_workspace_test_message(
                workspace,
                WireMessage::PointerTransitionAck(PointerTransitionAckV1 {
                    transition_id: enter.transition_id,
                    workspace_epoch: enter.workspace_epoch,
                    receiver_host: WireHostId(REMOTE_HOST.into_bytes()),
                    active_display: WireDisplayId(REMOTE_DISPLAY.into_bytes()),
                    outcome: PointerTransitionOutcomeV1::Accepted,
                }),
                now_ns + 1,
            )
            .unwrap();
    }

    #[test]
    fn trusted_native_edge_motion_starts_the_configured_handoff() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        outbound.clear();

        let outcome =
            manager.route_selected_capture(captured_pointer_at(1, Point::new(99.0, 25.0)), 10);

        assert_eq!(outcome.disposition(), CaptureDisposition::SuppressLocal);
        assert_eq!(outcome.state(), SelectedCaptureState::Inert);
        let enter = outbound
            .messages()
            .into_iter()
            .find_map(|message| match message {
                WireMessage::PointerEnter(enter) => Some(enter),
                _ => None,
            })
            .expect("the configured edge must enqueue one pointer proposal");
        assert!((enter.normalized_position - 0.25).abs() < f64::EPSILON);
    }

    fn snapshot(peer_id: PeerId, addresses: Vec<IpAddr>) -> DiscoverySnapshot {
        let mut cache = DiscoveryCache::new(DiscoveryCacheConfig::default()).unwrap();
        cache
            .apply_resolved(
                RawDiscoveryRecord {
                    service_type: SOFTWARE_KVM_SERVICE_TYPE.as_bytes().to_vec(),
                    fullname: b"peer._software-kvm._tcp.local.".to_vec(),
                    hostname: b"peer.local.".to_vec(),
                    port: 24_800,
                    addresses,
                    txt: vec![
                        RawTxtProperty {
                            key: b"ver".to_vec(),
                            value: Some(b"1".to_vec()),
                        },
                        RawTxtProperty {
                            key: b"peer".to_vec(),
                            value: Some(peer_id.to_string().into_bytes()),
                        },
                    ],
                    ttl: Duration::from_secs(30),
                },
                Duration::ZERO,
            )
            .unwrap();
        cache.snapshot()
    }

    #[test]
    fn selected_device_route_update_is_revisioned_durable_and_stale_safe() {
        let mut manager = manager(DIAL_PEER);
        activate_selected(&mut manager);
        let store = MemoryConfigStore::default();

        let outcome = manager
            .set_selected_device_route(&store, 0, DEVICE, DeviceRoute::Local, 10)
            .unwrap();
        assert_eq!(outcome.state(), DeviceRouteUpdateState::Committed);
        assert_eq!(outcome.committed_revision(), 1);
        let saved = store.load().unwrap().unwrap();
        assert_eq!(saved.device_route_revision, 1);
        assert_eq!(saved.device_routes.len(), 1);
        assert!(matches!(
            manager
                .set_selected_device_route(&store, 0, DEVICE, DeviceRoute::FollowActiveHost, 11,),
            Err(PeerManagerError::StaleRoutePolicyRevision)
        ));
        assert_eq!(manager.selected_device_route_revision().unwrap(), 1);
    }

    #[test]
    fn selected_device_route_requires_current_local_inventory() {
        let mut manager = manager(DIAL_PEER);
        activate_selected(&mut manager);
        let store = MemoryConfigStore::default();
        assert!(matches!(
            manager.set_selected_device_route(
                &store,
                0,
                DeviceId::from_bytes([0x55; 16]),
                DeviceRoute::Local,
                10,
            ),
            Err(PeerManagerError::UnknownLocalDevice)
        ));
        assert_eq!(manager.selected_device_route_revision().unwrap(), 0);
    }

    #[test]
    fn persistence_failure_retains_exact_candidate_for_retry() {
        let mut manager = manager(DIAL_PEER);
        activate_selected(&mut manager);
        let store = FailingConfigStore::default();
        let pending = manager
            .set_selected_device_route(&store, 0, DEVICE, DeviceRoute::Local, 10)
            .unwrap();
        assert_eq!(pending.state(), DeviceRouteUpdateState::PersistencePending);
        assert_eq!(pending.committed_revision(), 0);
        assert_eq!(store.load().unwrap().unwrap().device_route_revision, 1);

        let different_store = MemoryConfigStore::default();
        assert!(matches!(
            manager.retry_selected_device_route_update(&different_store, 11),
            Err(PeerManagerError::RoutePolicyBusy)
        ));
        assert!(matches!(
            manager.abort_selected_device_route_update(&different_store, 11),
            Err(PeerManagerError::RoutePolicyBusy)
        ));

        store.set_failure(false);
        let committed = manager
            .retry_selected_device_route_update(&store, 12)
            .unwrap();
        assert_eq!(committed.state(), DeviceRouteUpdateState::Committed);
        assert_eq!(committed.committed_revision(), 1);
        assert_eq!(store.load().unwrap().unwrap().device_route_revision, 1);
    }

    #[test]
    fn prepared_sender_installs_only_into_its_exact_manager_generation() {
        let mut owner = managed_outbound_manager();
        let peer = owner.peers.get_mut(&DIAL_PEER).unwrap();
        let pending = peer
            .supervisor
            .begin_pending(ConnectionDirection::Outbound)
            .unwrap();
        let generation = pending.generation();
        peer.task = PeerTaskSlot::Session { generation };
        let (session, sender, events) = GenerationBoundPeerSession::new(
            RejectingAdmission,
            PersistentPeerConfig::default(),
            pending,
        )
        .unwrap();
        let prepared = PreparedPeerSessionParts {
            runner: PreparedPeerSession {
                manager_id: owner.manager_id,
                peer_id: DIAL_PEER,
                generation,
                stream: (),
                session,
            },
            _sender: sender,
            events,
        };

        let mut other = managed_outbound_manager();
        let prepared = *other
            .install_prepared_session(prepared)
            .expect_err("a different manager must return every prepared resource");
        assert_eq!(prepared.peer_id(), DIAL_PEER);
        assert_eq!(prepared.generation(), generation);

        let installed = owner
            .install_prepared_session(prepared)
            .expect("the exact owner installs its private sender");
        let snapshot = owner
            .workspace
            .as_ref()
            .unwrap()
            .device_inventory()
            .local_wire_snapshot()
            .unwrap();
        owner
            .peers
            .get_mut(&DIAL_PEER)
            .unwrap()
            .supervisor
            .test_session_outbound(WireMessage::DeviceSnapshot(snapshot))
            .expect("the installed facade reaches the live bounded FIFO");
        drop(installed);
    }

    #[test]
    fn held_follow_route_releases_before_policy_publication() {
        let (mut manager, outbound) =
            manager_with_configured_route(ConfiguredDeviceRoute::FollowActiveHost);
        activate_selected(&mut manager);
        commit_selected_pointer(&mut manager, &outbound, 10);
        let press =
            manager.route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 20);
        assert_eq!(press.state(), SelectedCaptureState::RemoteQueued);

        let store = MemoryConfigStore::default();
        let outcome = manager
            .set_selected_device_route(&store, 0, DEVICE, DeviceRoute::Local, 21)
            .unwrap();
        assert_eq!(outcome.state(), DeviceRouteUpdateState::Committed);
        let messages = outbound.messages();
        let input_position = messages
            .iter()
            .position(|message| matches!(message, WireMessage::Input(_)))
            .unwrap();
        let release_position = messages
            .iter()
            .position(|message| matches!(message, WireMessage::ReleaseInput(_)))
            .unwrap();
        assert!(input_position < release_position);
        assert_eq!(
            store.load().unwrap().unwrap().device_routes[0].route,
            ConfiguredDeviceRoute::Local
        );
    }

    #[test]
    fn local_device_inventory_is_revisioned_ordered_and_retryable() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        outbound.clear();
        let added_id = DeviceId::from_bytes([0x44; 16]);
        let added = InputDevice::new(
            added_id,
            LOCAL_HOST,
            "second keyboard",
            DeviceKind::Keyboard,
            DeviceCapabilities::KEYBOARD,
        );
        let existing = InputDevice::new(
            DEVICE,
            LOCAL_HOST,
            "test keyboard",
            DeviceKind::Keyboard,
            DeviceCapabilities::KEYBOARD,
        );

        let added_outcome = manager
            .replace_local_device_inventory(3, vec![existing.clone(), added], 10)
            .unwrap();
        assert_eq!(added_outcome.state(), DeviceInventoryUpdateState::Committed);
        assert!(manager
            .device_inventory_snapshot()
            .unwrap()
            .owns_device(LOCAL_HOST, added_id));
        assert!(outbound.messages().iter().any(|message| {
            matches!(message, WireMessage::DeviceSnapshot(snapshot) if snapshot.revision == 3)
        }));

        outbound.clear();
        let removed = manager
            .replace_local_device_inventory(4, vec![existing], 11)
            .unwrap();
        assert_eq!(removed.state(), DeviceInventoryUpdateState::Committed);
        assert!(!manager
            .device_inventory_snapshot()
            .unwrap()
            .owns_device(LOCAL_HOST, added_id));
    }

    #[test]
    fn selected_inventory_send_failure_retains_published_phase_for_retry() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        outbound.clear();
        outbound.fail_times(1, OutboundPeerError::Full);
        let changed = InputDevice::new(
            DEVICE,
            LOCAL_HOST,
            "replacement keyboard",
            DeviceKind::Keyboard,
            DeviceCapabilities::KEYBOARD,
        );

        let pending = manager
            .replace_local_device_inventory(3, vec![changed], 10)
            .unwrap();
        assert_eq!(pending.state(), DeviceInventoryUpdateState::CleanupPending);
        assert_eq!(pending.committed_revision(), 3);
        let committed = manager.retry_local_device_inventory_update(11).unwrap();
        assert_eq!(committed.state(), DeviceInventoryUpdateState::Committed);
        assert_eq!(committed.committed_revision(), 3);
    }

    #[test]
    fn replacement_activation_satisfies_committed_inventory_sync_once() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        outbound.clear();
        outbound.fail_times(1, OutboundPeerError::Full);
        let changed = InputDevice::new(
            DEVICE,
            LOCAL_HOST,
            "replacement keyboard",
            DeviceKind::Keyboard,
            DeviceCapabilities::KEYBOARD,
        );

        let pending = manager
            .replace_local_device_inventory(3, vec![changed], 10)
            .unwrap();
        assert_eq!(pending.state(), DeviceInventoryUpdateState::CleanupPending);
        assert_eq!(pending.committed_revision(), 3);
        assert!(manager
            .peers
            .get(&DIAL_PEER)
            .unwrap()
            .supervisor
            .active_generation()
            .is_none());
        assert_eq!(
            manager.peers.get(&DIAL_PEER).unwrap().task,
            PeerTaskSlot::Idle
        );

        outbound.clear();
        activate_selected(&mut manager);
        let revision_three_count = || {
            outbound
                .messages()
                .iter()
                .filter(|message| {
                    matches!(message, WireMessage::DeviceSnapshot(snapshot) if snapshot.revision == 3)
                })
                .count()
        };
        assert_eq!(revision_three_count(), 1);
        let committed = manager.retry_local_device_inventory_update(12).unwrap();
        assert_eq!(committed.state(), DeviceInventoryUpdateState::Committed);
        assert_eq!(revision_three_count(), 1);
    }

    #[test]
    fn offline_remove_then_readd_restores_the_explicit_selected_route() {
        let (mut manager, outbound) = manager_with_configured_route(ConfiguredDeviceRoute::Host {
            host_id: REMOTE_HOST,
        });
        let removed = manager
            .replace_local_device_inventory(3, Vec::new(), 10)
            .unwrap();
        assert_eq!(removed.state(), DeviceInventoryUpdateState::Committed);
        activate_selected(&mut manager);
        let gated =
            manager.route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 11);
        assert_eq!(gated.state(), SelectedCaptureState::Gated);
        let _ =
            manager.route_selected_capture(captured_key(2, KeyCode::KeyA, KeyState::Released), 12);
        let generation = manager
            .peers
            .get(&DIAL_PEER)
            .unwrap()
            .supervisor
            .active_generation()
            .unwrap();
        assert!(matches!(
            manager.connection_lost(DIAL_PEER, generation, 13).unwrap(),
            SupervisorEventOutcome::Retired(_)
        ));

        let restored = InputDevice::new(
            DEVICE,
            LOCAL_HOST,
            "test keyboard",
            DeviceKind::Keyboard,
            DeviceCapabilities::KEYBOARD,
        );
        let readded = manager
            .replace_local_device_inventory(4, vec![restored], 14)
            .unwrap();
        assert_eq!(readded.state(), DeviceInventoryUpdateState::Committed);
        outbound.clear();
        activate_selected(&mut manager);
        let routed =
            manager.route_selected_capture(captured_key(3, KeyCode::KeyB, KeyState::Pressed), 15);
        assert_eq!(routed.state(), SelectedCaptureState::RemoteQueued);
        assert_eq!(routed.disposition(), CaptureDisposition::SuppressLocal);
    }

    #[test]
    fn abort_local_inventory_drains_cleanup_and_restores_committed_device() {
        let (mut manager, outbound) =
            manager_with_configured_route(ConfiguredDeviceRoute::FollowActiveHost);
        activate_selected(&mut manager);
        commit_selected_pointer(&mut manager, &outbound, 10);
        assert_eq!(
            manager
                .route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 20,)
                .state(),
            SelectedCaptureState::RemoteQueued
        );
        outbound.fail_times(1, OutboundPeerError::Full);
        let pending = manager
            .replace_local_device_inventory(3, Vec::new(), 21)
            .unwrap();
        assert_eq!(pending.state(), DeviceInventoryUpdateState::CleanupPending);

        let aborted = manager.abort_local_device_inventory_update(22).unwrap();
        assert_eq!(aborted.state(), DeviceInventoryUpdateState::Committed);
        assert_eq!(aborted.committed_revision(), 2);
        assert!(manager
            .device_inventory_snapshot()
            .unwrap()
            .owns_device(LOCAL_HOST, DEVICE));
        assert!(outbound
            .messages()
            .iter()
            .any(|message| matches!(message, WireMessage::ReleaseInput(_))));
    }

    #[test]
    fn local_host_route_normalizes_and_offline_policy_can_commit_or_abort() {
        let mut manager = manager(DIAL_PEER);
        let store = FailingConfigStore::default();
        store.set_failure(false);
        let committed = manager
            .set_selected_device_route(&store, 0, DEVICE, DeviceRoute::Host(LOCAL_HOST), 10)
            .unwrap();
        assert_eq!(committed.state(), DeviceRouteUpdateState::Committed);
        assert_eq!(
            store.load().unwrap().unwrap().device_routes[0].route,
            ConfiguredDeviceRoute::Local
        );

        store.set_failure(true);
        let pending = manager
            .set_selected_device_route(&store, 1, DEVICE, DeviceRoute::FollowActiveHost, 11)
            .unwrap();
        assert_eq!(pending.state(), DeviceRouteUpdateState::PersistencePending);
        assert_eq!(store.load().unwrap().unwrap().device_route_revision, 2);
        store.set_failure(false);
        let aborted = manager
            .abort_selected_device_route_update(&store, 12)
            .unwrap();
        assert_eq!(aborted.state(), DeviceRouteUpdateState::Committed);
        assert_eq!(aborted.committed_revision(), 1);
        assert_eq!(store.load().unwrap().unwrap().device_route_revision, 1);
    }

    #[test]
    fn workspace_attachment_is_pre_session_and_selects_the_only_routing_handle() {
        let mut manager = manager(DIAL_PEER);
        let workspace = manager.workspace.take().unwrap();
        assert!(matches!(
            manager.selected_routing_handle(),
            Err(PeerManagerError::WorkspaceRequired)
        ));
        let pending = manager
            .peers
            .get_mut(&DIAL_PEER)
            .unwrap()
            .supervisor
            .begin_pending(ConnectionDirection::Outbound)
            .unwrap();
        let generation = pending.generation();
        manager.peers.get_mut(&DIAL_PEER).unwrap().task = PeerTaskSlot::Session { generation };
        assert!(matches!(
            manager.attach_workspace_control(workspace),
            Err(PeerManagerError::InvalidIdentity)
        ));
        manager
            .peers
            .get_mut(&DIAL_PEER)
            .unwrap()
            .supervisor
            .cancel_pending(pending)
            .unwrap();
        manager.peers.get_mut(&DIAL_PEER).unwrap().task = PeerTaskSlot::Idle;

        let replacement = self::manager(DIAL_PEER).workspace.unwrap();
        manager.attach_workspace_control(replacement).unwrap();
        let selected = manager.selected_routing_handle().unwrap().load();
        assert_eq!(selected.workspace.active_host, LOCAL_HOST);
        assert!(!selected.handoff_pending);
    }

    #[test]
    fn selected_capture_waits_for_fresh_inventory_and_queues_after_commit() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());

        let gated =
            manager.route_selected_capture(captured_key(1, KeyCode::KeyB, KeyState::Pressed), 1);
        assert_eq!(gated.disposition(), CaptureDisposition::AllowLocal);
        assert_eq!(gated.state(), SelectedCaptureState::Local);

        activate_selected(&mut manager);
        outbound.clear();
        commit_selected_pointer(&mut manager, &outbound, 3);
        let routed =
            manager.route_selected_capture(captured_key(2, KeyCode::KeyA, KeyState::Pressed), 5);
        assert_eq!(routed.disposition(), CaptureDisposition::SuppressLocal);
        assert_eq!(routed.state(), SelectedCaptureState::RemoteQueued);

        let messages = outbound.messages();
        let commit = messages
            .iter()
            .position(|message| matches!(message, WireMessage::PointerTransitionCommit(_)))
            .unwrap();
        let input = messages
            .iter()
            .position(|message| matches!(message, WireMessage::Input(_)))
            .unwrap();
        assert!(
            commit < input,
            "Commit must precede selected Input in the FIFO"
        );
    }

    #[test]
    fn new_manager_requires_explicit_running_native_capture_health() {
        let managed =
            managed_peer_with_outbound(LOCAL_PEER, DIAL_PEER, 11, TestOutbound::default());
        let mut candidate =
            PeerManager::new(LOCAL_PEER, [managed], PeerManagerConfig::default()).unwrap();
        let plane = manager(DIAL_PEER).workspace.take().unwrap();
        candidate.attach_workspace_control(plane).unwrap();

        let unavailable =
            candidate.route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 1);
        assert_eq!(unavailable.disposition(), CaptureDisposition::AllowLocal);
        assert_eq!(unavailable.state(), SelectedCaptureState::Rejected);
        assert!(candidate
            .rearm_native_capture(CaptureLifecycleState::Unknown)
            .is_err());
        candidate
            .rearm_native_capture(CaptureLifecycleState::Running)
            .unwrap();
    }

    #[test]
    fn capture_during_pending_activation_preserves_the_exact_session_slot() {
        let mut manager = manager(DIAL_PEER);
        let pending = manager
            .peers
            .get_mut(&DIAL_PEER)
            .unwrap()
            .supervisor
            .begin_pending(ConnectionDirection::Outbound)
            .unwrap();
        let generation = pending.generation();
        manager.peers.get_mut(&DIAL_PEER).unwrap().task = PeerTaskSlot::Session { generation };

        let outcome =
            manager.route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 1);

        assert_eq!(outcome.disposition(), CaptureDisposition::AllowLocal);
        assert_eq!(outcome.state(), SelectedCaptureState::Gated);
        let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
        assert_eq!(peer.task, PeerTaskSlot::Session { generation });
        assert_eq!(peer.supervisor.pending_generation(), Some(generation));
        peer.supervisor.cancel_pending(pending).unwrap();
    }

    #[test]
    fn native_capture_discontinuity_gates_before_releasing_remote_holds() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        commit_selected_pointer(&mut manager, &outbound, 3);
        outbound.clear();

        assert_eq!(
            manager
                .route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 5)
                .state(),
            SelectedCaptureState::RemoteQueued
        );
        manager.native_capture_discontinued(6).unwrap();
        assert!(outbound
            .messages()
            .iter()
            .any(|message| matches!(message, WireMessage::ReleaseInput(_))));

        let delayed =
            manager.route_selected_capture(captured_key(2, KeyCode::KeyB, KeyState::Pressed), 7);
        assert_eq!(delayed.disposition(), CaptureDisposition::AllowLocal);
        assert_eq!(delayed.state(), SelectedCaptureState::Rejected);

        assert!(manager
            .rearm_native_capture(CaptureLifecycleState::Unknown)
            .is_err());
        manager
            .rearm_native_capture(CaptureLifecycleState::Running)
            .unwrap();
        let rearmed =
            manager.route_selected_capture(captured_key(3, KeyCode::KeyB, KeyState::Pressed), 8);
        assert_eq!(rearmed.disposition(), CaptureDisposition::AllowLocal);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn destination_ack_barrier_orders_release_and_duplicate_enter_does_not_reopen_it() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        commit_selected_pointer(&mut manager, &outbound, 3);
        outbound.clear();

        assert_eq!(
            manager
                .route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 5)
                .state(),
            SelectedCaptureState::RemoteQueued
        );
        let epoch = manager
            .workspace
            .as_ref()
            .unwrap()
            .pointer()
            .unwrap()
            .protocol_epoch();
        let leave = PointerLeaveV1 {
            transition_id: 1,
            workspace_epoch: epoch,
            sequence: 1,
            source_host: WireHostId(REMOTE_HOST.into_bytes()),
            source_display: WireDisplayId(REMOTE_DISPLAY.into_bytes()),
            edge: WireEdge::Left,
            normalized_position: 0.5,
        };
        let enter = PointerEnterV1 {
            transition_id: 1,
            workspace_epoch: epoch,
            sequence: 1,
            source_host: WireHostId(REMOTE_HOST.into_bytes()),
            destination_host: WireHostId(LOCAL_HOST.into_bytes()),
            source_display: WireDisplayId(REMOTE_DISPLAY.into_bytes()),
            destination_display: WireDisplayId(DISPLAY.into_bytes()),
            destination_edge: WireEdge::Right,
            normalized_position: 0.5,
        };
        {
            let workspace = manager.workspace.as_mut().unwrap();
            let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
            peer.supervisor
                .apply_workspace_test_message(workspace, WireMessage::PointerLeave(leave), 6)
                .unwrap();
            peer.supervisor
                .apply_workspace_test_message(workspace, WireMessage::PointerEnter(enter), 7)
                .unwrap();
        }

        let messages = outbound.messages();
        let input = messages
            .iter()
            .position(|message| matches!(message, WireMessage::Input(_)))
            .unwrap();
        let release = messages
            .iter()
            .position(|message| matches!(message, WireMessage::ReleaseInput(_)))
            .unwrap();
        let ack = messages
            .iter()
            .position(|message| {
                matches!(
                    message,
                    WireMessage::PointerTransitionAck(PointerTransitionAckV1 {
                        outcome: PointerTransitionOutcomeV1::Accepted,
                        ..
                    })
                )
            })
            .unwrap();
        assert!(input < release && release < ack);

        {
            let workspace = manager.workspace.as_mut().unwrap();
            let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
            peer.supervisor
                .apply_workspace_test_message(
                    workspace,
                    WireMessage::PointerTransitionCommit(PointerTransitionCommitV1 {
                        transition_id: 1,
                        workspace_epoch: epoch,
                        sequence: 1,
                        source_host: WireHostId(REMOTE_HOST.into_bytes()),
                        destination_host: WireHostId(LOCAL_HOST.into_bytes()),
                        source_display: WireDisplayId(REMOTE_DISPLAY.into_bytes()),
                        destination_display: WireDisplayId(DISPLAY.into_bytes()),
                    }),
                    8,
                )
                .unwrap();
        }
        let routing = manager.selected_routing_handle().unwrap().load();
        assert_eq!(routing.workspace.active_host, LOCAL_HOST);
        assert!(!routing.handoff_pending);
        let physical_release =
            manager.route_selected_capture(captured_key(2, KeyCode::KeyA, KeyState::Released), 9);
        assert_eq!(
            physical_release.disposition(),
            CaptureDisposition::SuppressLocal
        );

        let before_duplicate = outbound.messages().len();
        {
            let workspace = manager.workspace.as_mut().unwrap();
            let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
            peer.supervisor
                .apply_workspace_test_message(workspace, WireMessage::PointerEnter(enter), 10)
                .unwrap();
        }
        let routing = manager.selected_routing_handle().unwrap().load();
        assert!(!routing.handoff_pending);
        assert_eq!(outbound.messages().len(), before_duplicate + 1);
    }

    #[test]
    fn selected_capture_preserves_press_repeat_release_wire_states() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        commit_selected_pointer(&mut manager, &outbound, 3);
        outbound.clear();

        for (sequence, state) in [
            (1, KeyState::Pressed),
            (2, KeyState::Repeated),
            (3, KeyState::Released),
        ] {
            assert_eq!(
                manager
                    .route_selected_capture(
                        captured_key(sequence, KeyCode::KeyA, state),
                        4 + sequence,
                    )
                    .state(),
                SelectedCaptureState::RemoteQueued
            );
        }
        let states: Vec<_> = outbound
            .messages()
            .into_iter()
            .filter_map(|message| match message {
                WireMessage::Input(input) => match input.payload {
                    WireInputPayloadV1::Key { state, .. } => Some(state),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(
            states,
            [WireKeyState::Down, WireKeyState::Repeat, WireKeyState::Up]
        );
    }

    #[test]
    fn handoff_failsafe_is_synchronous_local_and_never_queues_input() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        outbound.clear();
        manager
            .propose_pointer_handoff(Edge::Right, 0.5, 3)
            .unwrap();

        for (sequence, key) in [
            (1, KeyCode::ControlLeft),
            (2, KeyCode::AltLeft),
            (3, KeyCode::ShiftLeft),
        ] {
            let outcome = manager.route_selected_capture(
                captured_key(sequence, key, KeyState::Pressed),
                10 + sequence,
            );
            assert_eq!(outcome.state(), SelectedCaptureState::Inert);
        }
        let escape = manager
            .route_selected_capture(captured_key(4, KeyCode::Backspace, KeyState::Pressed), 14);
        assert_eq!(escape.disposition(), CaptureDisposition::AllowLocal);
        assert!(escape.failsafe_activated());
        assert!(!outbound
            .messages()
            .iter()
            .any(|message| matches!(message, WireMessage::Input(_))));

        for (sequence, key) in [
            (5, KeyCode::ControlLeft),
            (6, KeyCode::AltLeft),
            (7, KeyCode::ShiftLeft),
            (8, KeyCode::Backspace),
        ] {
            assert_eq!(
                manager
                    .route_selected_capture(
                        captured_key(sequence, key, KeyState::Released),
                        20 + sequence,
                    )
                    .disposition(),
                CaptureDisposition::AllowLocal
            );
        }
        assert!(manager.selected_lifecycle_tick(10_000_000_100).unwrap());
        let snapshot = manager.selected_routing_handle().unwrap().load();
        assert!(snapshot.enabled);
        assert_eq!(snapshot.workspace.active_host, LOCAL_HOST);
    }

    #[test]
    fn failed_repeat_stays_suppressed_and_blocks_replacement_until_retry() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        commit_selected_pointer(&mut manager, &outbound, 3);
        assert_eq!(
            manager
                .route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 5,)
                .state(),
            SelectedCaptureState::RemoteQueued
        );

        // One failure rejects the repeat and one blocks the first graceful
        // workspace-release attempt. The explicit reconciliation retry owns
        // the next attempt; the supervisor no longer spins multiple cleanup
        // sends inside a single call.
        outbound.fail_times(2, OutboundPeerError::Full);
        let failed =
            manager.route_selected_capture(captured_key(2, KeyCode::KeyA, KeyState::Pressed), 6);
        assert_eq!(failed.disposition(), CaptureDisposition::SuppressLocal);
        assert_eq!(failed.state(), SelectedCaptureState::Inert);
        assert!(manager.peers[&DIAL_PEER]
            .supervisor
            .active_generation()
            .is_some());

        assert!(matches!(
            manager.retry_reconciliation(DIAL_PEER, 7).unwrap(),
            SupervisorEventOutcome::Retired(_)
        ));
        assert_eq!(manager.peers[&DIAL_PEER].task, PeerTaskSlot::Idle);
    }

    #[test]
    fn actual_transport_loss_settles_a_closed_cleanup_fifo_and_retires() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        commit_selected_pointer(&mut manager, &outbound, 3);
        assert_eq!(
            manager
                .route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 5)
                .state(),
            SelectedCaptureState::RemoteQueued
        );
        let generation = manager.peers[&DIAL_PEER]
            .supervisor
            .active_generation()
            .unwrap();
        outbound.fail_times(1, OutboundPeerError::Closed);

        assert!(matches!(
            manager.connection_lost(DIAL_PEER, generation, 6).unwrap(),
            SupervisorEventOutcome::Retired(_)
        ));
        assert!(manager.peers[&DIAL_PEER]
            .supervisor
            .active_generation()
            .is_none());
        assert_eq!(manager.peers[&DIAL_PEER].task, PeerTaskSlot::Idle);
    }

    #[test]
    fn terminal_injection_cleanup_failure_retries_without_session_authority() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound);
        activate_selected(&mut manager);
        let generation = manager.peers[&DIAL_PEER]
            .supervisor
            .active_generation()
            .unwrap();
        {
            let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
            peer.supervisor
                .test_hold_inbound(
                    InputEvent::new(
                        1,
                        1,
                        REMOTE_HOST,
                        DEVICE,
                        InputPayload::Key {
                            code: KeyCode::KeyA,
                            state: KeyState::Pressed,
                        },
                    ),
                    4,
                )
                .unwrap();
            peer.supervisor.test_injection_mut().fail_times(1);
        }

        assert!(manager.connection_lost(DIAL_PEER, generation, 5).is_err());
        assert_eq!(
            manager.peers[&DIAL_PEER].supervisor.active_generation(),
            Some(generation)
        );
        {
            let workspace = manager.workspace.as_mut().unwrap();
            let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
            assert!(matches!(
                peer.supervisor.apply_workspace_test_state(
                    workspace,
                    kvm_network::ConnectionState::Connected,
                    6,
                ),
                Err(PeerSessionSupervisorError::Unavailable)
            ));
        }

        assert!(matches!(
            manager.retry_reconciliation(DIAL_PEER, 7).unwrap(),
            SupervisorEventOutcome::Retired(_)
        ));
        assert_eq!(manager.peers[&DIAL_PEER].task, PeerTaskSlot::Idle);
    }

    #[test]
    fn disconnected_state_hint_retains_cleanup_authority_until_retry() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound);
        activate_selected(&mut manager);
        let generation = manager.peers[&DIAL_PEER]
            .supervisor
            .active_generation()
            .unwrap();
        {
            let workspace = manager.workspace.as_mut().unwrap();
            let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
            peer.supervisor
                .test_hold_inbound(
                    InputEvent::new(
                        1,
                        1,
                        REMOTE_HOST,
                        DEVICE,
                        InputPayload::Key {
                            code: KeyCode::KeyA,
                            state: KeyState::Pressed,
                        },
                    ),
                    4,
                )
                .unwrap();
            peer.supervisor.test_injection_mut().fail_times(3);

            assert!(peer
                .supervisor
                .apply_workspace_test_state(
                    workspace,
                    kvm_network::ConnectionState::Disconnected,
                    5,
                )
                .is_err());
            assert_eq!(peer.supervisor.active_generation(), Some(generation));
        }

        assert!(matches!(
            manager.retry_reconciliation(DIAL_PEER, 6).unwrap(),
            SupervisorEventOutcome::Retired(_)
        ));
        assert_eq!(manager.peers[&DIAL_PEER].task, PeerTaskSlot::Idle);
    }

    #[test]
    fn degraded_selected_session_resyncs_before_control_delivery() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        outbound.clear();
        let workspace = manager.workspace.as_mut().unwrap();
        let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();

        assert!(matches!(
            peer.supervisor
                .apply_workspace_test_state(workspace, kvm_network::ConnectionState::Degraded, 4,)
                .unwrap(),
            SupervisorEventOutcome::Applied(_)
        ));
        assert!(matches!(
            peer.supervisor
                .apply_workspace_test_state(workspace, kvm_network::ConnectionState::Connected, 5,)
                .unwrap(),
            SupervisorEventOutcome::Applied(_)
        ));
        assert_eq!(
            outbound
                .messages()
                .iter()
                .filter(|message| matches!(message, WireMessage::DeviceSnapshot(_)))
                .count(),
            1
        );
        assert!(peer.supervisor.active_generation().is_some());
    }

    #[test]
    fn protocol_failure_with_settled_inner_cleanup_retires_workspace_metadata() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound);
        activate_selected(&mut manager);
        let workspace = manager.workspace.as_mut().unwrap();
        let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
        let outcome = peer
            .supervisor
            .apply_workspace_test_protocol_failure(
                workspace,
                WireMessage::Input(InputEventV1 {
                    sequence: 1,
                    timestamp_ns: 1,
                    source_host: WireHostId([99; 16]),
                    source_device: WireDeviceId(DEVICE.into_bytes()),
                    payload: WireInputPayloadV1::PointerMove { dx: 1.0, dy: 0.0 },
                }),
                6,
            )
            .unwrap();

        assert!(matches!(outcome, SupervisorEventOutcome::Retired(_)));
        assert!(peer.supervisor.active_generation().is_none());
        assert!(peer
            .supervisor
            .begin_pending(kvm_network::ConnectionDirection::Outbound)
            .is_ok());
    }

    #[test]
    fn manual_selected_candidate_uses_the_exact_affine_outbound_path() {
        let mut manager = manager(DIAL_PEER);
        let address = LanPeerAddress::new("10.0.0.2:24800".parse().unwrap()).unwrap();

        manager
            .replace_selected_outbound_candidate(DIAL_PEER, address)
            .unwrap();
        let task = manager.poll_outbound(Duration::ZERO).unwrap().unwrap();

        assert_eq!(task.peer_id(), DIAL_PEER);
        assert_eq!(task.address(), address);
        assert_eq!(
            task.expected_identity(),
            &transport_identity(&manager.peers.get(&DIAL_PEER).unwrap().identity)
        );
        assert_eq!(manager.snapshot().connecting_tasks, 1);
    }

    #[test]
    fn manual_candidate_rejects_a_paired_but_nonselected_peer() {
        let workspace = manager(DIAL_PEER).workspace.unwrap();
        let mut manager = PeerManager::new(
            LOCAL_PEER,
            [
                managed_peer(LOCAL_PEER, DIAL_PEER, 11),
                managed_peer(LOCAL_PEER, LISTEN_PEER, 12),
            ],
            PeerManagerConfig::default(),
        )
        .unwrap();
        manager.attach_workspace_control(workspace).unwrap();
        let address = LanPeerAddress::new("10.0.0.2:24800".parse().unwrap()).unwrap();

        assert!(matches!(
            manager.replace_selected_outbound_candidate(LISTEN_PEER, address),
            Err(PeerManagerError::PeerRejected)
        ));
        assert_eq!(manager.snapshot().peers_with_candidates, 0);
    }

    #[test]
    fn manual_candidate_rejects_occupied_revoked_and_shutdown_peers_without_mutation() {
        let first = LanPeerAddress::new("10.0.0.2:24800".parse().unwrap()).unwrap();
        let replacement = LanPeerAddress::new("10.0.0.3:24800".parse().unwrap()).unwrap();

        let mut connecting = manager(DIAL_PEER);
        connecting
            .replace_selected_outbound_candidate(DIAL_PEER, first)
            .unwrap();
        let task = connecting.poll_outbound(Duration::ZERO).unwrap().unwrap();
        assert!(matches!(
            connecting.replace_selected_outbound_candidate(DIAL_PEER, replacement),
            Err(PeerManagerError::PeerRejected)
        ));
        connecting
            .outbound_task_lost(&task, Duration::ZERO)
            .unwrap();
        assert_eq!(
            connecting
                .poll_outbound(Duration::from_secs(1))
                .unwrap()
                .unwrap()
                .address(),
            first
        );

        let mut pending = manager(DIAL_PEER);
        pending
            .replace_selected_outbound_candidate(DIAL_PEER, first)
            .unwrap();
        let pending_capability = pending
            .peers
            .get_mut(&DIAL_PEER)
            .unwrap()
            .supervisor
            .begin_pending(ConnectionDirection::Outbound)
            .unwrap();
        let generation = pending_capability.generation();
        pending.peers.get_mut(&DIAL_PEER).unwrap().task = PeerTaskSlot::Session { generation };
        assert!(matches!(
            pending.replace_selected_outbound_candidate(DIAL_PEER, replacement),
            Err(PeerManagerError::PeerRejected)
        ));
        assert_eq!(
            pending.peers.get(&DIAL_PEER).unwrap().candidates,
            BTreeSet::from([first])
        );
        pending
            .peers
            .get_mut(&DIAL_PEER)
            .unwrap()
            .supervisor
            .cancel_pending(pending_capability)
            .unwrap();

        let mut active = manager(DIAL_PEER);
        active
            .replace_selected_outbound_candidate(DIAL_PEER, first)
            .unwrap();
        activate_selected(&mut active);
        assert!(matches!(
            active.replace_selected_outbound_candidate(DIAL_PEER, replacement),
            Err(PeerManagerError::PeerRejected)
        ));
        assert_eq!(
            active.peers.get(&DIAL_PEER).unwrap().candidates,
            BTreeSet::from([first])
        );

        let mut revoked = manager(DIAL_PEER);
        revoked.revoke(DIAL_PEER, 0).unwrap();
        assert!(matches!(
            revoked.replace_selected_outbound_candidate(DIAL_PEER, replacement),
            Err(PeerManagerError::PeerRejected)
        ));
        assert_eq!(revoked.snapshot().peers_with_candidates, 0);

        let mut shutdown = manager(DIAL_PEER);
        shutdown.shutdown(0).unwrap();
        assert!(matches!(
            shutdown.replace_selected_outbound_candidate(DIAL_PEER, replacement),
            Err(PeerManagerError::PeerRejected)
        ));
        assert_eq!(shutdown.snapshot().peers_with_candidates, 0);
    }

    #[test]
    fn manual_candidate_replacement_is_transactional() {
        let mut manager = manager(DIAL_PEER);
        let first = LanPeerAddress::new("10.0.0.2:24800".parse().unwrap()).unwrap();
        let replacement = LanPeerAddress::new("10.0.0.3:24800".parse().unwrap()).unwrap();

        manager
            .replace_selected_outbound_candidate(DIAL_PEER, first)
            .unwrap();
        manager
            .replace_selected_outbound_candidate(DIAL_PEER, replacement)
            .unwrap();
        assert_eq!(
            manager
                .poll_outbound(Duration::ZERO)
                .unwrap()
                .unwrap()
                .address(),
            replacement
        );
    }

    #[test]
    fn manual_candidate_replacement_does_not_bypass_failure_backoff() {
        let mut manager = manager(DIAL_PEER);
        let first = LanPeerAddress::new("10.0.0.2:24800".parse().unwrap()).unwrap();
        let replacement = LanPeerAddress::new("10.0.0.3:24800".parse().unwrap()).unwrap();

        manager
            .replace_selected_outbound_candidate(DIAL_PEER, first)
            .unwrap();
        let task = manager.poll_outbound(Duration::ZERO).unwrap().unwrap();
        manager.outbound_failed(task, Duration::ZERO).unwrap();
        manager
            .replace_selected_outbound_candidate(DIAL_PEER, replacement)
            .unwrap();

        assert!(manager
            .poll_outbound(Duration::from_millis(999))
            .unwrap()
            .is_none());
        assert_eq!(
            manager
                .poll_outbound(Duration::from_secs(1))
                .unwrap()
                .unwrap()
                .address(),
            replacement
        );
    }

    #[test]
    fn graceful_cleanup_retries_an_exact_partially_sent_suffix() {
        for failure in [OutboundPeerError::Full, OutboundPeerError::Closed] {
            let outbound = TestOutbound::default();
            let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
            activate_selected(&mut manager);
            commit_selected_pointer(&mut manager, &outbound, 3);
            for (sequence, key) in [(1, KeyCode::KeyA), (2, KeyCode::KeyB)] {
                assert_eq!(
                    manager
                        .route_selected_capture(
                            captured_key(sequence, key, KeyState::Pressed),
                            4 + sequence,
                        )
                        .state(),
                    SelectedCaptureState::RemoteQueued
                );
            }
            outbound.clear();
            // Accept the first release, retain the exact failed suffix, then
            // let the explicit reconciliation retry enqueue that suffix.
            outbound.fail_after(1, 1, failure);

            assert!(manager.revoke(DIAL_PEER, 7).is_err());
            assert!(manager.peers[&DIAL_PEER]
                .supervisor
                .active_generation()
                .is_some());
            assert_eq!(
                outbound
                    .messages()
                    .iter()
                    .filter(|message| matches!(message, WireMessage::ReleaseInput(_)))
                    .count(),
                1
            );

            assert!(matches!(
                manager.retry_reconciliation(DIAL_PEER, 8).unwrap(),
                SupervisorEventOutcome::Retired(_)
            ));
            assert_eq!(
                outbound
                    .messages()
                    .iter()
                    .filter(|message| matches!(message, WireMessage::ReleaseInput(_)))
                    .count(),
                2
            );
        }
    }

    #[test]
    fn stale_manager_session_slot_never_dispatches_selected_input() {
        let outbound = TestOutbound::default();
        let mut manager = manager_with_outbound(DIAL_PEER, outbound.clone());
        activate_selected(&mut manager);
        commit_selected_pointer(&mut manager, &outbound, 3);
        outbound.clear();
        manager.peers.get_mut(&DIAL_PEER).unwrap().task = PeerTaskSlot::Idle;

        let outcome =
            manager.route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 5);
        assert_eq!(outcome.disposition(), CaptureDisposition::AllowLocal);
        assert_eq!(outcome.state(), SelectedCaptureState::SessionRetired);
        assert!(!outbound
            .messages()
            .iter()
            .any(|message| matches!(message, WireMessage::Input(_))));
        assert!(manager.peers[&DIAL_PEER]
            .supervisor
            .active_generation()
            .is_none());
    }

    #[test]
    fn selected_capture_diagnostics_are_payload_and_identity_redacted() {
        let outcome = SelectedCaptureOutcome {
            disposition: CaptureDisposition::AllowLocal,
            failsafe_activated: true,
            state: SelectedCaptureState::Gated,
        };
        let rendered = format!("{outcome:?}");
        for marker in [
            LOCAL_HOST.to_string(),
            DEVICE.to_string(),
            "KeyA".to_owned(),
        ] {
            assert!(!rendered.contains(&marker));
        }
    }

    #[test]
    fn selected_capture_preserves_local_and_exact_peer_pins_during_handoff() {
        let (mut local, _) = manager_with_configured_route(ConfiguredDeviceRoute::Local);
        activate_selected(&mut local);
        assert_eq!(
            local
                .route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 3,)
                .disposition(),
            CaptureDisposition::AllowLocal
        );

        let (mut pinned, outbound) = manager_with_configured_route(ConfiguredDeviceRoute::Host {
            host_id: REMOTE_HOST,
        });
        activate_selected(&mut pinned);
        assert_eq!(
            pinned
                .route_selected_capture(captured_key(1, KeyCode::KeyA, KeyState::Pressed), 3,)
                .state(),
            SelectedCaptureState::RemoteQueued
        );
        pinned.propose_pointer_handoff(Edge::Right, 0.5, 4).unwrap();
        assert_eq!(
            pinned
                .route_selected_capture(captured_key(2, KeyCode::KeyB, KeyState::Pressed), 5,)
                .state(),
            SelectedCaptureState::RemoteQueued
        );
        assert_eq!(
            outbound
                .messages()
                .iter()
                .filter(|message| matches!(message, WireMessage::Input(_)))
                .count(),
            2
        );
    }

    #[test]
    fn selected_workspace_rejects_a_third_host_device_route() {
        let selected_identity = identity(DIAL_PEER, 11);
        let third_host = HostId::from_bytes([31; 16]);
        let third_peer = PeerId::from_bytes([32; 16]);
        let mut config = Config::default();
        config.paired_hosts.push(PairedHostConfig {
            host_id: REMOTE_HOST,
            peer_id: DIAL_PEER,
            name: "selected".into(),
            platform: Platform::Windows,
            identity_fingerprint: selected_identity.fingerprint().to_string(),
            last_address: None,
        });
        config.paired_hosts.push(PairedHostConfig {
            host_id: third_host,
            peer_id: third_peer,
            name: "third".into(),
            platform: Platform::MacOS,
            identity_fingerprint: IdentityFingerprint::from_sha256([32; 32]).to_string(),
            last_address: None,
        });
        config.device_routes.push(DeviceRouteConfig {
            device_id: DEVICE,
            route: ConfiguredDeviceRoute::Host {
                host_id: third_host,
            },
        });
        let initial = WorkspaceState::new(
            LOCAL_HOST,
            LOCAL_HOST,
            LogicalPointer::new(DISPLAY, 0.0, 0.0),
        );
        let coordinator = PeerSessionCoordinator::new(
            DaemonCore::new(config, initial).unwrap(),
            selected_identity.clone(),
            TestInjection::default(),
            TestOutbound::default(),
        )
        .unwrap();
        let gate = ConnectionGenerationGate::new(
            WirePeerId(LOCAL_PEER.into_bytes()),
            WirePeerId(DIAL_PEER.into_bytes()),
        )
        .unwrap();
        let managed = ManagedPairedPeer::new(
            &PairedPeer::from_persisted_public_identity(selected_identity),
            PeerSessionSupervisor::new(gate, coordinator),
        );
        let mut candidate =
            PeerManager::new(LOCAL_PEER, [managed], PeerManagerConfig::default()).unwrap();
        let plane = manager(DIAL_PEER).workspace.unwrap();
        assert!(matches!(
            candidate.attach_workspace_control(plane),
            Err(PeerManagerError::InvalidIdentity)
        ));
    }

    #[test]
    fn runtime_topology_replacement_clears_pending_and_invalid_candidate_is_transactional() {
        let mut manager = manager(DIAL_PEER);
        activate_selected(&mut manager);
        let generation = manager.peers[&DIAL_PEER]
            .supervisor
            .active_generation()
            .unwrap();

        manager
            .propose_pointer_handoff(Edge::Right, 0.5, 3)
            .unwrap();
        assert!(manager
            .workspace
            .as_ref()
            .unwrap()
            .pointer()
            .unwrap()
            .next_deadline_ns()
            .is_some());

        manager
            .replace_workspace_topology(
                vec![
                    WorkspacePlacement::new(DISPLAY, Point::new(0.0, 0.0)),
                    WorkspacePlacement::new(REMOTE_DISPLAY, Point::new(100.0, 0.0)),
                ],
                vec![WorkspaceLink::new(
                    DISPLAY,
                    Edge::Right,
                    REMOTE_DISPLAY,
                    Edge::Left,
                )],
                4,
            )
            .unwrap();
        assert!(manager
            .workspace
            .as_ref()
            .unwrap()
            .pointer()
            .unwrap()
            .next_deadline_ns()
            .is_none());
        assert_eq!(
            manager.peers[&DIAL_PEER].supervisor.active_generation(),
            Some(generation)
        );

        let epoch = manager
            .workspace
            .as_ref()
            .unwrap()
            .pointer()
            .unwrap()
            .workspace_epoch();
        let invalid = vec![
            WorkspacePlacement::new(DISPLAY, Point::new(0.0, 0.0)),
            WorkspacePlacement::new(DISPLAY, Point::new(50.0, 0.0)),
        ];
        assert!(matches!(
            manager.replace_workspace_topology(invalid, Vec::new(), 5),
            Err(PeerManagerError::Supervisor(
                PeerSessionSupervisorError::Workspace(_)
            ))
        ));
        assert_eq!(
            manager
                .workspace
                .as_ref()
                .unwrap()
                .pointer()
                .unwrap()
                .workspace_epoch(),
            epoch
        );
        assert_eq!(
            manager.peers[&DIAL_PEER].supervisor.active_generation(),
            Some(generation)
        );
    }

    #[test]
    fn local_revision_recompiles_from_current_inventory_and_keeps_exact_session() {
        let mut manager = manager(DIAL_PEER);
        activate_selected(&mut manager);
        let generation = manager.peers[&DIAL_PEER]
            .supervisor
            .active_generation()
            .unwrap();

        manager
            .apply_local_display_update(2, local_display("renamed"), 3)
            .unwrap();

        assert_eq!(
            manager
                .workspace
                .as_ref()
                .unwrap()
                .inventory()
                .snapshot()
                .host(LOCAL_HOST)
                .unwrap()
                .revision(),
            2
        );
        assert_eq!(
            manager.peers[&DIAL_PEER].supervisor.active_generation(),
            Some(generation)
        );
        assert!(manager.workspace.as_ref().unwrap().pointer().is_some());
    }

    #[test]
    fn pointer_timeout_retires_exact_session_and_restores_selected_routing_local() {
        let mut manager = manager(DIAL_PEER);
        activate_selected(&mut manager);
        manager
            .propose_pointer_handoff(Edge::Right, 0.5, 3)
            .unwrap();

        assert!(matches!(
            manager.selected_lifecycle_tick(1_000_000_003),
            Err(PeerManagerError::Supervisor(_))
        ));
        assert_eq!(
            manager.peers[&DIAL_PEER].supervisor.active_generation(),
            None
        );
        assert_eq!(manager.peers[&DIAL_PEER].task, PeerTaskSlot::Idle);
        let snapshot = manager.selected_routing_handle().unwrap().load();
        assert_eq!(snapshot.workspace.active_host, LOCAL_HOST);
        assert!(!snapshot.handoff_pending);
    }

    #[test]
    fn stale_delayed_commit_is_fatal_and_releases_manager_slot() {
        let mut manager = manager(DIAL_PEER);
        activate_selected(&mut manager);
        let epoch = manager
            .workspace
            .as_ref()
            .unwrap()
            .pointer()
            .unwrap()
            .workspace_epoch()
            .get();
        let result = {
            let workspace = manager.workspace.as_mut().unwrap();
            let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
            peer.supervisor.apply_workspace_test_message(
                workspace,
                WireMessage::PointerTransitionCommit(PointerTransitionCommitV1 {
                    transition_id: 1,
                    workspace_epoch: epoch,
                    sequence: 1,
                    source_host: WireHostId(REMOTE_HOST.into_bytes()),
                    destination_host: WireHostId(LOCAL_HOST.into_bytes()),
                    source_display: WireDisplayId(REMOTE_DISPLAY.into_bytes()),
                    destination_display: WireDisplayId(DISPLAY.into_bytes()),
                }),
                4,
            )
        };
        assert!(result.is_err());
        let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
        assert!(settle_bound_event_result(
            peer,
            GenerationBoundEventClassification::Active,
            result.map(SupervisorEventOutcome::Applied),
            4,
        )
        .is_err());
        assert_eq!(peer.supervisor.active_generation(), None);
        assert_eq!(peer.task, PeerTaskSlot::Idle);
        assert_eq!(peer.backoff.attempts(), 1);
    }

    #[test]
    fn typed_discovery_snapshot_schedules_only_a_paired_canonical_dialer() {
        let mut scheduler = manager(DIAL_PEER);
        scheduler
            .apply_discovery_snapshot(&snapshot(
                DIAL_PEER,
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
            ))
            .unwrap();

        let task = scheduler.poll_outbound(Duration::ZERO).unwrap().unwrap();
        assert_eq!(task.peer_id(), DIAL_PEER);
        assert_eq!(scheduler.snapshot().connecting_tasks, 1);
        assert!(scheduler.poll_outbound(Duration::ZERO).unwrap().is_none());

        let mut listener = manager(LISTEN_PEER);
        listener
            .apply_discovery_snapshot(&snapshot(
                LISTEN_PEER,
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))],
            ))
            .unwrap();
        assert!(listener.poll_outbound(Duration::ZERO).unwrap().is_none());
    }

    #[test]
    fn unknown_discovery_identity_is_not_an_authorization_source() {
        let mut manager = manager(DIAL_PEER);
        manager
            .apply_discovery_snapshot(&snapshot(
                UNKNOWN_PEER,
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))],
            ))
            .unwrap();

        assert!(manager.poll_outbound(Duration::ZERO).unwrap().is_none());
        assert_eq!(manager.snapshot().peers_with_candidates, 0);
    }

    #[test]
    fn discovery_removal_does_not_cancel_an_existing_task() {
        let mut manager = manager(DIAL_PEER);
        manager
            .apply_discovery_snapshot(&snapshot(
                DIAL_PEER,
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
            ))
            .unwrap();
        let task = manager.poll_outbound(Duration::ZERO).unwrap().unwrap();

        manager
            .apply_discovery_snapshot(&DiscoverySnapshot::default())
            .unwrap();

        assert_eq!(manager.snapshot().connecting_tasks, 1);
        manager.outbound_failed(task, Duration::ZERO).unwrap();
        assert!(manager
            .poll_outbound(Duration::from_secs(9))
            .unwrap()
            .is_none());
    }

    #[test]
    fn failures_rotate_deterministic_candidates_and_enforce_backoff() {
        let mut manager = manager(DIAL_PEER);
        manager
            .apply_discovery_snapshot(&snapshot(
                DIAL_PEER,
                vec![
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                ],
            ))
            .unwrap();
        let first = manager.poll_outbound(Duration::ZERO).unwrap().unwrap();
        let first_address = first.address();
        manager.outbound_failed(first, Duration::ZERO).unwrap();

        assert!(manager
            .poll_outbound(Duration::from_millis(999))
            .unwrap()
            .is_none());
        let second = manager
            .poll_outbound(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_ne!(second.address(), first_address);
    }

    #[test]
    fn revoke_and_shutdown_cancel_connect_slots_and_reject_late_results() {
        let mut revoked = manager(DIAL_PEER);
        revoked
            .replace_candidates([(DIAL_PEER, "10.0.0.2:24800".parse().unwrap())])
            .unwrap();
        let task = revoked.poll_outbound(Duration::ZERO).unwrap().unwrap();
        revoked.revoke(DIAL_PEER, 0).unwrap();
        assert_eq!(revoked.snapshot().connecting_tasks, 0);
        assert!(matches!(
            revoked.outbound_failed(task, Duration::ZERO),
            Err(PeerManagerError::StaleTask)
        ));

        let mut shutdown = manager(DIAL_PEER);
        shutdown
            .replace_candidates([(DIAL_PEER, "10.0.0.2:24800".parse().unwrap())])
            .unwrap();
        let task = shutdown.poll_outbound(Duration::ZERO).unwrap().unwrap();
        shutdown.shutdown(0).unwrap();
        assert!(shutdown.poll_outbound(Duration::MAX).unwrap().is_none());
        assert!(matches!(
            shutdown.outbound_failed(task, Duration::ZERO),
            Err(PeerManagerError::StaleTask)
        ));
    }

    #[test]
    fn invalid_candidate_replacement_is_transactional_and_diagnostics_are_redacted() {
        let mut manager = manager(DIAL_PEER);
        manager
            .replace_candidates([(DIAL_PEER, "10.0.0.2:24800".parse().unwrap())])
            .unwrap();
        assert!(matches!(
            manager.replace_candidates([(DIAL_PEER, "8.8.8.8:24800".parse().unwrap())]),
            Err(PeerManagerError::InvalidCandidate)
        ));
        let rendered = format!("{manager:?}");
        assert!(!rendered.contains("10.0.0.2"));
        assert!(!rendered.contains(&"0b".repeat(32)));
        assert!(manager.poll_outbound(Duration::ZERO).unwrap().is_some());
    }

    #[test]
    fn manager_and_task_capabilities_do_not_cross_instances() {
        let mut first = manager(DIAL_PEER);
        first
            .replace_candidates([(DIAL_PEER, "10.0.0.2:24800".parse().unwrap())])
            .unwrap();
        let task = first.poll_outbound(Duration::ZERO).unwrap().unwrap();
        let mut second = manager(DIAL_PEER);

        assert!(matches!(
            second.outbound_failed(task, Duration::ZERO),
            Err(PeerManagerError::StaleTask)
        ));
    }

    #[test]
    fn lost_outbound_task_recovers_exact_connect_slot_with_backoff() {
        let mut manager = manager(DIAL_PEER);
        manager
            .replace_candidates([(DIAL_PEER, "10.0.0.2:24800".parse().unwrap())])
            .unwrap();
        let task = manager.poll_outbound(Duration::ZERO).unwrap().unwrap();

        manager.outbound_task_lost(&task, Duration::ZERO).unwrap();

        assert_eq!(manager.snapshot().connecting_tasks, 0);
        assert!(manager
            .poll_outbound(Duration::from_millis(999))
            .unwrap()
            .is_none());
        assert!(manager
            .poll_outbound(Duration::from_secs(1))
            .unwrap()
            .is_some());
    }

    #[test]
    fn stale_outbound_task_recovery_cannot_clear_a_newer_connect_slot() {
        let mut manager = manager(DIAL_PEER);
        manager
            .replace_candidates([(DIAL_PEER, "10.0.0.2:24800".parse().unwrap())])
            .unwrap();
        let stale = manager.poll_outbound(Duration::ZERO).unwrap().unwrap();
        manager.outbound_task_lost(&stale, Duration::ZERO).unwrap();
        let current = manager
            .poll_outbound(Duration::from_secs(1))
            .unwrap()
            .unwrap();

        assert!(matches!(
            manager.outbound_task_lost(&stale, Duration::from_secs(1)),
            Err(PeerManagerError::StaleTask)
        ));
        assert_eq!(manager.snapshot().connecting_tasks, 1);
        manager
            .outbound_task_lost(&current, Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn cross_manager_recovery_rejects_without_consuming_the_exact_task_token() {
        let mut issuing_manager = manager(DIAL_PEER);
        issuing_manager
            .replace_candidates([(DIAL_PEER, "10.0.0.2:24800".parse().unwrap())])
            .unwrap();
        let issued_task = issuing_manager
            .poll_outbound(Duration::ZERO)
            .unwrap()
            .unwrap();
        let mut other = manager(DIAL_PEER);
        other
            .replace_candidates([(DIAL_PEER, "10.0.0.3:24800".parse().unwrap())])
            .unwrap();
        let other_task = other.poll_outbound(Duration::ZERO).unwrap().unwrap();

        assert!(matches!(
            other.outbound_task_lost(&issued_task, Duration::ZERO),
            Err(PeerManagerError::StaleTask)
        ));
        assert_eq!(issuing_manager.snapshot().connecting_tasks, 1);
        assert_eq!(other.snapshot().connecting_tasks, 1);
        issuing_manager
            .outbound_task_lost(&issued_task, Duration::ZERO)
            .unwrap();
        other
            .outbound_task_lost(&other_task, Duration::ZERO)
            .unwrap();
    }

    #[test]
    fn lost_pending_runner_is_abandoned_and_replacement_can_begin() {
        let mut manager = manager(DIAL_PEER);
        let generation = {
            let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
            let pending = peer
                .supervisor
                .begin_pending(ConnectionDirection::Outbound)
                .unwrap();
            let generation = pending.generation();
            peer.task = PeerTaskSlot::Session { generation };
            generation
        };

        assert_eq!(
            manager
                .connection_task_lost(DIAL_PEER, generation, 0)
                .unwrap(),
            SupervisorEventOutcome::PendingCancelled
        );
        let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
        assert!(peer
            .supervisor
            .begin_pending(ConnectionDirection::Outbound)
            .is_ok());
    }

    #[test]
    fn stale_or_cross_manager_loss_report_cannot_cancel_current_pending() {
        let mut current = manager(DIAL_PEER);
        let peer = current.peers.get_mut(&DIAL_PEER).unwrap();
        let pending_capability = peer
            .supervisor
            .begin_pending(ConnectionDirection::Outbound)
            .unwrap();
        let current_generation = pending_capability.generation();
        peer.task = PeerTaskSlot::Session {
            generation: current_generation,
        };

        let mut other = manager(DIAL_PEER);
        let other_peer = other.peers.get_mut(&DIAL_PEER).unwrap();
        let other_pending_capability = other_peer
            .supervisor
            .begin_pending(ConnectionDirection::Outbound)
            .unwrap();
        let other_generation = other_pending_capability.generation();
        other_peer.task = PeerTaskSlot::Session {
            generation: other_generation,
        };

        assert_eq!(
            current
                .connection_task_lost(DIAL_PEER, other_generation, 0)
                .unwrap(),
            SupervisorEventOutcome::StaleIgnored
        );
        assert_eq!(
            current.peers[&DIAL_PEER].supervisor.active_generation(),
            None
        );
        assert!(matches!(
            current
                .peers
                .get_mut(&DIAL_PEER)
                .unwrap()
                .supervisor
                .begin_pending(ConnectionDirection::Outbound),
            Err(PeerSessionSupervisorError::Generation(_))
        ));
    }

    #[test]
    fn revoke_and_shutdown_abandon_pending_sessions_before_terminal_lifecycle() {
        for shutdown in [false, true] {
            let mut manager = manager(DIAL_PEER);
            let generation = {
                let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
                let pending = peer
                    .supervisor
                    .begin_pending(ConnectionDirection::Outbound)
                    .unwrap();
                let generation = pending.generation();
                peer.task = PeerTaskSlot::Session { generation };
                generation
            };

            if shutdown {
                manager.shutdown(0).unwrap();
            } else {
                manager.revoke(DIAL_PEER, 0).unwrap();
            }

            assert_eq!(manager.snapshot().session_tasks, 0);
            assert_eq!(
                manager
                    .peers
                    .get_mut(&DIAL_PEER)
                    .unwrap()
                    .supervisor
                    .connection_task_lost(generation, 1,)
                    .unwrap(),
                SupervisorEventOutcome::StaleIgnored
            );
            assert!(matches!(
                manager
                    .peers
                    .get_mut(&DIAL_PEER)
                    .unwrap()
                    .supervisor
                    .begin_pending(ConnectionDirection::Outbound),
                Err(PeerSessionSupervisorError::Unavailable)
            ));
        }
    }

    #[test]
    fn failed_activation_after_gate_cleanup_releases_manager_session_slot() {
        let mut manager = manager(DIAL_PEER);
        let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
        let pending = peer
            .supervisor
            .begin_pending(ConnectionDirection::Outbound)
            .unwrap();
        let generation = pending.generation();
        peer.task = PeerTaskSlot::Session { generation };
        assert_eq!(
            peer.supervisor.connection_task_lost(generation, 0).unwrap(),
            SupervisorEventOutcome::PendingCancelled
        );

        assert!(matches!(
            settle_bound_event_result(
                peer,
                GenerationBoundEventClassification::Activated,
                Err(PeerSessionSupervisorError::Coordinator(
                    CoordinatorError::CleanupIncomplete
                )),
                0,
            ),
            Err(PeerManagerError::Supervisor(_))
        ));
        assert_eq!(peer.task, PeerTaskSlot::Idle);
        assert_eq!(peer.backoff.attempts(), 1);
    }

    fn assert_reconciliation_retirement_schedules_backoff(now_ns: u64, retry: bool) {
        let mut manager = manager(DIAL_PEER);
        manager
            .replace_candidates([(DIAL_PEER, "10.0.0.2:24800".parse().unwrap())])
            .unwrap();
        let peer = manager.peers.get_mut(&DIAL_PEER).unwrap();
        let pending = peer
            .supervisor
            .begin_pending(ConnectionDirection::Outbound)
            .unwrap();
        let generation = pending.generation();
        peer.task = PeerTaskSlot::Session { generation };
        assert_eq!(
            peer.supervisor
                .connection_task_lost(generation, now_ns)
                .unwrap(),
            SupervisorEventOutcome::PendingCancelled
        );

        let result = Ok(SupervisorEventOutcome::Retired(
            crate::PeerEventOutcome::Applied,
        ));
        let outcome = if retry {
            settle_reconciliation_retry_result(peer, result, now_ns)
        } else {
            settle_connection_lost_result(peer, result, now_ns)
        };
        assert!(outcome.is_ok());

        assert_eq!(peer.task, PeerTaskSlot::Idle);
        assert_eq!(peer.backoff.attempts(), 1);
        assert_eq!(
            peer.retry_not_before,
            Duration::from_nanos(now_ns) + Duration::from_secs(1)
        );
    }

    #[test]
    fn direct_active_channel_loss_schedules_reconnect_backoff() {
        assert_reconciliation_retirement_schedules_backoff(2_000_000_000, false);
    }

    #[test]
    fn successful_reconciliation_retry_schedules_reconnect_backoff() {
        assert_reconciliation_retirement_schedules_backoff(4_000_000_000, true);
    }

    #[test]
    fn nil_and_role_inconsistent_pairing_snapshots_fail_closed() {
        assert!(matches!(
            PeerManager::<TestInjection, TestOutbound>::new(
                PeerId::from_bytes([0; 16]),
                [],
                PeerManagerConfig::default()
            ),
            Err(PeerManagerError::InvalidIdentity)
        ));

        let wrong_role_peer = managed_peer(DIAL_PEER, LOCAL_PEER, 11);
        assert!(matches!(
            PeerManager::new(LOCAL_PEER, [wrong_role_peer], PeerManagerConfig::default()),
            Err(PeerManagerError::InvalidIdentity)
        ));
    }

    #[test]
    fn errors_never_include_discovery_or_credential_payloads() {
        let error = PeerManagerError::InvalidCandidate;
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("10.0.0.2"));
    }

    #[test]
    fn managed_session_error_category_never_renders_peer_heartbeat_text() {
        let marker = "SECRET-HEARTBEAT-NONCE-TEXT";
        let error = SessionError::Heartbeat(marker.to_owned());
        let rendered = format!("{:?}", CoarseSessionError(&error));

        assert_eq!(rendered, "Heartbeat");
        assert!(!rendered.contains(marker));
    }
}
