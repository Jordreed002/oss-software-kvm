//! Mandatory composition of authenticated display inventory and pointer authority.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use kvm_network::ConnectionGeneration;
use kvm_protocol::{InputEventV1, WireInputPayloadV1, WireMessage};
use kvm_topology::{
    ConfiguredWorkspaceCompiler, WorkspaceCompileError, WorkspaceLink, WorkspacePlacement,
    MAX_WORKSPACE_DISPLAYS, MAX_WORKSPACE_LINKS,
};
use kvm_types::{DeviceId, Display, InputDevice};
use kvm_types::{Edge, LogicalPointer, PeerId, Point, Rect, WorkspaceState};

use crate::device_inventory::{DeviceInventory, DeviceInventoryConfig, DeviceInventoryError};
use crate::display_inventory::{DisplayInventory, DisplayInventoryError};
use crate::platform::OutputInjectionBackend;
use crate::pointer_handoff::{
    PointerAckOutcome, PointerDispatchError, PointerEffectCompletion, PointerHandoffConfig,
    PointerHandoffCoordinator, PointerHandoffEffect, PointerHandoffError,
};
use crate::session::{CoordinatorError, OutboundPeer, PeerEventOutcome, SessionRoutingContext};
use crate::supervisor::CurrentAdmittedSession;

const NATIVE_EDGE_TOLERANCE: f64 = 1.0;

/// Coarse workspace-control failure. Pointer protocol failures are session-fatal.
pub enum WorkspaceControlError {
    Inventory(DisplayInventoryError),
    DeviceInventory(DeviceInventoryError),
    Pointer(PointerHandoffError),
    Coordinator(CoordinatorError),
    WrongPointerPeer,
    AlreadyAttached,
    Unavailable,
    InvalidConfiguration,
    Topology(WorkspaceCompileError),
}

impl fmt::Debug for WorkspaceControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Inventory(_) => "Inventory",
            Self::DeviceInventory(_) => "DeviceInventory",
            Self::Pointer(_) => "Pointer",
            Self::Coordinator(_) => "Coordinator",
            Self::WrongPointerPeer => "WrongPointerPeer",
            Self::AlreadyAttached => "AlreadyAttached",
            Self::Unavailable => "Unavailable",
            Self::InvalidConfiguration => "InvalidConfiguration",
            Self::Topology(_) => "Topology",
        };
        formatter
            .debug_struct("WorkspaceControlError")
            .field("kind", &kind)
            .finish()
    }
}

impl fmt::Display for WorkspaceControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("workspace control operation failed")
    }
}

impl Error for WorkspaceControlError {}

impl From<DisplayInventoryError> for WorkspaceControlError {
    fn from(error: DisplayInventoryError) -> Self {
        Self::Inventory(error)
    }
}

impl From<DeviceInventoryError> for WorkspaceControlError {
    fn from(error: DeviceInventoryError) -> Self {
        Self::DeviceInventory(error)
    }
}

impl From<PointerHandoffError> for WorkspaceControlError {
    fn from(error: PointerHandoffError) -> Self {
        Self::Pointer(error)
    }
}

impl From<CoordinatorError> for WorkspaceControlError {
    fn from(error: CoordinatorError) -> Self {
        Self::Coordinator(error)
    }
}

impl From<WorkspaceCompileError> for WorkspaceControlError {
    fn from(error: WorkspaceCompileError) -> Self {
        Self::Topology(error)
    }
}

/// One global workspace owner with exactly one immutable pointer-authority peer.
///
/// M06 deliberately limits pointer transfer to a two-host workspace. Other
/// paired peers may publish display inventory, but cannot mutate pointer state.
pub struct WorkspaceControlPlane {
    selected_pointer_peer: PeerId,
    inventory: DisplayInventory,
    device_inventory: DeviceInventory,
    compiler: ConfiguredWorkspaceCompiler,
    placements: Vec<WorkspacePlacement>,
    links: Vec<WorkspaceLink>,
    pointer_config: PointerHandoffConfig,
    initial_state: WorkspaceState,
    local_fallback: LogicalPointer,
    pointer: Option<PointerHandoffCoordinator>,
    selected_inventory_ready: bool,
    device_resync_required: BTreeSet<(kvm_types::HostId, ConnectionGeneration)>,
    pending_local_devices: Option<PendingLocalDeviceInventory>,
    shutting_down: bool,
}

struct PendingLocalDeviceInventory {
    revision: u64,
    requested: Vec<InputDevice>,
    affected: Vec<DeviceId>,
    restore: Vec<DeviceId>,
    abort_restore: Vec<DeviceId>,
    committed: bool,
    selected_synced: bool,
}

pub(crate) struct PendingLocalDeviceUpdate {
    pub(crate) revision: u64,
    pub(crate) affected: Vec<DeviceId>,
    pub(crate) restore: Vec<DeviceId>,
    pub(crate) abort_restore: Vec<DeviceId>,
    pub(crate) committed: bool,
    pub(crate) selected_synced: bool,
}

impl fmt::Debug for PendingLocalDeviceInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingLocalDeviceInventory")
            .field("revision", &"[REDACTED]")
            .field("device_count", &self.requested.len())
            .field("affected_count", &self.affected.len())
            .field("restore_count", &self.restore.len())
            .field("abort_restore_count", &self.abort_restore.len())
            .field("committed", &self.committed)
            .field("selected_synced", &self.selected_synced)
            .finish()
    }
}

impl fmt::Debug for WorkspaceControlPlane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceControlPlane")
            .field("selected_pointer_peer", &"[REDACTED]")
            .field("inventory", &self.inventory.snapshot())
            .field("device_inventory", &self.device_inventory.snapshot())
            .field("pointer_ready", &self.selected_inventory_ready)
            .field("device_resync_count", &self.device_resync_required.len())
            .field(
                "local_device_update_pending",
                &self.pending_local_devices.is_some(),
            )
            .field("shutting_down", &self.shutting_down)
            .finish_non_exhaustive()
    }
}

impl WorkspaceControlPlane {
    /// Builds the single, bounded M06 workspace authority plane.
    ///
    /// # Errors
    ///
    /// Rejects nil identities, inconsistent local ownership, unbounded or
    /// duplicate topology declarations, and non-finite placement origins.
    pub fn new(
        selected_pointer_peer: PeerId,
        inventory: DisplayInventory,
        pointer_config: PointerHandoffConfig,
        initial_state: WorkspaceState,
        local_fallback: LogicalPointer,
        placements: Vec<WorkspacePlacement>,
        links: Vec<WorkspaceLink>,
    ) -> Result<Self, WorkspaceControlError> {
        if selected_pointer_peer.into_bytes() == [0; 16]
            || initial_state.local_host != inventory.local_host_id()
            || initial_state.active_host != initial_state.local_host
            || validate_topology_config(&placements, &links).is_err()
        {
            return Err(WorkspaceControlError::InvalidConfiguration);
        }
        let mut device_inventory =
            DeviceInventory::new(initial_state.local_host, DeviceInventoryConfig::default())?;
        device_inventory.apply_local_snapshot(1, Vec::new())?;
        Ok(Self {
            selected_pointer_peer,
            inventory,
            device_inventory,
            compiler: ConfiguredWorkspaceCompiler::new(),
            placements,
            links,
            pointer_config,
            initial_state,
            local_fallback,
            pointer: None,
            selected_inventory_ready: false,
            device_resync_required: BTreeSet::new(),
            pending_local_devices: None,
            shutting_down: false,
        })
    }

    #[must_use]
    pub const fn selected_pointer_peer(&self) -> PeerId {
        self.selected_pointer_peer
    }

    #[must_use]
    pub(crate) const fn initial_state(&self) -> WorkspaceState {
        self.initial_state
    }

    #[must_use]
    pub const fn inventory(&self) -> &DisplayInventory {
        &self.inventory
    }

    #[must_use]
    pub const fn device_inventory(&self) -> &DeviceInventory {
        &self.device_inventory
    }

    #[must_use]
    pub const fn pointer(&self) -> Option<&PointerHandoffCoordinator> {
        self.pointer.as_ref()
    }

    pub(crate) fn local_device_update_pending(&self) -> bool {
        self.pending_local_devices.is_some()
    }

    pub(crate) fn pointer_transition_pending(&self) -> bool {
        self.pointer
            .as_ref()
            .is_some_and(|pointer| pointer.next_deadline_ns().is_some())
    }

    /// Resolves a trusted native cursor position to one configured local
    /// display-edge transition. Ambiguous corners, unlinked edges, remote
    /// authority, and stale/unready workspaces return no proposal.
    pub(crate) fn native_pointer_boundary(&self, position: Point) -> Option<(Edge, f64)> {
        if !position.x.is_finite()
            || !position.y.is_finite()
            || !self.selected_inventory_ready
            || self.pointer_transition_pending()
        {
            return None;
        }
        let pointer = self.pointer.as_ref()?;
        if !pointer.has_local_authority() {
            return None;
        }
        let state = pointer.workspace_state();
        let display = self
            .inventory
            .snapshot()
            .host(state.local_host)?
            .get(state.active_display)?
            .clone();
        let mut candidate = None;
        for link in self
            .links
            .iter()
            .filter(|link| link.source_display() == display.id)
        {
            let edge = link.source_edge();
            let Some(normalized) = native_edge_position(display.native_bounds, edge, position)
            else {
                continue;
            };
            if candidate.is_some() {
                return None;
            }
            candidate = Some((edge, normalized));
        }
        candidate
    }

    pub(crate) fn activate<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        if self.shutting_down {
            return Err(WorkspaceControlError::Unavailable);
        }
        routing.require_endpoint(session.endpoint())?;
        if self.pointer.is_none() && routing.core_workspace()? != self.initial_state {
            return Err(WorkspaceControlError::InvalidConfiguration);
        }
        if self.is_selected(session) {
            routing.clear_workspace_routing_ready(now_ns)?;
        }
        self.inventory.activate_remote(session)?;
        self.device_inventory.activate_remote(session)?;
        if self.is_selected(session) {
            self.selected_inventory_ready = false;
            let local_host = self.device_inventory.local_host_id();
            let local_devices = self
                .device_inventory
                .snapshot()
                .host(local_host)
                .map(|inventory| inventory.iter().map(|device| device.id).collect::<Vec<_>>())
                .unwrap_or_default();
            for device in local_devices {
                if let Err(error) = routing.restore_local_device(device, now_ns) {
                    self.rollback_activation(session, routing, now_ns);
                    return Err(error.into());
                }
            }
        }
        let snapshot = match self.inventory.local_wire_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.rollback_activation(session, routing, now_ns);
                return Err(error.into());
            }
        };
        if let Err(error) = routing.try_send_control(WireMessage::DisplaySnapshot(snapshot)) {
            self.rollback_activation(session, routing, now_ns);
            return Err(error.into());
        }
        let device_snapshot = match self.device_inventory.local_wire_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.rollback_activation(session, routing, now_ns);
                return Err(error.into());
            }
        };
        if let Err(error) = routing.try_send_control(WireMessage::DeviceSnapshot(device_snapshot)) {
            self.rollback_activation(session, routing, now_ns);
            return Err(error.into());
        }
        if self.is_selected(session) {
            if let Some(pending) = self.pending_local_devices.as_mut() {
                if pending.committed {
                    pending.selected_synced = true;
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn handle_message<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        message: WireMessage,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        routing.require_endpoint(session.endpoint())?;
        message
            .validate()
            .map_err(|_| WorkspaceControlError::Unavailable)?;
        if self.pending_local_devices.is_some()
            && matches!(
                &message,
                WireMessage::PointerLeave(_)
                    | WireMessage::PointerEnter(_)
                    | WireMessage::PointerTransitionAck(_)
                    | WireMessage::PointerTransitionCommit(_)
            )
        {
            return Err(WorkspaceControlError::AlreadyAttached);
        }
        match message {
            WireMessage::DeviceSnapshot(message) => {
                let before = self.device_inventory.snapshot();
                let mut candidate = self.device_inventory.clone();
                candidate.apply_remote_snapshot(session, &message)?;
                let after = candidate.snapshot();
                let remote_host = session.remote_host_id();
                if let Some(previous) = before.host(remote_host) {
                    for device in previous.iter() {
                        if after.host(remote_host).and_then(|host| host.get(device.id))
                            != Some(device)
                        {
                            routing.release_inbound_device(device.id, now_ns)?;
                        }
                    }
                }
                self.device_inventory = candidate;
            }
            WireMessage::DeviceAdded(message) => {
                let mut candidate = self.device_inventory.clone();
                candidate.apply_remote_add(session, &message)?;
                self.device_inventory = candidate;
            }
            WireMessage::DeviceRemoved(message) => {
                let mut candidate = self.device_inventory.clone();
                candidate.apply_remote_remove(session, &message)?;
                routing.release_inbound_device(
                    kvm_types::DeviceId::from_bytes(message.device_id.0),
                    now_ns,
                )?;
                self.device_inventory = candidate;
            }
            WireMessage::DisplaySnapshot(message) => {
                if self.is_selected(session) {
                    self.suspend_selected(session, routing, now_ns)?;
                }
                self.inventory.apply_remote_snapshot(session, &message)?;
                if self.is_selected(session) {
                    self.recompile_selected(session)?;
                    self.publish_ready_pointer_workspace(routing, now_ns)?;
                }
            }
            WireMessage::DisplayUpdated(message) => {
                if self.is_selected(session) {
                    self.suspend_selected(session, routing, now_ns)?;
                }
                self.inventory.apply_remote_update(session, &message)?;
                if self.is_selected(session) {
                    self.recompile_selected(session)?;
                    self.publish_ready_pointer_workspace(routing, now_ns)?;
                }
            }
            WireMessage::PointerLeave(message) => {
                self.require_selected(session)?;
                self.ready_pointer_mut()?
                    .receive_leave(session, message, now_ns)?;
            }
            WireMessage::PointerEnter(message) => {
                self.require_selected(session)?;
                let effect = self
                    .ready_pointer_mut()?
                    .receive_enter(session, message, now_ns)?;
                let accepted = effect.is_accepted_ack();
                if accepted {
                    routing.begin_destination_handoff_barrier(now_ns)?;
                }
                if let Err(error) =
                    self.dispatch_pointer_effect(session, routing, effect, false, now_ns)
                {
                    if accepted {
                        let _ = routing.abort_destination_handoff_barrier(now_ns);
                    }
                    return Err(error);
                }
            }
            WireMessage::PointerTransitionAck(message) => {
                self.require_selected(session)?;
                if let PointerAckOutcome::Commit(effect) = self
                    .ready_pointer_mut()?
                    .receive_ack(session, message, now_ns)?
                {
                    self.dispatch_pointer_effect(session, routing, *effect, true, now_ns)?;
                }
            }
            WireMessage::PointerTransitionCommit(message) => {
                self.require_selected(session)?;
                self.ready_pointer_mut()?
                    .receive_commit(session, message, now_ns)?;
                self.publish_pointer_workspace(routing, now_ns)?;
            }
            other => return Ok(PeerEventOutcome::Deferred(other.message_type())),
        }
        Ok(PeerEventOutcome::Applied)
    }

    pub(crate) fn connected<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        routing.require_endpoint(session.endpoint())?;
        let resync = (session.remote_host_id(), session.generation());
        if self.device_resync_required.contains(&resync) {
            let snapshot = self.device_inventory.local_wire_snapshot()?;
            routing.try_send_control(WireMessage::DeviceSnapshot(snapshot))?;
            self.device_resync_required.remove(&resync);
        }
        if self.is_selected(session) && self.selected_inventory_ready {
            self.ready_pointer_mut()?.mark_session_healthy(session)?;
        }
        Ok(())
    }

    pub(crate) fn degrade<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        routing.require_endpoint(session.endpoint())?;
        self.device_inventory.suspend_remote(session);
        self.device_resync_required
            .insert((session.remote_host_id(), session.generation()));
        if self.is_selected(session) {
            self.suspend_selected(session, routing, now_ns)?;
        }
        Ok(())
    }

    pub(crate) fn validate_remote_input(
        &self,
        session: &CurrentAdmittedSession,
        input: &InputEventV1,
    ) -> Result<(), WorkspaceControlError> {
        if input.source_host.0 != session.remote_host_id().into_bytes() {
            return Err(WorkspaceControlError::Unavailable);
        }
        let device = self.device_inventory.remote_device(
            session,
            kvm_types::DeviceId::from_bytes(input.source_device.0),
        )?;
        let supported = match &input.payload {
            WireInputPayloadV1::Key { .. } => device.capabilities.keyboard,
            WireInputPayloadV1::PointerMove { .. } | WireInputPayloadV1::PointerButton { .. } => {
                device.capabilities.pointer
            }
            WireInputPayloadV1::Scroll {
                horizontal,
                vertical,
            } => {
                (*horizontal == 0.0 || device.capabilities.horizontal_scroll)
                    && (*vertical == 0.0 || device.capabilities.vertical_scroll)
            }
        };
        if supported {
            Ok(())
        } else {
            Err(WorkspaceControlError::Unavailable)
        }
    }

    pub(crate) fn retire<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        routing.require_endpoint(session.endpoint())?;
        if self.is_selected(session) {
            routing.clear_workspace_routing_ready(now_ns)?;
        }
        self.inventory.invalidate_remote(session);
        self.device_inventory.invalidate_remote(session);
        self.device_resync_required
            .remove(&(session.remote_host_id(), session.generation()));
        if self.is_selected(session) {
            self.selected_inventory_ready = false;
            if let Some(pointer) = self.pointer.as_mut() {
                match pointer.disconnect_session(session) {
                    Ok(_) => self.publish_pointer_workspace(routing, now_ns)?,
                    Err(error)
                        if error.kind()
                            == crate::pointer_handoff::PointerHandoffErrorKind::NoCurrentSession =>
                    {
                        routing.cancel_pointer_handoff(now_ns)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            } else {
                routing.cancel_pointer_handoff(now_ns)?;
            }
        }
        Ok(())
    }

    /// Retires workspace metadata after the exact transport has been proven
    /// terminal. This path deliberately performs no routing-core mutation:
    /// terminal invalidation has already made the coordinator local and
    /// discarded only that endpoint's transport-bound obligations.
    pub(crate) fn retire_after_transport_loss(
        &mut self,
        session: &CurrentAdmittedSession,
    ) -> Result<(), WorkspaceControlError> {
        self.retire_settled_metadata(session)
    }

    /// Retires metadata after graceful coordinator cleanup has already
    /// settled every exact FIFO obligation and retired the endpoint.
    pub(crate) fn retire_after_graceful_settlement(
        &mut self,
        session: &CurrentAdmittedSession,
    ) -> Result<(), WorkspaceControlError> {
        self.retire_settled_metadata(session)
    }

    fn retire_settled_metadata(
        &mut self,
        session: &CurrentAdmittedSession,
    ) -> Result<(), WorkspaceControlError> {
        self.inventory.invalidate_remote(session);
        self.device_inventory.invalidate_remote(session);
        self.device_resync_required
            .remove(&(session.remote_host_id(), session.generation()));
        if self.is_selected(session) {
            self.selected_inventory_ready = false;
            if let Some(pointer) = self.pointer.as_mut() {
                match pointer.disconnect_session(session) {
                    Ok(_) => {}
                    Err(error)
                        if error.kind()
                            == crate::pointer_handoff::PointerHandoffErrorKind::NoCurrentSession =>
                    {
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }

    pub(crate) fn shutdown(&mut self) {
        self.shutting_down = true;
        self.inventory.invalidate_all_remote();
        self.device_inventory.invalidate_all_remote();
        self.device_resync_required.clear();
        self.pending_local_devices = None;
        if let Some(pointer) = self.pointer.as_mut() {
            pointer.shutdown();
        }
        self.selected_inventory_ready = false;
    }

    pub(crate) fn apply_local_snapshot_offline(
        &mut self,
        revision: u64,
        displays: Vec<Display>,
    ) -> Result<(), WorkspaceControlError> {
        self.selected_inventory_ready = false;
        self.inventory.apply_local_snapshot(revision, displays)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn apply_local_device_snapshot_offline(
        &mut self,
        revision: u64,
        devices: Vec<InputDevice>,
    ) -> Result<(), WorkspaceControlError> {
        if self.pending_local_devices.is_some() {
            return Err(WorkspaceControlError::AlreadyAttached);
        }
        self.device_inventory
            .apply_local_snapshot(revision, devices)?;
        Ok(())
    }

    pub(crate) fn stage_local_device_snapshot(
        &mut self,
        revision: u64,
        mut devices: Vec<InputDevice>,
    ) -> Result<(), WorkspaceControlError> {
        devices.sort_by_key(|device| device.id);
        if let Some(pending) = self.pending_local_devices.as_ref() {
            return if pending.revision == revision && pending.requested == devices {
                Ok(())
            } else {
                Err(WorkspaceControlError::AlreadyAttached)
            };
        }
        let mut candidate = self.device_inventory.clone();
        candidate.apply_local_snapshot(revision, devices)?;
        let local_host = self.device_inventory.local_host_id();
        let requested = candidate
            .snapshot()
            .host(local_host)
            .map(|host| host.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let before = self.device_inventory.snapshot();
        let after = candidate.snapshot();
        let before = before.host(local_host);
        let after = after.host(local_host);
        let mut identifiers = BTreeSet::new();
        if let Some(before) = before {
            identifiers.extend(before.iter().map(|device| device.id));
        }
        if let Some(after) = after {
            identifiers.extend(after.iter().map(|device| device.id));
        }
        let mut affected = Vec::new();
        let mut restore = Vec::new();
        let mut abort_restore = Vec::new();
        for device in identifiers {
            let old = before.and_then(|inventory| inventory.get(device));
            let new = after.and_then(|inventory| inventory.get(device));
            if old != new {
                affected.push(device);
                abort_restore.push(device);
                if new.is_some() {
                    restore.push(device);
                }
            }
        }
        self.pending_local_devices = Some(PendingLocalDeviceInventory {
            revision,
            requested,
            affected,
            restore,
            abort_restore,
            committed: false,
            selected_synced: false,
        });
        Ok(())
    }

    pub(crate) fn pending_local_device_update(&self) -> Option<PendingLocalDeviceUpdate> {
        self.pending_local_devices
            .as_ref()
            .map(|pending| PendingLocalDeviceUpdate {
                revision: pending.revision,
                affected: pending.affected.clone(),
                restore: pending.restore.clone(),
                abort_restore: pending.abort_restore.clone(),
                committed: pending.committed,
                selected_synced: pending.selected_synced,
            })
    }

    pub(crate) fn mark_local_device_snapshot_selected_synced(
        &mut self,
        revision: u64,
    ) -> Result<(), WorkspaceControlError> {
        let pending = self
            .pending_local_devices
            .as_mut()
            .ok_or(WorkspaceControlError::Unavailable)?;
        if pending.revision != revision || !pending.committed {
            return Err(WorkspaceControlError::Unavailable);
        }
        pending.selected_synced = true;
        Ok(())
    }

    pub(crate) fn commit_local_device_snapshot(
        &mut self,
        revision: u64,
    ) -> Result<kvm_protocol::DeviceSnapshotV1, WorkspaceControlError> {
        let pending = self
            .pending_local_devices
            .as_mut()
            .ok_or(WorkspaceControlError::Unavailable)?;
        if pending.revision != revision {
            return Err(WorkspaceControlError::Unavailable);
        }
        if !pending.committed {
            self.device_inventory
                .apply_local_snapshot(revision, pending.requested.clone())?;
            pending.committed = true;
        }
        let snapshot = self.device_inventory.local_wire_snapshot()?;
        Ok(snapshot)
    }

    pub(crate) fn complete_local_device_snapshot(
        &mut self,
        revision: u64,
    ) -> Result<(), WorkspaceControlError> {
        let pending = self
            .pending_local_devices
            .as_ref()
            .ok_or(WorkspaceControlError::Unavailable)?;
        if pending.revision != revision || !pending.committed {
            return Err(WorkspaceControlError::Unavailable);
        }
        self.pending_local_devices = None;
        Ok(())
    }

    pub(crate) fn abort_local_device_snapshot(
        &mut self,
        revision: u64,
    ) -> Result<(), WorkspaceControlError> {
        let pending = self
            .pending_local_devices
            .as_ref()
            .ok_or(WorkspaceControlError::Unavailable)?;
        if pending.revision != revision || pending.committed {
            return Err(WorkspaceControlError::Unavailable);
        }
        self.pending_local_devices = None;
        Ok(())
    }

    pub(crate) fn apply_local_update_offline(
        &mut self,
        revision: u64,
        display: Display,
    ) -> Result<(), WorkspaceControlError> {
        self.selected_inventory_ready = false;
        self.inventory.apply_local_update(revision, display)?;
        Ok(())
    }

    pub(crate) fn prepare_local_change<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        routing.require_endpoint(session.endpoint())?;
        self.suspend_selected(session, routing, now_ns)
    }

    pub(crate) fn refresh_selected<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        routing.require_endpoint(session.endpoint())?;
        self.recompile_selected(session)?;
        self.publish_ready_pointer_workspace(routing, now_ns)?;
        let snapshot = self.inventory.local_wire_snapshot()?;
        routing.try_send_control(WireMessage::DisplaySnapshot(snapshot))?;
        Ok(())
    }

    pub(crate) fn replace_topology<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        placements: Vec<WorkspacePlacement>,
        links: Vec<WorkspaceLink>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        routing.require_endpoint(session.endpoint())?;
        self.require_selected(session)?;
        validate_topology_config(&placements, &links)?;
        if !self.selected_inventory_ready || self.pointer.is_none() {
            return Err(WorkspaceControlError::Unavailable);
        }

        self.suspend_selected(session, routing, now_ns)?;
        let candidate = match self.compile_selected_candidate(session, &placements, &links) {
            Ok(candidate) => candidate,
            Err(error) => {
                self.restore_selected(session, routing, now_ns)?;
                return Err(error);
            }
        };
        if !candidate.contains_local_point(
            self.local_fallback.display_id,
            kvm_types::Point::new(self.local_fallback.x, self.local_fallback.y),
        ) {
            self.restore_selected(session, routing, now_ns)?;
            return Err(WorkspaceControlError::InvalidConfiguration);
        }

        let pointer = self
            .pointer
            .as_mut()
            .ok_or(WorkspaceControlError::Unavailable)?;
        pointer.replace_workspace(candidate, self.local_fallback)?;
        pointer.mark_session_healthy(session)?;
        self.placements = placements;
        self.links = links;
        self.selected_inventory_ready = true;
        self.publish_ready_pointer_workspace(routing, now_ns)
    }

    pub(crate) fn local_snapshot_message(
        &self,
    ) -> Result<kvm_protocol::DisplaySnapshotV1, WorkspaceControlError> {
        self.inventory.local_wire_snapshot().map_err(Into::into)
    }

    pub(crate) fn propose_pointer_handoff<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        edge: Edge,
        normalized_position: f64,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        routing.require_endpoint(session.endpoint())?;
        self.require_selected(session)?;
        let effect =
            self.ready_pointer_mut()?
                .propose_leave(session, edge, normalized_position, now_ns)?;
        routing.begin_pointer_handoff(now_ns)?;
        if let Err(error) = self.dispatch_pointer_effect(session, routing, effect, false, now_ns) {
            routing.cancel_pointer_handoff(now_ns)?;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn poll_timeout<I, O>(
        &mut self,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        if !self.selected_inventory_ready {
            return Ok(());
        }
        let expired = self.ready_pointer_mut()?.poll_timeout(now_ns)?;
        if expired.outbound || expired.inbound || expired.reply {
            self.publish_pointer_workspace(routing, now_ns)?;
            return Err(WorkspaceControlError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn cancel_handoff_for_failsafe<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        routing.require_endpoint(session.endpoint())?;
        self.require_selected(session)?;
        if let Some(pointer) = self.pointer.as_mut() {
            pointer.degrade_session(session)?;
            pointer.mark_session_healthy(session)?;
            self.publish_pointer_workspace(routing, now_ns)
        } else {
            routing.cancel_pointer_handoff(now_ns)?;
            Ok(())
        }
    }

    fn dispatch_pointer_effect<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        mut effect: PointerHandoffEffect,
        mut commit: bool,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        loop {
            if commit {
                routing.begin_pointer_handoff(now_ns)?;
            }
            let result =
                self.ready_pointer_mut()?
                    .dispatch_effect(session, effect, now_ns, |message| {
                        routing.try_send_control(message)
                    });
            match result {
                Ok(PointerEffectCompletion::Sent) => return Ok(()),
                Ok(PointerEffectCompletion::AuthorityCommitted) => {
                    self.publish_pointer_workspace(routing, now_ns)?;
                    return Ok(());
                }
                Ok(PointerEffectCompletion::Next(next)) => {
                    effect = *next;
                    commit = false;
                }
                Err(PointerDispatchError::Handoff(error)) => {
                    if commit {
                        routing.cancel_pointer_handoff(now_ns)?;
                    }
                    return Err(error.into());
                }
                Err(PointerDispatchError::Outbound(error)) => {
                    if commit {
                        routing.cancel_pointer_handoff(now_ns)?;
                    }
                    return Err(error.into());
                }
            }
        }
    }

    fn publish_pointer_workspace<I, O>(
        &self,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        let state = self
            .pointer
            .as_ref()
            .ok_or(WorkspaceControlError::Unavailable)?
            .workspace_state();
        routing.finish_pointer_handoff(state, now_ns)?;
        Ok(())
    }

    fn publish_ready_pointer_workspace<I, O>(
        &self,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        self.publish_pointer_workspace(routing, now_ns)?;
        routing.mark_workspace_routing_ready(now_ns)?;
        Ok(())
    }

    fn rollback_activation<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        self.inventory.invalidate_remote(session);
        self.device_inventory.invalidate_remote(session);
        self.device_resync_required
            .remove(&(session.remote_host_id(), session.generation()));
        if self.is_selected(session) {
            if let Some(pointer) = self.pointer.as_mut() {
                let _ = pointer.disconnect_session(session);
            }
            self.selected_inventory_ready = false;
            let _ = routing.clear_workspace_routing_ready(now_ns);
            let _ = routing.cancel_pointer_handoff(now_ns);
        }
    }

    fn require_selected(
        &self,
        session: &CurrentAdmittedSession,
    ) -> Result<(), WorkspaceControlError> {
        if self.is_selected(session) {
            Ok(())
        } else {
            Err(WorkspaceControlError::WrongPointerPeer)
        }
    }

    fn is_selected(&self, session: &CurrentAdmittedSession) -> bool {
        PeerId::from_bytes(session.remote_hello().peer_id.0) == self.selected_pointer_peer
    }

    fn ready_pointer_mut(
        &mut self,
    ) -> Result<&mut PointerHandoffCoordinator, WorkspaceControlError> {
        if !self.selected_inventory_ready {
            return Err(WorkspaceControlError::Unavailable);
        }
        self.pointer
            .as_mut()
            .ok_or(WorkspaceControlError::Unavailable)
    }

    fn suspend_selected<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        routing.clear_workspace_routing_ready(now_ns)?;
        self.selected_inventory_ready = false;
        if let Some(pointer) = self.pointer.as_mut() {
            match pointer.degrade_session(session) {
                Ok(_) => self.publish_pointer_workspace(routing, now_ns)?,
                Err(error)
                    if error.kind()
                        == crate::pointer_handoff::PointerHandoffErrorKind::NoCurrentSession =>
                {
                    routing.cancel_pointer_handoff(now_ns)?;
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            routing.cancel_pointer_handoff(now_ns)?;
        }
        Ok(())
    }

    fn recompile_selected(
        &mut self,
        session: &CurrentAdmittedSession,
    ) -> Result<(), WorkspaceControlError> {
        let placements = self.placements.clone();
        let links = self.links.clone();
        let candidate = self.compile_selected_candidate(session, &placements, &links)?;
        if let Some(pointer) = self.pointer.as_mut() {
            pointer.replace_workspace(candidate, self.local_fallback)?;
            pointer.bind_session(session)?;
            pointer.mark_session_healthy(session)?;
        } else {
            let mut pointer = PointerHandoffCoordinator::new(
                self.pointer_config,
                candidate,
                self.initial_state,
                self.local_fallback,
            )?;
            pointer.bind_session(session)?;
            self.pointer = Some(pointer);
        }
        self.selected_inventory_ready = true;
        Ok(())
    }

    fn compile_selected_candidate(
        &mut self,
        session: &CurrentAdmittedSession,
        placements: &[WorkspacePlacement],
        links: &[WorkspaceLink],
    ) -> Result<kvm_topology::ConfiguredWorkspace, WorkspaceControlError> {
        let local = session.local_host_id();
        let remote = session.remote_host_id();
        let displays = self
            .inventory
            .snapshot()
            .displays()
            .filter(|display| display.host_id == local || display.host_id == remote)
            .cloned()
            .collect::<Vec<_>>();
        self.compiler
            .compile_candidate(displays, placements.iter().copied(), links.iter().copied())
            .map_err(Into::into)
    }

    fn restore_selected<I, O>(
        &mut self,
        session: &CurrentAdmittedSession,
        routing: &mut SessionRoutingContext<'_, I, O>,
        now_ns: u64,
    ) -> Result<(), WorkspaceControlError>
    where
        I: OutputInjectionBackend,
        O: OutboundPeer,
    {
        let pointer = self
            .pointer
            .as_mut()
            .ok_or(WorkspaceControlError::Unavailable)?;
        pointer.mark_session_healthy(session)?;
        self.selected_inventory_ready = true;
        self.publish_ready_pointer_workspace(routing, now_ns)
    }
}

fn native_edge_position(bounds: Rect, edge: Edge, position: Point) -> Option<f64> {
    if !bounds.is_valid() || bounds.width <= 0.0 || bounds.height <= 0.0 {
        return None;
    }
    let within_horizontal = position.x >= bounds.min_x() - NATIVE_EDGE_TOLERANCE
        && position.x <= bounds.max_x() + NATIVE_EDGE_TOLERANCE;
    let within_vertical = position.y >= bounds.min_y() - NATIVE_EDGE_TOLERANCE
        && position.y <= bounds.max_y() + NATIVE_EDGE_TOLERANCE;
    let on_edge = match edge {
        Edge::Left => {
            within_vertical && (position.x - bounds.min_x()).abs() <= NATIVE_EDGE_TOLERANCE
        }
        Edge::Right => {
            within_vertical && (position.x - bounds.max_x()).abs() <= NATIVE_EDGE_TOLERANCE
        }
        Edge::Top => {
            within_horizontal && (position.y - bounds.min_y()).abs() <= NATIVE_EDGE_TOLERANCE
        }
        Edge::Bottom => {
            within_horizontal && (position.y - bounds.max_y()).abs() <= NATIVE_EDGE_TOLERANCE
        }
    };
    if !on_edge {
        return None;
    }
    let normalized = match edge {
        Edge::Left | Edge::Right => (position.y - bounds.min_y()) / bounds.height,
        Edge::Top | Edge::Bottom => (position.x - bounds.min_x()) / bounds.width,
    };
    Some(normalized.clamp(0.0, 1.0))
}

fn validate_topology_config(
    placements: &[WorkspacePlacement],
    links: &[WorkspaceLink],
) -> Result<(), WorkspaceControlError> {
    if placements.is_empty()
        || placements.len() > MAX_WORKSPACE_DISPLAYS
        || links.len() > MAX_WORKSPACE_LINKS
    {
        return Err(WorkspaceControlError::InvalidConfiguration);
    }
    let mut placed = BTreeSet::new();
    if placements.iter().any(|placement| {
        let origin = placement.origin();
        placement.display_id().into_bytes() == [0; 16]
            || !origin.x.is_finite()
            || !origin.y.is_finite()
            || !placed.insert(placement.display_id())
    }) {
        return Err(WorkspaceControlError::InvalidConfiguration);
    }
    for (index, link) in links.iter().enumerate() {
        if link.source_display().into_bytes() == [0; 16]
            || link.destination_display().into_bytes() == [0; 16]
            || links[..index].iter().any(|previous| {
                previous.source_display() == link.source_display()
                    && previous.source_edge() == link.source_edge()
            })
        {
            return Err(WorkspaceControlError::InvalidConfiguration);
        }
    }
    Ok(())
}
