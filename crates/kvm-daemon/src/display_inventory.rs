//! Bounded, authenticated display inventories for logical-workspace input.
//!
//! Wire ownership is checked against the exact currently admitted session.
//! Published snapshots contain public display metadata only and never confer
//! trust on a later session.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use kvm_network::ConnectionGeneration;
use kvm_protocol::{
    DisplaySnapshotV1, DisplayUpdatedV1, WireDisplayId, WireDisplayV1, WireHostId, WireRect,
    WireSize, MAX_DISPLAY_LOGICAL_DIMENSION, MAX_DISPLAY_NAME_BYTES,
    MAX_DISPLAY_NATIVE_COORDINATE_ABS, MAX_DISPLAY_PHYSICAL_DIMENSION, MAX_DISPLAY_REFRESH_RATE_HZ,
    MAX_DISPLAY_SCALE_FACTOR, MAX_SNAPSHOT_ITEMS,
};
use kvm_types::{Display, DisplayId, HostId, Rect, Size};
use thiserror::Error;

use crate::supervisor::CurrentAdmittedSession;

pub const MAX_INVENTORY_REMOTE_HOSTS: usize = 256;
pub const MAX_INVENTORY_DISPLAYS_PER_HOST: usize = MAX_SNAPSHOT_ITEMS;
pub const MAX_INVENTORY_TOTAL_DISPLAYS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayInventoryConfig {
    pub remote_hosts: usize,
    pub displays_per_host: usize,
    pub total_displays: usize,
}

impl Default for DisplayInventoryConfig {
    fn default() -> Self {
        Self {
            remote_hosts: 32,
            displays_per_host: 32,
            total_displays: 512,
        }
    }
}

impl DisplayInventoryConfig {
    fn validate(self) -> Result<Self, DisplayInventoryError> {
        if self.remote_hosts == 0
            || self.remote_hosts > MAX_INVENTORY_REMOTE_HOSTS
            || self.displays_per_host == 0
            || self.displays_per_host > MAX_INVENTORY_DISPLAYS_PER_HOST
            || self.total_displays == 0
            || self.total_displays > MAX_INVENTORY_TOTAL_DISPLAYS
            || self.displays_per_host > self.total_displays
        {
            return Err(DisplayInventoryError::InvalidConfiguration);
        }
        Ok(self)
    }
}

/// Coarse inventory failure with no display names, IDs, geometry, or session
/// identifiers.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DisplayInventoryError {
    #[error("display inventory configuration is invalid")]
    InvalidConfiguration,
    #[error("display inventory host identity is invalid")]
    InvalidHost,
    #[error("display inventory message failed validation")]
    InvalidMessage,
    #[error("display inventory metadata is invalid")]
    InvalidDisplay,
    #[error("display inventory revision is invalid")]
    InvalidRevision,
    #[error("display inventory contains a duplicate display")]
    DuplicateDisplay,
    #[error("display inventory must contain exactly one primary display")]
    InvalidPrimaryCount,
    #[error("display inventory capacity was exceeded")]
    CapacityExceeded,
    #[error("display inventory revision is stale or duplicated")]
    StaleRevision,
    #[error("display inventory update skipped a required revision")]
    RevisionGap,
    #[error("display inventory revision space is exhausted")]
    RevisionExhausted,
    #[error("display inventory is unavailable for this host")]
    InventoryUnavailable,
    #[error("display inventory belongs to another admitted session")]
    SessionMismatch,
}

#[derive(Clone, PartialEq)]
pub struct HostDisplayInventorySnapshot {
    host_id: HostId,
    revision: u64,
    displays: BTreeMap<DisplayId, Display>,
}

impl HostDisplayInventorySnapshot {
    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.displays.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.displays.is_empty()
    }

    #[must_use]
    pub fn get(&self, display_id: DisplayId) -> Option<&Display> {
        self.displays.get(&display_id)
    }

    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Display> {
        self.displays.values()
    }
}

impl fmt::Debug for HostDisplayInventorySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostDisplayInventorySnapshot")
            .field("display_count", &self.displays.len())
            .finish_non_exhaustive()
    }
}

/// Immutable display metadata published by the inventory.
///
/// A retained snapshot is historical data, not proof that its originating
/// session remains admitted. Consumers must obtain a fresh snapshot after
/// lifecycle reconciliation and must never use this value as session
/// authority.
#[derive(Clone, Default, PartialEq)]
pub struct DisplayInventorySnapshot {
    hosts: BTreeMap<HostId, HostDisplayInventorySnapshot>,
    display_count: usize,
}

impl DisplayInventorySnapshot {
    #[must_use]
    pub fn host(&self, host_id: HostId) -> Option<&HostDisplayInventorySnapshot> {
        self.hosts.get(&host_id)
    }

    #[must_use]
    pub fn hosts(&self) -> impl ExactSizeIterator<Item = &HostDisplayInventorySnapshot> {
        self.hosts.values()
    }

    pub fn displays(&self) -> impl Iterator<Item = &Display> {
        self.hosts
            .values()
            .flat_map(HostDisplayInventorySnapshot::iter)
    }

    #[must_use]
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    #[must_use]
    pub const fn display_count(&self) -> usize {
        self.display_count
    }
}

impl fmt::Debug for DisplayInventorySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisplayInventorySnapshot")
            .field("host_count", &self.hosts.len())
            .field("display_count", &self.display_count)
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SessionBinding {
    generation: ConnectionGeneration,
    local_host_id: HostId,
    remote_host_id: HostId,
}

impl fmt::Debug for SessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionBinding([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InventorySource {
    Local,
    Remote(SessionBinding),
}

struct HostRecord {
    source: InventorySource,
    revision: u64,
    displays: BTreeMap<DisplayId, Display>,
}

/// Mutable bounded inventory with lock-free immutable snapshot publication.
pub struct DisplayInventory {
    local_host_id: HostId,
    config: DisplayInventoryConfig,
    active_sessions: BTreeMap<HostId, SessionBinding>,
    retired_sessions: BTreeMap<HostId, SessionBinding>,
    remote_shutdown: bool,
    records: BTreeMap<HostId, HostRecord>,
    published: ArcSwap<DisplayInventorySnapshot>,
}

impl DisplayInventory {
    /// Creates an empty inventory for one non-nil local host.
    ///
    /// # Errors
    ///
    /// Rejects a nil local host or a zero/excessive resource bound.
    pub fn new(
        local_host_id: HostId,
        config: DisplayInventoryConfig,
    ) -> Result<Self, DisplayInventoryError> {
        if local_host_id.into_bytes() == [0; 16] {
            return Err(DisplayInventoryError::InvalidHost);
        }
        Ok(Self {
            local_host_id,
            config: config.validate()?,
            active_sessions: BTreeMap::new(),
            retired_sessions: BTreeMap::new(),
            remote_shutdown: false,
            records: BTreeMap::new(),
            published: ArcSwap::from_pointee(DisplayInventorySnapshot::default()),
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<DisplayInventorySnapshot> {
        self.published.load_full()
    }

    #[must_use]
    pub const fn local_host_id(&self) -> HostId {
        self.local_host_id
    }

    /// Atomically replaces local platform inventory after applying the same
    /// metadata, ownership, primary, revision, and capacity policy as remote
    /// inventory.
    ///
    /// # Errors
    ///
    /// Rejects invalid metadata, stale/equal revision, duplicates, invalid
    /// primary count, or capacity overflow without changing the active state.
    pub fn apply_local_snapshot(
        &mut self,
        revision: u64,
        displays: Vec<Display>,
    ) -> Result<Arc<DisplayInventorySnapshot>, DisplayInventoryError> {
        self.apply_snapshot(
            InventorySource::Local,
            self.local_host_id,
            revision,
            displays,
        )
    }

    /// Applies exactly the next local platform display update.
    ///
    /// # Errors
    ///
    /// Rejects unavailable state, a revision gap, invalid metadata, or a
    /// candidate that would violate primary or capacity invariants.
    pub fn apply_local_update(
        &mut self,
        revision: u64,
        display: Display,
    ) -> Result<Arc<DisplayInventorySnapshot>, DisplayInventoryError> {
        self.apply_update(
            InventorySource::Local,
            self.local_host_id,
            revision,
            display,
        )
    }

    /// Produces a fully revalidated wire snapshot of the current local
    /// inventory in deterministic display-ID order.
    ///
    /// # Errors
    ///
    /// Returns [`DisplayInventoryError::InventoryUnavailable`] before a local
    /// snapshot exists, or a coarse validation error if stored domain state
    /// cannot be represented by the hardened wire schema.
    pub(crate) fn local_wire_snapshot(&self) -> Result<DisplaySnapshotV1, DisplayInventoryError> {
        let record = self
            .records
            .get(&self.local_host_id)
            .filter(|record| record.source == InventorySource::Local)
            .ok_or(DisplayInventoryError::InventoryUnavailable)?;
        let message = DisplaySnapshotV1 {
            revision: record.revision,
            host_id: WireHostId(self.local_host_id.into_bytes()),
            displays: record.displays.values().map(display_to_wire).collect(),
        };
        message
            .validate()
            .map_err(|_| DisplayInventoryError::InvalidMessage)?;
        Ok(message)
    }

    pub(crate) fn apply_remote_snapshot(
        &mut self,
        session: &CurrentAdmittedSession,
        message: &DisplaySnapshotV1,
    ) -> Result<Arc<DisplayInventorySnapshot>, DisplayInventoryError> {
        self.apply_remote_snapshot_bound(self.binding(session)?, message)
    }

    /// Registers an exact admitted session before it may publish remote
    /// display metadata. Retired generations and terminal shutdown cannot be
    /// reactivated.
    pub(crate) fn activate_remote(
        &mut self,
        session: &CurrentAdmittedSession,
    ) -> Result<(), DisplayInventoryError> {
        let binding = self.binding(session)?;
        self.activate_remote_binding(binding)
    }

    pub(crate) fn apply_remote_update(
        &mut self,
        session: &CurrentAdmittedSession,
        message: &DisplayUpdatedV1,
    ) -> Result<Arc<DisplayInventorySnapshot>, DisplayInventoryError> {
        self.apply_remote_update_bound(self.binding(session)?, message)
    }

    /// Removes only inventory minted by this exact admitted session. A stale
    /// generation cannot clear a replacement session's state.
    pub(crate) fn invalidate_remote(&mut self, session: &CurrentAdmittedSession) -> bool {
        let Ok(binding) = self.binding(session) else {
            return false;
        };
        self.invalidate_remote_binding(binding)
    }

    fn invalidate_remote_binding(&mut self, binding: SessionBinding) -> bool {
        if self.active_sessions.get(&binding.remote_host_id) != Some(&binding) {
            return false;
        }
        if !self.retired_sessions.contains_key(&binding.remote_host_id)
            && self.retired_sessions.len() >= self.config.remote_hosts
        {
            self.shutdown_remote();
            return true;
        }
        self.active_sessions.remove(&binding.remote_host_id);
        self.retired_sessions
            .insert(binding.remote_host_id, binding);
        let remove = self
            .records
            .get(&binding.remote_host_id)
            .is_some_and(|record| record.source == InventorySource::Remote(binding));
        if remove {
            self.records.remove(&binding.remote_host_id);
            self.publish();
        }
        true
    }

    /// Clears every remote record during terminal global shutdown. Local
    /// inventory is retained, and this inventory instance permanently rejects
    /// later remote activation.
    pub(crate) fn invalidate_all_remote(&mut self) {
        self.shutdown_remote();
    }

    fn binding(
        &self,
        session: &CurrentAdmittedSession,
    ) -> Result<SessionBinding, DisplayInventoryError> {
        let binding = SessionBinding {
            generation: session.generation(),
            local_host_id: session.local_host_id(),
            remote_host_id: session.remote_host_id(),
        };
        if binding.local_host_id != self.local_host_id
            || binding.remote_host_id.into_bytes() == [0; 16]
            || binding.remote_host_id == binding.local_host_id
        {
            return Err(DisplayInventoryError::SessionMismatch);
        }
        Ok(binding)
    }

    fn activate_remote_binding(
        &mut self,
        binding: SessionBinding,
    ) -> Result<(), DisplayInventoryError> {
        if self.remote_shutdown {
            return Err(DisplayInventoryError::SessionMismatch);
        }
        match self.active_sessions.get(&binding.remote_host_id) {
            Some(active) if *active == binding => return Ok(()),
            Some(_) => return Err(DisplayInventoryError::SessionMismatch),
            None => {}
        }
        if self
            .retired_sessions
            .get(&binding.remote_host_id)
            // Generation ordering includes the process-monotonic, never-reused
            // gate instance ID before its per-gate sequence. A replacement
            // gate therefore orders after every token from an older gate.
            .is_some_and(|retired| binding.generation <= retired.generation)
        {
            return Err(DisplayInventoryError::SessionMismatch);
        }
        if self.active_sessions.len() >= self.config.remote_hosts {
            return Err(DisplayInventoryError::CapacityExceeded);
        }
        self.active_sessions.insert(binding.remote_host_id, binding);
        Ok(())
    }

    fn require_active(&self, binding: SessionBinding) -> Result<(), DisplayInventoryError> {
        if self.active_sessions.get(&binding.remote_host_id) == Some(&binding) {
            Ok(())
        } else {
            Err(DisplayInventoryError::SessionMismatch)
        }
    }

    fn shutdown_remote(&mut self) {
        self.remote_shutdown = true;
        self.active_sessions.clear();
        self.retired_sessions.clear();
        self.records
            .retain(|_, record| record.source == InventorySource::Local);
        self.publish();
    }

    fn apply_remote_snapshot_bound(
        &mut self,
        binding: SessionBinding,
        message: &DisplaySnapshotV1,
    ) -> Result<Arc<DisplayInventorySnapshot>, DisplayInventoryError> {
        self.require_active(binding)?;
        message
            .validate()
            .map_err(|_| DisplayInventoryError::InvalidMessage)?;
        if message.host_id.0 != binding.remote_host_id.into_bytes() {
            return Err(DisplayInventoryError::SessionMismatch);
        }
        let displays = message
            .displays
            .iter()
            .map(|display| display_from_wire(display, binding.remote_host_id))
            .collect::<Result<Vec<_>, _>>()?;
        self.apply_snapshot(
            InventorySource::Remote(binding),
            binding.remote_host_id,
            message.revision,
            displays,
        )
    }

    fn apply_remote_update_bound(
        &mut self,
        binding: SessionBinding,
        message: &DisplayUpdatedV1,
    ) -> Result<Arc<DisplayInventorySnapshot>, DisplayInventoryError> {
        self.require_active(binding)?;
        message
            .validate()
            .map_err(|_| DisplayInventoryError::InvalidMessage)?;
        let display = display_from_wire(&message.display, binding.remote_host_id)?;
        self.apply_update(
            InventorySource::Remote(binding),
            binding.remote_host_id,
            message.revision,
            display,
        )
    }

    fn apply_snapshot(
        &mut self,
        source: InventorySource,
        host_id: HostId,
        revision: u64,
        displays: Vec<Display>,
    ) -> Result<Arc<DisplayInventorySnapshot>, DisplayInventoryError> {
        if revision == 0 {
            return Err(DisplayInventoryError::InvalidRevision);
        }
        if let Some(existing) = self.records.get(&host_id) {
            if existing.source != source {
                return Err(DisplayInventoryError::SessionMismatch);
            }
            if revision <= existing.revision {
                return Err(DisplayInventoryError::StaleRevision);
            }
        }
        let candidate = self.validate_candidate(host_id, displays)?;
        self.ensure_total_capacity(host_id, candidate.len())?;
        self.records.insert(
            host_id,
            HostRecord {
                source,
                revision,
                displays: candidate,
            },
        );
        Ok(self.publish())
    }

    fn apply_update(
        &mut self,
        source: InventorySource,
        host_id: HostId,
        revision: u64,
        display: Display,
    ) -> Result<Arc<DisplayInventorySnapshot>, DisplayInventoryError> {
        let existing = self
            .records
            .get(&host_id)
            .ok_or(DisplayInventoryError::InventoryUnavailable)?;
        if existing.source != source {
            return Err(DisplayInventoryError::SessionMismatch);
        }
        let next_revision = existing
            .revision
            .checked_add(1)
            .ok_or(DisplayInventoryError::RevisionExhausted)?;
        if revision < next_revision {
            return Err(DisplayInventoryError::StaleRevision);
        }
        if revision != next_revision {
            return Err(DisplayInventoryError::RevisionGap);
        }
        validate_domain_display(&display, host_id)?;
        let mut candidate = existing.displays.clone();
        candidate.insert(display.id, display);
        validate_primary_count(candidate.values())?;
        if candidate.len() > self.config.displays_per_host {
            return Err(DisplayInventoryError::CapacityExceeded);
        }
        self.ensure_total_capacity(host_id, candidate.len())?;
        self.records.insert(
            host_id,
            HostRecord {
                source,
                revision,
                displays: candidate,
            },
        );
        Ok(self.publish())
    }

    fn validate_candidate(
        &self,
        host_id: HostId,
        displays: Vec<Display>,
    ) -> Result<BTreeMap<DisplayId, Display>, DisplayInventoryError> {
        if displays.len() > self.config.displays_per_host {
            return Err(DisplayInventoryError::CapacityExceeded);
        }
        let mut candidate = BTreeMap::new();
        for display in displays {
            validate_domain_display(&display, host_id)?;
            if candidate.insert(display.id, display).is_some() {
                return Err(DisplayInventoryError::DuplicateDisplay);
            }
        }
        validate_primary_count(candidate.values())?;
        Ok(candidate)
    }

    fn ensure_total_capacity(
        &self,
        replacing_host: HostId,
        replacement_count: usize,
    ) -> Result<(), DisplayInventoryError> {
        let existing_elsewhere = self
            .records
            .iter()
            .filter(|(host, _)| **host != replacing_host)
            .try_fold(0_usize, |total, (_, record)| {
                total.checked_add(record.displays.len())
            })
            .ok_or(DisplayInventoryError::CapacityExceeded)?;
        if existing_elsewhere
            .checked_add(replacement_count)
            .is_none_or(|total| total > self.config.total_displays)
        {
            return Err(DisplayInventoryError::CapacityExceeded);
        }
        Ok(())
    }

    fn publish(&self) -> Arc<DisplayInventorySnapshot> {
        let mut hosts = BTreeMap::new();
        let mut display_count = 0_usize;
        for (host_id, record) in &self.records {
            display_count += record.displays.len();
            hosts.insert(
                *host_id,
                HostDisplayInventorySnapshot {
                    host_id: *host_id,
                    revision: record.revision,
                    displays: record.displays.clone(),
                },
            );
        }
        let snapshot = Arc::new(DisplayInventorySnapshot {
            hosts,
            display_count,
        });
        self.published.store(Arc::clone(&snapshot));
        snapshot
    }
}

impl fmt::Debug for DisplayInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snapshot = self.published.load();
        formatter
            .debug_struct("DisplayInventory")
            .field("config", &self.config)
            .field("active_session_count", &self.active_sessions.len())
            .field("retired_session_count", &self.retired_sessions.len())
            .field("remote_shutdown", &self.remote_shutdown)
            .field("host_count", &snapshot.host_count())
            .field("display_count", &snapshot.display_count())
            .finish_non_exhaustive()
    }
}

fn display_from_wire(
    wire: &WireDisplayV1,
    expected_host: HostId,
) -> Result<Display, DisplayInventoryError> {
    if wire.host_id.0 != expected_host.into_bytes() {
        return Err(DisplayInventoryError::SessionMismatch);
    }
    let display = Display {
        id: DisplayId::from_bytes(wire.id.0),
        host_id: HostId::from_bytes(wire.host_id.0),
        name: wire.name.clone(),
        logical_size: Size::new(wire.logical_size.width, wire.logical_size.height),
        physical_size: wire
            .physical_size
            .map(|size| Size::new(size.width, size.height)),
        scale_factor: wire.scale_factor,
        refresh_rate: wire.refresh_rate,
        native_bounds: Rect::new(
            wire.native_bounds.x,
            wire.native_bounds.y,
            wire.native_bounds.width,
            wire.native_bounds.height,
        ),
        primary: wire.primary,
    };
    validate_domain_display(&display, expected_host)?;
    Ok(display)
}

fn display_to_wire(display: &Display) -> WireDisplayV1 {
    WireDisplayV1 {
        id: WireDisplayId(display.id.into_bytes()),
        host_id: WireHostId(display.host_id.into_bytes()),
        name: display.name.clone(),
        logical_size: WireSize {
            width: display.logical_size.width,
            height: display.logical_size.height,
        },
        physical_size: display.physical_size.map(|size| WireSize {
            width: size.width,
            height: size.height,
        }),
        scale_factor: display.scale_factor,
        refresh_rate: display.refresh_rate,
        native_bounds: WireRect {
            x: display.native_bounds.x,
            y: display.native_bounds.y,
            width: display.native_bounds.width,
            height: display.native_bounds.height,
        },
        primary: display.primary,
    }
}

fn validate_domain_display(
    display: &Display,
    expected_host: HostId,
) -> Result<(), DisplayInventoryError> {
    if display.id.into_bytes() == [0; 16]
        || display.host_id != expected_host
        || expected_host.into_bytes() == [0; 16]
        || display.name.trim().is_empty()
        || display.name.len() > MAX_DISPLAY_NAME_BYTES
        || display.name.chars().any(char::is_control)
        || !positive_bounded(display.logical_size.width, MAX_DISPLAY_LOGICAL_DIMENSION)
        || !positive_bounded(display.logical_size.height, MAX_DISPLAY_LOGICAL_DIMENSION)
        || display.physical_size.is_some_and(|size| {
            !positive_bounded(size.width, MAX_DISPLAY_PHYSICAL_DIMENSION)
                || !positive_bounded(size.height, MAX_DISPLAY_PHYSICAL_DIMENSION)
        })
        || !positive_bounded(display.scale_factor, MAX_DISPLAY_SCALE_FACTOR)
        || display
            .refresh_rate
            .is_some_and(|rate| !positive_bounded(rate, MAX_DISPLAY_REFRESH_RATE_HZ))
        || !bounded_coordinate(display.native_bounds.x)
        || !bounded_coordinate(display.native_bounds.y)
        || !positive_bounded(display.native_bounds.width, MAX_DISPLAY_PHYSICAL_DIMENSION)
        || !positive_bounded(display.native_bounds.height, MAX_DISPLAY_PHYSICAL_DIMENSION)
        || !bounded_coordinate(display.native_bounds.x + display.native_bounds.width)
        || !bounded_coordinate(display.native_bounds.y + display.native_bounds.height)
    {
        return Err(DisplayInventoryError::InvalidDisplay);
    }
    Ok(())
}

fn positive_bounded(value: f64, maximum: f64) -> bool {
    value.is_finite() && value > 0.0 && value <= maximum
}

fn bounded_coordinate(value: f64) -> bool {
    value.is_finite() && value.abs() <= MAX_DISPLAY_NATIVE_COORDINATE_ABS
}

fn validate_primary_count<'a>(
    displays: impl IntoIterator<Item = &'a Display>,
) -> Result<(), DisplayInventoryError> {
    if displays
        .into_iter()
        .filter(|display| display.primary)
        .count()
        != 1
    {
        return Err(DisplayInventoryError::InvalidPrimaryCount);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_network::ConnectionGenerationGate;
    use kvm_protocol::{WireHostId, WirePeerId, WireRect, WireSize};

    fn host(value: u8) -> HostId {
        HostId::from_bytes([value; 16])
    }

    fn display(value: u8, owner: HostId, primary: bool) -> Display {
        Display {
            id: DisplayId::from_bytes([value; 16]),
            host_id: owner,
            name: format!("display-{value}"),
            logical_size: Size::new(1_920.0, 1_080.0),
            physical_size: Some(Size::new(3_840.0, 2_160.0)),
            scale_factor: 2.0,
            refresh_rate: Some(120.0),
            native_bounds: Rect::new(0.0, 0.0, 1_920.0, 1_080.0),
            primary,
        }
    }

    fn wire_display(value: u8, owner: HostId, primary: bool) -> WireDisplayV1 {
        let display = display(value, owner, primary);
        WireDisplayV1 {
            id: kvm_protocol::WireDisplayId(display.id.into_bytes()),
            host_id: WireHostId(display.host_id.into_bytes()),
            name: display.name,
            logical_size: WireSize {
                width: display.logical_size.width,
                height: display.logical_size.height,
            },
            physical_size: display.physical_size.map(|size| WireSize {
                width: size.width,
                height: size.height,
            }),
            scale_factor: display.scale_factor,
            refresh_rate: display.refresh_rate,
            native_bounds: WireRect {
                x: display.native_bounds.x,
                y: display.native_bounds.y,
                width: display.native_bounds.width,
                height: display.native_bounds.height,
            },
            primary: display.primary,
        }
    }

    fn generation(value: u8) -> ConnectionGeneration {
        let mut gate = ConnectionGenerationGate::new(
            WirePeerId([value; 16]),
            WirePeerId([value.saturating_add(64); 16]),
        )
        .unwrap();
        let pending = gate.begin_pending(gate.role().direction()).unwrap();
        gate.activate(pending).unwrap().generation()
    }

    fn binding(value: u8, local: HostId, remote: HostId) -> SessionBinding {
        SessionBinding {
            generation: generation(value),
            local_host_id: local,
            remote_host_id: remote,
        }
    }

    fn inventory(local: HostId) -> DisplayInventory {
        DisplayInventory::new(local, DisplayInventoryConfig::default()).unwrap()
    }

    #[test]
    fn configuration_and_local_host_are_positively_bounded() {
        assert!(matches!(
            DisplayInventory::new(host(0), DisplayInventoryConfig::default()),
            Err(DisplayInventoryError::InvalidHost)
        ));
        for config in [
            DisplayInventoryConfig {
                remote_hosts: 0,
                ..DisplayInventoryConfig::default()
            },
            DisplayInventoryConfig {
                displays_per_host: MAX_INVENTORY_DISPLAYS_PER_HOST + 1,
                ..DisplayInventoryConfig::default()
            },
            DisplayInventoryConfig {
                total_displays: MAX_INVENTORY_TOTAL_DISPLAYS + 1,
                ..DisplayInventoryConfig::default()
            },
            DisplayInventoryConfig {
                displays_per_host: 2,
                total_displays: 1,
                ..DisplayInventoryConfig::default()
            },
        ] {
            assert!(matches!(
                DisplayInventory::new(host(1), config),
                Err(DisplayInventoryError::InvalidConfiguration)
            ));
        }
    }

    #[test]
    fn snapshots_replace_atomically_and_publish_deterministic_order() {
        let local = host(1);
        let mut inventory = inventory(local);
        let first = inventory
            .apply_local_snapshot(3, vec![display(9, local, false), display(7, local, true)])
            .unwrap();
        assert_eq!(first.host(local).unwrap().revision(), 3);
        assert_eq!(
            first
                .host(local)
                .unwrap()
                .iter()
                .map(|display| display.id)
                .collect::<Vec<_>>(),
            vec![
                DisplayId::from_bytes([7; 16]),
                DisplayId::from_bytes([9; 16])
            ]
        );

        for revision in [2, 3] {
            assert_eq!(
                inventory.apply_local_snapshot(revision, vec![display(8, local, true)]),
                Err(DisplayInventoryError::StaleRevision)
            );
        }
        let unchanged = inventory.snapshot();
        assert_eq!(unchanged.host(local).unwrap().revision(), 3);
        assert!(unchanged
            .host(local)
            .unwrap()
            .get(DisplayId::from_bytes([7; 16]))
            .is_some());

        let jumped = inventory
            .apply_local_snapshot(10, vec![display(8, local, true)])
            .unwrap();
        assert_eq!(jumped.host(local).unwrap().revision(), 10);
        assert_eq!(jumped.display_count(), 1);
    }

    #[test]
    fn local_wire_snapshot_is_unavailable_then_revalidated_and_ordered() {
        let local = host(1);
        let mut inventory = inventory(local);
        assert_eq!(
            inventory.local_wire_snapshot(),
            Err(DisplayInventoryError::InventoryUnavailable)
        );
        let mut marked = display(9, local, false);
        marked.name = "local-wire-display-marker".to_owned();
        inventory
            .apply_local_snapshot(7, vec![marked, display(7, local, true)])
            .unwrap();

        let message = inventory.local_wire_snapshot().unwrap();

        assert_eq!(message.revision, 7);
        assert_eq!(message.host_id, WireHostId(local.into_bytes()));
        assert_eq!(
            message
                .displays
                .iter()
                .map(|display| display.id)
                .collect::<Vec<_>>(),
            vec![WireDisplayId([7; 16]), WireDisplayId([9; 16])]
        );
        message.validate().unwrap();
        assert!(!format!("{message:?}").contains("local-wire-display-marker"));
    }

    #[test]
    fn updates_require_the_next_exact_revision_and_preserve_atomic_state() {
        let local = host(1);
        let mut inventory = inventory(local);
        inventory
            .apply_local_snapshot(5, vec![display(1, local, true)])
            .unwrap();
        assert_eq!(
            inventory.apply_local_update(7, display(2, local, false)),
            Err(DisplayInventoryError::RevisionGap)
        );
        assert_eq!(
            inventory.apply_local_update(5, display(2, local, false)),
            Err(DisplayInventoryError::StaleRevision)
        );
        let before = inventory.snapshot();
        assert_eq!(before.host(local).unwrap().revision(), 5);
        assert_eq!(before.display_count(), 1);

        let after = inventory
            .apply_local_update(6, display(2, local, false))
            .unwrap();
        assert_eq!(after.host(local).unwrap().revision(), 6);
        assert_eq!(after.display_count(), 2);
    }

    #[test]
    fn invalid_candidate_primary_owner_name_geometry_and_duplicates_are_atomic() {
        let local = host(1);
        let mut inventory = inventory(local);
        inventory
            .apply_local_snapshot(1, vec![display(1, local, true)])
            .unwrap();
        let original = inventory.snapshot();

        let mut invalid_name = display(2, local, true);
        invalid_name.name = "bad\nname".to_owned();
        let mut blank_name = display(2, local, true);
        blank_name.name = "   ".to_owned();
        let mut nil_id = display(2, local, true);
        nil_id.id = DisplayId::from_bytes([0; 16]);
        let mut invalid_geometry = display(2, local, true);
        invalid_geometry.logical_size.width = MAX_DISPLAY_LOGICAL_DIMENSION + 1.0;
        for (candidate, error) in [
            (
                vec![display(2, host(2), true)],
                DisplayInventoryError::InvalidDisplay,
            ),
            (vec![invalid_name], DisplayInventoryError::InvalidDisplay),
            (vec![blank_name], DisplayInventoryError::InvalidDisplay),
            (vec![nil_id], DisplayInventoryError::InvalidDisplay),
            (
                vec![invalid_geometry],
                DisplayInventoryError::InvalidDisplay,
            ),
            (
                vec![display(2, local, false)],
                DisplayInventoryError::InvalidPrimaryCount,
            ),
            (
                vec![display(2, local, true), display(3, local, true)],
                DisplayInventoryError::InvalidPrimaryCount,
            ),
            (
                vec![display(2, local, true), display(2, local, false)],
                DisplayInventoryError::DuplicateDisplay,
            ),
        ] {
            assert_eq!(inventory.apply_local_snapshot(2, candidate), Err(error));
            assert!(Arc::ptr_eq(&original, &inventory.snapshot()));
        }
    }

    #[test]
    fn capacity_failure_does_not_partially_replace_inventory() {
        let local = host(1);
        let config = DisplayInventoryConfig {
            remote_hosts: 1,
            displays_per_host: 1,
            total_displays: 1,
        };
        let mut inventory = DisplayInventory::new(local, config).unwrap();
        let before = inventory
            .apply_local_snapshot(1, vec![display(1, local, true)])
            .unwrap();
        assert_eq!(
            inventory
                .apply_local_snapshot(2, vec![display(1, local, true), display(2, local, false)]),
            Err(DisplayInventoryError::CapacityExceeded)
        );
        assert!(Arc::ptr_eq(&before, &inventory.snapshot()));
    }

    #[test]
    fn remote_wire_state_is_exactly_session_bound_and_revalidated() {
        let local = host(1);
        let remote = host(2);
        let current = binding(1, local, remote);
        let replacement = binding(2, local, remote);
        let mut inventory = inventory(local);
        let snapshot = DisplaySnapshotV1 {
            revision: 1,
            host_id: WireHostId(remote.into_bytes()),
            displays: vec![wire_display(4, remote, true)],
        };
        assert_eq!(
            inventory.apply_remote_snapshot_bound(current, &snapshot),
            Err(DisplayInventoryError::SessionMismatch)
        );
        inventory.activate_remote_binding(current).unwrap();
        inventory
            .apply_remote_snapshot_bound(current, &snapshot)
            .unwrap();
        assert_eq!(
            inventory.activate_remote_binding(replacement),
            Err(DisplayInventoryError::SessionMismatch)
        );
        assert_eq!(
            inventory.apply_remote_snapshot_bound(replacement, &snapshot),
            Err(DisplayInventoryError::SessionMismatch)
        );

        let wrong_host = DisplaySnapshotV1 {
            host_id: WireHostId(host(3).into_bytes()),
            displays: vec![wire_display(4, host(3), true)],
            ..snapshot.clone()
        };
        assert_eq!(
            inventory.apply_remote_snapshot_bound(current, &wrong_host),
            Err(DisplayInventoryError::SessionMismatch)
        );
        let invalid = DisplaySnapshotV1 {
            revision: 2,
            displays: vec![
                wire_display(4, remote, true),
                wire_display(4, remote, false),
            ],
            ..snapshot
        };
        assert_eq!(
            inventory.apply_remote_snapshot_bound(current, &invalid),
            Err(DisplayInventoryError::InvalidMessage)
        );
        assert_eq!(inventory.snapshot().host(remote).unwrap().revision(), 1);
    }

    #[test]
    fn exact_generation_invalidation_blocks_stale_and_cached_reuse() {
        let local = host(1);
        let remote = host(2);
        let first = binding(1, local, remote);
        let second = binding(2, local, remote);
        assert!(second.generation > first.generation);
        let mut inventory = inventory(local);
        let snapshot = DisplaySnapshotV1 {
            revision: 1,
            host_id: WireHostId(remote.into_bytes()),
            displays: vec![wire_display(4, remote, true)],
        };
        inventory.activate_remote_binding(first).unwrap();
        inventory
            .apply_remote_snapshot_bound(first, &snapshot)
            .unwrap();
        assert!(!inventory.invalidate_remote_binding(second));
        assert!(inventory.snapshot().host(remote).is_some());
        assert!(inventory.invalidate_remote_binding(first));
        assert!(inventory.snapshot().host(remote).is_none());
        assert_eq!(
            inventory.activate_remote_binding(first),
            Err(DisplayInventoryError::SessionMismatch)
        );
        assert_eq!(
            inventory.apply_remote_snapshot_bound(first, &snapshot),
            Err(DisplayInventoryError::SessionMismatch)
        );
        inventory.activate_remote_binding(second).unwrap();
        inventory
            .apply_remote_snapshot_bound(second, &snapshot)
            .unwrap();
        assert_eq!(
            inventory.apply_remote_snapshot_bound(first, &snapshot),
            Err(DisplayInventoryError::SessionMismatch)
        );
        assert!(inventory.snapshot().host(remote).is_some());
    }

    #[test]
    fn global_invalidation_is_terminal_for_cached_session_tokens() {
        let local = host(1);
        let remote = host(2);
        let current = binding(1, local, remote);
        let replacement = binding(2, local, remote);
        let mut inventory = inventory(local);
        let snapshot = DisplaySnapshotV1 {
            revision: 1,
            host_id: WireHostId(remote.into_bytes()),
            displays: vec![wire_display(4, remote, true)],
        };
        inventory.activate_remote_binding(current).unwrap();
        inventory
            .apply_remote_snapshot_bound(current, &snapshot)
            .unwrap();

        inventory.invalidate_all_remote();

        assert!(inventory.snapshot().host(remote).is_none());
        for session in [current, replacement] {
            assert_eq!(
                inventory.activate_remote_binding(session),
                Err(DisplayInventoryError::SessionMismatch)
            );
            assert_eq!(
                inventory.apply_remote_snapshot_bound(session, &snapshot),
                Err(DisplayInventoryError::SessionMismatch)
            );
        }
    }

    #[test]
    fn active_and_retired_remote_host_bounds_are_independent() {
        let local = host(1);
        let config = DisplayInventoryConfig {
            remote_hosts: 1,
            ..DisplayInventoryConfig::default()
        };
        let mut inventory = DisplayInventory::new(local, config).unwrap();
        let first = binding(1, local, host(2));
        let second = binding(2, local, host(3));

        inventory.activate_remote_binding(first).unwrap();
        assert_eq!(
            inventory.activate_remote_binding(second),
            Err(DisplayInventoryError::CapacityExceeded)
        );
        assert!(inventory.invalidate_remote_binding(first));
        inventory.activate_remote_binding(second).unwrap();
    }

    #[test]
    fn retired_host_churn_overflow_transitions_to_terminal_shutdown() {
        let local = host(1);
        let config = DisplayInventoryConfig {
            remote_hosts: 1,
            ..DisplayInventoryConfig::default()
        };
        let mut inventory = DisplayInventory::new(local, config).unwrap();
        let first = binding(1, local, host(2));
        let second = binding(2, local, host(3));
        let third = binding(3, local, host(4));

        inventory.activate_remote_binding(first).unwrap();
        assert!(inventory.invalidate_remote_binding(first));
        inventory.activate_remote_binding(second).unwrap();
        assert!(inventory.invalidate_remote_binding(second));
        assert!(inventory.remote_shutdown);
        for session in [first, second, third] {
            assert_eq!(
                inventory.activate_remote_binding(session),
                Err(DisplayInventoryError::SessionMismatch)
            );
        }
    }

    #[test]
    fn diagnostics_are_count_only_and_redact_stable_metadata() {
        let local = host(71);
        let mut inventory = inventory(local);
        let mut marked = display(83, local, true);
        marked.name = "peer-controlled-display-marker".to_owned();
        let snapshot = inventory.apply_local_snapshot(97, vec![marked]).unwrap();
        let inventory_debug = format!("{inventory:?}");
        let snapshot_debug = format!("{snapshot:?}");
        let host_debug = format!("{:?}", snapshot.host(local).unwrap());
        for debug in [inventory_debug, snapshot_debug, host_debug] {
            assert!(!debug.contains("peer-controlled-display-marker"));
            assert!(!debug.contains("WireHostId"));
            assert!(!debug.contains("DisplayId"));
            assert!(!debug.contains("97"));
        }
    }

    #[test]
    fn update_at_maximum_revision_fails_closed() {
        let local = host(1);
        let mut inventory = inventory(local);
        inventory
            .apply_local_snapshot(u64::MAX, vec![display(1, local, true)])
            .unwrap();
        assert_eq!(
            inventory.apply_local_update(u64::MAX, display(2, local, false)),
            Err(DisplayInventoryError::RevisionExhausted)
        );
        assert_eq!(inventory.snapshot().display_count(), 1);
    }
}
