//! Bounded, revisioned device inventories for runtime routing policy.
//!
//! Remote metadata is accepted only through a live borrow of the exact current
//! admitted session. Published snapshots are observational: retaining one does
//! not retain admission authority for its originating connection generation.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use kvm_network::ConnectionGeneration;
use kvm_protocol::{
    DeviceAddedV1, DeviceRemovedV1, DeviceSnapshotV1, WireDeviceCapabilities, WireDeviceId,
    WireDeviceKind, WireHostId, WireInputDeviceV1, MAX_DEVICE_NAME_BYTES, MAX_SNAPSHOT_ITEMS,
};
use kvm_types::{DeviceCapabilities, DeviceId, DeviceKind, HostId, InputDevice, PeerId};
use thiserror::Error;

use crate::supervisor::CurrentAdmittedSession;

pub const MAX_DEVICE_INVENTORY_REMOTE_HOSTS: usize = 256;
pub const MAX_DEVICE_INVENTORY_PER_HOST: usize = MAX_SNAPSHOT_ITEMS;
pub const MAX_DEVICE_INVENTORY_TOTAL: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceInventoryConfig {
    pub remote_hosts: usize,
    pub devices_per_host: usize,
    pub total_devices: usize,
}

impl Default for DeviceInventoryConfig {
    fn default() -> Self {
        Self {
            remote_hosts: 32,
            devices_per_host: 256,
            total_devices: 1_024,
        }
    }
}

impl DeviceInventoryConfig {
    fn validate(self) -> Result<Self, DeviceInventoryError> {
        if self.remote_hosts == 0
            || self.remote_hosts > MAX_DEVICE_INVENTORY_REMOTE_HOSTS
            || self.devices_per_host == 0
            || self.devices_per_host > MAX_DEVICE_INVENTORY_PER_HOST
            || self.total_devices == 0
            || self.total_devices > MAX_DEVICE_INVENTORY_TOTAL
            || self.devices_per_host > self.total_devices
        {
            return Err(DeviceInventoryError::InvalidConfiguration);
        }
        Ok(self)
    }
}

/// Payload- and identity-redacted inventory failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DeviceInventoryError {
    #[error("device inventory configuration is invalid")]
    InvalidConfiguration,
    #[error("device inventory host identity is invalid")]
    InvalidHost,
    #[error("device inventory message failed validation")]
    InvalidMessage,
    #[error("device inventory metadata is invalid")]
    InvalidDevice,
    #[error("device inventory revision is invalid")]
    InvalidRevision,
    #[error("device inventory contains a duplicate device")]
    DuplicateDevice,
    #[error("device inventory update requires a new device")]
    DeviceAlreadyExists,
    #[error("device inventory removal requires an existing device")]
    DeviceNotFound,
    #[error("device inventory capacity was exceeded")]
    CapacityExceeded,
    #[error("device inventory revision is stale or duplicated")]
    StaleRevision,
    #[error("device inventory update skipped a required revision")]
    RevisionGap,
    #[error("device inventory revision space is exhausted")]
    RevisionExhausted,
    #[error("device inventory is unavailable for this host")]
    InventoryUnavailable,
    #[error("device inventory belongs to another admitted session")]
    SessionMismatch,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HostDeviceInventorySnapshot {
    host_id: HostId,
    revision: u64,
    devices: BTreeMap<DeviceId, InputDevice>,
}

impl HostDeviceInventorySnapshot {
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
        self.devices.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    #[must_use]
    pub fn get(&self, device_id: DeviceId) -> Option<&InputDevice> {
        self.devices.get(&device_id)
    }

    #[must_use]
    pub fn contains(&self, device_id: DeviceId) -> bool {
        self.devices.contains_key(&device_id)
    }

    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &InputDevice> {
        self.devices.values()
    }
}

impl fmt::Debug for HostDeviceInventorySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostDeviceInventorySnapshot")
            .field("device_count", &self.devices.len())
            .finish_non_exhaustive()
    }
}

/// Immutable observational inventory projection.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct DeviceInventorySnapshot {
    hosts: BTreeMap<HostId, HostDeviceInventorySnapshot>,
    device_count: usize,
}

impl DeviceInventorySnapshot {
    #[must_use]
    pub fn host(&self, host_id: HostId) -> Option<&HostDeviceInventorySnapshot> {
        self.hosts.get(&host_id)
    }

    #[must_use]
    pub fn hosts(&self) -> impl ExactSizeIterator<Item = &HostDeviceInventorySnapshot> {
        self.hosts.values()
    }

    pub fn devices(&self) -> impl Iterator<Item = &InputDevice> {
        self.hosts
            .values()
            .flat_map(HostDeviceInventorySnapshot::iter)
    }

    #[must_use]
    pub fn device(&self, host_id: HostId, device_id: DeviceId) -> Option<&InputDevice> {
        self.host(host_id)?.get(device_id)
    }

    #[must_use]
    pub fn owns_device(&self, host_id: HostId, device_id: DeviceId) -> bool {
        self.host(host_id)
            .is_some_and(|inventory| inventory.contains(device_id))
    }

    #[must_use]
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    #[must_use]
    pub const fn device_count(&self) -> usize {
        self.device_count
    }
}

impl fmt::Debug for DeviceInventorySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceInventorySnapshot")
            .field("host_count", &self.hosts.len())
            .field("device_count", &self.device_count)
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SessionBinding {
    generation: ConnectionGeneration,
    local_host_id: HostId,
    remote_host_id: HostId,
    remote_peer_id: PeerId,
    credential_fingerprint: [u8; 32],
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

#[derive(Clone)]
struct HostRecord {
    source: InventorySource,
    revision: u64,
    devices: BTreeMap<DeviceId, InputDevice>,
}

#[derive(Clone, Copy, Default)]
struct RemoteSessionSlot {
    current: Option<SessionBinding>,
    retired: Option<SessionBinding>,
    suspended_revision: Option<u64>,
}

/// Mutable bounded device inventory.
///
/// Cloning creates an independent transactional candidate with the same
/// published value. Mutating that candidate cannot affect readers of the
/// original inventory until its owner explicitly replaces the original.
pub struct DeviceInventory {
    local_host_id: HostId,
    config: DeviceInventoryConfig,
    remote_sessions: BTreeMap<HostId, RemoteSessionSlot>,
    remote_shutdown: bool,
    records: BTreeMap<HostId, HostRecord>,
    published: ArcSwap<DeviceInventorySnapshot>,
}

impl Clone for DeviceInventory {
    fn clone(&self) -> Self {
        Self {
            local_host_id: self.local_host_id,
            config: self.config,
            remote_sessions: self.remote_sessions.clone(),
            remote_shutdown: self.remote_shutdown,
            records: self.records.clone(),
            published: ArcSwap::from(self.published.load_full()),
        }
    }
}

impl DeviceInventory {
    /// Creates an empty inventory for one non-nil local host.
    ///
    /// # Errors
    ///
    /// Rejects a nil local host or a zero/excessive resource bound.
    pub fn new(
        local_host_id: HostId,
        config: DeviceInventoryConfig,
    ) -> Result<Self, DeviceInventoryError> {
        if local_host_id.into_bytes() == [0; 16] {
            return Err(DeviceInventoryError::InvalidHost);
        }
        Ok(Self {
            local_host_id,
            config: config.validate()?,
            remote_sessions: BTreeMap::new(),
            remote_shutdown: false,
            records: BTreeMap::new(),
            published: ArcSwap::from_pointee(DeviceInventorySnapshot::default()),
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<DeviceInventorySnapshot> {
        self.published.load_full()
    }

    #[must_use]
    pub const fn local_host_id(&self) -> HostId {
        self.local_host_id
    }

    #[must_use]
    pub fn contains_local_device(&self, device_id: DeviceId) -> bool {
        self.records.get(&self.local_host_id).is_some_and(|record| {
            record.source == InventorySource::Local && record.devices.contains_key(&device_id)
        })
    }

    #[must_use]
    pub fn local_device(&self, device_id: DeviceId) -> Option<&InputDevice> {
        self.records
            .get(&self.local_host_id)
            .filter(|record| record.source == InventorySource::Local)?
            .devices
            .get(&device_id)
    }

    /// Atomically replaces local inventory. A positive revision may jump but
    /// must be strictly newer than the current full state.
    ///
    /// # Errors
    ///
    /// Rejects invalid ownership or metadata, a stale/zero revision,
    /// duplicates, or a candidate exceeding configured capacity.
    pub fn apply_local_snapshot(
        &mut self,
        revision: u64,
        devices: Vec<InputDevice>,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        self.apply_snapshot(
            InventorySource::Local,
            self.local_host_id,
            revision,
            devices,
        )
    }

    /// Adds a new local device at exactly the next revision.
    ///
    /// # Errors
    ///
    /// Rejects unavailable inventory, an inexact revision, invalid metadata,
    /// an existing identifier, or a capacity overflow.
    pub fn apply_local_add(
        &mut self,
        revision: u64,
        device: InputDevice,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        self.apply_add(InventorySource::Local, self.local_host_id, revision, device)
    }

    /// Removes an existing local device at exactly the next revision.
    ///
    /// # Errors
    ///
    /// Rejects unavailable inventory, an inexact revision, a nil identifier,
    /// or an identifier which is not currently present.
    pub fn apply_local_remove(
        &mut self,
        revision: u64,
        device_id: DeviceId,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        self.apply_remove(
            InventorySource::Local,
            self.local_host_id,
            revision,
            device_id,
        )
    }

    /// Generates a fully revalidated deterministic local wire snapshot.
    pub(crate) fn local_wire_snapshot(&self) -> Result<DeviceSnapshotV1, DeviceInventoryError> {
        let record = self
            .records
            .get(&self.local_host_id)
            .filter(|record| record.source == InventorySource::Local)
            .ok_or(DeviceInventoryError::InventoryUnavailable)?;
        let message = DeviceSnapshotV1 {
            revision: record.revision,
            host_id: WireHostId(self.local_host_id.into_bytes()),
            devices: record.devices.values().map(device_to_wire).collect(),
        };
        validate_wire_snapshot(&message, self.local_host_id, self.config.devices_per_host)?;
        Ok(message)
    }

    pub(crate) fn activate_remote(
        &mut self,
        session: &CurrentAdmittedSession,
    ) -> Result<(), DeviceInventoryError> {
        let binding = self.binding(session)?;
        self.activate_remote_binding(binding)
    }

    pub(crate) fn apply_remote_snapshot(
        &mut self,
        session: &CurrentAdmittedSession,
        message: &DeviceSnapshotV1,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        self.apply_remote_snapshot_bound(self.binding(session)?, message)
    }

    pub(crate) fn apply_remote_add(
        &mut self,
        session: &CurrentAdmittedSession,
        message: &DeviceAddedV1,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        self.apply_remote_add_bound(self.binding(session)?, message)
    }

    pub(crate) fn apply_remote_remove(
        &mut self,
        session: &CurrentAdmittedSession,
        message: &DeviceRemovedV1,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        self.apply_remote_remove_bound(self.binding(session)?, message)
    }

    /// Returns one device only when the caller presents the exact active
    /// admitted session which owns the current remote record. Observational
    /// snapshots cannot be used to satisfy this authority check.
    pub(crate) fn remote_device(
        &self,
        session: &CurrentAdmittedSession,
        device_id: DeviceId,
    ) -> Result<&InputDevice, DeviceInventoryError> {
        self.remote_device_bound(self.binding(session)?, device_id)
    }

    /// Invalidates only the exact current generation represented by `session`.
    pub(crate) fn invalidate_remote(&mut self, session: &CurrentAdmittedSession) -> bool {
        let Ok(binding) = self.binding(session) else {
            return false;
        };
        self.invalidate_remote_binding(binding)
    }

    /// Removes metadata authority for an exact degraded session without
    /// retiring its transport generation. That same generation must publish a
    /// strictly newer full snapshot before its metadata becomes observable
    /// again.
    pub(crate) fn suspend_remote(&mut self, session: &CurrentAdmittedSession) -> bool {
        let Ok(binding) = self.binding(session) else {
            return false;
        };
        self.suspend_remote_binding(binding)
    }

    /// Permanently rejects remote repopulation and retains only local state.
    pub(crate) fn invalidate_all_remote(&mut self) {
        self.remote_shutdown = true;
        self.remote_sessions.clear();
        self.records
            .retain(|_, record| record.source == InventorySource::Local);
        self.publish();
    }

    fn binding(
        &self,
        session: &CurrentAdmittedSession,
    ) -> Result<SessionBinding, DeviceInventoryError> {
        let transport = session.transport_identity();
        let remote_peer_id = PeerId::from_bytes(transport.peer_id.0);
        let binding = SessionBinding {
            generation: session.generation(),
            local_host_id: session.local_host_id(),
            remote_host_id: session.remote_host_id(),
            remote_peer_id,
            credential_fingerprint: transport.credential_fingerprint,
        };
        if binding.local_host_id != self.local_host_id
            || binding.remote_host_id.into_bytes() == [0; 16]
            || binding.remote_host_id == binding.local_host_id
            || binding.remote_peer_id.into_bytes() == [0; 16]
            || transport.host_id.0 != binding.remote_host_id.into_bytes()
            || session.remote_hello().peer_id.0 != binding.remote_peer_id.into_bytes()
            || binding.credential_fingerprint == [0; 32]
        {
            return Err(DeviceInventoryError::SessionMismatch);
        }
        Ok(binding)
    }

    fn activate_remote_binding(
        &mut self,
        binding: SessionBinding,
    ) -> Result<(), DeviceInventoryError> {
        if self.remote_shutdown {
            return Err(DeviceInventoryError::SessionMismatch);
        }
        if let Some(slot) = self.remote_sessions.get(&binding.remote_host_id) {
            if slot.current == Some(binding) {
                return Ok(());
            }
            if slot.current.is_some()
                || slot
                    .retired
                    .is_some_and(|retired| binding.generation <= retired.generation)
            {
                return Err(DeviceInventoryError::SessionMismatch);
            }
        } else if self.remote_sessions.len() >= self.config.remote_hosts {
            return Err(DeviceInventoryError::CapacityExceeded);
        }
        self.remote_sessions
            .entry(binding.remote_host_id)
            .or_default()
            .current = Some(binding);
        if let Some(slot) = self.remote_sessions.get_mut(&binding.remote_host_id) {
            slot.suspended_revision = None;
        }
        Ok(())
    }

    fn require_active(&self, binding: SessionBinding) -> Result<(), DeviceInventoryError> {
        if self
            .remote_sessions
            .get(&binding.remote_host_id)
            .and_then(|slot| slot.current)
            == Some(binding)
        {
            Ok(())
        } else {
            Err(DeviceInventoryError::SessionMismatch)
        }
    }

    fn remote_device_bound(
        &self,
        binding: SessionBinding,
        device_id: DeviceId,
    ) -> Result<&InputDevice, DeviceInventoryError> {
        if device_id.into_bytes() == [0; 16] {
            return Err(DeviceInventoryError::InvalidDevice);
        }
        self.require_active(binding)?;
        self.records
            .get(&binding.remote_host_id)
            .filter(|record| record.source == InventorySource::Remote(binding))
            .ok_or(DeviceInventoryError::InventoryUnavailable)?
            .devices
            .get(&device_id)
            .ok_or(DeviceInventoryError::DeviceNotFound)
    }

    fn invalidate_remote_binding(&mut self, binding: SessionBinding) -> bool {
        let Some(slot) = self.remote_sessions.get_mut(&binding.remote_host_id) else {
            return false;
        };
        if slot.current != Some(binding) {
            return false;
        }
        slot.current = None;
        slot.retired = Some(binding);
        slot.suspended_revision = None;
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

    fn suspend_remote_binding(&mut self, binding: SessionBinding) -> bool {
        let Some(slot) = self.remote_sessions.get_mut(&binding.remote_host_id) else {
            return false;
        };
        if slot.current != Some(binding) {
            return false;
        }
        let suspended_revision = self
            .records
            .get(&binding.remote_host_id)
            .filter(|record| record.source == InventorySource::Remote(binding))
            .map(|record| record.revision);
        if let Some(revision) = suspended_revision {
            slot.suspended_revision = Some(
                slot.suspended_revision
                    .map_or(revision, |current| current.max(revision)),
            );
            self.records.remove(&binding.remote_host_id);
            self.publish();
        }
        true
    }

    fn apply_remote_snapshot_bound(
        &mut self,
        binding: SessionBinding,
        message: &DeviceSnapshotV1,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        self.require_active(binding)?;
        validate_wire_snapshot(
            message,
            binding.remote_host_id,
            self.config.devices_per_host,
        )?;
        if self
            .remote_sessions
            .get(&binding.remote_host_id)
            .and_then(|slot| slot.suspended_revision)
            .is_some_and(|revision| message.revision <= revision)
        {
            return Err(DeviceInventoryError::StaleRevision);
        }
        let devices = message
            .devices
            .iter()
            .map(|device| device_from_wire(device, binding.remote_host_id))
            .collect::<Result<Vec<_>, _>>()?;
        let snapshot = self.apply_snapshot(
            InventorySource::Remote(binding),
            binding.remote_host_id,
            message.revision,
            devices,
        )?;
        if let Some(slot) = self.remote_sessions.get_mut(&binding.remote_host_id) {
            slot.suspended_revision = None;
        }
        Ok(snapshot)
    }

    fn apply_remote_add_bound(
        &mut self,
        binding: SessionBinding,
        message: &DeviceAddedV1,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        self.require_active(binding)?;
        message
            .validate()
            .map_err(|_| DeviceInventoryError::InvalidMessage)?;
        let device = device_from_wire(&message.device, binding.remote_host_id)?;
        self.apply_add(
            InventorySource::Remote(binding),
            binding.remote_host_id,
            message.revision,
            device,
        )
    }

    fn apply_remote_remove_bound(
        &mut self,
        binding: SessionBinding,
        message: &DeviceRemovedV1,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        self.require_active(binding)?;
        message
            .validate()
            .map_err(|_| DeviceInventoryError::InvalidMessage)?;
        if message.host_id.0 != binding.remote_host_id.into_bytes() {
            return Err(DeviceInventoryError::SessionMismatch);
        }
        if message.device_id.0 == [0; 16] {
            return Err(DeviceInventoryError::InvalidDevice);
        }
        self.apply_remove(
            InventorySource::Remote(binding),
            binding.remote_host_id,
            message.revision,
            DeviceId::from_bytes(message.device_id.0),
        )
    }

    fn apply_snapshot(
        &mut self,
        source: InventorySource,
        host_id: HostId,
        revision: u64,
        devices: Vec<InputDevice>,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        if revision == 0 {
            return Err(DeviceInventoryError::InvalidRevision);
        }
        if let Some(existing) = self.records.get(&host_id) {
            if existing.source != source {
                return Err(DeviceInventoryError::SessionMismatch);
            }
            if revision <= existing.revision {
                return Err(DeviceInventoryError::StaleRevision);
            }
        }
        let candidate = self.validate_candidate(host_id, devices)?;
        self.ensure_total_capacity(host_id, candidate.len())?;
        self.records.insert(
            host_id,
            HostRecord {
                source,
                revision,
                devices: candidate,
            },
        );
        Ok(self.publish())
    }

    fn apply_add(
        &mut self,
        source: InventorySource,
        host_id: HostId,
        revision: u64,
        device: InputDevice,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        let existing = self
            .records
            .get(&host_id)
            .ok_or(DeviceInventoryError::InventoryUnavailable)?;
        if existing.source != source {
            return Err(DeviceInventoryError::SessionMismatch);
        }
        validate_exact_next(existing.revision, revision)?;
        validate_domain_device(&device, host_id)?;
        if existing.devices.contains_key(&device.id) {
            return Err(DeviceInventoryError::DeviceAlreadyExists);
        }
        let mut candidate = existing.devices.clone();
        candidate.insert(device.id, device);
        if candidate.len() > self.config.devices_per_host {
            return Err(DeviceInventoryError::CapacityExceeded);
        }
        self.ensure_total_capacity(host_id, candidate.len())?;
        self.records.insert(
            host_id,
            HostRecord {
                source,
                revision,
                devices: candidate,
            },
        );
        Ok(self.publish())
    }

    fn apply_remove(
        &mut self,
        source: InventorySource,
        host_id: HostId,
        revision: u64,
        device_id: DeviceId,
    ) -> Result<Arc<DeviceInventorySnapshot>, DeviceInventoryError> {
        if device_id.into_bytes() == [0; 16] {
            return Err(DeviceInventoryError::InvalidDevice);
        }
        let existing = self
            .records
            .get(&host_id)
            .ok_or(DeviceInventoryError::InventoryUnavailable)?;
        if existing.source != source {
            return Err(DeviceInventoryError::SessionMismatch);
        }
        validate_exact_next(existing.revision, revision)?;
        let mut candidate = existing.devices.clone();
        if candidate.remove(&device_id).is_none() {
            return Err(DeviceInventoryError::DeviceNotFound);
        }
        self.records.insert(
            host_id,
            HostRecord {
                source,
                revision,
                devices: candidate,
            },
        );
        Ok(self.publish())
    }

    fn validate_candidate(
        &self,
        host_id: HostId,
        devices: Vec<InputDevice>,
    ) -> Result<BTreeMap<DeviceId, InputDevice>, DeviceInventoryError> {
        if devices.len() > self.config.devices_per_host {
            return Err(DeviceInventoryError::CapacityExceeded);
        }
        let mut candidate = BTreeMap::new();
        for device in devices {
            validate_domain_device(&device, host_id)?;
            if candidate.insert(device.id, device).is_some() {
                return Err(DeviceInventoryError::DuplicateDevice);
            }
        }
        Ok(candidate)
    }

    fn ensure_total_capacity(
        &self,
        replacing_host: HostId,
        replacement_count: usize,
    ) -> Result<(), DeviceInventoryError> {
        let elsewhere = self
            .records
            .iter()
            .filter(|(host, _)| **host != replacing_host)
            .try_fold(0_usize, |total, (_, record)| {
                total.checked_add(record.devices.len())
            })
            .ok_or(DeviceInventoryError::CapacityExceeded)?;
        if elsewhere
            .checked_add(replacement_count)
            .is_none_or(|total| total > self.config.total_devices)
        {
            return Err(DeviceInventoryError::CapacityExceeded);
        }
        Ok(())
    }

    fn publish(&self) -> Arc<DeviceInventorySnapshot> {
        let mut hosts = BTreeMap::new();
        let mut device_count = 0_usize;
        for (host_id, record) in &self.records {
            device_count += record.devices.len();
            hosts.insert(
                *host_id,
                HostDeviceInventorySnapshot {
                    host_id: *host_id,
                    revision: record.revision,
                    devices: record.devices.clone(),
                },
            );
        }
        let snapshot = Arc::new(DeviceInventorySnapshot {
            hosts,
            device_count,
        });
        self.published.store(Arc::clone(&snapshot));
        snapshot
    }
}

impl fmt::Debug for DeviceInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snapshot = self.published.load();
        formatter
            .debug_struct("DeviceInventory")
            .field("config", &self.config)
            .field("remote_session_host_count", &self.remote_sessions.len())
            .field("remote_shutdown", &self.remote_shutdown)
            .field("host_count", &snapshot.host_count())
            .field("device_count", &snapshot.device_count())
            .finish_non_exhaustive()
    }
}

fn validate_exact_next(current: u64, proposed: u64) -> Result<(), DeviceInventoryError> {
    if proposed == 0 {
        return Err(DeviceInventoryError::InvalidRevision);
    }
    let next = current
        .checked_add(1)
        .ok_or(DeviceInventoryError::RevisionExhausted)?;
    match proposed.cmp(&next) {
        Ordering::Less => Err(DeviceInventoryError::StaleRevision),
        Ordering::Greater => Err(DeviceInventoryError::RevisionGap),
        Ordering::Equal => Ok(()),
    }
}

fn validate_domain_device(
    device: &InputDevice,
    expected_host: HostId,
) -> Result<(), DeviceInventoryError> {
    if expected_host.into_bytes() == [0; 16]
        || device.id.into_bytes() == [0; 16]
        || device.host_id != expected_host
        || device.name.trim().is_empty()
        || device.name.len() > MAX_DEVICE_NAME_BYTES
        || device.name.chars().any(char::is_control)
    {
        return Err(DeviceInventoryError::InvalidDevice);
    }
    Ok(())
}

fn validate_wire_snapshot(
    message: &DeviceSnapshotV1,
    expected_host: HostId,
    maximum_devices: usize,
) -> Result<(), DeviceInventoryError> {
    message
        .validate()
        .map_err(|_| DeviceInventoryError::InvalidMessage)?;
    if expected_host.into_bytes() == [0; 16] || message.host_id.0 != expected_host.into_bytes() {
        return Err(DeviceInventoryError::SessionMismatch);
    }
    if message.devices.len() > maximum_devices || message.devices.len() > MAX_SNAPSHOT_ITEMS {
        return Err(DeviceInventoryError::CapacityExceeded);
    }
    let mut seen = BTreeSet::new();
    for wire in &message.devices {
        let device = device_from_wire(wire, expected_host)?;
        if !seen.insert(device.id) {
            return Err(DeviceInventoryError::DuplicateDevice);
        }
    }
    Ok(())
}

fn device_from_wire(
    wire: &WireInputDeviceV1,
    expected_host: HostId,
) -> Result<InputDevice, DeviceInventoryError> {
    if wire.host_id.0 != expected_host.into_bytes() {
        return Err(DeviceInventoryError::SessionMismatch);
    }
    let device = InputDevice {
        id: DeviceId::from_bytes(wire.id.0),
        host_id: HostId::from_bytes(wire.host_id.0),
        name: wire.name.clone(),
        vendor_id: wire.vendor_id,
        product_id: wire.product_id,
        kind: match wire.kind {
            WireDeviceKind::Keyboard => DeviceKind::Keyboard,
            WireDeviceKind::Mouse => DeviceKind::Mouse,
            WireDeviceKind::Trackpad => DeviceKind::Trackpad,
            WireDeviceKind::Other => DeviceKind::Other,
        },
        capabilities: DeviceCapabilities {
            pointer: wire.capabilities.pointer,
            keyboard: wire.capabilities.keyboard,
            vertical_scroll: wire.capabilities.vertical_scroll,
            horizontal_scroll: wire.capabilities.horizontal_scroll,
            extra_buttons: wire.capabilities.extra_buttons,
        },
    };
    validate_domain_device(&device, expected_host)?;
    Ok(device)
}

fn device_to_wire(device: &InputDevice) -> WireInputDeviceV1 {
    WireInputDeviceV1 {
        id: WireDeviceId(device.id.into_bytes()),
        host_id: WireHostId(device.host_id.into_bytes()),
        name: device.name.clone(),
        vendor_id: device.vendor_id,
        product_id: device.product_id,
        kind: match device.kind {
            DeviceKind::Keyboard => WireDeviceKind::Keyboard,
            DeviceKind::Mouse => WireDeviceKind::Mouse,
            DeviceKind::Trackpad => WireDeviceKind::Trackpad,
            _ => WireDeviceKind::Other,
        },
        capabilities: WireDeviceCapabilities {
            pointer: device.capabilities.pointer,
            keyboard: device.capabilities.keyboard,
            vertical_scroll: device.capabilities.vertical_scroll,
            horizontal_scroll: device.capabilities.horizontal_scroll,
            extra_buttons: device.capabilities.extra_buttons,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_network::ConnectionGenerationGate;
    use kvm_protocol::WirePeerId;

    fn host(value: u8) -> HostId {
        HostId::from_bytes([value; 16])
    }

    fn peer(value: u8) -> PeerId {
        PeerId::from_bytes([value; 16])
    }

    fn device(value: u8, owner: HostId) -> InputDevice {
        InputDevice {
            id: DeviceId::from_bytes([value; 16]),
            host_id: owner,
            name: format!("device-{value}"),
            vendor_id: Some(u16::from(value)),
            product_id: Some(u16::from(value) + 100),
            kind: DeviceKind::Keyboard,
            capabilities: DeviceCapabilities::KEYBOARD,
        }
    }

    fn wire_device(value: u8, owner: HostId) -> WireInputDeviceV1 {
        device_to_wire(&device(value, owner))
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
            remote_peer_id: peer(value.saturating_add(16)),
            credential_fingerprint: [value; 32],
        }
    }

    fn inventory(local: HostId) -> DeviceInventory {
        DeviceInventory::new(local, DeviceInventoryConfig::default()).unwrap()
    }

    #[test]
    fn configuration_and_local_host_are_positively_bounded() {
        assert_eq!(
            DeviceInventory::new(host(0), DeviceInventoryConfig::default()).err(),
            Some(DeviceInventoryError::InvalidHost)
        );
        for config in [
            DeviceInventoryConfig {
                remote_hosts: 0,
                ..DeviceInventoryConfig::default()
            },
            DeviceInventoryConfig {
                devices_per_host: MAX_DEVICE_INVENTORY_PER_HOST + 1,
                ..DeviceInventoryConfig::default()
            },
            DeviceInventoryConfig {
                total_devices: MAX_DEVICE_INVENTORY_TOTAL + 1,
                ..DeviceInventoryConfig::default()
            },
            DeviceInventoryConfig {
                devices_per_host: 2,
                total_devices: 1,
                ..DeviceInventoryConfig::default()
            },
        ] {
            assert_eq!(
                DeviceInventory::new(host(1), config).err(),
                Some(DeviceInventoryError::InvalidConfiguration)
            );
        }
    }

    #[test]
    fn local_full_snapshots_are_atomic_newer_and_deterministic() {
        let local = host(1);
        let mut inventory = inventory(local);
        let first = inventory
            .apply_local_snapshot(3, vec![device(9, local), device(7, local)])
            .unwrap();
        assert_eq!(first.host(local).unwrap().revision(), 3);
        assert_eq!(
            first
                .host(local)
                .unwrap()
                .iter()
                .map(|device| device.id)
                .collect::<Vec<_>>(),
            vec![DeviceId::from_bytes([7; 16]), DeviceId::from_bytes([9; 16])]
        );
        assert_eq!(
            inventory.apply_local_snapshot(3, Vec::new()),
            Err(DeviceInventoryError::StaleRevision)
        );
        let jumped = inventory.apply_local_snapshot(9, Vec::new()).unwrap();
        assert_eq!(jumped.host(local).unwrap().revision(), 9);
        assert!(jumped.host(local).unwrap().is_empty());
    }

    #[test]
    fn invalid_full_candidates_do_not_publish_partial_state() {
        let local = host(1);
        let mut inventory = inventory(local);
        let original = inventory
            .apply_local_snapshot(1, vec![device(1, local)])
            .unwrap();
        let mut nil = device(2, local);
        nil.id = DeviceId::from_bytes([0; 16]);
        let mut blank = device(2, local);
        blank.name = "   ".to_owned();
        let mut control = device(2, local);
        control.name = "secret\nname".to_owned();
        let mut long = device(2, local);
        long.name = "x".repeat(MAX_DEVICE_NAME_BYTES + 1);
        for (candidate, expected) in [
            (vec![nil], DeviceInventoryError::InvalidDevice),
            (vec![blank], DeviceInventoryError::InvalidDevice),
            (vec![control], DeviceInventoryError::InvalidDevice),
            (vec![long], DeviceInventoryError::InvalidDevice),
            (
                vec![device(2, host(2))],
                DeviceInventoryError::InvalidDevice,
            ),
            (
                vec![device(2, local), device(2, local)],
                DeviceInventoryError::DuplicateDevice,
            ),
        ] {
            assert_eq!(inventory.apply_local_snapshot(2, candidate), Err(expected));
            assert!(Arc::ptr_eq(&original, &inventory.snapshot()));
        }
        assert_eq!(
            inventory.apply_local_snapshot(0, Vec::new()),
            Err(DeviceInventoryError::InvalidRevision)
        );
    }

    #[test]
    fn local_add_and_remove_require_exact_next_and_correct_membership() {
        let local = host(1);
        let mut inventory = inventory(local);
        inventory
            .apply_local_snapshot(5, vec![device(1, local)])
            .unwrap();
        for (revision, expected) in [
            (5, DeviceInventoryError::StaleRevision),
            (7, DeviceInventoryError::RevisionGap),
        ] {
            assert_eq!(
                inventory.apply_local_add(revision, device(2, local)),
                Err(expected)
            );
        }
        inventory.apply_local_add(6, device(2, local)).unwrap();
        assert!(inventory.contains_local_device(DeviceId::from_bytes([2; 16])));
        assert_eq!(
            inventory.apply_local_add(7, device(2, local)),
            Err(DeviceInventoryError::DeviceAlreadyExists)
        );
        assert_eq!(
            inventory.apply_local_remove(7, DeviceId::from_bytes([3; 16])),
            Err(DeviceInventoryError::DeviceNotFound)
        );
        inventory
            .apply_local_remove(7, DeviceId::from_bytes([2; 16]))
            .unwrap();
        assert!(!inventory.contains_local_device(DeviceId::from_bytes([2; 16])));
    }

    #[test]
    fn add_capacity_and_revision_exhaustion_are_atomic() {
        let local = host(1);
        let config = DeviceInventoryConfig {
            remote_hosts: 1,
            devices_per_host: 1,
            total_devices: 1,
        };
        let mut bounded = DeviceInventory::new(local, config).unwrap();
        let before = bounded
            .apply_local_snapshot(1, vec![device(1, local)])
            .unwrap();
        assert_eq!(
            bounded.apply_local_add(2, device(2, local)),
            Err(DeviceInventoryError::CapacityExceeded)
        );
        assert!(Arc::ptr_eq(&before, &bounded.snapshot()));

        let mut exhausted = inventory(local);
        exhausted
            .apply_local_snapshot(u64::MAX, vec![device(1, local)])
            .unwrap();
        assert_eq!(
            exhausted.apply_local_remove(u64::MAX, DeviceId::from_bytes([1; 16])),
            Err(DeviceInventoryError::RevisionExhausted)
        );
    }

    #[test]
    fn local_wire_snapshot_is_sorted_and_round_trips_metadata() {
        let local = host(1);
        let mut inventory = inventory(local);
        assert_eq!(
            inventory.local_wire_snapshot(),
            Err(DeviceInventoryError::InventoryUnavailable)
        );
        inventory
            .apply_local_snapshot(4, vec![device(9, local), device(3, local)])
            .unwrap();
        let message = inventory.local_wire_snapshot().unwrap();
        assert_eq!(message.revision, 4);
        assert_eq!(
            message
                .devices
                .iter()
                .map(|device| device.id)
                .collect::<Vec<_>>(),
            vec![WireDeviceId([3; 16]), WireDeviceId([9; 16])]
        );
        assert_eq!(message.devices[0].vendor_id, Some(3));
        assert!(message.devices[0].capabilities.keyboard);
    }

    #[test]
    fn remote_full_and_deltas_require_exact_active_session() {
        let local = host(1);
        let remote = host(2);
        let current = binding(1, local, remote);
        let other = binding(2, local, remote);
        let mut inventory = inventory(local);
        let snapshot = DeviceSnapshotV1 {
            revision: 4,
            host_id: WireHostId(remote.into_bytes()),
            devices: vec![wire_device(1, remote)],
        };
        assert_eq!(
            inventory.apply_remote_snapshot_bound(current, &snapshot),
            Err(DeviceInventoryError::SessionMismatch)
        );
        inventory.activate_remote_binding(current).unwrap();
        inventory
            .apply_remote_snapshot_bound(current, &snapshot)
            .unwrap();
        assert_eq!(
            inventory
                .remote_device_bound(current, DeviceId::from_bytes([1; 16]))
                .unwrap()
                .host_id,
            remote
        );
        assert_eq!(
            inventory.remote_device_bound(other, DeviceId::from_bytes([1; 16])),
            Err(DeviceInventoryError::SessionMismatch)
        );
        assert_eq!(
            inventory.remote_device_bound(current, DeviceId::from_bytes([9; 16])),
            Err(DeviceInventoryError::DeviceNotFound)
        );
        assert_eq!(
            inventory.apply_remote_add_bound(
                other,
                &DeviceAddedV1 {
                    revision: 5,
                    device: wire_device(2, remote)
                },
            ),
            Err(DeviceInventoryError::SessionMismatch)
        );
        inventory
            .apply_remote_add_bound(
                current,
                &DeviceAddedV1 {
                    revision: 5,
                    device: wire_device(2, remote),
                },
            )
            .unwrap();
        inventory
            .apply_remote_remove_bound(
                current,
                &DeviceRemovedV1 {
                    revision: 6,
                    host_id: WireHostId(remote.into_bytes()),
                    device_id: WireDeviceId([1; 16]),
                },
            )
            .unwrap();
        assert!(inventory
            .snapshot()
            .owns_device(remote, DeviceId::from_bytes([2; 16])));
        assert!(!inventory
            .snapshot()
            .owns_device(remote, DeviceId::from_bytes([1; 16])));
    }

    #[test]
    fn remote_wire_ownership_nil_duplicate_and_revision_failures_are_atomic() {
        let local = host(1);
        let remote = host(2);
        let current = binding(1, local, remote);
        let mut inventory = inventory(local);
        inventory.activate_remote_binding(current).unwrap();
        let original = inventory
            .apply_remote_snapshot_bound(
                current,
                &DeviceSnapshotV1 {
                    revision: 1,
                    host_id: WireHostId(remote.into_bytes()),
                    devices: vec![wire_device(1, remote)],
                },
            )
            .unwrap();
        let mut nil = wire_device(2, remote);
        nil.id = WireDeviceId([0; 16]);
        for (message, expected) in [
            (
                DeviceSnapshotV1 {
                    revision: 2,
                    host_id: WireHostId(host(3).into_bytes()),
                    devices: vec![wire_device(2, host(3))],
                },
                DeviceInventoryError::SessionMismatch,
            ),
            (
                DeviceSnapshotV1 {
                    revision: 2,
                    host_id: WireHostId(remote.into_bytes()),
                    devices: vec![nil],
                },
                DeviceInventoryError::InvalidMessage,
            ),
            (
                DeviceSnapshotV1 {
                    revision: 2,
                    host_id: WireHostId(remote.into_bytes()),
                    devices: vec![wire_device(2, remote), wire_device(2, remote)],
                },
                DeviceInventoryError::InvalidMessage,
            ),
            (
                DeviceSnapshotV1 {
                    revision: 0,
                    host_id: WireHostId(remote.into_bytes()),
                    devices: Vec::new(),
                },
                DeviceInventoryError::InvalidMessage,
            ),
        ] {
            assert_eq!(
                inventory.apply_remote_snapshot_bound(current, &message),
                Err(expected)
            );
            assert!(Arc::ptr_eq(&original, &inventory.snapshot()));
        }
    }

    #[test]
    fn exact_invalidation_blocks_stale_repopulation_and_allows_newer_generation() {
        let local = host(1);
        let remote = host(2);
        let first = binding(1, local, remote);
        let second = binding(2, local, remote);
        assert!(second.generation > first.generation);
        let snapshot = DeviceSnapshotV1 {
            revision: 1,
            host_id: WireHostId(remote.into_bytes()),
            devices: vec![wire_device(1, remote)],
        };
        let mut inventory = inventory(local);
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
            Err(DeviceInventoryError::SessionMismatch)
        );
        assert_eq!(
            inventory.apply_remote_snapshot_bound(first, &snapshot),
            Err(DeviceInventoryError::SessionMismatch)
        );
        inventory.activate_remote_binding(second).unwrap();
        inventory
            .apply_remote_snapshot_bound(second, &snapshot)
            .unwrap();
        assert_eq!(
            inventory.apply_remote_snapshot_bound(first, &snapshot),
            Err(DeviceInventoryError::SessionMismatch)
        );
    }

    #[test]
    fn suspension_clears_only_exact_metadata_and_requires_a_newer_full_snapshot() {
        let local = host(1);
        let remote = host(2);
        let current = binding(1, local, remote);
        let stale = binding(2, local, remote);
        let mut inventory = inventory(local);
        let snapshot = DeviceSnapshotV1 {
            revision: 4,
            host_id: WireHostId(remote.into_bytes()),
            devices: vec![wire_device(1, remote)],
        };
        inventory.activate_remote_binding(current).unwrap();
        inventory
            .apply_remote_snapshot_bound(current, &snapshot)
            .unwrap();

        assert!(!inventory.suspend_remote_binding(stale));
        assert!(inventory.snapshot().host(remote).is_some());
        assert!(inventory.suspend_remote_binding(current));
        assert!(inventory.snapshot().host(remote).is_none());
        assert_eq!(
            inventory.remote_device_bound(current, DeviceId::from_bytes([1; 16])),
            Err(DeviceInventoryError::InventoryUnavailable)
        );
        assert!(inventory.suspend_remote_binding(current));
        assert_eq!(
            inventory.apply_remote_snapshot_bound(current, &snapshot),
            Err(DeviceInventoryError::StaleRevision)
        );
        let refreshed = DeviceSnapshotV1 {
            revision: 6,
            devices: vec![wire_device(2, remote)],
            ..snapshot
        };
        inventory
            .apply_remote_snapshot_bound(current, &refreshed)
            .unwrap();
        assert!(inventory
            .snapshot()
            .owns_device(remote, DeviceId::from_bytes([2; 16])));
    }

    #[test]
    fn remote_host_and_total_device_bounds_are_transactional() {
        let local = host(1);
        let config = DeviceInventoryConfig {
            remote_hosts: 1,
            devices_per_host: 2,
            total_devices: 2,
        };
        let mut inventory = DeviceInventory::new(local, config).unwrap();
        inventory
            .apply_local_snapshot(1, vec![device(1, local)])
            .unwrap();
        let first = binding(1, local, host(2));
        let second = binding(2, local, host(3));
        inventory.activate_remote_binding(first).unwrap();
        assert_eq!(
            inventory.activate_remote_binding(second),
            Err(DeviceInventoryError::CapacityExceeded)
        );
        inventory
            .apply_remote_snapshot_bound(
                first,
                &DeviceSnapshotV1 {
                    revision: 1,
                    host_id: WireHostId(host(2).into_bytes()),
                    devices: vec![wire_device(2, host(2))],
                },
            )
            .unwrap();
        let before = inventory.snapshot();
        assert_eq!(
            inventory.apply_remote_add_bound(
                first,
                &DeviceAddedV1 {
                    revision: 2,
                    device: wire_device(3, host(2))
                },
            ),
            Err(DeviceInventoryError::CapacityExceeded)
        );
        assert!(Arc::ptr_eq(&before, &inventory.snapshot()));
    }

    #[test]
    fn global_remote_invalidation_is_terminal_and_preserves_local_state() {
        let local = host(1);
        let remote = host(2);
        let first = binding(1, local, remote);
        let newer = binding(2, local, remote);
        let mut inventory = inventory(local);
        inventory
            .apply_local_snapshot(1, vec![device(1, local)])
            .unwrap();
        inventory.activate_remote_binding(first).unwrap();
        inventory
            .apply_remote_snapshot_bound(
                first,
                &DeviceSnapshotV1 {
                    revision: 1,
                    host_id: WireHostId(remote.into_bytes()),
                    devices: vec![wire_device(2, remote)],
                },
            )
            .unwrap();
        inventory.invalidate_all_remote();
        assert!(inventory.snapshot().host(local).is_some());
        assert!(inventory.snapshot().host(remote).is_none());
        assert_eq!(
            inventory.activate_remote_binding(newer),
            Err(DeviceInventoryError::SessionMismatch)
        );
    }

    #[test]
    fn clone_is_an_isolated_transactional_candidate() {
        let local = host(1);
        let mut inventory = inventory(local);
        let original = inventory
            .apply_local_snapshot(1, vec![device(1, local)])
            .unwrap();
        let mut candidate = inventory.clone();
        candidate.apply_local_add(2, device(2, local)).unwrap();
        assert!(Arc::ptr_eq(&original, &inventory.snapshot()));
        assert_eq!(inventory.snapshot().device_count(), 1);
        assert_eq!(candidate.snapshot().device_count(), 2);
    }

    #[test]
    fn debug_surfaces_are_count_only_and_marker_free() {
        const MARKER: &str = "SECRET-DEVICE-INVENTORY-MARKER";
        let local = host(1);
        let mut marked = device(1, local);
        marked.name = MARKER.to_owned();
        let mut inventory = inventory(local);
        inventory.apply_local_snapshot(1, vec![marked]).unwrap();
        let host_snapshot = inventory.snapshot().host(local).unwrap().clone();
        for rendered in [
            format!("{inventory:?}"),
            format!("{:?}", inventory.snapshot()),
            format!("{host_snapshot:?}"),
            format!("{:?}", DeviceInventoryError::InvalidDevice),
        ] {
            assert!(!rendered.contains(MARKER));
            assert!(!rendered.contains(&local.to_string()));
        }
    }
}
