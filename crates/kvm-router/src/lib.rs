//! Per-device routing decisions for platform-neutral input events.
//!
//! A route resolves to `Local` whenever it targets the daemon's local host.
//! This keeps platform suppression code from needing to compare host IDs.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use kvm_input::InputEvent;
use kvm_types::{DeviceId, HostId, WorkspaceState};
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use kvm_types::DeviceRoute;

/// Maximum number of explicit per-device policies retained at runtime.
pub const MAX_DEVICE_ROUTES: usize = 1_024;

/// Coarse validation failure for bounded runtime routing policy.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RoutingTableError {
    InvalidDevice,
    InvalidTarget,
    DuplicateDevice,
    CapacityExceeded,
}

impl fmt::Debug for RoutingTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::InvalidDevice => "InvalidDevice",
            Self::InvalidTarget => "InvalidTarget",
            Self::DuplicateDevice => "DuplicateDevice",
            Self::CapacityExceeded => "CapacityExceeded",
        };
        formatter
            .debug_struct("RoutingTableError")
            .field("kind", &kind)
            .finish()
    }
}

impl fmt::Display for RoutingTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("routing table policy is invalid")
    }
}

impl Error for RoutingTableError {}

/// The action a platform backend must take for a captured input event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destination {
    /// Let the physical event execute on this daemon's host.
    Local,
    /// Suppress the physical event locally and send it to this host.
    Remote(HostId),
}

/// Resolves captured input against a current workspace snapshot.
pub trait InputRouter {
    fn destination(&self, event: &InputEvent, state: &WorkspaceState) -> Destination;
}

/// Per-device route overrides.
///
/// Missing devices deliberately behave as `FollowActiveHost`. Newly attached
/// keyboards and pointing devices therefore join the shared workspace without
/// needing a configuration write on the latency-sensitive input path.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct RoutingTable {
    routes: HashMap<DeviceId, DeviceRoute>,
}

impl fmt::Debug for RoutingTable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutingTable")
            .field("route_count", &self.routes.len())
            .finish_non_exhaustive()
    }
}

impl Serialize for RoutingTable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RoutingTable", 1)?;
        state.serialize_field("routes", &self.routes)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RoutingTable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct("RoutingTable", &["routes"], RoutingTableVisitor)
    }
}

struct RoutingTableVisitor;

impl<'de> Visitor<'de> for RoutingTableVisitor {
    type Value = RoutingTable;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded routing table")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut routes = None;
        while let Some(field) = map.next_key::<RoutingTableField>()? {
            match field {
                RoutingTableField::Routes => {
                    if routes.is_some() {
                        return Err(de::Error::custom("routing table policy is invalid"));
                    }
                    routes = Some(map.next_value::<BoundedRoutes>()?.0);
                }
                RoutingTableField::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        let routes = routes.ok_or_else(|| de::Error::missing_field("routes"))?;
        Ok(RoutingTable { routes })
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum RoutingTableField {
    Routes,
    #[serde(other)]
    Other,
}

struct BoundedRoutes(HashMap<DeviceId, DeviceRoute>);

impl<'de> Deserialize<'de> for BoundedRoutes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(BoundedRoutesVisitor)
    }
}

struct BoundedRoutesVisitor;

impl<'de> Visitor<'de> for BoundedRoutesVisitor {
    type Value = BoundedRoutes;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded per-device routes")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut routes = HashMap::new();
        while let Some((device, route)) = map.next_entry::<DeviceId, DeviceRoute>()? {
            validate_entry(device, route)
                .map_err(|_| de::Error::custom("routing table policy is invalid"))?;
            if routes.contains_key(&device) || routes.len() >= MAX_DEVICE_ROUTES {
                return Err(de::Error::custom("routing table policy is invalid"));
            }
            routes.insert(device, route);
        }
        Ok(BoundedRoutes(routes))
    }
}

impl RoutingTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a bounded table from validated configured overrides.
    ///
    /// # Errors
    ///
    /// Rejects nil device/host identifiers, duplicate devices, and inputs
    /// exceeding [`MAX_DEVICE_ROUTES`] without returning partial state.
    pub fn try_from_routes(
        routes: impl IntoIterator<Item = (DeviceId, DeviceRoute)>,
    ) -> Result<Self, RoutingTableError> {
        let mut table = Self::new();
        for (device, route) in routes {
            validate_entry(device, route)?;
            if table.routes.contains_key(&device) {
                return Err(RoutingTableError::DuplicateDevice);
            }
            if table.routes.len() >= MAX_DEVICE_ROUTES {
                return Err(RoutingTableError::CapacityExceeded);
            }
            table.routes.insert(device, route);
        }
        Ok(table)
    }

    /// Adds or replaces one route transactionally.
    ///
    /// Replacement remains available at capacity because it does not grow
    /// retained state.
    ///
    /// # Errors
    ///
    /// Rejects nil device/host identifiers and new entries above the bound.
    pub fn set_route(
        &mut self,
        device: DeviceId,
        route: DeviceRoute,
    ) -> Result<Option<DeviceRoute>, RoutingTableError> {
        validate_entry(device, route)?;
        if !self.routes.contains_key(&device) && self.routes.len() >= MAX_DEVICE_ROUTES {
            return Err(RoutingTableError::CapacityExceeded);
        }
        Ok(self.routes.insert(device, route))
    }

    /// Removes an explicit route. The device returns to `FollowActiveHost`.
    pub fn remove_route(&mut self, device: DeviceId) -> Option<DeviceRoute> {
        self.routes.remove(&device)
    }

    /// Returns the effective route, including the default for unknown devices.
    #[must_use]
    pub fn route_for(&self, device: DeviceId) -> DeviceRoute {
        self.routes
            .get(&device)
            .copied()
            .unwrap_or(DeviceRoute::FollowActiveHost)
    }

    /// Returns only an explicitly configured route.
    #[must_use]
    pub fn configured_route(&self, device: DeviceId) -> Option<DeviceRoute> {
        self.routes.get(&device).copied()
    }

    pub fn routes(&self) -> impl ExactSizeIterator<Item = (&DeviceId, &DeviceRoute)> {
        self.routes.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn clear(&mut self) {
        self.routes.clear();
    }

    /// Resolves a policy without requiring an `InputEvent`.
    #[must_use]
    pub fn destination_for_device(&self, device: DeviceId, state: &WorkspaceState) -> Destination {
        // F-14: fail-closed on a malformed caller-supplied workspace snapshot.
        // A nil active or local host must never yield `Remote(nil)` — route
        // `Local` so a phantom endpoint is never addressed. The authority layer
        // above gates unknown endpoints; this is the router's own nil guard.
        if state.active_host.into_bytes() == [0; 16] || state.local_host.into_bytes() == [0; 16] {
            return Destination::Local;
        }
        let target = match self.route_for(device) {
            DeviceRoute::Local => return Destination::Local,
            DeviceRoute::FollowActiveHost => state.active_host,
            DeviceRoute::Host(host) => host,
        };

        if target == state.local_host {
            Destination::Local
        } else {
            Destination::Remote(target)
        }
    }
}

fn validate_entry(device: DeviceId, route: DeviceRoute) -> Result<(), RoutingTableError> {
    if device.into_bytes() == [0; 16] {
        return Err(RoutingTableError::InvalidDevice);
    }
    if matches!(route, DeviceRoute::Host(host) if host.into_bytes() == [0; 16]) {
        return Err(RoutingTableError::InvalidTarget);
    }
    Ok(())
}

impl InputRouter for RoutingTable {
    fn destination(&self, event: &InputEvent, state: &WorkspaceState) -> Destination {
        self.destination_for_device(event.source_device, state)
    }
}

#[cfg(test)]
mod tests {
    use kvm_input::{InputEvent, InputPayload};
    use kvm_types::{DeviceId, DisplayId, HostId, LogicalPointer, WorkspaceState};

    use super::*;

    const LOCAL: HostId = HostId::from_bytes([1; 16]);
    const REMOTE: HostId = HostId::from_bytes([2; 16]);
    const THIRD: HostId = HostId::from_bytes([3; 16]);
    const DEVICE: DeviceId = DeviceId::from_bytes([4; 16]);
    const DISPLAY: DisplayId = DisplayId::from_bytes([5; 16]);

    fn state(active_host: HostId) -> WorkspaceState {
        WorkspaceState::new(LOCAL, active_host, LogicalPointer::new(DISPLAY, 10.0, 20.0))
    }

    fn event(device: DeviceId) -> InputEvent {
        InputEvent::new(
            7,
            10_000,
            LOCAL,
            device,
            InputPayload::PointerMove { dx: 1.0, dy: -2.0 },
        )
    }

    #[test]
    fn unknown_device_follows_the_active_remote_host() {
        let routes = RoutingTable::new();

        assert_eq!(
            routes.destination(&event(DEVICE), &state(REMOTE)),
            Destination::Remote(REMOTE)
        );
        assert_eq!(routes.route_for(DEVICE), DeviceRoute::FollowActiveHost);
        assert_eq!(routes.configured_route(DEVICE), None);
    }

    #[test]
    fn follow_active_host_resolves_local_without_a_network_hop() {
        let routes = RoutingTable::new();

        assert_eq!(
            routes.destination(&event(DEVICE), &state(LOCAL)),
            Destination::Local
        );
    }

    #[test]
    fn local_override_ignores_active_host() {
        let mut routes = RoutingTable::new();
        routes.set_route(DEVICE, DeviceRoute::Local).unwrap();

        assert_eq!(
            routes.destination(&event(DEVICE), &state(REMOTE)),
            Destination::Local
        );
    }

    #[test]
    fn explicit_host_is_local_or_remote_relative_to_this_daemon() {
        let mut routes = RoutingTable::new();
        routes.set_route(DEVICE, DeviceRoute::Host(LOCAL)).unwrap();
        assert_eq!(
            routes.destination(&event(DEVICE), &state(REMOTE)),
            Destination::Local
        );

        routes.set_route(DEVICE, DeviceRoute::Host(THIRD)).unwrap();
        assert_eq!(
            routes.destination(&event(DEVICE), &state(LOCAL)),
            Destination::Remote(THIRD)
        );
    }

    #[test]
    fn routes_are_isolated_per_physical_device() {
        let local_device = DeviceId::from_bytes([6; 16]);
        let remote_device = DeviceId::from_bytes([7; 16]);
        let mut routes = RoutingTable::new();
        routes.set_route(local_device, DeviceRoute::Local).unwrap();
        routes
            .set_route(remote_device, DeviceRoute::Host(REMOTE))
            .unwrap();

        assert_eq!(
            routes.destination(&event(local_device), &state(REMOTE)),
            Destination::Local
        );
        assert_eq!(
            routes.destination(&event(remote_device), &state(LOCAL)),
            Destination::Remote(REMOTE)
        );
    }

    #[test]
    fn removing_override_restores_follow_active_default() {
        let mut routes = RoutingTable::try_from_routes([(DEVICE, DeviceRoute::Local)]).unwrap();

        assert_eq!(routes.remove_route(DEVICE), Some(DeviceRoute::Local));
        assert!(routes.is_empty());
        assert_eq!(
            routes.destination(&event(DEVICE), &state(REMOTE)),
            Destination::Remote(REMOTE)
        );
    }

    #[test]
    fn nil_workspace_host_fails_closed_to_local() {
        // F-14: a caller-supplied workspace snapshot with a nil active or local
        // host must never route Remote(nil); the router fails closed to Local.
        let routes = RoutingTable::new(); // DEVICE defaults to FollowActiveHost
        let nil = HostId::from_bytes([0; 16]);
        assert_eq!(
            routes.destination_for_device(DEVICE, &state(nil)),
            Destination::Local
        );
        let nil_local = WorkspaceState::new(nil, REMOTE, LogicalPointer::new(DISPLAY, 10.0, 20.0));
        assert_eq!(
            routes.destination_for_device(DEVICE, &nil_local),
            Destination::Local
        );
    }

    fn indexed_device(index: usize) -> DeviceId {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_be_bytes());
        DeviceId::from_bytes(bytes)
    }

    #[test]
    fn construction_rejects_invalid_duplicate_and_oversized_inputs() {
        for entry in [
            (DeviceId::from_bytes([0; 16]), DeviceRoute::Local),
            (DEVICE, DeviceRoute::Host(HostId::from_bytes([0; 16]))),
        ] {
            assert!(RoutingTable::try_from_routes([entry]).is_err());
        }
        assert_eq!(
            RoutingTable::try_from_routes([
                (DEVICE, DeviceRoute::Local),
                (DEVICE, DeviceRoute::FollowActiveHost),
            ])
            .unwrap_err(),
            RoutingTableError::DuplicateDevice
        );

        let maximum = (0..MAX_DEVICE_ROUTES).map(|index| {
            (
                indexed_device(index),
                if index % 2 == 0 {
                    DeviceRoute::Local
                } else {
                    DeviceRoute::FollowActiveHost
                },
            )
        });
        let table = RoutingTable::try_from_routes(maximum).unwrap();
        assert_eq!(table.len(), MAX_DEVICE_ROUTES);

        let oversized =
            (0..=MAX_DEVICE_ROUTES).map(|index| (indexed_device(index), DeviceRoute::Local));
        assert_eq!(
            RoutingTable::try_from_routes(oversized).unwrap_err(),
            RoutingTableError::CapacityExceeded
        );
    }

    #[test]
    fn mutation_at_capacity_is_transactional_but_replacement_succeeds() {
        let mut table = RoutingTable::try_from_routes(
            (0..MAX_DEVICE_ROUTES).map(|index| (indexed_device(index), DeviceRoute::Local)),
        )
        .unwrap();
        let before = table.clone();
        assert_eq!(
            table.set_route(indexed_device(MAX_DEVICE_ROUTES), DeviceRoute::Local),
            Err(RoutingTableError::CapacityExceeded)
        );
        assert_eq!(table, before);

        assert_eq!(
            table
                .set_route(indexed_device(0), DeviceRoute::FollowActiveHost)
                .unwrap(),
            Some(DeviceRoute::Local)
        );
        assert_eq!(table.len(), MAX_DEVICE_ROUTES);
    }

    #[test]
    fn routing_diagnostics_are_count_only_and_redacted() {
        let device = DeviceId::from_bytes([0x41; 16]);
        let host = HostId::from_bytes([0x42; 16]);
        let table = RoutingTable::try_from_routes([(device, DeviceRoute::Host(host))]).unwrap();
        let rendered = format!(
            "{table:?} {:?} {}",
            RoutingTableError::InvalidTarget,
            RoutingTableError::InvalidTarget
        );

        assert!(rendered.contains("route_count: 1"));
        assert!(!rendered.contains(&device.to_string()));
        assert!(!rendered.contains(&host.to_string()));
    }

    #[test]
    fn serde_round_trip_preserves_bounds_and_rejects_duplicate_map_keys() {
        let table = RoutingTable::try_from_routes([
            (DEVICE, DeviceRoute::Host(REMOTE)),
            (indexed_device(1), DeviceRoute::Local),
        ])
        .unwrap();
        let encoded = serde_json::to_string(&table).unwrap();
        assert_eq!(
            serde_json::from_str::<RoutingTable>(&encoded).unwrap(),
            table
        );

        let duplicate =
            format!(r#"{{"routes":{{"{DEVICE}":"local","{DEVICE}":"follow_active_host"}}}}"#);
        let error = serde_json::from_str::<RoutingTable>(&duplicate).unwrap_err();
        assert!(!error.to_string().contains(&DEVICE.to_string()));

        let mut value = serde_json::to_value(
            RoutingTable::try_from_routes(
                (0..MAX_DEVICE_ROUTES).map(|index| (indexed_device(index), DeviceRoute::Local)),
            )
            .unwrap(),
        )
        .unwrap();
        value["routes"].as_object_mut().unwrap().insert(
            indexed_device(MAX_DEVICE_ROUTES).to_string(),
            serde_json::json!("local"),
        );
        assert!(serde_json::from_value::<RoutingTable>(value).is_err());
    }
}
