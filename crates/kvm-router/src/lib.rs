//! Per-device routing decisions for platform-neutral input events.
//!
//! A route resolves to `Local` whenever it targets the daemon's local host.
//! This keeps platform suppression code from needing to compare host IDs.

use std::collections::HashMap;

use kvm_input::InputEvent;
use kvm_types::{DeviceId, HostId, WorkspaceState};
use serde::{Deserialize, Serialize};

pub use kvm_types::DeviceRoute;

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
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoutingTable {
    routes: HashMap<DeviceId, DeviceRoute>,
}

impl RoutingTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a table from configured overrides. Later duplicate IDs win.
    #[must_use]
    pub fn from_routes(routes: impl IntoIterator<Item = (DeviceId, DeviceRoute)>) -> Self {
        Self {
            routes: routes.into_iter().collect(),
        }
    }

    /// Adds or replaces a configured route, returning the previous value.
    pub fn set_route(&mut self, device: DeviceId, route: DeviceRoute) -> Option<DeviceRoute> {
        self.routes.insert(device, route)
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
        routes.set_route(DEVICE, DeviceRoute::Local);

        assert_eq!(
            routes.destination(&event(DEVICE), &state(REMOTE)),
            Destination::Local
        );
    }

    #[test]
    fn explicit_host_is_local_or_remote_relative_to_this_daemon() {
        let mut routes = RoutingTable::new();
        routes.set_route(DEVICE, DeviceRoute::Host(LOCAL));
        assert_eq!(
            routes.destination(&event(DEVICE), &state(REMOTE)),
            Destination::Local
        );

        routes.set_route(DEVICE, DeviceRoute::Host(THIRD));
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
        routes.set_route(local_device, DeviceRoute::Local);
        routes.set_route(remote_device, DeviceRoute::Host(REMOTE));

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
        let mut routes = RoutingTable::from_routes([(DEVICE, DeviceRoute::Local)]);

        assert_eq!(routes.remove_route(DEVICE), Some(DeviceRoute::Local));
        assert!(routes.is_empty());
        assert_eq!(
            routes.destination(&event(DEVICE), &state(REMOTE)),
            Destination::Remote(REMOTE)
        );
    }
}
