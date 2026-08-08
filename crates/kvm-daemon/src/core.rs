use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use kvm_config::{Config, ConfigError, ShortcutKey};
use kvm_input::{InputEvent, InputPayload, KeyCode, KeyState, PressedState};
use kvm_router::{Destination, InputRouter, RoutingTable};
use kvm_types::{DeviceId, HostId, WorkspaceState};
use thiserror::Error;
use tracing::{info, warn};

use crate::platform::{CaptureDisposition, CapturedInput, EventClassification};

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
#[derive(Clone, Debug)]
pub struct RoutingSnapshot {
    pub workspace: WorkspaceState,
    pub routing: RoutingTable,
    pub peers: BTreeMap<HostId, PeerState>,
    pub enabled: bool,
}

impl RoutingSnapshot {
    /// Makes a conservative, allocation-free suppression decision.
    ///
    /// Unknown or KVM-injected events always remain local. A remote event is
    /// suppressible only while the selected, configured peer is connected.
    #[must_use]
    pub fn capture_disposition(&self, captured: &CapturedInput) -> CaptureDisposition {
        if captured.classification != EventClassification::Physical
            || captured.event.source_host != self.workspace.local_host
            || !captured.event.payload.is_finite()
            || !self.enabled
        {
            return CaptureDisposition::AllowLocal;
        }

        match self.routing.destination(&captured.event, &self.workspace) {
            Destination::Remote(host)
                if self
                    .peers
                    .get(&host)
                    .is_some_and(|state| state.accepts_input()) =>
            {
                CaptureDisposition::SuppressLocal
            }
            Destination::Local | Destination::Remote(_) => CaptureDisposition::AllowLocal,
        }
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
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RemoteRelease {
    pub target: HostId,
    pub source_device: DeviceId,
    pub payload: InputPayload,
}

/// Side effects for the transport layer. The daemon core performs no network
/// or native API calls itself.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CoreAction {
    Forward { target: HostId, event: InputEvent },
    Release(RemoteRelease),
}

/// Complete result of handling one captured input event.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessResult {
    pub disposition: CaptureDisposition,
    pub actions: Vec<CoreAction>,
    pub failsafe_activated: bool,
}

impl ProcessResult {
    fn local() -> Self {
        Self {
            disposition: CaptureDisposition::AllowLocal,
            actions: Vec::new(),
            failsafe_activated: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("invalid daemon configuration: {0}")]
    Config(#[from] ConfigError),
    #[error("workspace local host changed from {expected} to {actual}")]
    LocalHostChanged { expected: HostId, actual: HostId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleState {
    Running { routing_requested: bool },
    ShuttingDown,
}

/// Authoritative mutable daemon state. Every mutating operation republishes a
/// single immutable view for platform callbacks.
#[derive(Debug)]
pub struct DaemonCore {
    config: Config,
    workspace: WorkspaceState,
    routing: RoutingTable,
    peers: BTreeMap<HostId, PeerState>,
    lifecycle: LifecycleState,
    suspended_until_ns: u64,
    failsafe_latched: bool,
    drain_failsafe_keys: bool,
    physical_keys: HashSet<KeyCode>,
    remote_pressed: BTreeMap<(HostId, DeviceId), PressedState>,
    snapshots: Arc<ArcSwap<RoutingSnapshot>>,
}

impl DaemonCore {
    /// Creates a running core after validating all durable configuration.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Config`] when configuration validation fails.
    pub fn new(config: Config, workspace: WorkspaceState) -> Result<Self, DaemonError> {
        config.validate()?;
        let routing = routing_from_config(&config);
        let peers: BTreeMap<HostId, PeerState> = config
            .paired_hosts
            .iter()
            .map(|peer| (peer.host_id, PeerState::Disconnected))
            .collect();
        let initial = RoutingSnapshot {
            workspace,
            routing: routing.clone(),
            peers: peers.clone(),
            enabled: true,
        };

        Ok(Self {
            config,
            workspace,
            routing,
            peers,
            lifecycle: LifecycleState::Running {
                routing_requested: true,
            },
            suspended_until_ns: 0,
            failsafe_latched: false,
            drain_failsafe_keys: false,
            physical_keys: HashSet::new(),
            remote_pressed: BTreeMap::new(),
            snapshots: Arc::new(ArcSwap::from_pointee(initial)),
        })
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
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
    pub fn routing_handle(&self) -> RoutingSnapshotHandle {
        RoutingSnapshotHandle {
            current: Arc::clone(&self.snapshots),
        }
    }

    /// Processes trusted physical input and emits transport actions.
    /// `now_ns` must use the same monotonic clock on every call.
    #[must_use]
    pub fn process_captured(&mut self, captured: CapturedInput, now_ns: u64) -> ProcessResult {
        if captured.classification != EventClassification::Physical
            || captured.event.source_host != self.workspace.local_host
            || !captured.event.payload.is_finite()
        {
            return ProcessResult::local();
        }

        self.update_physical_keys(captured.event.payload);

        if self.failsafe_matches() && !self.failsafe_latched {
            self.failsafe_latched = true;
            self.drain_failsafe_keys = true;
            let actions = self.activate_failsafe(now_ns);
            return ProcessResult {
                disposition: CaptureDisposition::AllowLocal,
                actions,
                failsafe_activated: true,
            };
        }

        if self.failsafe_latched && !self.failsafe_matches() {
            self.failsafe_latched = false;
        }
        if self.drain_failsafe_keys {
            if !self.any_failsafe_key_pressed() {
                self.drain_failsafe_keys = false;
            }
            return ProcessResult::local();
        }

        let snapshot = self.snapshots.load();
        if snapshot.capture_disposition(&captured) == CaptureDisposition::AllowLocal {
            return ProcessResult::local();
        }

        let Destination::Remote(target) =
            self.routing.destination(&captured.event, &self.workspace)
        else {
            return ProcessResult::local();
        };
        self.remote_pressed
            .entry((target, captured.event.source_device))
            .or_default()
            .apply(&captured.event.payload);

        ProcessResult {
            disposition: CaptureDisposition::SuppressLocal,
            actions: vec![CoreAction::Forward {
                target,
                event: captured.event,
            }],
            failsafe_activated: false,
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

    /// Replaces durable settings and releases all remote held state before a
    /// route policy can change.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Config`] for invalid settings.
    pub fn update_config(
        &mut self,
        config: Config,
        now_ns: u64,
    ) -> Result<Vec<CoreAction>, DaemonError> {
        config.validate()?;
        let actions = self.release_all_remote();
        self.routing = routing_from_config(&config);
        self.peers
            .retain(|host, _| config.paired_hosts.iter().any(|peer| peer.host_id == *host));
        for peer in &config.paired_hosts {
            self.peers
                .entry(peer.host_id)
                .or_insert(PeerState::Disconnected);
        }
        self.config = config;
        self.publish(now_ns);
        info!(
            release_count = actions.len(),
            "input routing configuration changed"
        );
        Ok(actions)
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
    ) -> Result<Vec<CoreAction>, DaemonError> {
        if workspace.local_host != self.workspace.local_host {
            return Err(DaemonError::LocalHostChanged {
                expected: self.workspace.local_host,
                actual: workspace.local_host,
            });
        }
        let actions = if workspace.active_host == self.workspace.active_host {
            Vec::new()
        } else {
            self.release_all_remote()
        };
        let previous = self.workspace.active_host;
        self.workspace = workspace;
        self.publish(now_ns);
        if previous != workspace.active_host {
            info!(previous = %previous, active = %workspace.active_host, "active host changed");
        }
        Ok(actions)
    }

    /// Changes peer health. Any non-connected transition releases held input;
    /// losing the active peer immediately restores the local host.
    #[must_use]
    pub fn set_peer_state(
        &mut self,
        host: HostId,
        state: PeerState,
        now_ns: u64,
    ) -> Vec<CoreAction> {
        if !self.peers.contains_key(&host) {
            warn!(peer = %host, ?state, "ignored state for unconfigured peer");
            return Vec::new();
        }
        self.peers.insert(host, state);
        let actions = if state.accepts_input() {
            Vec::new()
        } else {
            self.release_remote_for_host(host)
        };
        if !state.accepts_input() && self.workspace.active_host == host {
            self.workspace.active_host = self.workspace.local_host;
        }
        self.publish(now_ns);
        info!(peer = %host, ?state, release_count = actions.len(), "peer state changed");
        actions
    }

    /// Handles a failed transport delivery as a peer failure.
    #[must_use]
    pub fn remote_delivery_failed(&mut self, host: HostId, now_ns: u64) -> Vec<CoreAction> {
        warn!(peer = %host, "remote input delivery failed; restoring local control");
        self.set_peer_state(host, PeerState::Disconnected, now_ns)
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
    #[must_use]
    pub fn disable(&mut self, now_ns: u64) -> Vec<CoreAction> {
        if let LifecycleState::Running { routing_requested } = &mut self.lifecycle {
            *routing_requested = false;
        }
        let actions = self.release_all_remote();
        self.workspace.active_host = self.workspace.local_host;
        self.publish(now_ns);
        info!(release_count = actions.len(), "KVM routing disabled");
        actions
    }

    /// Activates the permanent local emergency path without requiring a
    /// captured shortcut event.
    #[must_use]
    pub fn trigger_emergency(&mut self, now_ns: u64) -> Vec<CoreAction> {
        self.drain_failsafe_keys = true;
        self.activate_failsafe(now_ns)
    }

    /// Permanently stops this core and returns final cleanup actions.
    #[must_use]
    pub fn shutdown(&mut self, now_ns: u64) -> Vec<CoreAction> {
        self.lifecycle = LifecycleState::ShuttingDown;
        let actions = self.release_all_remote();
        self.workspace.active_host = self.workspace.local_host;
        self.publish(now_ns);
        info!(release_count = actions.len(), "daemon core shut down");
        actions
    }

    fn activate_failsafe(&mut self, now_ns: u64) -> Vec<CoreAction> {
        self.suspended_until_ns = now_ns.saturating_add(
            u64::from(self.config.failsafe.routing_suspend_seconds) * 1_000_000_000,
        );
        let actions = self.release_all_remote();
        self.workspace.active_host = self.workspace.local_host;
        self.publish(now_ns);
        warn!(
            suspended_until_ns = self.suspended_until_ns,
            release_count = actions.len(),
            "emergency failsafe triggered"
        );
        actions
    }

    fn update_physical_keys(&mut self, payload: InputPayload) {
        if let InputPayload::Key { code, state } = payload {
            match state {
                KeyState::Pressed => {
                    self.physical_keys.insert(code);
                }
                KeyState::Released => {
                    self.physical_keys.remove(&code);
                }
            }
        }
    }

    fn failsafe_matches(&self) -> bool {
        self.config
            .failsafe
            .shortcut
            .iter()
            .all(|key| shortcut_key_pressed(*key, &self.physical_keys))
    }

    fn any_failsafe_key_pressed(&self) -> bool {
        self.config
            .failsafe
            .shortcut
            .iter()
            .any(|key| shortcut_key_pressed(*key, &self.physical_keys))
    }

    fn release_all_remote(&mut self) -> Vec<CoreAction> {
        let held = std::mem::take(&mut self.remote_pressed);
        held.into_iter()
            .flat_map(|((target, source_device), mut state)| {
                state
                    .take_release_payloads()
                    .into_iter()
                    .map(move |payload| {
                        CoreAction::Release(RemoteRelease {
                            target,
                            source_device,
                            payload,
                        })
                    })
            })
            .collect()
    }

    fn release_remote_for_host(&mut self, target: HostId) -> Vec<CoreAction> {
        let matching: Vec<_> = self
            .remote_pressed
            .keys()
            .copied()
            .filter(|(host, _)| *host == target)
            .collect();
        let mut actions = Vec::new();
        for (host, device) in matching {
            if let Some(mut state) = self.remote_pressed.remove(&(host, device)) {
                actions.extend(state.take_release_payloads().into_iter().map(|payload| {
                    CoreAction::Release(RemoteRelease {
                        target: host,
                        source_device: device,
                        payload,
                    })
                }));
            }
        }
        actions
    }

    fn publish(&self, now_ns: u64) {
        self.snapshots.store(Arc::new(RoutingSnapshot {
            workspace: self.workspace,
            routing: self.routing.clone(),
            peers: self.peers.clone(),
            enabled: self.routing_should_be_active(now_ns),
        }));
    }

    fn routing_should_be_active(&self, now_ns: u64) -> bool {
        self.is_enabled() && now_ns >= self.suspended_until_ns && !self.drain_failsafe_keys
    }
}

fn routing_from_config(config: &Config) -> RoutingTable {
    RoutingTable::from_routes(
        config
            .device_routes
            .iter()
            .map(|route| (route.device_id, route.route.into())),
    )
}

fn shortcut_key_pressed(key: ShortcutKey, pressed: &HashSet<KeyCode>) -> bool {
    match key {
        ShortcutKey::Control => {
            pressed.contains(&KeyCode::ControlLeft) || pressed.contains(&KeyCode::ControlRight)
        }
        ShortcutKey::Alt => {
            pressed.contains(&KeyCode::AltLeft) || pressed.contains(&KeyCode::AltRight)
        }
        ShortcutKey::Shift => {
            pressed.contains(&KeyCode::ShiftLeft) || pressed.contains(&KeyCode::ShiftRight)
        }
        ShortcutKey::Meta => {
            pressed.contains(&KeyCode::MetaLeft) || pressed.contains(&KeyCode::MetaRight)
        }
        ShortcutKey::Backspace => pressed.contains(&KeyCode::Backspace),
        ShortcutKey::Escape => pressed.contains(&KeyCode::Escape),
        ShortcutKey::Physical { usage_page, usage } => pressed.contains(&KeyCode::Unidentified {
            usage_page,
            usage_id: usage,
        }),
    }
}

#[cfg(test)]
mod tests {
    use kvm_config::{DeviceRouteConfig, PairedHostConfig};
    use kvm_input::{ButtonState, PointerButton};
    use kvm_types::{DisplayId, LogicalPointer, PeerId, Platform};

    use super::*;

    const LOCAL: HostId = HostId::from_bytes([1; 16]);
    const REMOTE: HostId = HostId::from_bytes([2; 16]);
    const DISPLAY: DisplayId = DisplayId::from_bytes([3; 16]);
    const DEVICE: DeviceId = DeviceId::from_bytes([4; 16]);

    fn config() -> Config {
        let mut config = Config::default();
        config.paired_hosts.push(PairedHostConfig {
            host_id: REMOTE,
            peer_id: PeerId::from_bytes([5; 16]),
            name: "remote".into(),
            platform: Platform::MacOS,
            identity_fingerprint: "sha256:test".into(),
            last_address: None,
        });
        config.device_routes.push(DeviceRouteConfig {
            device_id: DEVICE,
            route: kvm_config::ConfiguredDeviceRoute::Host { host_id: REMOTE },
        });
        config
    }

    fn core() -> DaemonCore {
        let workspace =
            WorkspaceState::new(LOCAL, REMOTE, LogicalPointer::new(DISPLAY, 10.0, 20.0));
        let mut core = DaemonCore::new(config(), workspace).unwrap();
        assert!(core
            .set_peer_state(REMOTE, PeerState::Connected, 0)
            .is_empty());
        core
    }

    fn event(sequence: u64, payload: InputPayload) -> InputEvent {
        InputEvent::new(sequence, sequence * 10, LOCAL, DEVICE, payload)
    }

    fn captured(sequence: u64, payload: InputPayload) -> CapturedInput {
        CapturedInput::new(event(sequence, payload), EventClassification::Physical)
    }

    #[test]
    fn unknown_and_injected_events_never_route_remotely() {
        let mut core = core();
        for classification in [
            EventClassification::Unknown,
            EventClassification::InjectedByKvm,
        ] {
            let result = core.process_captured(
                CapturedInput::new(
                    event(1, InputPayload::PointerMove { dx: 1.0, dy: 2.0 }),
                    classification,
                ),
                1,
            );
            assert_eq!(result.disposition, CaptureDisposition::AllowLocal);
            assert!(result.actions.is_empty());
        }
    }

    #[test]
    fn peer_failure_immediately_returns_control_to_local_host() {
        let mut core = core();
        let first = core.process_captured(
            captured(1, InputPayload::PointerMove { dx: 1.0, dy: 2.0 }),
            1,
        );
        assert_eq!(first.disposition, CaptureDisposition::SuppressLocal);

        let _ = core.remote_delivery_failed(REMOTE, 2);
        let after_failure = core.process_captured(
            captured(2, InputPayload::PointerMove { dx: 3.0, dy: 4.0 }),
            3,
        );

        assert_eq!(core.workspace().active_host, LOCAL);
        assert_eq!(after_failure.disposition, CaptureDisposition::AllowLocal);
        assert!(after_failure.actions.is_empty());
        assert_eq!(
            core.routing_handle()
                .load()
                .capture_disposition(&captured(3, InputPayload::PointerMove { dx: 1.0, dy: 1.0 })),
            CaptureDisposition::AllowLocal
        );
    }

    #[test]
    fn completed_failsafe_is_never_forwarded_and_clears_prior_holds() {
        let mut core = core();
        for (sequence, key) in [
            (1, KeyCode::ControlLeft),
            (2, KeyCode::AltLeft),
            (3, KeyCode::ShiftLeft),
        ] {
            let result = core.process_captured(
                captured(
                    sequence,
                    InputPayload::Key {
                        code: key,
                        state: KeyState::Pressed,
                    },
                ),
                sequence,
            );
            assert_eq!(result.disposition, CaptureDisposition::SuppressLocal);
        }

        let result = core.process_captured(
            captured(
                4,
                InputPayload::Key {
                    code: KeyCode::Backspace,
                    state: KeyState::Pressed,
                },
            ),
            4,
        );

        assert!(result.failsafe_activated);
        assert_eq!(result.disposition, CaptureDisposition::AllowLocal);
        assert!(result
            .actions
            .iter()
            .all(|action| matches!(action, CoreAction::Release(_))));
        assert!(!result.actions.iter().any(|action| matches!(
            action,
            CoreAction::Forward {
                event: InputEvent {
                    payload: InputPayload::Key {
                        code: KeyCode::Backspace,
                        ..
                    },
                    ..
                },
                ..
            }
        )));
        assert_eq!(core.workspace().active_host, LOCAL);
    }

    #[test]
    fn route_change_releases_held_keys_and_buttons_deterministically() {
        let mut core = core();
        for (sequence, payload) in [
            (
                1,
                InputPayload::Key {
                    code: KeyCode::ControlLeft,
                    state: KeyState::Pressed,
                },
            ),
            (
                2,
                InputPayload::Key {
                    code: KeyCode::KeyA,
                    state: KeyState::Pressed,
                },
            ),
            (
                3,
                InputPayload::PointerButton {
                    button: PointerButton::Left,
                    state: ButtonState::Pressed,
                },
            ),
        ] {
            let _ = core.process_captured(captured(sequence, payload), sequence);
        }

        let local_workspace =
            WorkspaceState::new(LOCAL, LOCAL, LogicalPointer::new(DISPLAY, 10.0, 20.0));
        let releases = core.update_workspace(local_workspace, 4).unwrap();

        assert_eq!(
            releases,
            vec![
                CoreAction::Release(RemoteRelease {
                    target: REMOTE,
                    source_device: DEVICE,
                    payload: InputPayload::Key {
                        code: KeyCode::KeyA,
                        state: KeyState::Released,
                    },
                }),
                CoreAction::Release(RemoteRelease {
                    target: REMOTE,
                    source_device: DEVICE,
                    payload: InputPayload::Key {
                        code: KeyCode::ControlLeft,
                        state: KeyState::Released,
                    },
                }),
                CoreAction::Release(RemoteRelease {
                    target: REMOTE,
                    source_device: DEVICE,
                    payload: InputPayload::PointerButton {
                        button: PointerButton::Left,
                        state: ButtonState::Released,
                    },
                }),
            ]
        );
        assert!(core.shutdown(5).is_empty());
    }

    #[test]
    fn snapshot_handle_keeps_old_reads_immutable() {
        let mut core = core();
        let handle = core.routing_handle();
        let before = handle.load();
        let _ = core.disable(1);
        let after = handle.load();

        assert!(before.enabled);
        assert!(!after.enabled);
    }

    #[test]
    fn forged_wrong_source_chord_cannot_trigger_local_failsafe() {
        let mut core = core();
        for (sequence, key) in [
            (1, KeyCode::ControlLeft),
            (2, KeyCode::AltLeft),
            (3, KeyCode::ShiftLeft),
            (4, KeyCode::Backspace),
        ] {
            let forged = InputEvent::new(
                sequence,
                sequence,
                REMOTE,
                DEVICE,
                InputPayload::Key {
                    code: key,
                    state: KeyState::Pressed,
                },
            );
            let result = core.process_captured(
                CapturedInput::new(forged, EventClassification::Physical),
                sequence,
            );
            assert!(!result.failsafe_activated);
            assert_eq!(result.disposition, CaptureDisposition::AllowLocal);
        }

        assert_eq!(core.workspace().active_host, REMOTE);
        let valid = core.process_captured(
            captured(5, InputPayload::PointerMove { dx: 1.0, dy: 1.0 }),
            5,
        );
        assert_eq!(valid.disposition, CaptureDisposition::SuppressLocal);
    }

    #[test]
    fn failsafe_stays_local_until_keys_are_drained_and_expiry_is_ticked() {
        let mut core = core();
        let pressed = [
            KeyCode::ControlLeft,
            KeyCode::AltLeft,
            KeyCode::ShiftLeft,
            KeyCode::Backspace,
        ];
        for (index, key) in pressed.into_iter().enumerate() {
            let _ = core.process_captured(
                captured(
                    index as u64 + 1,
                    InputPayload::Key {
                        code: key,
                        state: KeyState::Pressed,
                    },
                ),
                index as u64 + 1,
            );
        }
        for (index, key) in pressed.into_iter().enumerate() {
            let result = core.process_captured(
                captured(
                    index as u64 + 10,
                    InputPayload::Key {
                        code: key,
                        state: KeyState::Released,
                    },
                ),
                index as u64 + 10,
            );
            assert_eq!(result.disposition, CaptureDisposition::AllowLocal);
        }

        assert!(core.is_enabled());
        assert!(!core.is_routing_active());
        assert!(!core.tick(10_000_000_003));
        assert!(!core.is_routing_active());

        let before_tick = core.process_captured(
            captured(20, InputPayload::PointerMove { dx: 1.0, dy: 1.0 }),
            10_000_000_100,
        );
        assert_eq!(before_tick.disposition, CaptureDisposition::AllowLocal);
        assert!(core.tick(10_000_000_100));
        assert!(core.is_routing_active());

        // A peer must explicitly become active again after failure recovery.
        assert!(core
            .update_workspace(
                WorkspaceState::new(LOCAL, REMOTE, LogicalPointer::new(DISPLAY, 10.0, 20.0),),
                10_000_000_101,
            )
            .unwrap()
            .is_empty());
        let after_tick = core.process_captured(
            captured(21, InputPayload::PointerMove { dx: 1.0, dy: 1.0 }),
            10_000_000_102,
        );
        assert_eq!(after_tick.disposition, CaptureDisposition::SuppressLocal);
    }
}
