//! Daemon-side handler for the §31 local control IPC.
//!
//! The control panel talks to its local daemon over a [`LocalControlTransport`]
//! (named pipe on Windows, Unix socket on macOS — both plugged in through the
//! same trait). This module owns the *logic* behind that channel: it decodes a
//! [`ControlRequest`], validates it against live daemon state, routes writes
//! through an injectable effect trait, and encodes the [`ControlResponse`].
//!
//! The handler is deliberately transport- and backend-agnostic:
//!
//! - **Reads** go through [`ControlState`] (`&self`). The production backend
//!   queries `PeerManager` / `WorkspaceControlPlane` snapshots; a test fake
//!   serves canned values.
//! - **Writes** go through [`ControlEffects`] (`&mut self`). This is the seam
//!   the spec calls for: each `Set*` / `Enable*` / `Trigger*` command becomes a
//!   method the real daemon implements against its revisioned update paths
//!   (e.g. `SetDeviceRoute` → `PeerManager::set_selected_device_route`), while a
//!   test fake records the call.
//!
//! Keeping the seams in wire DTOs means the handler never touches daemon
//! internals — the `WireDeviceId` ↔ `DeviceId` translation belongs to the
//! backend, not the handler.
//!
//! Spec reference: `.spec/implementation.md` §31 (Daemon IPC commands + events).

use kvm_protocol::{
    ControlCodecError, ControlFrame, ControlRequest, ControlResponse, LocalControlTransport,
};
use std::fmt;

/// Read-only views the handler queries to build responses (`&self`).
///
/// Implement this against the daemon's live snapshots: `PeerManager::snapshot`,
/// `device_inventory_snapshot`, `workspace.inventory().snapshot()`, and the
/// selected routing handle. The handler calls these only for the `Get*`
/// commands; write commands are routed through [`ControlEffects`].
pub trait ControlState {
    /// Overall daemon status (active host/display, kvm+clipboard flags, RTT).
    fn status(&self) -> ControlStatusOutput;

    /// One entry per paired peer.
    fn peers(&self) -> Vec<ControlPeerEntry>;

    /// Every known input device across all hosts.
    fn devices(&self) -> Vec<ControlDeviceEntry>;

    /// Every known display across all hosts.
    fn displays(&self) -> Vec<ControlDisplayEntry>;

    /// The configured display-edge adjacencies.
    fn topology(&self) -> Vec<ControlTopologyEdge>;
}

/// Write effects the handler routes `Set*` / `Enable*` / `Trigger*` commands
/// through (`&mut self`). Each method returns `Ok(())` on success or a
/// [`ControlError`] describing why the daemon refused.
///
/// This is the injectable effect seam: production wires it to the daemon's
/// revisioned update paths; tests wire it to a recorder.
pub trait ControlEffects {
    /// Apply a per-device routing override.
    ///
    /// # Errors
    /// [`ControlError::UnknownDevice`] if the device is not paired, or another
    /// [`ControlError`] if the daemon rejects the update.
    fn set_device_route(
        &mut self,
        device: kvm_protocol::WireDeviceId,
        route: ControlDeviceRoute,
    ) -> Result<(), ControlError>;

    /// Replace the full display-edge adjacency graph.
    ///
    /// # Errors
    /// [`ControlError::InvalidTopology`] or [`ControlError::UnknownDisplay`] if
    /// the edge list is malformed, or another [`ControlError`] on rejection.
    fn set_topology(&mut self, edges: Vec<ControlTopologyEdge>) -> Result<(), ControlError>;

    /// Enable or disable KVM routing (`EnableKvm` / `DisableKvm`).
    ///
    /// # Errors
    /// [`ControlError::KvmDisabled`] is never returned by the enable path; a
    /// backend returns [`ControlError::Internal`] only if it cannot apply the
    /// change (e.g. remote cleanup fails mid-disable).
    fn set_kvm_enabled(&mut self, enabled: bool) -> Result<(), ControlError>;

    /// Enable or disable clipboard sharing (`EnableClipboard` / `DisableClipboard`).
    ///
    /// # Errors
    /// [`ControlError::Internal`] if the daemon does not (yet) back clipboard.
    fn set_clipboard_enabled(&mut self, enabled: bool) -> Result<(), ControlError>;

    /// Set the audio routing direction.
    ///
    /// # Errors
    /// [`ControlError::Internal`] if the daemon does not (yet) back audio.
    fn set_audio_route(&mut self, route: ControlAudioRoute) -> Result<(), ControlError>;

    /// Invoke the emergency failsafe (release all remote-held state).
    ///
    /// # Errors
    /// [`ControlError::Internal`] if the daemon cannot complete the release.
    fn trigger_failsafe(&mut self) -> Result<(), ControlError>;
}

/// Read outputs, expressed in the wire DTOs a backend already produces.
///
/// These mirror the `kvm_protocol::control` response payloads so a backend
/// built directly from daemon snapshots needs no translation.
pub type ControlStatusOutput = ControlStatus;
pub type ControlPeerEntry = ControlPeerStatus;
pub type ControlDeviceEntry = ControlDeviceSummary;
pub type ControlDisplayEntry = ControlDisplaySummary;

// Re-export the wire DTO types so a backend implementor can write
// `use kvm_daemon::control_handler::*` without reaching into kvm_protocol.
pub use kvm_protocol::{
    ControlAudioRoute, ControlDeviceKind, ControlDeviceRoute, ControlDeviceSummary,
    ControlDisplaySummary, ControlEdgeSide, ControlError, ControlPeerState, ControlPeerStatus,
    ControlStatus, ControlTopologyEdge,
};

/// Drives the §31 request/response exchange over a [`LocalControlTransport`].
///
/// Holds a borrow of the read state and a mutable borrow of the write effects
/// for the duration of the serve loop. Both seams are injectable, so the same
/// handler tests run against an in-memory fake and (later) the live daemon.
pub struct ControlHandler<'a, B: ControlState + ControlEffects + ?Sized> {
    backend: &'a mut B,
}

impl<B: ControlState + ControlEffects + ?Sized> fmt::Debug for ControlHandler<'_, B> {
    // The borrowed backend may carry device or peer identifiers, so the daemon
    // convention is to redact rather than render them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlHandler")
            .finish_non_exhaustive()
    }
}

/// Why a [`ControlHandler::serve`] call returned control to its caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServeOutcome {
    /// No frame was pending. A polling runtime should run its other work and
    /// call `serve` again on the next tick.
    Idle,
    /// The peer (control panel) closed its end of the channel.
    Closed,
}

impl<'a, B: ControlState + ControlEffects + ?Sized> ControlHandler<'a, B> {
    /// Wraps a backend for a serve loop. The backend must implement both
    /// [`ControlState`] (reads, `&self`) and [`ControlEffects`] (writes,
    /// `&mut self`); the handler holds a single `&mut` borrow, so reads and
    /// writes never alias.
    #[must_use]
    pub fn new(backend: &'a mut B) -> Self {
        Self { backend }
    }

    /// Maps one request to one response, validating inputs first.
    ///
    /// Validation is the handler's responsibility (not the backend's): a
    /// `SetDeviceRoute` for an unknown device returns [`ControlError::UnknownDevice`]
    /// before any effect runs, and a `SetTopology` referencing an unknown display
    /// returns [`ControlError::UnknownDisplay`]. This keeps the effect trait
    /// focused on *doing* the change rather than re-checking preconditions.
    #[must_use]
    pub fn handle(&mut self, request: ControlRequest) -> ControlResponse {
        match request {
            ControlRequest::GetStatus => ControlResponse::Status(self.backend.status()),
            ControlRequest::GetPeers => ControlResponse::Peers {
                peers: self.backend.peers(),
            },
            ControlRequest::GetDevices => ControlResponse::Devices {
                devices: self.backend.devices(),
            },
            ControlRequest::GetDisplays => ControlResponse::Displays {
                displays: self.backend.displays(),
            },
            ControlRequest::GetTopology => ControlResponse::Topology {
                edges: self.backend.topology(),
            },
            ControlRequest::SetDeviceRoute { device, route } => {
                if !self.backend.devices().iter().any(|d| d.device_id == device) {
                    return ControlResponse::Error {
                        error: ControlError::UnknownDevice,
                    };
                }
                self.effect(|b| b.set_device_route(device, route))
            }
            ControlRequest::SetTopology { edges } => {
                if let Some(error) = self.validate_topology(&edges) {
                    return ControlResponse::Error { error };
                }
                self.effect(|b| b.set_topology(edges))
            }
            ControlRequest::EnableKvm => self.effect(|b| b.set_kvm_enabled(true)),
            ControlRequest::DisableKvm => self.effect(|b| b.set_kvm_enabled(false)),
            ControlRequest::EnableClipboard => self.effect(|b| b.set_clipboard_enabled(true)),
            ControlRequest::DisableClipboard => self.effect(|b| b.set_clipboard_enabled(false)),
            ControlRequest::SetAudioRoute { route } => self.effect(|b| b.set_audio_route(route)),
            ControlRequest::TriggerFailsafe => self.effect(ControlEffects::trigger_failsafe),
        }
    }

    /// Pumps all currently-pending frames through [`handle`](Self::handle),
    /// replying to each, then returns control to the caller's runtime.
    ///
    /// Returns [`ServeOutcome::Idle`] when no frame is pending, and
    /// [`ServeOutcome::Closed`] when the peer has gone away. A genuine decode
    /// failure with the peer still connected is surfaced as
    /// [`ControlCodecError`]; a peer disconnect is reported as [`ServeOutcome::Closed`].
    ///
    /// # Errors
    /// Propagates [`ControlCodecError`] from the transport only when a frame
    /// could not be decoded (or sent) and the peer is still connected.
    pub fn serve<T: LocalControlTransport + ?Sized>(
        &mut self,
        transport: &mut T,
    ) -> Result<ServeOutcome, ControlCodecError> {
        loop {
            if transport.is_closed() {
                return Ok(ServeOutcome::Closed);
            }
            match transport.try_recv() {
                Ok(None) => return Ok(ServeOutcome::Idle),
                Ok(Some(ControlFrame::Request(request))) => {
                    let response = self.handle(request);
                    // A send failure may be a peer disconnect (the panel dropped
                    // its receiver between our recv and this reply). Mirroring
                    // the recv-error branch, treat that as a clean closure; only
                    // surface a genuine codec error when the peer is still there.
                    if let Err(error) = transport.send(ControlFrame::Response(response)) {
                        if transport.is_closed() {
                            return Ok(ServeOutcome::Closed);
                        }
                        return Err(error);
                    }
                }
                // The daemon is the responder; a Response/Event arriving here is
                // panel-side protocol misuse. Drop it and keep draining rather
                // than tearing down the channel on a single bad frame.
                Ok(Some(_)) => {}
                Err(error) => {
                    if transport.is_closed() {
                        return Ok(ServeOutcome::Closed);
                    }
                    return Err(error);
                }
            }
        }
    }

    /// Runs an effect and folds its result into a response.
    fn effect(&mut self, run: impl FnOnce(&mut B) -> Result<(), ControlError>) -> ControlResponse {
        match run(self.backend) {
            Ok(()) => ControlResponse::Acknowledged,
            Err(error) => ControlResponse::Error { error },
        }
    }

    /// Validates a topology edge list against the known displays.
    fn validate_topology(&self, edges: &[ControlTopologyEdge]) -> Option<ControlError> {
        // WireDisplayId is Copy, so collecting owned ids avoids borrowing the
        // temporary Vec returned by `displays()`.
        let known: std::collections::HashSet<kvm_protocol::WireDisplayId> = self
            .backend
            .displays()
            .iter()
            .map(|d| d.display_id)
            .collect();
        for edge in edges {
            if edge.from == edge.to {
                return Some(ControlError::InvalidTopology);
            }
            if !known.contains(&edge.from) || !known.contains(&edge.to) {
                return Some(ControlError::UnknownDisplay);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    //! The handler is exercised end-to-end through the real `LoopbackControlTransport`
    //! (which round-trips the postcard codec), against an in-memory backend that
    //! records every write and serves canned reads. This proves the §31 mapping,
    //! the validation preconditions, and the serve loop without standing up the
    //! full `PeerManager` + `DaemonCore` runtime.

    use super::*;
    use kvm_protocol::{
        LoopbackControlTransport, WireDeviceId, WireDisplayId, WireHostId, WirePeerId,
        MAX_CONTROL_SNAPSHOT_ITEMS,
    };
    use std::cell::RefCell;

    /// A canned snapshot plus a recorded log of every write the handler routed.
    struct FakeBackend {
        status: ControlStatus,
        peers: Vec<ControlPeerStatus>,
        devices: Vec<ControlDeviceSummary>,
        displays: Vec<ControlDisplaySummary>,
        topology: Vec<ControlTopologyEdge>,
        writes: RefCell<Vec<RecordedWrite>>,
        // When set, the next write returns this error instead of succeeding.
        reject_with: Option<ControlError>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RecordedWrite {
        SetDeviceRoute {
            device: WireDeviceId,
            route: ControlDeviceRoute,
        },
        SetTopology {
            edge_count: usize,
        },
        SetKvmEnabled {
            enabled: bool,
        },
        SetClipboardEnabled {
            enabled: bool,
        },
        SetAudioRoute {
            route: ControlAudioRoute,
        },
        TriggerFailsafe,
    }

    impl FakeBackend {
        fn empty() -> Self {
            Self {
                status: sample_status(),
                peers: Vec::new(),
                devices: Vec::new(),
                displays: Vec::new(),
                topology: Vec::new(),
                writes: RefCell::new(Vec::new()),
                reject_with: None,
            }
        }

        fn record(&self, write: RecordedWrite) -> Result<(), ControlError> {
            self.writes.borrow_mut().push(write);
            if let Some(error) = self.reject_with {
                return Err(error);
            }
            Ok(())
        }
    }

    impl ControlState for FakeBackend {
        fn status(&self) -> ControlStatus {
            self.status.clone()
        }
        fn peers(&self) -> Vec<ControlPeerStatus> {
            self.peers.clone()
        }
        fn devices(&self) -> Vec<ControlDeviceSummary> {
            self.devices.clone()
        }
        fn displays(&self) -> Vec<ControlDisplaySummary> {
            self.displays.clone()
        }
        fn topology(&self) -> Vec<ControlTopologyEdge> {
            self.topology.clone()
        }
    }

    impl ControlEffects for FakeBackend {
        fn set_device_route(
            &mut self,
            device: WireDeviceId,
            route: ControlDeviceRoute,
        ) -> Result<(), ControlError> {
            self.record(RecordedWrite::SetDeviceRoute { device, route })
        }
        fn set_topology(&mut self, edges: Vec<ControlTopologyEdge>) -> Result<(), ControlError> {
            let edge_count = edges.len();
            self.record(RecordedWrite::SetTopology { edge_count })
        }
        fn set_kvm_enabled(&mut self, enabled: bool) -> Result<(), ControlError> {
            self.record(RecordedWrite::SetKvmEnabled { enabled })
        }
        fn set_clipboard_enabled(&mut self, enabled: bool) -> Result<(), ControlError> {
            self.record(RecordedWrite::SetClipboardEnabled { enabled })
        }
        fn set_audio_route(&mut self, route: ControlAudioRoute) -> Result<(), ControlError> {
            self.record(RecordedWrite::SetAudioRoute { route })
        }
        fn trigger_failsafe(&mut self) -> Result<(), ControlError> {
            self.record(RecordedWrite::TriggerFailsafe)
        }
    }

    fn host(n: u8) -> WireHostId {
        WireHostId([n; 16])
    }
    fn device(n: u8) -> WireDeviceId {
        WireDeviceId([n; 16])
    }
    fn display(n: u8) -> WireDisplayId {
        WireDisplayId([n; 16])
    }
    fn peer(n: u8) -> WirePeerId {
        WirePeerId([n; 16])
    }

    fn sample_status() -> ControlStatus {
        ControlStatus {
            active_host: host(1),
            active_display: display(2),
            kvm_enabled: true,
            clipboard_enabled: false,
            protocol_version: kvm_protocol::PROTOCOL_VERSION,
            round_trip_time_ms: Some(7),
            peer_state: ControlPeerState::Connected,
        }
    }

    fn sample_backend() -> FakeBackend {
        let mut backend = FakeBackend::empty();
        backend.devices = vec![ControlDeviceSummary {
            device_id: device(7),
            host_id: host(8),
            name: "MX Master".to_owned(),
            kind: ControlDeviceKind::Mouse,
            route: ControlDeviceRoute::FollowActiveHost,
        }];
        backend.displays = vec![
            ControlDisplaySummary {
                display_id: display(1),
                host_id: host(1),
                name: "Left".to_owned(),
                logical_width: 1920,
                logical_height: 1080,
                scale_factor_percent: 100,
                primary: true,
            },
            ControlDisplaySummary {
                display_id: display(2),
                host_id: host(1),
                name: "Right".to_owned(),
                logical_width: 1920,
                logical_height: 1080,
                scale_factor_percent: 100,
                primary: false,
            },
        ];
        backend.topology = vec![ControlTopologyEdge {
            from: display(1),
            side: ControlEdgeSide::Right,
            to: display(2),
        }];
        backend.peers = vec![ControlPeerStatus {
            peer_id: peer(3),
            host_id: host(4),
            host_name: "desk-mac".to_owned(),
            state: ControlPeerState::Connected,
        }];
        backend
    }

    /// Sends a request from the panel end, pumps the daemon handler once, and
    /// returns the response decoded on the panel end.
    fn round_trip(
        backend: &mut FakeBackend,
        panel: &mut LoopbackControlTransport,
        daemon: &mut LoopbackControlTransport,
        request: ControlRequest,
    ) -> ControlResponse {
        panel
            .send(ControlFrame::Request(request))
            .expect("panel sends request");
        let mut handler = ControlHandler::new(backend);
        let outcome = handler.serve(daemon).expect("serve does not error");
        assert_eq!(
            outcome,
            ServeOutcome::Idle,
            "drains the one request then idles"
        );
        let frame = panel
            .try_recv()
            .expect("panel receives response")
            .expect("a frame is pending");
        let ControlFrame::Response(response) = frame else {
            panic!("expected a response frame, got {frame:?}");
        };
        response
    }

    #[test]
    fn get_status_reflects_backend_state() {
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        let response = round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::GetStatus,
        );
        let ControlResponse::Status(status) = response else {
            panic!("expected Status, got {response:?}");
        };
        assert_eq!(status.active_display, display(2));
        assert!(status.kvm_enabled);
        assert_eq!(status.round_trip_time_ms, Some(7));
    }

    #[test]
    fn get_peers_devices_displays_topology_each_return_backend_lists() {
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();

        match round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::GetPeers,
        ) {
            ControlResponse::Peers { peers } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].host_name, "desk-mac");
            }
            other => panic!("expected Peers, got {other:?}"),
        }
        match round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::GetDevices,
        ) {
            ControlResponse::Devices { devices } => {
                assert_eq!(devices.len(), 1);
                assert_eq!(devices[0].device_id, device(7));
            }
            other => panic!("expected Devices, got {other:?}"),
        }
        match round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::GetDisplays,
        ) {
            ControlResponse::Displays { displays } => assert_eq!(displays.len(), 2),
            other => panic!("expected Displays, got {other:?}"),
        }
        match round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::GetTopology,
        ) {
            ControlResponse::Topology { edges } => assert_eq!(edges.len(), 1),
            other => panic!("expected Topology, got {other:?}"),
        }
    }

    #[test]
    fn set_device_route_routes_through_effects_and_acknowledges() {
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        let response = round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::SetDeviceRoute {
                device: device(7),
                route: ControlDeviceRoute::Host(host(4)),
            },
        );
        assert_eq!(response, ControlResponse::Acknowledged);
        assert_eq!(
            backend.writes.borrow().as_slice(),
            &[RecordedWrite::SetDeviceRoute {
                device: device(7),
                route: ControlDeviceRoute::Host(host(4)),
            }]
        );
    }

    #[test]
    fn set_device_route_for_unknown_device_is_rejected_before_effects() {
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        let response = round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::SetDeviceRoute {
                device: device(99),
                route: ControlDeviceRoute::Local,
            },
        );
        assert_eq!(
            response,
            ControlResponse::Error {
                error: ControlError::UnknownDevice,
            }
        );
        // The effect must never run for a request that failed validation.
        assert!(backend.writes.borrow().is_empty());
    }

    #[test]
    fn set_topology_routes_valid_edges_through_effects() {
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        let edges = vec![ControlTopologyEdge {
            from: display(1),
            side: ControlEdgeSide::Right,
            to: display(2),
        }];
        let response = round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::SetTopology { edges },
        );
        assert_eq!(response, ControlResponse::Acknowledged);
        assert_eq!(
            backend.writes.borrow().as_slice(),
            &[RecordedWrite::SetTopology { edge_count: 1 }]
        );
    }

    #[test]
    fn set_topology_rejects_unknown_display_without_routing() {
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        let response = round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::SetTopology {
                edges: vec![ControlTopologyEdge {
                    from: display(1),
                    side: ControlEdgeSide::Right,
                    to: display(99),
                }],
            },
        );
        assert_eq!(
            response,
            ControlResponse::Error {
                error: ControlError::UnknownDisplay,
            }
        );
        assert!(backend.writes.borrow().is_empty());
    }

    #[test]
    fn set_topology_rejects_self_adjacency_as_invalid() {
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        let response = round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::SetTopology {
                edges: vec![ControlTopologyEdge {
                    from: display(1),
                    side: ControlEdgeSide::Right,
                    to: display(1),
                }],
            },
        );
        assert_eq!(
            response,
            ControlResponse::Error {
                error: ControlError::InvalidTopology,
            }
        );
        assert!(backend.writes.borrow().is_empty());
    }

    #[test]
    fn enable_disable_kvm_and_clipboard_each_route_distinctly() {
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();

        assert_eq!(
            round_trip(
                &mut backend,
                &mut panel,
                &mut daemon,
                ControlRequest::EnableKvm
            ),
            ControlResponse::Acknowledged
        );
        assert_eq!(
            round_trip(
                &mut backend,
                &mut panel,
                &mut daemon,
                ControlRequest::DisableKvm
            ),
            ControlResponse::Acknowledged
        );
        assert_eq!(
            round_trip(
                &mut backend,
                &mut panel,
                &mut daemon,
                ControlRequest::EnableClipboard
            ),
            ControlResponse::Acknowledged
        );
        assert_eq!(
            round_trip(
                &mut backend,
                &mut panel,
                &mut daemon,
                ControlRequest::DisableClipboard
            ),
            ControlResponse::Acknowledged
        );
        assert_eq!(
            backend.writes.borrow().as_slice(),
            &[
                RecordedWrite::SetKvmEnabled { enabled: true },
                RecordedWrite::SetKvmEnabled { enabled: false },
                RecordedWrite::SetClipboardEnabled { enabled: true },
                RecordedWrite::SetClipboardEnabled { enabled: false },
            ]
        );
    }

    #[test]
    fn set_audio_route_and_trigger_failsafe_route_through_effects() {
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        assert_eq!(
            round_trip(
                &mut backend,
                &mut panel,
                &mut daemon,
                ControlRequest::SetAudioRoute {
                    route: ControlAudioRoute::MacToWindows,
                }
            ),
            ControlResponse::Acknowledged
        );
        assert_eq!(
            round_trip(
                &mut backend,
                &mut panel,
                &mut daemon,
                ControlRequest::TriggerFailsafe
            ),
            ControlResponse::Acknowledged
        );
        assert_eq!(
            backend.writes.borrow().as_slice(),
            &[
                RecordedWrite::SetAudioRoute {
                    route: ControlAudioRoute::MacToWindows,
                },
                RecordedWrite::TriggerFailsafe,
            ]
        );
    }

    #[test]
    fn effect_error_is_returned_as_control_error_not_panicked() {
        let mut backend = sample_backend();
        backend.reject_with = Some(ControlError::Internal);
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        let response = round_trip(
            &mut backend,
            &mut panel,
            &mut daemon,
            ControlRequest::TriggerFailsafe,
        );
        assert_eq!(
            response,
            ControlResponse::Error {
                error: ControlError::Internal,
            }
        );
        // The write was still routed (and recorded) before the backend refused.
        assert_eq!(
            backend.writes.borrow().as_slice(),
            &[RecordedWrite::TriggerFailsafe]
        );
    }

    #[test]
    fn serve_drains_a_batch_of_requests_in_order_and_replies_to_each() {
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        // Queue three requests before the daemon pumps.
        panel
            .send(ControlFrame::Request(ControlRequest::EnableKvm))
            .unwrap();
        panel
            .send(ControlFrame::Request(ControlRequest::EnableClipboard))
            .unwrap();
        panel
            .send(ControlFrame::Request(ControlRequest::TriggerFailsafe))
            .unwrap();

        let mut handler = ControlHandler::new(&mut backend);
        let outcome = handler.serve(&mut daemon).expect("serve drains the batch");
        assert_eq!(outcome, ServeOutcome::Idle);

        let mut responses = Vec::new();
        while let Ok(Some(frame)) = panel.try_recv() {
            let ControlFrame::Response(response) = frame else {
                panic!("expected only responses, got {frame:?}");
            };
            responses.push(response);
        }
        assert_eq!(responses, vec![ControlResponse::Acknowledged; 3]);
        assert_eq!(
            backend.writes.borrow().as_slice(),
            &[
                RecordedWrite::SetKvmEnabled { enabled: true },
                RecordedWrite::SetClipboardEnabled { enabled: true },
                RecordedWrite::TriggerFailsafe,
            ]
        );
    }

    #[test]
    fn serve_returns_idle_when_nothing_is_pending() {
        let mut backend = sample_backend();
        let (panel, mut daemon) = LoopbackControlTransport::pair();
        let mut handler = ControlHandler::new(&mut backend);
        assert_eq!(handler.serve(&mut daemon).unwrap(), ServeOutcome::Idle);
        // Channel is still open and usable afterwards.
        assert!(!daemon.is_closed());
        drop(panel); // panel lives for the test; not closed
    }

    #[test]
    fn serve_returns_closed_after_the_panel_drops_its_end() {
        let mut backend = sample_backend();
        let (panel, mut daemon) = LoopbackControlTransport::pair();
        drop(panel);
        let mut handler = ControlHandler::new(&mut backend);
        // try_recv observes the disconnect; the handler reports closure rather
        // than surfacing it as a codec error.
        let outcome = handler
            .serve(&mut daemon)
            .expect("disconnect is not an error");
        assert_eq!(outcome, ServeOutcome::Closed);
    }

    #[test]
    fn serve_returns_closed_when_the_panel_drops_between_recv_and_send() {
        // The panel queues a request, then drops its end. The daemon receives
        // the request fine, but its reply send fails because the panel is gone.
        // The documented contract maps this disconnect to `Closed`, not a fatal
        // codec error (the send-path analogue of the recv-disconnect test above).
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        panel
            .send(ControlFrame::Request(ControlRequest::EnableKvm))
            .expect("request is queued before the panel drops");
        drop(panel);
        let mut handler = ControlHandler::new(&mut backend);
        let outcome = handler
            .serve(&mut daemon)
            .expect("a send-path disconnect is Closed, not an error");
        assert_eq!(outcome, ServeOutcome::Closed);
        // The request was still handled (the effect routed) even though the
        // reply could not be delivered.
        assert_eq!(
            backend.writes.borrow().as_slice(),
            &[RecordedWrite::SetKvmEnabled { enabled: true }]
        );
    }

    #[test]
    fn oversize_topology_is_rejected_by_the_codec_before_the_handler() {
        // An edge list longer than MAX_CONTROL_SNAPSHOT_ITEMS passes the byte-size
        // encode bound (each item is tiny) but is rejected by decode-time
        // validation. The handler therefore never sees it: the daemon's serve
        // surfaces a codec error and no write is routed.
        let too_many = vec![
            ControlTopologyEdge {
                from: display(1),
                side: ControlEdgeSide::Left,
                to: display(2),
            };
            MAX_CONTROL_SNAPSHOT_ITEMS + 1
        ];
        let mut backend = sample_backend();
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();
        panel
            .send(ControlFrame::Request(ControlRequest::SetTopology {
                edges: too_many,
            }))
            .expect("encode succeeds: the frame is under the byte-size cap");
        let mut handler = ControlHandler::new(&mut backend);
        let error = handler
            .serve(&mut daemon)
            .expect_err("decode-time validation rejects the over-long list");
        assert_eq!(error, ControlCodecError::Invalid);
        assert!(backend.writes.borrow().is_empty());
    }
}
