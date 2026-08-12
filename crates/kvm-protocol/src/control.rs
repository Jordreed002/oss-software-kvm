//! Local control-plane protocol between the KVM daemon and the control panel.
//!
//! This is intentionally independent of the peer wire protocol ([`crate::WireMessage`]):
//! the control panel talks to its *local* daemon over a named pipe / Unix domain
//! socket, not the encrypted inter-host transport. Keeping the surfaces separate
//! lets the local control contract evolve without touching the peer wire format
//! (and vice-versa), matching the spec's call for independent versioning.
//!
//! Types here are transport DTOs. The daemon translates to and from its domain
//! model (`kvm-daemon` snapshots, `kvm-input`, `kvm-types`); the control panel
//! consumes the decoded values directly.
//!
//! Spec reference: `.spec/implementation.md` §31 (Daemon IPC commands + events).

use crate::{WireDeviceId, WireDisplayId, WireHostId, WirePeerId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Control-plane protocol version. Bump independently of the peer
/// [`crate::PROTOCOL_VERSION`].
pub const CONTROL_PROTOCOL_VERSION: u8 = 1;

/// Maximum entries in a snapshot list response (peers, devices, displays, edges).
pub const MAX_CONTROL_SNAPSHOT_ITEMS: usize = 256;
/// Bound on a device or display name carried in a control response.
pub const MAX_CONTROL_NAME_BYTES: usize = 255;
/// Bound on the total encoded control frame, defending against malicious peers
/// on a shared machine. The transport is local, so this is generous but finite.
pub const MAX_CONTROL_FRAME_BYTES: usize = 1 << 20; // 1 MiB

// --- Reused wire DTOs for control payloads ---------------------------------

/// Per-device routing override (spec §8).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlDeviceRoute {
    FollowActiveHost,
    Local,
    Host(WireHostId),
}

/// Physical device class (spec §6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlDeviceKind {
    Keyboard,
    Mouse,
    Trackpad,
    Other,
}

/// Peer connection state (spec §22).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlPeerState {
    Disconnected,
    Discovering,
    Connecting,
    Authenticating,
    Connected,
    Degraded,
}

/// A display edge that connects to a neighbour (spec §11/§14).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlEdgeSide {
    Left,
    Right,
    Top,
    Bottom,
}

/// Audio routing direction (spec §28). Both directions at once is intentionally
/// absent because of feedback risk.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlAudioRoute {
    Disabled,
    WindowsToMac,
    MacToWindows,
}

/// One configured display-edge adjacency.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlTopologyEdge {
    pub from: WireDisplayId,
    pub side: ControlEdgeSide,
    pub to: WireDisplayId,
}

/// Failure reported back to the control panel for a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlError {
    KvmDisabled,
    UnknownDevice,
    UnknownDisplay,
    InvalidRoute,
    InvalidTopology,
    NotPaired,
    Internal,
}

// --- Request (spec §31 commands) -------------------------------------------

/// A control-panel command directed at the local daemon.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlRequest {
    GetStatus,
    GetPeers,
    GetDevices,
    GetDisplays,
    GetTopology,
    SetDeviceRoute {
        device: WireDeviceId,
        route: ControlDeviceRoute,
    },
    SetTopology {
        edges: Vec<ControlTopologyEdge>,
    },
    EnableKvm,
    DisableKvm,
    EnableClipboard,
    DisableClipboard,
    SetAudioRoute {
        route: ControlAudioRoute,
    },
    TriggerFailsafe,
}

// --- Response payloads -----------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlStatus {
    pub active_host: WireHostId,
    pub active_display: WireDisplayId,
    pub kvm_enabled: bool,
    pub clipboard_enabled: bool,
    pub protocol_version: u16,
    /// Most recent peer round-trip time in milliseconds, if a peer is connected.
    pub round_trip_time_ms: Option<u32>,
    pub peer_state: ControlPeerState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlPeerStatus {
    pub peer_id: WirePeerId,
    pub host_id: WireHostId,
    pub host_name: String,
    pub state: ControlPeerState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlDeviceSummary {
    pub device_id: WireDeviceId,
    pub host_id: WireHostId,
    pub name: String,
    pub kind: ControlDeviceKind,
    pub route: ControlDeviceRoute,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlDisplaySummary {
    pub display_id: WireDisplayId,
    pub host_id: WireHostId,
    pub name: String,
    pub logical_width: u32,
    pub logical_height: u32,
    pub scale_factor_percent: u32,
    pub primary: bool,
}

/// Daemon reply to a [`ControlRequest`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlResponse {
    Status(ControlStatus),
    Peers {
        peers: Vec<ControlPeerStatus>,
    },
    Devices {
        devices: Vec<ControlDeviceSummary>,
    },
    Displays {
        displays: Vec<ControlDisplaySummary>,
    },
    Topology {
        edges: Vec<ControlTopologyEdge>,
    },
    Acknowledged,
    Error {
        error: ControlError,
    },
}

// --- Events (spec §31 events) ----------------------------------------------

/// An unsolicited daemon-to-panel notification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlEvent {
    PeerChanged,
    DeviceChanged,
    DisplayChanged,
    ActiveHostChanged { active_host: WireHostId },
    ActiveDisplayChanged { active_display: WireDisplayId },
    LatencyChanged { round_trip_time_ms: u32 },
    ErrorOccurred { error: ControlError },
}

/// One frame on the local control channel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlFrame {
    Request(ControlRequest),
    Response(ControlResponse),
    Event(ControlEvent),
}

/// Encoding/decoding failure for a control frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ControlCodecError {
    /// The encoded frame exceeded [`MAX_CONTROL_FRAME_BYTES`].
    #[error("control frame exceeds maximum size")]
    Oversized,
    /// The leading version byte does not match [`CONTROL_PROTOCOL_VERSION`].
    #[error("unsupported control protocol version")]
    UnsupportedVersion,
    /// Postcard (de)serialization failed.
    #[error("control frame was malformed")]
    Malformed,
    /// A decoded frame violated a length or content bound.
    #[error("control frame failed validation")]
    Invalid,
}

/// Encode a frame with a leading version byte.
///
/// # Errors
/// Returns [`ControlCodecError::Oversized`] when the encoded frame (version byte
/// + postcard payload) exceeds [`MAX_CONTROL_FRAME_BYTES`].
pub fn encode_control(frame: &ControlFrame) -> Result<Vec<u8>, ControlCodecError> {
    let payload = postcard::to_allocvec(frame).map_err(|_| ControlCodecError::Malformed)?;
    let mut bytes = Vec::with_capacity(payload.len() + 1);
    bytes.push(CONTROL_PROTOCOL_VERSION);
    bytes.extend(payload);
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlCodecError::Oversized);
    }
    Ok(bytes)
}

/// Decode a frame produced by [`encode_control`].
///
/// # Errors
/// Returns [`ControlCodecError::UnsupportedVersion`] when the version byte is
/// wrong, [`ControlCodecError::Oversized`] when the buffer is too large,
/// [`ControlCodecError::Malformed`] on a postcard failure, and
/// [`ControlCodecError::Invalid`] when a decoded frame violates a bound.
pub fn decode_control(bytes: &[u8]) -> Result<ControlFrame, ControlCodecError> {
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlCodecError::Oversized);
    }
    let (version, payload) = bytes.split_first().ok_or(ControlCodecError::Malformed)?;
    if *version != CONTROL_PROTOCOL_VERSION {
        return Err(ControlCodecError::UnsupportedVersion);
    }
    let frame: ControlFrame =
        postcard::from_bytes(payload).map_err(|_| ControlCodecError::Malformed)?;
    frame.validate()?;
    Ok(frame)
}

impl ControlFrame {
    /// Enforces length bounds on decoded payloads.
    fn validate(&self) -> Result<(), ControlCodecError> {
        let snapshot_ok = |len: usize| len <= MAX_CONTROL_SNAPSHOT_ITEMS;
        let name_ok = |name: &str| name.len() <= MAX_CONTROL_NAME_BYTES;
        let require = |cond: bool| cond.then_some(()).ok_or(ControlCodecError::Invalid);
        match self {
            Self::Request(ControlRequest::SetTopology { edges })
            | Self::Response(ControlResponse::Topology { edges }) => {
                require(snapshot_ok(edges.len()))
            }
            Self::Response(ControlResponse::Peers { peers }) => {
                require(snapshot_ok(peers.len()) && peers.iter().all(|p| name_ok(&p.host_name)))
            }
            Self::Response(ControlResponse::Devices { devices }) => {
                require(snapshot_ok(devices.len()) && devices.iter().all(|d| name_ok(&d.name)))
            }
            Self::Response(ControlResponse::Displays { displays }) => {
                require(snapshot_ok(displays.len()) && displays.iter().all(|d| name_ok(&d.name)))
            }
            _ => Ok(()),
        }
    }
}

// --- Local transport abstraction -------------------------------------------
//
// The control panel and daemon exchange [`ControlFrame`]s over a local channel
// (named pipe on Windows, Unix domain socket on macOS). This trait captures the
// contract both ends program against so the daemon, the panel, and integration
// tests can be written before a specific OS-backed implementation exists. The
// loopback below carries frames through the real codec so it also exercises
// [`encode_control`]/[`decode_control`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

/// One end of a daemon↔control-panel local channel.
///
/// The channel is reliable, ordered, and carries whole [`ControlFrame`]s.
/// Implementations wrap a platform transport (named pipe / Unix socket) and
/// serialise through [`encode_control`]/[`decode_control`].
pub trait LocalControlTransport: Send {
    /// Send a frame to the peer.
    ///
    /// # Errors
    /// Returns [`ControlCodecError::Oversized`] when the frame exceeds
    /// [`MAX_CONTROL_FRAME_BYTES`], or [`ControlCodecError::Malformed`] when the
    /// peer's end has gone away.
    fn send(&mut self, frame: ControlFrame) -> Result<(), ControlCodecError>;

    /// Receive the next pending frame without blocking.
    ///
    /// # Errors
    /// Returns [`ControlCodecError::Malformed`] on a decode failure or when the
    /// peer's end has gone away.
    fn try_recv(&mut self) -> Result<Option<ControlFrame>, ControlCodecError>;

    /// Whether the peer has closed its end of the channel.
    #[must_use]
    fn is_closed(&self) -> bool;
}

/// In-process loopback transport for tests and the control panel's dev harness.
///
/// Create a connected pair with [`LoopbackControlTransport::pair`]. Frames pass
/// through the real codec so the loopback doubles as an end-to-end codec test.
#[derive(Debug)]
pub struct LoopbackControlTransport {
    tx: Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    peer_closed: Arc<AtomicBool>,
}

impl LoopbackControlTransport {
    /// Creates two ends connected to each other.
    #[must_use]
    pub fn pair() -> (Self, Self) {
        let (tx_a, rx_a) = mpsc::channel();
        let (tx_b, rx_b) = mpsc::channel();
        let peer_closed_a = Arc::new(AtomicBool::new(false));
        let peer_closed_b = Arc::new(AtomicBool::new(false));
        (
            Self {
                tx: tx_a,
                rx: rx_b,
                peer_closed: peer_closed_a,
            },
            Self {
                tx: tx_b,
                rx: rx_a,
                peer_closed: peer_closed_b,
            },
        )
    }
}

impl LocalControlTransport for LoopbackControlTransport {
    fn send(&mut self, frame: ControlFrame) -> Result<(), ControlCodecError> {
        let bytes = encode_control(&frame)?;
        // A send error means the peer dropped its receiver: mark this end
        // closed and surface the error. Callers (notably `ControlHandler::serve`)
        // then observe `is_closed()` and map the disconnect to a clean closure
        // rather than a fatal codec error.
        if self.tx.send(bytes).is_err() {
            self.peer_closed.store(true, Ordering::Release);
            return Err(ControlCodecError::Malformed);
        }
        Ok(())
    }

    fn try_recv(&mut self) -> Result<Option<ControlFrame>, ControlCodecError> {
        match self.rx.recv_timeout(Duration::ZERO) {
            Ok(bytes) => decode_control(&bytes).map(Some),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                self.peer_closed.store(true, Ordering::Release);
                Err(ControlCodecError::Malformed)
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.peer_closed.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn every_request_round_trips() {
        let requests = [
            ControlRequest::GetStatus,
            ControlRequest::GetPeers,
            ControlRequest::GetDevices,
            ControlRequest::GetDisplays,
            ControlRequest::GetTopology,
            ControlRequest::SetDeviceRoute {
                device: device(1),
                route: ControlDeviceRoute::Host(host(2)),
            },
            ControlRequest::SetTopology {
                edges: vec![ControlTopologyEdge {
                    from: display(3),
                    side: ControlEdgeSide::Right,
                    to: display(4),
                }],
            },
            ControlRequest::EnableKvm,
            ControlRequest::DisableKvm,
            ControlRequest::EnableClipboard,
            ControlRequest::DisableClipboard,
            ControlRequest::SetAudioRoute {
                route: ControlAudioRoute::WindowsToMac,
            },
            ControlRequest::TriggerFailsafe,
        ];
        for request in requests {
            let frame = ControlFrame::Request(request);
            let bytes = encode_control(&frame).unwrap();
            assert_eq!(decode_control(&bytes).unwrap(), frame);
        }
    }

    #[test]
    fn every_response_round_trips() {
        let responses = [
            ControlResponse::Status(ControlStatus {
                active_host: host(1),
                active_display: display(2),
                kvm_enabled: true,
                clipboard_enabled: false,
                protocol_version: 2,
                round_trip_time_ms: Some(7),
                peer_state: ControlPeerState::Connected,
            }),
            ControlResponse::Peers {
                peers: vec![ControlPeerStatus {
                    peer_id: peer(3),
                    host_id: host(4),
                    host_name: "desk-mac".to_owned(),
                    state: ControlPeerState::Degraded,
                }],
            },
            ControlResponse::Devices {
                devices: vec![sample_device()],
            },
            ControlResponse::Displays {
                displays: vec![ControlDisplaySummary {
                    display_id: display(5),
                    host_id: host(6),
                    name: "Monitor 1".to_owned(),
                    logical_width: 3840,
                    logical_height: 2160,
                    scale_factor_percent: 150,
                    primary: true,
                }],
            },
            ControlResponse::Topology {
                edges: vec![ControlTopologyEdge {
                    from: display(1),
                    side: ControlEdgeSide::Bottom,
                    to: display(2),
                }],
            },
            ControlResponse::Acknowledged,
            ControlResponse::Error {
                error: ControlError::NotPaired,
            },
        ];
        for response in responses {
            let frame = ControlFrame::Response(response);
            let bytes = encode_control(&frame).unwrap();
            assert_eq!(decode_control(&bytes).unwrap(), frame);
        }
    }

    fn sample_device() -> ControlDeviceSummary {
        ControlDeviceSummary {
            device_id: device(7),
            host_id: host(8),
            name: "MX Master".to_owned(),
            kind: ControlDeviceKind::Mouse,
            route: ControlDeviceRoute::FollowActiveHost,
        }
    }

    #[test]
    fn every_event_round_trips() {
        let events = [
            ControlEvent::PeerChanged,
            ControlEvent::DeviceChanged,
            ControlEvent::DisplayChanged,
            ControlEvent::ActiveHostChanged {
                active_host: host(1),
            },
            ControlEvent::ActiveDisplayChanged {
                active_display: display(2),
            },
            ControlEvent::LatencyChanged {
                round_trip_time_ms: 12,
            },
            ControlEvent::ErrorOccurred {
                error: ControlError::Internal,
            },
        ];
        for event in events {
            let frame = ControlFrame::Event(event);
            let bytes = encode_control(&frame).unwrap();
            assert_eq!(decode_control(&bytes).unwrap(), frame);
        }
    }

    #[test]
    fn version_byte_is_rejected() {
        let mut bytes = encode_control(&ControlFrame::Request(ControlRequest::GetStatus)).unwrap();
        bytes[0] = CONTROL_PROTOCOL_VERSION.wrapping_add(1);
        assert_eq!(
            decode_control(&bytes).unwrap_err(),
            ControlCodecError::UnsupportedVersion
        );
    }

    #[test]
    fn oversize_topology_is_invalid() {
        let too_many = vec![
            ControlTopologyEdge {
                from: display(1),
                side: ControlEdgeSide::Left,
                to: display(2)
            };
            MAX_CONTROL_SNAPSHOT_ITEMS + 1
        ];
        let frame = ControlFrame::Request(ControlRequest::SetTopology { edges: too_many });
        // Encode succeeds (under the frame byte cap because items are small);
        // decode rejects it via validation.
        let bytes = encode_control(&frame).unwrap();
        assert_eq!(
            decode_control(&bytes).unwrap_err(),
            ControlCodecError::Invalid
        );
    }

    #[test]
    fn empty_buffer_is_malformed() {
        assert_eq!(
            decode_control(&[]).unwrap_err(),
            ControlCodecError::Malformed
        );
    }

    #[test]
    fn loopback_round_trips_request_and_response_in_order() {
        let (mut panel, mut daemon) = LoopbackControlTransport::pair();

        // Panel -> daemon: a request. Daemon starts with nothing pending.
        assert_eq!(daemon.try_recv().unwrap(), None);
        panel
            .send(ControlFrame::Request(ControlRequest::GetStatus))
            .unwrap();

        let received = daemon.try_recv().unwrap().unwrap();
        assert_eq!(received, ControlFrame::Request(ControlRequest::GetStatus));

        // Daemon -> panel: the response, through the same codec.
        daemon
            .send(ControlFrame::Response(ControlResponse::Status(
                ControlStatus {
                    active_host: host(1),
                    active_display: display(2),
                    kvm_enabled: true,
                    clipboard_enabled: true,
                    protocol_version: 2,
                    round_trip_time_ms: Some(4),
                    peer_state: ControlPeerState::Connected,
                },
            )))
            .unwrap();
        let response = panel.try_recv().unwrap().unwrap();
        let ControlFrame::Response(ControlResponse::Status(status)) = response else {
            panic!("expected status response, got {response:?}");
        };
        assert!(status.kvm_enabled);
        assert_eq!(status.round_trip_time_ms, Some(4));

        // No further frames pending on either end, and neither is closed.
        assert_eq!(panel.try_recv().unwrap(), None);
        assert!(!panel.is_closed());
        assert!(!daemon.is_closed());
    }

    #[test]
    fn dropping_one_end_observes_closure_on_the_other() {
        let (mut panel, daemon) = LoopbackControlTransport::pair();
        drop(daemon);
        // A send after the peer is gone fails; the panel learns it is closed.
        assert!(panel
            .send(ControlFrame::Request(ControlRequest::TriggerFailsafe))
            .is_err());
    }
}
