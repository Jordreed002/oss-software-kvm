//! Panel-side §31 control client (spec §31).
//!
//! One Tauri command reads the daemon's live status over the local control
//! endpoint (Unix domain socket / named pipe) using the daemon crate's
//! bounded poll helper. Transport absence is not an error: it maps to the
//! `unreachable` state so the UI can show "daemon not running".

use kvm_daemon::control_service::{
    poll_default_control_status, ControlError, ControlPeerState, ControlStatus, ControlStatusPoll,
};
use serde::Serialize;

/// Outcome of one §31 status poll.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlDaemonState {
    /// No daemon answered at the local endpoint.
    Unreachable,
    /// The daemon answered with a status payload.
    Responded,
    /// The daemon answered with a §31 error response.
    Refused,
}

/// Panel-ready projection of the §31 `ControlStatus`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DaemonControlStatus {
    pub kvm_enabled: bool,
    pub clipboard_enabled: bool,
    pub peer_state: ControlPeerStateDto,
    pub round_trip_time_ms: Option<u32>,
    /// 16-byte active host id; the UI compares it against the local identity.
    pub active_host: [u8; 16],
    pub protocol_version: u16,
}

/// Panel-ready projection of the §31 peer connection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlPeerStateDto {
    Disconnected,
    Discovering,
    Connecting,
    Authenticating,
    Connected,
    Degraded,
}

impl From<ControlPeerState> for ControlPeerStateDto {
    fn from(state: ControlPeerState) -> Self {
        match state {
            ControlPeerState::Disconnected => Self::Disconnected,
            ControlPeerState::Discovering => Self::Discovering,
            ControlPeerState::Connecting => Self::Connecting,
            ControlPeerState::Authenticating => Self::Authenticating,
            ControlPeerState::Connected => Self::Connected,
            ControlPeerState::Degraded => Self::Degraded,
        }
    }
}

impl From<ControlStatus> for DaemonControlStatus {
    fn from(status: ControlStatus) -> Self {
        Self {
            kvm_enabled: status.kvm_enabled,
            clipboard_enabled: status.clipboard_enabled,
            peer_state: status.peer_state.into(),
            round_trip_time_ms: status.round_trip_time_ms,
            active_host: status.active_host.0,
            protocol_version: status.protocol_version,
        }
    }
}

/// Reply shape returned to the webview. `status` is present only for
/// `responded`; `error` only for `refused`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ControlStatusReply {
    pub state: ControlDaemonState,
    pub status: Option<DaemonControlStatus>,
    pub error: Option<ControlError>,
}

/// Reads the daemon's live §31 status over the local control endpoint.
///
/// Always resolves: a missing or slow daemon maps to the `unreachable` state
/// instead of surfacing a hard error on every poll.
#[tauri::command]
pub(crate) async fn control_status() -> ControlStatusReply {
    ControlStatusReply::from(poll_default_control_status().await)
}

impl From<ControlStatusPoll> for ControlStatusReply {
    fn from(poll: ControlStatusPoll) -> Self {
        match poll {
            ControlStatusPoll::Status(status) => Self {
                state: ControlDaemonState::Responded,
                status: Some(DaemonControlStatus::from(status)),
                error: None,
            },
            ControlStatusPoll::Refused(error) => Self {
                state: ControlDaemonState::Refused,
                status: None,
                error: Some(error),
            },
            ControlStatusPoll::Unreachable => Self {
                state: ControlDaemonState::Unreachable,
                status: None,
                error: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_daemon::control_service::{WireDisplayId, WireHostId};

    fn sample_status() -> ControlStatus {
        ControlStatus {
            active_host: WireHostId([7; 16]),
            active_display: WireDisplayId([8; 16]),
            kvm_enabled: true,
            clipboard_enabled: false,
            protocol_version: 3,
            round_trip_time_ms: Some(4),
            peer_state: ControlPeerState::Degraded,
        }
    }

    #[test]
    fn status_projection_carries_every_control_field() {
        let projected = DaemonControlStatus::from(sample_status());

        assert!(projected.kvm_enabled);
        assert!(!projected.clipboard_enabled);
        assert_eq!(projected.peer_state, ControlPeerStateDto::Degraded);
        assert_eq!(projected.round_trip_time_ms, Some(4));
        assert_eq!(projected.protocol_version, 3);
    }

    #[test]
    fn peer_state_projection_maps_every_variant() {
        let pairs = [
            (ControlPeerState::Disconnected, ControlPeerStateDto::Disconnected),
            (ControlPeerState::Discovering, ControlPeerStateDto::Discovering),
            (ControlPeerState::Connecting, ControlPeerStateDto::Connecting),
            (ControlPeerState::Authenticating, ControlPeerStateDto::Authenticating),
            (ControlPeerState::Connected, ControlPeerStateDto::Connected),
            (ControlPeerState::Degraded, ControlPeerStateDto::Degraded),
        ];
        for (wire, projected) in pairs {
            assert_eq!(ControlPeerStateDto::from(wire), projected);
        }
    }

    #[test]
    fn poll_outcomes_project_to_the_reply_shape() {
        let unreachable = ControlStatusReply::from(ControlStatusPoll::Unreachable);
        assert_eq!(unreachable.state, ControlDaemonState::Unreachable);
        assert!(unreachable.status.is_none());
        assert!(unreachable.error.is_none());

        let refused = ControlStatusReply::from(ControlStatusPoll::Refused(ControlError::Internal));
        assert_eq!(refused.state, ControlDaemonState::Refused);
        assert_eq!(refused.error, Some(ControlError::Internal));

        let responded = ControlStatusReply::from(ControlStatusPoll::Status(sample_status()));
        assert_eq!(responded.state, ControlDaemonState::Responded);
        assert!(responded.status.is_some());
    }

    #[test]
    fn reply_serializes_states_the_webview_expects() {
        let unreachable = ControlStatusReply::from(ControlStatusPoll::Unreachable);
        let json = serde_json::to_string(&unreachable).expect("serialize");
        assert_eq!(json, r#"{"state":"unreachable","status":null,"error":null}"#);

        let responded = ControlStatusReply::from(ControlStatusPoll::Status(sample_status()));
        let json = serde_json::to_string(&responded).expect("serialize");
        assert!(json.contains(r#""state":"responded""#));
        assert!(json.contains(r#""peerState":"degraded""#));
        assert!(json.contains(r#""kvmEnabled":true"#));
        assert!(json.contains(r#""roundTripTimeMs":4"#));
        assert!(json.contains(r#""activeHost":["#));
    }
}
