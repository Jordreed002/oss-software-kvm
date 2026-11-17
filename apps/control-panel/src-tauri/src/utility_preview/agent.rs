//! Read-only agent status bridge for the `--utility-agent` development mode.
//!
//! Exposes exactly one IPC command, [`agent_status`], registered only by the
//! agent-mode builder in debug builds served by the Vite dev server. It never
//! touches the legacy `SetupService`, discovery, runtime or input capture.
//!
//! The agent API's types are deliberately not serialized directly: the
//! webview gets a small local projection ([`AgentStatus`]) so the wire
//! contract and the UI contract can evolve separately, every agent enum is
//! matched exhaustively (a new upstream variant fails to compile here rather
//! than leaking through), and `StatusError` (not `Serialize`) maps to a fixed
//! payload-free category.

use kvm_agent::client::StatusError;
use kvm_agent_api::{
    AgentSnapshot, InputDestination, LifecyclePhase, Prerequisite, SafetyCause, SafetyState,
    Support, UserIntent,
};
use serde::Serialize;

/// The only window allowed to call [`agent_status`].
pub(crate) const WINDOW_LABEL: &str = "utility-agent";
/// Emitted to [`WINDOW_LABEL`] when the tray re-opens the window, so the page
/// can fetch once per open. There is no polling.
pub(crate) const OPENED_EVENT: &str = "utility-agent:opened";

/// Error returned to the webview when the caller is not the authorized window.
/// Agent failures are *not* errors at this layer; they are [`AgentStatus`].
const NOT_AUTHORIZED: &str = "agent_status is only available to the utility-agent window";

/// Whether a window label may read agent status.
pub(crate) fn authorized(label: &str) -> bool {
    label == WINDOW_LABEL
}

/// Reads one snapshot from the native agent endpoint.
///
/// Read-only: no command is sent besides the API's hello/snapshot exchange.
/// The client bounds the whole query (2 s), so this cannot hang the webview.
#[tauri::command]
pub(crate) async fn agent_status(window: tauri::Window) -> Result<AgentStatus, &'static str> {
    if !authorized(window.label()) {
        return Err(NOT_AUTHORIZED);
    }
    Ok(AgentStatus::from_result(
        kvm_agent::client::query_native().await,
    ))
}

/// Serialized result of one status query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum AgentStatus {
    /// A verified agent answered with an instance-bound snapshot.
    Connected { snapshot: SnapshotView },
    /// No snapshot was obtained. Never a confirmed idle state.
    Unavailable { error: ErrorKind },
}

impl AgentStatus {
    pub(crate) fn from_result(result: Result<AgentSnapshot, StatusError>) -> Self {
        match result {
            Ok(snapshot) => Self::Connected {
                snapshot: SnapshotView::from(&snapshot),
            },
            Err(error) => Self::Unavailable {
                error: ErrorKind::from(error),
            },
        }
    }
}

/// Payload-free failure category. No endpoint path, account or OS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorKind {
    /// No agent endpoint exists (or it refused the connection).
    NotFound,
    /// The endpoint exists but failed native peer verification.
    PermissionDenied,
    /// The bounded query budget expired.
    TimedOut,
    /// Protocol name or version could not be agreed.
    Incompatible,
    /// Malformed, mismatched or out-of-order reply.
    InvalidReply,
    /// Any other connection failure.
    Transport,
}

impl From<StatusError> for ErrorKind {
    fn from(error: StatusError) -> Self {
        match error {
            StatusError::NotFound => Self::NotFound,
            StatusError::PermissionDenied => Self::PermissionDenied,
            StatusError::TimedOut => Self::TimedOut,
            StatusError::Incompatible => Self::Incompatible,
            StatusError::InvalidReply => Self::InvalidReply,
            StatusError::Transport => Self::Transport,
        }
    }
}

/// UI projection of [`AgentSnapshot`]. Unknown stays unknown: nothing here is
/// defaulted, inferred or upgraded to a confirmed value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SnapshotView {
    /// Canonical agent instance UUID (troubleshooting only).
    instance: String,
    /// Decimal revision as a string: u64 does not fit a JS number exactly.
    revision: String,
    lifecycle: Lifecycle,
    user_intent: Intent,
    safety: Safety,
    cleanup_unconfirmed: bool,
    input: Input,
    readiness: ReadinessView,
    capabilities: CapabilitiesView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Lifecycle {
    Idle,
    Preparing,
    Active,
    Draining,
    Faulted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Intent {
    Paused,
    SharingRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Safety {
    Clear,
    Latched { cause: Cause },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Cause {
    FailsafeCommand,
    NativePermissionLoss,
    PeerLinkFailure,
    Unspecified,
}

/// Session and generation are intentionally omitted; the UI only names the
/// confirmed remote host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "destination", rename_all = "snake_case")]
enum Input {
    Local,
    Remote { host: String },
    Transitioning,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Check {
    Confirmed,
    Unconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadinessView {
    configuration: Check,
    enrollment: Check,
    permissions: Check,
    inventory: Check,
    peer_authentication: Check,
    input_authority: Check,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Offer {
    Supported,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitiesView {
    pause: Offer,
    resume: Offer,
    failsafe: Offer,
    quit: Offer,
    snapshot: Offer,
}

impl From<&AgentSnapshot> for SnapshotView {
    fn from(s: &AgentSnapshot) -> Self {
        Self {
            instance: s.instance.get().hyphenated().to_string(),
            revision: s.revision.get().to_string(),
            lifecycle: match s.lifecycle {
                LifecyclePhase::Idle => Lifecycle::Idle,
                LifecyclePhase::Preparing => Lifecycle::Preparing,
                LifecyclePhase::Active => Lifecycle::Active,
                LifecyclePhase::Draining => Lifecycle::Draining,
                LifecyclePhase::Faulted => Lifecycle::Faulted,
            },
            user_intent: match s.user_intent {
                UserIntent::Paused => Intent::Paused,
                UserIntent::SharingRequested => Intent::SharingRequested,
            },
            safety: match s.safety {
                SafetyState::Clear(_) => Safety::Clear,
                SafetyState::Latched(latch) => Safety::Latched {
                    cause: match latch.cause {
                        SafetyCause::FailsafeCommand => Cause::FailsafeCommand,
                        SafetyCause::NativePermissionLoss => Cause::NativePermissionLoss,
                        SafetyCause::PeerLinkFailure => Cause::PeerLinkFailure,
                        SafetyCause::Unspecified => Cause::Unspecified,
                    },
                },
            },
            cleanup_unconfirmed: s.cleanup_unconfirmed,
            input: match &s.input_destination {
                InputDestination::Local(_) => Input::Local,
                InputDestination::Remote(target) => Input::Remote {
                    host: target.host.as_str().to_owned(),
                },
                InputDestination::Transitioning(_) => Input::Transitioning,
                InputDestination::Unknown(_) => Input::Unknown,
            },
            readiness: ReadinessView {
                configuration: check(s.readiness.configuration),
                enrollment: check(s.readiness.enrollment),
                permissions: check(s.readiness.permissions),
                inventory: check(s.readiness.inventory),
                peer_authentication: check(s.readiness.peer_authentication),
                input_authority: check(s.readiness.input_authority),
            },
            capabilities: CapabilitiesView {
                pause: offer(s.capabilities.pause),
                resume: offer(s.capabilities.resume),
                failsafe: offer(s.capabilities.failsafe),
                quit: offer(s.capabilities.quit),
                snapshot: offer(s.capabilities.snapshot),
            },
        }
    }
}

fn check(p: Prerequisite) -> Check {
    match p {
        Prerequisite::Confirmed => Check::Confirmed,
        Prerequisite::Unconfirmed => Check::Unconfirmed,
    }
}

fn offer(s: Support) -> Offer {
    match s {
        Support::Supported => Offer::Supported,
        Support::Unsupported => Offer::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_agent_api::{
        Capabilities, Generation, HostLabel, InstanceId, Latch, LocalInput, Readiness,
        RemoteTarget, Revision, SafetyClear, SessionId, UnknownInput,
    };
    use serde_json::json;

    const ID: &str = "6f1c2f4e-8a1b-4c3d-9e5f-0a1b2c3d4e5f";

    /// Mirrors the idle agent stub: everything unknown/unconfirmed.
    fn idle_stub() -> AgentSnapshot {
        AgentSnapshot {
            instance: InstanceId::new(uuid::Uuid::parse_str(ID).unwrap()).unwrap(),
            revision: Revision::new(0),
            lifecycle: LifecyclePhase::Idle,
            user_intent: UserIntent::Paused,
            safety: SafetyState::Clear(SafetyClear {}),
            cleanup_unconfirmed: false,
            input_destination: InputDestination::Unknown(UnknownInput {}),
            readiness: Readiness {
                configuration: Prerequisite::Unconfirmed,
                enrollment: Prerequisite::Unconfirmed,
                permissions: Prerequisite::Unconfirmed,
                inventory: Prerequisite::Unconfirmed,
                peer_authentication: Prerequisite::Unconfirmed,
                input_authority: Prerequisite::Unconfirmed,
            },
            capabilities: Capabilities {
                pause: Support::Unsupported,
                resume: Support::Unsupported,
                failsafe: Support::Unsupported,
                quit: Support::Unsupported,
                snapshot: Support::Supported,
            },
        }
    }

    #[test]
    fn idle_stub_projects_unknown_as_unknown() {
        let value = serde_json::to_value(AgentStatus::from_result(Ok(idle_stub()))).unwrap();
        assert_eq!(
            value,
            json!({
                "kind": "connected",
                "snapshot": {
                    "instance": ID,
                    "revision": "0",
                    "lifecycle": "idle",
                    "userIntent": "paused",
                    "safety": { "state": "clear" },
                    "cleanupUnconfirmed": false,
                    "input": { "destination": "unknown" },
                    "readiness": {
                        "configuration": "unconfirmed",
                        "enrollment": "unconfirmed",
                        "permissions": "unconfirmed",
                        "inventory": "unconfirmed",
                        "peerAuthentication": "unconfirmed",
                        "inputAuthority": "unconfirmed"
                    },
                    "capabilities": {
                        "pause": "unsupported",
                        "resume": "unsupported",
                        "failsafe": "unsupported",
                        "quit": "unsupported",
                        "snapshot": "supported"
                    }
                }
            })
        );
    }

    #[test]
    fn projects_latch_remote_host_and_large_revision_exactly() {
        let mut s = idle_stub();
        s.revision = Revision::new(u64::MAX);
        s.lifecycle = LifecyclePhase::Active;
        s.user_intent = UserIntent::SharingRequested;
        s.safety = SafetyState::Latched(Latch {
            cause: SafetyCause::PeerLinkFailure,
        });
        s.cleanup_unconfirmed = true;
        s.input_destination = InputDestination::Remote(RemoteTarget {
            host: HostLabel::new("Desk PC"),
            session: SessionId::new(7),
            generation: Generation::new(3),
        });
        s.readiness.enrollment = Prerequisite::Confirmed;
        s.capabilities.pause = Support::Supported;
        let value = serde_json::to_value(AgentStatus::from_result(Ok(s))).unwrap();
        let snap = &value["snapshot"];
        assert_eq!(snap["revision"], "18446744073709551615");
        assert_eq!(snap["lifecycle"], "active");
        assert_eq!(snap["userIntent"], "sharing_requested");
        assert_eq!(
            snap["safety"],
            json!({ "state": "latched", "cause": "peer_link_failure" })
        );
        assert_eq!(snap["cleanupUnconfirmed"], true);
        // Session/generation are not exposed to the webview.
        assert_eq!(
            snap["input"],
            json!({ "destination": "remote", "host": "Desk PC" })
        );
        assert_eq!(snap["readiness"]["enrollment"], "confirmed");
        assert_eq!(snap["capabilities"]["pause"], "supported");

        let mut local = idle_stub();
        local.input_destination = InputDestination::Local(LocalInput {});
        let value = serde_json::to_value(SnapshotView::from(&local)).unwrap();
        assert_eq!(value["input"], json!({ "destination": "local" }));
    }

    #[test]
    fn every_status_error_maps_to_a_distinct_payload_free_category() {
        let cases = [
            (StatusError::NotFound, "not_found"),
            (StatusError::PermissionDenied, "permission_denied"),
            (StatusError::TimedOut, "timed_out"),
            (StatusError::Incompatible, "incompatible"),
            (StatusError::InvalidReply, "invalid_reply"),
            (StatusError::Transport, "transport"),
        ];
        for (error, expected) in cases {
            let value = serde_json::to_value(AgentStatus::from_result(Err(error))).unwrap();
            assert_eq!(value, json!({ "kind": "unavailable", "error": expected }));
        }
    }

    #[test]
    fn only_the_agent_window_is_authorized() {
        assert!(authorized("utility-agent"));
        for label in ["main", "utility", "utility-agent ", "Utility-Agent", ""] {
            assert!(!authorized(label), "{label:?}");
        }
    }
}
