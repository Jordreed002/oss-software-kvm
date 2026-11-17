//! Typed wire messages for the local agent control API.
//!
//! Messages are tagged `snake_case` enums. Every variant wraps a plain struct
//! marked `deny_unknown_fields`, so unknown fields are rejected in every
//! position, including inside internally tagged enums. Fields are fixed and
//! enumerated; there are no free-form text fields, maps or lists except the
//! three bounded labels ([`ProtocolName`], [`HostLabel`], [`AgentVersion`]),
//! which the codecs validate against their per-field byte and character
//! limits.

use serde::{Deserialize, Deserializer, Serialize};

use crate::decimal::{CorrelationId, Generation, Revision, SessionId};
use crate::identity::{AgentVersion, HostLabel, InstanceId, ProtocolName};

/// Client-to-agent request. The first message must be [`ClientMessage::Hello`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Opening handshake carrying the protocol name and inclusive schema
    /// version range. Version agreement is reached only through
    /// [`crate::negotiate`]; a range this codec cannot speak still parses.
    Hello(HelloRequest),
    /// Read-only state request bound to an expected agent instance.
    SnapshotRequest(SnapshotRequest),
    /// Mutation command: set paused intent, close admission, reconcile held
    /// input and stop suppression. Keeps the agent/control endpoint
    /// available. A safety command: it carries no revision precondition, so
    /// a stale observation can never block a safety stop.
    Pause(SafetyRequest),
    /// Mutation command: prepare and open sharing after all prerequisites
    /// commit. Acknowledging queue entry does not mean sharing started. The
    /// only mutation carrying an expected revision; the owner rejects stale
    /// writes.
    Resume(ResumeRequest),
    /// Mutation command: latch safety independently of IPC/webview and
    /// perform bounded cleanup. Ordinary Resume cannot clear the latch. A
    /// safety command: no revision precondition.
    Failsafe(SafetyRequest),
    /// Mutation command: pause, cleanup, then stop agent and shell. A client
    /// timeout remains unconfirmed, never a successful quit. A safety
    /// command: no revision precondition.
    Quit(SafetyRequest),
}

/// Hello handshake payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloRequest {
    /// Protocol namespace; must equal [`crate::PROTOCOL_NAME`].
    pub protocol: ProtocolName,
    /// Inclusive lowest schema version the client supports.
    pub min_version: u32,
    /// Inclusive highest schema version the client supports.
    pub max_version: u32,
}

/// Snapshot request payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRequest {
    /// Agent instance the client believes it is talking to. The owner must
    /// match it before serving; a mismatch belongs to the owner's rejection
    /// behavior, not to this codec.
    pub instance: InstanceId,
    /// Client correlation identifier echoed in the reply.
    pub correlation_id: CorrelationId,
}

/// Safety command payload (Pause, Failsafe, Quit): instance-bound with no
/// revision precondition. `expected_revision` is deliberately not a field
/// here, so sending one is rejected as an unknown field: a stale observed
/// revision must never prevent a safety stop.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyRequest {
    /// Agent instance the command is bound to.
    pub instance: InstanceId,
    /// Client correlation identifier echoed in the reply.
    pub correlation_id: CorrelationId,
}

/// Resume payload: the only mutation carrying a revision precondition, so
/// the owner can reject writes made from a stale observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeRequest {
    /// Agent instance the command is bound to.
    pub instance: InstanceId,
    /// Client correlation identifier echoed in the reply.
    pub correlation_id: CorrelationId,
    /// Committed revision the client observed before issuing the command.
    pub expected_revision: Revision,
}

/// Agent-to-client reply.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Reply to [`ClientMessage::Hello`] with the server's supported range,
    /// the negotiated version and the agent's own instance identity.
    Hello(ServerHello),
    /// Reply to [`ClientMessage::SnapshotRequest`].
    Snapshot(SnapshotReply),
    /// Reply to a mutation command.
    CommandResult(CommandResultReply),
    /// Protocol-level error with a closed reason set. Payload-free: an
    /// error never echoes client text; it carries at most a correlation id
    /// and structured version bounds.
    Error(ProtocolError),
}

/// Server Hello payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerHello {
    /// Protocol namespace; must equal [`crate::PROTOCOL_NAME`].
    pub protocol: ProtocolName,
    /// Inclusive lowest schema version this server supports.
    pub min_version: u32,
    /// Inclusive highest schema version this server supports.
    pub max_version: u32,
    /// Version negotiated for this connection; must lie within both ranges.
    /// A client must also verify it against the range it offered; see
    /// [`crate::accept_server_hello`].
    pub negotiated_version: u32,
    /// The agent's instance identity. This is the bootstrap value: a client
    /// cannot form its first instance-bound [`SnapshotRequest`] until it has
    /// this id, and must bind every later request to it. Obtaining an
    /// expected instance from a filename, a nil placeholder or a PID is not
    /// a valid substitute.
    pub instance: InstanceId,
    /// Bounded, character-restricted agent build version, e.g. a semver or
    /// `git describe` label. A version label supplements native
    /// authentication; alone it proves nothing about code identity.
    pub agent_version: AgentVersion,
}

/// Structured protocol error. The reason set is closed and payload-free: no
/// variant carries client-supplied text, and the optional correlation id is
/// supplied by the owner when it decoded a correlated request. Owners omit
/// it for Hello-time failures and undecodable input. The codec accepts either
/// presence for any reason because it cannot infer connection history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    /// Correlation id of the decoded request this error answers, when one
    /// was decoded; absent for Hello-time errors and undecodable input.
    /// Exactly one spelling of absent exists: the field is omitted. `null`
    /// is not a synonym and is rejected.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_or_missing"
    )]
    pub correlation_id: Option<CorrelationId>,
    /// Closed reason. Unknown reasons are rejected at decode.
    pub reason: ProtocolErrorReason,
}

/// Deserializes a present field value, mapping only a genuinely absent field
/// to `None`. serde's plain `Option` handling would also accept `null` as
/// `None`; this contract keeps one spelling of "absent" — omission — so
/// `null` fails inside the value's own deserializer instead.
fn deserialize_present_or_missing<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Closed protocol-error reasons. Each variant name is its wire spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProtocolErrorReason {
    /// The Hello version ranges had no overlap; the server reports its own
    /// supported range so the client can diagnose without echoing anything.
    UnsupportedVersion(UnsupportedVersionRange),
    /// The Hello used an unknown protocol name.
    WrongProtocol(WrongProtocolReason),
    /// The input could not be decoded as this schema.
    MalformedRequest(MalformedRequestReason),
    /// A non-Hello request arrived before the handshake completed.
    HelloRequired(HelloRequiredReason),
    /// A decoded request named an instance other than this agent's.
    InstanceMismatch(InstanceMismatchReason),
    /// The decoded operation exists in the schema but is not offered by
    /// this agent.
    Unsupported(UnsupportedReason),
}

/// The server's inclusive supported range, reported with
/// [`ProtocolErrorReason::UnsupportedVersion`]. Bounds only; never client
/// text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedVersionRange {
    /// Inclusive lowest schema version the server supports.
    pub server_min: u32,
    /// Inclusive highest schema version the server supports.
    pub server_max: u32,
}

/// Declares a payload-free closed-reason marker. The struct form plus
/// `deny_unknown_fields` keeps a fieldless internally tagged variant from
/// silently dropping extra keys, matching the marker pattern used by
/// [`SafetyClear`] and the input destinations.
macro_rules! closed_reason_marker {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {}
    };
}

closed_reason_marker! {
    /// Marker: `wrong_protocol` carries no payload. Unknown keys next to the
    /// reason are rejected so extra data cannot ride along.
    WrongProtocolReason
}

closed_reason_marker! {
    /// Marker: `malformed_request` carries no payload; the offending bytes
    /// are never echoed. Unknown keys are rejected.
    MalformedRequestReason
}

closed_reason_marker! {
    /// Marker: `hello_required` carries no payload. Unknown keys are
    /// rejected.
    HelloRequiredReason
}

closed_reason_marker! {
    /// Marker: `instance_mismatch` carries no payload; which instance was
    /// wrong is a fact for the snapshot, not the error. Unknown keys are
    /// rejected.
    InstanceMismatchReason
}

closed_reason_marker! {
    /// Marker: `unsupported` carries no payload. Unknown keys are rejected.
    UnsupportedReason
}

/// Snapshot reply payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotReply {
    /// Correlation identifier of the answered snapshot request.
    pub correlation_id: CorrelationId,
    /// Confirmed agent state. Only facts the owner can confirm appear here.
    pub snapshot: AgentSnapshot,
}

/// Confirmed agent state, as defined by the replacement agent contract.
///
/// The snapshot reports dimensions separately: lifecycle, user intent,
/// safety latch, cleanup failure and input destination never fold into one
/// field. An idle stub reports [`LifecyclePhase::Idle`] with unconfirmed
/// prerequisites and [`InputDestination::Unknown`]; nothing here may present
/// unknown authority as confirmed local control.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSnapshot {
    /// Agent instance identity. A new instance invalidates old commands,
    /// subscriptions and authority.
    pub instance: InstanceId,
    /// Monotonic snapshot revision; observers resynchronize on gaps.
    pub revision: Revision,
    /// Session lifecycle, independent of safety and input destination.
    pub lifecycle: LifecyclePhase,
    /// The user's standing sharing intent, independent of authority: intent
    /// never establishes where input flows.
    pub user_intent: UserIntent,
    /// Safety latch state, visible in every phase including failed cleanup.
    pub safety: SafetyState,
    /// Whether cleanup failed and its outcome remains unconfirmed.
    pub cleanup_unconfirmed: bool,
    /// Where input is currently authorized to flow.
    pub input_destination: InputDestination,
    /// Per-prerequisite readiness. Unconfirmed is the honest default.
    pub readiness: Readiness,
    /// Explicitly negotiated capabilities; never inferred from command names.
    pub capabilities: Capabilities,
}

/// Session lifecycle. `Active` means capture/session preparation actually
/// completed; it is not claimed by an accepted Resume.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePhase {
    /// No session work in flight.
    Idle,
    /// Preparation requested; admission still closed.
    Preparing,
    /// Preparation completed and committed; admission may open.
    Active,
    /// Teardown in progress or awaiting confirmed completion.
    Draining,
    /// Lifecycle failed; recovery guidance distinguishes this from drained.
    Faulted,
}

/// The user's standing sharing intent. Intent is a request, not a fact about
/// authority: [`UserIntent::SharingRequested`] while unready, latched or
/// cleaning up still means admission is closed, and [`UserIntent::Paused`]
/// never claims by itself that input stopped flowing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserIntent {
    /// The user asked to pause; admission closed.
    Paused,
    /// The user asked to share; readiness and safety are reported
    /// separately and may still block.
    SharingRequested,
}

/// Safety latch state, separate from lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SafetyState {
    /// No condition latched.
    Clear(SafetyClear),
    /// Latched with a structured cause. Ordinary Resume cannot clear it.
    Latched(Latch),
}

/// Marker: safety clear carries no fields. Unknown keys are still rejected,
/// so a future variant cannot smuggle extra data through the clear spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyClear {}

/// Latch detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Latch {
    /// Structured cause of the latch.
    pub cause: SafetyCause,
}

/// Why safety latched. `Unspecified` is an explicit unknown, never a guess.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCause {
    /// Explicit Failsafe command.
    FailsafeCommand,
    /// Native permission loss reported by the platform.
    NativePermissionLoss,
    /// Peer or link failure.
    PeerLinkFailure,
    /// Latched for a cause the owner cannot confirm further.
    Unspecified,
}

/// Input authority destination. `Unknown` must never be displayed or treated
/// as confirmed local authority, even while the process is paused.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "destination", rename_all = "snake_case")]
pub enum InputDestination {
    /// Confirmed local authority.
    Local(LocalInput),
    /// Confirmed remote authority for an exact host/session/generation.
    Remote(RemoteTarget),
    /// Authority is moving between local and remote; neither is confirmed.
    Transitioning(TransitioningInput),
    /// Destination unconfirmed or unobservable.
    Unknown(UnknownInput),
}

/// Marker: confirmed local authority carries no fields. Unknown keys are
/// still rejected, so extra data cannot ride along with a `local` verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalInput {}

/// Marker: transitioning carries no fields; neither side is confirmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitioningInput {}

/// Marker: unknown destination carries no fields. Unknown keys are rejected
/// so unconfirmed authority cannot arrive with attached claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownInput {}

/// Exact remote authority target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteTarget {
    /// Remote host label, bounded by the codecs.
    pub host: HostLabel,
    /// Session identifier on the remote host.
    pub session: SessionId,
    /// Session generation; late events from a retired generation are inert.
    pub generation: Generation,
}

/// One readiness prerequisite. Only the owner can confirm a prerequisite;
/// `Unconfirmed` carries no implication about any other check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prerequisite {
    /// Confirmed by the owning agent.
    Confirmed,
    /// Not confirmed; the honest default, including for an idle stub.
    Unconfirmed,
}

/// Independent readiness blockers. No field implies any other.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Readiness {
    /// Committed configuration valid for session use.
    pub configuration: Prerequisite,
    /// Peer enrollment complete and trusted.
    pub enrollment: Prerequisite,
    /// Native capture/permissions granted.
    pub permissions: Prerequisite,
    /// Hardware/device inventories collected.
    pub inventory: Prerequisite,
    /// Peer authentication established.
    pub peer_authentication: Prerequisite,
    /// Input authority available for this host.
    pub input_authority: Prerequisite,
}

/// Whether one capability is supported. Unsupported mutations must not be
/// presented as working controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// The owner implements and offers this capability.
    Supported,
    /// Not offered in this build or state.
    Unsupported,
}

/// Negotiated capabilities. The initial idle-agent stub supports read-only
/// status only; no native capability is fabricated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// Pause mutation.
    pub pause: Support,
    /// Resume mutation.
    pub resume: Support,
    /// Failsafe mutation.
    pub failsafe: Support,
    /// Quit mutation.
    pub quit: Support,
    /// Snapshot requests.
    pub snapshot: Support,
}

/// Reply to a mutation command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandResultReply {
    /// Correlation identifier of the answered command.
    pub correlation_id: CorrelationId,
    /// Structured outcome. Absence of a reply (client timeout) is none of
    /// these; it is unconfirmed and must stay that way.
    pub outcome: CommandOutcome,
}

/// Mutation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommandOutcome {
    /// The command entered the owner's bounded queue. It has not been
    /// applied; do not report it as done.
    Accepted(AcceptedOutcome),
    /// The operation completed and produced this resulting committed
    /// revision.
    Applied(AppliedOutcome),
    /// The owner rejected the command with a structured reason.
    Rejected(RejectedOutcome),
}

/// Accepted marker. Acknowledged queue entry only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedOutcome {}

/// Applied detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedOutcome {
    /// Revision committed by applying the operation.
    pub revision: Revision,
}

/// Rejection detail. Rejections are owner decisions with structured causes;
/// the codec never invents one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedOutcome {
    /// Structured rejection reason.
    pub reason: RejectionReason,
}

/// Structured command rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Readiness prerequisites unmet.
    NotReady,
    /// Admission or bounded queue full or lifecycle busy.
    Busy,
    /// Safety latch active; ordinary Resume cannot clear it.
    SafetyLatched,
    /// Command bound to an instance other than the current agent instance.
    InstanceMismatch,
    /// Expected revision does not match the committed revision.
    RevisionMismatch,
    /// Capability not supported by this agent.
    Unsupported,
}
