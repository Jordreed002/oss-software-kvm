use crate::codec::FrameReadProgress;
use crate::connection_role::{
    ActiveConnection, ConnectionGeneration, ConnectionGenerationError, ConnectionGenerationGate,
    ConnectionRole, ConnectionRoleError, PendingConnection,
};
use crate::{
    AuthenticatedConnector, DevelopmentAddress, FrameReader, FrameWriter, HeartbeatAction,
    HeartbeatConfig, HeartbeatController, NetworkError, ObservableSessionStats, OutboundQueue,
    QueueConfig, ReconnectBackoff, ReconnectPolicy, SecurePeerStream, SessionStats, TrafficClass,
    TransportPeerIdentity,
};
use kvm_protocol::{
    decode_frame_for_version, encode_frame_for_version, encode_frame_for_version_into,
    AuthenticateV1, FrameHeader, HelloV1, MessageType, WireMessage, CURRENT_PROTOCOL_VERSION,
    FRAME_HEADER_LEN, MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION_V1,
};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior};

/// User-visible lifecycle of one persistent peer connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Degraded,
}

/// A peer admitted by the caller-owned authentication and allow-list policy.
///
/// The fields are intentionally private and there is no public constructor.
/// Receiving a `Hello` or `Authenticate` frame is not sufficient to create
/// this token; the session creates it only after [`SessionAdmission`] accepts
/// the exchange on a [`SecurePeerStream`].
#[derive(Clone, PartialEq)]
pub struct AdmittedPeer {
    transport_identity: TransportPeerIdentity,
    // The two hellos are immutable after admission and each carry two `String`s
    // (`host_name`, `daemon_version`). Wrapping them in `Arc` makes cloning an
    // `AdmittedPeer` — which happens for every inbound `PeerEvent::Message` — a
    // pair of refcount bumps instead of four heap allocations.
    local_hello: Arc<HelloV1>,
    remote_hello: Arc<HelloV1>,
    selected_protocol_version: u16,
    session_id: [u8; 32],
}

impl std::fmt::Debug for AdmittedPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdmittedPeer([REDACTED])")
    }
}

impl AdmittedPeer {
    pub const fn transport_identity(&self) -> &TransportPeerIdentity {
        &self.transport_identity
    }

    pub fn hello(&self) -> &HelloV1 {
        &self.remote_hello
    }

    pub fn local_hello(&self) -> &HelloV1 {
        &self.local_hello
    }

    /// Exact framing version authenticated for this admitted connection.
    #[must_use]
    pub const fn selected_protocol_version(&self) -> u16 {
        self.selected_protocol_version
    }

    /// Whether this exact admitted session can carry confirmed release proof.
    #[must_use]
    pub const fn supports_release_proof(&self) -> bool {
        kvm_protocol::supports_release_proof(self.selected_protocol_version)
    }

    /// Opaque exporter-derived binding for this exact admitted transport.
    ///
    /// It may be retained with a cleanup obligation after this generation
    /// closes, but is deliberately omitted from all debug output.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
}

/// Exact immutable values covered by both authentication proof operations.
#[derive(Clone, PartialEq)]
pub struct HandshakeTranscript {
    local_hello: HelloV1,
    remote_hello: HelloV1,
    transport_identity: TransportPeerIdentity,
    local_exporter_proof: [u8; 32],
    remote_exporter_proof: [u8; 32],
    selected_protocol_version: u16,
    session_id: [u8; 32],
}

impl std::fmt::Debug for HandshakeTranscript {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HandshakeTranscript([REDACTED])")
    }
}

impl HandshakeTranscript {
    pub const fn local_hello(&self) -> &HelloV1 {
        &self.local_hello
    }

    pub const fn remote_hello(&self) -> &HelloV1 {
        &self.remote_hello
    }

    pub const fn transport_identity(&self) -> &TransportPeerIdentity {
        &self.transport_identity
    }

    /// Highest mutually advertised protocol version bound into both proofs.
    #[must_use]
    pub const fn selected_protocol_version(&self) -> u16 {
        self.selected_protocol_version
    }

    /// Returns the direction-bound proof this endpoint may send in its
    /// application authentication message.
    #[must_use]
    pub const fn local_exporter_proof(&self) -> [u8; 32] {
        self.local_exporter_proof
    }

    /// Verifies the remote endpoint's direction-bound proof without exposing
    /// the locally derived expected value.
    #[must_use]
    pub fn verify_remote_exporter_proof(&self, proof: &[u8]) -> bool {
        proof.len() == self.remote_exporter_proof.len()
            && bool::from(proof.ct_eq(self.remote_exporter_proof.as_slice()))
    }
}

/// Deliberately coarse admission failure that cannot accidentally expose
/// credential material in logs.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AdmissionError {
    #[error("peer admission was rejected")]
    Rejected,
    #[error("peer admission service is unavailable")]
    Unavailable,
}

/// Caller-owned application handshake and admission boundary.
///
/// Implementations should delegate proof verification and allow-list policy to
/// `kvm-security`. This crate only sequences the exchange and gates traffic.
pub trait SessionAdmission: Send + Sync {
    /// Creates the local Hello for this connection. Implementations must use a
    /// fresh cryptographically random nonce on every call.
    ///
    /// # Errors
    ///
    /// Returns an error when fresh nonce generation or local identity loading
    /// is unavailable.
    fn local_hello(&self) -> Result<HelloV1, AdmissionError>;

    /// Builds the local channel-bound authentication response.
    ///
    /// # Errors
    ///
    /// Returns an error when a response cannot safely be created over the
    /// exact local hello, remote hello, and transport identity transcript.
    fn authentication_message(
        &self,
        transcript: &HandshakeTranscript,
    ) -> Result<AuthenticateV1, AdmissionError>;

    /// Verifies the peer proof and applies the paired-peer admission policy.
    ///
    /// # Errors
    ///
    /// Returns an error unless the proof covers that same transcript, is
    /// channel-bound, and the transport identity is authorized for input.
    fn admit(
        &self,
        transcript: &HandshakeTranscript,
        authentication: &AuthenticateV1,
    ) -> Result<(), AdmissionError>;
}

/// Events produced by the persistent peer task.
#[derive(Clone, PartialEq)]
pub enum PeerEvent {
    StateChanged(ConnectionState),
    Admitted(AdmittedPeer),
    Message {
        peer: AdmittedPeer,
        message: WireMessage,
    },
    Disconnected {
        reason: DisconnectReason,
        undelivered: UndeliveredTraffic,
        /// Cumulative outbound-queue diagnostics (§23 coalescing, §35 drops)
        /// captured from the session's queue at disconnect time, so the burst
        /// pressure that preceded the failure is observable by the consumer.
        stats: SessionStats,
    },
    ReconnectScheduled(Duration),
}

impl std::fmt::Debug for PeerEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateChanged(state) => {
                formatter.debug_tuple("StateChanged").field(state).finish()
            }
            Self::Admitted(_) => formatter
                .debug_struct("Admitted")
                .field("peer", &"[REDACTED]")
                .finish(),
            Self::Message { message, .. } => formatter
                .debug_struct("Message")
                .field("message_type", &message.message_type())
                .finish_non_exhaustive(),
            Self::Disconnected { reason, .. } => formatter
                .debug_struct("Disconnected")
                .field("reason", reason)
                .field("undelivered", &"[REDACTED]")
                .finish(),
            Self::ReconnectScheduled(delay) => formatter
                .debug_tuple("ReconnectScheduled")
                .field(delay)
                .finish(),
        }
    }
}

enum GenerationBoundPeerEventState {
    Pending,
    Admission(PendingConnection),
    Active,
    Cancelled(PendingConnection),
}

/// A network-minted event bound to one affine connection generation.
///
/// The private state prevents downstream code from attaching a cloned
/// [`AdmittedPeer`] to a newer generation. Apply the event to its exact
/// [`ConnectionGenerationGate`] before passing it to daemon coordination.
pub struct GenerationBoundPeerEvent {
    generation: ConnectionGeneration,
    state: GenerationBoundPeerEventState,
    event: Option<PeerEvent>,
}

impl std::fmt::Debug for GenerationBoundPeerEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenerationBoundPeerEvent")
            .field("classification", &self.classification())
            .field("event", &self.event)
            .finish_non_exhaustive()
    }
}

/// Public, payload-free classification for a generation-bound event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationBoundEventClassification {
    PendingIgnored,
    Activated,
    Active,
    Cancelled,
}

impl GenerationBoundPeerEvent {
    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    #[must_use]
    pub const fn classification(&self) -> GenerationBoundEventClassification {
        match self.state {
            GenerationBoundPeerEventState::Pending => {
                GenerationBoundEventClassification::PendingIgnored
            }
            GenerationBoundPeerEventState::Admission(_) => {
                GenerationBoundEventClassification::Activated
            }
            GenerationBoundPeerEventState::Active => GenerationBoundEventClassification::Active,
            GenerationBoundPeerEventState::Cancelled(_) => {
                GenerationBoundEventClassification::Cancelled
            }
        }
    }

    /// Applies the embedded affine capability to the exact generation gate.
    ///
    /// # Errors
    ///
    /// Returns a stale/duplicate generation error if this event did not come
    /// from the gate supplied by the caller.
    pub fn apply(
        self,
        gate: &mut ConnectionGenerationGate,
    ) -> Result<AppliedGenerationEvent, ConnectionGenerationError> {
        let Self {
            generation,
            state,
            event,
        } = self;
        let state = match state {
            GenerationBoundPeerEventState::Pending => AppliedGenerationEventState::PendingIgnored,
            GenerationBoundPeerEventState::Admission(pending) => {
                AppliedGenerationEventState::Activated(gate.activate(pending)?)
            }
            GenerationBoundPeerEventState::Active => {
                gate.validate_active_generation(generation)?;
                AppliedGenerationEventState::Active
            }
            GenerationBoundPeerEventState::Cancelled(pending) => {
                gate.cancel_pending(pending)?;
                AppliedGenerationEventState::Cancelled
            }
        };
        Ok(AppliedGenerationEvent {
            generation,
            state,
            event,
        })
    }
}

enum AppliedGenerationEventState {
    PendingIgnored,
    Activated(ActiveConnection),
    Active,
    Cancelled,
}

/// Successfully gate-validated event accepted by daemon supervision.
///
/// Construction is private; callers cannot re-tag an event or admitted peer.
pub struct AppliedGenerationEvent {
    generation: ConnectionGeneration,
    state: AppliedGenerationEventState,
    event: Option<PeerEvent>,
}

impl AppliedGenerationEvent {
    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    #[must_use]
    pub const fn classification(&self) -> GenerationBoundEventClassification {
        match self.state {
            AppliedGenerationEventState::PendingIgnored => {
                GenerationBoundEventClassification::PendingIgnored
            }
            AppliedGenerationEventState::Activated(_) => {
                GenerationBoundEventClassification::Activated
            }
            AppliedGenerationEventState::Active => GenerationBoundEventClassification::Active,
            AppliedGenerationEventState::Cancelled => GenerationBoundEventClassification::Cancelled,
        }
    }

    #[must_use]
    pub const fn event(&self) -> Option<&PeerEvent> {
        self.event.as_ref()
    }

    /// Consumes an activation event and returns the affine active token and
    /// the actual network-minted admitted event.
    pub fn into_activation(self) -> Option<(ActiveConnection, PeerEvent)> {
        match (self.state, self.event) {
            (AppliedGenerationEventState::Activated(active), Some(event)) => Some((active, event)),
            _ => None,
        }
    }

    /// Consumes a non-activation event after its classification was checked.
    #[must_use]
    pub fn into_event(self) -> Option<PeerEvent> {
        match self.state {
            AppliedGenerationEventState::Activated(_) => None,
            _ => self.event,
        }
    }
}

impl std::fmt::Debug for AppliedGenerationEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppliedGenerationEvent")
            .field("classification", &self.classification())
            .field("event", &self.event)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectReason {
    ConnectFailed(std::io::ErrorKind),
    RemoteClosed,
    TransportIo(std::io::ErrorKind),
    InvalidFrame,
    AdmissionRejected,
    AdmissionUnavailable,
    AdmissionTimeout,
    IdentityMismatch,
    ProtocolViolation,
    RepeatedHandshake,
    HeartbeatInvalid,
    HeartbeatTimeout,
    QueueFull(TrafficClass),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct UndeliveredMessage {
    pub message_type: MessageType,
    pub traffic_class: TrafficClass,
    pub sequence: Option<u64>,
    pub partially_sent: bool,
}

impl std::fmt::Debug for UndeliveredMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UndeliveredMessage")
            .field("message_type", &self.message_type)
            .field("traffic_class", &self.traffic_class)
            .field("partially_sent", &self.partially_sent)
            .finish_non_exhaustive()
    }
}

/// Redacted traffic inventory that the daemon must reconcile after a failed
/// session. Messages are deliberately not replayed on a new connection.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct UndeliveredTraffic {
    pub messages: Vec<UndeliveredMessage>,
    pub partial_inbound_bytes: usize,
    pub requires_input_reconciliation: bool,
}

impl std::fmt::Debug for UndeliveredTraffic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UndeliveredTraffic")
            .field("message_count", &self.messages.len())
            .field("has_partial_inbound", &(self.partial_inbound_bytes > 0))
            .field(
                "requires_input_reconciliation",
                &self.requires_input_reconciliation,
            )
            .finish()
    }
}

impl UndeliveredTraffic {
    fn record(&mut self, message: &WireMessage, partially_sent: bool) {
        let metadata = undelivered_metadata(message, partially_sent);
        self.requires_input_reconciliation |= metadata.traffic_class == TrafficClass::Input;
        self.messages.push(metadata);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentPeerConfig {
    pub queue: QueueConfig,
    pub heartbeat: HeartbeatConfig,
    pub reconnect: ReconnectPolicy,
    pub outbound_channel_capacity: usize,
    pub event_channel_capacity: usize,
    pub admission_timeout: Duration,
    pub shutdown_timeout: Duration,
    /// Backoff resets only after this admitted duration, while healthy, with
    /// at least one validated pong.
    pub healthy_reset_after: Duration,
}

impl Default for PersistentPeerConfig {
    fn default() -> Self {
        Self {
            queue: QueueConfig::default(),
            heartbeat: HeartbeatConfig::default(),
            reconnect: ReconnectPolicy::default(),
            outbound_channel_capacity: 1_024,
            event_channel_capacity: 256,
            admission_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_millis(250),
            healthy_reset_after: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PeerConfigError {
    #[error("{0}")]
    Invalid(&'static str),
}

/// Injected reconnect jitter source. Production composition should provide a
/// seeded random implementation; tests can provide a deterministic one.
pub trait ReconnectJitter: Send {
    fn apply(&mut self, base: Duration, attempt: u32) -> Duration;
}

/// Deterministic development policy that leaves reconnect delays unchanged.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoReconnectJitter;

impl ReconnectJitter for NoReconnectJitter {
    fn apply(&mut self, base: Duration, _attempt: u32) -> Duration {
        base
    }
}

impl PersistentPeerConfig {
    /// Validates all bounded resources and timing relationships.
    ///
    /// # Errors
    ///
    /// Returns the first invalid queue, heartbeat, reconnect, channel, or
    /// timeout relationship.
    pub fn validate(&self) -> Result<(), PeerConfigError> {
        if self.queue.validate().is_err() {
            return Err(PeerConfigError::Invalid(
                "all queue capacities and maximum input burst must be positive",
            ));
        }
        if self.heartbeat.validate().is_err() {
            return Err(PeerConfigError::Invalid(
                "invalid heartbeat intervals or outstanding-ping bound",
            ));
        }
        if self.reconnect.validate().is_err() {
            return Err(PeerConfigError::Invalid("invalid reconnect policy"));
        }
        if self.outbound_channel_capacity == 0 || self.event_channel_capacity == 0 {
            return Err(PeerConfigError::Invalid(
                "outbound and event channel capacities must be positive",
            ));
        }
        if self.admission_timeout == Duration::ZERO
            || self.shutdown_timeout == Duration::ZERO
            || self.healthy_reset_after == Duration::ZERO
        {
            return Err(PeerConfigError::Invalid(
                "admission, shutdown, and healthy-reset timeouts must be positive",
            ));
        }
        Ok(())
    }
}

/// Non-blocking handle for submitting outbound protocol messages.
#[derive(Clone, Debug)]
pub struct PeerSender {
    sender: mpsc::Sender<WireMessage>,
    observable_stats: Arc<ObservableSessionStats>,
}

impl PeerSender {
    /// Submits a message to the bounded persistent-session channel.
    ///
    /// # Errors
    ///
    /// Returns the original message when the channel is full or closed.
    pub fn try_send(&self, message: WireMessage) -> Result<(), OutboundSendError> {
        self.sender.try_send(message).map_err(|error| match error {
            mpsc::error::TrySendError::Full(message) => {
                self.observable_stats
                    .record_channel_rejection(TrafficClass::for_message(&message));
                OutboundSendError::Full(Box::new(message))
            }
            mpsc::error::TrySendError::Closed(message) => {
                OutboundSendError::Closed(Box::new(message))
            }
        })
    }
}

#[derive(Error)]
pub enum OutboundSendError {
    #[error("persistent peer outbound channel is full")]
    Full(Box<WireMessage>),
    #[error("persistent peer outbound channel is closed")]
    Closed(Box<WireMessage>),
}

impl std::fmt::Debug for OutboundSendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (state, message) = match self {
            Self::Full(message) => ("Full", message.as_ref()),
            Self::Closed(message) => ("Closed", message.as_ref()),
        };
        formatter
            .debug_struct("OutboundSendError")
            .field("state", &state)
            .field("message_type", &message.message_type())
            .finish_non_exhaustive()
    }
}

impl OutboundSendError {
    pub fn into_message(self) -> WireMessage {
        match self {
            Self::Full(message) | Self::Closed(message) => *message,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEnd {
    Shutdown,
    OutboundClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentExit {
    Shutdown,
    OutboundClosed,
}

#[derive(Error)]
pub enum SessionError {
    #[error(transparent)]
    Network(#[from] NetworkError),
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error("transport identity does not match the peer hello")]
    TransportIdentityMismatch,
    #[error("local authentication response does not match the local hello")]
    LocalIdentityMismatch,
    #[error("local and remote peer identities must be distinct")]
    PeerIdentityCollision,
    #[error("connection direction is not canonical for this peer pair")]
    NoncanonicalDirection,
    #[error("peers did not advertise a compatible protocol version")]
    NoCompatibleProtocolVersion,
    #[error("authenticated transport produced an invalid session binding")]
    InvalidSessionBinding,
    #[error("received {0:?} before peer admission")]
    PreAdmissionMessage(MessageType),
    #[error("received repeated handshake message {0:?} after admission")]
    RepeatedHandshake(MessageType),
    #[error("received {0:?} with an invalid sender or destination identity")]
    MessageIdentityMismatch(MessageType),
    #[error("heartbeat validation failed")]
    Heartbeat(String),
    #[error("peer heartbeat timed out")]
    HeartbeatTimeout,
    #[error("peer did not complete admission before the deadline")]
    AdmissionTimeout,
    #[error("outbound {class:?} lane reached capacity {capacity}")]
    QueueFull {
        class: TrafficClass,
        capacity: usize,
        undelivered: UndeliveredMessage,
    },
    #[error("peer event consumer is not keeping up")]
    EventChannelFull,
    #[error("peer event consumer has closed")]
    EventChannelClosed,
}

impl std::fmt::Debug for SessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let category = match self {
            Self::Network(_) => "Network",
            Self::Admission(_) => "Admission",
            Self::TransportIdentityMismatch => "TransportIdentityMismatch",
            Self::LocalIdentityMismatch => "LocalIdentityMismatch",
            Self::PeerIdentityCollision => "PeerIdentityCollision",
            Self::NoncanonicalDirection => "NoncanonicalDirection",
            Self::NoCompatibleProtocolVersion => "NoCompatibleProtocolVersion",
            Self::InvalidSessionBinding => "InvalidSessionBinding",
            Self::PreAdmissionMessage(_) => "PreAdmissionMessage",
            Self::RepeatedHandshake(_) => "RepeatedHandshake",
            Self::MessageIdentityMismatch(_) => "MessageIdentityMismatch",
            Self::Heartbeat(_) => "Heartbeat",
            Self::HeartbeatTimeout => "HeartbeatTimeout",
            Self::AdmissionTimeout => "AdmissionTimeout",
            Self::QueueFull { .. } => "QueueFull",
            Self::EventChannelFull => "EventChannelFull",
            Self::EventChannelClosed => "EventChannelClosed",
        };
        formatter.write_str("SessionError::")?;
        formatter.write_str(category)
    }
}

#[derive(Debug)]
struct SessionFailure {
    error: SessionError,
    undelivered: UndeliveredTraffic,
    reset_backoff: bool,
    /// Cumulative outbound-queue diagnostics (§23 coalescing, §35 drops)
    /// captured from the queue at failure time, so the burst pressure that
    /// preceded the disconnect is observable rather than discarded with the
    /// private queue. `default()` before admission — the queue did not exist yet.
    stats: SessionStats,
}

impl SessionFailure {
    fn before_admission(error: SessionError) -> Self {
        Self {
            error,
            undelivered: UndeliveredTraffic::default(),
            reset_backoff: false,
            stats: SessionStats::default(),
        }
    }
}

/// Upper bound on one outbound write batch. A batch coalesces every frame the
/// queue currently holds — up to these caps — into a single progressive write
/// and a single TLS flush, so a high-rate input burst (high-poll mice, 175 Hz
/// pointer motion) crosses the transport as a few large writes instead of one
/// write + one flush per frame. The first frame is always included even when it
/// alone exceeds the byte cap, so a lone large frame never stalls.
const OUTBOUND_BATCH_MAX_FRAMES: usize = 64;
const OUTBOUND_BATCH_MAX_BYTES: usize = 65_536;
/// Conservative upper bound on one encoded input frame (8-byte header plus a
/// `PointerMove` payload: two varint scalars, two 16-byte identifiers, and two
/// `f64` deltas). Used only to pre-size the batch buffer so a burst encodes
/// into a single allocation instead of growing the `Vec` frame-by-frame.
const OUTBOUND_BATCH_FRAME_BYTES_ESTIMATE: usize = 96;

#[derive(Debug, Default)]
struct PendingFrame {
    bytes: Vec<u8>,
    committed: usize,
    /// The batched frames in send order, each paired with its exclusive end
    /// byte offset within `bytes`, so failure accounting can mark each message
    /// fully sent, partially sent, or not yet sent relative to `committed`.
    frames: Vec<(UndeliveredMessage, usize)>,
    /// The messages popped from the queue for this batch, in pop order.
    /// Retained across batches (cleared, not reallocated) so a failure mid-batch
    /// can hand every already-popped-but-not-yet-returned message back to the
    /// queue via `unpop`. Mirrors the reuse strategy of `bytes`/`frames`.
    popped: Vec<WireMessage>,
}

/// One-shot direction-neutral owner for an already established secure stream.
///
/// This is the accepted-session entry point. It creates fresh bounded channels
/// for exactly one connection generation, performs exporter-bound admission,
/// and never carries queued or partially written traffic into another stream.
pub struct SecurePeerSession<A> {
    admission: A,
    config: PersistentPeerConfig,
    outbound: mpsc::Receiver<WireMessage>,
    events: mpsc::Sender<PeerEvent>,
    observable_stats: Arc<ObservableSessionStats>,
}

/// One-shot session whose events are cryptographically and affinely bound to
/// a pending connection generation.
pub struct GenerationBoundPeerSession<A> {
    admission: A,
    config: PersistentPeerConfig,
    outbound: mpsc::Receiver<WireMessage>,
    internal_events: mpsc::Sender<PeerEvent>,
    internal_event_receiver: mpsc::Receiver<PeerEvent>,
    bound_events: mpsc::Sender<GenerationBoundPeerEvent>,
    pending: PendingConnection,
    observable_stats: Arc<ObservableSessionStats>,
}

impl<A> std::fmt::Debug for GenerationBoundPeerSession<A> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenerationBoundPeerSession")
            .field("config", &self.config)
            .field("generation", &self.pending.generation())
            .field("admission", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Terminal failure from a generation-bound session.
///
/// If terminal delivery encountered local backpressure, the unsent opaque
/// cancellation or active-disconnection event is returned here so the owner
/// can still reconcile the exact gate capability.
pub struct GenerationBoundSessionError {
    error: SessionError,
    terminal_event: Option<Box<GenerationBoundPeerEvent>>,
}

impl GenerationBoundSessionError {
    #[must_use]
    pub const fn error(&self) -> &SessionError {
        &self.error
    }

    #[must_use]
    pub fn into_terminal_event(self) -> Option<GenerationBoundPeerEvent> {
        self.terminal_event.map(|event| *event)
    }
}

impl std::fmt::Debug for GenerationBoundSessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenerationBoundSessionError")
            .field("error", &self.error)
            .field("has_terminal_event", &self.terminal_event.is_some())
            .finish()
    }
}

impl std::fmt::Display for GenerationBoundSessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for GenerationBoundSessionError {}

/// Recoverable construction failure for a generation-bound session.
pub struct GenerationBoundSessionBuildError {
    error: PeerConfigError,
    cancellation: Box<GenerationBoundPeerEvent>,
}

impl GenerationBoundSessionBuildError {
    #[must_use]
    pub const fn error(&self) -> PeerConfigError {
        self.error
    }

    #[must_use]
    pub fn into_cancellation(self) -> GenerationBoundPeerEvent {
        *self.cancellation
    }
}

impl std::fmt::Debug for GenerationBoundSessionBuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenerationBoundSessionBuildError")
            .field("error", &self.error)
            .field("generation", &self.cancellation.generation())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for GenerationBoundSessionBuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for GenerationBoundSessionBuildError {}

impl<A> std::fmt::Debug for SecurePeerSession<A> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecurePeerSession")
            .field("config", &self.config)
            .field("admission", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<A: SessionAdmission> SecurePeerSession<A> {
    /// Creates a one-shot secure session plus its bounded outbound and event
    /// channels.
    ///
    /// # Errors
    ///
    /// Returns an error for any invalid bound or timing relationship.
    pub fn new(
        admission: A,
        config: PersistentPeerConfig,
    ) -> Result<(Self, PeerSender, mpsc::Receiver<PeerEvent>), PeerConfigError> {
        config.validate()?;
        let (outbound_sender, outbound) = mpsc::channel(config.outbound_channel_capacity);
        let (events, event_receiver) = mpsc::channel(config.event_channel_capacity);
        let observable_stats = Arc::new(ObservableSessionStats::default());
        Ok((
            Self {
                admission,
                config,
                outbound,
                events,
                observable_stats: Arc::clone(&observable_stats),
            },
            PeerSender {
                sender: outbound_sender,
                observable_stats,
            },
            event_receiver,
        ))
    }

    /// Returns a shared handle to this session's live outbound-queue diagnostics
    /// (§23 coalescing, §35 drops), published on the heartbeat tick. Clone it
    /// before [`run`](Self::run) consumes the session so the diagnostics surface
    /// can read cumulative counters while the session streams.
    #[must_use]
    pub fn observable_stats(&self) -> Arc<ObservableSessionStats> {
        Arc::clone(&self.observable_stats)
    }

    /// Runs exporter-bound admission and application transport over one sealed
    /// inbound or outbound stream.
    ///
    /// On connection failure this method emits the same redacted disconnected
    /// inventory as [`PersistentPeer`], drains this generation's outbound
    /// channel, and returns without reconnecting.
    ///
    /// # Errors
    ///
    /// Returns the session failure or an event-channel backpressure failure.
    pub async fn run<S: SecurePeerStream>(
        mut self,
        stream: S,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<SessionEnd, SessionError> {
        match run_session_with_stats(
            stream,
            &self.admission,
            self.config,
            &mut self.outbound,
            &self.events,
            &mut shutdown,
            Some(self.observable_stats.as_ref()),
        )
        .await
        {
            Ok(end) => Ok(end),
            Err(failure) => {
                if matches!(
                    failure.error,
                    SessionError::EventChannelFull | SessionError::EventChannelClosed
                ) {
                    return Err(failure.error);
                }
                let SessionFailure {
                    error,
                    mut undelivered,
                    stats,
                    ..
                } = failure;
                drain_outbound(&mut self.outbound, &mut undelivered);
                let reason = disconnect_reason(&error);
                send_event(
                    &self.events,
                    PeerEvent::StateChanged(ConnectionState::Disconnected),
                )?;
                send_event(
                    &self.events,
                    PeerEvent::Disconnected {
                        reason,
                        undelivered,
                        stats,
                    },
                )?;
                Err(error)
            }
        }
    }
}

impl<A: SessionAdmission> GenerationBoundPeerSession<A> {
    /// Creates a one-shot session and consumes the exact pending generation
    /// capability that will be attached to its admission or cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid resource or timing bounds.
    pub fn new(
        admission: A,
        config: PersistentPeerConfig,
        pending: PendingConnection,
    ) -> Result<
        (Self, PeerSender, mpsc::Receiver<GenerationBoundPeerEvent>),
        GenerationBoundSessionBuildError,
    > {
        if let Err(error) = config.validate() {
            let generation = pending.generation();
            return Err(GenerationBoundSessionBuildError {
                error,
                cancellation: Box::new(cancelled_event(generation, pending)),
            });
        }
        let (outbound_sender, outbound) = mpsc::channel(config.outbound_channel_capacity);
        let (internal_events, internal_event_receiver) =
            mpsc::channel(config.event_channel_capacity.max(4));
        let (bound_events, bound_event_receiver) = mpsc::channel(config.event_channel_capacity);
        let observable_stats = Arc::new(ObservableSessionStats::default());
        Ok((
            Self {
                admission,
                config,
                outbound,
                internal_events,
                internal_event_receiver,
                bound_events,
                pending,
                observable_stats: Arc::clone(&observable_stats),
            },
            PeerSender {
                sender: outbound_sender,
                observable_stats,
            },
            bound_event_receiver,
        ))
    }

    /// Returns a shared handle to this session's live outbound-queue diagnostics
    /// (§23 coalescing, §35 drops), published on the heartbeat tick. Clone it
    /// before [`run`](Self::run) consumes the session so the diagnostics surface
    /// can read cumulative counters while the session streams.
    #[must_use]
    pub fn observable_stats(&self) -> Arc<ObservableSessionStats> {
        Arc::clone(&self.observable_stats)
    }

    /// Runs exactly one sealed stream and emits only network-minted,
    /// generation-bound events.
    ///
    /// # Errors
    ///
    /// Returns the underlying session error. Before admission, an unsent
    /// terminal capability is retained in the error if event delivery is
    /// locally unavailable. Every admitted normal end also emits an active
    /// disconnection event before this method returns.
    // This is intentionally one linear state machine: splitting the admission
    // token relay from session termination makes capability loss easier.
    #[allow(clippy::too_many_lines)]
    pub async fn run<S: SecurePeerStream>(
        self,
        stream: S,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<SessionEnd, GenerationBoundSessionError> {
        let Self {
            admission,
            config,
            mut outbound,
            internal_events,
            mut internal_event_receiver,
            bound_events,
            pending,
            observable_stats,
        } = self;
        let generation = pending.generation();
        let mut pending = Some(pending);
        let mut admitted = false;
        let result = {
            let session = run_session_with_stats(
                stream,
                &admission,
                config,
                &mut outbound,
                &internal_events,
                &mut shutdown,
                Some(observable_stats.as_ref()),
            );
            tokio::pin!(session);

            loop {
                tokio::select! {
                    biased;
                    result = &mut session => break result,
                    event = internal_event_receiver.recv() => {
                        if let Some(event) = event {
                            let bound = bind_generation_event(
                                generation,
                                event,
                                &mut pending,
                                &mut admitted,
                            ).map_err(|error| GenerationBoundSessionError {
                                error,
                                terminal_event: pending
                                    .take()
                                    .map(|value| Box::new(cancelled_event(generation, value))),
                            })?;
                            if let Some(bound) = bound {
                                if let Err(error) = try_send_bound_event(&bound_events, bound) {
                                    reclaim_pending_event(error, &mut pending, &mut admitted);
                                    return Err(bound_session_delivery_error(pending, generation, admitted));
                                }
                            }
                        }
                    }
                }
            }
        };

        while let Ok(event) = internal_event_receiver.try_recv() {
            let bound = bind_generation_event(generation, event, &mut pending, &mut admitted)
                .map_err(|error| GenerationBoundSessionError {
                    error,
                    terminal_event: pending
                        .take()
                        .map(|value| Box::new(cancelled_event(generation, value))),
                })?;
            if let Some(bound) = bound {
                if let Err(error) = try_send_bound_event(&bound_events, bound) {
                    reclaim_pending_event(error, &mut pending, &mut admitted);
                    return Err(bound_session_delivery_error(pending, generation, admitted));
                }
            }
        }

        match result {
            Ok(end) => {
                if let Some(pending) = pending {
                    let cancellation = cancelled_event(generation, pending);
                    if let Err(cancellation) = try_send_bound_event(&bound_events, cancellation) {
                        return Err(GenerationBoundSessionError {
                            error: SessionError::EventChannelFull,
                            terminal_event: Some(cancellation),
                        });
                    }
                } else if admitted {
                    let terminal = active_termination_event(generation);
                    if let Err(terminal) = try_send_bound_event(&bound_events, terminal) {
                        return Err(GenerationBoundSessionError {
                            error: SessionError::EventChannelFull,
                            terminal_event: Some(terminal),
                        });
                    }
                }
                Ok(end)
            }
            Err(failure) => {
                let SessionFailure {
                    error,
                    mut undelivered,
                    stats,
                    ..
                } = failure;
                drain_outbound(&mut outbound, &mut undelivered);
                if matches!(
                    error,
                    SessionError::EventChannelFull | SessionError::EventChannelClosed
                ) {
                    return Err(GenerationBoundSessionError {
                        error,
                        terminal_event: pending
                            .map(|value| Box::new(cancelled_event(generation, value)))
                            .or_else(|| {
                                admitted.then(|| Box::new(active_termination_event(generation)))
                            }),
                    });
                }

                if admitted {
                    let state = GenerationBoundPeerEvent {
                        generation,
                        state: GenerationBoundPeerEventState::Active,
                        event: Some(PeerEvent::StateChanged(ConnectionState::Disconnected)),
                    };
                    if let Err(terminal) = try_send_bound_event(&bound_events, state) {
                        return Err(GenerationBoundSessionError {
                            error: SessionError::EventChannelFull,
                            terminal_event: recover_terminal_event(terminal, generation, true),
                        });
                    }
                }

                let event = PeerEvent::Disconnected {
                    reason: disconnect_reason(&error),
                    undelivered,
                    stats,
                };
                let bound =
                    bind_terminal_generation_event(generation, event, &mut pending, admitted)?;
                if let Err(terminal) = try_send_bound_event(&bound_events, bound) {
                    return Err(GenerationBoundSessionError {
                        error: SessionError::EventChannelFull,
                        terminal_event: recover_terminal_event(terminal, generation, admitted),
                    });
                }
                Err(GenerationBoundSessionError {
                    error,
                    terminal_event: None,
                })
            }
        }
    }
}

fn bind_generation_event(
    generation: ConnectionGeneration,
    event: PeerEvent,
    pending: &mut Option<PendingConnection>,
    admitted: &mut bool,
) -> Result<Option<GenerationBoundPeerEvent>, SessionError> {
    let state = if matches!(event, PeerEvent::Admitted(_)) && !*admitted {
        *admitted = true;
        let capability = pending.take().ok_or(SessionError::EventChannelClosed)?;
        GenerationBoundPeerEventState::Admission(capability)
    } else if *admitted {
        GenerationBoundPeerEventState::Active
    } else {
        // Pre-admission lifecycle state is deliberately suppressed. It cannot
        // reach the coordinator and this reserves external queue capacity for
        // the actual admission capability or terminal cancellation.
        return Ok(None);
    };
    Ok(Some(GenerationBoundPeerEvent {
        generation,
        state,
        event: Some(event),
    }))
}

fn bind_terminal_generation_event(
    generation: ConnectionGeneration,
    event: PeerEvent,
    pending: &mut Option<PendingConnection>,
    admitted: bool,
) -> Result<GenerationBoundPeerEvent, GenerationBoundSessionError> {
    let state = if admitted {
        GenerationBoundPeerEventState::Active
    } else if matches!(event, PeerEvent::Disconnected { .. }) {
        let capability = pending.take().ok_or(GenerationBoundSessionError {
            error: SessionError::EventChannelClosed,
            terminal_event: None,
        })?;
        GenerationBoundPeerEventState::Cancelled(capability)
    } else {
        GenerationBoundPeerEventState::Pending
    };
    Ok(GenerationBoundPeerEvent {
        generation,
        state,
        event: Some(event),
    })
}

fn try_send_bound_event(
    sender: &mpsc::Sender<GenerationBoundPeerEvent>,
    event: GenerationBoundPeerEvent,
) -> Result<(), Box<GenerationBoundPeerEvent>> {
    sender.try_send(event).map_err(|error| match error {
        mpsc::error::TrySendError::Full(event) | mpsc::error::TrySendError::Closed(event) => {
            Box::new(event)
        }
    })
}

fn reclaim_pending_event(
    event: Box<GenerationBoundPeerEvent>,
    pending: &mut Option<PendingConnection>,
    admitted: &mut bool,
) {
    if let GenerationBoundPeerEventState::Admission(capability)
    | GenerationBoundPeerEventState::Cancelled(capability) = event.state
    {
        *pending = Some(capability);
        *admitted = false;
    }
}

fn recover_terminal_event(
    event: Box<GenerationBoundPeerEvent>,
    generation: ConnectionGeneration,
    admitted: bool,
) -> Option<Box<GenerationBoundPeerEvent>> {
    match event.state {
        GenerationBoundPeerEventState::Cancelled(pending)
        | GenerationBoundPeerEventState::Admission(pending) => {
            Some(Box::new(GenerationBoundPeerEvent {
                generation,
                state: GenerationBoundPeerEventState::Cancelled(pending),
                event: None,
            }))
        }
        GenerationBoundPeerEventState::Active if admitted => {
            Some(Box::new(active_termination_event(generation)))
        }
        GenerationBoundPeerEventState::Pending | GenerationBoundPeerEventState::Active => None,
    }
}

fn bound_session_delivery_error(
    pending: Option<PendingConnection>,
    generation: ConnectionGeneration,
    admitted: bool,
) -> GenerationBoundSessionError {
    GenerationBoundSessionError {
        error: SessionError::EventChannelFull,
        terminal_event: pending
            .map(|value| Box::new(cancelled_event(generation, value)))
            .or_else(|| admitted.then(|| Box::new(active_termination_event(generation)))),
    }
}

fn cancelled_event(
    generation: ConnectionGeneration,
    pending: PendingConnection,
) -> GenerationBoundPeerEvent {
    GenerationBoundPeerEvent {
        generation,
        state: GenerationBoundPeerEventState::Cancelled(pending),
        event: None,
    }
}

fn active_termination_event(generation: ConnectionGeneration) -> GenerationBoundPeerEvent {
    GenerationBoundPeerEvent {
        generation,
        state: GenerationBoundPeerEventState::Active,
        event: Some(PeerEvent::Disconnected {
            reason: DisconnectReason::TransportIo(std::io::ErrorKind::Other),
            undelivered: UndeliveredTraffic {
                requires_input_reconciliation: true,
                ..UndeliveredTraffic::default()
            },
            // No session queue existed (synthetic termination), so no diagnostics.
            stats: SessionStats::default(),
        }),
    }
}

enum FrameWriteProgress {
    Bytes(usize),
    Flushed,
}

impl PendingFrame {
    /// Encodes every frame currently held by `queue` — up to the batch caps —
    /// into `reusable`, one contiguous, cancellation-safe write buffer whose
    /// allocation is retained across batches. The returned frame's `frames` list
    /// is empty when the queue held nothing, so the caller does not spin on an
    /// empty batch.
    ///
    /// A frame that would push the batch past [`OUTBOUND_BATCH_MAX_BYTES`] is
    /// returned to the front of its lane via [`OutboundQueue::unpop`]; it leads
    /// the next batch.
    fn encode_batch(
        queue: &mut OutboundQueue,
        selected_protocol_version: u16,
        mut reusable: Self,
    ) -> Result<Self, SessionError> {
        // Reuse the retained allocations (cleared in place) instead of
        // reallocating a fresh buffer for every batch under sustained throughput.
        reusable.bytes.clear();
        reusable.frames.clear();
        reusable.popped.clear();
        reusable.committed = 0;
        // Pre-size both buffers to the frames this batch will encode (bounded by
        // the batch cap) so the burst serializes into the allocation grown once
        // here, not grown frame-by-frame as each append crosses a power of two.
        // `Vec::reserve` is a no-op when the retained capacity already covers
        // the request, so this costs nothing at steady state.
        let frame_budget = queue.len().min(OUTBOUND_BATCH_MAX_FRAMES);
        reusable.frames.reserve(frame_budget);
        reusable.popped.reserve(frame_budget);
        reusable
            .bytes
            .reserve(frame_budget * OUTBOUND_BATCH_FRAME_BYTES_ESTIMATE);
        while reusable.frames.len() < OUTBOUND_BATCH_MAX_FRAMES {
            let Some(message) = queue.pop_next() else {
                break;
            };
            // Serialize the frame directly into the shared batch buffer — no
            // per-frame allocation. If encoding fails, unwind any partial
            // append so the buffer stays at its prior boundary.
            let before = reusable.bytes.len();
            if let Err(error) = encode_frame_for_version_into(
                &message,
                selected_protocol_version,
                &mut reusable.bytes,
            ) {
                reusable.bytes.truncate(before);
                // Hand every message popped for this batch back to the queue in
                // reverse pop order so the original send order is restored: the
                // failing message first, then the messages already successfully
                // encoded ahead of it. Previously only the failing message was
                // returned, dropping every earlier-popped message on the floor
                // (they were popped off the queue but never encoded into a
                // committed batch).
                queue.unpop(message);
                for prior in reusable.popped.drain(..).rev() {
                    queue.unpop(prior);
                }
                return Err(NetworkError::from(error).into());
            }
            // From the second frame onward, keep the batch under the byte cap by
            // unwinding this frame. The first frame is always included even when
            // it alone exceeds the cap, so a lone large frame never stalls.
            if !reusable.frames.is_empty() && reusable.bytes.len() > OUTBOUND_BATCH_MAX_BYTES {
                reusable.bytes.truncate(before);
                // The byte-cap break is not an error: the messages popped so far
                // (including this one) form a valid batch's worth, and this
                // message leads the next batch. Only `message` returns to the
                // queue; the messages already in `popped` belong to this batch.
                queue.unpop(message);
                break;
            }
            reusable
                .frames
                .push((undelivered_metadata(&message, false), reusable.bytes.len()));
            reusable.popped.push(message);
        }
        Ok(reusable)
    }

    fn remaining(&self) -> &[u8] {
        &self.bytes[self.committed..]
    }

    fn commit(&mut self, count: usize) {
        self.committed += count;
    }

    fn is_complete(&self) -> bool {
        self.committed == self.bytes.len()
    }
}

/// Persistent connection owner. It reconnects with bounded exponential
/// backoff until shutdown is requested.
#[derive(Debug)]
pub struct PersistentPeer<C, A, J = NoReconnectJitter> {
    connector: C,
    admission: A,
    jitter: J,
    config: PersistentPeerConfig,
    outbound: mpsc::Receiver<WireMessage>,
    events: mpsc::Sender<PeerEvent>,
    observable_stats: Arc<ObservableSessionStats>,
}

impl<C, A> PersistentPeer<C, A, NoReconnectJitter>
where
    C: AuthenticatedConnector,
    A: SessionAdmission,
{
    /// Creates a persistent peer plus its bounded outbound and event channels.
    ///
    /// # Errors
    ///
    /// Returns an error for any invalid bound or timing relationship.
    pub fn new(
        connector: C,
        admission: A,
        config: PersistentPeerConfig,
    ) -> Result<(Self, PeerSender, mpsc::Receiver<PeerEvent>), PeerConfigError> {
        Self::new_with_jitter(connector, admission, NoReconnectJitter, config)
    }
}

impl<C, A, J> PersistentPeer<C, A, J>
where
    C: AuthenticatedConnector,
    A: SessionAdmission,
    J: ReconnectJitter,
{
    /// Creates a persistent peer with an injected reconnect jitter source.
    ///
    /// # Errors
    ///
    /// Returns an error for any invalid bound or timing relationship.
    pub fn new_with_jitter(
        connector: C,
        admission: A,
        jitter: J,
        config: PersistentPeerConfig,
    ) -> Result<(Self, PeerSender, mpsc::Receiver<PeerEvent>), PeerConfigError> {
        config.validate()?;
        let (outbound_sender, outbound) = mpsc::channel(config.outbound_channel_capacity);
        let (events, event_receiver) = mpsc::channel(config.event_channel_capacity);
        let observable_stats = Arc::new(ObservableSessionStats::default());
        Ok((
            Self {
                connector,
                admission,
                jitter,
                config,
                outbound,
                events,
                observable_stats: Arc::clone(&observable_stats),
            },
            PeerSender {
                sender: outbound_sender,
                observable_stats,
            },
            event_receiver,
        ))
    }

    /// Returns a shared handle to this session's live outbound-queue diagnostics
    /// (§23 coalescing, §35 drops), published on the heartbeat tick. Clone it
    /// before [`run`](Self::run) consumes the session so the diagnostics surface
    /// can read cumulative counters while the session streams.
    #[must_use]
    pub fn observable_stats(&self) -> Arc<ObservableSessionStats> {
        Arc::clone(&self.observable_stats)
    }

    /// Runs connection, admission, message transport, heartbeat, and reconnect
    /// until bounded shutdown or outbound-channel closure.
    ///
    /// # Errors
    ///
    /// Returns an error only when the local event consumer prevents safe
    /// operation. Network and peer failures transition to disconnected and are
    /// retried with backoff.
    pub async fn run(
        mut self,
        address: DevelopmentAddress,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<PersistentExit, SessionError> {
        let mut backoff = ReconnectBackoff::new(self.config.reconnect);
        loop {
            if shutdown_now(&shutdown) {
                return Ok(PersistentExit::Shutdown);
            }
            send_event(
                &self.events,
                PeerEvent::StateChanged(ConnectionState::Connecting),
            )?;

            let connected = tokio::select! {
                biased;
                () = wait_for_shutdown(&mut shutdown) => return Ok(PersistentExit::Shutdown),
                result = self.connector.connect(address) => result,
            };

            let (reason, mut undelivered, stats) = match connected {
                Ok(stream) => match run_session_with_stats(
                    stream,
                    &self.admission,
                    self.config,
                    &mut self.outbound,
                    &self.events,
                    &mut shutdown,
                    Some(self.observable_stats.as_ref()),
                )
                .await
                {
                    Ok(SessionEnd::Shutdown) => return Ok(PersistentExit::Shutdown),
                    Ok(SessionEnd::OutboundClosed) => return Ok(PersistentExit::OutboundClosed),
                    Err(failure) => {
                        if matches!(
                            failure.error,
                            SessionError::EventChannelFull | SessionError::EventChannelClosed
                        ) {
                            return Err(failure.error);
                        }
                        if failure.reset_backoff {
                            backoff.reset();
                        }
                        (
                            disconnect_reason(&failure.error),
                            failure.undelivered,
                            failure.stats,
                        )
                    }
                },
                Err(error) => (
                    DisconnectReason::ConnectFailed(error.kind()),
                    UndeliveredTraffic::default(),
                    // No session queue existed (connect failed), so no diagnostics.
                    SessionStats::default(),
                ),
            };
            drain_outbound(&mut self.outbound, &mut undelivered);

            send_event(
                &self.events,
                PeerEvent::StateChanged(ConnectionState::Disconnected),
            )?;
            send_event(
                &self.events,
                PeerEvent::Disconnected {
                    reason,
                    undelivered,
                    stats,
                },
            )?;
            let base_delay = backoff.next_delay();
            let delay = self
                .jitter
                .apply(base_delay, backoff.attempts())
                .max(Duration::from_millis(1))
                .min(self.config.reconnect.maximum_delay);
            send_event(&self.events, PeerEvent::ReconnectScheduled(delay))?;
            tokio::select! {
                biased;
                () = wait_for_shutdown(&mut shutdown) => return Ok(PersistentExit::Shutdown),
                () = tokio::time::sleep(delay) => {}
            }
        }
    }
}

/// Test-only entry that mirrors the pre-observability `run_session` signature,
/// passing `None` so existing tests are unchanged. Production call sites use
/// [`run_session_with_stats`] with a live [`ObservableSessionStats`].
#[cfg(test)]
async fn run_session<S: SecurePeerStream, A: SessionAdmission>(
    stream: S,
    admission: &A,
    config: PersistentPeerConfig,
    outbound: &mut mpsc::Receiver<WireMessage>,
    events: &mpsc::Sender<PeerEvent>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<SessionEnd, SessionFailure> {
    run_session_with_stats(stream, admission, config, outbound, events, shutdown, None).await
}

#[allow(clippy::too_many_lines)]
async fn run_session_with_stats<S: SecurePeerStream, A: SessionAdmission>(
    stream: S,
    admission: &A,
    config: PersistentPeerConfig,
    outbound: &mut mpsc::Receiver<WireMessage>,
    events: &mpsc::Sender<PeerEvent>,
    shutdown: &mut watch::Receiver<bool>,
    stats: Option<&ObservableSessionStats>,
) -> Result<SessionEnd, SessionFailure> {
    let admission_result = tokio::time::timeout(
        config.admission_timeout,
        perform_admission(stream, admission, events, shutdown),
    )
    .await
    .map_err(|_| SessionFailure::before_admission(SessionError::AdmissionTimeout))?;
    let Some((mut reader, mut writer, admitted)) =
        admission_result.map_err(SessionFailure::before_admission)?
    else {
        return Ok(SessionEnd::Shutdown);
    };

    let origin = Instant::now();
    let mut heartbeat = HeartbeatController::new(config.heartbeat);
    heartbeat.connected(Duration::ZERO);
    let mut heartbeat_tick = tokio::time::interval(config.heartbeat.interval);
    heartbeat_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    heartbeat_tick.tick().await;
    let mut queue = OutboundQueue::new(config.queue);
    // Begin the session with a clean observable so the first heartbeat reflects
    // only traffic from this run, not values left over from a prior generation.
    if let Some(stats) = stats {
        stats.reset();
    }
    let mut pending = None;
    // Retains the last flushed batch's `bytes`/`frames` allocations so the next
    // batch reuses them instead of reallocating under sustained throughput.
    let mut recycled = None::<PendingFrame>;
    let selected_protocol_version = admitted.selected_protocol_version();
    let mut read_progress = FrameReadProgress::default();
    // Reused across drains so a multi-frame burst is decoded and dispatched
    // without per-drain or per-frame allocation.
    let mut inbound_messages = Vec::<WireMessage>::new();
    let mut outbound_open = true;
    let mut reset_backoff = false;

    let result: Result<SessionEnd, SessionError> = async {
    loop {
        while let Ok(message) = outbound.try_recv() {
            enqueue(&mut queue, message)?;
        }
        if pending.is_none() {
            let reusable = recycled.take().unwrap_or_default();
            let frame =
                PendingFrame::encode_batch(&mut queue, selected_protocol_version, reusable)?;
            if frame.frames.is_empty() {
                // Queue held nothing; keep the cleared allocation for next time.
                recycled = Some(frame);
            } else {
                pending = Some(frame);
            }
        }
        if !outbound_open && pending.is_none() && queue.is_empty() {
            return Ok(SessionEnd::OutboundClosed);
        }

        tokio::select! {
            biased;
            () = wait_for_shutdown(shutdown) => {
                let mut write = writer.into_inner();
                let _ = tokio::time::timeout(config.shutdown_timeout, write.shutdown()).await;
                return Ok(SessionEnd::Shutdown);
            }
            result = async {
                if let Some(frame) = pending.as_ref() {
                    if frame.is_complete() {
                        writer.flush().await.map(|()| FrameWriteProgress::Flushed)
                    } else {
                        writer.write_some(frame.remaining()).await.map(FrameWriteProgress::Bytes)
                    }
                } else {
                    Ok(FrameWriteProgress::Flushed)
                }
            }, if pending.is_some() => {
                match result? {
                    FrameWriteProgress::Bytes(committed) => {
                        if let Some(frame) = pending.as_mut() {
                            frame.commit(committed);
                        }
                    }
                    FrameWriteProgress::Flushed => {
                        // Retain the flushed batch's allocation for reuse by the
                        // next batch instead of dropping and reallocating it.
                        if let Some(frame) = pending.take() {
                            if let Some(stats) = stats {
                                stats.record_outbound(frame.frames.len(), frame.bytes.len());
                            }
                            recycled = Some(frame);
                        }
                    }
                }
            }
            read_result = reader.read_and_drain(&mut read_progress, &mut inbound_messages) => {
                let inbound_bytes = read_result?;
                // `read_and_drain` makes forward progress on every successful
                // call: it either decodes at least one buffered frame into
                // `inbound_messages`, or performs a transport read. A completed
                // call that leaves `inbound_messages` empty while no bytes
                // remain buffered would mean neither happened — a regression in
                // the receive hot path worth catching in debug builds.
                debug_assert!(
                    !inbound_messages.is_empty() || read_progress.buffered_bytes() > 0,
                    "read_and_drain made no forward progress"
                );
                if let Some(stats) = stats {
                    stats.record_inbound(inbound_messages.len(), inbound_bytes);
                }
                for message in inbound_messages.drain(..) {
                    handle_inbound(
                        message,
                        &admitted,
                        &mut heartbeat,
                        origin.elapsed(),
                        &mut queue,
                        events,
                    )?;
                }
                if let Some(stats) = stats {
                    stats.publish_rtt(heartbeat.health().last_rtt);
                }
            }
            message = outbound.recv(), if outbound_open => {
                if let Some(message) = message {
                    enqueue(&mut queue, message)?;
                } else {
                    outbound_open = false;
                }
            }
            _ = heartbeat_tick.tick() => {
                // Publish a live snapshot of outbound-queue state (drops +
                // coalescing) on the heartbeat cadence so a pull-model
                // diagnostics reader can observe the happy path, not just the
                // forensic Disconnect report.
                if let Some(stats) = stats {
                    stats.publish(queue.session_stats());
                }
                for action in heartbeat.poll(origin.elapsed()) {
                    handle_heartbeat_action(action, &mut queue, events)?;
                }
                reset_backoff |= origin.elapsed() >= config.healthy_reset_after
                    && heartbeat.health().state == crate::PeerState::Healthy
                    && heartbeat.health().last_pong_at.is_some();
            }
        }
    }}.await;

    result.map_err(|error| {
        collect_session_failure(error, pending, &mut queue, &read_progress, reset_backoff)
    })
}

fn collect_session_failure(
    error: SessionError,
    pending: Option<PendingFrame>,
    queue: &mut OutboundQueue,
    read_progress: &FrameReadProgress,
    reset_backoff: bool,
) -> SessionFailure {
    let mut undelivered = UndeliveredTraffic {
        partial_inbound_bytes: read_progress.buffered_bytes(),
        // Delivery of previously completed input frames is not acknowledged;
        // every admitted-session failure therefore requires release/state
        // reconciliation even when the local queues are empty.
        requires_input_reconciliation: true,
        ..UndeliveredTraffic::default()
    };
    if let SessionError::QueueFull {
        undelivered: rejected,
        ..
    } = &error
    {
        undelivered.requires_input_reconciliation |= rejected.traffic_class == TrafficClass::Input;
        undelivered.messages.push(*rejected);
    }
    if let Some(frame) = pending {
        let committed = frame.committed;
        let mut start = 0_usize;
        for (mut metadata, end) in frame.frames {
            // Conservative — matches the prior single-frame rule ("any
            // committed byte counts as partially in flight"): a frame whose
            // byte range [start, end) begins at or before the committed offset
            // had at least one byte handed to the transport.
            metadata.partially_sent = committed > start;
            undelivered.requires_input_reconciliation |=
                metadata.traffic_class == TrafficClass::Input;
            undelivered.messages.push(metadata);
            start = end;
        }
    }
    while let Some(message) = queue.pop_next() {
        undelivered.record(&message, false);
    }
    // Cumulative queue diagnostics survive draining the lane: coalescing and
    // drop counts are running totals over the session, so a burst that has
    // already been popped (or coalesced away) is still reflected here.
    let stats = queue.session_stats();
    SessionFailure {
        error,
        undelivered,
        reset_backoff,
        stats,
    }
}

#[allow(clippy::too_many_lines)]
async fn perform_admission<S: SecurePeerStream, A: SessionAdmission>(
    mut stream: S,
    admission: &A,
    events: &mpsc::Sender<PeerEvent>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<
    Option<(
        FrameReader<tokio::io::ReadHalf<S>>,
        FrameWriter<tokio::io::WriteHalf<S>>,
        AdmittedPeer,
    )>,
    SessionError,
> {
    let transport_identity = stream.authenticated_peer_identity().clone();
    let direction = stream.connection_direction();
    let local_hello = admission.local_hello()?;
    let role = ConnectionRole::for_peers(local_hello.peer_id, transport_identity.peer_id).map_err(
        |error| match error {
            ConnectionRoleError::IdentityCollision => SessionError::PeerIdentityCollision,
            ConnectionRoleError::NoncanonicalDirection => SessionError::NoncanonicalDirection,
        },
    )?;
    role.validate(direction)
        .map_err(|_| SessionError::NoncanonicalDirection)?;
    send_event(
        events,
        PeerEvent::StateChanged(ConnectionState::Authenticating),
    )?;
    {
        if !write_or_shutdown_for_version(
            &mut stream,
            &WireMessage::Hello(local_hello.clone()),
            PROTOCOL_VERSION_V1,
            shutdown,
        )
        .await?
        {
            return Ok(None);
        }
    }
    let first_message = {
        let Some(message) =
            read_or_shutdown_for_version(&mut stream, PROTOCOL_VERSION_V1, shutdown).await?
        else {
            return Ok(None);
        };
        message
    };
    let remote_hello = match first_message {
        WireMessage::Hello(hello) => hello,
        message => return Err(SessionError::PreAdmissionMessage(message.message_type())),
    };
    if remote_hello.host_id != transport_identity.host_id
        || remote_hello.peer_id != transport_identity.peer_id
    {
        return Err(SessionError::TransportIdentityMismatch);
    }
    let selected_protocol_version = negotiate_protocol_version(&local_hello, &remote_hello)?;
    let transcript = build_handshake_transcript(
        &stream,
        local_hello.clone(),
        remote_hello,
        transport_identity,
        selected_protocol_version,
    )?;
    let local_auth = admission.authentication_message(&transcript)?;
    if local_auth.peer_id != local_hello.peer_id {
        return Err(SessionError::LocalIdentityMismatch);
    }
    {
        if !write_or_shutdown_for_version(
            &mut stream,
            &WireMessage::Authenticate(local_auth),
            selected_protocol_version,
            shutdown,
        )
        .await?
        {
            return Ok(None);
        }
    }
    let second_message = {
        let Some(message) =
            read_or_shutdown_for_version(&mut stream, selected_protocol_version, shutdown).await?
        else {
            return Ok(None);
        };
        message
    };
    let remote_auth = match second_message {
        WireMessage::Authenticate(authentication) => authentication,
        message => return Err(SessionError::PreAdmissionMessage(message.message_type())),
    };
    if remote_auth.peer_id != transcript.transport_identity.peer_id {
        return Err(SessionError::TransportIdentityMismatch);
    }
    admission.admit(&transcript, &remote_auth)?;

    let admitted = AdmittedPeer {
        transport_identity: transcript.transport_identity,
        local_hello: Arc::new(transcript.local_hello),
        remote_hello: Arc::new(transcript.remote_hello),
        selected_protocol_version: transcript.selected_protocol_version,
        session_id: transcript.session_id,
    };
    send_event(events, PeerEvent::Admitted(admitted.clone()))?;
    send_event(events, PeerEvent::StateChanged(ConnectionState::Connected))?;
    let (read, write) = tokio::io::split(stream);
    let reader = FrameReader::new_authenticated_for_version(read, selected_protocol_version);
    let writer = FrameWriter::new_authenticated(write);
    Ok(Some((reader, writer, admitted)))
}

const AUTHENTICATION_EXPORTER_LABEL: &[u8] = b"EXPORTER-software-kvm-session-auth-v1";
const AUTHENTICATION_CONTEXT_DOMAIN: &[u8] = b"software-kvm/session-auth-context/v1";
const SESSION_ID_EXPORTER_LABEL: &[u8] = b"EXPORTER-software-kvm-session-id-v1";
const SESSION_ID_CONTEXT_DOMAIN: &[u8] = b"software-kvm/session-id-context/v1";

fn build_handshake_transcript<S: SecurePeerStream>(
    stream: &S,
    local_hello: HelloV1,
    remote_hello: HelloV1,
    transport_identity: TransportPeerIdentity,
    selected_protocol_version: u16,
) -> Result<HandshakeTranscript, SessionError> {
    if remote_hello.peer_id == local_hello.peer_id {
        return Err(SessionError::PeerIdentityCollision);
    }
    let local_context = authentication_exporter_context(
        &local_hello,
        &remote_hello,
        local_hello.peer_id,
        selected_protocol_version,
    )?;
    let remote_context = authentication_exporter_context(
        &local_hello,
        &remote_hello,
        remote_hello.peer_id,
        selected_protocol_version,
    )?;
    let local_exporter_proof = stream
        .export_keying_material(AUTHENTICATION_EXPORTER_LABEL, &local_context)
        .map_err(NetworkError::from)?;
    let remote_exporter_proof = stream
        .export_keying_material(AUTHENTICATION_EXPORTER_LABEL, &remote_context)
        .map_err(NetworkError::from)?;
    let session_context =
        session_exporter_context(&local_hello, &remote_hello, selected_protocol_version)?;
    let session_id = stream
        .export_keying_material(SESSION_ID_EXPORTER_LABEL, &session_context)
        .map_err(NetworkError::from)?;
    if bool::from(session_id.ct_eq(&[0; 32])) {
        return Err(SessionError::InvalidSessionBinding);
    }

    Ok(HandshakeTranscript {
        local_hello,
        remote_hello,
        transport_identity,
        local_exporter_proof,
        remote_exporter_proof,
        selected_protocol_version,
        session_id,
    })
}

fn negotiate_protocol_version(
    local_hello: &HelloV1,
    remote_hello: &HelloV1,
) -> Result<u16, SessionError> {
    let minimum = local_hello
        .minimum_protocol_version
        .max(remote_hello.minimum_protocol_version)
        .max(MIN_SUPPORTED_PROTOCOL_VERSION);
    let maximum = local_hello
        .maximum_protocol_version
        .min(remote_hello.maximum_protocol_version)
        .min(CURRENT_PROTOCOL_VERSION);
    (minimum <= maximum)
        .then_some(maximum)
        .ok_or(SessionError::NoCompatibleProtocolVersion)
}

fn authentication_exporter_context(
    local_hello: &HelloV1,
    remote_hello: &HelloV1,
    sender: kvm_protocol::WirePeerId,
    selected_protocol_version: u16,
) -> Result<Vec<u8>, SessionError> {
    if local_hello.peer_id == remote_hello.peer_id {
        return Err(SessionError::PeerIdentityCollision);
    }
    let local_frame = encode_frame_for_version(
        &WireMessage::Hello(local_hello.clone()),
        PROTOCOL_VERSION_V1,
    )
    .map_err(NetworkError::from)?;
    let remote_frame = encode_frame_for_version(
        &WireMessage::Hello(remote_hello.clone()),
        PROTOCOL_VERSION_V1,
    )
    .map_err(NetworkError::from)?;
    let mut hellos = [
        (local_hello.peer_id, local_frame),
        (remote_hello.peer_id, remote_frame),
    ];
    hellos.sort_unstable_by_key(|(peer_id, _)| peer_id.0);
    let sender_role = u8::from(sender != hellos[0].0);

    let mut context = Vec::with_capacity(
        AUTHENTICATION_CONTEXT_DOMAIN.len()
            + 2
            + 1
            + hellos
                .iter()
                .map(|(_, frame)| 4 + frame.len())
                .sum::<usize>(),
    );
    context.extend_from_slice(AUTHENTICATION_CONTEXT_DOMAIN);
    context.extend_from_slice(&selected_protocol_version.to_be_bytes());
    context.push(sender_role);
    for (_, frame) in hellos {
        let length = u32::try_from(frame.len()).map_err(|_| {
            NetworkError::from(kvm_protocol::ProtocolError::PayloadTooLarge {
                length: frame.len(),
                maximum: kvm_protocol::MAX_FRAME_PAYLOAD,
            })
        })?;
        context.extend_from_slice(&length.to_be_bytes());
        context.extend_from_slice(&frame);
    }
    Ok(context)
}

fn session_exporter_context(
    local_hello: &HelloV1,
    remote_hello: &HelloV1,
    selected_protocol_version: u16,
) -> Result<Vec<u8>, SessionError> {
    if local_hello.peer_id == remote_hello.peer_id {
        return Err(SessionError::PeerIdentityCollision);
    }
    let local_frame = encode_frame_for_version(
        &WireMessage::Hello(local_hello.clone()),
        PROTOCOL_VERSION_V1,
    )
    .map_err(NetworkError::from)?;
    let remote_frame = encode_frame_for_version(
        &WireMessage::Hello(remote_hello.clone()),
        PROTOCOL_VERSION_V1,
    )
    .map_err(NetworkError::from)?;
    let mut hellos = [
        (local_hello.peer_id, local_frame),
        (remote_hello.peer_id, remote_frame),
    ];
    hellos.sort_unstable_by_key(|(peer_id, _)| peer_id.0);

    let mut context = Vec::with_capacity(
        SESSION_ID_CONTEXT_DOMAIN.len()
            + 2
            + hellos
                .iter()
                .map(|(_, frame)| 4 + frame.len())
                .sum::<usize>(),
    );
    context.extend_from_slice(SESSION_ID_CONTEXT_DOMAIN);
    context.extend_from_slice(&selected_protocol_version.to_be_bytes());
    for (_, frame) in hellos {
        let length = u32::try_from(frame.len()).map_err(|_| {
            NetworkError::from(kvm_protocol::ProtocolError::PayloadTooLarge {
                length: frame.len(),
                maximum: kvm_protocol::MAX_FRAME_PAYLOAD,
            })
        })?;
        context.extend_from_slice(&length.to_be_bytes());
        context.extend_from_slice(&frame);
    }
    Ok(context)
}

fn handle_inbound(
    message: WireMessage,
    admitted: &AdmittedPeer,
    heartbeat: &mut HeartbeatController,
    now: Duration,
    queue: &mut OutboundQueue,
    events: &mpsc::Sender<PeerEvent>,
) -> Result<(), SessionError> {
    validate_message_identity(&message, admitted)?;
    let previous_state = heartbeat.health().state;
    let response = heartbeat
        .on_message(&message, now)
        .map_err(|error| SessionError::Heartbeat(error.to_string()))?;
    if previous_state == crate::PeerState::Degraded
        && heartbeat.health().state == crate::PeerState::Healthy
    {
        send_event(events, PeerEvent::StateChanged(ConnectionState::Connected))?;
    }
    if let Some(response) = response {
        enqueue(queue, response)?;
    }
    match message {
        WireMessage::Ping(_) | WireMessage::Pong(_) => Ok(()),
        WireMessage::Hello(_) | WireMessage::Authenticate(_) => {
            Err(SessionError::RepeatedHandshake(message.message_type()))
        }
        message => send_event(
            events,
            PeerEvent::Message {
                peer: admitted.clone(),
                message,
            },
        ),
    }
}

fn validate_message_identity(
    message: &WireMessage,
    admitted: &AdmittedPeer,
) -> Result<(), SessionError> {
    let remote = admitted.transport_identity.host_id;
    let local = admitted.local_hello.host_id;
    let valid = match message {
        WireMessage::DeviceSnapshot(value) => value.host_id == remote,
        WireMessage::DeviceAdded(value) => value.device.host_id == remote,
        WireMessage::DeviceRemoved(value) => value.host_id == remote,
        WireMessage::DisplaySnapshot(value) => value.host_id == remote,
        WireMessage::DisplayUpdated(value) => value.display.host_id == remote,
        WireMessage::Input(value) => value.source_host == remote,
        WireMessage::PointerEnter(value) => {
            value.source_host == remote && value.destination_host == local
        }
        WireMessage::PointerLeave(value) => value.source_host == remote,
        WireMessage::PointerTransitionAck(value) => value.receiver_host == remote,
        WireMessage::PointerTransitionCommit(value) => {
            value.source_host == remote && value.destination_host == local
        }
        WireMessage::Clipboard(value) => value.origin_host == remote,
        WireMessage::ReleaseInput(value) => value.source_host == remote,
        WireMessage::ReleaseInputV2(value) => {
            value.source_host == remote && value.applying_host == local
        }
        WireMessage::ReleaseAppliedAckV2(value) => {
            value.source_host == local && value.applying_host == remote
        }
        WireMessage::Hello(_)
        | WireMessage::Authenticate(_)
        | WireMessage::Ping(_)
        | WireMessage::Pong(_) => true,
    };
    if valid {
        Ok(())
    } else {
        Err(SessionError::MessageIdentityMismatch(
            message.message_type(),
        ))
    }
}

fn handle_heartbeat_action(
    action: HeartbeatAction,
    queue: &mut OutboundQueue,
    events: &mpsc::Sender<PeerEvent>,
) -> Result<(), SessionError> {
    match action {
        HeartbeatAction::Send(message) => enqueue(queue, message),
        HeartbeatAction::StateChanged(crate::PeerState::Degraded) => {
            send_event(events, PeerEvent::StateChanged(ConnectionState::Degraded))
        }
        HeartbeatAction::StateChanged(crate::PeerState::Disconnected)
        | HeartbeatAction::Disconnect => Err(SessionError::HeartbeatTimeout),
        HeartbeatAction::StateChanged(_) => Ok(()),
    }
}

fn enqueue(queue: &mut OutboundQueue, message: WireMessage) -> Result<(), SessionError> {
    queue.try_push(message).map_err(|error| {
        let class = error.class();
        let capacity = error.capacity();
        let message = error.into_message();
        SessionError::QueueFull {
            class,
            capacity,
            undelivered: undelivered_metadata(&message, false),
        }
    })
}

fn undelivered_metadata(message: &WireMessage, partially_sent: bool) -> UndeliveredMessage {
    UndeliveredMessage {
        message_type: message.message_type(),
        traffic_class: TrafficClass::for_message(message),
        sequence: message_sequence(message),
        partially_sent,
    }
}

fn drain_outbound(
    outbound: &mut mpsc::Receiver<WireMessage>,
    undelivered: &mut UndeliveredTraffic,
) {
    while let Ok(message) = outbound.try_recv() {
        undelivered.record(&message, false);
    }
}

fn disconnect_reason(error: &SessionError) -> DisconnectReason {
    match error {
        SessionError::Network(NetworkError::Io(io))
            if matches!(
                io.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            DisconnectReason::RemoteClosed
        }
        SessionError::Network(NetworkError::Io(io)) => DisconnectReason::TransportIo(io.kind()),
        SessionError::Network(NetworkError::Protocol(_)) => DisconnectReason::InvalidFrame,
        SessionError::Admission(AdmissionError::Rejected) => DisconnectReason::AdmissionRejected,
        SessionError::Admission(AdmissionError::Unavailable) => {
            DisconnectReason::AdmissionUnavailable
        }
        SessionError::AdmissionTimeout => DisconnectReason::AdmissionTimeout,
        SessionError::TransportIdentityMismatch
        | SessionError::LocalIdentityMismatch
        | SessionError::PeerIdentityCollision
        | SessionError::NoncanonicalDirection
        | SessionError::MessageIdentityMismatch(_) => DisconnectReason::IdentityMismatch,
        SessionError::NoCompatibleProtocolVersion
        | SessionError::InvalidSessionBinding
        | SessionError::PreAdmissionMessage(_) => DisconnectReason::ProtocolViolation,
        SessionError::RepeatedHandshake(_) => DisconnectReason::RepeatedHandshake,
        SessionError::Heartbeat(_) => DisconnectReason::HeartbeatInvalid,
        SessionError::HeartbeatTimeout => DisconnectReason::HeartbeatTimeout,
        SessionError::QueueFull { class, .. } => DisconnectReason::QueueFull(*class),
        SessionError::EventChannelFull | SessionError::EventChannelClosed => {
            DisconnectReason::TransportIo(std::io::ErrorKind::Other)
        }
    }
}

const fn message_sequence(message: &WireMessage) -> Option<u64> {
    match message {
        WireMessage::Input(value) => Some(value.sequence),
        WireMessage::PointerEnter(value) => Some(value.sequence),
        WireMessage::PointerLeave(value) => Some(value.sequence),
        WireMessage::PointerTransitionCommit(value) => Some(value.sequence),
        WireMessage::Clipboard(value) => Some(value.sequence),
        WireMessage::ReleaseInput(value) => Some(value.sequence),
        WireMessage::ReleaseInputV2(value) => Some(value.sequence),
        WireMessage::ReleaseAppliedAckV2(value) => Some(value.sequence),
        _ => None,
    }
}

fn send_event(events: &mpsc::Sender<PeerEvent>, event: PeerEvent) -> Result<(), SessionError> {
    events.try_send(event).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => SessionError::EventChannelFull,
        mpsc::error::TrySendError::Closed(_) => SessionError::EventChannelClosed,
    })
}

async fn write_or_shutdown_for_version<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    message: &WireMessage,
    selected_protocol_version: u16,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<bool, SessionError> {
    let frame =
        encode_frame_for_version(message, selected_protocol_version).map_err(NetworkError::from)?;
    tokio::select! {
        biased;
        () = wait_for_shutdown(shutdown) => Ok(false),
        result = async {
            writer.write_all(&frame).await?;
            writer.flush().await
        } => result.map(|()| true).map_err(NetworkError::from).map_err(SessionError::from),
    }
}

async fn read_or_shutdown_for_version<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    selected_protocol_version: u16,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Option<WireMessage>, SessionError> {
    tokio::select! {
        biased;
        () = wait_for_shutdown(shutdown) => Ok(None),
        result = read_message_for_version(reader, selected_protocol_version) => {
            result.map(Some).map_err(SessionError::from)
        },
    }
}

async fn read_message_for_version<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    selected_protocol_version: u16,
) -> Result<WireMessage, NetworkError> {
    let mut header_bytes = [0_u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header_bytes).await?;
    let header = FrameHeader::decode_for_version(&header_bytes, selected_protocol_version)?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + header.payload_length as usize);
    frame.extend_from_slice(&header_bytes);
    frame.resize(FRAME_HEADER_LEN + header.payload_length as usize, 0);
    reader.read_exact(&mut frame[FRAME_HEADER_LEN..]).await?;
    decode_frame_for_version(&frame, selected_protocol_version).map_err(NetworkError::from)
}

fn shutdown_now(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !shutdown_now(shutdown) {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectionDirection, TransportPeerIdentity};
    use kvm_protocol::{
        encode_frame_for_version, ClipboardV1, InputEventV1, PointerEnterV1, PointerLeaveV1,
        PointerTransitionCommitV1, ReleaseAppliedAckV2, ReleaseInputV1, ReleaseInputV2,
        ReleaseReasonV1, ReleaseReasonV2, WireClipboardId, WireDeviceId, WireDisplayId, WireEdge,
        WireHostId, WireInputPayloadV1, WirePeerId, WirePlatform, PROTOCOL_VERSION_V1,
        PROTOCOL_VERSION_V2,
    };
    use sha2::{Digest, Sha256};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    #[derive(Debug)]
    struct TestSecureStream {
        stream: DuplexStream,
        identity: TransportPeerIdentity,
    }

    impl AsyncRead for TestSecureStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for TestSecureStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.stream).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.stream).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.stream).poll_shutdown(context)
        }
    }

    impl SecurePeerStream for TestSecureStream {
        fn connection_direction(&self) -> ConnectionDirection {
            ConnectionDirection::Outbound
        }

        fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
            &self.identity
        }

        fn export_keying_material(
            &self,
            label: &[u8],
            context: &[u8],
        ) -> std::io::Result<[u8; 32]> {
            let mut digest = Sha256::new();
            digest.update(label);
            digest.update(context);
            Ok(digest.finalize().into())
        }
    }

    impl crate::connector::sealed::SecureStream for TestSecureStream {}

    #[derive(Debug)]
    struct ZeroExporterSecureStream(TestSecureStream);

    impl AsyncRead for ZeroExporterSecureStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for ZeroExporterSecureStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.0).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_shutdown(context)
        }
    }

    impl SecurePeerStream for ZeroExporterSecureStream {
        fn connection_direction(&self) -> ConnectionDirection {
            self.0.connection_direction()
        }

        fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
            self.0.authenticated_peer_identity()
        }

        fn export_keying_material(
            &self,
            _label: &[u8],
            _context: &[u8],
        ) -> std::io::Result<[u8; 32]> {
            Ok([0; 32])
        }
    }

    impl crate::connector::sealed::SecureStream for ZeroExporterSecureStream {}

    #[derive(Debug)]
    struct InboundTestSecureStream(TestSecureStream);

    impl AsyncRead for InboundTestSecureStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for InboundTestSecureStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.0).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_shutdown(context)
        }
    }

    impl SecurePeerStream for InboundTestSecureStream {
        fn connection_direction(&self) -> ConnectionDirection {
            ConnectionDirection::Inbound
        }

        fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
            self.0.authenticated_peer_identity()
        }

        fn export_keying_material(
            &self,
            label: &[u8],
            context: &[u8],
        ) -> std::io::Result<[u8; 32]> {
            self.0.export_keying_material(label, context)
        }
    }

    impl crate::connector::sealed::SecureStream for InboundTestSecureStream {}

    /// Alternates a small successful write with `Pending`. This reproduces the
    /// exact pattern that makes cancellation and recreation of `write_all`
    /// duplicate a frame prefix.
    #[derive(Debug)]
    struct PartialPendingSecureStream {
        inner: TestSecureStream,
        maximum_chunk: usize,
        pending_next: bool,
    }

    impl AsyncRead for PartialPendingSecureStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner.stream).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for PartialPendingSecureStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            if self.pending_next {
                self.pending_next = false;
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            let length = buffer.len().min(self.maximum_chunk);
            let result = Pin::new(&mut self.inner.stream).poll_write(context, &buffer[..length]);
            if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
                self.pending_next = true;
            }
            result
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner.stream).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner.stream).poll_shutdown(context)
        }
    }

    impl SecurePeerStream for PartialPendingSecureStream {
        fn connection_direction(&self) -> ConnectionDirection {
            ConnectionDirection::Outbound
        }

        fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
            &self.inner.identity
        }

        fn export_keying_material(
            &self,
            label: &[u8],
            context: &[u8],
        ) -> std::io::Result<[u8; 32]> {
            self.inner.export_keying_material(label, context)
        }
    }

    impl crate::connector::sealed::SecureStream for PartialPendingSecureStream {}

    #[derive(Debug)]
    struct PartialPendingReadSecureStream {
        inner: TestSecureStream,
        maximum_chunk: usize,
        pending_next: bool,
    }

    impl AsyncRead for PartialPendingReadSecureStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.pending_next {
                self.pending_next = false;
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            let permitted = buffer.remaining().min(self.maximum_chunk);
            let mut limited = ReadBuf::new(buffer.initialize_unfilled_to(permitted));
            let result = Pin::new(&mut self.inner.stream).poll_read(context, &mut limited);
            if let Poll::Ready(Ok(())) = result {
                let filled = limited.filled().len();
                if filled > 0 {
                    buffer.advance(filled);
                    self.pending_next = true;
                }
            }
            result
        }
    }

    impl AsyncWrite for PartialPendingReadSecureStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.inner.stream).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner.stream).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner.stream).poll_shutdown(context)
        }
    }

    impl SecurePeerStream for PartialPendingReadSecureStream {
        fn connection_direction(&self) -> ConnectionDirection {
            ConnectionDirection::Outbound
        }

        fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
            &self.inner.identity
        }

        fn export_keying_material(
            &self,
            label: &[u8],
            context: &[u8],
        ) -> std::io::Result<[u8; 32]> {
            self.inner.export_keying_material(label, context)
        }
    }

    impl crate::connector::sealed::SecureStream for PartialPendingReadSecureStream {}

    #[derive(Clone, Debug)]
    struct AlwaysFailConnector {
        attempts: Arc<AtomicUsize>,
    }

    impl crate::connector::sealed::Connector for AlwaysFailConnector {}

    impl AuthenticatedConnector for AlwaysFailConnector {
        type Stream = TestSecureStream;

        fn connect<'a>(
            &'a mut self,
            _address: DevelopmentAddress,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<Self::Stream>> + Send + 'a>,
        > {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "test refusal",
                ))
            })
        }
    }

    #[derive(Debug)]
    struct SilentConnector {
        attempts: Arc<AtomicUsize>,
        identity: TransportPeerIdentity,
        held_peers: Vec<DuplexStream>,
    }

    impl crate::connector::sealed::Connector for SilentConnector {}

    #[derive(Debug)]
    struct AddedJitter(Duration);

    impl ReconnectJitter for AddedJitter {
        fn apply(&mut self, base: Duration, _attempt: u32) -> Duration {
            base.saturating_add(self.0)
        }
    }

    impl AuthenticatedConnector for SilentConnector {
        type Stream = TestSecureStream;

        fn connect<'a>(
            &'a mut self,
            _address: DevelopmentAddress,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<Self::Stream>> + Send + 'a>,
        > {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let (session, silent_peer) = tokio::io::duplex(512);
            self.held_peers.push(silent_peer);
            let stream = TestSecureStream {
                stream: session,
                identity: self.identity.clone(),
            };
            Box::pin(async move { Ok(stream) })
        }
    }

    #[derive(Clone, Debug)]
    struct TestAdmission {
        hello: HelloV1,
    }

    impl SessionAdmission for TestAdmission {
        fn local_hello(&self) -> Result<HelloV1, AdmissionError> {
            Ok(self.hello.clone())
        }

        fn authentication_message(
            &self,
            transcript: &HandshakeTranscript,
        ) -> Result<AuthenticateV1, AdmissionError> {
            Ok(AuthenticateV1 {
                peer_id: self.hello.peer_id,
                scheme: "test-channel-binding-v1".to_owned(),
                proof: transcript.remote_hello().nonce.to_vec(),
            })
        }

        fn admit(
            &self,
            transcript: &HandshakeTranscript,
            authentication: &AuthenticateV1,
        ) -> Result<(), AdmissionError> {
            (authentication.proof == transcript.local_hello().nonce)
                .then_some(())
                .ok_or(AdmissionError::Rejected)
        }
    }

    fn hello(value: u8) -> HelloV1 {
        hello_with_versions(value, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V1)
    }

    fn hello_with_versions(value: u8, minimum: u16, maximum: u16) -> HelloV1 {
        HelloV1 {
            host_id: WireHostId([value; 16]),
            peer_id: WirePeerId([value.saturating_add(1); 16]),
            host_name: format!("host-{value}"),
            platform: WirePlatform::Linux,
            minimum_protocol_version: minimum,
            maximum_protocol_version: maximum,
            daemon_version: "test".to_owned(),
            nonce: [value.saturating_add(2); 32],
        }
    }

    fn identity(hello: &HelloV1) -> TransportPeerIdentity {
        TransportPeerIdentity {
            host_id: hello.host_id,
            peer_id: hello.peer_id,
            credential_fingerprint: [hello.host_id.0[0]; 32],
        }
    }

    fn test_config() -> PersistentPeerConfig {
        PersistentPeerConfig {
            heartbeat: HeartbeatConfig {
                interval: Duration::from_mins(1),
                degraded_after: Duration::from_mins(2),
                disconnect_after: Duration::from_mins(3),
                maximum_outstanding_pings: 8,
            },
            ..PersistentPeerConfig::default()
        }
    }

    fn privileged_messages() -> Vec<WireMessage> {
        let source_host = WireHostId([7; 16]);
        let destination_host = WireHostId([8; 16]);
        vec![
            WireMessage::Input(InputEventV1 {
                sequence: 1,
                timestamp_ns: 1,
                source_host,
                source_device: WireDeviceId([9; 16]),
                payload: WireInputPayloadV1::PointerMove { dx: 1.0, dy: 2.0 },
            }),
            WireMessage::Clipboard(ClipboardV1 {
                update_id: WireClipboardId([10; 16]),
                origin_host: source_host,
                sequence: 2,
                text: "secret".to_owned(),
            }),
            WireMessage::ReleaseInput(ReleaseInputV1 {
                sequence: 3,
                source_host,
                source_device: None,
                reason: ReleaseReasonV1::Failsafe,
                keys: Vec::new(),
                buttons: Vec::new(),
            }),
            WireMessage::PointerEnter(PointerEnterV1 {
                transition_id: 4,
                workspace_epoch: 1,
                sequence: 4,
                source_host,
                destination_host,
                source_display: WireDisplayId([11; 16]),
                destination_display: WireDisplayId([12; 16]),
                destination_edge: WireEdge::Left,
                normalized_position: 0.5,
            }),
            WireMessage::PointerLeave(PointerLeaveV1 {
                transition_id: 5,
                workspace_epoch: 1,
                sequence: 5,
                source_host,
                source_display: WireDisplayId([11; 16]),
                edge: WireEdge::Right,
                normalized_position: 0.5,
            }),
            WireMessage::PointerTransitionCommit(PointerTransitionCommitV1 {
                transition_id: 6,
                workspace_epoch: 1,
                sequence: 6,
                source_host,
                destination_host,
                source_display: WireDisplayId([11; 16]),
                destination_display: WireDisplayId([12; 16]),
            }),
        ]
    }

    fn input(sequence: u64) -> WireMessage {
        let mut message = privileged_messages()[0].clone();
        if let WireMessage::Input(input) = &mut message {
            input.sequence = sequence;
        }
        message
    }

    fn release_v2(sequence: u64) -> WireMessage {
        WireMessage::ReleaseInputV2(ReleaseInputV2 {
            transaction_id: 1,
            release_token: [4; 32],
            old_session_id: [5; 32],
            sequence,
            covered_input_sequence: sequence - 1,
            source_host: WireHostId([7; 16]),
            applying_host: WireHostId([8; 16]),
            source_device: Some(WireDeviceId([9; 16])),
            reason: ReleaseReasonV2::RouteChanged,
            keys: Vec::new(),
            buttons: Vec::new(),
        })
    }

    async fn write_test_message_for_version<W: AsyncWrite + Unpin>(
        writer: &mut W,
        message: &WireMessage,
        version: u16,
    ) {
        let frame = encode_frame_for_version(message, version).unwrap();
        writer.write_all(&frame).await.unwrap();
        writer.flush().await.unwrap();
    }

    /// A `PointerMove` input frame from `device` for queue-coalescing tests.
    fn move_from(device: u8, sequence: u64, dx: f64, dy: f64) -> WireMessage {
        WireMessage::Input(InputEventV1 {
            sequence,
            timestamp_ns: sequence,
            source_host: WireHostId([1; 16]),
            source_device: WireDeviceId([device; 16]),
            payload: WireInputPayloadV1::PointerMove { dx, dy },
        })
    }

    #[test]
    fn collect_session_failure_records_queue_diagnostics_in_stats() {
        // A queue that has both coalesced (same-source moves) and dropped
        // (capacity-1 input lane overflow on a different-source move) frames.
        let mut queue = OutboundQueue::new(QueueConfig {
            input: 1,
            control: 4,
            background: 4,
            maximum_input_burst: 8,
            coalesce_pointer_moves: true,
        });
        queue.try_push(move_from(2, 1, 1.0, 0.0)).unwrap();
        queue.try_push(move_from(2, 2, 1.0, 0.0)).unwrap(); // coalesced
        assert!(queue.try_push(move_from(3, 3, 1.0, 0.0)).is_err()); // lane full → drop

        let failure = collect_session_failure(
            SessionError::NoCompatibleProtocolVersion,
            None,
            &mut queue,
            &FrameReadProgress::default(),
            false,
        );

        // The burst pressure that preceded the disconnect is observable on the
        // failure, even though the queue itself is private and now drained.
        assert_eq!(failure.stats.coalesced_moves, 1);
        assert_eq!(failure.stats.dropped.input, 1);
        assert_eq!(failure.stats.dropped.total(), 1);
        // collect_session_failure drains the queue into `undelivered`; the one
        // surviving coalesced frame is reported there, distinct from the stats.
        assert_eq!(failure.undelivered.messages.len(), 1);
    }

    #[test]
    fn payload_bearing_debug_output_is_redacted() {
        let remote = hello(20);
        let peer = AdmittedPeer {
            transport_identity: identity(&remote),
            local_hello: Arc::new(hello(1)),
            remote_hello: Arc::new(remote.clone()),
            selected_protocol_version: PROTOCOL_VERSION_V1,
            session_id: [0; 32],
        };
        let message = WireMessage::Clipboard(ClipboardV1 {
            update_id: WireClipboardId([1; 16]),
            origin_host: remote.host_id,
            sequence: 987_654_321,
            text: "never-print-this-secret".to_owned(),
        });
        let event_debug = format!(
            "{:?}",
            PeerEvent::Message {
                peer,
                message: message.clone(),
            }
        );
        let error_debug = format!("{:?}", OutboundSendError::Full(Box::new(message)));
        let undelivered_debug = format!(
            "{:?}",
            UndeliveredTraffic {
                messages: vec![UndeliveredMessage {
                    message_type: MessageType::Input,
                    traffic_class: TrafficClass::Input,
                    sequence: Some(987_654_321),
                    partially_sent: true,
                }],
                partial_inbound_bytes: 987_654_321,
                requires_input_reconciliation: true,
            }
        );

        assert!(!event_debug.contains("never-print-this-secret"));
        assert!(!error_debug.contains("never-print-this-secret"));
        assert!(!event_debug.contains("987654321"));
        assert!(!error_debug.contains("987654321"));
        assert!(!undelivered_debug.contains("987654321"));
        assert!(event_debug.contains("Clipboard"));
        assert!(error_debug.contains("Clipboard"));
    }

    #[test]
    fn identity_and_peer_controlled_error_debug_output_is_redacted() {
        let remote = hello(83);
        let local = hello(71);
        let transport_identity = identity(&remote);
        let peer = AdmittedPeer {
            transport_identity: transport_identity.clone(),
            local_hello: Arc::new(local.clone()),
            remote_hello: Arc::new(remote.clone()),
            selected_protocol_version: PROTOCOL_VERSION_V1,
            session_id: [0; 32],
        };
        let transcript = HandshakeTranscript {
            local_hello: local,
            remote_hello: remote,
            transport_identity,
            local_exporter_proof: [97; 32],
            remote_exporter_proof: [101; 32],
            selected_protocol_version: PROTOCOL_VERSION_V1,
            session_id: [0; 32],
        };
        assert_eq!(format!("{peer:?}"), "AdmittedPeer([REDACTED])");
        assert_eq!(format!("{transcript:?}"), "HandshakeTranscript([REDACTED])");
        assert_eq!(
            format!("{:?}", PeerEvent::Admitted(peer)),
            "Admitted { peer: \"[REDACTED]\" }"
        );

        let heartbeat = SessionError::Heartbeat("peer-controlled-heartbeat-marker".to_owned());
        assert_eq!(format!("{heartbeat:?}"), "SessionError::Heartbeat");
        assert_eq!(heartbeat.to_string(), "heartbeat validation failed");
    }

    #[test]
    fn admitted_peer_clone_shares_hello_allocations() {
        // `handle_inbound` clones the admitted peer for every inbound
        // `PeerEvent::Message`. The two hellos each carry two `String`s, so a
        // deep clone would be four heap allocations per received event. The
        // hellos are `Arc`-shared, so a clone is a refcount bump: both clones
        // must point at the same hello allocation.
        let remote = hello(20);
        let peer = AdmittedPeer {
            transport_identity: identity(&remote),
            local_hello: Arc::new(hello(1)),
            remote_hello: Arc::new(remote.clone()),
            selected_protocol_version: PROTOCOL_VERSION_V1,
            session_id: [0; 32],
        };
        let cloned = peer.clone();
        assert!(Arc::ptr_eq(&peer.local_hello, &cloned.local_hello));
        assert!(Arc::ptr_eq(&peer.remote_hello, &cloned.remote_hello));
        // Content equality is preserved (Arc's PartialEq dereferences).
        assert_eq!(peer, cloned);
    }

    #[test]
    fn message_identity_validation_rejects_spoofed_sources_and_destinations() {
        let remote = hello(20);
        let peer = AdmittedPeer {
            transport_identity: identity(&remote),
            local_hello: Arc::new(hello(1)),
            remote_hello: Arc::new(remote),
            selected_protocol_version: PROTOCOL_VERSION_V1,
            session_id: [0; 32],
        };
        let spoofed_input = input(1);
        assert!(matches!(
            validate_message_identity(&spoofed_input, &peer),
            Err(SessionError::MessageIdentityMismatch(MessageType::Input))
        ));

        let mut wrong_destination = privileged_messages()
            .into_iter()
            .find(|message| message.message_type() == MessageType::PointerEnter)
            .unwrap();
        if let WireMessage::PointerEnter(pointer) = &mut wrong_destination {
            pointer.source_host = peer.transport_identity.host_id;
            pointer.destination_host = WireHostId([99; 16]);
        }
        assert!(matches!(
            validate_message_identity(&wrong_destination, &peer),
            Err(SessionError::MessageIdentityMismatch(
                MessageType::PointerEnter
            ))
        ));

        let mut wrong_commit = privileged_messages()
            .into_iter()
            .find(|message| message.message_type() == MessageType::PointerTransitionCommit)
            .unwrap();
        if let WireMessage::PointerTransitionCommit(commit) = &mut wrong_commit {
            commit.source_host = peer.transport_identity.host_id;
            commit.destination_host = WireHostId([99; 16]);
        }
        assert!(matches!(
            validate_message_identity(&wrong_commit, &peer),
            Err(SessionError::MessageIdentityMismatch(
                MessageType::PointerTransitionCommit
            ))
        ));

        if let WireMessage::PointerTransitionCommit(commit) = &mut wrong_commit {
            commit.source_host = WireHostId([98; 16]);
            commit.destination_host = peer.local_hello.host_id;
        }
        assert!(matches!(
            validate_message_identity(&wrong_commit, &peer),
            Err(SessionError::MessageIdentityMismatch(
                MessageType::PointerTransitionCommit
            ))
        ));
    }

    #[test]
    fn v2_release_proof_is_bound_to_authenticated_source_and_applying_hosts() {
        let remote = hello(20);
        let peer = AdmittedPeer {
            transport_identity: identity(&remote),
            local_hello: Arc::new(hello(1)),
            remote_hello: Arc::new(remote),
            selected_protocol_version: PROTOCOL_VERSION_V2,
            session_id: [6; 32],
        };
        let WireMessage::ReleaseInputV2(mut release) = release_v2(2) else {
            unreachable!()
        };
        release.source_host = peer.transport_identity.host_id;
        release.applying_host = peer.local_hello.host_id;
        assert!(
            validate_message_identity(&WireMessage::ReleaseInputV2(release.clone()), &peer).is_ok()
        );
        release.applying_host = WireHostId([99; 16]);
        assert!(matches!(
            validate_message_identity(&WireMessage::ReleaseInputV2(release), &peer),
            Err(SessionError::MessageIdentityMismatch(
                MessageType::ReleaseInputV2
            ))
        ));

        let mut acknowledgement = ReleaseAppliedAckV2 {
            transaction_id: 1,
            release_token: [4; 32],
            old_session_id: [5; 32],
            sequence: 3,
            release_sequence: 2,
            covered_input_sequence: 1,
            source_host: peer.local_hello.host_id,
            applying_host: peer.transport_identity.host_id,
        };
        assert!(validate_message_identity(
            &WireMessage::ReleaseAppliedAckV2(acknowledgement),
            &peer,
        )
        .is_ok());
        acknowledgement.source_host = WireHostId([98; 16]);
        assert!(matches!(
            validate_message_identity(&WireMessage::ReleaseAppliedAckV2(acknowledgement), &peer,),
            Err(SessionError::MessageIdentityMismatch(
                MessageType::ReleaseAppliedAckV2
            ))
        ));
    }

    #[test]
    fn persistent_config_validation_is_fallible_and_complete() {
        let mut invalid_queue = test_config();
        invalid_queue.queue.input = 0;
        assert!(invalid_queue.validate().is_err());

        let mut invalid_heartbeat = test_config();
        invalid_heartbeat.heartbeat.disconnect_after = invalid_heartbeat.heartbeat.degraded_after;
        assert!(invalid_heartbeat.validate().is_err());

        let mut invalid_reconnect = test_config();
        invalid_reconnect.reconnect.multiplier = 0;
        assert!(invalid_reconnect.validate().is_err());

        let mut invalid_timeout = test_config();
        invalid_timeout.admission_timeout = Duration::ZERO;
        assert!(invalid_timeout.validate().is_err());
        assert!(test_config().validate().is_ok());
    }

    #[test]
    fn producer_channel_backpressure_is_visible_by_traffic_lane() {
        let config = PersistentPeerConfig {
            outbound_channel_capacity: 1,
            ..test_config()
        };
        let (session, sender, _events) =
            SecurePeerSession::new(TestAdmission { hello: hello(1) }, config).unwrap();
        let observable = session.observable_stats();
        sender
            .try_send(WireMessage::Ping(kvm_protocol::PingV1 {
                nonce: 1,
                sent_at_ns: 1,
            }))
            .unwrap();
        assert!(matches!(
            sender.try_send(WireMessage::Ping(kvm_protocol::PingV1 {
                nonce: 2,
                sent_at_ns: 2,
            })),
            Err(OutboundSendError::Full(_))
        ));

        assert_eq!(
            observable.telemetry_snapshot().channel_rejections.control,
            1
        );
    }

    #[test]
    fn exporter_context_is_canonical_and_sender_direction_bound() {
        let lower = hello(1);
        let higher = hello(20);
        let lower_sender =
            authentication_exporter_context(&lower, &higher, lower.peer_id, PROTOCOL_VERSION_V1)
                .unwrap();
        let reversed_view =
            authentication_exporter_context(&higher, &lower, lower.peer_id, PROTOCOL_VERSION_V1)
                .unwrap();
        let higher_sender =
            authentication_exporter_context(&lower, &higher, higher.peer_id, PROTOCOL_VERSION_V1)
                .unwrap();

        assert_eq!(lower_sender, reversed_view);
        assert_ne!(lower_sender, higher_sender);
    }

    #[test]
    fn negotiation_selects_highest_overlap_and_rejects_no_overlap() {
        let v1 = hello_with_versions(1, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V1);
        let v1_to_v2 = hello_with_versions(20, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let v2 = hello_with_versions(40, PROTOCOL_VERSION_V2, PROTOCOL_VERSION_V2);

        assert_eq!(
            negotiate_protocol_version(&v1, &v1).unwrap(),
            PROTOCOL_VERSION_V1
        );
        assert_eq!(
            negotiate_protocol_version(&v1_to_v2, &v1).unwrap(),
            PROTOCOL_VERSION_V1
        );
        assert_eq!(
            negotiate_protocol_version(&v1_to_v2, &v1_to_v2).unwrap(),
            PROTOCOL_VERSION_V2
        );
        assert!(matches!(
            negotiate_protocol_version(&v1, &v2),
            Err(SessionError::NoCompatibleProtocolVersion)
        ));
    }

    #[test]
    fn selected_version_changes_authentication_and_session_binding_contexts() {
        let local = hello_with_versions(1, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let remote = hello_with_versions(20, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let auth_v1 =
            authentication_exporter_context(&local, &remote, local.peer_id, PROTOCOL_VERSION_V1)
                .unwrap();
        let auth_v2 =
            authentication_exporter_context(&local, &remote, local.peer_id, PROTOCOL_VERSION_V2)
                .unwrap();
        let session_v1 = session_exporter_context(&local, &remote, PROTOCOL_VERSION_V1).unwrap();
        let session_v2 = session_exporter_context(&local, &remote, PROTOCOL_VERSION_V2).unwrap();

        assert_ne!(auth_v1, auth_v2);
        assert_ne!(session_v1, session_v2);
        assert_eq!(
            session_v2,
            session_exporter_context(&remote, &local, PROTOCOL_VERSION_V2).unwrap()
        );
    }

    #[test]
    fn v1_session_rejects_v2_only_release_before_any_write() {
        let mut queue = OutboundQueue::default();
        queue.try_push(release_v2(2)).unwrap();
        let error =
            PendingFrame::encode_batch(&mut queue, PROTOCOL_VERSION_V1, PendingFrame::default())
                .unwrap_err();

        assert!(matches!(
            error,
            SessionError::Network(NetworkError::Protocol(
                kvm_protocol::ProtocolError::MessageVersionMismatch {
                    message_type: MessageType::ReleaseInputV2,
                    version: PROTOCOL_VERSION_V1,
                }
            ))
        ));
        // The un-encodable frame is returned to the queue, not silently lost.
        assert!(!queue.is_empty());
    }

    // --- outbound write batching (spec §37 latency) ---

    fn distinct_move(device: u8, sequence: u64) -> WireMessage {
        WireMessage::Input(InputEventV1 {
            sequence,
            timestamp_ns: sequence,
            source_host: WireHostId([7; 16]),
            source_device: WireDeviceId([device; 16]),
            payload: WireInputPayloadV1::PointerMove { dx: 1.0, dy: 2.0 },
        })
    }

    fn batch_queue() -> OutboundQueue {
        // Coalescing off so every queued move stays a distinct frame; the
        // batching under test is the write-batch, not pointer-move coalescing.
        OutboundQueue::new(QueueConfig {
            coalesce_pointer_moves: false,
            ..QueueConfig::default()
        })
    }

    #[test]
    fn encode_batch_concatenates_every_queued_frame() {
        let mut queue = batch_queue();
        let messages = [
            distinct_move(2, 1),
            distinct_move(3, 2),
            distinct_move(4, 3),
        ];
        for message in &messages {
            queue.try_push(message.clone()).unwrap();
        }

        let batch =
            PendingFrame::encode_batch(&mut queue, PROTOCOL_VERSION_V1, PendingFrame::default())
                .expect("encode");
        assert!(queue.is_empty());
        assert_eq!(batch.frames.len(), 3);
        assert_eq!(batch.committed, 0);
        assert!(!batch.is_complete());

        // The batch buffer is exactly the concatenation of the individually
        // encoded frames — one progressive write carries all three.
        let mut expected = Vec::new();
        for message in &messages {
            expected.extend_from_slice(
                &encode_frame_for_version(message, PROTOCOL_VERSION_V1).unwrap(),
            );
        }
        assert_eq!(batch.bytes, expected);

        // Frame end offsets strictly increase and land on the buffer length.
        let mut cursor = 0_usize;
        for (_, end) in &batch.frames {
            assert!(*end > cursor);
            cursor = *end;
        }
        assert_eq!(cursor, batch.bytes.len());
    }

    #[test]
    fn encode_batch_byte_cap_unpops_the_overflow_frame() {
        let mut queue = batch_queue();
        // Two ~40 KiB background frames: the first is always included (empty
        // batch); the second would exceed OUTBOUND_BATCH_MAX_BYTES and is
        // returned to the front of its lane for the next batch.
        let big = |update_byte: u8, sequence: u64| {
            WireMessage::Clipboard(ClipboardV1 {
                update_id: WireClipboardId([update_byte; 16]),
                origin_host: WireHostId([7; 16]),
                sequence,
                text: "x".repeat(40_000),
            })
        };
        queue.try_push(big(1, 1)).unwrap();
        queue.try_push(big(2, 2)).unwrap();

        let batch =
            PendingFrame::encode_batch(&mut queue, PROTOCOL_VERSION_V1, PendingFrame::default())
                .expect("encode");
        assert_eq!(batch.frames.len(), 1);
        assert_eq!(queue.len(), 1); // overflow frame preserved, not lost
    }

    #[test]
    fn encode_batch_of_empty_queue_yields_an_empty_reusable_frame() {
        let mut queue = batch_queue();
        let batch =
            PendingFrame::encode_batch(&mut queue, PROTOCOL_VERSION_V1, PendingFrame::default())
                .expect("encode");
        assert!(batch.frames.is_empty());
        assert!(batch.bytes.is_empty());
    }

    #[test]
    fn encode_batch_reuses_the_caller_buffer_without_leaking_prior_frames() {
        let mut queue = batch_queue();
        // First batch: three frames.
        for sequence in 1_u64..=3 {
            queue.try_push(distinct_move(2, sequence)).unwrap();
        }
        let first =
            PendingFrame::encode_batch(&mut queue, PROTOCOL_VERSION_V1, PendingFrame::default())
                .expect("encode");
        let first_len = first.bytes.len();
        let retained_capacity = first.bytes.capacity();
        assert_eq!(first.frames.len(), 3);
        assert_eq!(first.committed, 0);

        // Second batch into the SAME allocation: one frame. The buffer must be
        // cleared (not appended to), committed reset, and capacity retained.
        queue.try_push(distinct_move(3, 4)).unwrap();
        let second =
            PendingFrame::encode_batch(&mut queue, PROTOCOL_VERSION_V1, first).expect("encode");
        assert_eq!(second.frames.len(), 1);
        assert_eq!(second.committed, 0);
        // Holds only the one new frame, not the prior three.
        assert!(second.bytes.len() < first_len);
        // Capacity carried over (Vec never shrinks on clear).
        assert_eq!(second.bytes.capacity(), retained_capacity);
    }

    #[test]
    fn encode_batch_reserves_buffer_capacity_proportional_to_queue_depth() {
        // A cold (default) buffer encodes a multi-frame burst into a single
        // allocation: both Vecs are pre-sized to the batch's frame budget so the
        // burst does not grow the buffer frame-by-frame as each append crosses a
        // power of two.
        let mut queue = batch_queue();
        let n = 24_usize;
        for sequence in 1_u64..=n as u64 {
            queue
                .try_push(distinct_move((sequence % 7) as u8 + 2, sequence))
                .unwrap();
        }
        let frame_budget = n.min(OUTBOUND_BATCH_MAX_FRAMES);

        let batch =
            PendingFrame::encode_batch(&mut queue, PROTOCOL_VERSION_V1, PendingFrame::default())
                .expect("encode");

        // The reservation guaranteed at least this much capacity before encoding
        // began, and the actual burst fit within it (input frames are smaller
        // than the estimate), so no per-frame reallocation was needed.
        let reserved = frame_budget * OUTBOUND_BATCH_FRAME_BYTES_ESTIMATE;
        assert!(
            batch.bytes.capacity() >= reserved,
            "capacity {} should cover the reserved {} bytes",
            batch.bytes.capacity(),
            reserved
        );
        assert!(batch.bytes.len() <= batch.bytes.capacity());
        assert_eq!(batch.frames.len(), n);
        assert!(
            batch.frames.capacity() >= frame_budget,
            "frames capacity {} should cover the frame budget {}",
            batch.frames.capacity(),
            frame_budget
        );

        // Every input frame was smaller than the estimate, so the whole burst
        // fit inside the reservation with no growth beyond it — i.e. one
        // allocation, not log(n) of them.
        assert!(batch.bytes.len() <= reserved);
    }

    #[test]
    fn exporter_context_changes_with_the_complete_hello_transcript() {
        let local = hello(1);
        let remote = hello(20);
        let original =
            authentication_exporter_context(&local, &remote, local.peer_id, PROTOCOL_VERSION_V1)
                .unwrap();
        let mut modified = remote.clone();
        modified.nonce[0] ^= 1;
        let modified_context =
            authentication_exporter_context(&local, &modified, local.peer_id, PROTOCOL_VERSION_V1)
                .unwrap();
        let original_session =
            session_exporter_context(&local, &remote, PROTOCOL_VERSION_V1).unwrap();
        let modified_session =
            session_exporter_context(&local, &modified, PROTOCOL_VERSION_V1).unwrap();

        assert_ne!(original, modified_context);
        assert_ne!(original_session, modified_session);
        let stream = TestSecureStream {
            stream: tokio::io::duplex(1).0,
            identity: identity(&remote),
        };
        assert_ne!(
            stream
                .export_keying_material(AUTHENTICATION_EXPORTER_LABEL, &original)
                .unwrap(),
            stream
                .export_keying_material(AUTHENTICATION_EXPORTER_LABEL, &modified_context)
                .unwrap()
        );
        assert_ne!(
            stream
                .export_keying_material(SESSION_ID_EXPORTER_LABEL, &original_session)
                .unwrap(),
            stream
                .export_keying_material(SESSION_ID_EXPORTER_LABEL, &modified_session)
                .unwrap()
        );
    }

    #[test]
    fn exporter_context_rejects_equal_peer_ids() {
        let local = hello(1);
        let mut remote = hello(20);
        remote.peer_id = local.peer_id;

        assert!(matches!(
            authentication_exporter_context(&local, &remote, local.peer_id, PROTOCOL_VERSION_V1,),
            Err(SessionError::PeerIdentityCollision)
        ));
    }

    #[test]
    fn zero_exporter_session_binding_fails_closed() {
        let local = hello_with_versions(1, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let remote = hello_with_versions(20, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let (stream, _peer) = tokio::io::duplex(64);
        let secure = ZeroExporterSecureStream(TestSecureStream {
            stream,
            identity: identity(&remote),
        });

        assert!(matches!(
            build_handshake_transcript(
                &secure,
                local,
                remote.clone(),
                identity(&remote),
                PROTOCOL_VERSION_V2,
            ),
            Err(SessionError::InvalidSessionBinding)
        ));
    }

    #[tokio::test]
    async fn equal_peer_ids_are_rejected_before_authenticate() {
        let local_hello = hello(1);
        let mut remote_hello = hello(20);
        remote_hello.peer_id = local_hello.peer_id;
        let (session_stream, peer_stream) = tokio::io::duplex(4_096);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let admission = TestAdmission { hello: local_hello };
        let (_outbound_sender, mut outbound) = mpsc::channel(8);
        let (events, _event_receiver) = mpsc::channel(8);
        let (_shutdown_sender, mut shutdown) = watch::channel(false);

        let session = run_session(
            secure_stream,
            &admission,
            test_config(),
            &mut outbound,
            &events,
            &mut shutdown,
        );
        let peer = async move {
            let (read, _write) = tokio::io::split(peer_stream);
            let mut reader = FrameReader::new_authenticated(read);
            assert!(reader.read_message().await.is_err());
        };

        let (result, ()) = tokio::join!(session, peer);
        assert!(matches!(
            result,
            Err(SessionFailure {
                error: SessionError::PeerIdentityCollision,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn rejects_all_privileged_traffic_before_admission() {
        for message in privileged_messages() {
            let local_hello = hello(1);
            let remote_hello = hello(20);
            let (session_stream, attacker_stream) = tokio::io::duplex(4_096);
            let secure_stream = TestSecureStream {
                stream: session_stream,
                identity: identity(&remote_hello),
            };
            let admission = TestAdmission { hello: local_hello };
            let (_outbound_sender, mut outbound) = mpsc::channel(8);
            let (events, _event_receiver) = mpsc::channel(8);
            let (_shutdown_sender, mut shutdown) = watch::channel(false);
            let expected_type = message.message_type();

            let session = run_session(
                secure_stream,
                &admission,
                test_config(),
                &mut outbound,
                &events,
                &mut shutdown,
            );
            let attacker = async move {
                let (read, write) = tokio::io::split(attacker_stream);
                let mut reader = FrameReader::new_authenticated(read);
                let mut writer = FrameWriter::new_authenticated(write);
                assert!(matches!(
                    reader.read_message().await.unwrap(),
                    WireMessage::Hello(_)
                ));
                writer.write_message(&message).await.unwrap();
            };

            let (result, ()) = tokio::join!(session, attacker);
            assert!(matches!(
                result,
                Err(SessionFailure {
                    error: SessionError::PreAdmissionMessage(kind),
                    ..
                }) if kind == expected_type
            ));
        }
    }

    #[tokio::test]
    async fn admitted_session_prioritizes_input_without_reordering_it() {
        let local_hello = hello(1);
        let remote_hello = hello(20);
        let (session_stream, peer_stream) = tokio::io::duplex(8_192);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let admission = TestAdmission {
            hello: local_hello.clone(),
        };
        let (outbound_sender, mut outbound) = mpsc::channel(8);
        let (events, _event_receiver) = mpsc::channel(16);
        let (shutdown_sender, mut shutdown) = watch::channel(false);

        let background = privileged_messages()[1].clone();
        let first_input = privileged_messages()[0].clone();
        let mut second_input = first_input.clone();
        if let WireMessage::Input(input) = &mut second_input {
            input.sequence = 2;
            // Distinct source device so the two moves represent independent
            // streams and are not pointer-move-coalesced (spec §23); the test
            // exercises ordering, not coalescing.
            input.source_device = WireDeviceId([10; 16]);
        }
        outbound_sender.send(background.clone()).await.unwrap();
        outbound_sender.send(first_input.clone()).await.unwrap();
        outbound_sender.send(second_input.clone()).await.unwrap();

        let session = run_session(
            secure_stream,
            &admission,
            test_config(),
            &mut outbound,
            &events,
            &mut shutdown,
        );
        let peer = async move {
            let (read, write) = tokio::io::split(peer_stream);
            let mut reader = FrameReader::new_authenticated(read);
            let mut writer = FrameWriter::new_authenticated(write);
            let received_hello = match reader.read_message().await.unwrap() {
                WireMessage::Hello(hello) => hello,
                other => panic!("expected hello, got {other:?}"),
            };
            writer
                .write_message(&WireMessage::Hello(remote_hello.clone()))
                .await
                .unwrap();
            let local_auth = reader.read_message().await.unwrap();
            assert!(matches!(local_auth, WireMessage::Authenticate(_)));
            writer
                .write_message(&WireMessage::Authenticate(AuthenticateV1 {
                    peer_id: remote_hello.peer_id,
                    scheme: "test-channel-binding-v1".to_owned(),
                    proof: received_hello.nonce.to_vec(),
                }))
                .await
                .unwrap();

            assert_eq!(reader.read_message().await.unwrap(), first_input);
            assert_eq!(reader.read_message().await.unwrap(), second_input);
            assert_eq!(reader.read_message().await.unwrap(), background);
            shutdown_sender.send(true).unwrap();
        };

        let (result, ()) = tokio::join!(session, peer);
        assert_eq!(result.unwrap(), SessionEnd::Shutdown);
    }

    /// A live session publishes outbound-queue diagnostics (here: §23 coalesced
    /// moves) to the shared observable on the heartbeat tick, so a pull-model
    /// reader can observe the happy path — not only the forensic Disconnect
    /// report from iteration 7.
    #[tokio::test(start_paused = true)]
    async fn live_observable_publishes_coalesced_moves_on_the_heartbeat_tick() {
        let local_hello = hello(1);
        let remote_hello = hello(20);
        let (session_stream, peer_stream) = tokio::io::duplex(8_192);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let admission = TestAdmission {
            hello: local_hello.clone(),
        };
        let (outbound_sender, mut outbound) = mpsc::channel(8);
        let (events, _event_receiver) = mpsc::channel(16);
        let (shutdown_sender, mut shutdown) = watch::channel(false);

        // Two same-source PointerMove frames: the second folds into the first
        // (deltas summed) when the session drains both into the queue before its
        // first encode, yielding one coalesced move.
        let source_host = local_hello.host_id;
        let source_device = WireDeviceId([9; 16]);
        let first_move = WireMessage::Input(InputEventV1 {
            sequence: 1,
            timestamp_ns: 1,
            source_host,
            source_device,
            payload: WireInputPayloadV1::PointerMove { dx: 1.0, dy: 2.0 },
        });
        let mut second_move = first_move.clone();
        if let WireMessage::Input(input) = &mut second_move {
            input.sequence = 2;
            input.timestamp_ns = 2;
        }
        outbound_sender.send(first_move).await.unwrap();
        outbound_sender.send(second_move).await.unwrap();

        let config = PersistentPeerConfig {
            heartbeat: HeartbeatConfig {
                interval: Duration::from_millis(10),
                degraded_after: Duration::from_secs(1),
                disconnect_after: Duration::from_secs(2),
                maximum_outstanding_pings: 8,
            },
            ..test_config()
        };
        let observable = ObservableSessionStats::default();
        let session = run_session_with_stats(
            secure_stream,
            &admission,
            config,
            &mut outbound,
            &events,
            &mut shutdown,
            Some(&observable),
        );
        let peer = async move {
            let (read, write) = tokio::io::split(peer_stream);
            let mut reader = FrameReader::new_authenticated(read);
            let mut writer = FrameWriter::new_authenticated(write);
            let received_hello = match reader.read_message().await.unwrap() {
                WireMessage::Hello(hello) => hello,
                other => panic!("expected hello, got {other:?}"),
            };
            writer
                .write_message(&WireMessage::Hello(remote_hello.clone()))
                .await
                .unwrap();
            assert!(matches!(
                reader.read_message().await.unwrap(),
                WireMessage::Authenticate(_)
            ));
            writer
                .write_message(&WireMessage::Authenticate(AuthenticateV1 {
                    peer_id: remote_hello.peer_id,
                    scheme: "test-channel-binding-v1".to_owned(),
                    proof: received_hello.nonce.to_vec(),
                }))
                .await
                .unwrap();

            // Read the single coalesced move, then advance time past the
            // heartbeat interval and yield so the session's heartbeat-tick arm
            // fires and publishes the live snapshot BEFORE shutdown. (The select
            // is biased with shutdown ahead of the heartbeat, so the publish
            // must complete before the shutdown signal lands.)
            let received = reader.read_message().await.unwrap();
            assert!(matches!(received, WireMessage::Input(_)));
            tokio::time::advance(Duration::from_millis(20)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            shutdown_sender.send(true).unwrap();
        };

        let (result, ()) = tokio::join!(session, peer);
        assert_eq!(result.unwrap(), SessionEnd::Shutdown);

        // The coalesced move was published to the live observable.
        let snapshot = observable.snapshot();
        assert_eq!(
            snapshot.coalesced_moves, 1,
            "live observable must reflect the single coalesced move"
        );
        let telemetry = observable.telemetry_snapshot();
        assert!(telemetry.outbound_frames >= 1);
        assert!(telemetry.outbound_bytes > 0);
    }

    #[tokio::test]
    async fn v2_peers_authenticate_and_exchange_only_v2_application_frames() {
        let local_hello = hello_with_versions(1, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let remote_hello = hello_with_versions(20, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let (session_stream, mut peer_stream) = tokio::io::duplex(8_192);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let admission = TestAdmission {
            hello: local_hello.clone(),
        };
        let (_outbound_sender, mut outbound) = mpsc::channel(8);
        let (events, mut event_receiver) = mpsc::channel(16);
        let (shutdown_sender, mut shutdown) = watch::channel(false);

        let session = run_session(
            secure_stream,
            &admission,
            test_config(),
            &mut outbound,
            &events,
            &mut shutdown,
        );
        let peer = async move {
            let received_hello =
                match read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V1)
                    .await
                    .unwrap()
                {
                    WireMessage::Hello(hello) => hello,
                    other => panic!("expected hello, got {other:?}"),
                };
            assert_eq!(received_hello.minimum_protocol_version, PROTOCOL_VERSION_V1);
            assert_eq!(received_hello.maximum_protocol_version, PROTOCOL_VERSION_V2);
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Hello(remote_hello.clone()),
                PROTOCOL_VERSION_V1,
            )
            .await;
            assert!(matches!(
                read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V2)
                    .await
                    .unwrap(),
                WireMessage::Authenticate(_)
            ));
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Authenticate(AuthenticateV1 {
                    peer_id: remote_hello.peer_id,
                    scheme: "test-channel-binding-v1".to_owned(),
                    proof: received_hello.nonce.to_vec(),
                }),
                PROTOCOL_VERSION_V2,
            )
            .await;
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Ping(kvm_protocol::PingV1 {
                    nonce: 91,
                    sent_at_ns: 92,
                }),
                PROTOCOL_VERSION_V2,
            )
            .await;
            assert!(matches!(
                read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V2)
                    .await
                    .unwrap(),
                WireMessage::Pong(_)
            ));
            shutdown_sender.send(true).unwrap();
        };

        let (result, ()) = tokio::join!(session, peer);
        assert_eq!(result.unwrap(), SessionEnd::Shutdown);
        let admitted = std::iter::from_fn(|| event_receiver.try_recv().ok()).find_map(|event| {
            if let PeerEvent::Admitted(peer) = event {
                Some(peer)
            } else {
                None
            }
        });
        let admitted = admitted.expect("admission event");
        assert_eq!(admitted.selected_protocol_version(), PROTOCOL_VERSION_V2);
        assert!(admitted.supports_release_proof());
        assert_ne!(admitted.session_id(), [0; 32]);
        assert_eq!(format!("{admitted:?}"), "AdmittedPeer([REDACTED])");
    }

    #[tokio::test]
    async fn mixed_v1_v2_peers_fall_back_to_v1() {
        let local_hello = hello_with_versions(1, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let remote_hello = hello(20);
        let (session_stream, mut peer_stream) = tokio::io::duplex(4_096);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let admission = TestAdmission { hello: local_hello };
        let (_outbound_sender, mut outbound) = mpsc::channel(8);
        let (events, mut event_receiver) = mpsc::channel(16);
        let (shutdown_sender, mut shutdown) = watch::channel(false);

        let session = run_session(
            secure_stream,
            &admission,
            test_config(),
            &mut outbound,
            &events,
            &mut shutdown,
        );
        let peer = async move {
            let local = match read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V1)
                .await
                .unwrap()
            {
                WireMessage::Hello(hello) => hello,
                other => panic!("expected hello, got {other:?}"),
            };
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Hello(remote_hello.clone()),
                PROTOCOL_VERSION_V1,
            )
            .await;
            assert!(matches!(
                read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V1)
                    .await
                    .unwrap(),
                WireMessage::Authenticate(_)
            ));
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Authenticate(AuthenticateV1 {
                    peer_id: remote_hello.peer_id,
                    scheme: "test-channel-binding-v1".to_owned(),
                    proof: local.nonce.to_vec(),
                }),
                PROTOCOL_VERSION_V1,
            )
            .await;
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Ping(kvm_protocol::PingV1 {
                    nonce: 81,
                    sent_at_ns: 82,
                }),
                PROTOCOL_VERSION_V1,
            )
            .await;
            assert!(matches!(
                read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V1)
                    .await
                    .unwrap(),
                WireMessage::Pong(_)
            ));
            shutdown_sender.send(true).unwrap();
        };

        let (result, ()) = tokio::join!(session, peer);
        assert_eq!(result.unwrap(), SessionEnd::Shutdown);
        assert!(
            std::iter::from_fn(|| event_receiver.try_recv().ok()).any(|event| {
                matches!(
                    event,
                    PeerEvent::Admitted(peer)
                        if peer.selected_protocol_version() == PROTOCOL_VERSION_V1
                            && !peer.supports_release_proof()
                )
            })
        );
    }

    #[tokio::test]
    async fn admission_rejects_non_overlapping_protocol_ranges() {
        let local_hello = hello(1);
        let remote_hello = hello_with_versions(20, PROTOCOL_VERSION_V2, PROTOCOL_VERSION_V2);
        let (session_stream, mut peer_stream) = tokio::io::duplex(4_096);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let admission = TestAdmission { hello: local_hello };
        let (_outbound_sender, mut outbound) = mpsc::channel(8);
        let (events, _event_receiver) = mpsc::channel(8);
        let (_shutdown_sender, mut shutdown) = watch::channel(false);

        let session = run_session(
            secure_stream,
            &admission,
            test_config(),
            &mut outbound,
            &events,
            &mut shutdown,
        );
        let peer = async move {
            assert!(matches!(
                read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V1)
                    .await
                    .unwrap(),
                WireMessage::Hello(_)
            ));
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Hello(remote_hello),
                PROTOCOL_VERSION_V1,
            )
            .await;
        };

        let (result, ()) = tokio::join!(session, peer);
        assert!(matches!(
            result,
            Err(SessionFailure {
                error: SessionError::NoCompatibleProtocolVersion,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn bootstrap_rejects_header_only_wrong_version_or_v2_message() {
        let headers = [
            FrameHeader {
                protocol_version: PROTOCOL_VERSION_V2,
                message_type: MessageType::Hello,
                payload_length: u32::try_from(kvm_protocol::MAX_FRAME_PAYLOAD).unwrap(),
            },
            FrameHeader {
                protocol_version: PROTOCOL_VERSION_V1,
                message_type: MessageType::ReleaseInputV2,
                payload_length: u32::try_from(kvm_protocol::MAX_FRAME_PAYLOAD).unwrap(),
            },
        ];

        for malicious_header in headers {
            let local_hello = hello(1);
            let remote_hello = hello(20);
            let (session_stream, mut peer_stream) = tokio::io::duplex(4_096);
            let secure_stream = TestSecureStream {
                stream: session_stream,
                identity: identity(&remote_hello),
            };
            let admission = TestAdmission { hello: local_hello };
            let (_outbound_sender, mut outbound) = mpsc::channel(8);
            let (events, _event_receiver) = mpsc::channel(8);
            let (_shutdown_sender, mut shutdown) = watch::channel(false);

            let session = run_session(
                secure_stream,
                &admission,
                test_config(),
                &mut outbound,
                &events,
                &mut shutdown,
            );
            let peer = async move {
                assert!(matches!(
                    read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V1)
                        .await
                        .unwrap(),
                    WireMessage::Hello(_)
                ));
                peer_stream
                    .write_all(&malicious_header.encode())
                    .await
                    .unwrap();
                peer_stream.flush().await.unwrap();
            };

            let (result, ()) = tokio::join!(session, peer);
            assert!(matches!(
                result,
                Err(SessionFailure {
                    error: SessionError::Network(NetworkError::Protocol(_)),
                    ..
                })
            ));
        }
    }

    #[tokio::test]
    async fn selected_v2_rejects_v1_authenticate_frame() {
        let local_hello = hello_with_versions(1, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let remote_hello = hello_with_versions(20, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let (session_stream, mut peer_stream) = tokio::io::duplex(4_096);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let admission = TestAdmission { hello: local_hello };
        let (_outbound_sender, mut outbound) = mpsc::channel(8);
        let (events, _event_receiver) = mpsc::channel(8);
        let (_shutdown_sender, mut shutdown) = watch::channel(false);

        let session = run_session(
            secure_stream,
            &admission,
            test_config(),
            &mut outbound,
            &events,
            &mut shutdown,
        );
        let peer = async move {
            let local = match read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V1)
                .await
                .unwrap()
            {
                WireMessage::Hello(hello) => hello,
                other => panic!("expected hello, got {other:?}"),
            };
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Hello(remote_hello.clone()),
                PROTOCOL_VERSION_V1,
            )
            .await;
            assert!(matches!(
                read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V2)
                    .await
                    .unwrap(),
                WireMessage::Authenticate(_)
            ));
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Authenticate(AuthenticateV1 {
                    peer_id: remote_hello.peer_id,
                    scheme: "test-channel-binding-v1".to_owned(),
                    proof: local.nonce.to_vec(),
                }),
                PROTOCOL_VERSION_V1,
            )
            .await;
        };

        let (result, ()) = tokio::join!(session, peer);
        assert!(matches!(
            result,
            Err(SessionFailure {
                error: SessionError::Network(NetworkError::Protocol(_)),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn selected_v2_rejects_v1_application_frame() {
        let local_hello = hello_with_versions(1, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let remote_hello = hello_with_versions(20, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2);
        let (session_stream, mut peer_stream) = tokio::io::duplex(4_096);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let admission = TestAdmission { hello: local_hello };
        let (_outbound_sender, mut outbound) = mpsc::channel(8);
        let (events, _event_receiver) = mpsc::channel(8);
        let (_shutdown_sender, mut shutdown) = watch::channel(false);

        let session = run_session(
            secure_stream,
            &admission,
            test_config(),
            &mut outbound,
            &events,
            &mut shutdown,
        );
        let peer = async move {
            let local = match read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V1)
                .await
                .unwrap()
            {
                WireMessage::Hello(hello) => hello,
                other => panic!("expected hello, got {other:?}"),
            };
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Hello(remote_hello.clone()),
                PROTOCOL_VERSION_V1,
            )
            .await;
            assert!(matches!(
                read_message_for_version(&mut peer_stream, PROTOCOL_VERSION_V2)
                    .await
                    .unwrap(),
                WireMessage::Authenticate(_)
            ));
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Authenticate(AuthenticateV1 {
                    peer_id: remote_hello.peer_id,
                    scheme: "test-channel-binding-v1".to_owned(),
                    proof: local.nonce.to_vec(),
                }),
                PROTOCOL_VERSION_V2,
            )
            .await;
            write_test_message_for_version(
                &mut peer_stream,
                &WireMessage::Ping(kvm_protocol::PingV1 {
                    nonce: 51,
                    sent_at_ns: 52,
                }),
                PROTOCOL_VERSION_V1,
            )
            .await;
        };

        let (result, ()) = tokio::join!(session, peer);
        assert!(matches!(
            result,
            Err(SessionFailure {
                error: SessionError::Network(NetworkError::Protocol(_)),
                ..
            })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn partial_pending_writes_survive_inbound_and_heartbeat_branches() {
        let local_hello = hello(1);
        let remote_hello = hello(20);
        let (session_stream, peer_stream) = tokio::io::duplex(8_192);
        let secure_stream = PartialPendingSecureStream {
            inner: TestSecureStream {
                stream: session_stream,
                identity: identity(&remote_hello),
            },
            maximum_chunk: 3,
            pending_next: false,
        };
        let admission = TestAdmission {
            hello: local_hello.clone(),
        };
        let (outbound_sender, mut outbound) = mpsc::channel(8);
        let (events, _event_receiver) = mpsc::channel(32);
        let (shutdown_sender, mut shutdown) = watch::channel(false);
        let expected = WireMessage::Clipboard(ClipboardV1 {
            update_id: WireClipboardId([42; 16]),
            origin_host: local_hello.host_id,
            sequence: 7,
            text: "partial-frame-regression".repeat(20),
        });
        outbound_sender.send(expected.clone()).await.unwrap();
        let config = PersistentPeerConfig {
            heartbeat: HeartbeatConfig {
                interval: Duration::from_millis(10),
                degraded_after: Duration::from_secs(1),
                disconnect_after: Duration::from_secs(2),
                maximum_outstanding_pings: 8,
            },
            ..test_config()
        };
        let session = run_session(
            secure_stream,
            &admission,
            config,
            &mut outbound,
            &events,
            &mut shutdown,
        );
        let peer = async move {
            let (read, write) = tokio::io::split(peer_stream);
            let mut reader = FrameReader::new_authenticated(read);
            let mut writer = FrameWriter::new_authenticated(write);
            let received_hello = match reader.read_message().await.unwrap() {
                WireMessage::Hello(hello) => hello,
                other => panic!("expected hello, got {other:?}"),
            };
            writer
                .write_message(&WireMessage::Hello(remote_hello.clone()))
                .await
                .unwrap();
            assert!(matches!(
                reader.read_message().await.unwrap(),
                WireMessage::Authenticate(_)
            ));
            writer
                .write_message(&WireMessage::Authenticate(AuthenticateV1 {
                    peer_id: remote_hello.peer_id,
                    scheme: "test-channel-binding-v1".to_owned(),
                    proof: received_hello.nonce.to_vec(),
                }))
                .await
                .unwrap();

            writer
                .write_message(&WireMessage::Ping(kvm_protocol::PingV1 {
                    nonce: 99,
                    sent_at_ns: 123,
                }))
                .await
                .unwrap();
            tokio::time::advance(Duration::from_millis(10)).await;
            assert_eq!(reader.read_message().await.unwrap(), expected);
            shutdown_sender.send(true).unwrap();
        };

        let (result, ()) = tokio::join!(session, peer);
        assert_eq!(result.unwrap(), SessionEnd::Shutdown);
    }

    #[tokio::test(start_paused = true)]
    async fn partial_header_and_payload_reads_survive_competing_branches() {
        let local_hello = hello(1);
        let remote_hello = hello(20);
        let (session_stream, peer_stream) = tokio::io::duplex(16_384);
        let secure_stream = PartialPendingReadSecureStream {
            inner: TestSecureStream {
                stream: session_stream,
                identity: identity(&remote_hello),
            },
            maximum_chunk: 3,
            pending_next: false,
        };
        let admission = TestAdmission {
            hello: local_hello.clone(),
        };
        let (outbound_sender, mut outbound) = mpsc::channel(16);
        let (events, mut event_receiver) = mpsc::channel(32);
        let (shutdown_sender, mut shutdown) = watch::channel(false);
        let mut peer_shutdown = shutdown.clone();
        let outbound_message = WireMessage::Clipboard(ClipboardV1 {
            update_id: WireClipboardId([31; 16]),
            origin_host: local_hello.host_id,
            sequence: 1,
            text: "writer-competition".repeat(20),
        });
        outbound_sender.send(outbound_message).await.unwrap();
        let expected = WireMessage::Clipboard(ClipboardV1 {
            update_id: WireClipboardId([32; 16]),
            origin_host: remote_hello.host_id,
            sequence: 55,
            text: "fragmented-header-and-payload".repeat(30),
        });
        let config = PersistentPeerConfig {
            heartbeat: HeartbeatConfig {
                interval: Duration::from_millis(10),
                degraded_after: Duration::from_secs(1),
                disconnect_after: Duration::from_secs(2),
                maximum_outstanding_pings: 8,
            },
            ..test_config()
        };
        let expected_for_observer = expected.clone();

        let session = run_session(
            secure_stream,
            &admission,
            config,
            &mut outbound,
            &events,
            &mut shutdown,
        );
        let peer = async move {
            let (read, write) = tokio::io::split(peer_stream);
            let mut reader = FrameReader::new_authenticated(read);
            let mut writer = FrameWriter::new_authenticated(write);
            let received_hello = match reader.read_message().await.unwrap() {
                WireMessage::Hello(hello) => hello,
                other => panic!("expected hello, got {other:?}"),
            };
            writer
                .write_message(&WireMessage::Hello(remote_hello.clone()))
                .await
                .unwrap();
            assert!(matches!(
                reader.read_message().await.unwrap(),
                WireMessage::Authenticate(_)
            ));
            writer
                .write_message(&WireMessage::Authenticate(AuthenticateV1 {
                    peer_id: remote_hello.peer_id,
                    scheme: "test-channel-binding-v1".to_owned(),
                    proof: received_hello.nonce.to_vec(),
                }))
                .await
                .unwrap();
            writer.write_message(&expected).await.unwrap();
            tokio::time::advance(Duration::from_millis(20)).await;
            wait_for_shutdown(&mut peer_shutdown).await;
        };
        let observer = async move {
            loop {
                if let Some(PeerEvent::Message { message, .. }) = event_receiver.recv().await {
                    assert_eq!(message, expected_for_observer);
                    shutdown_sender.send(true).unwrap();
                    break;
                }
            }
        };

        let (result, (), ()) = tokio::join!(session, peer, observer);
        assert_eq!(result.unwrap(), SessionEnd::Shutdown);
    }

    #[tokio::test]
    async fn shutdown_interrupts_a_blocked_admission_read() {
        let local_hello = hello(1);
        let remote_hello = hello(20);
        let (session_stream, _peer_stream) = tokio::io::duplex(256);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let admission = TestAdmission { hello: local_hello };
        let (_outbound_sender, mut outbound) = mpsc::channel(8);
        let (events, _event_receiver) = mpsc::channel(8);
        let (shutdown_sender, mut shutdown) = watch::channel(false);
        shutdown_sender.send(true).unwrap();

        let result = run_session(
            secure_stream,
            &admission,
            test_config(),
            &mut outbound,
            &events,
            &mut shutdown,
        )
        .await;
        assert_eq!(result.unwrap(), SessionEnd::Shutdown);
    }

    #[tokio::test]
    async fn secure_peer_session_runs_the_listener_direction() {
        let local_hello = hello(20);
        let remote_hello = hello(1);
        let (session_stream, peer_stream) = tokio::io::duplex(4_096);
        let secure_stream = InboundTestSecureStream(TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        });
        let (session, _sender, mut events) =
            SecurePeerSession::new(TestAdmission { hello: local_hello }, test_config()).unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let mut peer_shutdown = shutdown.clone();

        let runner = session.run(secure_stream, shutdown);
        let peer = async move {
            let (read, write) = tokio::io::split(peer_stream);
            let mut reader = FrameReader::new_authenticated(read);
            let mut writer = FrameWriter::new_authenticated(write);
            let received_hello = match reader.read_message().await.unwrap() {
                WireMessage::Hello(hello) => hello,
                other => panic!("expected hello, got {other:?}"),
            };
            writer
                .write_message(&WireMessage::Hello(remote_hello.clone()))
                .await
                .unwrap();
            assert!(matches!(
                reader.read_message().await.unwrap(),
                WireMessage::Authenticate(_)
            ));
            writer
                .write_message(&WireMessage::Authenticate(AuthenticateV1 {
                    peer_id: remote_hello.peer_id,
                    scheme: "test-channel-binding-v1".to_owned(),
                    proof: received_hello.nonce.to_vec(),
                }))
                .await
                .unwrap();
            wait_for_shutdown(&mut peer_shutdown).await;
        };
        let observer = async move {
            assert_eq!(
                events.recv().await.unwrap(),
                PeerEvent::StateChanged(ConnectionState::Authenticating)
            );
            assert!(matches!(
                events.recv().await.unwrap(),
                PeerEvent::Admitted(_)
            ));
            assert_eq!(
                events.recv().await.unwrap(),
                PeerEvent::StateChanged(ConnectionState::Connected)
            );
            shutdown_sender.send(true).unwrap();
        };

        let (result, (), ()) = tokio::join!(runner, peer, observer);
        assert_eq!(result.unwrap(), SessionEnd::Shutdown);
    }

    #[tokio::test]
    async fn secure_peer_session_rejects_noncanonical_direction_before_hello() {
        let local_hello = hello(20);
        let remote_hello = hello(1);
        let (session_stream, mut peer_stream) = tokio::io::duplex(4_096);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let (session, sender, mut events) =
            SecurePeerSession::new(TestAdmission { hello: local_hello }, test_config()).unwrap();
        sender.try_send(input(91)).unwrap();
        let (_shutdown_sender, shutdown) = watch::channel(false);

        assert!(matches!(
            session.run(secure_stream, shutdown).await,
            Err(SessionError::NoncanonicalDirection)
        ));
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::StateChanged(ConnectionState::Disconnected)
        );
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::Disconnected {
                reason: DisconnectReason::IdentityMismatch,
                undelivered: UndeliveredTraffic {
                    messages: vec![UndeliveredMessage {
                        message_type: MessageType::Input,
                        traffic_class: TrafficClass::Input,
                        sequence: Some(91),
                        partially_sent: false,
                    }],
                    partial_inbound_bytes: 0,
                    requires_input_reconciliation: true,
                },
                stats: SessionStats::default(),
            }
        );
        let mut byte = [0_u8; 1];
        assert_eq!(peer_stream.read(&mut byte).await.unwrap(), 0);
    }

    #[test]
    fn generation_bound_admission_activates_only_its_embedded_capability() {
        let mut gate =
            ConnectionGenerationGate::new(WirePeerId([1; 16]), WirePeerId([2; 16])).unwrap();
        let pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        let generation = pending.generation();
        let local = hello(1);
        let remote = hello(2);
        let admitted = AdmittedPeer {
            transport_identity: identity(&remote),
            local_hello: Arc::new(local),
            remote_hello: Arc::new(remote),
            selected_protocol_version: PROTOCOL_VERSION_V1,
            session_id: [0; 32],
        };
        let bound = GenerationBoundPeerEvent {
            generation,
            state: GenerationBoundPeerEventState::Admission(pending),
            event: Some(PeerEvent::Admitted(admitted.clone())),
        };

        let applied = bound.apply(&mut gate).unwrap();
        assert_eq!(
            applied.classification(),
            GenerationBoundEventClassification::Activated
        );
        let (active, event) = applied.into_activation().unwrap();
        assert_eq!(active.generation(), generation);
        assert_eq!(event, PeerEvent::Admitted(admitted));
        assert!(gate.is_active(generation));
    }

    #[test]
    fn active_bound_event_is_rejected_by_an_equivalent_new_gate() {
        let mut first =
            ConnectionGenerationGate::new(WirePeerId([1; 16]), WirePeerId([2; 16])).unwrap();
        let first_pending = first.begin_pending(ConnectionDirection::Outbound).unwrap();
        let stale_generation = first_pending.generation();
        let _first_active = first.activate(first_pending).unwrap();

        let mut replacement =
            ConnectionGenerationGate::new(WirePeerId([1; 16]), WirePeerId([2; 16])).unwrap();
        let replacement_pending = replacement
            .begin_pending(ConnectionDirection::Outbound)
            .unwrap();
        let replacement_generation = replacement_pending.generation();
        let _replacement_active = replacement.activate(replacement_pending).unwrap();
        assert_eq!(stale_generation.get(), replacement_generation.get());
        assert_ne!(stale_generation, replacement_generation);

        let stale = GenerationBoundPeerEvent {
            generation: stale_generation,
            state: GenerationBoundPeerEventState::Active,
            event: Some(PeerEvent::StateChanged(ConnectionState::Connected)),
        };
        assert!(matches!(
            stale.apply(&mut replacement),
            Err(ConnectionGenerationError::StaleActive)
        ));
    }

    #[test]
    fn pre_admission_cancellation_clears_only_the_exact_pending_gate() {
        let mut gate =
            ConnectionGenerationGate::new(WirePeerId([1; 16]), WirePeerId([2; 16])).unwrap();
        let pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        let generation = pending.generation();
        let cancellation = GenerationBoundPeerEvent {
            generation,
            state: GenerationBoundPeerEventState::Cancelled(pending),
            event: None,
        };

        let applied = cancellation.apply(&mut gate).unwrap();
        assert_eq!(
            applied.classification(),
            GenerationBoundEventClassification::Cancelled
        );
        assert!(gate.begin_pending(ConnectionDirection::Outbound).is_ok());
    }

    #[test]
    fn invalid_bound_session_config_returns_the_pending_capability() {
        let mut gate =
            ConnectionGenerationGate::new(WirePeerId([1; 16]), WirePeerId([2; 16])).unwrap();
        let pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        let mut config = test_config();
        config.admission_timeout = Duration::ZERO;
        let Err(error) =
            GenerationBoundPeerSession::new(TestAdmission { hello: hello(1) }, config, pending)
        else {
            panic!("invalid config unexpectedly built a bound session");
        };

        assert!(matches!(error.error(), PeerConfigError::Invalid(_)));
        let applied = error.into_cancellation().apply(&mut gate).unwrap();
        assert_eq!(
            applied.classification(),
            GenerationBoundEventClassification::Cancelled
        );
        assert!(gate.begin_pending(ConnectionDirection::Outbound).is_ok());
    }

    #[tokio::test]
    async fn closed_receiver_before_protocol_failure_returns_exact_cancellation() {
        let local_hello = hello(1);
        let remote_hello = hello(20);
        let mut gate =
            ConnectionGenerationGate::new(local_hello.peer_id, remote_hello.peer_id).unwrap();
        let pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        let (session_stream, attacker_stream) = tokio::io::duplex(4_096);
        let secure_stream = TestSecureStream {
            stream: session_stream,
            identity: identity(&remote_hello),
        };
        let (session, _sender, bound_events) = GenerationBoundPeerSession::new(
            TestAdmission { hello: local_hello },
            test_config(),
            pending,
        )
        .unwrap();
        drop(bound_events);
        let (_shutdown_sender, shutdown) = watch::channel(false);

        let runner = session.run(secure_stream, shutdown);
        let attacker = async move {
            let (read, write) = tokio::io::split(attacker_stream);
            let mut reader = FrameReader::new_authenticated(read);
            let mut writer = FrameWriter::new_authenticated(write);
            assert!(matches!(
                reader.read_message().await.unwrap(),
                WireMessage::Hello(_)
            ));
            writer.write_message(&input(44)).await.unwrap();
        };
        let (result, ()) = tokio::join!(runner, attacker);
        let terminal = result
            .unwrap_err()
            .into_terminal_event()
            .expect("pre-admission failure retains cancellation capability");
        let applied = terminal.apply(&mut gate).unwrap();

        assert_eq!(
            applied.classification(),
            GenerationBoundEventClassification::Cancelled
        );
        assert!(gate.begin_pending(ConnectionDirection::Outbound).is_ok());
    }

    #[tokio::test]
    async fn capacity_one_preserves_an_active_terminal_after_admission_backpressure() {
        let mut gate =
            ConnectionGenerationGate::new(WirePeerId([1; 16]), WirePeerId([2; 16])).unwrap();
        let pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        let generation = pending.generation();
        let remote = hello(2);
        let admission = GenerationBoundPeerEvent {
            generation,
            state: GenerationBoundPeerEventState::Admission(pending),
            event: Some(PeerEvent::Admitted(AdmittedPeer {
                transport_identity: identity(&remote),
                local_hello: Arc::new(hello(1)),
                remote_hello: Arc::new(remote),
                selected_protocol_version: PROTOCOL_VERSION_V1,
                session_id: [0; 32],
            })),
        };
        let (sender, mut receiver) = mpsc::channel(1);
        try_send_bound_event(&sender, admission).unwrap();
        let rejected = try_send_bound_event(
            &sender,
            GenerationBoundPeerEvent {
                generation,
                state: GenerationBoundPeerEventState::Active,
                event: Some(PeerEvent::StateChanged(ConnectionState::Connected)),
            },
        )
        .unwrap_err();
        let terminal = recover_terminal_event(rejected, generation, true).unwrap();

        let applied = receiver.recv().await.unwrap().apply(&mut gate).unwrap();
        let (_active, _) = applied.into_activation().unwrap();
        assert!(matches!(
            terminal.apply(&mut gate).unwrap().event(),
            Some(PeerEvent::Disconnected { .. })
        ));
    }

    #[tokio::test]
    async fn receiver_closed_after_admission_preserves_an_active_terminal() {
        let mut gate =
            ConnectionGenerationGate::new(WirePeerId([1; 16]), WirePeerId([2; 16])).unwrap();
        let pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        let generation = pending.generation();
        let remote = hello(2);
        let admission = GenerationBoundPeerEvent {
            generation,
            state: GenerationBoundPeerEventState::Admission(pending),
            event: Some(PeerEvent::Admitted(AdmittedPeer {
                transport_identity: identity(&remote),
                local_hello: Arc::new(hello(1)),
                remote_hello: Arc::new(remote),
                selected_protocol_version: PROTOCOL_VERSION_V1,
                session_id: [0; 32],
            })),
        };
        let (sender, mut receiver) = mpsc::channel(1);
        try_send_bound_event(&sender, admission).unwrap();
        let admission = receiver.recv().await.unwrap();
        drop(receiver);
        let rejected = try_send_bound_event(
            &sender,
            GenerationBoundPeerEvent {
                generation,
                state: GenerationBoundPeerEventState::Active,
                event: Some(PeerEvent::StateChanged(ConnectionState::Connected)),
            },
        )
        .unwrap_err();
        let terminal = recover_terminal_event(rejected, generation, true).unwrap();

        let applied = admission.apply(&mut gate).unwrap();
        let (_active, _) = applied.into_activation().unwrap();
        assert!(matches!(
            terminal.apply(&mut gate).unwrap().event(),
            Some(PeerEvent::Disconnected { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_peer_reconnects_with_deterministic_backoff() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let connector = AlwaysFailConnector {
            attempts: Arc::clone(&attempts),
        };
        let config = PersistentPeerConfig {
            reconnect: ReconnectPolicy {
                initial_delay: Duration::from_millis(10),
                maximum_delay: Duration::from_millis(20),
                multiplier: 2,
            },
            event_channel_capacity: 16,
            ..test_config()
        };
        let (peer, sender, mut events) = PersistentPeer::new_with_jitter(
            connector,
            TestAdmission { hello: hello(1) },
            AddedJitter(Duration::from_millis(7)),
            config,
        )
        .unwrap();
        sender.try_send(input(77)).unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let address = DevelopmentAddress::new("127.0.0.1:24800".parse().unwrap());
        let task = tokio::spawn(peer.run(address, shutdown));

        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::StateChanged(ConnectionState::Connecting)
        );
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::StateChanged(ConnectionState::Disconnected)
        );
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::Disconnected {
                reason: DisconnectReason::ConnectFailed(std::io::ErrorKind::ConnectionRefused),
                undelivered: UndeliveredTraffic {
                    messages: vec![UndeliveredMessage {
                        message_type: MessageType::Input,
                        traffic_class: TrafficClass::Input,
                        sequence: Some(77),
                        partially_sent: false,
                    }],
                    partial_inbound_bytes: 0,
                    requires_input_reconciliation: true,
                },
                stats: SessionStats::default(),
            }
        );
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::ReconnectScheduled(Duration::from_millis(17))
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(17)).await;
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::StateChanged(ConnectionState::Connecting)
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::StateChanged(ConnectionState::Disconnected)
        );
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::Disconnected {
                reason: DisconnectReason::ConnectFailed(std::io::ErrorKind::ConnectionRefused),
                undelivered: UndeliveredTraffic::default(),
                stats: SessionStats::default(),
            }
        );

        shutdown_sender.send(true).unwrap();
        assert_eq!(task.await.unwrap().unwrap(), PersistentExit::Shutdown);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_secure_peer_times_out_and_reconnects() {
        let remote_hello = hello(20);
        let attempts = Arc::new(AtomicUsize::new(0));
        let connector = SilentConnector {
            attempts: Arc::clone(&attempts),
            identity: identity(&remote_hello),
            held_peers: Vec::new(),
        };
        let config = PersistentPeerConfig {
            reconnect: ReconnectPolicy {
                initial_delay: Duration::from_millis(10),
                maximum_delay: Duration::from_millis(20),
                multiplier: 2,
            },
            admission_timeout: Duration::from_millis(50),
            event_channel_capacity: 16,
            ..test_config()
        };
        let (peer, _sender, mut events) =
            PersistentPeer::new(connector, TestAdmission { hello: hello(1) }, config).unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let address = DevelopmentAddress::new("127.0.0.1:24800".parse().unwrap());
        let task = tokio::spawn(peer.run(address, shutdown));

        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::StateChanged(ConnectionState::Connecting)
        );
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::StateChanged(ConnectionState::Authenticating)
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(50)).await;
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::StateChanged(ConnectionState::Disconnected)
        );
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::Disconnected {
                reason: DisconnectReason::AdmissionTimeout,
                undelivered: UndeliveredTraffic::default(),
                stats: SessionStats::default(),
            }
        );
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::ReconnectScheduled(Duration::from_millis(10))
        );

        tokio::time::advance(Duration::from_millis(10)).await;
        assert_eq!(
            events.recv().await.unwrap(),
            PeerEvent::StateChanged(ConnectionState::Connecting)
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        shutdown_sender.send(true).unwrap();
        assert_eq!(task.await.unwrap().unwrap(), PersistentExit::Shutdown);
    }
}
