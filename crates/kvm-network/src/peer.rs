use crate::codec::FrameReadProgress;
use crate::{
    AuthenticatedConnector, DevelopmentAddress, FrameReader, FrameWriter, HeartbeatAction,
    HeartbeatConfig, HeartbeatController, NetworkError, OutboundQueue, QueueConfig,
    ReconnectBackoff, ReconnectPolicy, SecurePeerStream, TrafficClass, TransportPeerIdentity,
};
use kvm_protocol::{encode_frame, AuthenticateV1, HelloV1, MessageType, WireMessage};
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
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
    local_hello: HelloV1,
    remote_hello: HelloV1,
}

impl std::fmt::Debug for AdmittedPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedPeer")
            .field("local_host_id", &self.local_hello.host_id)
            .field("remote_host_id", &self.remote_hello.host_id)
            .field("remote_peer_id", &self.remote_hello.peer_id)
            .finish_non_exhaustive()
    }
}

impl AdmittedPeer {
    pub const fn transport_identity(&self) -> &TransportPeerIdentity {
        &self.transport_identity
    }

    pub const fn hello(&self) -> &HelloV1 {
        &self.remote_hello
    }

    pub const fn local_hello(&self) -> &HelloV1 {
        &self.local_hello
    }
}

/// Exact immutable values covered by both authentication proof operations.
#[derive(Clone, PartialEq)]
pub struct HandshakeTranscript {
    local_hello: HelloV1,
    remote_hello: HelloV1,
    transport_identity: TransportPeerIdentity,
}

impl std::fmt::Debug for HandshakeTranscript {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HandshakeTranscript")
            .field("local_host_id", &self.local_hello.host_id)
            .field("remote_host_id", &self.remote_hello.host_id)
            .field("remote_peer_id", &self.remote_hello.peer_id)
            .field("transport_identity", &self.transport_identity)
            .finish_non_exhaustive()
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
    fn local_hello(&self) -> HelloV1;

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
    },
    ReconnectScheduled(Duration),
}

impl std::fmt::Debug for PeerEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateChanged(state) => {
                formatter.debug_tuple("StateChanged").field(state).finish()
            }
            Self::Admitted(peer) => formatter
                .debug_struct("Admitted")
                .field("host_id", &peer.remote_hello.host_id)
                .field("peer_id", &peer.remote_hello.peer_id)
                .finish(),
            Self::Message { peer, message } => formatter
                .debug_struct("Message")
                .field("peer_id", &peer.remote_hello.peer_id)
                .field("message_type", &message.message_type())
                .field("sequence", &message_sequence(message))
                .finish_non_exhaustive(),
            Self::Disconnected {
                reason,
                undelivered,
            } => formatter
                .debug_struct("Disconnected")
                .field("reason", reason)
                .field("undelivered", undelivered)
                .finish(),
            Self::ReconnectScheduled(delay) => formatter
                .debug_tuple("ReconnectScheduled")
                .field(delay)
                .finish(),
        }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UndeliveredMessage {
    pub message_type: MessageType,
    pub traffic_class: TrafficClass,
    pub sequence: Option<u64>,
    pub partially_sent: bool,
}

/// Redacted traffic inventory that the daemon must reconcile after a failed
/// session. Messages are deliberately not replayed on a new connection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UndeliveredTraffic {
    pub messages: Vec<UndeliveredMessage>,
    pub partial_inbound_bytes: usize,
    pub requires_input_reconciliation: bool,
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
}

impl PeerSender {
    /// Submits a message to the bounded persistent-session channel.
    ///
    /// # Errors
    ///
    /// Returns the original message when the channel is full or closed.
    pub fn try_send(&self, message: WireMessage) -> Result<(), OutboundSendError> {
        self.sender.try_send(message).map_err(|error| match error {
            mpsc::error::TrySendError::Full(message) => OutboundSendError::Full(Box::new(message)),
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
            .field("sequence", &message_sequence(message))
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

#[derive(Debug, Error)]
pub enum SessionError {
    #[error(transparent)]
    Network(#[from] NetworkError),
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error("transport identity does not match the peer hello")]
    TransportIdentityMismatch,
    #[error("local authentication response does not match the local hello")]
    LocalIdentityMismatch,
    #[error("received {0:?} before peer admission")]
    PreAdmissionMessage(MessageType),
    #[error("received repeated handshake message {0:?} after admission")]
    RepeatedHandshake(MessageType),
    #[error("received {0:?} with an invalid sender or destination identity")]
    MessageIdentityMismatch(MessageType),
    #[error("heartbeat validation failed: {0}")]
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

#[derive(Debug)]
struct SessionFailure {
    error: SessionError,
    undelivered: UndeliveredTraffic,
    reset_backoff: bool,
}

impl SessionFailure {
    fn before_admission(error: SessionError) -> Self {
        Self {
            error,
            undelivered: UndeliveredTraffic::default(),
            reset_backoff: false,
        }
    }
}

#[derive(Debug)]
struct PendingFrame {
    bytes: Vec<u8>,
    committed: usize,
    metadata: UndeliveredMessage,
}

enum FrameWriteProgress {
    Bytes(usize),
    Flushed,
}

impl PendingFrame {
    fn encode(message: &WireMessage) -> Result<Self, SessionError> {
        Ok(Self {
            bytes: encode_frame(message).map_err(NetworkError::from)?,
            committed: 0,
            metadata: undelivered_metadata(message, false),
        })
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
        Ok((
            Self {
                connector,
                admission,
                jitter,
                config,
                outbound,
                events,
            },
            PeerSender {
                sender: outbound_sender,
            },
            event_receiver,
        ))
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

            let (reason, mut undelivered) = match connected {
                Ok(stream) => match run_session(
                    stream,
                    &self.admission,
                    self.config,
                    &mut self.outbound,
                    &self.events,
                    &mut shutdown,
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
                        (disconnect_reason(&failure.error), failure.undelivered)
                    }
                },
                Err(error) => (
                    DisconnectReason::ConnectFailed(error.kind()),
                    UndeliveredTraffic::default(),
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

async fn run_session<S: SecurePeerStream, A: SessionAdmission>(
    stream: S,
    admission: &A,
    config: PersistentPeerConfig,
    outbound: &mut mpsc::Receiver<WireMessage>,
    events: &mpsc::Sender<PeerEvent>,
    shutdown: &mut watch::Receiver<bool>,
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
    let mut pending = None;
    let mut read_progress = FrameReadProgress::default();
    let mut outbound_open = true;
    let mut reset_backoff = false;

    let result: Result<SessionEnd, SessionError> = async {
    loop {
        while let Ok(message) = outbound.try_recv() {
            enqueue(&mut queue, message)?;
        }
        if pending.is_none() {
            pending = queue
                .pop_next()
                .as_ref()
                .map(PendingFrame::encode)
                .transpose()?;
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
                    FrameWriteProgress::Flushed => pending = None,
                }
            }
            result = reader.read_some(&mut read_progress) => {
                if let Some(message) = result? {
                    handle_inbound(
                        message,
                        &admitted,
                        &mut heartbeat,
                        origin.elapsed(),
                        &mut queue,
                        events,
                    )?;
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
        let mut metadata = frame.metadata;
        metadata.partially_sent = frame.committed > 0;
        undelivered.requires_input_reconciliation |= metadata.traffic_class == TrafficClass::Input;
        undelivered.messages.push(metadata);
    }
    while let Some(message) = queue.pop_next() {
        undelivered.record(&message, false);
    }
    SessionFailure {
        error,
        undelivered,
        reset_backoff,
    }
}

async fn perform_admission<S: SecurePeerStream, A: SessionAdmission>(
    stream: S,
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
    send_event(
        events,
        PeerEvent::StateChanged(ConnectionState::Authenticating),
    )?;
    let transport_identity = stream.authenticated_peer_identity().clone();
    let (read, write) = tokio::io::split(stream);
    let mut reader = FrameReader::new_authenticated(read);
    let mut writer = FrameWriter::new_authenticated(write);

    let local_hello = admission.local_hello();
    if !write_or_shutdown(
        &mut writer,
        &WireMessage::Hello(local_hello.clone()),
        shutdown,
    )
    .await?
    {
        return Ok(None);
    }
    let Some(first_message) = read_or_shutdown(&mut reader, shutdown).await? else {
        return Ok(None);
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

    let transcript = HandshakeTranscript {
        local_hello: local_hello.clone(),
        remote_hello,
        transport_identity,
    };
    let local_auth = admission.authentication_message(&transcript)?;
    if local_auth.peer_id != local_hello.peer_id {
        return Err(SessionError::LocalIdentityMismatch);
    }
    if !write_or_shutdown(
        &mut writer,
        &WireMessage::Authenticate(local_auth),
        shutdown,
    )
    .await?
    {
        return Ok(None);
    }
    let Some(second_message) = read_or_shutdown(&mut reader, shutdown).await? else {
        return Ok(None);
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
        local_hello: transcript.local_hello,
        remote_hello: transcript.remote_hello,
    };
    send_event(events, PeerEvent::Admitted(admitted.clone()))?;
    send_event(events, PeerEvent::StateChanged(ConnectionState::Connected))?;
    Ok(Some((reader, writer, admitted)))
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
        WireMessage::Clipboard(value) => value.origin_host == remote,
        WireMessage::ReleaseInput(value) => value.source_host == remote,
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
        | SessionError::MessageIdentityMismatch(_) => DisconnectReason::IdentityMismatch,
        SessionError::PreAdmissionMessage(_) => DisconnectReason::ProtocolViolation,
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
        WireMessage::Clipboard(value) => Some(value.sequence),
        WireMessage::ReleaseInput(value) => Some(value.sequence),
        _ => None,
    }
}

fn send_event(events: &mpsc::Sender<PeerEvent>, event: PeerEvent) -> Result<(), SessionError> {
    events.try_send(event).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => SessionError::EventChannelFull,
        mpsc::error::TrySendError::Closed(_) => SessionError::EventChannelClosed,
    })
}

async fn write_or_shutdown<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut FrameWriter<W>,
    message: &WireMessage,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<bool, SessionError> {
    tokio::select! {
        biased;
        () = wait_for_shutdown(shutdown) => Ok(false),
        result = async {
            writer.write_message(message).await?;
            writer.flush().await
        } => result.map(|()| true).map_err(SessionError::from),
    }
}

async fn read_or_shutdown<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut FrameReader<R>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Option<WireMessage>, SessionError> {
    tokio::select! {
        biased;
        () = wait_for_shutdown(shutdown) => Ok(None),
        result = reader.read_message() => result.map(Some).map_err(SessionError::from),
    }
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
    use crate::TransportPeerIdentity;
    use kvm_protocol::{
        ClipboardV1, InputEventV1, PointerEnterV1, PointerLeaveV1, ReleaseInputV1, ReleaseReasonV1,
        WireClipboardId, WireDeviceId, WireDisplayId, WireEdge, WireHostId, WireInputPayloadV1,
        WirePeerId, WirePlatform, PROTOCOL_VERSION,
    };
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

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
        fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
            &self.identity
        }
    }

    impl crate::connector::sealed::SecureStream for TestSecureStream {}

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
        fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
            &self.inner.identity
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
        fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
            &self.inner.identity
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
        fn local_hello(&self) -> HelloV1 {
            self.hello.clone()
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
        HelloV1 {
            host_id: WireHostId([value; 16]),
            peer_id: WirePeerId([value.saturating_add(1); 16]),
            host_name: format!("host-{value}"),
            platform: WirePlatform::Linux,
            minimum_protocol_version: PROTOCOL_VERSION,
            maximum_protocol_version: PROTOCOL_VERSION,
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
        ]
    }

    fn input(sequence: u64) -> WireMessage {
        let mut message = privileged_messages()[0].clone();
        if let WireMessage::Input(input) = &mut message {
            input.sequence = sequence;
        }
        message
    }

    #[test]
    fn payload_bearing_debug_output_is_redacted() {
        let remote = hello(20);
        let peer = AdmittedPeer {
            transport_identity: identity(&remote),
            local_hello: hello(1),
            remote_hello: remote.clone(),
        };
        let message = WireMessage::Clipboard(ClipboardV1 {
            update_id: WireClipboardId([1; 16]),
            origin_host: remote.host_id,
            sequence: 8,
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

        assert!(!event_debug.contains("never-print-this-secret"));
        assert!(!error_debug.contains("never-print-this-secret"));
        assert!(event_debug.contains("Clipboard"));
        assert!(error_debug.contains("Clipboard"));
    }

    #[test]
    fn message_identity_validation_rejects_spoofed_sources_and_destinations() {
        let remote = hello(20);
        let peer = AdmittedPeer {
            transport_identity: identity(&remote),
            local_hello: hello(1),
            remote_hello: remote,
        };
        let spoofed_input = input(1);
        assert!(matches!(
            validate_message_identity(&spoofed_input, &peer),
            Err(SessionError::MessageIdentityMismatch(MessageType::Input))
        ));

        let mut wrong_destination = privileged_messages()[3].clone();
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
