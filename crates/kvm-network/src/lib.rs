//! Transport-independent networking primitives for Software KVM.
//!
//! This crate deliberately does not open sockets, perform discovery, implement
//! cryptography, or make allow-list decisions. Its persistent session accepts
//! only streams that an adapter marks encrypted and transport-authenticated,
//! then invokes a caller-owned admission policy before releasing application
//! traffic. TLS establishment and peer verification remain composition duties.

mod codec;
mod connector;
mod heartbeat;
mod peer;
mod queue;
mod reconnect;

pub use codec::{FrameReader, FrameWriter, NetworkError};
pub use connector::{
    AuthenticatedConnector, DevelopmentAddress, SecurePeerStream, TransportPeerIdentity,
};
pub use heartbeat::{
    HeartbeatAction, HeartbeatConfig, HeartbeatConfigError, HeartbeatController, HeartbeatError,
    PeerHealth, PeerState,
};
pub use peer::{
    AdmissionError, AdmittedPeer, ConnectionState, DisconnectReason, HandshakeTranscript,
    NoReconnectJitter, OutboundSendError, PeerConfigError, PeerEvent, PeerSender, PersistentExit,
    PersistentPeer, PersistentPeerConfig, ReconnectJitter, SessionAdmission, SessionEnd,
    SessionError, UndeliveredMessage, UndeliveredTraffic,
};
pub use queue::{EnqueueError, OutboundQueue, QueueConfig, QueueConfigError, TrafficClass};
pub use reconnect::{ReconnectBackoff, ReconnectPolicy, ReconnectPolicyError};
