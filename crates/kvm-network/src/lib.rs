//! Authenticated transport and networking primitives for Software KVM.
//!
//! This crate owns the audited outbound TCP/rustls adapter but does not perform
//! discovery, credential persistence, or allow-list decisions. Its persistent session accepts
//! only streams whose local endpoint completed encryption and remote-peer
//! authentication, then invokes a caller-owned bidirectional admission policy
//! before releasing application traffic. Outbound TLS completion presents, but
//! does not alone prove server acceptance of, configured client credentials.
//! TLS establishment and peer verification remain composition duties.

mod codec;
mod connector;
mod heartbeat;
mod peer;
mod queue;
mod reconnect;
mod rustls_connector;

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
pub use rustls_connector::{
    RustlsClientCredentials, RustlsConnectorConfig, RustlsConnectorConfigError, RustlsPeerStream,
    RustlsServerTrust, RustlsTcpConnector,
};
