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
mod connection_role;
mod connector;
mod diagnostics;
mod heartbeat;
mod listener;
mod local_ipc;
mod peer;
mod pointer_datagram;
mod queue;
mod reconnect;
mod rustls_acceptor;
mod rustls_connector;

pub use codec::{FrameReader, FrameWriter, NetworkError};
pub use connection_role::{
    ActiveConnection, ConnectionDirection, ConnectionGeneration, ConnectionGenerationError,
    ConnectionGenerationGate, ConnectionRole, ConnectionRoleError, PendingConnection,
};
pub use connector::{
    AuthenticatedAcceptor, AuthenticatedConnector, AuthenticatedLanConnector,
    ClientIdentityResolutionError, DevelopmentAddress, PairedClientIdentityResolver,
    SecurePeerStream, TransportPeerIdentity,
};
pub use diagnostics::{
    empty_capture_cell, fetch_report, read_report, spawn_diagnostics_server, write_report,
    CaptureDiagnostics, CaptureDiagnosticsCell, DiagnosticsError, DiagnosticsPublisher,
    DiagnosticsReport, NetworkDiagnostics, PersistentDiagnosticsClient, DEFAULT_DIAGNOSTICS_PORT,
    DIAGNOSTICS_SCHEMA_VERSION, MAX_DIAGNOSTICS_PAYLOAD,
};
pub use heartbeat::{
    HeartbeatAction, HeartbeatConfig, HeartbeatConfigError, HeartbeatController, HeartbeatError,
    PeerHealth, PeerState,
};
pub use listener::{
    BoundedLanListener, LanAddressError, LanListenerBuildError, LanListenerConfig,
    LanListenerConfigError, LanListenerEvent, LanListenerRejection, LanListenerReport,
    LanPeerAddress,
};
pub use local_ipc::{
    default_control_path, LocalControlClient, LocalControlConnection, LocalControlServer,
    LocalControlServerConfig, LocalIpcConfigError, LocalIpcError,
};
pub use peer::{
    AdmissionError, AdmittedPeer, AppliedGenerationEvent, ConnectionState, DisconnectReason,
    GenerationBoundEventClassification, GenerationBoundPeerEvent, GenerationBoundPeerSession,
    GenerationBoundSessionBuildError, GenerationBoundSessionError, HandshakeTranscript,
    NoReconnectJitter, OutboundSendError, PeerConfigError, PeerEvent, PeerSender, PersistentExit,
    PersistentPeer, PersistentPeerConfig, ReconnectJitter, SecurePeerSession, SessionAdmission,
    SessionEnd, SessionError, UndeliveredMessage, UndeliveredTraffic,
};
/// Pointer-datagram fast-path plaintext codec and reorder buffer. The session
/// treats these as internal details; they are public so cargo-fuzz targets
/// and criterion benches can exercise the datagram parse/encode/reassembly
/// paths without a socket or session keys.
pub use pointer_datagram::{
    encode_pointer_plaintext, parse_pointer_datagram_plaintext, PointerDatagramConfig,
    PointerDatagramConfigError, PointerDatagramPlaintext, ReliableReorderBuffer,
    POINTER_DATAGRAM_PORT,
};
pub use queue::{
    DropCounters, EnqueueError, ObservableSessionStats, OutboundQueue, QueueConfig,
    QueueConfigError, SessionStats, SessionTelemetry, TrafficClass,
};
pub use reconnect::{ReconnectBackoff, ReconnectPolicy, ReconnectPolicyError};
pub use rustls_acceptor::{
    RustlsAcceptedPeerStream, RustlsAcceptorConfig, RustlsAcceptorConfigError, RustlsClientTrust,
    RustlsServerCredentials, RustlsTcpAcceptor,
};
pub use rustls_connector::{
    RustlsClientCredentials, RustlsConnectorConfig, RustlsConnectorConfigError, RustlsPeerStream,
    RustlsServerTrust, RustlsTcpConnector,
};
