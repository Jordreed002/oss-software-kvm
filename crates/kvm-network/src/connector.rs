use kvm_protocol::{WireHostId, WirePeerId};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) mod sealed {
    pub trait SecureStream {}
    pub trait Connector {}
}

/// An address entered explicitly during development.
///
/// Production discovery must resolve a paired peer through mDNS and the
/// security layer. This type deliberately does not represent trust or make a
/// raw socket safe for input transport.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DevelopmentAddress(SocketAddr);

impl DevelopmentAddress {
    pub const fn new(address: SocketAddr) -> Self {
        Self(address)
    }

    pub const fn socket_addr(self) -> SocketAddr {
        self.0
    }
}

/// Identity asserted by the authenticated encrypted transport adapter.
///
/// The fingerprint is adapter-defined (normally the paired certificate or
/// public-key fingerprint). The network crate treats it as opaque evidence and
/// passes it to the caller-owned admission policy.
#[derive(Clone, Eq, PartialEq)]
pub struct TransportPeerIdentity {
    pub host_id: WireHostId,
    pub peer_id: WirePeerId,
    pub credential_fingerprint: [u8; 32],
}

impl std::fmt::Debug for TransportPeerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransportPeerIdentity")
            .field("host_id", &self.host_id)
            .field("peer_id", &self.peer_id)
            .field("credential_fingerprint", &"[REDACTED]")
            .finish()
    }
}

/// A byte stream whose adapter has completed encryption and authenticated the
/// remote peer credential from this endpoint's perspective.
///
/// This trait is sealed. An in-crate adapter may implement it only after its
/// local handshake, certificate validation, and protocol checks complete, and
/// it must expose the authenticated remote identity. For an outbound TLS 1.3
/// client, local handshake completion does not by itself acknowledge that the
/// server accepted the configured client certificate: successful bidirectional
/// application admission (or a future server-side acceptor) establishes that
/// reciprocal fact. Downstream safe code cannot bless a plaintext wrapper.
pub trait SecurePeerStream: sealed::SecureStream + AsyncRead + AsyncWrite + Unpin + Send {
    fn authenticated_peer_identity(&self) -> &TransportPeerIdentity;

    /// Derives 32 bytes bound to this completed authenticated TLS session.
    ///
    /// The sealed transport implementation must fail if its handshake has not
    /// completed. Exporter bytes must never be included in errors or debug
    /// output.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when authenticated exporter material is
    /// unavailable.
    fn export_keying_material(&self, label: &[u8], context: &[u8]) -> io::Result<[u8; 32]>;
}

/// Connects to an explicit development address and returns only a transport
/// whose local endpoint has completed encryption and remote-peer
/// authentication.
///
/// The trait is sealed so a future production socket/rustls adapter must live
/// in this crate and cannot be replaced by a safe plaintext downstream
/// implementation. Credential policy and allow-list decisions remain outside
/// this crate and are supplied to that adapter by the composition layer. An
/// outbound connector can present configured client credentials but cannot
/// infer reciprocal server acceptance merely from client-side TLS 1.3 handshake
/// completion; application admission proves both endpoints are participating.
pub trait AuthenticatedConnector: sealed::Connector {
    type Stream: SecurePeerStream;

    fn connect<'a>(
        &'a mut self,
        address: DevelopmentAddress,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + 'a>>;
}
