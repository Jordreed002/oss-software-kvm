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

/// A byte stream whose adapter has already completed encryption and peer
/// credential authentication.
///
/// This trait is sealed. A future in-crate rustls adapter must implement it
/// only after certificate validation and expose the authenticated identity.
/// Downstream safe code therefore cannot bless a plaintext wrapper.
pub trait SecurePeerStream: sealed::SecureStream + AsyncRead + AsyncWrite + Unpin + Send {
    fn authenticated_peer_identity(&self) -> &TransportPeerIdentity;
}

/// Connects to an explicit development address and returns only a transport
/// that has already completed encryption and peer authentication.
///
/// The trait is sealed so a future production socket/rustls adapter must live
/// in this crate and cannot be replaced by a safe plaintext downstream
/// implementation. Credential policy and allow-list decisions remain outside
/// this crate and are supplied to that adapter by the composition layer.
pub trait AuthenticatedConnector: sealed::Connector {
    type Stream: SecurePeerStream;

    fn connect<'a>(
        &'a mut self,
        address: DevelopmentAddress,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + 'a>>;
}
