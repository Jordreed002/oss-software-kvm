use crate::{ConnectionDirection, LanPeerAddress};
use kvm_protocol::{WireHostId, WirePeerId};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) mod sealed {
    pub trait SecureStream {}
    pub trait Connector {}
    pub trait Acceptor {}
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
        formatter.write_str("TransportPeerIdentity([REDACTED])")
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

    /// Direction in which this sealed transport was established at the local
    /// endpoint. Application code cannot forge this value independently of the
    /// in-crate authenticated adapter.
    fn connection_direction(&self) -> ConnectionDirection;

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

/// Connects to a policy-validated production LAN reachability address while
/// retaining the same sealed TLS identity and exporter guarantees.
///
/// Discovery and cached addresses must pass [`LanPeerAddress`] validation
/// before they can reach this interface. The address remains reachability
/// only; configured TLS identity is independently authenticated.
pub trait AuthenticatedLanConnector: sealed::Connector {
    type Stream: SecurePeerStream;

    /// Establishes the same authenticated TLS transport used by development
    /// dialing, but only after production LAN address validation.
    ///
    /// # Errors
    ///
    /// Returns a coarse I/O error when TCP connection, TLS authentication,
    /// exact ALPN, or configured remote fingerprint verification fails.
    fn connect_lan(
        &mut self,
        address: LanPeerAddress,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + '_>>;
}

/// Fail-closed outcomes from resolving an authenticated client credential.
///
/// These variants deliberately carry no resolver detail, identity, or
/// fingerprint so callers can report them without disclosing paired-peer
/// metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientIdentityResolutionError {
    Unavailable,
    Unknown,
    Ambiguous,
    InvalidIdentity,
}

impl std::fmt::Display for ClientIdentityResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("paired client identity could not be resolved")
    }
}

impl std::error::Error for ClientIdentityResolutionError {}

/// Resolves an authenticated client leaf-certificate fingerprint to stable
/// paired identity metadata.
///
/// The resolver is a caller-owned policy boundary. Implementations must use an
/// immutable, bounded snapshot and fail closed for unavailable, unknown,
/// ambiguous, changed, revoked, or invalid entries. Socket addresses,
/// certificate subject names, display names, and discovery metadata are not
/// identity inputs.
pub trait PairedClientIdentityResolver: Send + Sync {
    /// # Errors
    ///
    /// Returns a coarse, redacted error when the bounded snapshot is
    /// unavailable or the fingerprint is unknown, ambiguous, revoked, changed,
    /// or mapped to invalid identity metadata.
    fn resolve(
        &self,
        credential_fingerprint: &[u8; 32],
    ) -> Result<TransportPeerIdentity, ClientIdentityResolutionError>;
}

/// Accepts an already-established TCP socket and returns only a transport that
/// completed encrypted client-certificate authentication and paired identity
/// resolution.
///
/// Listener binding and interface selection remain outside this sealed trait.
/// Downstream safe code cannot implement another acceptor that blesses a
/// plaintext socket.
pub trait AuthenticatedAcceptor: sealed::Acceptor {
    type Stream: SecurePeerStream;

    fn accept(
        &self,
        stream: tokio::net::TcpStream,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_identity_debug_redacts_every_stable_identifier() {
        let identity = TransportPeerIdentity {
            host_id: WireHostId([71; 16]),
            peer_id: WirePeerId([83; 16]),
            credential_fingerprint: [97; 32],
        };
        assert_eq!(format!("{identity:?}"), "TransportPeerIdentity([REDACTED])");
    }
}
