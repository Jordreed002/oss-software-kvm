use std::collections::BTreeMap;
use std::fmt;

use kvm_types::{HostId, PeerId};
use thiserror::Error;

use crate::{IdentityFingerprint, PeerIdentity};

/// Public identity metadata retained after successful dual-approved pairing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairedPeer {
    identity: PeerIdentity,
}

impl PairedPeer {
    pub(crate) const fn new(identity: PeerIdentity) -> Self {
        Self { identity }
    }

    /// Restores public identity metadata produced by an earlier approved pairing.
    ///
    /// This constructor does not perform pairing. Callers must use it only for
    /// metadata read from their paired-peer persistence boundary; private
    /// credential material belongs in [`crate::CredentialStore`].
    #[must_use]
    pub const fn from_persisted_public_identity(identity: PeerIdentity) -> Self {
        Self { identity }
    }

    /// Public identity approved during pairing.
    #[must_use]
    pub const fn identity(&self) -> &PeerIdentity {
        &self.identity
    }
}

/// Persistence boundary for the public paired-peer allowlist.
///
/// Implementations may use normal configuration storage because this contains
/// only public metadata. Private credentials use [`crate::CredentialStore`].
pub trait PairedPeerStore {
    /// Looks up public pairing metadata by stable peer ID.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific persistence failure.
    fn get(&self, peer_id: PeerId) -> Result<Option<PairedPeer>, PairedPeerStoreError>;

    /// Inserts or replaces one peer's public pairing metadata.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific persistence failure.
    fn upsert(&mut self, peer: PairedPeer) -> Result<(), PairedPeerStoreError>;

    /// Revokes a paired peer. Missing peers are treated as already revoked.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific persistence failure.
    fn remove(&mut self, peer_id: PeerId) -> Result<(), PairedPeerStoreError>;
}

/// In-memory public-metadata store for deterministic tests and ephemeral tools.
#[derive(Default)]
pub struct MemoryPairedPeerStore {
    peers: BTreeMap<PeerId, PairedPeer>,
}

impl fmt::Debug for MemoryPairedPeerStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryPairedPeerStore")
            .field("peer_count", &self.peers.len())
            .finish_non_exhaustive()
    }
}

impl PairedPeerStore for MemoryPairedPeerStore {
    fn get(&self, peer_id: PeerId) -> Result<Option<PairedPeer>, PairedPeerStoreError> {
        Ok(self.peers.get(&peer_id).cloned())
    }

    fn upsert(&mut self, peer: PairedPeer) -> Result<(), PairedPeerStoreError> {
        self.peers.insert(peer.identity().peer_id(), peer);
        Ok(())
    }

    fn remove(&mut self, peer_id: PeerId) -> Result<(), PairedPeerStoreError> {
        self.peers.remove(&peer_id);
        Ok(())
    }
}

/// Public paired-peer persistence failure.
#[derive(Clone, Eq, Error, PartialEq)]
pub enum PairedPeerStoreError {
    /// Storage is temporarily unavailable.
    #[error("paired-peer store is unavailable")]
    Unavailable,
    /// Public pairing metadata was unreadable or internally inconsistent.
    #[error("paired-peer metadata is corrupt")]
    Corrupt,
    /// Backend-specific failure without private key material.
    #[error("paired-peer store backend failed")]
    Backend(String),
}

impl fmt::Debug for PairedPeerStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Unavailable => "Unavailable",
            Self::Corrupt => "Corrupt",
            Self::Backend(_) => "Backend",
        };
        formatter
            .debug_struct("PairedPeerStoreError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

/// TLS transport boundary that vouches for the connected peer identity.
///
/// Implementations must return an identity only after encrypted transport setup
/// and peer credential proof have both completed. Discovery objects intentionally
/// do not implement this trait and therefore cannot authorize remote input.
pub trait AuthenticatedPeerTransport {
    /// Returns identity proven by the current encrypted connection.
    ///
    /// # Errors
    ///
    /// Returns an authentication failure when encryption or peer proof is absent.
    fn authenticated_peer_identity(&self) -> Result<PeerIdentity, TransportAuthenticationError>;
}

/// Failure at the encrypted transport authentication boundary.
#[derive(Clone, Eq, Error, PartialEq)]
pub enum TransportAuthenticationError {
    /// The connection is not encrypted.
    #[error("remote input requires an encrypted connection")]
    Unencrypted,
    /// No peer credential was authenticated.
    #[error("remote input requires an authenticated peer")]
    Unauthenticated,
    /// The peer credential failed transport-level verification.
    #[error("peer credential is invalid")]
    InvalidCredential,
    /// Backend-specific authentication failure without credential material.
    #[error("transport authentication backend failed")]
    Backend(String),
}

impl fmt::Debug for TransportAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Unencrypted => "Unencrypted",
            Self::Unauthenticated => "Unauthenticated",
            Self::InvalidCredential => "InvalidCredential",
            Self::Backend(_) => "Backend",
        };
        formatter
            .debug_struct("TransportAuthenticationError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

/// Capability minted only after transport authentication and allowlist matching.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InputAuthorization {
    peer_id: PeerId,
    host_id: HostId,
}

impl fmt::Debug for InputAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputAuthorization([REDACTED])")
    }
}

impl InputAuthorization {
    /// Authenticated and paired peer allowed to send input.
    #[must_use]
    pub const fn peer_id(self) -> PeerId {
        self.peer_id
    }

    /// Authenticated host allowed to receive routing authority.
    #[must_use]
    pub const fn host_id(self) -> HostId {
        self.host_id
    }
}

/// Pairing allowlist service. Authorization fails closed on every store or
/// transport error.
pub struct PairedPeerAllowlist<S> {
    store: S,
}

impl<S> fmt::Debug for PairedPeerAllowlist<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedPeerAllowlist")
            .field("store", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<S> PairedPeerAllowlist<S>
where
    S: PairedPeerStore,
{
    /// Creates an allowlist backed by public-metadata storage.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Persists a peer returned by a completed pairing session.
    ///
    /// # Errors
    ///
    /// Returns a persistence failure without changing authorization semantics.
    pub fn pair(&mut self, peer: PairedPeer) -> Result<(), PairedPeerStoreError> {
        self.store.upsert(peer)
    }

    /// Removes a peer's future input authority.
    ///
    /// # Errors
    ///
    /// Returns a persistence failure; callers must continue treating uncertain
    /// state as unauthorized until successful reload/revocation.
    pub fn revoke(&mut self, peer_id: PeerId) -> Result<(), PairedPeerStoreError> {
        self.store.remove(peer_id)
    }

    /// Authorizes input only when the transport-authenticated identity exactly
    /// matches previously approved stable IDs and public-key fingerprint.
    ///
    /// Display names are intentionally excluded from authentication and may be
    /// changed without pairing again.
    ///
    /// # Errors
    ///
    /// Fails for unencrypted/unauthenticated transports, unknown peers,
    /// identity changes, or allowlist storage failures.
    pub fn authorize_input(
        &self,
        transport: &impl AuthenticatedPeerTransport,
    ) -> Result<InputAuthorization, AuthorizationError> {
        let presented = transport.authenticated_peer_identity()?;
        self.authorize_identity(&presented)
    }

    pub(crate) fn authorize_identity(
        &self,
        presented: &PeerIdentity,
    ) -> Result<InputAuthorization, AuthorizationError> {
        let paired = self
            .store
            .get(presented.peer_id())?
            .ok_or(AuthorizationError::PeerNotPaired(presented.peer_id()))?;

        let expected = paired.identity();
        if expected.host_id() != presented.host_id()
            || expected.fingerprint() != presented.fingerprint()
        {
            return Err(AuthorizationError::IdentityMismatch {
                peer_id: presented.peer_id(),
                expected_fingerprint: expected.fingerprint(),
                presented_fingerprint: presented.fingerprint(),
            });
        }

        Ok(InputAuthorization {
            peer_id: presented.peer_id(),
            host_id: presented.host_id(),
        })
    }

    /// Returns the backing store for shutdown or test inspection.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }
}

/// Input authorization failure. Every variant must be treated as denial.
#[derive(Clone, Eq, Error, PartialEq)]
pub enum AuthorizationError {
    /// The transport did not establish encrypted peer authentication.
    #[error(transparent)]
    Transport(#[from] TransportAuthenticationError),
    /// Public allowlist storage could not be read.
    #[error(transparent)]
    Store(#[from] PairedPeerStoreError),
    /// The authenticated peer has never completed explicit pairing.
    #[error("authenticated peer is not paired and cannot authorize input")]
    PeerNotPaired(PeerId),
    /// A known peer ID presented a different host identity or public key.
    #[error("authenticated identity does not match its paired public credential")]
    IdentityMismatch {
        peer_id: PeerId,
        expected_fingerprint: IdentityFingerprint,
        presented_fingerprint: IdentityFingerprint,
    },
}

impl fmt::Debug for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Transport(_) => "Transport",
            Self::Store(_) => "Store",
            Self::PeerNotPaired(_) => "PeerNotPaired",
            Self::IdentityMismatch { .. } => "IdentityMismatch",
        };
        formatter
            .debug_struct("AuthorizationError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_types::{HostId, PeerId};

    #[derive(Debug)]
    struct TestTransport(Result<PeerIdentity, TransportAuthenticationError>);

    impl AuthenticatedPeerTransport for TestTransport {
        fn authenticated_peer_identity(
            &self,
        ) -> Result<PeerIdentity, TransportAuthenticationError> {
            self.0.clone()
        }
    }

    fn identity(peer: u8, host: u8, fingerprint: u8) -> PeerIdentity {
        PeerIdentity::new(
            PeerId::from_bytes([peer; 16]),
            HostId::from_bytes([host; 16]),
            "peer",
            IdentityFingerprint::from_sha256([fingerprint; 32]),
        )
        .unwrap()
    }

    #[test]
    fn paired_authenticated_peer_can_authorize_input() {
        let peer = identity(1, 2, 3);
        let transport = TestTransport(Ok(peer.clone()));
        let mut allowlist = PairedPeerAllowlist::new(MemoryPairedPeerStore::default());
        allowlist.pair(PairedPeer::new(peer.clone())).unwrap();

        let authorization = allowlist.authorize_input(&transport).unwrap();
        assert_eq!(authorization.peer_id(), peer.peer_id());
        assert_eq!(authorization.host_id(), peer.host_id());
    }

    #[test]
    fn discovery_or_unknown_identity_never_implies_trust() {
        let discovered = crate::DiscoveredPeer::new(identity(1, 2, 3));
        let transport = TestTransport(Ok(discovered.identity().clone()));
        let allowlist = PairedPeerAllowlist::new(MemoryPairedPeerStore::default());

        assert_eq!(
            allowlist.authorize_input(&transport),
            Err(AuthorizationError::PeerNotPaired(
                discovered.identity().peer_id()
            ))
        );
    }

    #[test]
    fn changed_fingerprint_is_denied() {
        let paired = identity(1, 2, 3);
        let presented = identity(1, 2, 4);
        let mut allowlist = PairedPeerAllowlist::new(MemoryPairedPeerStore::default());
        allowlist.pair(PairedPeer::new(paired)).unwrap();

        assert!(matches!(
            allowlist.authorize_input(&TestTransport(Ok(presented))),
            Err(AuthorizationError::IdentityMismatch { .. })
        ));
    }

    #[test]
    fn authorization_diagnostics_redact_stable_identity_metadata() {
        let peer = PeerId::from_bytes([0x11; 16]);
        let expected = IdentityFingerprint::from_sha256([0x22; 32]);
        let presented = IdentityFingerprint::from_sha256([0x33; 32]);
        let errors = [
            AuthorizationError::PeerNotPaired(peer),
            AuthorizationError::IdentityMismatch {
                peer_id: peer,
                expected_fingerprint: expected,
                presented_fingerprint: presented,
            },
        ];
        let rendered = format!(
            "{:?} {} {:?} {}",
            errors[0], errors[0], errors[1], errors[1]
        );
        for marker in [
            peer.to_string(),
            expected.to_string(),
            presented.to_string(),
        ] {
            assert!(!rendered.contains(&marker));
        }

        let backend_marker = "SECRET-ALLOWLIST-BACKEND";
        let store_error = PairedPeerStoreError::Backend(backend_marker.to_owned());
        let transport_error = TransportAuthenticationError::Backend(backend_marker.to_owned());
        let rendered =
            format!("{store_error:?} {store_error} {transport_error:?} {transport_error}");
        assert!(!rendered.contains(backend_marker));
    }

    #[test]
    fn unauthenticated_transport_is_denied_before_allowlist_lookup() {
        let allowlist = PairedPeerAllowlist::new(MemoryPairedPeerStore::default());
        let transport = TestTransport(Err(TransportAuthenticationError::Unauthenticated));

        assert_eq!(
            allowlist.authorize_input(&transport),
            Err(AuthorizationError::Transport(
                TransportAuthenticationError::Unauthenticated
            ))
        );
    }

    #[derive(Debug)]
    struct FailingPeerStore;

    impl PairedPeerStore for FailingPeerStore {
        fn get(&self, _peer_id: PeerId) -> Result<Option<PairedPeer>, PairedPeerStoreError> {
            Err(PairedPeerStoreError::Unavailable)
        }

        fn upsert(&mut self, _peer: PairedPeer) -> Result<(), PairedPeerStoreError> {
            Err(PairedPeerStoreError::Unavailable)
        }

        fn remove(&mut self, _peer_id: PeerId) -> Result<(), PairedPeerStoreError> {
            Err(PairedPeerStoreError::Unavailable)
        }
    }

    #[test]
    fn store_failure_fails_authorization_closed() {
        let allowlist = PairedPeerAllowlist::new(FailingPeerStore);
        let transport = TestTransport(Ok(identity(1, 2, 3)));

        assert_eq!(
            allowlist.authorize_input(&transport),
            Err(AuthorizationError::Store(PairedPeerStoreError::Unavailable))
        );
    }
}
