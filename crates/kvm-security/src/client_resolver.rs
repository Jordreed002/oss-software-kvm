//! Immutable paired-client identity resolution for inbound TLS authentication.
//!
//! The snapshot contains public pairing metadata only. It deliberately has no
//! persistence, discovery, certificate parsing, or socket-address fallback.

use std::collections::BTreeMap;
use std::fmt;

use kvm_network::{
    ClientIdentityResolutionError, PairedClientIdentityResolver, TransportPeerIdentity,
};
use kvm_protocol::{WireHostId, WirePeerId};
use kvm_types::{HostId, PeerId};
use thiserror::Error;

use crate::PairedPeer;

/// Maximum number of current paired identities retained in one resolver.
pub const MAX_PAIRED_CLIENT_RESOLVER_ENTRIES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StableIdentity {
    peer_id: PeerId,
    host_id: HostId,
    fingerprint: [u8; 32],
}

impl StableIdentity {
    fn from_paired(peer: &PairedPeer) -> Self {
        let identity = peer.identity();
        Self {
            peer_id: identity.peer_id(),
            host_id: identity.host_id(),
            fingerprint: *identity.fingerprint().as_bytes(),
        }
    }

    fn into_transport(self) -> TransportPeerIdentity {
        TransportPeerIdentity {
            host_id: WireHostId(self.host_id.into_bytes()),
            peer_id: WirePeerId(self.peer_id.into_bytes()),
            credential_fingerprint: self.fingerprint,
        }
    }
}

/// A bounded, immutable view of currently paired public client identities.
///
/// Build a new snapshot after any pairing, identity change, or revocation and
/// atomically replace the old snapshot at the outer composition boundary.
/// Revoked entries must not be supplied to the constructor.
pub struct PairedClientResolverSnapshot {
    by_fingerprint: BTreeMap<[u8; 32], StableIdentity>,
}

impl PairedClientResolverSnapshot {
    /// Builds a fail-closed snapshot from current paired-peer metadata.
    ///
    /// Exact duplicate records are deduplicated. Reusing a fingerprint for a
    /// different stable identity, or changing the identity associated with a
    /// peer or host in the same snapshot, is rejected as corrupt metadata.
    /// Iteration stops after the positive entry bound is exceeded.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for oversized, ambiguous, or inconsistent
    /// metadata. No partial snapshot is returned.
    pub fn from_paired_peers(
        peers: impl IntoIterator<Item = PairedPeer>,
    ) -> Result<Self, PairedClientResolverSnapshotError> {
        let mut by_fingerprint = BTreeMap::new();
        let mut by_peer = BTreeMap::new();
        let mut by_host = BTreeMap::new();

        for (index, peer) in peers.into_iter().enumerate() {
            if index >= MAX_PAIRED_CLIENT_RESOLVER_ENTRIES {
                return Err(PairedClientResolverSnapshotError::TooManyEntries);
            }

            let stable = StableIdentity::from_paired(&peer);
            if stable.peer_id.into_bytes() == [0; 16] || stable.host_id.into_bytes() == [0; 16] {
                return Err(PairedClientResolverSnapshotError::InvalidIdentity);
            }
            if by_peer
                .get(&stable.peer_id)
                .is_some_and(|existing| existing != &stable)
                || by_host
                    .get(&stable.host_id)
                    .is_some_and(|existing| existing != &stable)
            {
                return Err(PairedClientResolverSnapshotError::IdentityMismatch);
            }
            if by_fingerprint
                .get(&stable.fingerprint)
                .is_some_and(|existing| existing != &stable)
            {
                return Err(PairedClientResolverSnapshotError::AmbiguousFingerprint);
            }

            by_peer.insert(stable.peer_id, stable);
            by_host.insert(stable.host_id, stable);
            by_fingerprint.insert(stable.fingerprint, stable);
        }

        Ok(Self { by_fingerprint })
    }

    /// Number of unique, currently resolvable identities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_fingerprint.len()
    }

    /// Whether the snapshot contains no current paired identities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_fingerprint.is_empty()
    }
}

impl fmt::Debug for PairedClientResolverSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedClientResolverSnapshot")
            .field("entry_count", &self.by_fingerprint.len())
            .finish_non_exhaustive()
    }
}

impl PairedClientIdentityResolver for PairedClientResolverSnapshot {
    fn resolve(
        &self,
        credential_fingerprint: &[u8; 32],
    ) -> Result<TransportPeerIdentity, ClientIdentityResolutionError> {
        let identity = self
            .by_fingerprint
            .get(credential_fingerprint)
            .copied()
            .ok_or(ClientIdentityResolutionError::Unknown)?;
        if &identity.fingerprint != credential_fingerprint {
            return Err(ClientIdentityResolutionError::InvalidIdentity);
        }
        Ok(identity.into_transport())
    }
}

/// Invalid public metadata supplied while constructing a paired-client view.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PairedClientResolverSnapshotError {
    /// The positive snapshot entry bound was exceeded.
    #[error("paired-client resolver snapshot exceeds its entry bound")]
    TooManyEntries,
    /// One credential fingerprint was assigned to different identities.
    #[error("paired-client resolver metadata contains an ambiguous fingerprint")]
    AmbiguousFingerprint,
    /// Stable peer or host metadata changed within one snapshot.
    #[error("paired-client resolver metadata contains an identity mismatch")]
    IdentityMismatch,
    /// A stable peer or host identifier was the nil UUID.
    #[error("paired-client resolver metadata contains an invalid identity")]
    InvalidIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdentityFingerprint, PeerIdentity};

    fn paired(peer: u8, host: u8, fingerprint: [u8; 32], name: &str) -> PairedPeer {
        PairedPeer::from_persisted_public_identity(
            PeerIdentity::new(
                PeerId::from_bytes([peer; 16]),
                HostId::from_bytes([host; 16]),
                name,
                IdentityFingerprint::from_sha256(fingerprint),
            )
            .unwrap(),
        )
    }

    #[test]
    fn exact_full_fingerprint_resolves_stable_identity() {
        let fingerprint = [3; 32];
        let snapshot = PairedClientResolverSnapshot::from_paired_peers([paired(
            1,
            2,
            fingerprint,
            "current display name",
        )])
        .unwrap();

        assert_eq!(
            snapshot.resolve(&fingerprint),
            Ok(TransportPeerIdentity {
                host_id: WireHostId([2; 16]),
                peer_id: WirePeerId([1; 16]),
                credential_fingerprint: fingerprint,
            })
        );

        let mut near_match = fingerprint;
        near_match[31] ^= 1;
        assert_eq!(
            snapshot.resolve(&near_match),
            Err(ClientIdentityResolutionError::Unknown)
        );
    }

    #[test]
    fn exact_duplicate_is_deduplicated_without_using_display_name_as_identity() {
        let snapshot = PairedClientResolverSnapshot::from_paired_peers([
            paired(1, 2, [3; 32], "first name"),
            paired(1, 2, [3; 32], "renamed peer"),
        ])
        .unwrap();

        assert_eq!(snapshot.len(), 1);
    }

    #[test]
    fn duplicate_fingerprint_for_different_identity_is_rejected() {
        let result = PairedClientResolverSnapshot::from_paired_peers([
            paired(1, 2, [3; 32], "one"),
            paired(4, 5, [3; 32], "two"),
        ]);

        assert!(matches!(
            result,
            Err(PairedClientResolverSnapshotError::AmbiguousFingerprint)
        ));
    }

    #[test]
    fn changed_peer_or_host_identity_is_rejected() {
        for changed in [
            paired(1, 2, [4; 32], "changed credential"),
            paired(4, 2, [5; 32], "changed peer"),
        ] {
            let result = PairedClientResolverSnapshot::from_paired_peers([
                paired(1, 2, [3; 32], "original"),
                changed,
            ]);
            assert!(matches!(
                result,
                Err(PairedClientResolverSnapshotError::IdentityMismatch)
            ));
        }
    }

    #[test]
    fn nil_peer_or_host_identity_is_rejected() {
        for invalid in [
            paired(0, 2, [3; 32], "nil peer"),
            paired(1, 0, [3; 32], "nil host"),
        ] {
            assert!(matches!(
                PairedClientResolverSnapshot::from_paired_peers([invalid]),
                Err(PairedClientResolverSnapshotError::InvalidIdentity)
            ));
        }
    }

    #[test]
    fn revoked_or_missing_identity_is_unknown_in_rebuilt_snapshot() {
        let old =
            PairedClientResolverSnapshot::from_paired_peers([paired(1, 2, [3; 32], "paired")])
                .unwrap();
        assert!(old.resolve(&[3; 32]).is_ok());

        let after_revocation =
            PairedClientResolverSnapshot::from_paired_peers(std::iter::empty()).unwrap();
        assert_eq!(
            after_revocation.resolve(&[3; 32]),
            Err(ClientIdentityResolutionError::Unknown)
        );
    }

    #[test]
    fn entry_count_is_positively_bounded() {
        let peers = (0..=MAX_PAIRED_CLIENT_RESOLVER_ENTRIES).map(|index| {
            let mut peer = [0; 16];
            let mut host = [0; 16];
            let mut fingerprint = [0; 32];
            peer[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_le_bytes());
            host[..8].copy_from_slice(&u64::try_from(index + 1_000).unwrap().to_le_bytes());
            fingerprint[..8].copy_from_slice(&u64::try_from(index + 2_000).unwrap().to_le_bytes());
            PairedPeer::from_persisted_public_identity(
                PeerIdentity::new(
                    PeerId::from_bytes(peer),
                    HostId::from_bytes(host),
                    "peer",
                    IdentityFingerprint::from_sha256(fingerprint),
                )
                .unwrap(),
            )
        });

        assert!(matches!(
            PairedClientResolverSnapshot::from_paired_peers(peers),
            Err(PairedClientResolverSnapshotError::TooManyEntries)
        ));
    }

    #[test]
    fn debug_and_errors_redact_identity_metadata() {
        let marker = [0x5a; 32];
        let snapshot = PairedClientResolverSnapshot::from_paired_peers([paired(
            0x41,
            0x42,
            marker,
            "SECRET-DISPLAY-MARKER",
        )])
        .unwrap();
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("SECRET-DISPLAY-MARKER"));
        assert!(!debug.contains(&"5a".repeat(32)));
        assert!(!debug.contains(&"41".repeat(16)));
        assert!(!debug.contains(&"42".repeat(16)));

        let error = PairedClientResolverSnapshot::from_paired_peers([
            paired(1, 2, marker, "one"),
            paired(3, 4, marker, "two"),
        ])
        .unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(&"5a".repeat(32)));
    }
}
