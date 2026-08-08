use std::fmt;

use kvm_network::{AdmittedPeer, ConnectionGeneration};
use kvm_protocol::is_supported_protocol_version;
use kvm_types::{HostId, PeerId};

/// Exact authenticated destination for one admitted transport generation.
///
/// Production code can obtain this value only from a network-minted
/// [`AdmittedPeer`] and its generation token. Host identity alone is never an
/// equivalent routing or cleanup authority.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SessionEndpoint {
    peer_id: PeerId,
    host_id: HostId,
    generation: ConnectionGeneration,
    selected_protocol_version: u16,
    session_id: [u8; 32],
}

impl SessionEndpoint {
    pub(crate) fn from_admitted(
        generation: ConnectionGeneration,
        admitted: &AdmittedPeer,
    ) -> Option<Self> {
        let endpoint = Self::validated(
            PeerId::from_bytes(admitted.hello().peer_id.0),
            HostId::from_bytes(admitted.hello().host_id.0),
            generation,
            admitted.selected_protocol_version(),
            admitted.session_id(),
        )?;
        debug_assert_eq!(
            endpoint.peer_id(),
            PeerId::from_bytes(admitted.hello().peer_id.0)
        );
        debug_assert_eq!(
            endpoint.selected_protocol_version(),
            admitted.selected_protocol_version()
        );
        debug_assert_eq!(endpoint.session_id(), admitted.session_id());
        debug_assert_eq!(
            endpoint.supports_release_proof(),
            admitted.supports_release_proof()
        );
        Some(endpoint)
    }

    fn validated(
        peer_id: PeerId,
        host_id: HostId,
        generation: ConnectionGeneration,
        selected_protocol_version: u16,
        session_id: [u8; 32],
    ) -> Option<Self> {
        if peer_id.into_bytes() == [0; 16]
            || host_id.into_bytes() == [0; 16]
            || !is_supported_protocol_version(selected_protocol_version)
            || session_id == [0; 32]
        {
            return None;
        }
        Some(Self {
            peer_id,
            host_id,
            generation,
            selected_protocol_version,
            session_id,
        })
    }

    #[must_use]
    pub(crate) const fn peer_id(self) -> PeerId {
        self.peer_id
    }

    #[must_use]
    pub(crate) const fn host_id(self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub(crate) const fn generation(self) -> ConnectionGeneration {
        self.generation
    }

    #[must_use]
    pub(crate) const fn selected_protocol_version(self) -> u16 {
        self.selected_protocol_version
    }

    #[must_use]
    pub(crate) const fn session_id(self) -> [u8; 32] {
        self.session_id
    }

    #[must_use]
    pub(crate) const fn supports_release_proof(self) -> bool {
        kvm_protocol::supports_release_proof(self.selected_protocol_version)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        peer_id: PeerId,
        host_id: HostId,
        generation: ConnectionGeneration,
        selected_protocol_version: u16,
        session_id: [u8; 32],
    ) -> Option<Self> {
        Self::validated(
            peer_id,
            host_id,
            generation,
            selected_protocol_version,
            session_id,
        )
    }
}

impl fmt::Debug for SessionEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionEndpoint([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use kvm_network::{ConnectionGenerationGate, ConnectionRole};
    use kvm_protocol::{WirePeerId, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2};

    use super::*;

    const LOCAL_PEER: WirePeerId = WirePeerId([1; 16]);
    const REMOTE_PEER: WirePeerId = WirePeerId([2; 16]);
    const PEER: PeerId = PeerId::from_bytes([3; 16]);
    const HOST: HostId = HostId::from_bytes([4; 16]);

    fn generations() -> (ConnectionGeneration, ConnectionGeneration) {
        let mut gate = ConnectionGenerationGate::new(LOCAL_PEER, REMOTE_PEER).unwrap();
        assert_eq!(gate.role(), ConnectionRole::Dialer);
        let first = gate
            .begin_pending(ConnectionRole::Dialer.direction())
            .unwrap();
        let first_generation = first.generation();
        gate.cancel_pending(first).unwrap();
        let second = gate
            .begin_pending(ConnectionRole::Dialer.direction())
            .unwrap();
        (first_generation, second.generation())
    }

    #[test]
    fn equality_covers_generation_transcript_and_negotiated_version() {
        let (first, second) = generations();
        let endpoint =
            SessionEndpoint::for_test(PEER, HOST, first, PROTOCOL_VERSION_V2, [5; 32]).unwrap();
        assert_eq!(endpoint, endpoint);
        assert_ne!(
            endpoint,
            SessionEndpoint::for_test(PEER, HOST, second, PROTOCOL_VERSION_V2, [5; 32]).unwrap()
        );
        assert_ne!(
            endpoint,
            SessionEndpoint::for_test(PEER, HOST, first, PROTOCOL_VERSION_V2, [6; 32]).unwrap()
        );
        assert_ne!(
            endpoint,
            SessionEndpoint::for_test(PEER, HOST, first, PROTOCOL_VERSION_V1, [5; 32]).unwrap()
        );
        assert!(endpoint.supports_release_proof());
        assert_eq!(endpoint.peer_id(), PEER);
        assert_eq!(endpoint.host_id(), HOST);
        assert_eq!(endpoint.generation(), first);
        assert_eq!(endpoint.selected_protocol_version(), PROTOCOL_VERSION_V2);
        assert_eq!(endpoint.session_id(), [5; 32]);
    }

    #[test]
    fn invalid_or_zero_authority_is_rejected() {
        let (generation, _) = generations();
        assert!(SessionEndpoint::for_test(PEER, HOST, generation, 0, [5; 32]).is_none());
        assert!(
            SessionEndpoint::for_test(PEER, HOST, generation, PROTOCOL_VERSION_V2, [0; 32])
                .is_none()
        );
        assert!(SessionEndpoint::for_test(
            PeerId::from_bytes([0; 16]),
            HOST,
            generation,
            PROTOCOL_VERSION_V2,
            [5; 32],
        )
        .is_none());
        assert!(SessionEndpoint::for_test(
            PEER,
            HostId::from_bytes([0; 16]),
            generation,
            PROTOCOL_VERSION_V2,
            [5; 32],
        )
        .is_none());
    }

    #[test]
    fn debug_is_fully_redacted() {
        let (generation, _) = generations();
        let endpoint =
            SessionEndpoint::for_test(PEER, HOST, generation, PROTOCOL_VERSION_V2, [91; 32])
                .unwrap();
        assert_eq!(format!("{endpoint:?}"), "SessionEndpoint([REDACTED])");
    }
}
