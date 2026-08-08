use std::fmt;

use getrandom::fill as fill_random;
use kvm_network::{AdmissionError, HandshakeTranscript, SessionAdmission, TransportPeerIdentity};
use kvm_protocol::{AuthenticateV1, HelloV1, WireHostId, WireMessage, WirePeerId};
use kvm_types::{HostId, PeerId};
use thiserror::Error;

use crate::{
    AuthorizationError, IdentityFingerprint, PairedPeerAllowlist, PairedPeerStore, PeerIdentity,
};

/// Authentication scheme carried by [`AuthenticateV1`] after mutual TLS.
pub const TLS_EXPORTER_SCHEME: &str = "tls-exporter-v1";

/// Paired-peer admission policy for one local daemon identity.
///
/// The transport owns TLS and exporter derivation. This type owns the
/// application identity policy: it creates a fresh hello nonce, emits the
/// transcript-bound local proof, validates the remote response, reconstructs
/// the transport-authenticated public identity, and requires an exact paired
/// allowlist match.
pub struct PairedSessionAdmission<S> {
    local_identity: PeerIdentity,
    hello_template: HelloV1,
    allowlist: PairedPeerAllowlist<S>,
}

impl<S> fmt::Debug for PairedSessionAdmission<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedSessionAdmission")
            .field("local_identity", &"[REDACTED]")
            .field("hello_nonce", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<S> PairedSessionAdmission<S>
where
    S: PairedPeerStore,
{
    /// Creates an admission policy from validated local public identity and a
    /// hello template. The template nonce is never transmitted; every call to
    /// [`SessionAdmission::local_hello`] replaces it with fresh CSPRNG bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the template is not a valid protocol hello or its
    /// stable IDs do not match the local identity.
    pub fn new(
        local_identity: PeerIdentity,
        hello_template: HelloV1,
        allowlist: PairedPeerAllowlist<S>,
    ) -> Result<Self, PairedSessionAdmissionError> {
        WireMessage::Hello(hello_template.clone())
            .validate()
            .map_err(|_| PairedSessionAdmissionError::InvalidHelloTemplate)?;
        if hello_template.host_id != wire_host_id(local_identity.host_id())
            || hello_template.peer_id != wire_peer_id(local_identity.peer_id())
            || hello_template.host_name != local_identity.display_name()
        {
            return Err(PairedSessionAdmissionError::LocalIdentityMismatch);
        }

        Ok(Self {
            local_identity,
            hello_template,
            allowlist,
        })
    }

    /// Returns the allowlist after the session owner has stopped.
    #[must_use]
    pub fn into_allowlist(self) -> PairedPeerAllowlist<S> {
        self.allowlist
    }

    fn authentication_from_parts(
        &self,
        local_hello: &HelloV1,
        proof: [u8; 32],
    ) -> Result<AuthenticateV1, AdmissionError> {
        if !hello_matches_template(local_hello, &self.hello_template)
            || local_hello.host_id != wire_host_id(self.local_identity.host_id())
            || local_hello.peer_id != wire_peer_id(self.local_identity.peer_id())
        {
            return Err(AdmissionError::Rejected);
        }

        Ok(AuthenticateV1 {
            peer_id: local_hello.peer_id,
            scheme: TLS_EXPORTER_SCHEME.to_owned(),
            proof: proof.to_vec(),
        })
    }

    fn admit_with_verifier(
        &self,
        remote_hello: &HelloV1,
        transport: &TransportPeerIdentity,
        authentication: &AuthenticateV1,
        verify_proof: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), AdmissionError> {
        if authentication.peer_id != remote_hello.peer_id
            || authentication.peer_id != transport.peer_id
            || remote_hello.host_id != transport.host_id
            || remote_hello.peer_id != transport.peer_id
            || authentication.scheme != TLS_EXPORTER_SCHEME
            || authentication.proof.len() != 32
            || !verify_proof(&authentication.proof)
        {
            return Err(AdmissionError::Rejected);
        }

        let identity = PeerIdentity::new(
            PeerId::from_bytes(transport.peer_id.0),
            HostId::from_bytes(transport.host_id.0),
            remote_hello.host_name.clone(),
            IdentityFingerprint::from_sha256(transport.credential_fingerprint),
        )
        .map_err(|_| AdmissionError::Rejected)?;

        self.allowlist
            .authorize_identity(&identity)
            .map(|_| ())
            .map_err(|error| map_authorization_error(&error))
    }
}

impl<S> SessionAdmission for PairedSessionAdmission<S>
where
    S: PairedPeerStore + Send + Sync,
{
    fn local_hello(&self) -> Result<HelloV1, AdmissionError> {
        let mut hello = self.hello_template.clone();
        fill_random(&mut hello.nonce).map_err(|_| AdmissionError::Unavailable)?;
        Ok(hello)
    }

    fn authentication_message(
        &self,
        transcript: &HandshakeTranscript,
    ) -> Result<AuthenticateV1, AdmissionError> {
        self.authentication_from_parts(transcript.local_hello(), transcript.local_exporter_proof())
    }

    fn admit(
        &self,
        transcript: &HandshakeTranscript,
        authentication: &AuthenticateV1,
    ) -> Result<(), AdmissionError> {
        self.admit_with_verifier(
            transcript.remote_hello(),
            transcript.transport_identity(),
            authentication,
            |proof| transcript.verify_remote_exporter_proof(proof),
        )
    }
}

/// Invalid local admission configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PairedSessionAdmissionError {
    /// The hello violated protocol bounds or version requirements.
    #[error("local hello template is invalid")]
    InvalidHelloTemplate,
    /// The hello IDs did not match the validated local public identity.
    #[error("local hello identity does not match local peer identity")]
    LocalIdentityMismatch,
}

fn map_authorization_error(error: &AuthorizationError) -> AdmissionError {
    match error {
        AuthorizationError::Store(_) => AdmissionError::Unavailable,
        AuthorizationError::Transport(_)
        | AuthorizationError::PeerNotPaired(_)
        | AuthorizationError::IdentityMismatch { .. } => AdmissionError::Rejected,
    }
}

fn hello_matches_template(actual: &HelloV1, template: &HelloV1) -> bool {
    actual.host_id == template.host_id
        && actual.peer_id == template.peer_id
        && actual.host_name == template.host_name
        && actual.platform == template.platform
        && actual.minimum_protocol_version == template.minimum_protocol_version
        && actual.maximum_protocol_version == template.maximum_protocol_version
        && actual.daemon_version == template.daemon_version
}

const fn wire_host_id(id: HostId) -> WireHostId {
    WireHostId(id.into_bytes())
}

const fn wire_peer_id(id: PeerId) -> WirePeerId {
    WirePeerId(id.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_network::TransportPeerIdentity;
    use kvm_protocol::{WirePlatform, PROTOCOL_VERSION};

    use crate::{MemoryPairedPeerStore, PairedPeer, PairedPeerStoreError};

    const LOCAL_HOST: HostId = HostId::from_bytes([1; 16]);
    const LOCAL_PEER: PeerId = PeerId::from_bytes([2; 16]);
    const REMOTE_HOST: HostId = HostId::from_bytes([3; 16]);
    const REMOTE_PEER: PeerId = PeerId::from_bytes([4; 16]);
    const LOCAL_FINGERPRINT: [u8; 32] = [5; 32];
    const REMOTE_FINGERPRINT: [u8; 32] = [6; 32];
    const LOCAL_PROOF: [u8; 32] = [7; 32];
    const REMOTE_PROOF: [u8; 32] = [8; 32];

    fn identity(
        host_id: HostId,
        peer_id: PeerId,
        name: &str,
        fingerprint: [u8; 32],
    ) -> PeerIdentity {
        PeerIdentity::new(
            peer_id,
            host_id,
            name,
            IdentityFingerprint::from_sha256(fingerprint),
        )
        .unwrap()
    }

    fn hello(host_id: HostId, peer_id: PeerId, name: &str) -> HelloV1 {
        HelloV1 {
            host_id: wire_host_id(host_id),
            peer_id: wire_peer_id(peer_id),
            host_name: name.to_owned(),
            platform: WirePlatform::MacOs,
            minimum_protocol_version: PROTOCOL_VERSION,
            maximum_protocol_version: PROTOCOL_VERSION,
            daemon_version: "test-daemon".to_owned(),
            nonce: [0xa5; 32],
        }
    }

    fn transport() -> TransportPeerIdentity {
        TransportPeerIdentity {
            host_id: wire_host_id(REMOTE_HOST),
            peer_id: wire_peer_id(REMOTE_PEER),
            credential_fingerprint: REMOTE_FINGERPRINT,
        }
    }

    fn authentication(proof: &[u8]) -> AuthenticateV1 {
        AuthenticateV1 {
            peer_id: wire_peer_id(REMOTE_PEER),
            scheme: TLS_EXPORTER_SCHEME.to_owned(),
            proof: proof.to_vec(),
        }
    }

    fn admission_with_store<S: PairedPeerStore>(store: S) -> PairedSessionAdmission<S> {
        PairedSessionAdmission::new(
            identity(LOCAL_HOST, LOCAL_PEER, "local", LOCAL_FINGERPRINT),
            hello(LOCAL_HOST, LOCAL_PEER, "local"),
            PairedPeerAllowlist::new(store),
        )
        .unwrap()
    }

    fn paired_store() -> MemoryPairedPeerStore {
        let mut store = MemoryPairedPeerStore::default();
        store
            .upsert(PairedPeer::from_persisted_public_identity(identity(
                REMOTE_HOST,
                REMOTE_PEER,
                "persisted name",
                REMOTE_FINGERPRINT,
            )))
            .unwrap();
        store
    }

    #[test]
    fn local_hello_uses_a_fresh_csprng_nonce_per_connection() {
        let admission = admission_with_store(paired_store());
        let first = SessionAdmission::local_hello(&admission).unwrap();
        let second = SessionAdmission::local_hello(&admission).unwrap();

        assert_ne!(first.nonce, [0xa5; 32]);
        assert_ne!(second.nonce, [0xa5; 32]);
        assert_ne!(first.nonce, second.nonce);
        assert!(hello_matches_template(&first, &admission.hello_template));
        assert!(hello_matches_template(&second, &admission.hello_template));
    }

    #[test]
    fn emits_exact_scheme_peer_and_local_exporter_proof() {
        let admission = admission_with_store(paired_store());
        let local = SessionAdmission::local_hello(&admission).unwrap();
        let authentication = admission
            .authentication_from_parts(&local, LOCAL_PROOF)
            .unwrap();

        assert_eq!(authentication.peer_id, wire_peer_id(LOCAL_PEER));
        assert_eq!(authentication.scheme, TLS_EXPORTER_SCHEME);
        assert_eq!(authentication.proof, LOCAL_PROOF);
    }

    #[test]
    fn matching_proof_and_exact_paired_identity_are_admitted() {
        let admission = admission_with_store(paired_store());
        let remote = hello(REMOTE_HOST, REMOTE_PEER, "current display name");
        let result = admission.admit_with_verifier(
            &remote,
            &transport(),
            &authentication(&REMOTE_PROOF),
            |proof| proof == REMOTE_PROOF,
        );

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn reflection_replay_and_tamper_are_rejected() {
        let admission = admission_with_store(paired_store());
        let remote = hello(REMOTE_HOST, REMOTE_PEER, "remote");
        let presented = [LOCAL_PROOF, [9; 32], {
            let mut tampered = REMOTE_PROOF;
            tampered[17] ^= 1;
            tampered
        }];

        for proof in presented {
            assert_eq!(
                admission.admit_with_verifier(
                    &remote,
                    &transport(),
                    &authentication(&proof),
                    |candidate| candidate == REMOTE_PROOF,
                ),
                Err(AdmissionError::Rejected)
            );
        }
    }

    #[test]
    fn wrong_scheme_length_and_stable_ids_are_rejected() {
        let admission = admission_with_store(paired_store());
        let remote = hello(REMOTE_HOST, REMOTE_PEER, "remote");
        let cases = [
            AuthenticateV1 {
                scheme: "other".to_owned(),
                ..authentication(&REMOTE_PROOF)
            },
            authentication(&REMOTE_PROOF[..31]),
            authentication(&[8; 33]),
            AuthenticateV1 {
                peer_id: WirePeerId([99; 16]),
                ..authentication(&REMOTE_PROOF)
            },
        ];

        for candidate in cases {
            assert_eq!(
                admission.admit_with_verifier(&remote, &transport(), &candidate, |proof| proof
                    == REMOTE_PROOF,),
                Err(AdmissionError::Rejected)
            );
        }

        let wrong_hello = hello(HostId::from_bytes([90; 16]), REMOTE_PEER, "remote");
        assert_eq!(
            admission.admit_with_verifier(
                &wrong_hello,
                &transport(),
                &authentication(&REMOTE_PROOF),
                |proof| proof == REMOTE_PROOF,
            ),
            Err(AdmissionError::Rejected)
        );
    }

    #[test]
    fn changed_fingerprint_unpaired_and_revoked_peers_are_rejected() {
        let remote = hello(REMOTE_HOST, REMOTE_PEER, "remote");
        let auth = authentication(&REMOTE_PROOF);

        let admission = admission_with_store(paired_store());
        let mut changed = transport();
        changed.credential_fingerprint = [90; 32];
        assert_eq!(
            admission.admit_with_verifier(&remote, &changed, &auth, |_| true),
            Err(AdmissionError::Rejected)
        );

        let unpaired = admission_with_store(MemoryPairedPeerStore::default());
        assert_eq!(
            unpaired.admit_with_verifier(&remote, &transport(), &auth, |_| true),
            Err(AdmissionError::Rejected)
        );

        let mut revoked_store = paired_store();
        revoked_store.remove(REMOTE_PEER).unwrap();
        let revoked = admission_with_store(revoked_store);
        assert_eq!(
            revoked.admit_with_verifier(&remote, &transport(), &auth, |_| true),
            Err(AdmissionError::Rejected)
        );
    }

    #[derive(Debug)]
    struct UnavailableStore;

    impl PairedPeerStore for UnavailableStore {
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
    fn unavailable_store_maps_to_unavailable_admission() {
        let admission = admission_with_store(UnavailableStore);
        assert_eq!(
            admission.admit_with_verifier(
                &hello(REMOTE_HOST, REMOTE_PEER, "remote"),
                &transport(),
                &authentication(&REMOTE_PROOF),
                |_| true,
            ),
            Err(AdmissionError::Unavailable)
        );
    }

    #[test]
    fn configuration_and_debug_output_redact_nonce_and_proof_material() {
        let admission = admission_with_store(paired_store());
        let debug = format!("{admission:?}");
        let reflected = admission
            .admit_with_verifier(
                &hello(REMOTE_HOST, REMOTE_PEER, "remote"),
                &transport(),
                &authentication(&LOCAL_PROOF),
                |_| false,
            )
            .unwrap_err()
            .to_string();

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("165, 165"));
        assert!(!reflected.contains("7, 7"));
        assert_eq!(reflected, "peer admission was rejected");
    }

    #[test]
    fn constructor_rejects_invalid_or_mismatched_local_hello() {
        let local = identity(LOCAL_HOST, LOCAL_PEER, "local", LOCAL_FINGERPRINT);
        let allowlist = PairedPeerAllowlist::new(paired_store());
        let mut wrong = hello(LOCAL_HOST, PeerId::from_bytes([99; 16]), "local");
        assert!(matches!(
            PairedSessionAdmission::new(local.clone(), wrong, allowlist),
            Err(PairedSessionAdmissionError::LocalIdentityMismatch)
        ));

        wrong = hello(LOCAL_HOST, LOCAL_PEER, "local");
        wrong.minimum_protocol_version = PROTOCOL_VERSION + 1;
        assert!(matches!(
            PairedSessionAdmission::new(local, wrong, PairedPeerAllowlist::new(paired_store())),
            Err(PairedSessionAdmissionError::InvalidHelloTemplate)
        ));
    }
}
