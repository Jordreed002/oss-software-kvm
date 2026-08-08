//! Security-domain primitives for pairing and authorizing Software KVM peers.
//!
//! This crate intentionally does not implement cryptography or TLS. Instead,
//! pairing consumes keying material exported by an authenticated TLS session,
//! and input authorization consumes an identity vouched for by an authenticated,
//! encrypted transport. Concrete rustls and operating-system credential-store
//! adapters belong in platform and transport crates.

mod admission;
mod allowlist;
mod channel_binding;
mod credential;
mod identity;
mod pairing;

pub use admission::{PairedSessionAdmission, PairedSessionAdmissionError, TLS_EXPORTER_SCHEME};
pub use allowlist::{
    AuthenticatedPeerTransport, AuthorizationError, InputAuthorization, MemoryPairedPeerStore,
    PairedPeer, PairedPeerAllowlist, PairedPeerStore, PairedPeerStoreError,
    TransportAuthenticationError,
};
pub use channel_binding::{ChannelBindingError, PairingChannelBinding, PairingContext};
pub use credential::{
    CredentialKey, CredentialPurpose, CredentialStore, CredentialStoreError, MemoryCredentialStore,
    SecretBytes, SecretError,
};
pub use identity::{
    DiscoveredPeer, IdentityError, IdentityFingerprint, ParseFingerprintError, PeerIdentity,
};
pub use pairing::{
    PairingError, PairingSession, PairingState, VerificationCode, VerificationCodeParseError,
};
