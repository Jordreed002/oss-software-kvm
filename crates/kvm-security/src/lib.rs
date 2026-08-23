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
mod client_resolver;
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
pub use client_resolver::{
    PairedClientResolverSnapshot, PairedClientResolverSnapshotError,
    MAX_PAIRED_CLIENT_RESOLVER_ENTRIES,
};
pub use credential::{
    CredentialKey, CredentialPurpose, CredentialStore, CredentialStoreError, MemoryCredentialStore,
    SecretBytes, SecretError,
};
// Purely additive re-export so platform crates can implement the OS-neutral
// service/account credential-store trait; declared in credential.rs.
pub use credential::credential_store::{
    validate_secret_length, AccountName, CredentialLabelError, FileCredentialStore,
    KeyedCredentialStore, ServiceCredentialStore, ServiceName, MAX_LABEL_BYTES, MAX_SECRET_BYTES,
};
pub use identity::{
    DiscoveredPeer, IdentityError, IdentityFingerprint, ParseFingerprintError, PeerIdentity,
};
pub use pairing::{
    PairingAttemptTracker, PairingError, PairingLockoutPolicy, PairingLockoutPolicyError,
    PairingSession, PairingState, VerificationCode, VerificationCodeParseError,
    DEFAULT_MAX_FAILED_VERIFICATION_ATTEMPTS, DEFAULT_VERIFICATION_LOCKOUT_COOLDOWN,
};
