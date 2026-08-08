use core::fmt;
use std::collections::BTreeMap;

use kvm_types::PeerId;
use thiserror::Error;
use zeroize::Zeroize;

/// Purpose-specific key for private credential material.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CredentialKey {
    /// Private key for this daemon's long-term public identity.
    LocalIdentityPrivateKey,
    /// Private material associated with a paired peer and a constrained purpose.
    Peer {
        peer_id: PeerId,
        purpose: CredentialPurpose,
    },
}

/// Prevents one peer secret from being reused for another protocol purpose.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CredentialPurpose {
    /// TLS session resumption secret/ticket material.
    TlsResumption,
}

/// Owned secret bytes that are redacted in diagnostics and zeroized on drop.
///
/// The wrapper deliberately does not implement `Clone`; callers must make any
/// additional in-memory copy explicit through their credential-store boundary.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps non-empty private material.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Empty`] because an empty credential is never valid.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, SecretError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(SecretError::Empty);
        }
        Ok(Self(bytes))
    }

    /// Borrows secret material for the shortest possible cryptographic operation.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

/// Invalid secret material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretError {
    /// Credentials cannot be empty.
    #[error("secret credential must not be empty")]
    Empty,
}

/// Secure-storage boundary for private credential material.
///
/// Production implementations must use Keychain Services on macOS and an
/// appropriate OS-protected credential facility on Windows. Implementations
/// must not serialize values into `kvm-config` or other plaintext config files.
pub trait CredentialStore {
    /// Retrieves a private credential as newly owned, zeroizing memory.
    ///
    /// # Errors
    ///
    /// Returns a secure-store access, integrity, or backend failure.
    fn get(&self, key: CredentialKey) -> Result<Option<SecretBytes>, CredentialStoreError>;

    /// Stores or replaces private credential material.
    ///
    /// # Errors
    ///
    /// Returns a secure-store access or backend failure. The input is dropped
    /// and zeroized whether the operation succeeds or fails.
    fn put(&mut self, key: CredentialKey, secret: SecretBytes) -> Result<(), CredentialStoreError>;

    /// Deletes private material. Missing keys are treated as already deleted.
    ///
    /// # Errors
    ///
    /// Returns a secure-store access or backend failure.
    fn remove(&mut self, key: CredentialKey) -> Result<(), CredentialStoreError>;
}

/// Volatile credential store for tests and short-lived development tools.
///
/// It is not a production substitute for operating-system protected storage.
#[derive(Debug, Default)]
pub struct MemoryCredentialStore {
    credentials: BTreeMap<CredentialKey, SecretBytes>,
}

impl CredentialStore for MemoryCredentialStore {
    fn get(&self, key: CredentialKey) -> Result<Option<SecretBytes>, CredentialStoreError> {
        Ok(self.credentials.get(&key).map(SecretBytes::duplicate))
    }

    fn put(&mut self, key: CredentialKey, secret: SecretBytes) -> Result<(), CredentialStoreError> {
        self.credentials.insert(key, secret);
        Ok(())
    }

    fn remove(&mut self, key: CredentialKey) -> Result<(), CredentialStoreError> {
        self.credentials.remove(&key);
        Ok(())
    }
}

/// Private credential-store failure. Error values must never contain secret
/// bytes, passwords, bearer tokens, or private-key serialization.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CredentialStoreError {
    /// The operating-system credential service is unavailable.
    #[error("credential store is unavailable")]
    Unavailable,
    /// The current process/user may not access the requested credential.
    #[error("credential store access was denied")]
    AccessDenied,
    /// Stored credential bytes failed integrity or format validation.
    #[error("stored credential is corrupt")]
    Corrupt,
    /// Backend-specific error description that contains no credential material.
    #[error("credential store failed: {0}")]
    Backend(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_fully_redacted() {
        let secret = SecretBytes::new(b"a-very-distinct-private-key".to_vec()).unwrap();
        let debug = format!("{secret:?}");

        assert_eq!(debug, "SecretBytes([REDACTED])");
        assert!(!debug.contains("private-key"));
    }

    #[test]
    fn memory_store_round_trips_and_removes_secret() {
        let mut store = MemoryCredentialStore::default();
        let key = CredentialKey::LocalIdentityPrivateKey;
        store
            .put(key, SecretBytes::new(vec![1, 2, 3]).unwrap())
            .unwrap();

        let loaded = store.get(key).unwrap().unwrap();
        assert_eq!(loaded.expose_secret(), &[1, 2, 3]);
        store.remove(key).unwrap();
        assert!(store.get(key).unwrap().is_none());
    }

    #[derive(Debug)]
    struct FailingCredentialStore;

    impl CredentialStore for FailingCredentialStore {
        fn get(&self, _key: CredentialKey) -> Result<Option<SecretBytes>, CredentialStoreError> {
            Err(CredentialStoreError::AccessDenied)
        }

        fn put(
            &mut self,
            _key: CredentialKey,
            _secret: SecretBytes,
        ) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::AccessDenied)
        }

        fn remove(&mut self, _key: CredentialKey) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::AccessDenied)
        }
    }

    #[test]
    fn credential_store_errors_are_explicit_and_secret_free() {
        let mut store = FailingCredentialStore;
        let secret = SecretBytes::new(b"must-not-appear".to_vec()).unwrap();
        let error = store
            .put(CredentialKey::LocalIdentityPrivateKey, secret)
            .unwrap_err();

        assert_eq!(error, CredentialStoreError::AccessDenied);
        assert!(!error.to_string().contains("must-not-appear"));
        assert!(matches!(
            store.get(CredentialKey::LocalIdentityPrivateKey),
            Err(CredentialStoreError::AccessDenied)
        ));
    }

    #[test]
    fn empty_secrets_are_rejected() {
        assert!(matches!(
            SecretBytes::new(Vec::new()),
            Err(SecretError::Empty)
        ));
    }
}
