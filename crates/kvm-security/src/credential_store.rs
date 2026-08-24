//! OS-neutral credential-store addressing and a plain-file reference store.
//!
//! [`crate::credential::CredentialStore`] remains the domain-facing boundary:
//! it addresses credentials by [`crate::credential::CredentialKey`] and is what
//! pairing and identity code consume. This module adds the lower-level
//! service-and-account addressing that operating-system credential facilities
//! (macOS Keychain generic passwords, Windows Credential Manager) natively use,
//! so platform adapters translate domain keys once instead of per operation.
//!
//! [`crate::ServiceCredentialStore`] is deliberately async-free: every backend is a
//! short local operation, and callers that need concurrency can wrap the trait
//! themselves. [`crate::FileCredentialStore`] is the reference implementation for
//! tests and hosts without a native credential facility; it keeps secrets in
//! permission-restricted files (0600/0700 on Unix) and is never a production
//! substitute for Keychain or Credential Manager storage. This crate performs
//! no operating-system credential API calls of its own (architecture rule):
//! the Keychain and Credential Manager adapters live in the platform crates.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroize;

use crate::credential::{
    CredentialKey, CredentialPurpose, CredentialStore, CredentialStoreError, SecretBytes,
};

/// Maximum length of a credential service or account label, in UTF-8 bytes.
///
/// The bound keeps native-store keys small and keeps file-store path
/// components well inside filesystem name limits.
pub const MAX_LABEL_BYTES: usize = 64;

/// Maximum length of a stored secret, in bytes.
///
/// The bound stays below the Windows Credential Manager per-blob limit
/// (`CRED_MAX_CREDENTIAL_BLOB_SIZE`, 2560 bytes) with margin while remaining
/// far larger than every credential this workspace stores (identity private
/// keys, TLS resumption secrets).
pub const MAX_SECRET_BYTES: usize = 2048;

/// Invalid credential-store label.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialLabelError {
    /// The service or account name was empty or whitespace-only.
    #[error("credential {label} must not be empty")]
    Blank {
        /// Which label was invalid.
        label: &'static str,
    },
    /// The service or account name exceeded [`MAX_LABEL_BYTES`].
    #[error("credential {label} is {actual} bytes; the maximum is {maximum}")]
    TooLong {
        /// Which label was invalid.
        label: &'static str,
        /// The rejected length in bytes.
        actual: usize,
        /// The enforced maximum in bytes.
        maximum: usize,
    },
    /// The label contained a control character or the reserved `/` separator.
    #[error("credential {label} must not contain control characters or '/'")]
    InvalidCharacter {
        /// Which label was invalid.
        label: &'static str,
    },
}

fn validate_label(label: &'static str, value: &str) -> Result<(), CredentialLabelError> {
    if value.trim().is_empty() {
        return Err(CredentialLabelError::Blank { label });
    }
    let length = value.len();
    if length > MAX_LABEL_BYTES {
        return Err(CredentialLabelError::TooLong {
            label,
            actual: length,
            maximum: MAX_LABEL_BYTES,
        });
    }
    if value.chars().any(char::is_control) || value.contains('/') {
        return Err(CredentialLabelError::InvalidCharacter { label });
    }
    Ok(())
}

/// Service namespace of a stored credential, e.g. `software-kvm.identity`.
///
/// Labels are validated at construction, so every backend receives bounded,
/// NUL-free, separator-free identifiers. Diagnostics are redacted because
/// accounts embed stable peer identifiers, which the workspace never logs.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServiceName(String);

impl ServiceName {
    /// Creates a validated service label.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialLabelError`] when the label is blank, longer than
    /// [`MAX_LABEL_BYTES`], or contains a control character or `/`.
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialLabelError> {
        let value = value.into();
        validate_label("service name", &value)?;
        Ok(Self(value))
    }

    /// Returns the validated label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ServiceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceName([REDACTED])")
    }
}

/// Account name of a stored credential within its [`ServiceName`] namespace.
///
/// Accounts embed stable identifiers (e.g. peer IDs), so diagnostics are
/// redacted like the rest of the workspace's identity material.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountName(String);

impl AccountName {
    /// Creates a validated account label.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialLabelError`] when the label is blank, longer than
    /// [`MAX_LABEL_BYTES`], or contains a control character or `/`.
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialLabelError> {
        let value = value.into();
        validate_label("account name", &value)?;
        Ok(Self(value))
    }

    /// Returns the validated label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccountName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountName([REDACTED])")
    }
}

/// Validates a secret length against [`MAX_SECRET_BYTES`].
///
/// Shared by every store implementation so all backends enforce one bound;
/// Windows Credential Manager additionally enforces its own smaller hard
/// platform limit inside the platform adapter.
///
/// # Errors
///
/// Returns [`CredentialStoreError::Backend`] with a secret-free message when
/// the length exceeds [`MAX_SECRET_BYTES`].
pub fn validate_secret_length(length: usize) -> Result<(), CredentialStoreError> {
    if length > MAX_SECRET_BYTES {
        return Err(CredentialStoreError::Backend(format!(
            "credential secret is {length} bytes; the maximum is {MAX_SECRET_BYTES}"
        )));
    }
    Ok(())
}

/// OS-neutral credential storage addressed by service and account.
///
/// This is the abstraction native platform adapters implement: macOS Keychain
/// generic passwords and Windows Credential Manager entries both natively
/// address credentials by a service/target plus account. Retrieved secrets are
/// returned as newly owned [`SecretBytes`] that zeroize on drop; every store
/// must enforce [`MAX_LABEL_BYTES`] inputs (guaranteed by the label types) and
/// [`MAX_SECRET_BYTES`] via [`validate_secret_length`].
///
/// The trait is dyn-compatible for callers that need to select a backend at
/// runtime.
pub trait ServiceCredentialStore {
    /// Retrieves a stored credential as owned, zeroizing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError`] on backend failure; `Ok(None)` means
    /// no credential is stored under the given labels.
    fn get(
        &self,
        service: &ServiceName,
        account: &AccountName,
    ) -> Result<Option<SecretBytes>, CredentialStoreError>;

    /// Stores or replaces the credential under the given labels.
    ///
    /// The secret is consumed (and zeroized on drop) whether the operation
    /// succeeds or fails.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError`] on backend failure or when the secret
    /// exceeds [`MAX_SECRET_BYTES`].
    fn put(
        &mut self,
        service: &ServiceName,
        account: &AccountName,
        secret: SecretBytes,
    ) -> Result<(), CredentialStoreError>;

    /// Deletes the credential. Missing labels are treated as already deleted.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError`] on backend failure.
    fn delete(
        &mut self,
        service: &ServiceName,
        account: &AccountName,
    ) -> Result<(), CredentialStoreError>;
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex encoding of arbitrary label bytes.
///
/// Hex-encoded labels keep file-store paths free of traversal and separator
/// hazards regardless of what a label contains.
fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn credential_io_error(context: &'static str, error: &io::Error) -> CredentialStoreError {
    CredentialStoreError::Backend(format!("{context}: {error}"))
}

/// Creates a directory for secret material, restricting it to the owner on
/// Unix. A pre-existing directory is accepted only when it is a real
/// directory (not a symlink) with owner-only group/other permission bits on
/// Unix; anything looser is rejected rather than silently tightened, because
/// an administrator may have set the looser mode deliberately.
fn create_secret_dir(path: &Path) -> Result<(), CredentialStoreError> {
    let build = || -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(path)
        }
        #[cfg(not(unix))]
        {
            fs::DirBuilder::new().recursive(true).create(path)
        }
    };
    build()
        .or_else(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|error| credential_io_error("creating credential directory", &error))?;
    #[cfg(unix)]
    verify_secret_dir(path)?;
    Ok(())
}

/// Rejects a secret directory whose type or permissions would expose secret
/// material beyond its owner: symlinks and any group/other access bits are
/// refused.
#[cfg(unix)]
fn verify_secret_dir(path: &Path) -> Result<(), CredentialStoreError> {
    use std::os::unix::fs::PermissionsExt;

    // lstat: a symlink must be judged as a symlink, not by the permissions
    // of whatever directory it points at.
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| credential_io_error("inspecting credential directory", &error))?;
    if metadata.file_type().is_symlink() {
        return Err(CredentialStoreError::Insecure);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CredentialStoreError::Insecure);
    }
    Ok(())
}

/// Plain-file reference credential store for tests and non-native hosts.
///
/// Each credential is one file at
/// `<root>/<hex(service)>/<hex(account)>.secret`, written through a fresh
/// uniquely named temporary file (process id plus counter, always created
/// new so a stale temporary can never leak its permissions into the
/// published secret) that is atomically renamed into place so a crash never
/// leaves a truncated secret. On Unix the root, per-service directories,
/// and secret files are created with owner-only permissions (0700/0600),
/// and a pre-existing root or service directory is accepted only when it
/// is a real directory with owner-only group/other permission bits;
/// non-Unix hosts get the platform's default file security, which is why
/// production hosts must use the native platform adapter instead. File
/// contents are the raw secret bytes with no framing or encryption.
#[derive(Debug)]
pub struct FileCredentialStore {
    root: PathBuf,
}

/// Unique temporary-name counter for [`write_secret_file`]. Combined with
/// the process id it makes every temporary name fresh across restarts and
/// across concurrent writes within one process.
static NEXT_TEMP_SUFFIX: AtomicU64 = AtomicU64::new(0);

/// Upper bound on `create_new` collisions before a write gives up.
const MAX_TEMP_ATTEMPTS: u64 = 64;

impl FileCredentialStore {
    /// Opens (and creates if needed) a store rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError::Backend`] when the root directory
    /// cannot be created, and [`CredentialStoreError::Insecure`] on Unix
    /// when a pre-existing root is a symlink or allows group/other access.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, CredentialStoreError> {
        let root = root.into();
        create_secret_dir(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, service: &ServiceName, account: &AccountName) -> PathBuf {
        self.root
            .join(hex_encode(service.as_str().as_bytes()))
            .join(format!(
                "{}.secret",
                hex_encode(account.as_str().as_bytes())
            ))
    }
}

/// Returns the `<name>.<pid>.<suffix>.tmp` sibling of `path` used for one
/// temporary write attempt.
fn temp_path_for(path: &Path, suffix: u64) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}.{}.tmp", std::process::id(), suffix));
    path.with_file_name(name)
}

impl ServiceCredentialStore for FileCredentialStore {
    fn get(
        &self,
        service: &ServiceName,
        account: &AccountName,
    ) -> Result<Option<SecretBytes>, CredentialStoreError> {
        let path = self.path_for(service, account);
        let mut file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(credential_io_error("opening credential file", &error)),
        };
        let length = file
            .metadata()
            .map_err(|error| credential_io_error("reading credential metadata", &error))?
            .len();
        if length > MAX_SECRET_BYTES as u64 {
            return Err(CredentialStoreError::Corrupt);
        }
        // Pre-allocate exactly the (already bounded) length so the read
        // never reallocates and leaves stale plaintext copies behind.
        let capacity = usize::try_from(length).map_err(|_| CredentialStoreError::Corrupt)?;
        let mut bytes = Vec::with_capacity(capacity);
        if let Err(error) = file.read_to_end(&mut bytes) {
            bytes.zeroize();
            return Err(credential_io_error("reading credential file", &error));
        }
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            bytes.zeroize();
            return Err(CredentialStoreError::Corrupt);
        }
        Ok(Some(
            SecretBytes::new(bytes).map_err(|_| CredentialStoreError::Corrupt)?,
        ))
    }

    fn put(
        &mut self,
        service: &ServiceName,
        account: &AccountName,
        secret: SecretBytes,
    ) -> Result<(), CredentialStoreError> {
        validate_secret_length(secret.expose_secret().len())?;
        let path = self.path_for(service, account);
        let Some(parent) = path.parent() else {
            return Err(CredentialStoreError::Backend(
                "credential file has no parent directory".to_owned(),
            ));
        };
        create_secret_dir(parent)?;
        let temp_suffix = NEXT_TEMP_SUFFIX.fetch_add(1, Ordering::Relaxed);
        write_secret_file(&path, temp_suffix, secret.expose_secret())
    }

    fn delete(
        &mut self,
        service: &ServiceName,
        account: &AccountName,
    ) -> Result<(), CredentialStoreError> {
        let path = self.path_for(service, account);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(credential_io_error("deleting credential file", &error)),
        }
    }
}

/// Writes `bytes` to a fresh temporary sibling of `path`, syncs it, then
/// atomically renames it over `path`.
///
/// The temporary file is always created new (`create_new`) under a
/// process-id plus `temp_suffix` name (bumped on collision), so a temporary
/// file left behind by an earlier crash can never be written through and its
/// permissions can never become the published secret's permissions.
fn write_secret_file(
    path: &Path,
    temp_suffix: u64,
    bytes: &[u8],
) -> Result<(), CredentialStoreError> {
    #[cfg(unix)]
    let open_with_owner_permissions = |options: &mut fs::OpenOptions| {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    };
    #[cfg(not(unix))]
    let open_with_owner_permissions = |_options: &mut fs::OpenOptions| {};

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    open_with_owner_permissions(&mut options);

    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let temp_path = temp_path_for(path, temp_suffix.wrapping_add(attempt));
        let mut file = match options.open(&temp_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                // A leftover temporary file owns this name; never write
                // through it — try the next unique name.
                continue;
            }
            Err(error) => {
                return Err(credential_io_error("creating credential file", &error));
            }
        };
        let write_result = file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| credential_io_error("writing credential file", &error));
        drop(file);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
        let published = fs::rename(&temp_path, path)
            .map_err(|error| credential_io_error("publishing credential file", &error));
        if published.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        return published;
    }
    Err(CredentialStoreError::Backend(format!(
        "credential temp file name collided {MAX_TEMP_ATTEMPTS} times"
    )))
}

const IDENTITY_SERVICE: &str = "software-kvm.identity";
const IDENTITY_ACCOUNT: &str = "local-identity-private-key";
const PEER_TLS_RESUMPTION_SERVICE: &str = "software-kvm.peer.tls-resumption";

fn invalid_label_error() -> CredentialStoreError {
    CredentialStoreError::Backend(
        "credential key mapping produced an invalid store label".to_owned(),
    )
}

/// Adapter that presents any [`ServiceCredentialStore`] as the domain-facing
/// [`CredentialStore`] addressed by [`CredentialKey`].
///
/// Domain keys map one-to-one onto service/account labels: the local identity
/// private key has a dedicated service, and each peer credential purpose gets
/// its own service so material can never be replayed across purposes. The
/// mapping is total and its labels are covered by tests.
#[derive(Debug)]
pub struct KeyedCredentialStore<S> {
    inner: S,
}

impl<S> KeyedCredentialStore<S> {
    /// Wraps a raw store.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    /// Returns the wrapped store.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Borrows the wrapped store.
    #[must_use]
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Maps a domain key to its store labels.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError::Backend`] only if a mapping constant
    /// were to violate the label rules; tests pin the constants, so this is
    /// unreachable defensive handling rather than an expected failure.
    pub fn labels(key: CredentialKey) -> Result<(ServiceName, AccountName), CredentialStoreError> {
        let (service, account): (&str, String) = match key {
            CredentialKey::LocalIdentityPrivateKey => {
                (IDENTITY_SERVICE, IDENTITY_ACCOUNT.to_owned())
            }
            CredentialKey::Peer { peer_id, purpose } => {
                let service = match purpose {
                    CredentialPurpose::TlsResumption => PEER_TLS_RESUMPTION_SERVICE,
                };
                (service, peer_id.to_string())
            }
        };
        let service = ServiceName::new(service).map_err(|_| invalid_label_error())?;
        let account = AccountName::new(account).map_err(|_| invalid_label_error())?;
        Ok((service, account))
    }
}

impl<S: ServiceCredentialStore> CredentialStore for KeyedCredentialStore<S> {
    fn get(&self, key: CredentialKey) -> Result<Option<SecretBytes>, CredentialStoreError> {
        let (service, account) = Self::labels(key)?;
        self.inner.get(&service, &account)
    }

    fn put(&mut self, key: CredentialKey, secret: SecretBytes) -> Result<(), CredentialStoreError> {
        let (service, account) = Self::labels(key)?;
        self.inner.put(&service, &account, secret)
    }

    fn remove(&mut self, key: CredentialKey) -> Result<(), CredentialStoreError> {
        let (service, account) = Self::labels(key)?;
        self.inner.delete(&service, &account)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use kvm_types::PeerId;

    use super::*;

    static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn scratch_store(tag: &str) -> (FileCredentialStore, PathBuf) {
        let unique = format!(
            "kvm-security-credential-store-{tag}-{}-{}",
            std::process::id(),
            SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let root = std::env::temp_dir().join(unique);
        let store = FileCredentialStore::new(&root).unwrap();
        (store, root)
    }

    fn labels(service: &str, account: &str) -> (ServiceName, AccountName) {
        (
            ServiceName::new(service).unwrap(),
            AccountName::new(account).unwrap(),
        )
    }

    #[test]
    fn labels_reject_blank_oversized_and_invalid_characters() {
        assert_eq!(
            ServiceName::new("   "),
            Err(CredentialLabelError::Blank {
                label: "service name"
            })
        );
        assert_eq!(
            AccountName::new("x".repeat(MAX_LABEL_BYTES + 1)),
            Err(CredentialLabelError::TooLong {
                label: "account name",
                actual: MAX_LABEL_BYTES + 1,
                maximum: MAX_LABEL_BYTES,
            })
        );
        assert_eq!(
            ServiceName::new("a/b"),
            Err(CredentialLabelError::InvalidCharacter {
                label: "service name"
            })
        );
        assert_eq!(
            AccountName::new("a\u{0}b"),
            Err(CredentialLabelError::InvalidCharacter {
                label: "account name"
            })
        );
        assert_eq!(ServiceName::new("x").unwrap().as_str(), "x");
        assert_eq!(
            AccountName::new("x".repeat(MAX_LABEL_BYTES))
                .unwrap()
                .as_str(),
            "x".repeat(MAX_LABEL_BYTES)
        );
    }

    #[test]
    fn label_diagnostics_are_redacted() {
        let (service, account) = labels("SECRET-SERVICE-NAME", "SECRET-ACCOUNT-NAME");
        let rendered = format!("{service:?} {account:?}");

        assert_eq!(rendered, "ServiceName([REDACTED]) AccountName([REDACTED])");
        assert!(!rendered.contains("SECRET-SERVICE-NAME"));
        assert!(!rendered.contains("SECRET-ACCOUNT-NAME"));
    }

    #[test]
    fn file_store_round_trips_replaces_and_deletes() {
        let (mut store, root) = scratch_store("roundtrip");
        let (service, account) = labels("software-kvm-test.service", "round-trip");

        assert!(store.get(&service, &account).unwrap().is_none());
        store
            .put(
                &service,
                &account,
                SecretBytes::new(b"first-secret-material".to_vec()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store
                .get(&service, &account)
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"first-secret-material"
        );
        store
            .put(
                &service,
                &account,
                SecretBytes::new(b"replacement-secret-material".to_vec()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store
                .get(&service, &account)
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"replacement-secret-material"
        );
        store.delete(&service, &account).unwrap();
        store.delete(&service, &account).unwrap();
        assert!(store.get(&service, &account).unwrap().is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_store_keeps_services_isolated() {
        let (mut store, root) = scratch_store("isolation");
        let (service_a, account) = labels("software-kvm-test.service-a", "shared-account");
        let (service_b, account_b) = labels("software-kvm-test.service-b", "shared-account");

        store
            .put(
                &service_a,
                &account,
                SecretBytes::new(vec![1, 2, 3]).unwrap(),
            )
            .unwrap();
        assert!(store.get(&service_b, &account_b).unwrap().is_none());
        store.delete(&service_a, &account).unwrap();
        assert!(store.get(&service_a, &account).unwrap().is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn file_store_restricts_file_and_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (mut store, root) = scratch_store("permissions");
        let (service, account) = labels("software-kvm-test.service", "permissions");
        store
            .put(&service, &account, SecretBytes::new(vec![9; 16]).unwrap())
            .unwrap();

        let service_dir = root.join(hex_encode(service.as_str().as_bytes()));
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&service_dir), 0o700);
        let secret_file = service_dir.join(format!(
            "{}.secret",
            hex_encode(account.as_str().as_bytes())
        ));
        assert_eq!(mode(&secret_file), 0o600);

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn file_store_rejects_a_world_accessible_preexisting_service_dir() {
        use std::os::unix::fs::PermissionsExt;

        let (mut store, root) = scratch_store("loose-service-dir");
        let (service, account) = labels("software-kvm-test.service", "loose-dir");
        let service_dir = root.join(hex_encode(service.as_str().as_bytes()));
        fs::create_dir(&service_dir).unwrap();
        fs::set_permissions(&service_dir, fs::Permissions::from_mode(0o707)).unwrap();

        let error = store
            .put(&service, &account, SecretBytes::new(vec![1, 2, 3]).unwrap())
            .unwrap_err();
        assert_eq!(error, CredentialStoreError::Insecure);
        // Nothing was published next to the rejected directory.
        assert!(store.get(&service, &account).unwrap().is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn file_store_rejects_world_accessible_and_symlinked_roots() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        // A pre-made world-writable root is rejected, not silently tightened.
        let loose_root = std::env::temp_dir().join(format!(
            "kvm-security-credential-store-loose-root-{}-{}",
            std::process::id(),
            SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&loose_root).unwrap();
        fs::set_permissions(&loose_root, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            FileCredentialStore::new(&loose_root).unwrap_err(),
            CredentialStoreError::Insecure
        );

        // A symlink is rejected even when it points at a well-protected
        // directory.
        let (_, protected_root) = scratch_store("link-target");
        let link = std::env::temp_dir().join(format!(
            "kvm-security-credential-store-link-{}-{}",
            std::process::id(),
            SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        symlink(&protected_root, &link).unwrap();
        assert_eq!(
            FileCredentialStore::new(&link).unwrap_err(),
            CredentialStoreError::Insecure
        );

        fs::set_permissions(&loose_root, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(loose_root);
        let _ = fs::remove_dir_all(protected_root);
        let _ = fs::remove_file(link);
    }

    #[test]
    fn write_secret_file_never_writes_through_a_leftover_temp_file() {
        let root = std::env::temp_dir().join(format!(
            "kvm-security-credential-store-leftover-{}-{}",
            std::process::id(),
            SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("account.secret");

        // A temporary file left behind by an earlier crashed write of this
        // process, occupying the exact suffix the next write would use.
        let stale_temp = temp_path_for(&path, 24);
        fs::write(&stale_temp, b"stale-plaintext").unwrap();

        write_secret_file(&path, 24, b"fresh-secret").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"fresh-secret");
        assert_eq!(
            fs::read(&stale_temp).unwrap(),
            b"stale-plaintext",
            "the leftover temp file must not be written through"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600,
                "the published secret keeps the fresh temp file's permissions"
            );
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_store_rejects_oversized_secrets() {
        let (mut store, root) = scratch_store("oversize");
        let (service, account) = labels("software-kvm-test.service", "oversize");

        let error = store
            .put(
                &service,
                &account,
                SecretBytes::new(vec![7; MAX_SECRET_BYTES + 1]).unwrap(),
            )
            .unwrap_err();
        assert!(
            matches!(&error, CredentialStoreError::Backend(message) if message.contains("maximum")),
            "unexpected error: {error:?}"
        );
        assert!(store.get(&service, &account).unwrap().is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_store_reports_empty_and_oversized_files_as_corrupt() {
        let (mut store, root) = scratch_store("corrupt");
        let (service, account) = labels("software-kvm-test.service", "corrupt");
        store
            .put(&service, &account, SecretBytes::new(vec![5; 8]).unwrap())
            .unwrap();
        let secret_file = store.path_for(&service, &account);
        drop(store);

        fs::write(&secret_file, b"").unwrap();
        let reopened = FileCredentialStore::new(&root).unwrap();
        assert!(matches!(
            reopened.get(&service, &account),
            Err(CredentialStoreError::Corrupt)
        ));

        fs::write(&secret_file, vec![0; MAX_SECRET_BYTES + 1]).unwrap();
        assert!(matches!(
            reopened.get(&service, &account),
            Err(CredentialStoreError::Corrupt)
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn keyed_labels_map_domain_keys_to_purpose_separated_services() {
        let (service, account) = KeyedCredentialStore::<FileCredentialStore>::labels(
            CredentialKey::LocalIdentityPrivateKey,
        )
        .unwrap();
        assert_eq!(service.as_str(), "software-kvm.identity");
        assert_eq!(account.as_str(), "local-identity-private-key");

        let peer_id = PeerId::from_bytes([0x44; 16]);
        let (service, account) =
            KeyedCredentialStore::<FileCredentialStore>::labels(CredentialKey::Peer {
                peer_id,
                purpose: CredentialPurpose::TlsResumption,
            })
            .unwrap();
        assert_eq!(service.as_str(), "software-kvm.peer.tls-resumption");
        assert_eq!(account.as_str(), peer_id.to_string());
    }

    #[test]
    fn keyed_store_backs_the_domain_trait_with_any_raw_store() {
        let (file_store, root) = scratch_store("keyed");
        let mut store = KeyedCredentialStore::new(file_store);
        let key = CredentialKey::LocalIdentityPrivateKey;

        store
            .put(
                key,
                SecretBytes::new(b"identity-key-material".to_vec()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store.get(key).unwrap().unwrap().expose_secret(),
            b"identity-key-material"
        );
        store.remove(key).unwrap();
        assert!(store.get(key).unwrap().is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn keyed_store_propagates_backend_errors_without_secret_material() {
        struct FailingStore;
        impl ServiceCredentialStore for FailingStore {
            fn get(
                &self,
                _service: &ServiceName,
                _account: &AccountName,
            ) -> Result<Option<SecretBytes>, CredentialStoreError> {
                Err(CredentialStoreError::AccessDenied)
            }

            fn put(
                &mut self,
                _service: &ServiceName,
                _account: &AccountName,
                _secret: SecretBytes,
            ) -> Result<(), CredentialStoreError> {
                Err(CredentialStoreError::AccessDenied)
            }

            fn delete(
                &mut self,
                _service: &ServiceName,
                _account: &AccountName,
            ) -> Result<(), CredentialStoreError> {
                Err(CredentialStoreError::AccessDenied)
            }
        }

        let mut store = KeyedCredentialStore::new(FailingStore);
        let error = store
            .put(
                CredentialKey::LocalIdentityPrivateKey,
                SecretBytes::new(b"must-not-appear".to_vec()).unwrap(),
            )
            .unwrap_err();
        assert_eq!(error, CredentialStoreError::AccessDenied);
        assert!(!error.to_string().contains("must-not-appear"));
    }
}
