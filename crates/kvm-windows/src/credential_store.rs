//! Windows Credential Manager adapter for the OS-neutral credential store.
//!
//! Secrets are stored as generic credentials (`CRED_TYPE_GENERIC`) addressed
//! by a `service/account` target name; label validation upstream forbids `/`
//! in labels, so the joined target is unambiguous. Entries persist for the
//! local machine only (`CRED_PERSIST_LOCAL_MACHINE`) — host identity material
//! must never roam with a user profile. `CredWriteW` replaces an existing
//! entry with the same target name and type, so storing is an upsert and
//! re-pairing cannot leave stale material. Deletion is idempotent: missing
//! entries are treated as already deleted.
//!
//! Every buffer passed to the Win32 API is owned and kept alive for the
//! duration of its call, the credential record returned by `CredReadW` is
//! released with `CredFree` on every path, and diagnostics contain only the
//! failing operation name and an HRESULT — never label text or secret bytes.

// Win32 bindings necessarily cross an FFI boundary; each unsafe block below
// carries a local SAFETY justification.
#![allow(unsafe_code)]

use std::ptr;
use std::slice;

use kvm_security::{
    validate_secret_length, AccountName, CredentialStoreError, SecretBytes, ServiceCredentialStore,
    ServiceName, MAX_SECRET_BYTES,
};
use windows::core::{Error as WindowsError, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NOT_FOUND};
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};

/// The Credential Manager per-blob hard limit (`CRED_MAX_CREDENTIAL_BLOB_SIZE`).
///
/// [`MAX_SECRET_BYTES`] is deliberately below it; this constant documents and
/// enforces the platform ceiling independently.
const MAX_CREDENTIAL_BLOB_BYTES: usize = 5 * 512;

/// Windows Credential Manager store over generic credentials.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsCredentialStore;

impl WindowsCredentialStore {
    /// Creates a store bound to the current user's Credential Manager.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Builds the NUL-terminated UTF-16 `service/account` target name.
///
/// Labels cannot contain `/` (validated at construction in kvm-security), so
/// distinct label pairs always produce distinct target names.
fn target_name(service: &ServiceName, account: &AccountName) -> Vec<u16> {
    format!("{}/{}", service.as_str(), account.as_str())
        .encode_utf16()
        .chain([0])
        .collect()
}

/// Builds the NUL-terminated UTF-16 account name for the credential's
/// `UserName` field.
fn user_name(account: &AccountName) -> Vec<u16> {
    account.as_str().encode_utf16().chain([0]).collect()
}

fn is_not_found(error: &WindowsError) -> bool {
    error.code() == HRESULT::from_win32(ERROR_NOT_FOUND.0)
}

/// Converts a Win32 failure into the store error taxonomy.
///
/// Only the failing operation name and HRESULT are included, so no
/// diagnostic can leak label text or secret material.
fn credential_error(operation: &'static str, error: &WindowsError) -> CredentialStoreError {
    if error.code() == HRESULT::from_win32(ERROR_ACCESS_DENIED.0) {
        CredentialStoreError::AccessDenied
    } else {
        CredentialStoreError::Backend(format!("{operation} failed with HRESULT {}", error.code()))
    }
}

/// Copies the blob out of a live `CredReadW` record.
///
/// Validation happens before any copy, so no partial secret buffer can
/// outlive this helper.
fn extract_blob(record: &CREDENTIALW) -> Result<SecretBytes, CredentialStoreError> {
    let Ok(size) = usize::try_from(record.CredentialBlobSize) else {
        return Err(CredentialStoreError::Corrupt);
    };
    if size == 0 || size > MAX_SECRET_BYTES || record.CredentialBlob.is_null() {
        return Err(CredentialStoreError::Corrupt);
    }
    // SAFETY: `CredentialBlob` points at `CredentialBlobSize` readable bytes
    // owned by the still-live credential record; `size` reuses that bound.
    let bytes = unsafe { slice::from_raw_parts(record.CredentialBlob, size) }.to_vec();
    SecretBytes::new(bytes).map_err(|_| CredentialStoreError::Corrupt)
}

impl ServiceCredentialStore for WindowsCredentialStore {
    fn get(
        &self,
        service: &ServiceName,
        account: &AccountName,
    ) -> Result<Option<SecretBytes>, CredentialStoreError> {
        let target = target_name(service, account);
        let mut credential: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: `target` is a NUL-terminated UTF-16 buffer valid for the
        // call; on success `credential` receives an allocation owned by this
        // function that is released with `CredFree` on every path below.
        let read = unsafe {
            CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                None,
                &raw mut credential,
            )
        };
        match read {
            Ok(()) => {
                // SAFETY: `credential` is the live record returned by
                // `CredReadW`; borrowing it for extraction does not transfer
                // ownership.
                let record = unsafe { &*credential };
                let outcome = extract_blob(record);
                // SAFETY: the record allocation came from `CredReadW` and is
                // released here exactly once on every path.
                unsafe { CredFree(credential.cast()) };
                outcome.map(Some)
            }
            Err(error) if is_not_found(&error) => Ok(None),
            Err(error) => Err(credential_error("CredReadW", &error)),
        }
    }

    fn put(
        &mut self,
        service: &ServiceName,
        account: &AccountName,
        secret: SecretBytes,
    ) -> Result<(), CredentialStoreError> {
        let length = secret.expose_secret().len();
        validate_secret_length(length)?;
        if length > MAX_CREDENTIAL_BLOB_BYTES {
            return Err(CredentialStoreError::Backend(format!(
                "credential secret is {length} bytes; the Credential Manager limit is \
                 {MAX_CREDENTIAL_BLOB_BYTES}"
            )));
        }
        let mut target = target_name(service, account);
        let mut user_name = user_name(account);
        let blob_size = u32::try_from(length).map_err(|_| {
            CredentialStoreError::Backend(
                "credential secret exceeds the Credential Manager size limit".to_owned(),
            )
        })?;
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target.as_mut_ptr()),
            UserName: PWSTR(user_name.as_mut_ptr()),
            CredentialBlob: secret.expose_secret().as_ptr().cast_mut(),
            CredentialBlobSize: blob_size,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..CREDENTIALW::default()
        };
        // SAFETY: every pointer in `credential` points at buffers that outlive
        // this call, and `CredWriteW` only reads them. It replaces an existing
        // entry with the same target name and type, making this an upsert.
        let written = unsafe { CredWriteW(&raw const credential, 0) };
        // Drop (and therefore zeroize) the owned secret whether or not the
        // entry was stored; the target/user-name buffers free naturally at
        // the end of the scope, after the call has already completed.
        drop(secret);
        written.map_err(|error| credential_error("CredWriteW", &error))
    }

    fn delete(
        &mut self,
        service: &ServiceName,
        account: &AccountName,
    ) -> Result<(), CredentialStoreError> {
        let target = target_name(service, account);
        // SAFETY: `target` is a NUL-terminated UTF-16 buffer valid for the
        // call; deletion takes no output pointers.
        let deleted = unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None) };
        match deleted {
            Ok(()) => Ok(()),
            // Missing entries are treated as already deleted.
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(credential_error("CredDeleteW", &error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use kvm_security::{AccountName, SecretBytes, ServiceName};

    use super::*;

    fn unique_service() -> ServiceName {
        ServiceName::new(format!("software-kvm-test-{}", Uuid::new_v4())).unwrap()
    }

    #[test]
    fn target_names_separate_services_and_accounts() {
        let service = ServiceName::new("software-kvm.test").unwrap();
        let account = AccountName::new("account").unwrap();
        let other = AccountName::new("other").unwrap();

        assert_eq!(
            target_name(&service, &account),
            "software-kvm.test/account"
                .encode_utf16()
                .chain([0])
                .collect::<Vec<_>>()
        );
        assert_ne!(
            target_name(&service, &account),
            target_name(&service, &other)
        );
        assert_eq!(*target_name(&service, &account).last().unwrap(), 0);
    }

    #[test]
    fn not_found_and_access_denied_map_to_the_store_taxonomy() {
        // `HRESULT::from_win32` is the exact wrapping the windows crate uses
        // for `GetLastError`, so these comparisons exercise the mapping.
        let not_found = WindowsError::from_hresult(HRESULT::from_win32(ERROR_NOT_FOUND.0));
        let denied = WindowsError::from_hresult(HRESULT::from_win32(ERROR_ACCESS_DENIED.0));

        assert!(is_not_found(&not_found));
        assert!(!is_not_found(&denied));
        assert_eq!(
            credential_error("CredWriteW", &denied),
            CredentialStoreError::AccessDenied
        );
        assert!(matches!(
            credential_error("CredWriteW", &not_found),
            CredentialStoreError::Backend(_)
        ));
    }

    #[test]
    fn credential_manager_round_trips_replaces_and_deletes() {
        let mut store = WindowsCredentialStore::new();
        let service = unique_service();
        let account = AccountName::new("round-trip").unwrap();

        assert!(store.get(&service, &account).unwrap().is_none());
        store
            .put(
                &service,
                &account,
                SecretBytes::new(b"credman-test-secret-A".to_vec()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store
                .get(&service, &account)
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"credman-test-secret-A"
        );
        store
            .put(
                &service,
                &account,
                SecretBytes::new(b"credman-test-secret-B".to_vec()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store
                .get(&service, &account)
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"credman-test-secret-B"
        );
        store.delete(&service, &account).unwrap();
        assert!(store.get(&service, &account).unwrap().is_none());
        // Deletion is idempotent.
        store.delete(&service, &account).unwrap();
    }

    #[test]
    fn credential_manager_keeps_accounts_and_services_isolated() {
        let mut store = WindowsCredentialStore::new();
        let service = unique_service();
        let account = AccountName::new("isolated-account").unwrap();
        let other_account = AccountName::new("other-account").unwrap();

        store
            .put(&service, &account, SecretBytes::new(vec![1, 2, 3]).unwrap())
            .unwrap();
        assert!(store.get(&service, &other_account).unwrap().is_none());

        let missing_service = ServiceName::new("software-kvm-test-missing-service").unwrap();
        assert!(store.get(&missing_service, &account).unwrap().is_none());
        // Deleting from an unknown service stays a success.
        store.delete(&missing_service, &account).unwrap();
    }

    #[test]
    fn credential_manager_rejects_oversized_secrets() {
        let mut store = WindowsCredentialStore::new();
        let service = unique_service();
        let account = AccountName::new("oversize").unwrap();

        let error = store
            .put(
                &service,
                &account,
                SecretBytes::new(vec![0x5a; MAX_SECRET_BYTES + 1]).unwrap(),
            )
            .unwrap_err();
        assert!(matches!(error, CredentialStoreError::Backend(_)));
        assert!(store.get(&service, &account).unwrap().is_none());
    }
}
