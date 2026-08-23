//! macOS Keychain Services adapter for the OS-neutral credential store.
//!
//! Secrets are stored as generic-password items in the user's default
//! (login) keychain, addressed by service and account exactly like the
//! [`ServiceCredentialStore`] abstraction. Storing replaces an existing item
//! through `SecItemUpdate` so re-pairing cannot leave stale material, and
//! deletion is idempotent (`errSecItemNotFound` is success).
//!
//! Every CoreFoundation reference obtained from a create/copy call is owned by
//! an `OwnedCF` guard and released exactly once on every path, following the
//! FFI discipline of `native.rs`. Attribute dictionaries use the documented
//! `SecItem` convention of `null` key/value callbacks: the dictionary never
//! takes ownership of its keys or values, and this module keeps one owning
//! guard per value it adds. No diagnostic ever contains key material, label
//! text, or anything but the failing operation name and numeric `OSStatus`.

// Keychain Services necessarily cross an FFI boundary; each unsafe block
// below carries a local SAFETY justification.
#![allow(unsafe_code)]

use std::ffi::{c_char, c_void, CString};
use std::ptr;
use std::slice;

use kvm_security::{
    validate_secret_length, AccountName, CredentialStoreError, SecretBytes, ServiceCredentialStore,
    ServiceName, MAX_SECRET_BYTES,
};

use crate::native::{CFStringRef, CFTypeRef};

type CFIndex = isize;
type CFAllocatorRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFMutableDictionaryRef = *mut c_void;
type CFDataRef = *const c_void;

const KCF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(value: CFTypeRef);
    fn CFStringCreateWithCString(
        allocator: CFAllocatorRef,
        value: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
    fn CFDictionaryCreateMutable(
        allocator: CFAllocatorRef,
        capacity: CFIndex,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFMutableDictionaryRef;
    fn CFDictionaryAddValue(dictionary: CFMutableDictionaryRef, key: CFTypeRef, value: CFTypeRef);
    fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
    fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    fn CFDataGetLength(data: CFDataRef) -> CFIndex;
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> i32;
    fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> i32;
    fn SecItemUpdate(item_ref: CFTypeRef, attributes_to_update: CFDictionaryRef) -> i32;
    fn SecItemDelete(query: CFDictionaryRef) -> i32;

    #[allow(non_upper_case_globals)]
    static kCFBooleanTrue: CFTypeRef;

    #[allow(non_upper_case_globals)]
    static kSecClass: CFStringRef;
    #[allow(non_upper_case_globals)]
    static kSecClassGenericPassword: CFStringRef;
    #[allow(non_upper_case_globals)]
    static kSecAttrService: CFStringRef;
    #[allow(non_upper_case_globals)]
    static kSecAttrAccount: CFStringRef;
    #[allow(non_upper_case_globals)]
    static kSecValueData: CFStringRef;
    #[allow(non_upper_case_globals)]
    static kSecReturnData: CFStringRef;
    #[allow(non_upper_case_globals)]
    static kSecMatchLimit: CFStringRef;
    #[allow(non_upper_case_globals)]
    static kSecMatchLimitOne: CFStringRef;
}

/// The Security.framework attribute constants used by this adapter.
///
/// Collected in one place so a single audited unsafe block covers every
/// framework global read.
struct SecKeys {
    class: CFStringRef,
    class_generic_password: CFStringRef,
    service: CFStringRef,
    account: CFStringRef,
    value_data: CFStringRef,
    return_data: CFStringRef,
    match_limit: CFStringRef,
    match_limit_one: CFStringRef,
    boolean_true: CFTypeRef,
}

/// Owned CoreFoundation reference that releases exactly once on drop.
///
/// Local companion to `native.rs`'s guard so this module stays self-contained;
/// constructed only from create/copy calls that return an owned (+1)
/// reference.
struct OwnedCFRef(CFTypeRef);

impl OwnedCFRef {
    fn new(value: CFTypeRef, operation: &'static str) -> Result<Self, CredentialStoreError> {
        if value.is_null() {
            Err(CredentialStoreError::Backend(format!(
                "{operation} returned no value"
            )))
        } else {
            Ok(Self(value))
        }
    }

    fn as_ptr(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for OwnedCFRef {
    fn drop(&mut self) {
        // SAFETY: constructed only from create/copy calls returning an owned
        // +1 reference; this drop balances it exactly once.
        unsafe { CFRelease(self.0) };
    }
}

fn sec_keys() -> SecKeys {
    // SAFETY: every value is a framework-owned constant that exists for the
    // process lifetime; reading them cannot fail and retains nothing.
    unsafe {
        SecKeys {
            class: kSecClass,
            class_generic_password: kSecClassGenericPassword,
            service: kSecAttrService,
            account: kSecAttrAccount,
            value_data: kSecValueData,
            return_data: kSecReturnData,
            match_limit: kSecMatchLimit,
            match_limit_one: kSecMatchLimitOne,
            boolean_true: kCFBooleanTrue,
        }
    }
}

/// Keychain Services credential store over generic-password items in the
/// user's default keychain.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeychainCredentialStore;

impl KeychainCredentialStore {
    /// Creates a store bound to the user's default (login) keychain.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceCredentialStore for KeychainCredentialStore {
    fn get(
        &self,
        service: &ServiceName,
        account: &AccountName,
    ) -> Result<Option<SecretBytes>, CredentialStoreError> {
        keychain_get(service.as_str(), account.as_str())
    }

    fn put(
        &mut self,
        service: &ServiceName,
        account: &AccountName,
        secret: SecretBytes,
    ) -> Result<(), CredentialStoreError> {
        let result = keychain_put(service.as_str(), account.as_str(), secret.expose_secret());
        // Drop (and therefore zeroize) the owned secret whether or not the
        // item was stored.
        drop(secret);
        result
    }

    fn delete(
        &mut self,
        service: &ServiceName,
        account: &AccountName,
    ) -> Result<(), CredentialStoreError> {
        keychain_delete(service.as_str(), Some(account.as_str()))
    }
}

/// Converts an `OSStatus` into the store error taxonomy.
///
/// Only the failing operation name and numeric status are ever included, so
/// no diagnostic can leak label text or secret material.
fn keychain_status_error(operation: &'static str, status: i32) -> CredentialStoreError {
    match status {
        ERR_SEC_NOT_AVAILABLE | ERR_SEC_MISSING_ENTITLEMENT => CredentialStoreError::Unavailable,
        ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => CredentialStoreError::AccessDenied,
        _ => CredentialStoreError::Backend(format!("{operation} failed with OSStatus {status}")),
    }
}

fn cf_string(value: &str) -> Result<OwnedCFRef, CredentialStoreError> {
    let cstring = CString::new(value).map_err(|_| {
        CredentialStoreError::Backend("keychain label contains an interior NUL".to_owned())
    })?;
    // SAFETY: NULL selects the default allocator; `cstring` outlives the call
    // and CFStringCreateWithCString copies it; UTF-8 is a supported encoding.
    let string = unsafe {
        CFStringCreateWithCString(ptr::null(), cstring.as_ptr(), KCF_STRING_ENCODING_UTF8)
    };
    OwnedCFRef::new(string, "CFStringCreateWithCString")
        .map_err(|_| CredentialStoreError::Backend("keychain label allocation failed".to_owned()))
}

fn cf_data(bytes: &[u8]) -> Result<OwnedCFRef, CredentialStoreError> {
    let length = CFIndex::try_from(bytes.len()).map_err(|_| {
        CredentialStoreError::Backend("secret exceeds keychain length limits".to_owned())
    })?;
    // SAFETY: NULL selects the default allocator; the bytes slice and length
    // are valid for the call, which copies them into the new CFData.
    let data = unsafe { CFDataCreate(ptr::null(), bytes.as_ptr(), length) };
    OwnedCFRef::new(data, "CFDataCreate")
        .map_err(|_| CredentialStoreError::Backend("keychain data allocation failed".to_owned()))
}

fn mutable_dictionary(capacity: usize) -> Result<OwnedCFRef, CredentialStoreError> {
    let capacity = CFIndex::try_from(capacity).map_err(|_| {
        CredentialStoreError::Backend("keychain attribute capacity is invalid".to_owned())
    })?;
    // SAFETY: NULL allocator and NULL callbacks are the documented SecItem
    // attribute-dictionary convention: the dictionary neither retains nor
    // releases its keys and values, and this module owns each value through
    // its own OwnedCF guard for exactly as long as the dictionary is used.
    let dictionary =
        unsafe { CFDictionaryCreateMutable(ptr::null(), capacity, ptr::null(), ptr::null()) };
    OwnedCFRef::new(dictionary.cast_const(), "CFDictionaryCreateMutable").map_err(|_| {
        CredentialStoreError::Backend("keychain attribute allocation failed".to_owned())
    })
}

fn add_attribute(dictionary: &OwnedCFRef, key: CFStringRef, value: CFTypeRef) {
    // SAFETY: the dictionary is owned and live; with NULL callbacks the call
    // performs no ownership change on key or value.
    unsafe { CFDictionaryAddValue(dictionary.as_ptr().cast_mut(), key, value) };
}

fn class_query_dictionary(
    keys: &SecKeys,
    service: &OwnedCFRef,
    account: Option<&OwnedCFRef>,
) -> Result<OwnedCFRef, CredentialStoreError> {
    let dictionary = mutable_dictionary(3)?;
    add_attribute(&dictionary, keys.class, keys.class_generic_password);
    add_attribute(&dictionary, keys.service, service.as_ptr());
    if let Some(account) = account {
        add_attribute(&dictionary, keys.account, account.as_ptr());
    }
    Ok(dictionary)
}

fn keychain_get(service: &str, account: &str) -> Result<Option<SecretBytes>, CredentialStoreError> {
    let service_cf = cf_string(service)?;
    let account_cf = cf_string(account)?;
    let keys = sec_keys();
    let query = class_query_dictionary(&keys, &service_cf, Some(&account_cf))?;
    add_attribute(&query, keys.return_data, keys.boolean_true);
    add_attribute(&query, keys.match_limit, keys.match_limit_one);

    let mut result: CFTypeRef = ptr::null();
    // SAFETY: `query` is a live attribute dictionary; `result` receives an
    // owned (+1) CFDataRef that is released through OwnedCF below on every
    // path.
    let status = unsafe { SecItemCopyMatching(query.as_ptr(), &raw mut result) };
    if status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(None);
    }
    if status != ERR_SEC_SUCCESS {
        return Err(keychain_status_error("SecItemCopyMatching", status));
    }
    let data = OwnedCFRef::new(result, "SecItemCopyMatching")
        .map_err(|_| CredentialStoreError::Backend("keychain returned no data".to_owned()))?;

    // SAFETY: `data` owns a live CFDataRef for the duration of these reads.
    let (byte_ptr, byte_len) = unsafe {
        (
            CFDataGetBytePtr(data.as_ptr()),
            CFDataGetLength(data.as_ptr()),
        )
    };
    if byte_ptr.is_null() {
        return Err(CredentialStoreError::Corrupt);
    }
    let Ok(length) = usize::try_from(byte_len) else {
        return Err(CredentialStoreError::Corrupt);
    };
    if length == 0 || length > MAX_SECRET_BYTES {
        return Err(CredentialStoreError::Corrupt);
    }
    // SAFETY: CFData bytes remain valid while the owning CFDataRef is alive;
    // `length` is CFDataGetLength's own bound for this pointer.
    let bytes = unsafe { slice::from_raw_parts(byte_ptr, length) }.to_vec();
    Ok(Some(
        SecretBytes::new(bytes).map_err(|_| CredentialStoreError::Corrupt)?,
    ))
}

fn keychain_put(service: &str, account: &str, secret: &[u8]) -> Result<(), CredentialStoreError> {
    validate_secret_length(secret.len())?;
    let service_cf = cf_string(service)?;
    let account_cf = cf_string(account)?;
    let data_cf = cf_data(secret)?;
    let keys = sec_keys();

    let attributes = class_query_dictionary(&keys, &service_cf, Some(&account_cf))?;
    add_attribute(&attributes, keys.value_data, data_cf.as_ptr());
    // SAFETY: `attributes` is a live attribute dictionary; passing NULL for
    // the result out-parameter is correct because no item reference is wanted.
    let status = unsafe { SecItemAdd(attributes.as_ptr(), ptr::null_mut()) };
    if status == ERR_SEC_SUCCESS {
        return Ok(());
    }
    if status != ERR_SEC_DUPLICATE_ITEM {
        return Err(keychain_status_error("SecItemAdd", status));
    }

    // The item already exists: replace its secret through SecItemUpdate so a
    // re-pair cannot leave stale material behind.
    let query = class_query_dictionary(&keys, &service_cf, Some(&account_cf))?;
    let update = mutable_dictionary(1)?;
    add_attribute(&update, keys.value_data, data_cf.as_ptr());
    // SAFETY: both dictionaries are live; the query identifies the item and
    // the update carries the replacement value.
    let status = unsafe { SecItemUpdate(query.as_ptr(), update.as_ptr()) };
    if status == ERR_SEC_SUCCESS {
        Ok(())
    } else {
        Err(keychain_status_error("SecItemUpdate", status))
    }
}

fn keychain_delete(service: &str, account: Option<&str>) -> Result<(), CredentialStoreError> {
    let service_cf = cf_string(service)?;
    let account_cf = match account {
        Some(account) => Some(cf_string(account)?),
        None => None,
    };
    let keys = sec_keys();
    let query = class_query_dictionary(&keys, &service_cf, account_cf.as_ref())?;
    // SAFETY: `query` is a live attribute dictionary; deletion requests no
    // output.
    let status = unsafe { SecItemDelete(query.as_ptr()) };
    if status == ERR_SEC_SUCCESS || status == ERR_SEC_ITEM_NOT_FOUND {
        Ok(())
    } else {
        Err(keychain_status_error("SecItemDelete", status))
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use kvm_security::{AccountName, SecretBytes, ServiceName};

    use super::*;

    /// Deletes every test item under its service on scope exit, including on
    /// assertion failure, so tests never leave material in the login keychain.
    struct ServiceCleanup(String);

    impl Drop for ServiceCleanup {
        fn drop(&mut self) {
            let _ = keychain_delete(&self.0, None);
        }
    }

    fn unique_service() -> (ServiceCleanup, ServiceName) {
        let label = format!("software-kvm-test-{}", Uuid::new_v4());
        let service = ServiceName::new(label.clone()).unwrap();
        (ServiceCleanup(label), service)
    }

    /// Probes whether this environment can reach a keychain.
    ///
    /// Returns `None` (after printing a note) when keychain access is blocked
    /// — for example a locked login keychain or a session without a security
    /// agent — so tests skip cleanly instead of failing.
    fn probe_keychain() -> Option<KeychainCredentialStore> {
        let (cleanup, service) = unique_service();
        let account = AccountName::new("probe").unwrap();
        match keychain_put(service.as_str(), account.as_str(), b"keychain-access-probe") {
            Ok(()) => {
                drop(cleanup);
                Some(KeychainCredentialStore::new())
            }
            Err(CredentialStoreError::Unavailable | CredentialStoreError::AccessDenied) => {
                eprintln!(
                    "skipping: keychain access is blocked in this test environment \
                     (locked or unavailable login keychain)"
                );
                None
            }
            Err(error) => panic!("unexpected keychain probe failure: {error:?}"),
        }
    }

    #[test]
    fn blocked_statuses_map_to_the_store_error_taxonomy() {
        // Blocked-environment statuses: the probe skips tests on these.
        assert_eq!(
            keychain_status_error("SecItemAdd", ERR_SEC_NOT_AVAILABLE),
            CredentialStoreError::Unavailable
        );
        assert_eq!(
            keychain_status_error("SecItemAdd", ERR_SEC_MISSING_ENTITLEMENT),
            CredentialStoreError::Unavailable
        );
        assert_eq!(
            keychain_status_error("SecItemAdd", ERR_SEC_AUTH_FAILED),
            CredentialStoreError::AccessDenied
        );
        assert_eq!(
            keychain_status_error("SecItemAdd", ERR_SEC_INTERACTION_NOT_ALLOWED),
            CredentialStoreError::AccessDenied
        );
        // Item-level outcomes stay backend errors, not environment blocks.
        assert!(matches!(
            keychain_status_error("SecItemAdd", ERR_SEC_ITEM_NOT_FOUND),
            CredentialStoreError::Backend(_)
        ));
        assert!(matches!(
            keychain_status_error("SecItemAdd", ERR_SEC_DUPLICATE_ITEM),
            CredentialStoreError::Backend(_)
        ));
    }

    #[test]
    fn keychain_round_trips_replaces_and_deletes() {
        let Some(mut store) = probe_keychain() else {
            return;
        };
        let (_cleanup, service) = unique_service();
        let account = AccountName::new("round-trip").unwrap();

        assert!(store.get(&service, &account).unwrap().is_none());
        store
            .put(
                &service,
                &account,
                SecretBytes::new(b"keychain-test-secret-A".to_vec()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store
                .get(&service, &account)
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"keychain-test-secret-A"
        );
        store
            .put(
                &service,
                &account,
                SecretBytes::new(b"keychain-test-secret-B".to_vec()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store
                .get(&service, &account)
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"keychain-test-secret-B"
        );
        store.delete(&service, &account).unwrap();
        assert!(store.get(&service, &account).unwrap().is_none());
        // Deletion is idempotent.
        store.delete(&service, &account).unwrap();
    }

    #[test]
    fn keychain_keeps_accounts_and_services_isolated() {
        let Some(mut store) = probe_keychain() else {
            return;
        };
        let (_cleanup, service) = unique_service();
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
    fn keychain_rejects_oversized_secrets() {
        let Some(mut store) = probe_keychain() else {
            return;
        };
        let (_cleanup, service) = unique_service();
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
