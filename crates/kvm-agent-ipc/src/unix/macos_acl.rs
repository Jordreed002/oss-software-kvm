//! Narrow Darwin ACL ABI from Apple's Libc include/sys/acl.h.
//! <https://github.com/apple-oss-distributions/Libc/blob/main/include/sys/acl.h>
//! Iteration semantics: `posix1e/acl_get_entry.3` and `posix1e/acl_entry.c`.
//! Retrieval/free contract: `posix1e/acl_get.3`. No ACL internals are accessed.
#![allow(unsafe_code)]
use libc::{c_char, c_int, c_void};
use std::{
    ffi::CString,
    fs, io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
    ptr,
};

const ACL_TYPE_EXTENDED: c_int = 0x100;
const ACL_FIRST_ENTRY: c_int = 0;
const ACL_NEXT_ENTRY: c_int = -1;
const ACL_EXTENDED_DENY: c_int = 2;

extern "C" {
    fn acl_get_link_np(path: *const c_char, kind: c_int) -> *mut c_void;
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
    fn acl_free(acl: *mut c_void) -> c_int;
    fn acl_get_entry(acl: *mut c_void, id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
}

struct Acl(*mut c_void);
impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: owned allocation from acl_get_*; freed exactly once. Entries
        // borrow this allocation and are never separately freed or retained.
        unsafe { acl_free(self.0) };
    }
}

fn validate(raw: *mut c_void, private: bool) -> io::Result<()> {
    if raw.is_null() {
        let error = io::Error::last_os_error();
        // Darwin's FILESEC_ACL lookup reports ENOENT when the object exists
        // without an extended ACL. Path callers separately prove stable identity.
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(error)
        };
    }
    let acl = Acl(raw);
    let mut id = ACL_FIRST_ENTRY;
    loop {
        let mut entry = ptr::null_mut();
        // SAFETY: acl is a live native ACL and entry is writable pointer storage.
        let result = unsafe { acl_get_entry(acl.0, id, &raw mut entry) };
        if result == -1 {
            let error = io::Error::last_os_error();
            // Darwin returns EINVAL at exhaustion, including FIRST on an empty
            // ACL. This ACL came from the OS and only documented IDs are used.
            return if error.raw_os_error() == Some(libc::EINVAL) {
                Ok(())
            } else {
                Err(error)
            };
        }
        if result != 0 || entry.is_null() {
            return Err(io::Error::other("unexpected ACL iterator result"));
        }
        let mut tag = 0;
        // SAFETY: entry borrows the still-live ACL; tag is writable C int storage.
        if unsafe { acl_get_tag_type(entry, &raw mut tag) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Ancestors accept deny-only ACLs. Reject all allow entries, even
        // read-only/inherit-only ones, without guessing principal membership.
        if private || tag != ACL_EXTENDED_DENY {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "extended ACL rejected",
            ));
        }
        id = ACL_NEXT_ENTRY;
    }
}

pub(super) fn validate_path(path: &Path, private: bool) -> io::Result<()> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ACL symlink rejected",
        ));
    }
    let native_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in ACL path"))?;
    // SAFETY: __error returns this thread's valid errno storage. Reset before
    // retrieval so an unexplained NULL cannot inherit an earlier ENOENT.
    unsafe { *libc::__error() = 0 };
    // SAFETY: NUL-terminated path lives through call. The result transfers an
    // allocation to validate, which frees it on every non-null return path.
    validate(
        unsafe { acl_get_link_np(native_path.as_ptr(), ACL_TYPE_EXTENDED) },
        private,
    )?;
    let after = fs::symlink_metadata(path)?;
    if before.dev() != after.dev() || before.ino() != after.ino() || after.file_type().is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ACL path changed",
        ));
    }
    Ok(())
}

pub(super) fn validate_fd(fd: c_int) -> io::Result<()> {
    // SAFETY: thread-local errno storage is valid, as above.
    unsafe { *libc::__error() = 0 };
    // SAFETY: caller keeps the lock File/fd alive through this call. Retrieval
    // does not close it; validate takes ownership only of the returned ACL.
    validate(unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) }, true)
}
