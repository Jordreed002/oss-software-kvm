//! Audited Windows secure-file boundary.
//!
//! The unsafe operations in this module are limited to Win32/NT handle, token,
//! and ACL APIs. Filesystem traversal is handle-relative after opening a local
//! drive root, so a checked parent cannot be exchanged between path checks.

#![allow(unsafe_code)]

use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, Prefix};
use std::ptr::{addr_of, null};

use windows::core::PWSTR;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FileFsDeviceInformation, NtCreateFile, NtQueryVolumeInformationFile, FILE_DIRECTORY_FILE,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows::Wdk::System::SystemServices::{
    FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE, FILE_REMOVABLE_MEDIA,
};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, HANDLE, HLOCAL, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation, IsValidAcl,
    IsValidSid, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFileType, ReadFile, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DEVICE_DISK,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_TYPE_DISK, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::Ioctl::FILE_DEVICE_DISK_FILE_SYSTEM;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use zeroize::Zeroizing;

use super::{file_security_error, size_error, RuntimePreparationError};

#[derive(Clone, Copy)]
pub(super) enum FilePolicy {
    OwnerPrivate,
    PublicRegular,
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this type is constructed only from successful calls which
        // transfer ownership of a fresh handle, and it is neither Clone nor Copy.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocates this descriptor with LocalAlloc and
        // transfers it to the caller. The guard is unique and frees it once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}

pub(super) fn secure_read(
    path: &Path,
    maximum: usize,
    policy: FilePolicy,
) -> Result<Zeroizing<Vec<u8>>, RuntimePreparationError> {
    let (drive, components) = local_drive_components(path)?;
    let root_name = format!(r"\??\{}:\", char::from(drive));
    let root_wide: Vec<u16> = root_name.encode_utf16().collect();
    let mut current = open_nt(
        HANDLE::default(),
        &root_wide,
        false,
        FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
    )?;
    validate_handle_kind(current.raw(), false)?;
    validate_fixed_local_volume(current.raw())?;

    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let wide: Vec<u16> = component.encode_wide().collect();
        let access = if final_component {
            let acl_access = if matches!(policy, FilePolicy::OwnerPrivate) {
                READ_CONTROL
            } else {
                windows::Win32::Storage::FileSystem::FILE_ACCESS_RIGHTS(0)
            };
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE | acl_access
        } else {
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE
        };
        let next = open_nt(current.raw(), &wide, final_component, access)?;
        validate_handle_kind(next.raw(), final_component)?;
        current = next;
    }

    let size = regular_file_size(current.raw(), maximum)?;
    if matches!(policy, FilePolicy::OwnerPrivate) {
        validate_owner_private_acl(current.raw())?;
    }
    read_bounded(current.raw(), size, maximum)
}

fn local_drive_components(path: &Path) -> Result<(u8, Vec<OsString>), RuntimePreparationError> {
    let mut source = path.components();
    let drive = match source.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive.to_ascii_uppercase(),
            Prefix::UNC(..)
            | Prefix::VerbatimUNC(..)
            | Prefix::DeviceNS(..)
            | Prefix::Verbatim(_) => return Err(file_security_error()),
        },
        _ => return Err(file_security_error()),
    };
    if !matches!(source.next(), Some(Component::RootDir)) {
        return Err(file_security_error());
    }
    let mut output = Vec::new();
    for component in source {
        match component {
            Component::Normal(name)
                if !name.is_empty()
                    && !name
                        .encode_wide()
                        .any(|unit| unit == 0 || unit == u16::from(b':')) =>
            {
                output.push(name.to_owned());
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir
            | Component::Normal(_) => return Err(file_security_error()),
        }
    }
    if output.is_empty() {
        return Err(file_security_error());
    }
    Ok((drive, output))
}

fn open_nt(
    parent: HANDLE,
    name: &[u16],
    final_file: bool,
    access: windows::Win32::Storage::FileSystem::FILE_ACCESS_RIGHTS,
) -> Result<OwnedHandle, RuntimePreparationError> {
    let byte_length = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(file_security_error)?;
    let unicode = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: PWSTR(name.as_ptr().cast_mut()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).map_err(|_| file_security_error())?,
        RootDirectory: parent,
        ObjectName: addr_of!(unicode),
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if final_file {
            FILE_NON_DIRECTORY_FILE
        } else {
            FILE_DIRECTORY_FILE
        };
    let mut handle = HANDLE::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: all pointers refer to initialized values which remain alive for
    // the call; name byte lengths are checked; output handle is owned on success.
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            access,
            &raw const attributes,
            &raw mut status_block,
            None,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            options,
            None,
            0,
        )
    };
    if status.0 < 0 || handle.is_invalid() {
        return Err(file_security_error());
    }
    Ok(OwnedHandle(handle))
}

fn validate_handle_kind(handle: HANDLE, final_file: bool) -> Result<(), RuntimePreparationError> {
    let information = handle_information(handle)?;
    if GetFileType_safe(handle) != FILE_TYPE_DISK
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) == final_file)
    {
        return Err(file_security_error());
    }
    Ok(())
}

fn validate_fixed_local_volume(handle: HANDLE) -> Result<(), RuntimePreparationError> {
    let mut information = FILE_FS_DEVICE_INFORMATION::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the root handle is live and the typed output/status buffers are
    // initialized and correctly sized for FileFsDeviceInformation.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            handle,
            &raw mut status_block,
            (&raw mut information).cast(),
            u32::try_from(size_of::<FILE_FS_DEVICE_INFORMATION>())
                .map_err(|_| file_security_error())?,
            FileFsDeviceInformation,
        )
    };
    if status.0 < 0 || !is_fixed_local_volume(information.DeviceType, information.Characteristics) {
        return Err(file_security_error());
    }
    Ok(())
}

const fn is_fixed_local_volume(device_type: u32, characteristics: u32) -> bool {
    (device_type == FILE_DEVICE_DISK.0 || device_type == FILE_DEVICE_DISK_FILE_SYSTEM)
        && characteristics & (FILE_REMOTE_DEVICE | FILE_REMOVABLE_MEDIA) == 0
}

fn regular_file_size(handle: HANDLE, maximum: usize) -> Result<usize, RuntimePreparationError> {
    let information = handle_information(handle)?;
    let size = (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow);
    if size == 0 || size > u64::try_from(maximum).map_err(|_| size_error())? {
        return Err(size_error());
    }
    usize::try_from(size).map_err(|_| size_error())
}

fn handle_information(
    handle: HANDLE,
) -> Result<BY_HANDLE_FILE_INFORMATION, RuntimePreparationError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: information is an initialized out-parameter and handle is live.
    unsafe { GetFileInformationByHandle(handle, &raw mut information) }
        .map_err(|_| file_security_error())?;
    Ok(information)
}

#[allow(non_snake_case)]
fn GetFileType_safe(handle: HANDLE) -> windows::Win32::Storage::FileSystem::FILE_TYPE {
    // SAFETY: handle is live for the duration of the call.
    unsafe { GetFileType(handle) }
}

fn read_bounded(
    handle: HANDLE,
    expected_size: usize,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, RuntimePreparationError> {
    let capacity = maximum.checked_add(1).ok_or_else(size_error)?;
    let mut bytes = Zeroizing::new(vec![0; capacity]);
    let mut used = 0usize;
    loop {
        let mut read = 0u32;
        // SAFETY: the slice is initialized and exclusively borrowed, the live
        // synchronous handle owns its current file position, and no OVERLAPPED is used.
        unsafe { ReadFile(handle, Some(&mut bytes[used..]), Some(&raw mut read), None) }
            .map_err(|_| file_security_error())?;
        if read == 0 {
            break;
        }
        used = used
            .checked_add(usize::try_from(read).map_err(|_| size_error())?)
            .ok_or_else(size_error)?;
        if used > maximum || used == capacity {
            return Err(size_error());
        }
    }
    if used == 0 || used != expected_size {
        return Err(size_error());
    }
    bytes.truncate(used);
    Ok(bytes)
}

fn validate_owner_private_acl(handle: HANDLE) -> Result<(), RuntimePreparationError> {
    let token_user = current_token_user()?;
    let process_sid = token_user_sid(&token_user)?;
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: out-pointers are valid and the live handle was opened with READ_CONTROL.
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            Some(&raw mut dacl),
            None,
            Some(&raw mut descriptor),
        )
    };
    if result.0 != 0 || descriptor.is_invalid() {
        return Err(file_security_error());
    }
    let _descriptor_guard = LocalSecurityDescriptor(descriptor);
    if owner.is_invalid() || dacl.is_null() || !sid_valid(owner) || !sid_equal(owner, process_sid) {
        return Err(file_security_error());
    }

    let mut present = windows::core::BOOL::default();
    let mut descriptor_dacl = std::ptr::null_mut();
    let mut defaulted = windows::core::BOOL::default();
    // SAFETY: descriptor remains owned by the guard, and all outputs are valid.
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut descriptor_dacl,
            &raw mut defaulted,
        )
    }
    .map_err(|_| file_security_error())?;
    if !present.as_bool()
        || defaulted.as_bool()
        || descriptor_dacl.is_null()
        || descriptor_dacl != dacl
    {
        return Err(file_security_error());
    }
    // SAFETY: dacl is owned by the guarded security descriptor.
    if !unsafe { IsValidAcl(dacl) }.as_bool() {
        return Err(file_security_error());
    }
    // SAFETY: IsValidAcl succeeded and the descriptor guard keeps the ACL live.
    let acl = unsafe { &*dacl };
    if acl.AclRevision != 2 {
        return Err(file_security_error());
    }
    for index in 0..u32::from(acl.AceCount) {
        let mut raw_ace = std::ptr::null_mut();
        // SAFETY: index is within the validated ACL's advertised ACE count.
        unsafe { GetAce(dacl, index, &raw mut raw_ace) }.map_err(|_| file_security_error())?;
        if raw_ace.is_null() {
            return Err(file_security_error());
        }
        // SAFETY: GetAce returned an ACE pointer from a valid ACL.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if !matches!(header.AceType, 0 | 1) {
            return Err(file_security_error());
        }
        let (mask, sid) = standard_ace(raw_ace, header)?;
        if !ace_preserves_owner_only(header.AceType, mask, sid_equal(sid, owner)) {
            return Err(file_security_error());
        }
    }
    Ok(())
}

fn current_token_user() -> Result<Vec<usize>, RuntimePreparationError> {
    let mut token = HANDLE::default();
    // SAFETY: token is a valid out-parameter; the pseudo process handle is always live.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
        .map_err(|_| file_security_error())?;
    let token = OwnedHandle(token);
    let mut required = 0u32;
    // SAFETY: the documented sizing call accepts a null buffer and zero length.
    let _ = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &raw mut required) };
    if required < u32::try_from(size_of::<TOKEN_USER>()).map_err(|_| file_security_error())? {
        return Err(file_security_error());
    }
    let word = size_of::<usize>();
    let words = usize::try_from(required)
        .map_err(|_| file_security_error())?
        .checked_add(word - 1)
        .ok_or_else(file_security_error)?
        / word;
    let mut storage = vec![0usize; words];
    // SAFETY: usize storage has sufficient size/alignment and remains live.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            required,
            &raw mut required,
        )
    }
    .map_err(|_| file_security_error())?;
    Ok(storage)
}

fn token_user_sid(storage: &[usize]) -> Result<PSID, RuntimePreparationError> {
    if storage.len().checked_mul(size_of::<usize>()).unwrap_or(0) < size_of::<TOKEN_USER>() {
        return Err(file_security_error());
    }
    // SAFETY: current_token_user returns aligned storage populated as TOKEN_USER.
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    if !sid_valid(user.User.Sid) {
        return Err(file_security_error());
    }
    Ok(user.User.Sid)
}

fn standard_ace(
    raw_ace: *mut core::ffi::c_void,
    header: &ACE_HEADER,
) -> Result<(u32, PSID), RuntimePreparationError> {
    let ace_size = usize::from(header.AceSize);
    if ace_size < size_of::<ACCESS_ALLOWED_ACE>() {
        return Err(file_security_error());
    }
    // SAFETY: size was checked and standard allow/deny ACEs share this layout.
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    let sid_offset = addr_of!(ace.SidStart) as usize - raw_ace as usize;
    // SAFETY: IsValidAcl succeeded before GetAce returned this pointer, so the
    // complete advertised ACE lies inside the live ACL allocation.
    let ace_bytes = unsafe { std::slice::from_raw_parts(raw_ace.cast::<u8>(), ace_size) };
    let sid_length = contained_sid_length(ace_bytes, sid_offset).ok_or_else(file_security_error)?;
    let sid = PSID(addr_of!(ace.SidStart).cast_mut().cast());
    if !sid_valid(sid) {
        return Err(file_security_error());
    }
    // SAFETY: the fixed SID header and every advertised subauthority were
    // proved to lie inside the ACE before calling either SID API.
    if unsafe { GetLengthSid(sid) } as usize != sid_length {
        return Err(file_security_error());
    }
    Ok((ace.Mask, sid))
}

fn contained_sid_length(ace: &[u8], sid_offset: usize) -> Option<usize> {
    const FIXED_SID_BYTES: usize = 8;
    const SUBAUTHORITY_BYTES: usize = size_of::<u32>();

    let fixed = ace.get(sid_offset..sid_offset.checked_add(FIXED_SID_BYTES)?)?;
    let subauthority_count = usize::from(fixed[1]);
    let sid_length = subauthority_count
        .checked_mul(SUBAUTHORITY_BYTES)?
        .checked_add(FIXED_SID_BYTES)?;
    let end = sid_offset.checked_add(sid_length)?;
    (end <= ace.len()).then_some(sid_length)
}

fn sid_valid(sid: PSID) -> bool {
    !sid.is_invalid() && unsafe { IsValidSid(sid) }.as_bool()
}

fn sid_equal(left: PSID, right: PSID) -> bool {
    // SAFETY: every caller validates both SIDs before comparison.
    unsafe { EqualSid(left, right) }.is_ok()
}

const fn ace_preserves_owner_only(ace_type: u8, mask: u32, targets_owner: bool) -> bool {
    match ace_type {
        0 => mask == 0 || targets_owner,
        1 => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{ace_preserves_owner_only, contained_sid_length, is_fixed_local_volume};

    #[test]
    fn allows_owner_access_and_zero_access_only() {
        assert!(ace_preserves_owner_only(0, u32::MAX, true));
        assert!(ace_preserves_owner_only(0, 0, false));
        assert!(ace_preserves_owner_only(1, u32::MAX, false));
    }

    #[test]
    fn rejects_any_non_owner_allow_grant() {
        for mask in [1, 0x20, 0x1_200_089, u32::MAX] {
            assert!(!ace_preserves_owner_only(0, mask, false));
        }
    }

    #[test]
    fn rejects_ambiguous_ace_forms() {
        for ace_type in [2, 5, 9, u8::MAX] {
            assert!(!ace_preserves_owner_only(ace_type, 0, true));
        }
    }

    #[test]
    fn admits_only_nonremote_nonremovable_disk_volumes() {
        assert!(is_fixed_local_volume(7, 0));
        assert!(is_fixed_local_volume(8, 0));
        assert!(!is_fixed_local_volume(7, 1));
        assert!(!is_fixed_local_volume(8, 16));
        assert!(!is_fixed_local_volume(20, 0));
    }

    #[test]
    fn rejects_sid_with_truncated_fixed_header() {
        let ace = [0u8; 15];

        assert_eq!(contained_sid_length(&ace, 8), None);
    }

    #[test]
    fn rejects_sid_with_subauthorities_beyond_ace() {
        let mut ace = [0u8; 20];
        ace[8] = 1;
        ace[9] = 3;

        assert_eq!(contained_sid_length(&ace, 8), None);
    }

    #[test]
    fn accepts_only_fully_contained_sid_shape() {
        let mut ace = [0u8; 20];
        ace[8] = 1;
        ace[9] = 1;

        assert_eq!(contained_sid_length(&ace, 8), Some(12));
    }
}
