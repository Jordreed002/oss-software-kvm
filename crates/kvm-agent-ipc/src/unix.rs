//! Per-user Unix endpoint prototype, including macOS.
//!
//! Canonical ancestors must be root/euid-owned and not group/other writable,
//! except trusted-owned sticky directories. Checks are snapshots, not protection
//! against malicious same-UID rename/replacement. Peer UID is not code identity.
//! The lifetime lock and asynchronous stale probe coordinate compliant owners.

#[cfg(target_os = "macos")]
mod macos_acl;

#[allow(clippy::unnecessary_wraps)] // macOS validation is fallible; keep one call contract.
fn validate_acl(path: &Path, private: bool) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    return macos_acl::validate_path(path, private);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, private);
        Ok(())
    }
}

// Reject the final symlink before canonicalization; system ancestor aliases
// such as macOS /var are allowed, then only canonical absolute paths are used.
fn resolve_directory(directory: &Path, uid: u32, create: bool) -> io::Result<PathBuf> {
    if !directory.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute runtime directory required",
        ));
    }
    // Normalize trailing separators/dots before lstat so a final symlink
    // cannot be hidden by a trailing slash. Reject parent traversal outright.
    if directory
        .components()
        .any(|part| part == std::path::Component::ParentDir)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime parent traversal rejected",
        ));
    }
    let normalized: PathBuf = directory.components().collect();
    let directory = normalized.as_path();
    if fs::symlink_metadata(directory).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory symlink rejected",
        ));
    }
    let parent = directory.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime directory needs a parent",
        )
    })?;
    let name = directory.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime directory needs a name",
        )
    })?;
    let parent = fs::canonicalize(parent)?;
    let mut ancestors: Vec<_> = parent.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted runtime ancestor",
            ));
        }
        validate_acl(ancestor, false)?;
    }
    let directory = parent.join(name);
    if create {
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    validate_directory(&directory, uid)?;
    Ok(directory)
}

use std::os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};

#[allow(unsafe_code)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no pointers and cannot fail.
    unsafe { libc::geteuid() }
}

fn validate_directory(directory: &Path, uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory must be private and user-owned",
        ));
    }
    validate_acl(directory, true)
}

#[allow(unsafe_code)]
fn lock_directory(directory: &Path, uid: u32) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("agent.lock"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime lock file rejected",
        ));
    }
    #[cfg(target_os = "macos")]
    macos_acl::validate_fd(file.as_raw_fd())?;
    // SAFETY: file owns a valid fd. Nonblocking flock never waits for another
    // agent and is released by the OS when this file/process closes.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::WouldBlock {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                "agent instance already owns runtime directory",
            )
        } else {
            error
        });
    }
    Ok(file)
}

async fn retire_stale(path: &Path, uid: u32) -> io::Result<()> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !before.file_type().is_socket() || before.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing socket path is not an owned socket",
        ));
    }
    validate_acl(path, true)?;
    match tokio::time::timeout(
        std::time::Duration::from_millis(100),
        UnixStream::connect(path),
    )
    .await
    {
        Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "socket is active or stale state cannot be confirmed",
            ))
        }
    }
    let after = fs::symlink_metadata(path)?;
    if !after.file_type().is_socket()
        || after.uid() != uid
        || before.dev() != after.dev()
        || before.ino() != after.ino()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stale socket path changed",
        ));
    }
    validate_acl(path, true)?;
    // The lifetime lock excludes other compliant owners. Same-UID malicious
    // replacement remains outside this prototype's trust model.
    fs::remove_file(path)
}

/// Connects after validating the private directory, socket and server UID.
/// This proves a user boundary only. A schema/instance handshake must precede
/// commands. Ancestor checks cannot exclude malicious same-UID replacement.
///
/// # Errors
/// Rejects unsafe/replaced socket paths, different peer UIDs and expired or
/// unrepresentable budgets. Filesystem metadata checks are synchronous setup
/// work; the deadline bounds the asynchronous connection, not a stalled disk.
pub async fn connect(directory: &Path, budget: std::time::Duration) -> io::Result<UnixStream> {
    if budget.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "socket connection budget expired",
        ));
    }
    let deadline = tokio::time::Instant::now()
        .checked_add(budget)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket connection budget too large",
            )
        })?;
    let uid = effective_uid();
    let directory = resolve_directory(directory, uid, false)?;
    let path = directory.join("control.sock");
    let before = fs::symlink_metadata(&path)?;
    if !before.file_type().is_socket() || before.uid() != uid || before.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket path rejected",
        ));
    }
    validate_acl(&path, true)?;
    let stream = tokio::time::timeout_at(deadline, UnixStream::connect(&path))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socket connection timed out"))??;
    if stream.peer_cred()?.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket server UID rejected",
        ));
    }
    let after = fs::symlink_metadata(&path)?;
    if !after.file_type().is_socket()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.uid() != uid
        || after.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket path changed while connecting",
        ));
    }
    validate_acl(&path, true)?;
    Ok(stream)
}

/// Mode-restricted listener admitting one client at a time.
/// Checks canonical ancestors and, on macOS, extended ACLs.
pub struct UserSocket {
    listener: UnixListener,
    path: PathBuf,
    uid: u32,
    device: u64,
    inode: u64,
    admission: Arc<Semaphore>,
    _lock: fs::File,
}

impl std::fmt::Debug for UserSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserSocket").finish_non_exhaustive()
    }
}

/// One authorized UID connection. Drop before accepting the next.
#[derive(Debug)]
pub struct UserConnection {
    stream: UnixStream,
    _permit: OwnedSemaphorePermit,
}

impl UserConnection {
    /// Borrow the stream; the owner applies framing, API handshake and deadlines.
    pub fn stream(&mut self) -> &mut UnixStream {
        &mut self.stream
    }
}

impl UserSocket {
    /// Creates a 0700 directory if absent and requires a user-owned private mode.
    /// Holds a lifetime lock; recovers only an owned, confirmed stale socket.
    /// Never unlinks regular files or symlinks. Requires a Tokio I/O runtime.
    ///
    /// # Errors
    /// Rejects untrusted immediate directories, excessive path length, occupied
    /// paths and native failures. Same-UID replacement remains possible.
    pub async fn bind(directory: &Path) -> io::Result<Self> {
        let uid = effective_uid();
        let directory = resolve_directory(directory, uid, true)?;
        let lock = lock_directory(&directory, uid)?;
        let path = directory.join("control.sock");
        // Conservative common limit fits macOS sockaddr_un (104 bytes).
        if path.as_os_str().as_bytes().len() > 100 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime socket path too long",
            ));
        }
        retire_stale(&path, uid).await?;
        let listener = UnixListener::bind(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_socket() || metadata.uid() != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket ownership changed during bind",
            ));
        }
        let socket = Self {
            listener,
            path,
            uid,
            device: metadata.dev(),
            inode: metadata.ino(),
            admission: Arc::new(Semaphore::new(1)),
            _lock: lock,
        };
        // Directory privacy protects the bind-to-chmod interval.
        fs::set_permissions(&socket.path, fs::Permissions::from_mode(0o600))?;
        validate_acl(&socket.path, true)?;
        Ok(socket)
    }

    /// Contains a local data path; avoid exporting it in diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepts only the effective UID that owns this listener.
    ///
    /// # Errors
    /// Returns `WouldBlock` while a connection is held; rejects unknown/different
    /// peer UIDs. Cancelling accept releases its permit and is recoverable; a
    /// rejected UID is non-terminal. A pending accept also owns admission. The
    /// owner must enforce API negotiation and read/write deadlines.
    pub async fn accept(&self) -> io::Result<UserConnection> {
        let permit = self.admission.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "socket client already active")
        })?;
        let (stream, _) = self.listener.accept().await?;
        if stream.peer_cred()?.uid() != self.uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket peer UID rejected",
            ));
        }
        Ok(UserConnection {
            stream,
            _permit: permit,
        })
    }
}

impl Drop for UserSocket {
    fn drop(&mut self) {
        // Remove only this instance's socket; never delete a replacement file.
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_socket()
                && metadata.uid() == self.uid
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "kvm-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0.join("agent.lock"));
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[tokio::test]
    async fn nonsticky_writable_ancestor_is_rejected() {
        let parent = Directory::new();
        fs::DirBuilder::new().mode(0o700).create(&parent.0).unwrap();
        fs::set_permissions(&parent.0, fs::Permissions::from_mode(0o777)).unwrap();
        let child = parent.0.join("private");
        assert_eq!(
            UserSocket::bind(&child).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!child.exists());
    }

    #[tokio::test]
    async fn direct_directory_symlink_is_rejected() {
        let directory = Directory::new();
        let alias = Directory::new();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        std::os::unix::fs::symlink(&directory.0, &alias.0).unwrap();
        assert_eq!(
            UserSocket::bind(&alias.0).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            connect(&alias.0, std::time::Duration::from_secs(1))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_file(&alias.0).unwrap();
    }

    #[tokio::test]
    async fn canonical_trusted_path_and_drop_survive_removed_ancestor_alias() {
        let parent = Directory::new();
        let alias = Directory::new();
        fs::DirBuilder::new().mode(0o700).create(&parent.0).unwrap();
        std::os::unix::fs::symlink(&parent.0, &alias.0).unwrap();
        let child = Directory(parent.0.join("private"));
        let server = UserSocket::bind(&alias.0.join("private")).await.unwrap();
        let expected = fs::canonicalize(&child.0).unwrap().join("control.sock");
        assert!(server.path().is_absolute());
        assert_eq!(server.path(), expected);
        fs::remove_file(&alias.0).unwrap();
        let client = connect(&child.0, std::time::Duration::from_secs(1))
            .await
            .unwrap();
        drop(client);
        drop(server);
        assert!(!expected.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_fixture_acl_policy() {
        let directory = Directory::new();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        // Only this private fixture is modified; never system directories.
        let chmod = |args: &[&str]| {
            assert!(std::process::Command::new("/bin/chmod")
                .args(args)
                .arg(&directory.0)
                .status()
                .unwrap()
                .success());
        };
        chmod(&["-N"]);
        validate_acl(&directory.0, true).unwrap(); // NULL/ENOENT means no ACL
        let file = fs::File::open(&directory.0).unwrap();
        macos_acl::validate_fd(file.as_raw_fd()).unwrap();
        assert_eq!(
            validate_acl(&directory.0.join("missing"), true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        chmod(&["+a", "everyone deny delete"]);
        validate_acl(&directory.0, false).unwrap();
        assert_eq!(
            validate_acl(&directory.0, true).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        chmod(&["-N"]);
        chmod(&["+a", "everyone allow read"]);
        assert_eq!(
            validate_acl(&directory.0, false).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            validate_acl(&directory.0, true).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        chmod(&["-N"]);
    }

    #[tokio::test]
    async fn private_socket_roundtrip_and_collision() {
        let directory = Directory::new();
        let server = UserSocket::bind(&directory.0).await.unwrap();
        let inode = fs::symlink_metadata(server.path()).unwrap().ino();
        assert_eq!(
            UserSocket::bind(&directory.0).await.unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        assert_eq!(fs::symlink_metadata(server.path()).unwrap().ino(), inode);
        assert_eq!(fs::metadata(&directory.0).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(server.path()).unwrap().mode() & 0o777, 0o600);
        let mut client = connect(&directory.0, std::time::Duration::from_secs(1))
            .await
            .unwrap();
        let mut connection = server.accept().await.unwrap();
        assert_eq!(
            server.accept().await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        crate::write_frame(&mut client, b"status", 16)
            .await
            .unwrap();
        let mut buffer = [0_u8; 16];
        assert_eq!(
            crate::read_frame(connection.stream(), &mut buffer)
                .await
                .unwrap(),
            Some(b"status".as_slice())
        );
        drop(connection);
        drop(client);
        let second = UnixStream::connect(server.path()).await.unwrap();
        let next = server.accept().await.unwrap();
        drop(next);
        drop(second);
        let path = server.path().to_owned();
        drop(server);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn rejects_public_directory_without_changing_permissions() {
        let directory = Directory::new();
        fs::create_dir(&directory.0).unwrap();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            UserSocket::bind(&directory.0).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::metadata(&directory.0).unwrap().mode() & 0o777, 0o755);
    }

    #[tokio::test]
    async fn drop_does_not_remove_replacement_file() {
        let directory = Directory::new();
        let server = UserSocket::bind(&directory.0).await.unwrap();
        let path = server.path().to_owned();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"preserve").unwrap();
        drop(server);
        assert_eq!(fs::read(&path).unwrap(), b"preserve");
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn connector_rejects_symlink_and_invalid_budgets() {
        let directory = Directory::new();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        let path = directory.0.join("control.sock");
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert_eq!(
            connect(&directory.0, std::time::Duration::from_secs(1))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            connect(&directory.0, std::time::Duration::ZERO)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            connect(&directory.0, std::time::Duration::MAX)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn stale_socket_recovered_only_when_lock_is_free() {
        let directory = Directory::new();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        let path = directory.0.join("control.sock");
        let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(stale);
        let server = UserSocket::bind(&directory.0).await.unwrap();
        let client = connect(&directory.0, std::time::Duration::from_secs(1))
            .await
            .unwrap();
        let connection = server.accept().await.unwrap();
        drop(connection);
        drop(client);
        drop(server);
        assert!(!path.exists());
        assert!(directory.0.join("agent.lock").exists());
        let next = UserSocket::bind(&directory.0).await.unwrap();
        drop(next);
    }

    #[tokio::test]
    async fn regular_file_is_preserved_and_relative_path_rejected() {
        let directory = Directory::new();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        let path = directory.0.join("control.sock");
        fs::write(&path, b"preserve").unwrap();
        assert_eq!(
            UserSocket::bind(&directory.0).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::read(&path).unwrap(), b"preserve");
        fs::remove_file(path).unwrap();
        assert_eq!(
            UserSocket::bind(Path::new("relative-runtime"))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn cancelled_accept_releases_admission() {
        let directory = Directory::new();
        let server = UserSocket::bind(&directory.0).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), server.accept())
                .await
                .is_err()
        );
        let client = connect(&directory.0, std::time::Duration::from_secs(1))
            .await
            .unwrap();
        let connection = server.accept().await.unwrap();
        drop(connection);
        drop(client);
    }
}
