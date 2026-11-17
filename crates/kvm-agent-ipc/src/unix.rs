//! Per-user Unix endpoint prototype, including macOS.
//!
//! The caller must choose a stable application-owned runtime directory beneath
//! trusted ancestors. This validates the immediate directory, not every ancestor
//! against concurrent rename. Peer UID checks establish a user boundary, not
//! signed application identity. No stale socket is deleted automatically.

use std::os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
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
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory must be private and user-owned",
        ));
    }
    Ok(())
}

/// Private filesystem listener admitting one client at a time.
pub struct UserSocket {
    listener: UnixListener,
    path: PathBuf,
    uid: u32,
    device: u64,
    inode: u64,
    admission: Arc<Semaphore>,
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
    /// Creates a 0700 directory if absent; rejects unsafe existing directories.
    /// Binds control.sock without unlinking existing files, sockets or symlinks.
    ///
    /// # Errors
    /// Rejects untrusted immediate directories, excessive path length, occupied
    /// paths and native failures. Ancestor trust is a caller precondition.
    pub fn bind(directory: &Path) -> io::Result<Self> {
        let uid = effective_uid();
        match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        validate_directory(directory, uid)?;
        let path = directory.join("control.sock");
        // Conservative common limit fits macOS sockaddr_un (104 bytes).
        if path.as_os_str().as_bytes().len() > 100 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime socket path too long",
            ));
        }
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
        };
        // Directory privacy protects the bind-to-chmod interval.
        fs::set_permissions(&socket.path, fs::Permissions::from_mode(0o600))?;
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
    /// peer UIDs. The owner must enforce API negotiation and read/write deadlines.
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
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[tokio::test]
    async fn private_socket_roundtrip_and_collision() {
        let directory = Directory::new();
        let server = UserSocket::bind(&directory.0).unwrap();
        assert!(UserSocket::bind(&directory.0).is_err());
        assert_eq!(fs::metadata(&directory.0).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(server.path()).unwrap().mode() & 0o777, 0o600);
        let mut client = UnixStream::connect(server.path()).await.unwrap();
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
            UserSocket::bind(&directory.0).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::metadata(&directory.0).unwrap().mode() & 0o777, 0o755);
    }

    #[tokio::test]
    async fn drop_does_not_remove_replacement_file() {
        let directory = Directory::new();
        let server = UserSocket::bind(&directory.0).unwrap();
        let path = server.path().to_owned();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"preserve").unwrap();
        drop(server);
        assert_eq!(fs::read(&path).unwrap(), b"preserve");
        fs::remove_file(path).unwrap();
    }
}
