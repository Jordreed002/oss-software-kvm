//! One-client, current-user Windows control endpoint.
//!
//! The protected DACL grants access only to the process user and SYSTEM; remote
//! clients are rejected and first-instance creation refuses name collisions.
//! This is a user boundary, NOT proof of a signed application's identity. A
//! service must still negotiate the agent instance and apply command policy.
//! Same-user malicious processes and cross-session policy require further review.
//! See Microsoft's Named Pipe Security and Access Rights documentation:
//! <https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights>
#![allow(unsafe_code)]

use std::{ffi::c_void, io, mem, ptr};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: uniquely owned token handle from OpenProcessToken.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct LocalBlock(*mut c_void);
impl Drop for LocalBlock {
    fn drop(&mut self) {
        // SAFETY: pointer allocated by a Windows conversion API using LocalAlloc.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn current_sid() -> io::Result<String> {
    let mut raw = ptr::null_mut();
    // SAFETY: valid process pseudo-handle, output points to a live local handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(raw);
    let mut size = 0;
    // SAFETY: zero-size query intentionally requests the required buffer size.
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &raw mut size);
    }
    if size < u32::try_from(mem::size_of::<TOKEN_USER>()).unwrap_or(u32::MAX) || size > 65_536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token user size rejected",
        ));
    }
    // usize storage gives TOKEN_USER pointer alignment on supported Windows ABIs.
    let mut buffer = vec![0_usize; (size as usize).div_ceil(mem::size_of::<usize>())];
    // SAFETY: aligned buffer has at least size bytes; token remains live.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &raw mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful TokenUser query initialized TOKEN_USER in aligned storage.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut wide_sid = ptr::null_mut();
    // SAFETY: SID points into the still-live TokenUser buffer; API owns output.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut wide_sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalBlock(wide_sid.cast());
    let mut length = 0;
    // SAFETY: success returns a NUL-terminated SID string. The Windows SID text
    // maximum is bounded; the guard rejects unexpectedly long output.
    while length < 184 && unsafe { *wide_sid.add(length) } != 0 {
        length += 1;
    }
    if length == 184 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SID text too long",
        ));
    }
    // SAFETY: length was found within the API's allocated terminated string.
    String::from_utf16(unsafe { std::slice::from_raw_parts(wide_sid, length) })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SID text"))
}

fn descriptor(sid: &str) -> io::Result<LocalBlock> {
    // sid comes only from ConvertSidToStringSidW, never from an external client.
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;;GA;;;SY)(A;;GA;;;{sid})S:(ML;;NWNR;;;ME)")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut raw = ptr::null_mut();
    // SAFETY: valid terminated SDDL input, revision 1, writable output pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &raw mut raw,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalBlock(raw))
}

/// One-client listener, retaining a pending instance while an accepted client
/// owns the previous handle. This prevents a name gap between connections.
pub struct UserPipe {
    server: NamedPipeServer,
    path: String,
    sid: String,
    admission: std::sync::Arc<tokio::sync::Semaphore>,
    poisoned: bool,
}

/// One accepted connection. Drop it before accepting another client.
#[derive(Debug)]
pub struct UserConnection {
    stream: NamedPipeServer,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for UserConnection {
    fn drop(&mut self) {
        // Force pending writes to fail. mio deliberately leaves writes alive
        // on drop; without disconnect a nonreading client can pin an instance.
        let _ = self.stream.disconnect();
    }
}

impl UserConnection {
    /// Borrow the connected stream; apply framing and owner deadlines.
    pub fn stream(&mut self) -> &mut NamedPipeServer {
        &mut self.stream
    }
}

impl std::fmt::Debug for UserPipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserPipe").finish_non_exhaustive()
    }
}

fn create_server(path: &str, sid: &str, first: bool) -> io::Result<NamedPipeServer> {
    let security = descriptor(sid)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| io::Error::other("security attributes size rejected"))?,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };
    // SAFETY: attributes and descriptor remain valid through creation. Windows
    // copies the descriptor and the handle is non-inheritable.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(2)
            .in_buffer_size(16_384)
            .out_buffer_size(16_384)
            .create_with_security_attributes_raw(path, (&raw mut attributes).cast())
    }
}

impl UserPipe {
    /// Binds a per-user channel. Use "control" for the installed agent.
    ///
    /// # Errors
    /// Rejects invalid labels, occupied names and security/API failures.
    /// Requires a Tokio runtime with I/O enabled.
    pub fn bind(channel: &str) -> io::Result<Self> {
        if channel.is_empty()
            || channel.len() > 64
            || !channel
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid pipe channel",
            ));
        }
        let sid = current_sid()?;
        let path = format!(r"\\.\pipe\software-kvm-agent-{sid}-{channel}");
        if path.encode_utf16().count() > 240 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipe path too long",
            ));
        }
        let server = create_server(&path, &sid, true)?;
        Ok(Self {
            server,
            path,
            sid,
            admission: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            poisoned: false,
        })
    }

    /// Endpoint contains an account SID; avoid exporting it in diagnostics.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Accepts one client and creates its replacement listener before returning.
    /// A permit restricts the application to one accepted connection at a time.
    ///
    /// # Errors
    /// Returns `WouldBlock` while a connection is held. Other errors are terminal:
    /// close the listener rather than attempting to reuse a partially connected
    /// server. Cancelling this future poisons the listener, including during
    /// connect. The owner must enforce connection deadlines and command policy.
    pub async fn accept(&mut self) -> io::Result<UserConnection> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "listener must be recreated after cancellation or failure",
            ));
        }
        let permit =
            self.admission.clone().try_acquire_owned().map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "pipe client already active")
            })?;
        // Set before awaiting: cancellation cannot accidentally reuse a
        // connected client or half-completed replacement operation.
        self.poisoned = true;
        self.server.connect().await?;
        // Tokio may defer closing a dropped overlapped pipe handle until its
        // cancellation completion is serviced. Keep the two-instance OS bound
        // and yield to the reactor instead of raising the instance limit.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
        let next = loop {
            match create_server(&self.path, &self.sid, false) {
                Ok(server) => break server,
                Err(error) if error.raw_os_error() == Some(231) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "pipe handle retirement timed out",
                        ));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                Err(error) => return Err(error),
            }
        };
        let stream = mem::replace(&mut self.server, next);
        self.poisoned = false;
        Ok(UserConnection {
            stream,
            _permit: permit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::ClientOptions;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    fn channel() -> String {
        format!(
            "test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[tokio::test]
    async fn same_user_roundtrip_and_collision_rejection() {
        let channel = channel();
        let mut server = UserPipe::bind(&channel).unwrap();
        assert!(UserPipe::bind(&channel).is_err());
        let mut client = ClientOptions::new().open(server.path()).unwrap();
        let mut connection = server.accept().await.unwrap();
        let stream = connection.stream();
        crate::write_frame(&mut client, b"status", 16)
            .await
            .unwrap();
        let mut buffer = [0_u8; 16];
        assert_eq!(
            crate::read_frame(stream, &mut buffer).await.unwrap(),
            Some(b"status".as_slice())
        );
        assert!(server.accept().await.is_err());
        drop(connection);
        drop(client);
        let mut second = ClientOptions::new().open(server.path()).unwrap();
        let mut connection = server.accept().await.unwrap();
        let stream = connection.stream();
        crate::write_frame(&mut second, b"again", 16).await.unwrap();
        assert_eq!(
            crate::read_frame(stream, &mut buffer).await.unwrap(),
            Some(b"again".as_slice())
        );
    }

    #[tokio::test]
    async fn rejects_ambiguous_channel_names() {
        for name in ["", "../control", "a/b", "a\\b", "name\0suffix"] {
            assert_eq!(
                UserPipe::bind(name).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[tokio::test]
    async fn cancelled_accept_is_terminal() {
        let mut server = UserPipe::bind(&channel()).unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), server.accept())
                .await
                .is_err()
        );
        assert_eq!(
            server.accept().await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test]
    async fn nonreading_client_cannot_pin_retired_server() {
        let mut server = UserPipe::bind(&channel()).unwrap();
        let mut stalled = ClientOptions::new().open(server.path()).unwrap();
        let mut first = server.accept().await.unwrap();
        let payload = vec![0_u8; 65_536];
        let _ = first.stream().try_write(&payload);
        drop(first);
        // Keep the original client's handle live while accepting a new one.
        let mut next = ClientOptions::new().open(server.path()).unwrap();
        let mut second = tokio::time::timeout(std::time::Duration::from_secs(1), server.accept())
            .await
            .unwrap()
            .unwrap();
        crate::write_frame(&mut next, b"ok", 8).await.unwrap();
        let mut buffer = [0_u8; 8];
        assert_eq!(
            crate::read_frame(second.stream(), &mut buffer)
                .await
                .unwrap(),
            Some(b"ok".as_slice())
        );
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            stalled.read(&mut buffer),
        )
        .await
        .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
    }
}
