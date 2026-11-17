//! One-client, current-user Windows control endpoint.
//!
//! The protected DACL grants access only to the process user and SYSTEM; remote
//! clients are rejected and first-instance creation refuses name collisions.
//! This is a user boundary, NOT proof of a signed application's identity. A
//! service must still negotiate the agent instance and apply command policy.
//! Peers must share the current account SID and Windows session. This does not
//! exclude malicious processes running as that user in that session.
//! See Microsoft's Named Pipe Security and Access Rights documentation:
//! <https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights>
#![allow(unsafe_code)]

use std::{ffi::c_void, io, mem, os::windows::io::AsRawHandle, ptr, time::Duration};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_BUSY,
        HANDLE,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    },
    System::{
        Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
        RemoteDesktop::ProcessIdToSessionId,
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: uniquely owned process or token handle returned by Windows.
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
    // SAFETY: the pseudo-handle remains valid and is borrowed, never closed.
    token_sid(unsafe { GetCurrentProcess() })
}

// The handle is borrowed only for OpenProcessToken; callers keep its owner live.
fn token_sid(process: HANDLE) -> io::Result<String> {
    let mut raw = ptr::null_mut();
    // SAFETY: borrowed live process handle, output points to a live local handle.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(raw);
    let mut size = 0;
    // SAFETY: zero-size query intentionally requests the required buffer size.
    let result =
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &raw mut size) };
    validate_size_query(result, io::Error::last_os_error())?;
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

fn validate_size_query(result: i32, error: io::Error) -> io::Result<()> {
    if result == 0 && error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER.cast_signed()) {
        Ok(())
    } else if result == 0 {
        Err(error)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected token size query success",
        ))
    }
}

#[derive(Debug)]
struct Identity {
    sid: String,
    session: u32,
}

fn session_id(pid: u32) -> io::Result<u32> {
    let mut session = 0;
    // SAFETY: writable output, no retained pointer. Failure never yields identity.
    if unsafe { ProcessIdToSessionId(pid, &raw mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(session)
}

fn current_identity() -> io::Result<Identity> {
    Ok(Identity {
        sid: current_sid()?,
        session: session_id(std::process::id())?,
    })
}

fn process_identity(pid: u32) -> io::Result<Identity> {
    if pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unknown pipe peer PID",
        ));
    }
    // SAFETY: asks only for limited query access, with no inherited handle.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = OwnedHandle(raw);
    // Keep the process handle alive through both queries, including the PID lookup.
    Ok(Identity {
        sid: token_sid(process.0)?,
        session: session_id(pid)?,
    })
}

fn require_identity(expected: &Identity, peer: io::Result<Identity>) -> io::Result<()> {
    let peer = peer?;
    if peer.sid != expected.sid || peer.session != expected.session {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pipe peer user or session mismatch",
        ));
    }
    Ok(())
}

fn verify_peer(pipe: &impl AsRawHandle, server_peer: bool, expected: &Identity) -> io::Result<()> {
    let mut pid = 0;
    // SAFETY: pipe borrows a live Tokio pipe handle and pid is writable. No
    // ownership is transferred; neither API retains the output pointer.
    let result = unsafe {
        if server_peer {
            GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &raw mut pid)
        } else {
            GetNamedPipeClientProcessId(pipe.as_raw_handle().cast(), &raw mut pid)
        }
    };
    let peer = if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        process_identity(pid)
    };
    require_identity(expected, peer)
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))
}

fn endpoint_name(channel: &str, identity: &Identity) -> io::Result<String> {
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
    let path = format!(
        r"\\.\pipe\software-kvm-agent-{}-session-{}-{channel}",
        identity.sid, identity.session
    );
    if path.encode_utf16().count() > 240 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pipe path too long",
        ));
    }
    Ok(path)
}

fn retryable_connect(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == ERROR_FILE_NOT_FOUND.cast_signed() || code == ERROR_PIPE_BUSY.cast_signed())
}

/// Connect to this user's session endpoint and verify its server before returning.
/// Keeps Tokio's default identification SQOS. No protocol messages are sent.
///
/// # Errors
/// Returns identity/API errors immediately. Only missing or busy pipes are retried
/// within the caller's timeout. Expiration after a missing endpoint returns
/// `NotFound`; a busy endpoint or exhausted verification budget returns `TimedOut`.
pub async fn connect(channel: &str, timeout: Duration) -> io::Result<NamedPipeClient> {
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout too large"))?;
    let identity = current_identity()?;
    let path = endpoint_name(channel, &identity)?;
    let mut last_missing = false;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                if last_missing {
                    io::ErrorKind::NotFound
                } else {
                    io::ErrorKind::TimedOut
                },
                "pipe connection timed out",
            ));
        }
        match ClientOptions::new().open(&path) {
            Ok(stream) => {
                verify_peer(&stream, true, &identity)?;
                if tokio::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "pipe connection timed out",
                    ));
                }
                return Ok(stream);
            }
            Err(error) if retryable_connect(&error) => {
                last_missing = error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND.cast_signed());
                tokio::time::sleep_until(
                    deadline.min(tokio::time::Instant::now() + Duration::from_millis(5)),
                )
                .await;
            }
            Err(error) => return Err(error),
        }
    }
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
    identity: Identity,
    admission: std::sync::Arc<tokio::sync::Semaphore>,
    poisoned: bool,
}

/// One accepted connection. Drop it before accepting another client.
#[derive(Debug)]
pub struct UserConnection {
    stream: NamedPipeServer,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for UserPipe {
    fn drop(&mut self) {
        // A cancelled/failed accept may still own a connected client. Force
        // it off even when no UserConnection was returned to the owner.
        let _ = self.server.disconnect();
    }
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
        let identity = current_identity()?;
        let path = endpoint_name(channel, &identity)?;
        let server = create_server(&path, &identity.sid, true)?;
        Ok(Self {
            server,
            path,
            identity,
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
        if let Err(error) = verify_peer(&self.server, false, &self.identity) {
            let _ = self.server.disconnect();
            return Err(error);
        }
        // Tokio may defer closing a dropped overlapped pipe handle until its
        // cancellation completion is serviced. Keep the two-instance OS bound
        // and yield to the reactor instead of raising the instance limit.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
        let next = loop {
            match create_server(&self.path, &self.identity.sid, false) {
                Ok(server) => break server,
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY.cast_signed()) => {
                    if tokio::time::Instant::now() >= deadline {
                        let _ = self.server.disconnect();
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "pipe handle retirement timed out",
                        ));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                Err(error) => {
                    let _ = self.server.disconnect();
                    return Err(error);
                }
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

    #[test]
    fn identity_and_native_errors_fail_closed() {
        let expected = current_identity().unwrap();
        require_identity(&expected, process_identity(std::process::id())).unwrap();
        assert_eq!(
            process_identity(0).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(require_identity(&expected, Err(io::Error::from_raw_os_error(5))).is_err());
        for peer in [
            Identity {
                sid: "S-1-5-18".into(),
                session: expected.session,
            },
            Identity {
                sid: expected.sid.clone(),
                session: expected.session.wrapping_add(1),
            },
        ] {
            assert_eq!(
                require_identity(&expected, Ok(peer)).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        validate_size_query(0, io::Error::from_raw_os_error(122)).unwrap();
        assert_eq!(
            validate_size_query(0, io::Error::from_raw_os_error(5))
                .unwrap_err()
                .raw_os_error(),
            Some(5)
        );
        assert!(validate_size_query(1, io::Error::from_raw_os_error(122)).is_err());
        for code in [2, 231] {
            assert!(retryable_connect(&io::Error::from_raw_os_error(code)));
        }
        for code in [5, 109, 123] {
            assert!(!retryable_connect(&io::Error::from_raw_os_error(code)));
        }
        let name = endpoint_name("control", &expected).unwrap();
        assert_eq!(
            name,
            endpoint_name("control", &current_identity().unwrap()).unwrap()
        );
        let other = Identity {
            sid: expected.sid.clone(),
            session: expected.session.wrapping_add(1),
        };
        assert_ne!(name, endpoint_name("control", &other).unwrap());
    }

    #[tokio::test]
    async fn rejected_peer_disconnects_and_poisons_listener() {
        let mut server = UserPipe::bind(&channel()).unwrap();
        let mut client = ClientOptions::new().open(server.path()).unwrap();
        let wrong = Identity {
            sid: server.identity.sid.clone(),
            session: server.identity.session.wrapping_add(1),
        };
        assert_eq!(
            verify_peer(&client, true, &wrong).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        server.identity = wrong;
        assert_eq!(
            server.accept().await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            server.accept().await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let mut buffer = [0; 1];
        let result = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buffer))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn connector_retries_missing_and_busy_with_deadline() {
        let label = channel();
        assert_eq!(
            connect(&label, Duration::from_millis(10))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        let delayed = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            UserPipe::bind(&label).unwrap()
        };
        let (client, mut server) = tokio::join!(connect(&label, Duration::from_secs(1)), delayed);
        let _client = client.unwrap();
        let _connection = server.accept().await.unwrap();
        let _pending = connect(&label, Duration::from_secs(1)).await.unwrap();
        assert_eq!(
            connect(&label, Duration::from_millis(10))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            connect(&label, Duration::ZERO).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn same_user_roundtrip_and_collision_rejection() {
        let channel = channel();
        let mut server = UserPipe::bind(&channel).unwrap();
        assert!(UserPipe::bind(&channel).is_err());
        let mut client = connect(&channel, Duration::from_secs(1)).await.unwrap();
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
        crate::write_frame(stream, b"reply", 16).await.unwrap();
        assert_eq!(
            crate::read_frame(&mut client, &mut buffer).await.unwrap(),
            Some(b"reply".as_slice())
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

    #[tokio::test]
    async fn unknown_peer_is_classified_as_untrusted() {
        let server = UserPipe::bind(&channel()).unwrap();
        let error = verify_peer(&server.server, false, &server.identity).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            error.get_ref().is_some(),
            "preserve the native failure as a source"
        );
    }

    #[tokio::test]
    async fn final_reply_survives_slow_reader_when_owner_waits_for_eof() {
        let name = channel();
        let mut listener = UserPipe::bind(&name).unwrap();
        let (written, ready) = tokio::sync::oneshot::channel();
        let serve = async {
            let mut connection = listener.accept().await.unwrap();
            crate::write_frame(connection.stream(), b"final status", 32)
                .await
                .unwrap();
            written.send(()).unwrap();
            let mut eof = [0_u8; 1];
            let count =
                tokio::time::timeout(Duration::from_secs(1), connection.stream().read(&mut eof))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(count, 0);
            // Drop now forces disconnect only AFTER the client consumed its
            // response and closed. A successful write alone is insufficient.
        };
        let request = async {
            let mut client = connect(&name, Duration::from_secs(1)).await.unwrap();
            ready.await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            let mut storage = [0_u8; 32];
            assert_eq!(
                crate::read_frame(&mut client, &mut storage).await.unwrap(),
                Some(b"final status".as_slice())
            );
            drop(client);
        };
        tokio::join!(serve, request);
    }
}
