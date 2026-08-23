//! OS-backed local transport carrying the daemon↔control-panel control plane
//! (spec §31; see `docs/audit/2026-08-10-daemon-control-ipc-orphaned.md`).
//!
//! The control panel talks to its *local* daemon over a Unix domain socket
//! (macOS/Linux) or a Windows named pipe — never over the network. Each
//! [`ControlFrame`] travels as a 4-byte big-endian length prefix followed by
//! the versioned bytes produced by [`encode_control`], so the wire format and
//! its bounds stay owned by `kvm-protocol`: this module adds an OS transport,
//! not a second codec.
//!
//! # Trust boundary
//!
//! The endpoint is local and same-user by construction. On Unix the socket
//! file is created with `0600` permissions, so only the daemon's own user can
//! connect; on Windows the pipe is created with remote clients rejected.
//! There is no listening TCP surface, so nothing on the machine's network is
//! reachable through this channel, and no in-protocol authentication is
//! layered on top of the OS's same-user rule. On Unix there is an unavoidable
//! bind→chmod window in which the socket file briefly carries the process
//! umask's permissions; a daemon that tightens its umask at startup closes it
//! (a composition duty, tracked in the audit doc).

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use kvm_protocol::{
    decode_control, encode_control, ControlCodecError, ControlFrame, MAX_CONTROL_FRAME_BYTES,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// Wire bytes dedicated to the frame length prefix. The payload that follows
/// is exactly the output of [`encode_control`].
const LENGTH_PREFIX_BYTES: usize = 4;
/// Default number of panel connections served concurrently: the deployment
/// shape the spec describes is one daemon plus one panel.
const DEFAULT_MAX_LOCAL_CONTROL_CONNECTIONS: usize = 1;
/// Ceiling on [`LocalControlServerConfig::max_connections`]. The bound exists
/// so a misconfigured daemon cannot admit an unbounded number of local
/// connections, each pinning a permit and a socket/pipe instance.
const HARD_MAX_LOCAL_CONTROL_CONNECTIONS: usize = 16;
/// Socket file name under the user's runtime directory on Unix.
const DEFAULT_SOCKET_FILE_NAME: &str = "software-kvm-control.sock";
/// Default named pipe path on Windows.
const DEFAULT_PIPE_PATH: &str = r"\\.\pipe\software-kvm-control";
/// Connect retry cadence, matching the diagnostics client so both local
/// consumers share one deterministic startup-race behaviour.
const CONNECT_RETRY_CADENCE: Duration = Duration::from_millis(20);

// --- Errors -----------------------------------------------------------------

/// Failure raised by the local daemon↔panel OS transport.
#[derive(Debug, Error)]
pub enum LocalIpcError {
    /// The server configuration failed validation.
    #[error("local control configuration invalid: {0}")]
    Config(#[from] LocalIpcConfigError),
    /// Socket/pipe bind, connect, accept, read, or write failure.
    #[error("local control transport I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A frame could not be encoded or decoded, or violated a size or
    /// content bound.
    #[error("local control frame rejected: {0}")]
    Codec(#[from] ControlCodecError),
    /// The peer closed its end of the connection.
    #[error("local control connection closed by peer")]
    Closed,
}

/// Invalid [`LocalControlServerConfig`].
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LocalIpcConfigError {
    /// The endpoint path was empty.
    #[error("local control endpoint path must not be empty")]
    EmptyPath,
    /// The connection bound was zero or exceeded the hard maximum.
    #[error(
        "max local control connections must be between 1 and {HARD_MAX_LOCAL_CONTROL_CONNECTIONS}"
    )]
    InvalidMaxConnections,
}

// --- Configuration ----------------------------------------------------------

/// Conventional control endpoint for this host: `software-kvm-control.sock`
/// under the user's runtime directory (`$TMPDIR`, falling back to `/tmp`) on
/// macOS/Linux, or the `\\.\pipe\software-kvm-control` named pipe on Windows.
#[must_use]
pub fn default_control_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(DEFAULT_PIPE_PATH)
    } else {
        std::env::temp_dir().join(DEFAULT_SOCKET_FILE_NAME)
    }
}

/// Configuration for [`LocalControlServer::bind`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalControlServerConfig {
    /// Endpoint path: a Unix socket file path (macOS/Linux) or a
    /// `\\.\pipe\name` pipe path (Windows). Caller-supplied so embedders can
    /// place the endpoint under their own runtime directory;
    /// [`default_control_path`] provides the conventional location.
    pub path: PathBuf,
    /// Maximum panel connections served concurrently. [`accept`] waits for a
    /// slot instead of handing out connections beyond this bound.
    ///
    /// [`accept`]: LocalControlServer::accept
    pub max_connections: usize,
}

impl Default for LocalControlServerConfig {
    fn default() -> Self {
        Self {
            path: default_control_path(),
            max_connections: DEFAULT_MAX_LOCAL_CONTROL_CONNECTIONS,
        }
    }
}

impl LocalControlServerConfig {
    /// Creates a config for a specific endpoint path with the default
    /// single-connection bound.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            max_connections: DEFAULT_MAX_LOCAL_CONTROL_CONNECTIONS,
        }
    }

    fn validate(&self) -> Result<(), LocalIpcConfigError> {
        if self.path.as_os_str().is_empty() {
            return Err(LocalIpcConfigError::EmptyPath);
        }
        if self.max_connections == 0 || self.max_connections > HARD_MAX_LOCAL_CONTROL_CONNECTIONS {
            return Err(LocalIpcConfigError::InvalidMaxConnections);
        }
        Ok(())
    }
}

// --- OS stream wrapper ------------------------------------------------------

/// The OS stream underlying one local control connection. One concrete type
/// (rather than a generic parameter) so the daemon service and the panel
/// client program against the same connection type on every platform.
#[derive(Debug)]
enum IpcStream {
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(windows)]
    PipeServer(NamedPipeServer),
    #[cfg(windows)]
    PipeClient(NamedPipeClient),
}

impl AsyncRead for IpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(inner) => Pin::new(inner).poll_read(cx, buf),
            #[cfg(windows)]
            Self::PipeServer(inner) => Pin::new(inner).poll_read(cx, buf),
            #[cfg(windows)]
            Self::PipeClient(inner) => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for IpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(inner) => Pin::new(inner).poll_write(cx, buf),
            #[cfg(windows)]
            Self::PipeServer(inner) => Pin::new(inner).poll_write(cx, buf),
            #[cfg(windows)]
            Self::PipeClient(inner) => Pin::new(inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(inner) => Pin::new(inner).poll_flush(cx),
            #[cfg(windows)]
            Self::PipeServer(inner) => Pin::new(inner).poll_flush(cx),
            #[cfg(windows)]
            Self::PipeClient(inner) => Pin::new(inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(inner) => Pin::new(inner).poll_shutdown(cx),
            #[cfg(windows)]
            Self::PipeServer(inner) => Pin::new(inner).poll_shutdown(cx),
            #[cfg(windows)]
            Self::PipeClient(inner) => Pin::new(inner).poll_shutdown(cx),
        }
    }
}

// --- Server -----------------------------------------------------------------

/// Daemon-side listener for local control-panel connections.
///
/// Serves at most [`LocalControlServerConfig::max_connections`] connections
/// concurrently (one by default): [`accept`] holds further connections until a
/// served one is dropped, so a second panel cannot silently displace the
/// first. Accept deliberately has no built-in timeout — waiting for a panel is
/// the listener's job — so callers that need a cap wrap it in
/// `tokio::time::timeout`.
///
/// [`accept`]: LocalControlServer::accept
#[derive(Debug)]
pub struct LocalControlServer {
    path: PathBuf,
    #[cfg(unix)]
    listener: UnixListener,
    /// Next named-pipe instance, already created so a queued client has
    /// something to connect to while the current instance is being served.
    #[cfg(windows)]
    pending: Option<NamedPipeServer>,
    connection_slots: Arc<Semaphore>,
}

impl LocalControlServer {
    /// Binds the daemon-side endpoint described by `config`.
    ///
    /// On Unix this creates the socket file, removing a stale file left by a
    /// crashed daemon when nothing answers a probe connection, and restricts
    /// the file to the daemon's own user. On Windows it creates the first
    /// named-pipe instance.
    ///
    /// # Errors
    ///
    /// Returns [`LocalIpcError::Config`] for an invalid bound or empty path,
    /// and [`LocalIpcError::Io`] when the endpoint cannot be created —
    /// including when another live daemon already owns it.
    pub fn bind(config: LocalControlServerConfig) -> Result<Self, LocalIpcError> {
        config.validate()?;
        let LocalControlServerConfig {
            path,
            max_connections,
        } = config;
        Ok(Self {
            #[cfg(unix)]
            listener: bind_unix_listener(&path)?,
            #[cfg(windows)]
            pending: Some(create_pipe_instance(&path)?),
            connection_slots: Arc::new(Semaphore::new(max_connections)),
            path,
        })
    }

    /// Endpoint path the server was bound to (for clients and diagnostics).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepts the next panel connection.
    ///
    /// A connection slot is acquired *before* touching the OS accept queue, so
    /// the configured bound holds even while clients queue in the socket
    /// backlog; the slot rides inside the returned connection and is released
    /// when the connection is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`LocalIpcError::Io`] when the OS accept or pipe connect
    /// fails.
    pub async fn accept(&mut self) -> Result<LocalControlConnection, LocalIpcError> {
        let permit = Arc::clone(&self.connection_slots)
            .acquire_owned()
            .await
            .map_err(|_| LocalIpcError::Closed)?;
        let stream = self.accept_stream().await?;
        Ok(LocalControlConnection {
            stream,
            permit: Some(permit),
        })
    }

    #[cfg(unix)]
    async fn accept_stream(&mut self) -> Result<IpcStream, LocalIpcError> {
        let (stream, _address) = self.listener.accept().await?;
        Ok(IpcStream::Unix(stream))
    }

    #[cfg(windows)]
    async fn accept_stream(&mut self) -> Result<IpcStream, LocalIpcError> {
        // Tokio's documented named-pipe server pattern: take the instance that
        // is waiting for a client, create its replacement before blocking on
        // connect, so at most one extra instance ever exists for queueing.
        let instance = match self.pending.take() {
            Some(instance) => instance,
            None => create_pipe_instance(&self.path)?,
        };
        self.pending = Some(create_pipe_instance(&self.path)?);
        instance.connect().await?;
        Ok(IpcStream::PipeServer(instance))
    }
}

/// Binds the Unix socket and restricts it to the daemon's own user.
///
/// A leftover socket file from a crashed daemon is detected by probing it: a
/// successful (immediately dropped) std connect means a live daemon owns the
/// endpoint and the bind error stands; a refused connection means the file is
/// stale, so it is removed and the bind retried once. The blocking std probe
/// is acceptable here because it only ever runs against a local endpoint and
/// fails fast.
#[cfg(unix)]
fn bind_unix_listener(path: &Path) -> Result<UnixListener, LocalIpcError> {
    let listener = match UnixListener::bind(path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(error.into());
            }
            std::fs::remove_file(path)?;
            UnixListener::bind(path)?
        }
        Err(error) => return Err(error.into()),
    };
    // 0600 is the local trust boundary: the panel runs as the same user as
    // the daemon, and no other local account (or any remote host) may
    // connect. See the module docs for the bind→chmod umask window.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Creates one server-side named-pipe instance. Remote clients are rejected —
/// the pipe is part of the same-user local trust boundary, never a network
/// surface.
#[cfg(windows)]
fn create_pipe_instance(path: &Path) -> Result<NamedPipeServer, LocalIpcError> {
    Ok(ServerOptions::new()
        .reject_remote_clients(true)
        .create(path)?)
}

// --- Client -----------------------------------------------------------------

/// Panel-side entry point for the daemon's local control endpoint.
#[derive(Debug)]
pub struct LocalControlClient;

impl LocalControlClient {
    /// Connects to the daemon endpoint at `path`, retrying failures within
    /// `timeout` at the crate's diagnostics-client cadence so the panel can
    /// race daemon startup. A zero `timeout` performs exactly one attempt.
    ///
    /// # Errors
    ///
    /// Returns the last connection failure once the timeout expires (or the
    /// single failure, for a zero timeout).
    pub async fn connect(
        path: &Path,
        timeout: Duration,
    ) -> Result<LocalControlConnection, LocalIpcError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Unix sockets connect asynchronously; named-pipe clients connect
            // synchronously. Each platform calls its real signature rather
            // than carrying a no-op async wrapper on Windows.
            #[cfg(unix)]
            let attempt = open_stream(path).await;
            #[cfg(windows)]
            let attempt = open_stream(path);
            match attempt {
                Ok(stream) => {
                    return Ok(LocalControlConnection {
                        stream,
                        permit: None,
                    });
                }
                Err(error) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(error);
                    }
                    tokio::time::sleep(CONNECT_RETRY_CADENCE).await;
                }
            }
        }
    }
}

#[cfg(unix)]
async fn open_stream(path: &Path) -> Result<IpcStream, LocalIpcError> {
    Ok(IpcStream::Unix(UnixStream::connect(path).await?))
}

#[cfg(windows)]
fn open_stream(path: &Path) -> Result<IpcStream, LocalIpcError> {
    Ok(IpcStream::PipeClient(ClientOptions::new().open(path)?))
}

// --- Connection -------------------------------------------------------------

/// One end of the daemon↔panel local channel, exchanging whole
/// [`ControlFrame`]s.
///
/// Frames are `[u32 big-endian payload length][versioned control codec
/// bytes]`. Connections obtained from [`LocalControlServer::accept`] hold a
/// concurrency slot that is released when the connection is dropped.
#[derive(Debug)]
pub struct LocalControlConnection {
    stream: IpcStream,
    /// Held purely for its drop side effect: releasing the server connection
    /// slot when a daemon-side connection goes away. Never read.
    #[allow(dead_code)]
    permit: Option<OwnedSemaphorePermit>,
}

impl LocalControlConnection {
    /// Sends one frame.
    ///
    /// # Errors
    ///
    /// Returns [`LocalIpcError::Codec`] when the frame cannot be encoded or
    /// exceeds the control frame cap, and [`LocalIpcError::Io`] when the
    /// socket or pipe cannot accept the complete frame.
    pub async fn send(&mut self, frame: ControlFrame) -> Result<(), LocalIpcError> {
        let payload = encode_control(&frame)?;
        // `encode_control` already capped the payload, which fits a u32; the
        // conversion is checked anyway so this path cannot panic on any
        // future cap change.
        let length = u32::try_from(payload.len()).map_err(|_| ControlCodecError::Oversized)?;
        self.stream.write_all(&length.to_be_bytes()).await?;
        self.stream.write_all(&payload).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receives the next frame.
    ///
    /// A length prefix advertising more than [`MAX_CONTROL_FRAME_BYTES`] is
    /// rejected before the payload is buffered, mirroring the authenticated
    /// reader's guarantee that a hostile local writer cannot force an
    /// unbounded allocation. Partially received frames are not retained
    /// across cancellations, so this future must not be raced against other
    /// readers of the same connection.
    ///
    /// # Errors
    ///
    /// Returns [`LocalIpcError::Closed`] when the peer has closed its end,
    /// [`LocalIpcError::Codec`] when the prefix or payload violates a bound,
    /// and [`LocalIpcError::Io`] on transport failure.
    pub async fn recv(&mut self) -> Result<ControlFrame, LocalIpcError> {
        let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
        read_exact_or_closed(&mut self.stream, &mut prefix).await?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > MAX_CONTROL_FRAME_BYTES {
            return Err(LocalIpcError::Codec(ControlCodecError::Oversized));
        }
        let mut payload = vec![0_u8; length];
        read_exact_or_closed(&mut self.stream, &mut payload).await?;
        Ok(decode_control(&payload)?)
    }

    /// Shuts down the write half: the peer's next [`recv`](Self::recv)
    /// observes the closure instead of blocking.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport's I/O error.
    pub async fn shutdown(&mut self) -> Result<(), LocalIpcError> {
        self.stream.shutdown().await?;
        Ok(())
    }
}

/// `read_exact` mapped so a clean peer close surfaces as
/// [`LocalIpcError::Closed`] rather than a generic truncated-read I/O error.
async fn read_exact_or_closed<S>(stream: &mut S, buf: &mut [u8]) -> Result<(), LocalIpcError>
where
    S: AsyncRead + Unpin,
{
    stream.read_exact(buf).await.map(|_| ()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            LocalIpcError::Closed
        } else {
            LocalIpcError::Io(error)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use kvm_protocol::{ControlEvent, ControlRequest, ControlResponse, CONTROL_PROTOCOL_VERSION};
    use std::ffi::OsStr;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    #[cfg(unix)]
    use tokio::time::timeout;

    /// Every await in these tests sits inside a `timeout` wrapper so a
    /// transport bug fails the suite instead of hanging it.
    #[cfg(unix)]
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    /// Long enough to prove an accept is being held, short enough to keep
    /// the suite fast.
    #[cfg(unix)]
    const SHORT_TIMEOUT: Duration = Duration::from_millis(150);

    #[cfg(unix)]
    fn unique_socket_path() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
        std::env::temp_dir().join(format!(
            "skvm-local-ipc-test-{}-{unique}.sock",
            std::process::id()
        ))
    }

    /// Binds a server and returns it with one connected client/server pair.
    #[cfg(unix)]
    async fn connected_pair(
        config: LocalControlServerConfig,
    ) -> (
        PathBuf,
        LocalControlServer,
        LocalControlConnection,
        LocalControlConnection,
    ) {
        let path = config.path.clone();
        let mut server = LocalControlServer::bind(config).expect("bind");
        let client = timeout(
            TEST_TIMEOUT,
            LocalControlClient::connect(server.path(), TEST_TIMEOUT),
        )
        .await
        .expect("client connect timed out")
        .expect("client connect");
        let server_connection = timeout(TEST_TIMEOUT, server.accept())
            .await
            .expect("accept timed out")
            .expect("accept");
        (path, server, server_connection, client)
    }

    #[test]
    fn config_rejects_empty_paths_and_out_of_range_bounds() {
        let path = PathBuf::from("unused-endpoint");
        assert_eq!(
            LocalControlServerConfig::new(PathBuf::new()).validate(),
            Err(LocalIpcConfigError::EmptyPath)
        );
        assert_eq!(
            LocalControlServerConfig {
                max_connections: 0,
                ..LocalControlServerConfig::new(path.clone())
            }
            .validate(),
            Err(LocalIpcConfigError::InvalidMaxConnections)
        );
        assert_eq!(
            LocalControlServerConfig {
                max_connections: HARD_MAX_LOCAL_CONTROL_CONNECTIONS + 1,
                ..LocalControlServerConfig::new(path)
            }
            .validate(),
            Err(LocalIpcConfigError::InvalidMaxConnections)
        );
        assert_eq!(
            LocalControlServerConfig::new(PathBuf::from("valid")).validate(),
            Ok(())
        );
        assert_eq!(
            LocalControlServerConfig::default().max_connections,
            DEFAULT_MAX_LOCAL_CONTROL_CONNECTIONS
        );
    }

    #[test]
    fn default_control_path_matches_the_platform_convention() {
        let path = default_control_path();
        if cfg!(windows) {
            assert!(path.as_os_str().to_string_lossy().starts_with(r"\\.\pipe\"));
        } else {
            assert!(path.starts_with(std::env::temp_dir()));
            assert_eq!(
                path.file_name(),
                Some(OsStr::new("software-kvm-control.sock"))
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn loopback_exchanges_request_response_and_event() {
        let (path, _server, mut daemon_side, mut panel_side) =
            connected_pair(LocalControlServerConfig::new(unique_socket_path())).await;

        // Panel -> daemon: one command.
        timeout(
            TEST_TIMEOUT,
            panel_side.send(ControlFrame::Request(ControlRequest::GetStatus)),
        )
        .await
        .expect("panel send timed out")
        .expect("panel send");
        let received = timeout(TEST_TIMEOUT, daemon_side.recv())
            .await
            .expect("daemon recv timed out")
            .expect("daemon recv");
        assert_eq!(received, ControlFrame::Request(ControlRequest::GetStatus));

        // Daemon -> panel: the response, then an unsolicited event.
        timeout(
            TEST_TIMEOUT,
            daemon_side.send(ControlFrame::Response(ControlResponse::Acknowledged)),
        )
        .await
        .expect("daemon send timed out")
        .expect("daemon send");
        timeout(
            TEST_TIMEOUT,
            daemon_side.send(ControlFrame::Event(ControlEvent::PeerChanged)),
        )
        .await
        .expect("daemon event send timed out")
        .expect("daemon event send");
        let response = timeout(TEST_TIMEOUT, panel_side.recv())
            .await
            .expect("panel recv timed out")
            .expect("panel recv");
        assert_eq!(
            response,
            ControlFrame::Response(ControlResponse::Acknowledged)
        );
        let event = timeout(TEST_TIMEOUT, panel_side.recv())
            .await
            .expect("panel event recv timed out")
            .expect("panel event recv");
        assert_eq!(event, ControlFrame::Event(ControlEvent::PeerChanged));

        // A clean daemon-side shutdown surfaces to the panel without hanging.
        timeout(TEST_TIMEOUT, daemon_side.shutdown())
            .await
            .expect("shutdown timed out")
            .expect("shutdown");
        let closed = timeout(TEST_TIMEOUT, panel_side.recv())
            .await
            .expect("recv after shutdown timed out")
            .unwrap_err();
        assert!(matches!(closed, LocalIpcError::Closed));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recv_rejects_an_oversized_prefix_without_buffering_it() {
        let path = unique_socket_path();
        let mut server =
            LocalControlServer::bind(LocalControlServerConfig::new(path.clone())).expect("bind");

        // A hostile local writer (not LocalControlClient) advertises a payload
        // one byte above the control frame cap and sends nothing else.
        let hostile = timeout(TEST_TIMEOUT, UnixStream::connect(server.path()))
            .await
            .expect("hostile connect timed out")
            .expect("hostile connect");
        let (_hostile_read, mut hostile_write) = hostile.into_split();
        let advertised = u32::try_from(MAX_CONTROL_FRAME_BYTES + 1).expect("cap fits u32");
        timeout(
            TEST_TIMEOUT,
            hostile_write.write_all(&advertised.to_be_bytes()),
        )
        .await
        .expect("hostile write timed out")
        .expect("hostile write");

        let mut daemon_side = timeout(TEST_TIMEOUT, server.accept())
            .await
            .expect("accept timed out")
            .expect("accept");
        let error = timeout(TEST_TIMEOUT, daemon_side.recv())
            .await
            .expect("recv timed out")
            .unwrap_err();
        assert!(matches!(
            error,
            LocalIpcError::Codec(ControlCodecError::Oversized)
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recv_rejects_a_frame_with_a_wrong_version_byte() {
        let path = unique_socket_path();
        let mut server =
            LocalControlServer::bind(LocalControlServerConfig::new(path.clone())).expect("bind");

        let hostile = timeout(TEST_TIMEOUT, UnixStream::connect(server.path()))
            .await
            .expect("hostile connect timed out")
            .expect("hostile connect");
        let (_hostile_read, mut hostile_write) = hostile.into_split();
        let mut frame = Vec::new();
        frame.extend_from_slice(&2_u32.to_be_bytes());
        frame.push(CONTROL_PROTOCOL_VERSION.wrapping_add(1));
        frame.push(0);
        timeout(TEST_TIMEOUT, hostile_write.write_all(&frame))
            .await
            .expect("hostile write timed out")
            .expect("hostile write");

        let mut daemon_side = timeout(TEST_TIMEOUT, server.accept())
            .await
            .expect("accept timed out")
            .expect("accept");
        let error = timeout(TEST_TIMEOUT, daemon_side.recv())
            .await
            .expect("recv timed out")
            .unwrap_err();
        assert!(matches!(
            error,
            LocalIpcError::Codec(ControlCodecError::UnsupportedVersion)
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accept_holds_connections_beyond_the_configured_bound() {
        let path = unique_socket_path();
        let mut server =
            LocalControlServer::bind(LocalControlServerConfig::new(path.clone())).expect("bind");

        let panel1 = timeout(
            TEST_TIMEOUT,
            LocalControlClient::connect(server.path(), TEST_TIMEOUT),
        )
        .await
        .expect("first connect timed out")
        .expect("first connect");
        let held = timeout(TEST_TIMEOUT, server.accept())
            .await
            .expect("first accept timed out")
            .expect("first accept");

        // The second panel connects at the OS level (socket backlog), but with
        // the default bound of one the server must not hand out a second
        // connection while the first is still served.
        let mut panel2 = timeout(
            TEST_TIMEOUT,
            LocalControlClient::connect(server.path(), TEST_TIMEOUT),
        )
        .await
        .expect("second connect timed out")
        .expect("second connect");
        assert!(
            timeout(SHORT_TIMEOUT, server.accept()).await.is_err(),
            "accept must wait for a free slot"
        );

        // Dropping the served connection releases its slot.
        drop(held);
        let mut second = timeout(TEST_TIMEOUT, server.accept())
            .await
            .expect("second accept timed out")
            .expect("second accept");
        timeout(
            TEST_TIMEOUT,
            panel2.send(ControlFrame::Request(ControlRequest::GetPeers)),
        )
        .await
        .expect("second panel send timed out")
        .expect("second panel send");
        let received = timeout(TEST_TIMEOUT, second.recv())
            .await
            .expect("second accept recv timed out")
            .expect("second accept recv");
        assert_eq!(received, ControlFrame::Request(ControlRequest::GetPeers));
        drop(panel1);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_raised_bound_serves_two_panels_concurrently() {
        let path = unique_socket_path();
        let config = LocalControlServerConfig {
            max_connections: 2,
            ..LocalControlServerConfig::new(path.clone())
        };
        let mut server = LocalControlServer::bind(config).expect("bind");

        let panel1 = timeout(
            TEST_TIMEOUT,
            LocalControlClient::connect(server.path(), TEST_TIMEOUT),
        )
        .await
        .expect("first connect timed out")
        .expect("first connect");
        let first = timeout(TEST_TIMEOUT, server.accept())
            .await
            .expect("first accept timed out")
            .expect("first accept");
        let panel2 = timeout(
            TEST_TIMEOUT,
            LocalControlClient::connect(server.path(), TEST_TIMEOUT),
        )
        .await
        .expect("second connect timed out")
        .expect("second connect");
        let second = timeout(TEST_TIMEOUT, server.accept())
            .await
            .expect("second accept timed out")
            .expect("second accept");

        // A third connection is held at the raised bound, not served.
        let panel3 = timeout(
            TEST_TIMEOUT,
            LocalControlClient::connect(server.path(), TEST_TIMEOUT),
        )
        .await
        .expect("third connect timed out")
        .expect("third connect");
        assert!(
            timeout(SHORT_TIMEOUT, server.accept()).await.is_err(),
            "third accept must wait for a free slot"
        );

        drop((first, second, panel1, panel2, panel3));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_the_daemon_side_closes_the_panel_without_hanging() {
        let (path, _server, daemon_side, mut panel_side) =
            connected_pair(LocalControlServerConfig::new(unique_socket_path())).await;

        drop(daemon_side);
        let closed = timeout(TEST_TIMEOUT, panel_side.recv())
            .await
            .expect("recv after drop timed out")
            .unwrap_err();
        assert!(matches!(closed, LocalIpcError::Closed));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_stale_socket_file_is_replaced_when_no_daemon_listens() {
        let path = unique_socket_path();
        {
            let (_path, _server, _daemon_side, _panel_side) =
                connected_pair(LocalControlServerConfig::new(path.clone())).await;
        }
        // Dropping the daemon left the socket file behind...
        assert!(path.exists());
        // Wait for the OS to finish tearing the listener down: until then a
        // probe can still succeed and the rebind would rightly report the
        // endpoint as taken by a live daemon.
        timeout(TEST_TIMEOUT, async {
            while std::os::unix::net::UnixStream::connect(&path).is_ok() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("listener teardown timed out");
        // ...but a fresh daemon takes the endpoint over and serves a panel.
        let mut server = LocalControlServer::bind(LocalControlServerConfig::new(path.clone()))
            .expect("rebind over stale socket file");
        let panel = timeout(
            TEST_TIMEOUT,
            LocalControlClient::connect(server.path(), TEST_TIMEOUT),
        )
        .await
        .expect("connect after rebind timed out")
        .expect("connect after rebind");
        let daemon_side = timeout(TEST_TIMEOUT, server.accept())
            .await
            .expect("accept after rebind timed out")
            .expect("accept after rebind");
        drop((panel, daemon_side));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_live_daemon_keeps_its_endpoint() {
        let (path, _server, _daemon_side, _panel_side) =
            connected_pair(LocalControlServerConfig::new(unique_socket_path())).await;

        let error = LocalControlServer::bind(LocalControlServerConfig::new(path.clone()))
            .expect_err("a second daemon must not take a live endpoint");
        assert!(matches!(
            error,
            LocalIpcError::Io(ref io) if io.kind() == std::io::ErrorKind::AddrInUse
        ));
        let _ = std::fs::remove_file(&path);
    }
}
