//! Daemon-side §31 control service over the local OS transport.
//!
//! This module turns `kvm_network::local_ipc`'s [`LocalControlServer`] into a
//! serving control plane: it answers the §31 read commands from a bounded
//! snapshot view, forwards the few mutating commands to the daemon's owner
//! loop, and fans server-initiated §31 events out to every connected panel.
//!
//! # Design invariants
//!
//! - The daemon's serialized authority is untouched. Read-only commands are
//!   answered from a [`ControlViewSource`] supplied by the embedder (the
//!   runtime refreshes it on its service tick); the mutating commands
//!   ([`ControlCommand`]) travel through a *bounded* mpsc queue that the
//!   owner loop drains on its existing tick. The service itself never takes
//!   a lock on the capture path.
//! - Backpressure is bounded everywhere: a full command queue rejects the
//!   request with the protocol's existing error response, and a lagging
//!   event subscriber misses events instead of delaying the daemon.
//! - No new wire types: unknown or not-yet-implemented commands answer with
//!   [`ControlResponse::Error`] using the closest existing
//!   [`ControlError`] variant (`Internal`), as required by §31's fixed
//!   vocabulary.
//!
//! Spec reference: `.spec/implementation.md` §31 (commands + events); see
//! `docs/audit/2026-08-10-daemon-control-ipc-orphaned.md` for the closure
//! state of each command.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kvm_network::{
    LocalControlClient, LocalControlServer, LocalControlServerConfig, LocalIpcError,
};
use kvm_protocol::{
    ControlDeviceSummary, ControlDisplaySummary, ControlEvent, ControlFrame, ControlPeerStatus,
    ControlRequest, ControlResponse, ControlTopologyEdge, MAX_CONTROL_NAME_BYTES,
    MAX_CONTROL_SNAPSHOT_ITEMS,
};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, watch};

// The §31 wire vocabulary this crate's clients program against. Re-exported
// so local consumers (the control panel, integration harnesses) need only
// depend on the daemon crate, which owns the §31 surface.
pub use kvm_protocol::{ControlError, ControlPeerState, ControlStatus, WireDisplayId, WireHostId};

/// Recommended bound for the embedder's owner-loop command queue. Small on
/// purpose: commands are rare (operator gates and failsafes), and the bound
/// exists so a misbehaving panel cannot pin daemon memory.
pub const CONTROL_COMMAND_QUEUE_CAPACITY: usize = 8;
/// Recommended bound for the §31 event broadcast. A slow panel that falls
/// more than this many events behind loses the overflow (`Lagged`) rather
/// than blocking the emitters.
pub const CONTROL_EVENT_CHANNEL_CAPACITY: usize = 16;
/// Recommended panel-side connect budget: short enough that a missing daemon
/// never stalls a UI poll, long enough to race daemon startup.
pub const CONTROL_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
/// Recommended panel-side response budget: covers the daemon's ~8 ms service
/// tick with generous margin.
pub const CONTROL_CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_millis(750);

// --- Mutating commands --------------------------------------------------------

/// A mutating §31 command forwarded to the daemon's serialized owner loop.
///
/// The service never executes these directly: it enqueues them and answers
/// [`ControlResponse::Acknowledged`]; execution (and its serialized safety
/// checks) belongs to the owner loop that drains the queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlCommand {
    /// Fail open immediately: release logically-held input and stop
    /// suppressing local input (the process failsafe path).
    TriggerFailsafe,
    /// Open the KVM routing gate.
    EnableKvm,
    /// Close the KVM routing gate; input stays local while closed.
    DisableKvm,
}

// --- Read-only view -----------------------------------------------------------

/// Bounded read-only view served to connected panels.
///
/// Built by the embedder from `PeerManager`'s public accessors (snapshot
/// counts, the routing handle, the device-inventory snapshot) plus whatever
/// runtime-owned sections it retains (display inventory, topology edges).
/// The service caps every list and name to the protocol's bounds before
/// responding, so a panel can always decode the reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlServiceView {
    /// Aggregate daemon status (§31 `GetStatus`).
    pub status: ControlStatus,
    /// Paired peers (§31 `GetPeers`). The two-host alpha carries one entry.
    pub peers: Vec<ControlPeerStatus>,
    /// Device inventory (§31 `GetDevices`).
    pub devices: Vec<ControlDeviceSummary>,
    /// Display inventory (§31 `GetDisplays`).
    pub displays: Vec<ControlDisplaySummary>,
    /// Configured topology edges (§31 `GetTopology`).
    pub edges: Vec<ControlTopologyEdge>,
}

impl Default for ControlServiceView {
    /// Empty view: the honest "nothing published yet" state before the
    /// embedder's first refresh.
    fn default() -> Self {
        Self {
            status: ControlStatus {
                active_host: WireHostId::default(),
                active_display: WireDisplayId::default(),
                kvm_enabled: false,
                clipboard_enabled: false,
                protocol_version: 0,
                round_trip_time_ms: None,
                peer_state: ControlPeerState::Disconnected,
            },
            peers: Vec::new(),
            devices: Vec::new(),
            displays: Vec::new(),
            edges: Vec::new(),
        }
    }
}

/// Source of the latest [`ControlServiceView`].
///
/// Implementations must be cheap, must never lock the capture path, and must
/// return an already-bounded view; the service still hard-caps lists and
/// names before encoding a response.
pub trait ControlViewSource: Send + Sync {
    /// Returns the latest read-only view.
    fn control_view(&self) -> ControlServiceView;
}

// --- Errors -------------------------------------------------------------------

/// Failure raised while binding or serving the local control endpoint.
#[derive(Debug, Error)]
pub enum ControlServiceError {
    /// The OS endpoint could not be created (invalid config, or another live
    /// daemon already owns it).
    #[error("local control endpoint bind failed: {0}")]
    Bind(#[from] LocalIpcError),
    /// Accepting a panel connection failed; the listener is no longer usable.
    #[error("local control accept failed: {0}")]
    Accept(LocalIpcError),
}

// --- Service ------------------------------------------------------------------

/// Daemon-side §31 control service: one [`LocalControlServer`] plus the
/// per-connection handlers that answer panel requests.
///
/// The embedder creates the bounded command channel and keeps its receiver
/// (the owner loop); the service clones the sender into every connection.
/// Likewise the embedder keeps the broadcast sender and emits §31 events;
/// the service holds one receiver and resubscribes it per connection.
pub struct ControlService {
    server: LocalControlServer,
    view: Arc<dyn ControlViewSource>,
    commands: mpsc::Sender<ControlCommand>,
    events: broadcast::Receiver<ControlEvent>,
}

impl fmt::Debug for ControlService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlService")
            .field("path", &self.server.path())
            .field("view", &"[SNAPSHOT PROVIDER]")
            .finish_non_exhaustive()
    }
}

impl ControlService {
    /// Binds the daemon-side control endpoint described by `config`.
    ///
    /// `commands` is the bounded owner-loop queue the service forwards
    /// mutating requests into; `events` is a receiver on the embedder's §31
    /// event broadcast.
    ///
    /// # Errors
    ///
    /// Returns [`ControlServiceError::Bind`] when the endpoint cannot be
    /// created — including when another live daemon owns it.
    pub fn bind(
        config: LocalControlServerConfig,
        view: Arc<dyn ControlViewSource>,
        commands: mpsc::Sender<ControlCommand>,
        events: broadcast::Receiver<ControlEvent>,
    ) -> Result<Self, ControlServiceError> {
        Ok(Self {
            server: LocalControlServer::bind(config)?,
            view,
            commands,
            events,
        })
    }

    /// Endpoint path the service is bound to (for clients and diagnostics).
    #[must_use]
    pub fn path(&self) -> &Path {
        self.server.path()
    }

    /// Serves panel connections until `shutdown` is signalled (or its sender
    /// is dropped). Connection-level failures close only that connection;
    /// only a listener failure propagates.
    ///
    /// # Errors
    ///
    /// Returns [`ControlServiceError::Accept`] when the listener itself
    /// fails.
    pub async fn run(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), ControlServiceError> {
        loop {
            let connection = tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                    continue;
                }
                accepted = self.server.accept() => accepted.map_err(ControlServiceError::Accept)?,
            };
            tokio::spawn(serve_connection(
                connection,
                Arc::clone(&self.view),
                self.commands.clone(),
                self.events.resubscribe(),
                shutdown.clone(),
            ));
        }
    }
}

/// Answers frames on one panel connection until the peer goes away, the
/// connection errors, or shutdown is signalled — then shuts the write half so
/// the panel observes closure instead of a hang.
async fn serve_connection(
    mut connection: kvm_network::LocalControlConnection,
    view: Arc<dyn ControlViewSource>,
    commands: mpsc::Sender<ControlCommand>,
    mut events: broadcast::Receiver<ControlEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let frame = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            received = events.recv() => {
                match received {
                    Ok(event) => {
                        if connection
                            .send(ControlFrame::Event(event))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    // Bounded broadcast: a lagging panel misses events.
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    // No emitters remain; park this branch.
                    Err(broadcast::error::RecvError::Closed) => {
                        std::future::pending::<()>().await;
                    }
                }
                continue;
            }
            frame = connection.recv() => match frame {
                Ok(frame) => frame,
                Err(_) => break,
            },
        };
        match frame {
            ControlFrame::Request(request) => {
                let response = respond(&request, view.as_ref(), &commands);
                if connection
                    .send(ControlFrame::Response(response))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            // The daemon is the server: panel-originated responses and events
            // are outside the §31 vocabulary, so the connection is closed.
            ControlFrame::Response(_) | ControlFrame::Event(_) => break,
        }
    }
    let _ = connection.shutdown().await;
}

/// Maps one §31 request to its response. Pure: reads the view, forwards
/// mutating commands, never blocks on the daemon.
fn respond(
    request: &ControlRequest,
    view: &dyn ControlViewSource,
    commands: &mpsc::Sender<ControlCommand>,
) -> ControlResponse {
    match request {
        ControlRequest::GetStatus => ControlResponse::Status(view.control_view().status),
        ControlRequest::GetPeers => {
            let mut peers = view.control_view().peers;
            peers.truncate(MAX_CONTROL_SNAPSHOT_ITEMS);
            for peer in &mut peers {
                bound_name(&mut peer.host_name);
            }
            ControlResponse::Peers { peers }
        }
        ControlRequest::GetDevices => {
            let mut devices = view.control_view().devices;
            devices.truncate(MAX_CONTROL_SNAPSHOT_ITEMS);
            for device in &mut devices {
                bound_name(&mut device.name);
            }
            ControlResponse::Devices { devices }
        }
        ControlRequest::GetDisplays => {
            let mut displays = view.control_view().displays;
            displays.truncate(MAX_CONTROL_SNAPSHOT_ITEMS);
            for display in &mut displays {
                bound_name(&mut display.name);
            }
            ControlResponse::Displays { displays }
        }
        ControlRequest::GetTopology => {
            let mut edges = view.control_view().edges;
            edges.truncate(MAX_CONTROL_SNAPSHOT_ITEMS);
            ControlResponse::Topology { edges }
        }
        ControlRequest::TriggerFailsafe => enqueue(commands, ControlCommand::TriggerFailsafe),
        ControlRequest::EnableKvm => enqueue(commands, ControlCommand::EnableKvm),
        ControlRequest::DisableKvm => enqueue(commands, ControlCommand::DisableKvm),
        // Deferred §31 commands (see the audit doc): no daemon path exists
        // yet, so answer with the protocol's existing error response rather
        // than inventing a wire type. `Internal` is the closest variant.
        ControlRequest::SetDeviceRoute { .. }
        | ControlRequest::SetTopology { .. }
        | ControlRequest::EnableClipboard
        | ControlRequest::DisableClipboard
        | ControlRequest::SetAudioRoute { .. } => ControlResponse::Error {
            error: ControlError::Internal,
        },
    }
}

/// Forwards one mutating command into the bounded owner-loop queue.
fn enqueue(commands: &mpsc::Sender<ControlCommand>, command: ControlCommand) -> ControlResponse {
    match commands.try_send(command) {
        Ok(()) => ControlResponse::Acknowledged,
        // Queue full (or the owner loop is gone): the command was *not*
        // accepted, and the closest existing error kind is `Internal`.
        Err(_) => ControlResponse::Error {
            error: ControlError::Internal,
        },
    }
}

/// Clamps a name to the protocol's byte bound on a char boundary.
fn bound_name(name: &mut String) {
    if name.len() > MAX_CONTROL_NAME_BYTES {
        let mut end = MAX_CONTROL_NAME_BYTES;
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        name.truncate(end);
    }
}

// --- Panel-side poll ----------------------------------------------------------

/// Outcome of one panel-side §31 `GetStatus` poll.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlStatusPoll {
    /// The daemon answered with a status payload.
    Status(ControlStatus),
    /// The daemon answered with a §31 error response.
    Refused(ControlError),
    /// No daemon answered at the endpoint, or it did not reply in time.
    Unreachable,
}

/// Panel-side §31 `GetStatus` poll over the real local transport, with the
/// daemon crate's recommended bounded waits.
///
/// Server-initiated §31 events that arrive between the request and its
/// response are skipped. Never panics and never blocks past
/// `response_timeout`; transport absence maps to
/// [`ControlStatusPoll::Unreachable`] so callers can render a friendly
/// "daemon not running" state instead of an error.
pub async fn poll_control_status(
    path: &Path,
    connect_timeout: Duration,
    response_timeout: Duration,
) -> ControlStatusPoll {
    let Ok(mut connection) = LocalControlClient::connect(path, connect_timeout).await else {
        return ControlStatusPoll::Unreachable;
    };
    if connection
        .send(ControlFrame::Request(ControlRequest::GetStatus))
        .await
        .is_err()
    {
        return ControlStatusPoll::Unreachable;
    }
    let reply = loop {
        let received = match tokio::time::timeout(response_timeout, connection.recv()).await {
            Ok(Ok(ControlFrame::Event(_))) => continue,
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) | Err(_) => return ControlStatusPoll::Unreachable,
        };
        break received;
    };
    match reply {
        ControlFrame::Response(ControlResponse::Status(status)) => {
            ControlStatusPoll::Status(status)
        }
        ControlFrame::Response(ControlResponse::Error { error }) => {
            ControlStatusPoll::Refused(error)
        }
        _ => ControlStatusPoll::Unreachable,
    }
}

/// [`poll_control_status`] against the conventional local endpoint with the
/// recommended bounded waits.
pub async fn poll_default_control_status() -> ControlStatusPoll {
    poll_control_status(
        &kvm_network::default_control_path(),
        CONTROL_CLIENT_CONNECT_TIMEOUT,
        CONTROL_CLIENT_RESPONSE_TIMEOUT,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_network::{LocalControlClient, LocalControlServerConfig};
    use kvm_protocol::{
        ControlDeviceKind, ControlDeviceRoute, ControlPeerState, WireDeviceId, WireDisplayId,
        WireHostId, WirePeerId, MAX_CONTROL_FRAME_BYTES,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    /// Every await in these tests sits inside a `timeout` wrapper so a
    /// service bug fails the suite instead of hanging it (repo history).
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn host(n: u8) -> WireHostId {
        WireHostId([n; 16])
    }
    fn peer(n: u8) -> WirePeerId {
        WirePeerId([n; 16])
    }
    fn device(n: u8) -> WireDeviceId {
        WireDeviceId([n; 16])
    }
    fn display(n: u8) -> WireDisplayId {
        WireDisplayId([n; 16])
    }

    fn sample_view() -> ControlServiceView {
        ControlServiceView {
            status: ControlStatus {
                active_host: host(1),
                active_display: display(2),
                kvm_enabled: true,
                clipboard_enabled: false,
                protocol_version: 3,
                round_trip_time_ms: Some(7),
                peer_state: ControlPeerState::Connected,
            },
            peers: vec![ControlPeerStatus {
                peer_id: peer(3),
                host_id: host(4),
                host_name: "desk-mac".to_owned(),
                state: ControlPeerState::Connected,
            }],
            devices: vec![ControlDeviceSummary {
                device_id: device(5),
                host_id: host(4),
                name: "MX Master".to_owned(),
                kind: ControlDeviceKind::Mouse,
                route: ControlDeviceRoute::FollowActiveHost,
            }],
            displays: vec![ControlDisplaySummary {
                display_id: display(2),
                host_id: host(1),
                name: "Built-in display".to_owned(),
                logical_width: 1512,
                logical_height: 982,
                scale_factor_percent: 200,
                primary: true,
            }],
            edges: vec![ControlTopologyEdge {
                from: display(2),
                side: kvm_protocol::ControlEdgeSide::Right,
                to: display(6),
            }],
        }
    }

    struct FixedView(ControlServiceView);

    impl ControlViewSource for FixedView {
        fn control_view(&self) -> ControlServiceView {
            self.0.clone()
        }
    }

    #[cfg(unix)]
    mod transport {
        use super::*;
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;
        use tokio::time::timeout;

        fn unique_socket_path() -> PathBuf {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
            std::env::temp_dir().join(format!(
                "skvm-control-service-test-{}-{unique}.sock",
                std::process::id()
            ))
        }

        struct Fixture {
            commands: mpsc::Receiver<ControlCommand>,
            events: broadcast::Sender<ControlEvent>,
            shutdown: watch::Sender<bool>,
            run: tokio::task::JoinHandle<Result<(), ControlServiceError>>,
            path: PathBuf,
        }

        /// Binds and spawns a service over the real UDS transport with the
        /// fixed sample view and a command queue of `capacity`.
        fn spawn_service(capacity: usize) -> Fixture {
            let (command_tx, command_rx) = mpsc::channel(capacity);
            let (event_tx, event_rx) = broadcast::channel(CONTROL_EVENT_CHANNEL_CAPACITY);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let service = ControlService::bind(
                LocalControlServerConfig::new(unique_socket_path()),
                Arc::new(FixedView(sample_view())),
                command_tx,
                event_rx,
            )
            .expect("bind control service");
            let path = service.path().to_path_buf();
            let run = tokio::spawn(service.run(shutdown_rx));
            Fixture {
                commands: command_rx,
                events: event_tx,
                shutdown: shutdown_tx,
                run,
                path,
            }
        }

        async fn connect(path: &std::path::Path) -> kvm_network::LocalControlConnection {
            timeout(
                TEST_TIMEOUT,
                LocalControlClient::connect(path, TEST_TIMEOUT),
            )
            .await
            .expect("panel connect timed out")
            .expect("panel connect")
        }

        async fn request(
            connection: &mut kvm_network::LocalControlConnection,
            request: ControlRequest,
        ) -> ControlResponse {
            timeout(
                TEST_TIMEOUT,
                connection.send(ControlFrame::Request(request)),
            )
            .await
            .expect("panel send timed out")
            .expect("panel send");
            let frame = timeout(TEST_TIMEOUT, connection.recv())
                .await
                .expect("panel recv timed out")
                .expect("panel recv");
            match frame {
                ControlFrame::Response(response) => response,
                other => panic!("expected a response frame, got {other:?}"),
            }
        }

        fn clean_up(path: &std::path::Path) {
            let _ = std::fs::remove_file(path);
        }

        #[tokio::test]
        async fn read_commands_answer_from_the_snapshot_view() {
            let fixture = spawn_service(CONTROL_COMMAND_QUEUE_CAPACITY);
            let mut panel = connect(&fixture.path).await;

            let expected = sample_view();
            assert_eq!(
                request(&mut panel, ControlRequest::GetStatus).await,
                ControlResponse::Status(expected.status)
            );
            assert_eq!(
                request(&mut panel, ControlRequest::GetPeers).await,
                ControlResponse::Peers {
                    peers: expected.peers
                }
            );
            assert_eq!(
                request(&mut panel, ControlRequest::GetDevices).await,
                ControlResponse::Devices {
                    devices: expected.devices
                }
            );
            assert_eq!(
                request(&mut panel, ControlRequest::GetDisplays).await,
                ControlResponse::Displays {
                    displays: expected.displays
                }
            );
            assert_eq!(
                request(&mut panel, ControlRequest::GetTopology).await,
                ControlResponse::Topology {
                    edges: expected.edges
                }
            );

            fixture.finish().await;
        }

        #[tokio::test]
        async fn mutating_commands_are_forwarded_and_acknowledged() {
            let mut fixture = spawn_service(CONTROL_COMMAND_QUEUE_CAPACITY);
            let mut panel = connect(&fixture.path).await;

            assert_eq!(
                request(&mut panel, ControlRequest::TriggerFailsafe).await,
                ControlResponse::Acknowledged
            );
            assert_eq!(
                request(&mut panel, ControlRequest::EnableKvm).await,
                ControlResponse::Acknowledged
            );
            assert_eq!(
                request(&mut panel, ControlRequest::DisableKvm).await,
                ControlResponse::Acknowledged
            );

            let forwarded = timeout(TEST_TIMEOUT, async {
                let mut received = Vec::new();
                while received.len() < 3 {
                    received.push(fixture.commands.recv().await.expect("command"));
                }
                received
            })
            .await
            .expect("owner loop drain timed out");
            assert_eq!(
                forwarded,
                vec![
                    ControlCommand::TriggerFailsafe,
                    ControlCommand::EnableKvm,
                    ControlCommand::DisableKvm,
                ]
            );

            fixture.finish().await;
        }

        #[tokio::test]
        async fn deferred_commands_answer_with_the_protocol_error() {
            let fixture = spawn_service(CONTROL_COMMAND_QUEUE_CAPACITY);
            let mut panel = connect(&fixture.path).await;

            for command in [
                ControlRequest::SetDeviceRoute {
                    device: device(9),
                    route: ControlDeviceRoute::Host(host(4)),
                },
                ControlRequest::SetTopology { edges: Vec::new() },
                ControlRequest::EnableClipboard,
                ControlRequest::DisableClipboard,
                ControlRequest::SetAudioRoute {
                    route: kvm_protocol::ControlAudioRoute::MacToWindows,
                },
            ] {
                assert_eq!(
                    request(&mut panel, command).await,
                    ControlResponse::Error {
                        error: ControlError::Internal
                    }
                );
            }

            fixture.finish().await;
        }

        #[tokio::test]
        async fn a_full_command_queue_rejects_instead_of_buffering() {
            let mut fixture = spawn_service(1);
            let mut panel = connect(&fixture.path).await;

            // Fill the bound of one without draining.
            assert_eq!(
                request(&mut panel, ControlRequest::TriggerFailsafe).await,
                ControlResponse::Acknowledged
            );
            assert_eq!(
                request(&mut panel, ControlRequest::TriggerFailsafe).await,
                ControlResponse::Error {
                    error: ControlError::Internal
                }
            );
            // Draining one slot re-opens the queue.
            let drained = timeout(TEST_TIMEOUT, fixture.commands.recv())
                .await
                .expect("owner loop drain timed out");
            assert_eq!(drained, Some(ControlCommand::TriggerFailsafe));
            assert_eq!(
                request(&mut panel, ControlRequest::TriggerFailsafe).await,
                ControlResponse::Acknowledged
            );

            fixture.finish().await;
        }

        #[tokio::test]
        async fn events_are_pushed_to_connected_panels() {
            let fixture = spawn_service(CONTROL_COMMAND_QUEUE_CAPACITY);
            let mut panel = connect(&fixture.path).await;
            // One round trip first so the connection is being served.
            assert_eq!(
                request(&mut panel, ControlRequest::GetStatus).await,
                ControlResponse::Status(sample_view().status)
            );

            fixture
                .events
                .send(ControlEvent::PeerChanged)
                .expect("event broadcast has a live receiver");
            let frame = timeout(TEST_TIMEOUT, panel.recv())
                .await
                .expect("panel event recv timed out")
                .expect("panel event recv");
            assert_eq!(frame, ControlFrame::Event(ControlEvent::PeerChanged));

            fixture.finish().await;
        }

        #[tokio::test]
        async fn an_oversized_frame_closes_that_connection_and_not_the_service() {
            let fixture = spawn_service(CONTROL_COMMAND_QUEUE_CAPACITY);

            // A hostile local writer (not LocalControlClient) advertises a
            // payload above the control frame cap and sends nothing else.
            let mut hostile = timeout(TEST_TIMEOUT, UnixStream::connect(&fixture.path))
                .await
                .expect("hostile connect timed out")
                .expect("hostile connect");
            let advertised = u32::try_from(MAX_CONTROL_FRAME_BYTES + 1).expect("cap fits u32");
            timeout(TEST_TIMEOUT, hostile.write_all(&advertised.to_be_bytes()))
                .await
                .expect("hostile write timed out")
                .expect("hostile write");
            // The service drops the connection; the hostile side observes the
            // closure (or a transport error) instead of a hang.
            timeout(TEST_TIMEOUT, async {
                use tokio::io::AsyncReadExt;
                let mut byte = [0_u8; 1];
                loop {
                    match hostile.read(&mut byte).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            })
            .await
            .expect("hostile close observation timed out");

            // The service itself keeps serving a well-behaved panel.
            let mut panel = connect(&fixture.path).await;
            assert_eq!(
                request(&mut panel, ControlRequest::GetStatus).await,
                ControlResponse::Status(sample_view().status)
            );

            fixture.finish().await;
        }

        #[tokio::test]
        async fn a_panel_originated_response_frame_closes_the_connection() {
            let fixture = spawn_service(CONTROL_COMMAND_QUEUE_CAPACITY);
            let mut panel = connect(&fixture.path).await;
            timeout(
                TEST_TIMEOUT,
                panel.send(ControlFrame::Response(ControlResponse::Acknowledged)),
            )
            .await
            .expect("panel send timed out")
            .expect("panel send");
            let error = timeout(TEST_TIMEOUT, panel.recv())
                .await
                .expect("panel recv timed out")
                .unwrap_err();
            assert!(matches!(error, kvm_network::LocalIpcError::Closed));

            fixture.finish().await;
        }

        #[tokio::test]
        async fn shutdown_stops_the_service_and_closes_panels_cleanly() {
            let fixture = spawn_service(CONTROL_COMMAND_QUEUE_CAPACITY);
            let mut panel = connect(&fixture.path).await;
            assert_eq!(
                request(&mut panel, ControlRequest::GetStatus).await,
                ControlResponse::Status(sample_view().status)
            );

            let Fixture {
                commands: _commands,
                events: _events,
                shutdown,
                mut run,
                path,
            } = fixture;
            shutdown.send(true).expect("signal shutdown");
            let joined = timeout(TEST_TIMEOUT, &mut run)
                .await
                .expect("service run timed out");
            assert!(joined.is_ok_and(|result| result.is_ok()));
            let closed = timeout(TEST_TIMEOUT, panel.recv())
                .await
                .expect("panel recv timed out")
                .unwrap_err();
            assert!(matches!(closed, kvm_network::LocalIpcError::Closed));
            clean_up(&path);
        }

        #[tokio::test]
        async fn panel_poll_reads_status_and_maps_absence_to_unreachable() {
            let fixture = spawn_service(CONTROL_COMMAND_QUEUE_CAPACITY);
            let expected = sample_view().status;
            let polled = timeout(
                TEST_TIMEOUT,
                poll_control_status(&fixture.path, TEST_TIMEOUT, TEST_TIMEOUT),
            )
            .await
            .expect("poll timed out");
            assert_eq!(polled, ControlStatusPoll::Status(expected));

            // A path with no daemon behind it is unreachable, not an error.
            let vacant = unique_socket_path();
            let polled = timeout(
                CONTROL_CLIENT_CONNECT_TIMEOUT + TEST_TIMEOUT,
                poll_control_status(&vacant, Duration::from_millis(20), TEST_TIMEOUT),
            )
            .await
            .expect("vacant poll timed out");
            assert_eq!(polled, ControlStatusPoll::Unreachable);
            drop(vacant);

            fixture.finish().await;
        }

        impl Fixture {
            /// Signals shutdown, awaits a clean service exit, and removes the
            /// endpoint file.
            async fn finish(self) {
                let Fixture {
                    commands: _commands,
                    events: _events,
                    shutdown,
                    run,
                    path,
                } = self;
                let _ = shutdown.send(true);
                let outcome = timeout(TEST_TIMEOUT, run).await;
                let clean = outcome
                    .as_ref()
                    .is_ok_and(|joined| joined.as_ref().is_ok_and(Result::is_ok));
                assert!(clean, "service must shut down cleanly, got {outcome:?}");
                clean_up(&path);
            }
        }
    }

    // --- Pure bounds tests (host-neutral) ------------------------------------

    #[test]
    fn responses_cap_lists_and_names_to_the_protocol_bounds() {
        // Cheap per-entry ids: the range covers the full u8 cycle once (the
        // wraparound duplicate is irrelevant to the capping under test).
        fn id(n: usize) -> u8 {
            u8::try_from(n % 256).expect("test index fits u8")
        }
        let oversized_view = ControlServiceView {
            peers: (0..=MAX_CONTROL_SNAPSHOT_ITEMS)
                .map(|n| ControlPeerStatus {
                    peer_id: peer(id(n)),
                    host_id: host(id(n)),
                    host_name: "x".repeat(MAX_CONTROL_NAME_BYTES + 40),
                    state: ControlPeerState::Connected,
                })
                .collect(),
            devices: (0..=MAX_CONTROL_SNAPSHOT_ITEMS)
                .map(|n| ControlDeviceSummary {
                    device_id: device(id(n)),
                    host_id: host(id(n)),
                    name: "y".repeat(MAX_CONTROL_NAME_BYTES + 10),
                    kind: ControlDeviceKind::Keyboard,
                    route: ControlDeviceRoute::Local,
                })
                .collect(),
            displays: (0..=MAX_CONTROL_SNAPSHOT_ITEMS)
                .map(|n| ControlDisplaySummary {
                    display_id: display(id(n)),
                    host_id: host(id(n)),
                    name: "z".repeat(MAX_CONTROL_NAME_BYTES + 10),
                    logical_width: 1,
                    logical_height: 1,
                    scale_factor_percent: 100,
                    primary: false,
                })
                .collect(),
            edges: (0..=MAX_CONTROL_SNAPSHOT_ITEMS)
                .map(|n| ControlTopologyEdge {
                    from: display(id(n)),
                    side: kvm_protocol::ControlEdgeSide::Left,
                    to: display(id(n)),
                })
                .collect(),
            ..sample_view()
        };
        let (commands_tx, _commands_rx) = mpsc::channel(1);
        let view = FixedView(oversized_view);

        let ControlResponse::Peers { peers } =
            respond(&ControlRequest::GetPeers, &view, &commands_tx)
        else {
            panic!("GetPeers must answer with a peers response");
        };
        assert_eq!(peers.len(), MAX_CONTROL_SNAPSHOT_ITEMS);
        assert!(peers
            .iter()
            .all(|p| p.host_name.len() <= MAX_CONTROL_NAME_BYTES));

        let ControlResponse::Devices { devices } =
            respond(&ControlRequest::GetDevices, &view, &commands_tx)
        else {
            panic!("GetDevices must answer with a devices response");
        };
        assert_eq!(devices.len(), MAX_CONTROL_SNAPSHOT_ITEMS);
        assert!(devices
            .iter()
            .all(|d| d.name.len() <= MAX_CONTROL_NAME_BYTES));

        let ControlResponse::Displays { displays } =
            respond(&ControlRequest::GetDisplays, &view, &commands_tx)
        else {
            panic!("GetDisplays must answer with a displays response");
        };
        assert_eq!(displays.len(), MAX_CONTROL_SNAPSHOT_ITEMS);
        assert!(displays
            .iter()
            .all(|d| d.name.len() <= MAX_CONTROL_NAME_BYTES));

        let ControlResponse::Topology { edges } =
            respond(&ControlRequest::GetTopology, &view, &commands_tx)
        else {
            panic!("GetTopology must answer with a topology response");
        };
        assert_eq!(edges.len(), MAX_CONTROL_SNAPSHOT_ITEMS);

        // The capped payloads must decode through the real codec validation.
        for response in [
            ControlResponse::Peers { peers },
            ControlResponse::Devices { devices },
            ControlResponse::Displays { displays },
            ControlResponse::Topology { edges },
        ] {
            let bytes =
                kvm_protocol::encode_control(&ControlFrame::Response(response)).expect("encode");
            assert!(kvm_protocol::decode_control(&bytes).is_ok());
        }
    }

    #[test]
    fn bound_name_truncates_on_a_char_boundary() {
        let mut ascii = "a".repeat(MAX_CONTROL_NAME_BYTES + 3);
        bound_name(&mut ascii);
        assert_eq!(ascii.len(), MAX_CONTROL_NAME_BYTES);

        // A multi-byte char straddling the bound must not split a char.
        let mut unicode = "é".repeat(MAX_CONTROL_NAME_BYTES);
        bound_name(&mut unicode);
        assert!(unicode.len() <= MAX_CONTROL_NAME_BYTES);
        assert!(unicode.chars().all(|c| c == 'é'));

        let mut short = "short".to_owned();
        bound_name(&mut short);
        assert_eq!(short, "short");
    }
}
