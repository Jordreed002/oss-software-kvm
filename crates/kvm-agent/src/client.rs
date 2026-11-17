//! Bounded read-only client. Native peer verification precedes every API byte.

use std::{io, time::Duration};

use kvm_agent_api::{
    AgentSnapshot, ClientMessage, CorrelationId, HelloRequest, ProtocolName, ServerMessage,
    SnapshotRequest, MAX_PAYLOAD_BYTES, MAX_SUPPORTED_VERSION, MIN_SUPPORTED_VERSION,
};
use tokio::io::{AsyncRead, AsyncWrite};

const QUERY_BUDGET: Duration = Duration::from_secs(2);
const CONNECT_BUDGET: Duration = Duration::from_millis(500);

/// Payload-free categories for the utility UI. No endpoint path or account ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusError {
    NotFound,
    PermissionDenied,
    TimedOut,
    Incompatible,
    InvalidReply,
    Transport,
}

impl From<io::Error> for StatusError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::TimedOut => Self::TimedOut,
            _ => Self::Transport,
        }
    }
}

impl From<kvm_agent_ipc::FrameError> for StatusError {
    fn from(error: kvm_agent_ipc::FrameError) -> Self {
        match error {
            kvm_agent_ipc::FrameError::Io(error) => Self::from(error),
            kvm_agent_ipc::FrameError::InvalidLength => Self::InvalidReply,
        }
    }
}

/// Shared development endpoint location. The Unix endpoint validates ownership,
/// modes, canonical ancestors and native peer UID before sending any data.
#[cfg(unix)]
#[must_use]
pub fn runtime_directory() -> std::path::PathBuf {
    std::env::temp_dir().join("software-kvm-agent")
}

/// Connects to the native endpoint and obtains one instance-bound snapshot.
///
/// # Errors
/// Returns separate unavailable, untrusted, timeout, incompatible and malformed
/// reply categories. A failed read never becomes a confirmed idle snapshot.
pub async fn query_native() -> Result<AgentSnapshot, StatusError> {
    tokio::time::timeout(QUERY_BUDGET, async {
        #[cfg(windows)]
        let mut stream = kvm_agent_ipc::windows::connect("control", CONNECT_BUDGET).await?;
        #[cfg(unix)]
        let mut stream = kvm_agent_ipc::unix::connect(&runtime_directory(), CONNECT_BUDGET).await?;
        query_connection(&mut stream).await
    })
    .await
    .map_err(|_| StatusError::TimedOut)?
}

async fn send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &ClientMessage,
) -> Result<(), StatusError> {
    let bytes = kvm_agent_api::encode_client(request).map_err(|_| StatusError::InvalidReply)?;
    kvm_agent_ipc::write_frame(stream, &bytes, MAX_PAYLOAD_BYTES).await?;
    Ok(())
}

async fn receive<S: AsyncRead + Unpin>(
    stream: &mut S,
    storage: &mut [u8],
) -> Result<ServerMessage, StatusError> {
    let payload = kvm_agent_ipc::read_frame(stream, storage)
        .await?
        .ok_or(StatusError::InvalidReply)?;
    kvm_agent_api::decode_server(payload).map_err(|error| match error {
        kvm_agent_api::DecodeError::WrongProtocol | kvm_agent_api::DecodeError::Version(_) => {
            StatusError::Incompatible
        }
        _ => StatusError::InvalidReply,
    })
}

/// Runs only after the caller has authenticated the native endpoint. The caller
/// owns the total deadline and drops the stream after consuming the snapshot,
/// allowing the Windows server's response-delivery fence to finish.
async fn query_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<AgentSnapshot, StatusError> {
    let mut storage = vec![0; MAX_PAYLOAD_BYTES];
    send(
        stream,
        &ClientMessage::Hello(HelloRequest {
            protocol: ProtocolName::standard(),
            min_version: MIN_SUPPORTED_VERSION,
            max_version: MAX_SUPPORTED_VERSION,
        }),
    )
    .await?;
    let ServerMessage::Hello(hello) = receive(stream, &mut storage).await? else {
        return Err(StatusError::Incompatible);
    };
    kvm_agent_api::accept_server_hello(MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION, &hello)
        .map_err(|_| StatusError::Incompatible)?;
    let correlation = CorrelationId::new(1);
    send(
        stream,
        &ClientMessage::SnapshotRequest(SnapshotRequest {
            instance: hello.instance,
            correlation_id: correlation,
        }),
    )
    .await?;
    let ServerMessage::Snapshot(reply) = receive(stream, &mut storage).await? else {
        return Err(StatusError::InvalidReply);
    };
    if reply.correlation_id != correlation || reply.snapshot.instance != hello.instance {
        return Err(StatusError::InvalidReply);
    }
    Ok(reply.snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Agent;

    async fn exchange(
        corrupt_instance: bool,
        corrupt_correlation: bool,
    ) -> Result<AgentSnapshot, StatusError> {
        let agent = Agent::new();
        let (mut client, mut server) = tokio::io::duplex(256);
        let serve = async {
            let mut storage = vec![0; MAX_PAYLOAD_BYTES];
            let mut negotiated = false;
            for _ in 0..2 {
                let bytes = kvm_agent_ipc::read_frame(&mut server, &mut storage)
                    .await
                    .unwrap()
                    .unwrap();
                let request = kvm_agent_api::decode_client(bytes).unwrap();
                let mut response = agent.handle(request, &mut negotiated).unwrap();
                if let ServerMessage::Snapshot(ref mut reply) = response {
                    if corrupt_instance {
                        reply.snapshot.instance = Agent::new().instance();
                    }
                    if corrupt_correlation {
                        reply.correlation_id = CorrelationId::new(2);
                    }
                }
                let bytes = kvm_agent_api::encode_server(&response).unwrap();
                kvm_agent_ipc::write_frame(&mut server, &bytes, MAX_PAYLOAD_BYTES)
                    .await
                    .unwrap();
            }
        };
        let (result, ()) = tokio::time::timeout(QUERY_BUDGET, async {
            tokio::join!(query_connection(&mut client), serve)
        })
        .await
        .unwrap();
        result
    }

    #[tokio::test]
    async fn bootstraps_instance_from_hello_without_out_of_band_identity() {
        let snapshot = exchange(false, false).await.unwrap();
        assert_eq!(
            snapshot.capabilities.snapshot,
            kvm_agent_api::Support::Supported
        );
        assert_eq!(
            snapshot.capabilities.resume,
            kvm_agent_api::Support::Unsupported
        );
    }

    #[tokio::test]
    async fn rejects_snapshot_from_different_instance() {
        assert_eq!(exchange(true, false).await, Err(StatusError::InvalidReply));
    }

    #[tokio::test]
    async fn rejects_reply_for_a_different_request() {
        assert_eq!(exchange(false, true).await, Err(StatusError::InvalidReply));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn status_roundtrip_uses_verified_native_pipe() {
        let channel = format!("status-test-{}", uuid::Uuid::new_v4().simple());
        let mut listener = kvm_agent_ipc::windows::UserPipe::bind(&channel).unwrap();
        let agent = Agent::new();
        let expected = agent.instance();
        let server = async {
            let mut connection = listener.accept().await.unwrap();
            agent
                .serve_connection(connection.stream(), QUERY_BUDGET)
                .await
                .unwrap();
        };
        let client = async {
            let mut stream = kvm_agent_ipc::windows::connect(&channel, QUERY_BUDGET)
                .await
                .unwrap();
            let snapshot = query_connection(&mut stream).await.unwrap();
            assert_eq!(snapshot.instance, expected);
            assert_eq!(
                snapshot.input_destination,
                kvm_agent_api::InputDestination::Unknown(kvm_agent_api::UnknownInput {})
            );
            drop(stream);
        };
        tokio::time::timeout(QUERY_BUDGET, async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn status_roundtrip_uses_verified_native_socket() {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let directory = std::env::temp_dir().join(format!("kvm-{}", &unique[..16]));
        let listener = kvm_agent_ipc::unix::UserSocket::bind(&directory)
            .await
            .unwrap();
        let agent = Agent::new();
        let expected = agent.instance();
        let server = async {
            let mut connection = listener.accept().await.unwrap();
            agent
                .serve_connection(connection.stream(), QUERY_BUDGET)
                .await
                .unwrap();
        };
        let client = async {
            let mut stream = kvm_agent_ipc::unix::connect(&directory, QUERY_BUDGET)
                .await
                .unwrap();
            let snapshot = query_connection(&mut stream).await.unwrap();
            assert_eq!(snapshot.instance, expected);
            drop(stream);
        };
        tokio::time::timeout(QUERY_BUDGET, async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
        drop(listener);
        std::fs::remove_file(directory.join("agent.lock")).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
