//! Replacement agent owner and read-only control service.
//!
//! Native input is intentionally unavailable at this increment. State is real
//! process-owned lifecycle state, not a UI fixture. This increment supports
//! read-only status. Native input and mutating commands remain unavailable.

use kvm_agent_api::{
    AgentSnapshot, Capabilities, ClientMessage, CommandOutcome, CommandResultReply,
    InputDestination, InstanceId, LifecyclePhase, Prerequisite, ProtocolName, Readiness,
    RejectedOutcome, RejectionReason, Revision, SafetyClear, SafetyState, ServerHello,
    ServerMessage, SnapshotReply, Support, UnknownInput, MAX_PAYLOAD_BYTES, MAX_SUPPORTED_VERSION,
    MIN_SUPPORTED_VERSION,
};
use kvm_agent_model::{Lifecycle, Phase};
use tokio::io::{AsyncRead, AsyncWrite};

pub mod client;

/// No error includes request payloads, account names or endpoint paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    Protocol,
    Transport,
    Deadline,
}

/// One authenticated agent instance. No route/capture mutation is implemented.
#[derive(Debug)]
pub struct Agent {
    instance: InstanceId,
    lifecycle: Lifecycle,
}

impl Default for Agent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent {
    /// Generates a fresh random process-instance identity and starts paused.
    ///
    /// # Panics
    /// Panics if OS randomness is unavailable or UUID generation violates its
    /// non-nil v4 invariant. No native resources have been activated here.
    #[must_use]
    pub fn new() -> Self {
        let uuid = uuid::Uuid::new_v4();
        // Random v4 UUIDs have fixed nonzero version/variant bits.
        let instance = InstanceId::new(uuid).expect("v4 UUID is never nil");
        Self {
            instance,
            lifecycle: Lifecycle::new(uuid.as_u128()),
        }
    }

    #[must_use]
    pub const fn instance(&self) -> InstanceId {
        self.instance
    }

    /// Observes only facts this idle owner knows. Unknown authority remains
    /// unknown; process existence does not establish capture readiness.
    #[must_use]
    pub fn snapshot(&self) -> AgentSnapshot {
        AgentSnapshot {
            instance: self.instance,
            revision: Revision::new(0),
            user_intent: kvm_agent_api::UserIntent::Paused,
            lifecycle: match self.lifecycle.phase() {
                Phase::Paused | Phase::SafetyLatched => LifecyclePhase::Idle,
                Phase::Preparing => LifecyclePhase::Preparing,
                Phase::Sharing => LifecyclePhase::Active,
                Phase::Draining => LifecyclePhase::Draining,
            },
            safety: if self.lifecycle.is_latched() {
                SafetyState::Latched(kvm_agent_api::Latch {
                    cause: kvm_agent_api::SafetyCause::Unspecified,
                })
            } else {
                SafetyState::Clear(SafetyClear {})
            },
            cleanup_unconfirmed: self.lifecycle.cleanup_failed(),
            input_destination: InputDestination::Unknown(UnknownInput {}),
            readiness: Readiness {
                configuration: Prerequisite::Unconfirmed,
                enrollment: Prerequisite::Unconfirmed,
                permissions: Prerequisite::Unconfirmed,
                inventory: Prerequisite::Unconfirmed,
                peer_authentication: Prerequisite::Unconfirmed,
                input_authority: Prerequisite::Unconfirmed,
            },
            capabilities: Capabilities {
                snapshot: Support::Supported,
                pause: Support::Unsupported,
                resume: Support::Unsupported,
                failsafe: Support::Unsupported,
                quit: Support::Unsupported,
            },
        }
    }

    fn reject_mutation(
        &self,
        instance: InstanceId,
        correlation_id: kvm_agent_api::CorrelationId,
        expected_revision: Option<Revision>,
    ) -> ServerMessage {
        let reason = if instance != self.instance {
            RejectionReason::InstanceMismatch
        } else if expected_revision.is_some_and(|revision| revision != Revision::new(0)) {
            RejectionReason::RevisionMismatch
        } else {
            RejectionReason::Unsupported
        };
        ServerMessage::CommandResult(CommandResultReply {
            correlation_id,
            outcome: CommandOutcome::Rejected(RejectedOutcome { reason }),
        })
    }

    fn handle(
        &self,
        request: ClientMessage,
        negotiated: &mut bool,
    ) -> Result<ServerMessage, ServiceError> {
        if let ClientMessage::Hello(hello) = request {
            if *negotiated {
                return Err(ServiceError::Protocol);
            }
            let Ok(version) = kvm_agent_api::negotiate(hello.min_version, hello.max_version) else {
                return Ok(Self::protocol_error(
                    None,
                    kvm_agent_api::ProtocolErrorReason::UnsupportedVersion(
                        kvm_agent_api::UnsupportedVersionRange {
                            server_min: MIN_SUPPORTED_VERSION,
                            server_max: MAX_SUPPORTED_VERSION,
                        },
                    ),
                ));
            };
            *negotiated = true;
            return Ok(ServerMessage::Hello(ServerHello {
                protocol: ProtocolName::standard(),
                min_version: MIN_SUPPORTED_VERSION,
                max_version: MAX_SUPPORTED_VERSION,
                negotiated_version: version,
                instance: self.instance,
                agent_version: kvm_agent_api::AgentVersion::new(env!("CARGO_PKG_VERSION")),
            }));
        }
        if !*negotiated {
            let correlation = match &request {
                ClientMessage::SnapshotRequest(r) => r.correlation_id,
                ClientMessage::Resume(r) => r.correlation_id,
                ClientMessage::Pause(r) | ClientMessage::Failsafe(r) | ClientMessage::Quit(r) => {
                    r.correlation_id
                }
                ClientMessage::Hello(_) => unreachable!(),
            };
            return Ok(Self::protocol_error(
                Some(correlation),
                kvm_agent_api::ProtocolErrorReason::HelloRequired(
                    kvm_agent_api::HelloRequiredReason {},
                ),
            ));
        }
        match request {
            ClientMessage::SnapshotRequest(request) => {
                if request.instance != self.instance {
                    return Ok(Self::protocol_error(
                        Some(request.correlation_id),
                        kvm_agent_api::ProtocolErrorReason::InstanceMismatch(
                            kvm_agent_api::InstanceMismatchReason {},
                        ),
                    ));
                }
                Ok(ServerMessage::Snapshot(SnapshotReply {
                    correlation_id: request.correlation_id,
                    snapshot: self.snapshot(),
                }))
            }
            ClientMessage::Pause(request)
            | ClientMessage::Failsafe(request)
            | ClientMessage::Quit(request) => {
                Ok(self.reject_mutation(request.instance, request.correlation_id, None))
            }
            ClientMessage::Resume(request) => Ok(self.reject_mutation(
                request.instance,
                request.correlation_id,
                Some(request.expected_revision),
            )),
            ClientMessage::Hello(_) => Err(ServiceError::Protocol),
        }
    }

    fn protocol_error(
        correlation_id: Option<kvm_agent_api::CorrelationId>,
        reason: kvm_agent_api::ProtocolErrorReason,
    ) -> ServerMessage {
        ServerMessage::Error(kvm_agent_api::ProtocolError {
            correlation_id,
            reason,
        })
    }

    /// Runs one already user-validated connection, with a finite total lifetime
    /// and request count. Replies remain owned until client EOF or the deadline.
    ///
    /// # Errors
    /// Protocol, framing and timeout failures close the connection at the caller.
    /// Endpoint authorization must precede this call. All mutations are rejected.
    /// Clients must use request/reply lockstep. A repeated Hello or frames beyond
    /// the request limit close without reply; unread pipelined replies may be lost.
    pub async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        lifetime: std::time::Duration,
    ) -> Result<(), ServiceError> {
        if lifetime.is_zero() {
            return Err(ServiceError::Deadline);
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(lifetime)
            .ok_or(ServiceError::Deadline)?;
        // One bounded control-plane buffer per connection, outside the input
        // path. Heap ownership keeps the async state below large-future limits.
        let mut storage = vec![0_u8; MAX_PAYLOAD_BYTES].into_boxed_slice();
        let mut negotiated = false;
        // One hello plus at most seven requests; a chatty client cannot hold the
        // native admission slot forever. Total lifetime also bounds idle clients.
        for _ in 0..8 {
            let payload =
                tokio::time::timeout_at(deadline, kvm_agent_ipc::read_frame(stream, &mut storage))
                    .await
                    .map_err(|_| ServiceError::Deadline)?
                    .map_err(|_| ServiceError::Transport)?;
            let Some(payload) = payload else {
                return Ok(());
            };
            let response = match kvm_agent_api::decode_client(payload) {
                Ok(request) => self.handle(request, &mut negotiated)?,
                Err(kvm_agent_api::DecodeError::WrongProtocol) => Self::protocol_error(
                    None,
                    kvm_agent_api::ProtocolErrorReason::WrongProtocol(
                        kvm_agent_api::WrongProtocolReason {},
                    ),
                ),
                Err(_) => Self::protocol_error(
                    None,
                    kvm_agent_api::ProtocolErrorReason::MalformedRequest(
                        kvm_agent_api::MalformedRequestReason {},
                    ),
                ),
            };
            let bytes =
                kvm_agent_api::encode_server(&response).map_err(|_| ServiceError::Protocol)?;
            tokio::time::timeout_at(
                deadline,
                kvm_agent_ipc::write_frame(stream, &bytes, MAX_PAYLOAD_BYTES),
            )
            .await
            .map_err(|_| ServiceError::Deadline)?
            .map_err(|_| ServiceError::Transport)?;
        }
        // Do not drop a Windows connection immediately after the final write:
        // wait for a client close. Extra frames after the bound are rejected.
        match tokio::time::timeout_at(deadline, kvm_agent_ipc::read_frame(stream, &mut storage))
            .await
        {
            Ok(Ok(None)) => Ok(()),
            Ok(_) => Err(ServiceError::Protocol),
            Err(_) => Err(ServiceError::Deadline),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_agent_api::{CorrelationId, HelloRequest, SnapshotRequest};

    fn hello() -> ClientMessage {
        ClientMessage::Hello(HelloRequest {
            protocol: ProtocolName::standard(),
            min_version: 1,
            max_version: 1,
        })
    }

    #[test]
    fn idle_status_never_fabricates_readiness_or_authority() {
        let snapshot = Agent::new().snapshot();
        assert_eq!(snapshot.lifecycle, LifecyclePhase::Idle);
        assert_eq!(
            snapshot.input_destination,
            InputDestination::Unknown(UnknownInput {})
        );
        assert_eq!(snapshot.capabilities.resume, Support::Unsupported);
        assert_eq!(snapshot.readiness.permissions, Prerequisite::Unconfirmed);
    }

    #[test]
    fn requires_handshake_and_correct_instance() {
        let agent = Agent::new();
        let mut negotiated = false;
        let status = ClientMessage::SnapshotRequest(SnapshotRequest {
            instance: agent.instance(),
            correlation_id: CorrelationId::new(1),
        });
        assert!(matches!(
            agent.handle(status.clone(), &mut negotiated),
            Ok(ServerMessage::Error(kvm_agent_api::ProtocolError {
                reason: kvm_agent_api::ProtocolErrorReason::HelloRequired(_),
                ..
            }))
        ));
        agent.handle(hello(), &mut negotiated).unwrap();
        assert!(matches!(
            agent.handle(status, &mut negotiated),
            Ok(ServerMessage::Snapshot(_))
        ));
        assert_eq!(
            agent.handle(hello(), &mut negotiated),
            Err(ServiceError::Protocol)
        );
        let wrong = ClientMessage::SnapshotRequest(SnapshotRequest {
            instance: Agent::new().instance(),
            correlation_id: CorrelationId::new(2),
        });
        assert!(matches!(
            agent.handle(wrong, &mut negotiated),
            Ok(ServerMessage::Error(kvm_agent_api::ProtocolError {
                reason: kvm_agent_api::ProtocolErrorReason::InstanceMismatch(_),
                ..
            }))
        ));
    }

    #[test]
    fn every_mutation_is_rejected_without_changing_state() {
        let agent = Agent::new();
        let before = agent.snapshot();
        let request = kvm_agent_api::SafetyRequest {
            instance: agent.instance(),
            correlation_id: CorrelationId::new(3),
        };
        for command in [
            ClientMessage::Pause(request.clone()),
            ClientMessage::Resume(kvm_agent_api::ResumeRequest {
                instance: agent.instance(),
                correlation_id: CorrelationId::new(4),
                expected_revision: Revision::new(0),
            }),
            ClientMessage::Failsafe(request.clone()),
            ClientMessage::Quit(request),
        ] {
            let result = agent.handle(command, &mut true).unwrap();
            assert!(matches!(
                result,
                ServerMessage::CommandResult(CommandResultReply {
                    outcome: CommandOutcome::Rejected(RejectedOutcome {
                        reason: RejectionReason::Unsupported
                    }),
                    ..
                })
            ));
            assert_eq!(agent.snapshot(), before);
        }
    }

    #[tokio::test]
    async fn stalled_client_loses_its_connection_budget() {
        let agent = Agent::new();
        let (_client, mut server) = tokio::io::duplex(32);
        assert_eq!(
            agent
                .serve_connection(&mut server, std::time::Duration::from_millis(5))
                .await,
            Err(ServiceError::Deadline)
        );
    }

    #[test]
    fn snapshot_exposes_latch_independently_of_idle_phase() {
        let mut agent = Agent::new();
        let _ = agent.lifecycle.failsafe();
        let snapshot = agent.snapshot();
        assert_eq!(snapshot.lifecycle, LifecyclePhase::Idle);
        assert!(matches!(snapshot.safety, SafetyState::Latched(_)));
        assert_eq!(snapshot.capabilities.resume, Support::Unsupported);
    }

    #[tokio::test]
    async fn serialized_status_connection_completes_on_client_eof() {
        let agent = Agent::new();
        let (mut client, mut server) = tokio::io::duplex(256);
        let serve = agent.serve_connection(&mut server, std::time::Duration::from_secs(1));
        let request = async {
            let bytes = kvm_agent_api::encode_client(&hello()).unwrap();
            kvm_agent_ipc::write_frame(&mut client, &bytes, MAX_PAYLOAD_BYTES)
                .await
                .unwrap();
            let mut storage = vec![0_u8; MAX_PAYLOAD_BYTES];
            let reply = kvm_agent_ipc::read_frame(&mut client, &mut storage)
                .await
                .unwrap()
                .unwrap();
            let ServerMessage::Hello(hello) = kvm_agent_api::decode_server(reply).unwrap() else {
                panic!("expected hello")
            };
            let instance = hello.instance;
            let query = ClientMessage::SnapshotRequest(SnapshotRequest {
                instance,
                correlation_id: CorrelationId::new(u64::MAX),
            });
            let bytes = kvm_agent_api::encode_client(&query).unwrap();
            kvm_agent_ipc::write_frame(&mut client, &bytes, MAX_PAYLOAD_BYTES)
                .await
                .unwrap();
            let reply = kvm_agent_ipc::read_frame(&mut client, &mut storage)
                .await
                .unwrap()
                .unwrap();
            let ServerMessage::Snapshot(snapshot) = kvm_agent_api::decode_server(reply).unwrap()
            else {
                panic!("expected status")
            };
            assert_eq!(snapshot.correlation_id, CorrelationId::new(u64::MAX));
            assert_eq!(snapshot.snapshot.instance, instance);
            assert_eq!(snapshot.snapshot.capabilities.snapshot, Support::Supported);
            assert_eq!(snapshot.snapshot.capabilities.resume, Support::Unsupported);
            drop(client);
        };
        let (result, ()) = tokio::join!(serve, request);
        assert_eq!(result, Ok(()));
    }
}
