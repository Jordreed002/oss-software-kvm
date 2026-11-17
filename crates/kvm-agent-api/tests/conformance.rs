//! Software contract tests against the fixture corpus: canonical roundtrips,
//! exact serialized outcomes, and rejection of every documented malformation.
//!
//! These tests exercise serialization only — no transport, authentication or
//! native acceptance. The manifest-driven test reads `fixtures/manifest.json`
//! and every fixture file at runtime, the same way a TypeScript conformance
//! harness would.

use std::{fs, path::Path};

use kvm_agent_api::fixtures;
use kvm_agent_api::message::{
    AcceptedOutcome, AgentSnapshot, Capabilities, ClientMessage, CommandOutcome,
    CommandResultReply, HelloRequest, HelloRequiredReason, InputDestination,
    InstanceMismatchReason, Latch, LifecyclePhase, MalformedRequestReason, Prerequisite,
    ProtocolError, ProtocolErrorReason, Readiness, RejectedOutcome, RejectionReason, RemoteTarget,
    ResumeRequest, SafetyCause, SafetyClear, SafetyRequest, SafetyState, ServerHello,
    ServerMessage, SnapshotReply, SnapshotRequest, Support, TransitioningInput, UnknownInput,
    UnsupportedReason, UnsupportedVersionRange, UserIntent, WrongProtocolReason,
};
use kvm_agent_api::{
    accept_server_hello, AgentVersion, AppliedOutcome, CorrelationId, DecodeError, EncodeError,
    Field, Generation, HostLabel, InstanceId, Malformation, ProtocolName, Revision, SessionId,
    VersionError, MAX_AGENT_VERSION_BYTES, MAX_HOST_LABEL_BYTES, MAX_PAYLOAD_BYTES,
    MAX_PROTOCOL_NAME_BYTES, MAX_SUPPORTED_VERSION, MIN_SUPPORTED_VERSION,
};
use uuid::Uuid;

const INSTANCE: Uuid = Uuid::from_u128(0x9d2c8a40_1f6b_4c3e_a3b5_7e8f9a0b1c2d);

fn unconfirmed_readiness() -> Readiness {
    Readiness {
        configuration: Prerequisite::Unconfirmed,
        enrollment: Prerequisite::Unconfirmed,
        permissions: Prerequisite::Unconfirmed,
        inventory: Prerequisite::Unconfirmed,
        peer_authentication: Prerequisite::Unconfirmed,
        input_authority: Prerequisite::Unconfirmed,
    }
}

fn confirmed_readiness(input_authority: Prerequisite) -> Readiness {
    Readiness {
        configuration: Prerequisite::Confirmed,
        enrollment: Prerequisite::Confirmed,
        permissions: Prerequisite::Confirmed,
        inventory: Prerequisite::Confirmed,
        peer_authentication: Prerequisite::Confirmed,
        input_authority,
    }
}

fn capabilities(all: Support) -> Capabilities {
    Capabilities {
        pause: all,
        resume: all,
        failsafe: all,
        quit: all,
        snapshot: all,
    }
}

fn server_hello(negotiated_version: u32) -> ServerHello {
    ServerHello {
        protocol: ProtocolName::standard(),
        min_version: MIN_SUPPORTED_VERSION,
        max_version: 1,
        negotiated_version,
        instance: InstanceId::new(INSTANCE).expect("non-nil instance"),
        agent_version: AgentVersion::new("0.1.0"),
    }
}

fn idle_snapshot() -> AgentSnapshot {
    AgentSnapshot {
        instance: InstanceId::new(INSTANCE).expect("non-nil instance"),
        revision: Revision::new(1),
        lifecycle: LifecyclePhase::Idle,
        user_intent: UserIntent::Paused,
        safety: SafetyState::Clear(SafetyClear {}),
        cleanup_unconfirmed: false,
        input_destination: InputDestination::Unknown(UnknownInput {}),
        readiness: unconfirmed_readiness(),
        capabilities: Capabilities {
            pause: Support::Unsupported,
            resume: Support::Unsupported,
            failsafe: Support::Unsupported,
            quit: Support::Unsupported,
            snapshot: Support::Supported,
        },
    }
}

fn assert_client_roundtrip(message: &ClientMessage, fixture: &str) {
    let encoded = kvm_agent_api::encode_client(message).unwrap();
    assert_eq!(encoded.as_slice(), fixture.as_bytes(), "canonical bytes");
    assert_eq!(&kvm_agent_api::decode_client(&encoded).unwrap(), message);
}

fn assert_server_roundtrip(message: &ServerMessage, fixture: &str) {
    let encoded = kvm_agent_api::encode_server(message).unwrap();
    assert_eq!(encoded.as_slice(), fixture.as_bytes(), "canonical bytes");
    assert_eq!(&kvm_agent_api::decode_server(&encoded).unwrap(), message);
}

#[test]
fn hello_fixture_is_canonical_and_roundtrips() {
    assert_client_roundtrip(
        &ClientMessage::Hello(HelloRequest {
            protocol: ProtocolName::standard(),
            min_version: 1,
            max_version: 1,
        }),
        fixtures::VALID_CLIENT_HELLO,
    );
}

#[test]
fn future_range_hello_parses_but_negotiation_rejects() {
    // Schema validity and negotiability are separate decisions: a Hello
    // advertising 2..=3 is well formed and must parse, then negotiation
    // rejects it because this codec speaks only version 1.
    let message =
        kvm_agent_api::decode_client(fixtures::VALID_CLIENT_HELLO_FUTURE_RANGE.as_bytes())
            .expect("future range is valid schema input");
    assert_eq!(
        message,
        ClientMessage::Hello(HelloRequest {
            protocol: ProtocolName::standard(),
            min_version: 2,
            max_version: 3,
        })
    );
    assert_eq!(
        kvm_agent_api::negotiate(2, 3),
        Err(VersionError::NoOverlap {
            client_min: 2,
            client_max: 3,
            server_min: MIN_SUPPORTED_VERSION,
            server_max: MAX_SUPPORTED_VERSION,
        })
    );
}

#[test]
fn snapshot_request_fixture_roundtrips() {
    assert_client_roundtrip(
        &ClientMessage::SnapshotRequest(SnapshotRequest {
            instance: InstanceId::new(INSTANCE).unwrap(),
            correlation_id: CorrelationId::new(42),
        }),
        fixtures::VALID_CLIENT_SNAPSHOT_REQUEST,
    );
}

#[test]
fn escaped_decimal_digits_decode_to_canonical_values() {
    assert!(fixtures::VALID_CLIENT_SNAPSHOT_REQUEST_ESCAPED.contains(r"\u0032"));
    assert_ne!(
        fixtures::VALID_CLIENT_SNAPSHOT_REQUEST_ESCAPED,
        fixtures::VALID_CLIENT_SNAPSHOT_REQUEST
    );
    // Canonicality applies to the decoded string, so a JSON-escaped digit is
    // accepted and re-encodes to the plain canonical bytes.
    let message =
        kvm_agent_api::decode_client(fixtures::VALID_CLIENT_SNAPSHOT_REQUEST_ESCAPED.as_bytes())
            .expect("escaped spelling decodes to a canonical value");
    assert_eq!(
        message,
        ClientMessage::SnapshotRequest(SnapshotRequest {
            instance: InstanceId::new(INSTANCE).unwrap(),
            correlation_id: CorrelationId::new(42),
        })
    );
    assert_eq!(
        kvm_agent_api::encode_client(&message).unwrap(),
        fixtures::VALID_CLIENT_SNAPSHOT_REQUEST.as_bytes()
    );
}

#[test]
fn u64_maximum_roundtrips_through_canonical_decimal_string() {
    // Pause is a safety command: instance and correlation only, no revision
    // precondition on the wire.
    assert_client_roundtrip(
        &ClientMessage::Pause(SafetyRequest {
            instance: InstanceId::new(INSTANCE).unwrap(),
            correlation_id: CorrelationId::new(u64::MAX),
        }),
        fixtures::VALID_CLIENT_PAUSE_U64MAX,
    );
}

#[test]
fn resume_fixture_roundtrips_with_its_revision_precondition() {
    assert_client_roundtrip(
        &ClientMessage::Resume(ResumeRequest {
            instance: InstanceId::new(INSTANCE).unwrap(),
            correlation_id: CorrelationId::new(42),
            expected_revision: Revision::new(7),
        }),
        fixtures::VALID_CLIENT_RESUME_REVISION,
    );
}

#[test]
fn server_hello_fixture_roundtrips() {
    assert_server_roundtrip(
        &ServerMessage::Hello(server_hello(1)),
        fixtures::VALID_SERVER_HELLO,
    );
}

#[test]
fn server_hello_bootstraps_the_first_instance_bound_request() {
    // The server Hello returns the agent instance identity; only with that
    // identity can a client form its first instance-bound request, and a
    // client that offered a range must verify the chosen version against it.
    let ServerMessage::Hello(hello) =
        kvm_agent_api::decode_server(fixtures::VALID_SERVER_HELLO.as_bytes())
            .expect("server Hello decodes")
    else {
        panic!("fixture must decode as a Hello");
    };
    assert_eq!(hello.instance, InstanceId::new(INSTANCE).unwrap());
    assert_eq!(accept_server_hello(1, 1, &hello), Ok(1));

    // The same chosen version lies outside what a 2..=3 client offered.
    assert_eq!(
        accept_server_hello(2, 3, &hello),
        Err(VersionError::NegotiatedOutsideAdvertised {
            negotiated: 1,
            min: 2,
            max: 3
        })
    );

    let request = ClientMessage::SnapshotRequest(SnapshotRequest {
        instance: hello.instance,
        correlation_id: CorrelationId::new(42),
    });
    assert_client_roundtrip(&request, fixtures::VALID_CLIENT_SNAPSHOT_REQUEST);
}

#[test]
fn idle_stub_snapshot_reports_no_fabricated_capability_or_authority() {
    let message = ServerMessage::Snapshot(SnapshotReply {
        correlation_id: CorrelationId::new(42),
        snapshot: idle_snapshot(),
    });
    assert_eq!(
        kvm_agent_api::decode_server(fixtures::VALID_SERVER_SNAPSHOT_IDLE.as_bytes()).unwrap(),
        message
    );
    assert_server_roundtrip(&message, fixtures::VALID_SERVER_SNAPSHOT_IDLE);
}

#[test]
fn latched_draining_snapshot_never_confirms_remote_authority() {
    // The latched fixture pairs its latch with draining, unconfirmed cleanup
    // and a transitioning destination; confirmed remote authority cannot
    // coexist with an unconfirmed cleanup outcome.
    let message = ServerMessage::Snapshot(SnapshotReply {
        correlation_id: CorrelationId::new(9),
        snapshot: AgentSnapshot {
            instance: InstanceId::new(INSTANCE).unwrap(),
            revision: Revision::new(5),
            lifecycle: LifecyclePhase::Draining,
            user_intent: UserIntent::SharingRequested,
            safety: SafetyState::Latched(Latch {
                cause: SafetyCause::PeerLinkFailure,
            }),
            cleanup_unconfirmed: true,
            input_destination: InputDestination::Transitioning(TransitioningInput {}),
            readiness: confirmed_readiness(Prerequisite::Unconfirmed),
            capabilities: capabilities(Support::Supported),
        },
    });
    assert_eq!(
        kvm_agent_api::decode_server(fixtures::VALID_SERVER_SNAPSHOT_DRAINING_LATCHED.as_bytes())
            .unwrap(),
        message
    );
    assert_server_roundtrip(&message, fixtures::VALID_SERVER_SNAPSHOT_DRAINING_LATCHED);
}

#[test]
fn active_remote_snapshot_confirms_authority_only_with_clear_safety() {
    // The honest counterpart: a confirmed remote destination appears only
    // with clear safety, confirmed cleanup and every prerequisite confirmed.
    let message = ServerMessage::Snapshot(SnapshotReply {
        correlation_id: CorrelationId::new(11),
        snapshot: AgentSnapshot {
            instance: InstanceId::new(INSTANCE).unwrap(),
            revision: Revision::new(8),
            lifecycle: LifecyclePhase::Active,
            user_intent: UserIntent::SharingRequested,
            safety: SafetyState::Clear(SafetyClear {}),
            cleanup_unconfirmed: false,
            input_destination: InputDestination::Remote(RemoteTarget {
                host: HostLabel::new("desk-b.internal"),
                session: SessionId::new(3),
                generation: Generation::new(2),
            }),
            readiness: confirmed_readiness(Prerequisite::Confirmed),
            capabilities: capabilities(Support::Supported),
        },
    });
    assert_eq!(
        kvm_agent_api::decode_server(fixtures::VALID_SERVER_SNAPSHOT_ACTIVE_REMOTE.as_bytes())
            .unwrap(),
        message
    );
    assert_server_roundtrip(&message, fixtures::VALID_SERVER_SNAPSHOT_ACTIVE_REMOTE);
}

#[test]
fn accepted_and_applied_are_exact_and_distinct_outcomes() {
    let accepted = ServerMessage::CommandResult(CommandResultReply {
        correlation_id: CorrelationId::new(u64::MAX),
        outcome: CommandOutcome::Accepted(AcceptedOutcome {}),
    });
    assert_eq!(
        kvm_agent_api::encode_server(&accepted).unwrap(),
        fixtures::VALID_SERVER_RESULT_ACCEPTED.as_bytes()
    );

    // 2^53 + 1 exceeds JavaScript's exact integer range but survives as a
    // canonical decimal string; the resulting revision is u64::MAX.
    let applied = ServerMessage::CommandResult(CommandResultReply {
        correlation_id: CorrelationId::new(9_007_199_254_740_993),
        outcome: CommandOutcome::Applied(AppliedOutcome {
            revision: Revision::new(u64::MAX),
        }),
    });
    assert_eq!(
        kvm_agent_api::encode_server(&applied).unwrap(),
        fixtures::VALID_SERVER_RESULT_APPLIED_U64MAX.as_bytes()
    );
    assert_ne!(
        kvm_agent_api::encode_server(&accepted).unwrap(),
        kvm_agent_api::encode_server(&applied).unwrap()
    );

    let rejected = ServerMessage::CommandResult(CommandResultReply {
        correlation_id: CorrelationId::new(7),
        outcome: CommandOutcome::Rejected(RejectedOutcome {
            reason: RejectionReason::RevisionMismatch,
        }),
    });
    assert_eq!(
        kvm_agent_api::encode_server(&rejected).unwrap(),
        fixtures::VALID_SERVER_RESULT_REJECTED.as_bytes()
    );
}

#[test]
fn protocol_errors_use_closed_reasons_with_optional_correlation() {
    // Hello-time failures and undecodable input carry no correlation id;
    // errors that answer a decoded request carry its correlation id. No
    // reason echoes client text.
    let cases = [
        (
            fixtures::VALID_SERVER_ERROR_UNSUPPORTED_VERSION,
            ServerMessage::Error(ProtocolError {
                correlation_id: None,
                reason: ProtocolErrorReason::UnsupportedVersion(UnsupportedVersionRange {
                    server_min: 1,
                    server_max: 1,
                }),
            }),
        ),
        (
            fixtures::VALID_SERVER_ERROR_WRONG_PROTOCOL,
            ServerMessage::Error(ProtocolError {
                correlation_id: None,
                reason: ProtocolErrorReason::WrongProtocol(WrongProtocolReason {}),
            }),
        ),
        (
            fixtures::VALID_SERVER_ERROR_MALFORMED_REQUEST,
            ServerMessage::Error(ProtocolError {
                correlation_id: None,
                reason: ProtocolErrorReason::MalformedRequest(MalformedRequestReason {}),
            }),
        ),
        (
            fixtures::VALID_SERVER_ERROR_HELLO_REQUIRED,
            ServerMessage::Error(ProtocolError {
                correlation_id: Some(CorrelationId::new(7)),
                reason: ProtocolErrorReason::HelloRequired(HelloRequiredReason {}),
            }),
        ),
        (
            fixtures::VALID_SERVER_ERROR_INSTANCE_MISMATCH,
            ServerMessage::Error(ProtocolError {
                correlation_id: Some(CorrelationId::new(7)),
                reason: ProtocolErrorReason::InstanceMismatch(InstanceMismatchReason {}),
            }),
        ),
        (
            fixtures::VALID_SERVER_ERROR_UNSUPPORTED,
            ServerMessage::Error(ProtocolError {
                correlation_id: Some(CorrelationId::new(7)),
                reason: ProtocolErrorReason::Unsupported(UnsupportedReason {}),
            }),
        ),
    ];
    for (fixture, message) in cases {
        assert_server_roundtrip(&message, fixture);
    }
}

#[test]
fn protocol_error_malformations_are_rejected() {
    assert_eq!(
        kvm_agent_api::decode_server(fixtures::INVALID_SERVER_ERROR_UNKNOWN_REASON.as_bytes()),
        Err(DecodeError::Malformed {
            kind: Malformation::Shape
        })
    );
    assert_eq!(
        kvm_agent_api::decode_server(fixtures::INVALID_SERVER_ERROR_BAD_BOUNDS.as_bytes()),
        Err(DecodeError::Version(VersionError::Reversed {
            min: 3,
            max: 1
        }))
    );
    assert_eq!(
        kvm_agent_api::decode_server(fixtures::INVALID_SERVER_ERROR_UNKNOWN_FIELD.as_bytes()),
        Err(DecodeError::Malformed {
            kind: Malformation::Shape
        })
    );
    // A null correlation id is not an absent one; null never decodes as a
    // canonical decimal string.
    assert_eq!(
        kvm_agent_api::decode_server(
            b"{\"type\":\"error\",\"correlation_id\":null,\"reason\":{\"kind\":\"hello_required\"}}"
        ),
        Err(DecodeError::Malformed {
            kind: Malformation::Shape
        })
    );
}

#[test]
fn json_number_identifiers_are_rejected_at_every_magnitude() {
    for payload in [
        fixtures::INVALID_NUMERIC_CORRELATION.as_bytes(),
        fixtures::INVALID_NUMERIC_CORRELATION_SMALL.as_bytes(),
    ] {
        assert_eq!(
            kvm_agent_api::decode_client(payload),
            Err(DecodeError::Malformed {
                kind: Malformation::Shape
            })
        );
    }
    // The rejection never echoes the offending number.
    let error =
        kvm_agent_api::decode_client(fixtures::INVALID_NUMERIC_CORRELATION.as_bytes()).unwrap_err();
    assert!(!error.to_string().contains("9007199254740993"));
}

#[test]
fn overflow_sign_and_noncanonical_decimal_strings_are_rejected() {
    for fixture in [
        fixtures::INVALID_OVERFLOW_CORRELATION,
        fixtures::INVALID_NONCANONICAL_CORRELATION,
        fixtures::INVALID_NONCANONICAL_SIGN,
        fixtures::INVALID_EMPTY_CORRELATION,
    ] {
        assert_eq!(
            kvm_agent_api::decode_client(fixture.as_bytes()),
            Err(DecodeError::Malformed {
                kind: Malformation::Shape
            })
        );
    }
}

#[test]
fn nil_instance_identity_is_rejected() {
    assert_eq!(
        kvm_agent_api::decode_client(fixtures::INVALID_NIL_INSTANCE.as_bytes()),
        Err(DecodeError::NilInstance)
    );
}

#[test]
fn only_the_canonical_uuid_spelling_is_accepted() {
    for fixture in [
        fixtures::INVALID_UPPERCASE_INSTANCE,
        fixtures::INVALID_MALFORMED_INSTANCE,
    ] {
        assert_eq!(
            kvm_agent_api::decode_client(fixture.as_bytes()),
            Err(DecodeError::Malformed {
                kind: Malformation::Shape
            })
        );
    }
}

#[test]
fn server_hello_requires_a_valid_agent_instance() {
    assert_eq!(
        kvm_agent_api::decode_server(fixtures::INVALID_SERVER_HELLO_NIL_INSTANCE.as_bytes()),
        Err(DecodeError::NilInstance)
    );
    for fixture in [
        fixtures::INVALID_SERVER_HELLO_MISSING_INSTANCE,
        fixtures::INVALID_SERVER_HELLO_UPPERCASE_INSTANCE,
    ] {
        assert_eq!(
            kvm_agent_api::decode_server(fixture.as_bytes()),
            Err(DecodeError::Malformed {
                kind: Malformation::Shape
            }),
            "case {fixture}"
        );
    }

    // Encode side: serde's public Deserialize accepts the nil UUID (the
    // codecs defer that check), but the encoder refuses to serialize it.
    let ServerMessage::Hello(decoded) =
        serde_json::from_str(fixtures::INVALID_SERVER_HELLO_NIL_INSTANCE)
            .expect("serde accepts; codec defers the nil check")
    else {
        panic!("fixture must deserialize as a Hello");
    };
    assert_eq!(
        kvm_agent_api::encode_server(&ServerMessage::Hello(decoded)),
        Err(EncodeError::NilInstance)
    );
}

#[test]
fn agent_version_is_bounded_and_character_restricted_on_the_wire() {
    assert_eq!(
        kvm_agent_api::decode_server(fixtures::INVALID_SERVER_HELLO_CONTROL_VERSION.as_bytes()),
        Err(DecodeError::FieldInvalidCharacters {
            field: Field::AgentVersion
        })
    );
    assert_eq!(
        kvm_agent_api::decode_server(fixtures::INVALID_SERVER_HELLO_OVERSIZE_VERSION.as_bytes()),
        Err(DecodeError::FieldTooLarge {
            field: Field::AgentVersion,
            length: MAX_AGENT_VERSION_BYTES + 1,
            limit: MAX_AGENT_VERSION_BYTES,
        })
    );

    let mut hello = server_hello(1);
    hello.agent_version = AgentVersion::new("");
    assert_eq!(
        kvm_agent_api::encode_server(&ServerMessage::Hello(hello)),
        Err(EncodeError::FieldEmpty {
            field: Field::AgentVersion
        })
    );
}

#[test]
fn unknown_fields_and_variants_are_rejected_in_every_position() {
    for (payload, direction) in [
        (fixtures::INVALID_UNKNOWN_FIELD.as_bytes(), "client"),
        (fixtures::INVALID_UNKNOWN_VARIANT.as_bytes(), "client"),
        (fixtures::INVALID_UNKNOWN_LIFECYCLE.as_bytes(), "server"),
        // Fieldless variants of internally tagged enums must not silently
        // drop extra keys: clear safety, unknown/local input destinations.
        (fixtures::INVALID_UNKNOWN_SAFETY_FIELD.as_bytes(), "server"),
        (
            fixtures::INVALID_UNKNOWN_DESTINATION_FIELD.as_bytes(),
            "server",
        ),
        (fixtures::INVALID_UNKNOWN_LOCAL_FIELD.as_bytes(), "server"),
        (fixtures::INVALID_UNKNOWN_SNAPSHOT_FIELD.as_bytes(), "server"),
        (fixtures::INVALID_RESULT_UNKNOWN_FIELD.as_bytes(), "server"),
        (fixtures::INVALID_SERVER_ERROR_REASON_EXTRA_KEY.as_bytes(), "server"),
        // Unknown variant and duplicate keys inline, plus a transitioning
        // destination with an extra key.
        (
            b"{\"type\":\"snapshot_request\",\"instance\":\"9d2c8a40-1f6b-4c3e-a3b5-7e8f9a0b1c2d\",\"correlation_id\":\"1\",\"correlation_id\":\"2\"}",
            "client",
        ),
        (
            b"{\"type\":\"snapshot\",\"correlation_id\":\"1\",\"snapshot\":{\"instance\":\"9d2c8a40-1f6b-4c3e-a3b5-7e8f9a0b1c2d\",\"revision\":\"1\",\"lifecycle\":\"idle\",\"user_intent\":\"paused\",\"safety\":{\"state\":\"clear\"},\"cleanup_unconfirmed\":false,\"input_destination\":{\"destination\":\"transitioning\",\"x\":1},\"readiness\":{\"configuration\":\"unconfirmed\",\"enrollment\":\"unconfirmed\",\"permissions\":\"unconfirmed\",\"inventory\":\"unconfirmed\",\"peer_authentication\":\"unconfirmed\",\"input_authority\":\"unconfirmed\"},\"capabilities\":{\"pause\":\"unsupported\",\"resume\":\"unsupported\",\"failsafe\":\"unsupported\",\"quit\":\"unsupported\",\"snapshot\":\"supported\"}}}",
            "server",
        ),
    ] {
        let error = if direction == "client" {
            kvm_agent_api::decode_client(payload).unwrap_err()
        } else {
            kvm_agent_api::decode_server(payload).unwrap_err()
        };
        assert_eq!(
            error,
            DecodeError::Malformed {
                kind: Malformation::Shape
            }
        );
    }
}

#[test]
fn duplicate_keys_are_rejected_in_every_position() {
    // A duplicated data field and a duplicated internally tagged `type` tag
    // are both shape errors. Last-value-wins decoding would silently bind
    // the first case to the nil instance and treat the second as a snapshot
    // request; both behaviors are non-conforming.
    assert_eq!(
        kvm_agent_api::decode_client(fixtures::INVALID_DUPLICATE_INSTANCE.as_bytes()),
        Err(DecodeError::Malformed {
            kind: Malformation::Shape
        })
    );
    assert_eq!(
        kvm_agent_api::decode_client(fixtures::INVALID_DUPLICATE_TYPE.as_bytes()),
        Err(DecodeError::Malformed {
            kind: Malformation::Shape
        })
    );
}

#[test]
fn safety_commands_reject_the_revision_precondition() {
    // Pause, Failsafe and Quit carry no expected revision: sending one is an
    // unknown-field error, so a stale observation can never block a safety
    // stop. Resume without its revision is equally malformed.
    assert_eq!(
        kvm_agent_api::decode_client(fixtures::INVALID_PAUSE_WITH_REVISION.as_bytes()),
        Err(DecodeError::Malformed {
            kind: Malformation::Shape
        })
    );
    assert_eq!(
        kvm_agent_api::decode_client(
            b"{\"type\":\"resume\",\"instance\":\"9d2c8a40-1f6b-4c3e-a3b5-7e8f9a0b1c2d\",\"correlation_id\":\"1\"}"
        ),
        Err(DecodeError::Malformed {
            kind: Malformation::Shape
        })
    );
}

#[test]
fn malformed_versions_and_wrong_protocol_are_rejected() {
    assert_eq!(
        kvm_agent_api::decode_client(fixtures::INVALID_VERSION_AS_STRING.as_bytes()),
        Err(DecodeError::Malformed {
            kind: Malformation::Shape
        })
    );
    assert_eq!(
        kvm_agent_api::decode_client(fixtures::INVALID_WRONG_PROTOCOL.as_bytes()),
        Err(DecodeError::WrongProtocol)
    );
    assert_eq!(
        kvm_agent_api::decode_client(fixtures::INVALID_HELLO_ZERO_VERSION.as_bytes()),
        Err(DecodeError::Version(VersionError::Zero))
    );
    assert_eq!(
        kvm_agent_api::decode_client(fixtures::INVALID_HELLO_REVERSED.as_bytes()),
        Err(DecodeError::Version(VersionError::Reversed {
            min: 3,
            max: 1
        }))
    );
    assert_eq!(
        kvm_agent_api::decode_server(fixtures::INVALID_SERVER_HELLO_BAD_NEGOTIATED.as_bytes()),
        Err(DecodeError::Version(
            VersionError::NegotiatedOutsideAdvertised {
                negotiated: 2,
                min: 1,
                max: 1
            }
        ))
    );
}

#[test]
fn invalid_version_bounds_are_rejected_before_serializing() {
    let reversed = ClientMessage::Hello(HelloRequest {
        protocol: ProtocolName::standard(),
        min_version: 3,
        max_version: 1,
    });
    assert_eq!(
        kvm_agent_api::encode_client(&reversed),
        Err(EncodeError::Version(VersionError::Reversed {
            min: 3,
            max: 1
        }))
    );

    let mut zero = server_hello(1);
    zero.min_version = 0;
    assert_eq!(
        kvm_agent_api::encode_server(&ServerMessage::Hello(zero)),
        Err(EncodeError::Version(VersionError::Zero))
    );

    let mut unsupported = server_hello(3);
    unsupported.max_version = 9;
    assert_eq!(
        kvm_agent_api::encode_server(&ServerMessage::Hello(unsupported)),
        Err(EncodeError::Version(VersionError::UnsupportedNegotiated {
            version: 3
        }))
    );
}

#[test]
fn payload_cap_is_the_oversize_fixtures_only_defect() {
    // The oversize fixture is a valid Hello padded with whitespace; the only
    // rejection reason is the cap, so a decoder lacking the cap would accept.
    let error = kvm_agent_api::decode_client(fixtures::OVERSIZED_PAYLOAD.as_bytes()).unwrap_err();
    assert_eq!(
        error,
        DecodeError::PayloadTooLarge {
            size: fixtures::OVERSIZED_PAYLOAD.len(),
            limit: MAX_PAYLOAD_BYTES
        }
    );
    assert_eq!(fixtures::OVERSIZED_PAYLOAD.len(), MAX_PAYLOAD_BYTES + 1);

    // The same Hello at exactly the cap decodes.
    assert!(
        kvm_agent_api::decode_client(fixtures::VALID_CLIENT_HELLO_AT_LIMIT.as_bytes()).is_ok(),
        "boundary-size payload must be accepted"
    );
    assert_eq!(
        fixtures::VALID_CLIENT_HELLO_AT_LIMIT.len(),
        MAX_PAYLOAD_BYTES
    );
}

#[test]
fn truncated_input_syntax_error_and_invalid_utf8_are_classified() {
    assert_eq!(
        kvm_agent_api::decode_client(b"{\"type\":\"hel"),
        Err(DecodeError::Malformed {
            kind: Malformation::Truncated
        })
    );
    assert_eq!(
        kvm_agent_api::decode_client(b"not json"),
        Err(DecodeError::Malformed {
            kind: Malformation::Syntax
        })
    );
    assert_eq!(
        kvm_agent_api::decode_client(&[0xff, 0xfe]),
        Err(DecodeError::InvalidUtf8)
    );
}

#[test]
fn overlimit_encode_is_rejected_before_serializing() {
    // A 20 KiB protocol name exceeds both the per-field limit and the payload
    // cap; the encoder must reject it by field rule, not by serialized size.
    let oversized = ClientMessage::Hello(HelloRequest {
        protocol: ProtocolName::new("a".repeat(MAX_PAYLOAD_BYTES + 1)),
        min_version: 1,
        max_version: 1,
    });
    assert_eq!(
        kvm_agent_api::encode_client(&oversized),
        Err(EncodeError::FieldTooLarge {
            field: Field::ProtocolName,
            length: MAX_PAYLOAD_BYTES + 1,
            limit: MAX_PROTOCOL_NAME_BYTES
        })
    );
}

#[test]
fn overlimit_and_illegal_host_labels_are_rejected_in_both_directions() {
    let long_host = "h".repeat(MAX_HOST_LABEL_BYTES + 1);
    let mut snapshot = idle_snapshot();
    snapshot.input_destination = InputDestination::Remote(RemoteTarget {
        host: HostLabel::new(long_host.clone()),
        session: SessionId::new(1),
        generation: Generation::new(1),
    });
    let oversize_snapshot = ServerMessage::Snapshot(SnapshotReply {
        correlation_id: CorrelationId::new(1),
        snapshot,
    });
    assert_eq!(
        kvm_agent_api::encode_server(&oversize_snapshot),
        Err(EncodeError::FieldTooLarge {
            field: Field::HostLabel,
            length: MAX_HOST_LABEL_BYTES + 1,
            limit: MAX_HOST_LABEL_BYTES
        })
    );

    let mut controlled = idle_snapshot();
    controlled.input_destination = InputDestination::Remote(RemoteTarget {
        host: HostLabel::new("a\nb\u{1b}[31m"),
        session: SessionId::new(1),
        generation: Generation::new(1),
    });
    let control_snapshot = ServerMessage::Snapshot(SnapshotReply {
        correlation_id: CorrelationId::new(1),
        snapshot: controlled,
    });
    assert_eq!(
        kvm_agent_api::encode_server(&control_snapshot),
        Err(EncodeError::FieldInvalidCharacters {
            field: Field::HostLabel
        })
    );
}

#[test]
fn empty_bounded_fields_are_rejected_in_both_directions() {
    let empty_hello = ClientMessage::Hello(HelloRequest {
        protocol: ProtocolName::new(""),
        min_version: 1,
        max_version: 1,
    });
    assert_eq!(
        kvm_agent_api::encode_client(&empty_hello),
        Err(EncodeError::FieldEmpty {
            field: Field::ProtocolName
        })
    );
    assert_eq!(
        kvm_agent_api::decode_client(fixtures::INVALID_EMPTY_PROTOCOL.as_bytes()),
        Err(DecodeError::FieldEmpty {
            field: Field::ProtocolName
        })
    );
}

#[test]
fn decoding_never_authorizes_and_errors_never_carry_payload_text() {
    // A fully valid mutation decodes; that grants nothing. Separately, every
    // rejection's Display output stays free of fixture text. Each fixture is
    // decoded through its own direction so the error under test is actually
    // reached.
    assert!(kvm_agent_api::decode_client(fixtures::VALID_CLIENT_PAUSE_U64MAX.as_bytes()).is_ok());
    let client_leaks = [
        kvm_agent_api::decode_client(fixtures::INVALID_UNKNOWN_FIELD.as_bytes())
            .unwrap_err()
            .to_string(),
        kvm_agent_api::decode_client(fixtures::INVALID_NONCANONICAL_CORRELATION.as_bytes())
            .unwrap_err()
            .to_string(),
    ];
    let server_leaks = [
        kvm_agent_api::decode_server(fixtures::INVALID_UNKNOWN_LIFECYCLE.as_bytes())
            .unwrap_err()
            .to_string(),
        kvm_agent_api::decode_server(fixtures::INVALID_UNKNOWN_SNAPSHOT_FIELD.as_bytes())
            .unwrap_err()
            .to_string(),
        kvm_agent_api::decode_server(fixtures::INVALID_UNKNOWN_LOCAL_FIELD.as_bytes())
            .unwrap_err()
            .to_string(),
        kvm_agent_api::decode_server(fixtures::INVALID_SERVER_ERROR_UNKNOWN_FIELD.as_bytes())
            .unwrap_err()
            .to_string(),
    ];
    for text in client_leaks.into_iter().chain(server_leaks) {
        for fragment in [
            "surprise",
            "007",
            "hibernating",
            "surcharge",
            "confirmed",
            "evil",
            "hello_required",
            "boom",
        ] {
            assert!(!text.contains(fragment), "error text leaked: {text}");
        }
    }
}

fn fixture_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn decode_bytes(direction: &str, bytes: &[u8]) -> Result<(), DecodeError> {
    match direction {
        "client" => kvm_agent_api::decode_client(bytes).map(|_| ()),
        "server" => kvm_agent_api::decode_server(bytes).map(|_| ()),
        _ => panic!("unknown direction {direction}"),
    }
}

fn matches_category(error: DecodeError, expect: &str) -> bool {
    match expect {
        "shape" => {
            error
                == DecodeError::Malformed {
                    kind: Malformation::Shape,
                }
        }
        "nil_instance" => error == DecodeError::NilInstance,
        "wrong_protocol" => error == DecodeError::WrongProtocol,
        "field_empty" => matches!(error, DecodeError::FieldEmpty { .. }),
        "field_too_large" => matches!(error, DecodeError::FieldTooLarge { .. }),
        "field_invalid_characters" => matches!(error, DecodeError::FieldInvalidCharacters { .. }),
        "version_invalid" => matches!(error, DecodeError::Version(_)),
        "payload_too_large" => matches!(error, DecodeError::PayloadTooLarge { .. }),
        other => panic!("manifest lists unknown expectation {other}"),
    }
}

#[test]
fn manifest_cases_agree_with_the_codec() {
    let manifest: serde_json::Value =
        serde_json::from_str(fixtures::MANIFEST).expect("manifest is valid JSON");
    let root = fixture_root();

    for entry in manifest["valid"].as_array().expect("valid array") {
        let file = entry["file"].as_str().expect("file name");
        let direction = entry["direction"].as_str().expect("direction");
        let byte_exact = entry["byte_exact"].as_bool().unwrap_or(true);
        let bytes = fs::read(root.join("valid").join(file)).expect("fixture exists");
        let case = format!("valid/{file}");

        match direction {
            "client" => {
                let message = kvm_agent_api::decode_client(&bytes)
                    .unwrap_or_else(|error| panic!("{case}: {error}"));
                if byte_exact {
                    assert_eq!(
                        kvm_agent_api::encode_client(&message).unwrap(),
                        bytes,
                        "{case}: re-encode is byte-exact"
                    );
                }
            }
            "server" => {
                let message = kvm_agent_api::decode_server(&bytes)
                    .unwrap_or_else(|error| panic!("{case}: {error}"));
                if byte_exact {
                    assert_eq!(
                        kvm_agent_api::encode_server(&message).unwrap(),
                        bytes,
                        "{case}: re-encode is byte-exact"
                    );
                }
            }
            other => panic!("{case}: unknown direction {other}"),
        }
    }

    for entry in manifest["invalid"].as_array().expect("invalid array") {
        let file = entry["file"].as_str().expect("file name");
        let direction = entry["direction"].as_str().expect("direction");
        let expect = entry["expect"].as_str().expect("expectation");
        let bytes = fs::read(root.join("invalid").join(file)).expect("fixture exists");
        let case = format!("invalid/{file}");

        let error = match decode_bytes(direction, &bytes) {
            Ok(()) => panic!("{case}: expected rejection"),
            Err(error) => error,
        };
        assert!(
            matches_category(error, expect),
            "{case}: error {error:?} does not match category {expect}"
        );
    }

    // Orphan check: every fixture file on disk must be listed, so a harness
    // driven by this manifest can never silently skip a case.
    for group in ["valid", "invalid"] {
        let mut listed: Vec<String> = manifest[group]
            .as_array()
            .expect("group array")
            .iter()
            .map(|entry| entry["file"].as_str().expect("file name").to_string())
            .collect();
        listed.sort_unstable();
        let mut on_disk: Vec<String> = fs::read_dir(root.join(group))
            .expect("group directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| {
                Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
            })
            .collect();
        on_disk.sort_unstable();
        assert_eq!(listed, on_disk, "{group}: manifest and disk disagree");
    }
}
