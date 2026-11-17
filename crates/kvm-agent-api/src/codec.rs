//! Bounded encode/decode entry points for both directions.
//!
//! Pipeline order is part of the contract. Decoding: payload-size cap, then
//! UTF-8, then JSON/schema parse (unknown fields, unknown variants,
//! noncanonical identifier strings and noncanonical UUIDs are rejected), then
//! semantic validation (nil instance identity, bounded field text, protocol
//! name, Hello version invariants and the bounds an error reply reports).
//! Finally compare parsed JSON with the typed serialization to reject sequence
//! structs and numeric enum tags. Semantic errors take priority over shape
//! errors when the same input violates both rules.
//! Encoding: semantic validation first — so
//! oversized field text and invalid version bounds are never serialized —
//! then serialization, then a final payload-size backstop.
//!
//! These functions confer no authority. The transport authenticates endpoint
//! and client identities; decoding JSON authorizes no command, and encoding
//! one proves no authorization. Request deduplication and snapshot-event
//! reconciliation belong to the owning service.

use serde_json::error::Category;

use crate::error::{DecodeError, EncodeError, FieldViolation, Malformation};
use crate::identity::InstanceId;
use crate::message::{InputDestination, ProtocolErrorReason, ServerMessage};
use crate::version::{validate_advertised_range, validate_negotiated};
use crate::ClientMessage;

/// Maximum serialized payload size in either direction.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

/// Serializes a client request. Validates bounded field text before
/// serializing and checks the final size against [`MAX_PAYLOAD_BYTES`].
///
/// # Errors
///
/// Returns [`EncodeError`] without serializing when a field violates its
/// limit or the protocol name is wrong, and after serializing if the payload
/// exceeds the cap.
pub fn encode_client(message: &ClientMessage) -> Result<Vec<u8>, EncodeError> {
    validate_client(message).map_err(encode_violation)?;
    finish_encoding(serde_json::to_vec(message))
}

/// Serializes an agent reply under the same bounds and validation order.
///
/// # Errors
///
/// Returns [`EncodeError`] under the same conditions as [`encode_client`].
pub fn encode_server(message: &ServerMessage) -> Result<Vec<u8>, EncodeError> {
    validate_server(message).map_err(encode_violation)?;
    finish_encoding(serde_json::to_vec(message))
}

fn finish_encoding(bytes: Result<Vec<u8>, serde_json::Error>) -> Result<Vec<u8>, EncodeError> {
    let bytes = bytes.map_err(|_| EncodeError::Serialization)?;
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(EncodeError::PayloadTooLarge {
            size: bytes.len(),
            limit: MAX_PAYLOAD_BYTES,
        });
    }
    Ok(bytes)
}

/// Decodes a client request. Enforces the payload cap before parsing and
/// never retains payload text in errors.
///
/// # Errors
///
/// Returns [`DecodeError`] for oversized or non-UTF-8 input, malformed JSON,
/// schema violations, unknown protocol names, over-limit field text or the
/// nil instance identity.
pub fn decode_client(bytes: &[u8]) -> Result<ClientMessage, DecodeError> {
    check_size(bytes.len())?;
    let text = core::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)?;
    let message: ClientMessage = serde_json::from_str(text).map_err(|error| json_error(&error))?;
    validate_client(&message).map_err(decode_violation)?;
    check_json_shape(text, &message)?;
    Ok(message)
}

/// Decodes an agent reply under the same bounds and validation order.
///
/// # Errors
///
/// Returns [`DecodeError`] under the same conditions as [`decode_client`].
pub fn decode_server(bytes: &[u8]) -> Result<ServerMessage, DecodeError> {
    check_size(bytes.len())?;
    let text = core::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)?;
    let message: ServerMessage = serde_json::from_str(text).map_err(|error| json_error(&error))?;
    validate_server(&message).map_err(decode_violation)?;
    check_json_shape(text, &message)?;
    Ok(message)
}

// Serde's derived visitors also accept sequence structs and numeric enum
// indices. Compare JSON values after typed decoding has rejected duplicates,
// preserving escaped strings and whitespace while requiring the public shape.
// This extra bounded control-plane parse never runs on the input event path.
fn check_json_shape<T: serde::Serialize>(text: &str, message: &T) -> Result<(), DecodeError> {
    let input: serde_json::Value =
        serde_json::from_str(text).map_err(|error| json_error(&error))?;
    let expected = serde_json::to_value(message).map_err(|_| DecodeError::Malformed {
        kind: Malformation::Shape,
    })?;
    if input != expected {
        return Err(DecodeError::Malformed {
            kind: Malformation::Shape,
        });
    }
    Ok(())
}

fn check_size(size: usize) -> Result<(), DecodeError> {
    if size > MAX_PAYLOAD_BYTES {
        return Err(DecodeError::PayloadTooLarge {
            size,
            limit: MAX_PAYLOAD_BYTES,
        });
    }
    Ok(())
}

fn json_error(error: &serde_json::Error) -> DecodeError {
    let kind = match error.classify() {
        Category::Syntax | Category::Io => Malformation::Syntax,
        Category::Eof => Malformation::Truncated,
        Category::Data => Malformation::Shape,
    };
    DecodeError::Malformed { kind }
}

fn validate_client(message: &ClientMessage) -> Result<(), FieldViolation> {
    match message {
        ClientMessage::Hello(hello) => {
            hello.protocol.validate()?;
            validate_advertised_range(hello.min_version, hello.max_version)
                .map_err(FieldViolation::Version)
        }
        ClientMessage::SnapshotRequest(request) => check_instance(&request.instance),
        ClientMessage::Pause(request)
        | ClientMessage::Failsafe(request)
        | ClientMessage::Quit(request) => check_instance(&request.instance),
        ClientMessage::Resume(request) => check_instance(&request.instance),
    }
}

fn validate_server(message: &ServerMessage) -> Result<(), FieldViolation> {
    match message {
        ServerMessage::Hello(hello) => {
            hello.protocol.validate()?;
            validate_negotiated(
                hello.min_version,
                hello.max_version,
                hello.negotiated_version,
            )
            .map_err(FieldViolation::Version)?;
            check_instance(&hello.instance)?;
            hello.agent_version.validate()
        }
        ServerMessage::Snapshot(reply) => {
            check_instance(&reply.snapshot.instance)?;
            if let InputDestination::Remote(target) = &reply.snapshot.input_destination {
                return target.host.validate();
            }
            Ok(())
        }
        ServerMessage::CommandResult(_) => Ok(()),
        ServerMessage::Error(error) => {
            if let ProtocolErrorReason::UnsupportedVersion(range) = &error.reason {
                validate_advertised_range(range.server_min, range.server_max)
                    .map_err(FieldViolation::Version)?;
            }
            Ok(())
        }
    }
}

fn check_instance(instance: &InstanceId) -> Result<(), FieldViolation> {
    if instance.get().is_nil() {
        return Err(FieldViolation::NilInstance);
    }
    Ok(())
}

fn encode_violation(violation: FieldViolation) -> EncodeError {
    match violation {
        FieldViolation::Empty(field) => EncodeError::FieldEmpty { field },
        FieldViolation::TooLarge {
            field,
            length,
            limit,
        } => EncodeError::FieldTooLarge {
            field,
            length,
            limit,
        },
        FieldViolation::InvalidCharacters(field) => EncodeError::FieldInvalidCharacters { field },
        FieldViolation::WrongName => EncodeError::WrongProtocol,
        FieldViolation::NilInstance => EncodeError::NilInstance,
        FieldViolation::Version(error) => EncodeError::Version(error),
    }
}

fn decode_violation(violation: FieldViolation) -> DecodeError {
    match violation {
        FieldViolation::Empty(field) => DecodeError::FieldEmpty { field },
        FieldViolation::TooLarge {
            field,
            length,
            limit,
        } => DecodeError::FieldTooLarge {
            field,
            length,
            limit,
        },
        FieldViolation::InvalidCharacters(field) => DecodeError::FieldInvalidCharacters { field },
        FieldViolation::WrongName => DecodeError::WrongProtocol,
        FieldViolation::NilInstance => DecodeError::NilInstance,
        FieldViolation::Version(error) => DecodeError::Version(error),
    }
}
