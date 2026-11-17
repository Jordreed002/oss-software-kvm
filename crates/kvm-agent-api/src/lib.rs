//! Bounded, typed JSON codecs for the replacement local agent control API.
//!
//! This crate implements the first serialized contract described in
//! `docs/overhaul/local-api-schema.md`: a new protocol namespace, independent
//! of legacy IPC and peer frames. It contains data types, validation and
//! serialization only.
//!
//! # Transport authentication is not serialization
//!
//! The transport must authenticate endpoint and client identities. Decoding a
//! message authorizes nothing: successful [`codec::decode_client`] or
//! [`codec::decode_server`] proves only that the bytes matched this schema.
//! Authorization, command admission, request deduplication and
//! snapshot-event reconciliation belong to the owning service, not to this
//! crate. A client timeout is an unconfirmed outcome; no type here converts it
//! into a success or a rejection, and callers must not either.
//!
//! # Bounded payloads
//!
//! Every payload is capped at [`codec::MAX_PAYLOAD_BYTES`] (16 KiB) in both
//! directions. Decoding rejects larger inputs before parsing. Encoding
//! validates unbounded text fields against their per-field limits *before*
//! serializing, and still checks the final serialized length as a backstop.
//! No error variant retains any part of the payload text; diagnostics carry
//! lengths, categories and field names only.
//!
//! # Identifier encoding
//!
//! 64-bit values ([`CorrelationId`], [`Revision`], [`SessionId`],
//! [`Generation`]) travel as canonical unsigned decimal strings, never as JSON
//! numbers, to prevent JavaScript precision loss. Canonical means: non-empty,
//! ASCII digits only, no leading zeros unless the value is exactly `"0"`, and
//! within `u64` range. JSON numbers, overflow, signs, whitespace and
//! noncanonical spellings are rejected. Canonicality applies to the decoded
//! string value, not the raw JSON bytes: JSON-escaped spellings that decode
//! to a canonical value are accepted, matching `JSON.parse` semantics.
//! [`InstanceId`] wraps a UUID supplied by the native owner; the codec
//! generates no identity and rejects the nil UUID.
//!
//! # Facts, not inferences
//!
//! Snapshot data exposes only facts the owning agent can confirm. Readiness is
//! reported per prerequisite as confirmed or unconfirmed; capabilities are
//! explicit supported/unsupported values, never inferred from command names;
//! user intent is the user's standing request and never establishes where
//! input flows; input destination has an explicit `unknown` variant which must
//! never be presented as confirmed local authority merely because the process
//! is paused. This crate performs no native behavior and draws no authority
//! conclusions from any field.
//!
//! # Handshake, bootstrap and errors
//!
//! The server Hello returns the agent's instance identity and a bounded,
//! character-restricted version label. That identity is the bootstrap value:
//! a client cannot form its first instance-bound request until it has the
//! id, and every later request must be bound to it. A client that offered a
//! version range must also verify the chosen version against it before
//! trusting the connection; [`accept_server_hello`] performs that check.
//! Protocol errors travel as [`ServerMessage::Error`] with a closed,
//! payload-free reason set: an error never echoes client text, and carries a
//! correlation id according to owner policy. The codec permits presence for
//! any reason; owners omit it for Hello and undecodable requests, and echo it
//! for decoded correlated requests. Pause, Failsafe and Quit
//! are safety commands and deliberately carry no revision precondition, so a
//! stale observation can never block a safety stop; only Resume does.
//!
//! Only the [`codec`] entry points enforce this contract. Deserializing the
//! message types directly with serde skips the payload cap, canonical-field
//! and semantic validation; owners must go through the codecs.

pub mod codec;
pub mod error;
pub mod fixtures;
pub mod identity;
pub mod message;
pub mod version;

mod decimal;

pub use codec::{decode_client, decode_server, encode_client, encode_server, MAX_PAYLOAD_BYTES};
pub use decimal::{CorrelationId, Generation, Revision, SessionId};
pub use error::{DecodeError, EncodeError, Field, Malformation};
pub use identity::{
    AgentVersion, HostLabel, InstanceId, ProtocolName, MAX_AGENT_VERSION_BYTES,
    MAX_HOST_LABEL_BYTES, MAX_PROTOCOL_NAME_BYTES,
};
pub use message::{
    AcceptedOutcome, AgentSnapshot, AppliedOutcome, Capabilities, ClientMessage, CommandOutcome,
    CommandResultReply, HelloRequest, HelloRequiredReason, InputDestination,
    InstanceMismatchReason, Latch, LifecyclePhase, LocalInput, MalformedRequestReason,
    Prerequisite, ProtocolError, ProtocolErrorReason, Readiness, RejectedOutcome, RejectionReason,
    RemoteTarget, ResumeRequest, SafetyCause, SafetyClear, SafetyRequest, SafetyState, ServerHello,
    ServerMessage, SnapshotReply, SnapshotRequest, Support, TransitioningInput, UnknownInput,
    UnsupportedReason, UnsupportedVersionRange, UserIntent, WrongProtocolReason,
};
pub use version::{
    accept_server_hello, negotiate, VersionError, MAX_SUPPORTED_VERSION, MIN_SUPPORTED_VERSION,
};

/// Protocol namespace for this contract, independent of legacy IPC and peer frames.
pub const PROTOCOL_NAME: &str = "software-kvm-agent";
