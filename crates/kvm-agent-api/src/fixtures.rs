//! Language-neutral conformance fixtures.
//!
//! The files under `fixtures/` are the canonical wire bytes for this
//! contract. Rust tests consume them through these constants and through the
//! manifest-driven test in `tests/conformance.rs`; the TypeScript conformance
//! harness must read the same files and [`MANIFEST`], so both stacks verify
//! one byte-level truth. Valid fixtures are exactly the canonical
//! serialization of their typed values (compact, no trailing newline);
//! re-encoding the decoded value must reproduce the file byte for byte. The
//! marked exceptions are the whitespace-padded boundary fixture, which is
//! valid JSON at exactly the payload cap, and the JSON-escaped fixture, which
//! decodes to a canonical value but is deliberately not canonical bytes.
//!
//! Files under `fixtures/invalid/` are each rejected for exactly one
//! documented reason. `OVERSIZED_PAYLOAD` is a valid Hello padded with
//! insignificant whitespace to one byte over the cap, so the size cap is its
//! only defect; it is rejected before parsing. An over-limit *encode* cannot
//! be a file because it is a typed value — the Rust tests construct one (an
//! over-long protocol name) and assert the encoder rejects it without
//! serializing.
//!
//! Every decoder, including a future TypeScript client, must reject duplicate
//! JSON keys rather than accepting the last value; the duplicate-key fixtures
//! exist to pin that behavior in every stack.

/// Index of every fixture: file, direction and expected outcome. The
/// language-neutral entry point for non-Rust conformance harnesses.
pub const MANIFEST: &str = include_str!("../fixtures/manifest.json");

/// Valid Hello with the contract protocol name and version range 1..=1.
pub const VALID_CLIENT_HELLO: &str = include_str!("../fixtures/valid/client_hello.json");

/// Valid Hello padded with insignificant whitespace to exactly the 16 KiB
/// payload cap; decodes successfully but is not canonical bytes.
pub const VALID_CLIENT_HELLO_AT_LIMIT: &str =
    include_str!("../fixtures/valid/client_hello_at_limit.json");

/// Valid Hello advertising schema range 2..=3: well formed for this schema,
/// so it must parse, but this codec supports only version 1 and negotiation
/// rejects it. Parsing and negotiating are separate decisions.
pub const VALID_CLIENT_HELLO_FUTURE_RANGE: &str =
    include_str!("../fixtures/valid/client_hello_future_range.json");

/// Valid snapshot request bound to an instance.
pub const VALID_CLIENT_SNAPSHOT_REQUEST: &str =
    include_str!("../fixtures/valid/client_snapshot_request.json");

/// Valid snapshot request with a JSON-escaped decimal digit: canonicality
/// applies to the decoded value, so this decodes to the same message as
/// [`VALID_CLIENT_SNAPSHOT_REQUEST`] but re-encodes to different bytes.
pub const VALID_CLIENT_SNAPSHOT_REQUEST_ESCAPED: &str =
    include_str!("../fixtures/valid/client_snapshot_request_escaped.json");

/// Valid Pause (a safety command: instance and correlation only, no revision
/// precondition) whose correlation id is `u64::MAX`.
pub const VALID_CLIENT_PAUSE_U64MAX: &str =
    include_str!("../fixtures/valid/client_pause_u64max.json");

/// Valid Resume, the only mutation carrying an expected revision.
pub const VALID_CLIENT_RESUME_REVISION: &str =
    include_str!("../fixtures/valid/client_resume_revision.json");

/// Valid server Hello echoing the negotiated version, returning the agent
/// instance identity that bootstraps instance-bound requests, and a bounded
/// agent version label.
pub const VALID_SERVER_HELLO: &str = include_str!("../fixtures/valid/server_hello.json");

/// Valid idle-agent stub snapshot: no fabricated capability, paused intent,
/// unknown input destination, all prerequisites unconfirmed.
pub const VALID_SERVER_SNAPSHOT_IDLE: &str =
    include_str!("../fixtures/valid/server_snapshot_idle.json");

/// Valid latched snapshot: draining lifecycle, latched safety cause,
/// unconfirmed cleanup and a transitioning destination. Nothing here claims
/// confirmed remote authority while cleanup is unconfirmed.
pub const VALID_SERVER_SNAPSHOT_DRAINING_LATCHED: &str =
    include_str!("../fixtures/valid/server_snapshot_draining_latched.json");

/// Valid active snapshot: clear safety, confirmed remote input destination
/// with every readiness prerequisite confirmed. The honest counterpart to
/// the latched fixture: confirmed remote authority appears only when safety
/// is clear and cleanup is confirmed.
pub const VALID_SERVER_SNAPSHOT_ACTIVE_REMOTE: &str =
    include_str!("../fixtures/valid/server_snapshot_active_remote.json");

/// Valid command result: Accepted (queue entry acknowledged, not applied).
pub const VALID_SERVER_RESULT_ACCEPTED: &str =
    include_str!("../fixtures/valid/server_result_accepted.json");

/// Valid command result: Applied with revision `u64::MAX` and a correlation
/// id above JavaScript's exact numeric range (safe here because it is a
/// string).
pub const VALID_SERVER_RESULT_APPLIED_U64MAX: &str =
    include_str!("../fixtures/valid/server_result_applied_u64max.json");

/// Valid command result: Rejected with a structured reason.
pub const VALID_SERVER_RESULT_REJECTED: &str =
    include_str!("../fixtures/valid/server_result_rejected.json");

/// Valid protocol error: unsupported version, carrying the server's
/// supported range and no correlation id (the failure is at Hello time).
pub const VALID_SERVER_ERROR_UNSUPPORTED_VERSION: &str =
    include_str!("../fixtures/valid/server_error_unsupported_version.json");

/// Valid protocol error: wrong protocol name, no correlation id.
pub const VALID_SERVER_ERROR_WRONG_PROTOCOL: &str =
    include_str!("../fixtures/valid/server_error_wrong_protocol.json");

/// Valid protocol error: malformed request, no correlation id; the
/// undecodable bytes are never echoed.
pub const VALID_SERVER_ERROR_MALFORMED_REQUEST: &str =
    include_str!("../fixtures/valid/server_error_malformed_request.json");

/// Valid protocol error: Hello required, with the decoded request's
/// correlation id.
pub const VALID_SERVER_ERROR_HELLO_REQUIRED: &str =
    include_str!("../fixtures/valid/server_error_hello_required.json");

/// Valid protocol error: instance mismatch, with correlation id.
pub const VALID_SERVER_ERROR_INSTANCE_MISMATCH: &str =
    include_str!("../fixtures/valid/server_error_instance_mismatch.json");

/// Valid protocol error: unsupported operation, with correlation id.
pub const VALID_SERVER_ERROR_UNSUPPORTED: &str =
    include_str!("../fixtures/valid/server_error_unsupported.json");

/// Rejected: correlation id as a JSON number above `2^53`.
pub const INVALID_NUMERIC_CORRELATION: &str =
    include_str!("../fixtures/invalid/client_numeric_correlation.json");

/// Rejected: correlation id as a small JSON number; numbers are never valid.
pub const INVALID_NUMERIC_CORRELATION_SMALL: &str =
    include_str!("../fixtures/invalid/client_numeric_correlation_small.json");

/// Rejected: decimal string one above `u64::MAX`.
pub const INVALID_OVERFLOW_CORRELATION: &str =
    include_str!("../fixtures/invalid/client_overflow_correlation.json");

/// Rejected: leading-zero (noncanonical) decimal string.
pub const INVALID_NONCANONICAL_CORRELATION: &str =
    include_str!("../fixtures/invalid/client_noncanonical_correlation.json");

/// Rejected: signed decimal string.
pub const INVALID_NONCANONICAL_SIGN: &str =
    include_str!("../fixtures/invalid/client_noncanonical_sign.json");

/// Rejected: empty decimal string.
pub const INVALID_EMPTY_CORRELATION: &str =
    include_str!("../fixtures/invalid/client_empty_correlation.json");

/// Rejected: nil UUID as agent instance identity.
pub const INVALID_NIL_INSTANCE: &str = include_str!("../fixtures/invalid/client_nil_instance.json");

/// Rejected: uppercase UUID spelling (only hyphenated lowercase is canonical).
pub const INVALID_UPPERCASE_INSTANCE: &str =
    include_str!("../fixtures/invalid/client_uppercase_instance.json");

/// Rejected: simple 32-hex UUID spelling.
pub const INVALID_MALFORMED_INSTANCE: &str =
    include_str!("../fixtures/invalid/client_malformed_instance.json");

/// Rejected: unknown field inside a Pause.
pub const INVALID_UNKNOWN_FIELD: &str =
    include_str!("../fixtures/invalid/client_unknown_field.json");

/// Rejected: unknown top-level variant.
pub const INVALID_UNKNOWN_VARIANT: &str =
    include_str!("../fixtures/invalid/client_unknown_variant.json");

/// Rejected: duplicate `instance` key. Last-value-wins decoding is
/// non-conforming: a lenient decoder would bind this request to the nil
/// instance instead of rejecting the duplicate.
pub const INVALID_DUPLICATE_INSTANCE: &str =
    include_str!("../fixtures/invalid/client_duplicate_instance.json");

/// Rejected: duplicate top-level `type` tag. Last-value-wins decoding is
/// non-conforming: a lenient decoder would silently treat this as a snapshot
/// request instead of rejecting the duplicate.
pub const INVALID_DUPLICATE_TYPE: &str =
    include_str!("../fixtures/invalid/client_duplicate_type.json");

/// Rejected: `expected_revision` inside a Pause. Safety commands carry no
/// revision precondition; a stale observation must never block a safety
/// stop, so the field is rejected outright rather than ignored.
pub const INVALID_PAUSE_WITH_REVISION: &str =
    include_str!("../fixtures/invalid/client_pause_with_revision.json");

/// Rejected: Hello carrying a protocol name other than the contract's.
pub const INVALID_WRONG_PROTOCOL: &str =
    include_str!("../fixtures/invalid/client_wrong_protocol.json");

/// Rejected: empty protocol name.
pub const INVALID_EMPTY_PROTOCOL: &str =
    include_str!("../fixtures/invalid/client_empty_protocol.json");

/// Rejected: schema version bound as a string instead of a number.
pub const INVALID_VERSION_AS_STRING: &str =
    include_str!("../fixtures/invalid/client_version_as_string.json");

/// Rejected: zero version bound.
pub const INVALID_HELLO_ZERO_VERSION: &str =
    include_str!("../fixtures/invalid/client_hello_zero_version.json");

/// Rejected: reversed version range.
pub const INVALID_HELLO_REVERSED: &str =
    include_str!("../fixtures/invalid/client_hello_reversed.json");

/// Rejected: negotiated version outside the advertised range.
pub const INVALID_SERVER_HELLO_BAD_NEGOTIATED: &str =
    include_str!("../fixtures/invalid/server_hello_bad_negotiated.json");

/// Rejected: nil UUID as the server Hello's agent instance. The bootstrap
/// identity is never a nil placeholder.
pub const INVALID_SERVER_HELLO_NIL_INSTANCE: &str =
    include_str!("../fixtures/invalid/server_hello_nil_instance.json");

/// Rejected: server Hello without an instance field. A client cannot accept
/// an instance-free Hello; guessing from a filename or PID is not a valid
/// bootstrap mechanism.
pub const INVALID_SERVER_HELLO_MISSING_INSTANCE: &str =
    include_str!("../fixtures/invalid/server_hello_missing_instance.json");

/// Rejected: uppercase UUID spelling for the server Hello's instance.
pub const INVALID_SERVER_HELLO_UPPERCASE_INSTANCE: &str =
    include_str!("../fixtures/invalid/server_hello_uppercase_instance.json");

/// Rejected: agent version containing control characters (log-forgery
/// attempt).
pub const INVALID_SERVER_HELLO_CONTROL_VERSION: &str =
    include_str!("../fixtures/invalid/server_hello_control_version.json");

/// Rejected: agent version above its 64-byte limit.
pub const INVALID_SERVER_HELLO_OVERSIZE_VERSION: &str =
    include_str!("../fixtures/invalid/server_hello_oversize_version.json");

/// Rejected: unknown lifecycle variant inside a snapshot.
pub const INVALID_UNKNOWN_LIFECYCLE: &str =
    include_str!("../fixtures/invalid/server_unknown_lifecycle.json");

/// Rejected: unknown field next to the clear safety state.
pub const INVALID_UNKNOWN_SAFETY_FIELD: &str =
    include_str!("../fixtures/invalid/server_unknown_safety_field.json");

/// Rejected: unknown field next to the unknown input destination.
pub const INVALID_UNKNOWN_DESTINATION_FIELD: &str =
    include_str!("../fixtures/invalid/server_unknown_destination_field.json");

/// Rejected: unknown field next to a confirmed local input destination.
pub const INVALID_UNKNOWN_LOCAL_FIELD: &str =
    include_str!("../fixtures/invalid/server_unknown_local_field.json");

/// Rejected: unknown field inside the snapshot object.
pub const INVALID_UNKNOWN_SNAPSHOT_FIELD: &str =
    include_str!("../fixtures/invalid/server_unknown_snapshot_field.json");

/// Rejected: unknown field inside an applied outcome.
pub const INVALID_RESULT_UNKNOWN_FIELD: &str =
    include_str!("../fixtures/invalid/server_result_unknown_field.json");

/// Rejected: host label containing control characters.
pub const INVALID_CONTROL_HOST: &str = include_str!("../fixtures/invalid/server_control_host.json");

/// Rejected: host label above its 255-byte limit.
pub const INVALID_OVERSIZE_HOST: &str =
    include_str!("../fixtures/invalid/server_oversize_host.json");

/// Rejected: protocol error with a reason outside the closed set.
pub const INVALID_SERVER_ERROR_UNKNOWN_REASON: &str =
    include_str!("../fixtures/invalid/server_error_unknown_reason.json");

/// Rejected: `unsupported_version` error whose server bounds are reversed.
pub const INVALID_SERVER_ERROR_BAD_BOUNDS: &str =
    include_str!("../fixtures/invalid/server_error_bad_bounds.json");

/// Rejected: unknown field next to a protocol error's reason; errors are
/// payload-free and never echo client text.
pub const INVALID_SERVER_ERROR_UNKNOWN_FIELD: &str =
    include_str!("../fixtures/invalid/server_error_unknown_field.json");

/// Rejected: unknown key inside a payload-free reason; extra data cannot
/// ride along with a closed reason.
pub const INVALID_SERVER_ERROR_REASON_EXTRA_KEY: &str =
    include_str!("../fixtures/invalid/server_error_reason_extra_key.json");

/// Rejected before parsing: valid Hello padded with whitespace to one byte
/// over the 16 KiB cap, so the cap is its only defect.
pub const OVERSIZED_PAYLOAD: &str = include_str!("../fixtures/invalid/oversize_payload.json");
