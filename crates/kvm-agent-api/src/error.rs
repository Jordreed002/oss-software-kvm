//! Codec error values.
//!
//! No variant retains any part of a payload. Diagnostics carry lengths,
//! categories and field names only, so parse failures never echo attacker- or
//! peer-controlled text back into logs.

use std::fmt;

/// Which bounded text field a validation failure concerns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field {
    /// The protocol name carried by a Hello message.
    ProtocolName,
    /// A peer host label inside a remote input destination.
    HostLabel,
    /// The agent version label carried by a server Hello.
    AgentVersion,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ProtocolName => "protocol name",
            Self::HostLabel => "host label",
            Self::AgentVersion => "agent version",
        })
    }
}

/// Internal classification of a field-validation failure, mapped by the
/// codecs into the public [`DecodeError`] and [`EncodeError`] variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FieldViolation {
    /// A bounded text field was empty.
    Empty(Field),
    /// A bounded text field exceeded its per-field byte limit.
    TooLarge {
        /// The offending field.
        field: Field,
        /// Observed field length in bytes.
        length: usize,
        /// Enforced maximum in bytes.
        limit: usize,
    },
    /// A bounded text field contained a character outside its allowed set.
    InvalidCharacters(Field),
    /// A protocol name did not match this contract.
    WrongName,
    /// An agent instance identity was the nil UUID.
    NilInstance,
    /// Version bounds violated a documented invariant.
    Version(crate::VersionError),
}

/// Why raw bytes were not well-formed JSON for this contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Malformation {
    /// Invalid JSON syntax.
    Syntax,
    /// Valid prefix but the payload ended inside a value.
    Truncated,
    /// Parsed as JSON but did not match the schema: wrong shape or type,
    /// unknown field, unknown variant, duplicate field, noncanonical or
    /// out-of-range identifier string, or malformed or noncanonical UUID.
    Shape,
}

impl fmt::Display for Malformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Syntax => "invalid JSON syntax",
            Self::Truncated => "truncated JSON",
            Self::Shape => "a schema violation",
        })
    }
}

/// Failure to decode a message. Never retains payload text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Input exceeded the payload cap before parsing. `size` is the observed
    /// input length; no content was inspected.
    PayloadTooLarge {
        /// Observed input length in bytes.
        size: usize,
        /// Enforced maximum in bytes.
        limit: usize,
    },
    /// Input was not valid UTF-8.
    InvalidUtf8,
    /// Input was not well-formed JSON for this contract.
    Malformed {
        /// Payload-free classification of the malformation.
        kind: Malformation,
    },
    /// A Hello carried a protocol name other than [`crate::PROTOCOL_NAME`].
    WrongProtocol,
    /// A bounded text field exceeded its per-field byte limit.
    FieldTooLarge {
        /// The offending field.
        field: Field,
        /// Observed field length in bytes.
        length: usize,
        /// Enforced maximum in bytes.
        limit: usize,
    },
    /// A bounded text field was empty.
    FieldEmpty {
        /// The offending field.
        field: Field,
    },
    /// A bounded text field contained a character outside its allowed set.
    FieldInvalidCharacters {
        /// The offending field.
        field: Field,
    },
    /// An agent instance identity was the nil UUID.
    NilInstance,
    /// Version bounds in a Hello or error reply violated a documented
    /// invariant: a zero bound, a reversed range, a negotiated version
    /// outside the advertised range, or one this codec does not support.
    Version(#[doc(alias = "VersionError")] crate::VersionError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { size, limit } => {
                write!(f, "payload of {size} bytes exceeds the {limit}-byte limit")
            }
            Self::InvalidUtf8 => write!(f, "payload is not valid UTF-8"),
            Self::Malformed { kind } => write!(f, "payload is {kind}"),
            Self::WrongProtocol => write!(f, "hello used an unknown protocol name"),
            Self::FieldTooLarge {
                field,
                length,
                limit,
            } => write!(
                f,
                "{field} of {length} bytes exceeds its {limit}-byte limit"
            ),
            Self::FieldEmpty { field } => write!(f, "{field} must not be empty"),
            Self::FieldInvalidCharacters { field } => {
                write!(f, "{field} contains a character outside its allowed set")
            }
            Self::NilInstance => write!(f, "agent instance identity must not be the nil UUID"),
            Self::Version(error) => write!(f, "invalid schema version bounds: {error}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Failure to encode a message. Never retains field text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// A bounded text field exceeded its per-field byte limit. Checked before
    /// serialization, so oversized field text is never serialized.
    FieldTooLarge {
        /// The offending field.
        field: Field,
        /// Observed field length in bytes.
        length: usize,
        /// Enforced maximum in bytes.
        limit: usize,
    },
    /// A bounded text field was empty.
    FieldEmpty {
        /// The offending field.
        field: Field,
    },
    /// A Hello carried a protocol name other than [`crate::PROTOCOL_NAME`].
    WrongProtocol,
    /// An agent instance identity was the nil UUID. Reachable through the
    /// public `Deserialize` impls, since message fields are public; the
    /// codecs reject it before serializing.
    NilInstance,
    /// A bounded text field contained a character outside its allowed set.
    FieldInvalidCharacters {
        /// The offending field.
        field: Field,
    },
    /// Version bounds in a Hello or error reply violated a documented
    /// invariant. Checked before serialization.
    Version(crate::VersionError),
    /// Serialized output exceeded the payload cap. Defensive backstop: the
    /// per-field limits make this unreachable for currently valid messages.
    PayloadTooLarge {
        /// Serialized length in bytes.
        size: usize,
        /// Enforced maximum in bytes.
        limit: usize,
    },
    /// The serializer failed. Unreachable for the plain data types in this
    /// crate; retained so encoding never panics.
    Serialization,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldTooLarge {
                field,
                length,
                limit,
            } => write!(
                f,
                "{field} of {length} bytes exceeds its {limit}-byte limit"
            ),
            Self::FieldEmpty { field } => write!(f, "{field} must not be empty"),
            Self::WrongProtocol => write!(f, "hello used an unknown protocol name"),
            Self::NilInstance => write!(f, "agent instance identity must not be the nil UUID"),
            Self::FieldInvalidCharacters { field } => {
                write!(f, "{field} contains a character outside its allowed set")
            }
            Self::Version(error) => write!(f, "invalid schema version bounds: {error}"),
            Self::PayloadTooLarge { size, limit } => {
                write!(
                    f,
                    "encoded payload of {size} bytes exceeds the {limit}-byte limit"
                )
            }
            Self::Serialization => write!(f, "serialization failed"),
        }
    }
}

impl std::error::Error for EncodeError {}
