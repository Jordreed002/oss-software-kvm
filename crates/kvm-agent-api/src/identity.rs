//! Identity and bounded text-label values.

use std::fmt;

use serde::{
    de::{Error as SerdeError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use uuid::Uuid;

use crate::error::{Field, FieldViolation};

/// Maximum byte length of a Hello protocol name, enforced by the codecs.
pub const MAX_PROTOCOL_NAME_BYTES: usize = 32;

/// Maximum byte length of a remote host label, enforced by the codecs.
pub const MAX_HOST_LABEL_BYTES: usize = 255;

/// Maximum byte length of an agent version label, enforced by the codecs.
pub const MAX_AGENT_VERSION_BYTES: usize = 64;

/// Error returned when an instance identity is the nil UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NilInstance;

impl fmt::Display for NilInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("agent instance identity must not be the nil UUID")
    }
}

impl std::error::Error for NilInstance {}

/// Agent instance identity: a cryptographically fresh UUID supplied by the
/// native owner. The codec generates no identity; a fresh instance
/// invalidates old subscriptions, commands and authority.
///
/// Construction with [`InstanceId::new`] rejects the nil UUID. Deserialization
/// accepts exactly one spelling — 36 bytes of lowercase hex in 8-4-4-4-12
/// hyphenated form — so decode/encode roundtrips are byte-stable; the nil
/// check is deferred to the codecs so failures surface as the distinct
/// [`crate::DecodeError::NilInstance`] instead of a generic shape error.
/// Canonicality applies to the decoded string value, not the raw JSON bytes:
/// a JSON-escaped spelling decodes and re-encodes to the canonical form, the
/// same unescaping `JSON.parse` performs in TypeScript consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceId(Uuid);

/// Accepts only the canonical hyphenated lowercase spelling. Uppercase,
/// simple 32-hex, braced and URN forms are valid UUIDs but not canonical
/// wire spellings, and are rejected so every implementation agrees on the
/// bytes used for authority binding.
fn parse_canonical_uuid(text: &str) -> Option<Uuid> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    for (index, &byte) in bytes.iter().enumerate() {
        match index {
            8 | 13 | 18 | 23 => {
                if byte != b'-' {
                    return None;
                }
            }
            _ => {
                if !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase() {
                    return None;
                }
            }
        }
    }
    Uuid::try_parse(text).ok()
}

impl InstanceId {
    /// Wraps an owner-supplied UUID.
    ///
    /// # Errors
    ///
    /// Returns [`NilInstance`] for the nil UUID, which is never a valid
    /// agent identity.
    pub fn new(id: Uuid) -> Result<Self, NilInstance> {
        if id.is_nil() {
            Err(NilInstance)
        } else {
            Ok(Self(id))
        }
    }

    /// Returns the wrapped UUID.
    #[must_use]
    pub const fn get(self) -> Uuid {
        self.0
    }
}

impl Serialize for InstanceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InstanceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CanonicalUuidVisitor;

        impl Visitor<'_> for CanonicalUuidVisitor {
            type Value = InstanceId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a hyphenated lowercase UUID string")
            }

            fn visit_str<E>(self, text: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                parse_canonical_uuid(text)
                    .map(InstanceId)
                    .ok_or_else(|| E::custom("noncanonical or invalid UUID string"))
            }
        }

        deserializer.deserialize_str(CanonicalUuidVisitor)
    }
}

/// Protocol name carried by Hello messages. The codecs enforce non-empty,
/// at most [`MAX_PROTOCOL_NAME_BYTES`] bytes, and exact equality with
/// [`crate::PROTOCOL_NAME`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolName(String);

impl ProtocolName {
    /// Wraps a protocol name. Validation happens in the codecs.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the name for this contract.
    #[must_use]
    pub fn standard() -> Self {
        Self::new(crate::PROTOCOL_NAME)
    }

    /// Returns the wrapped name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validates non-empty, within the byte limit, and equal to the contract
    /// protocol name. Wrong-name and size violations are distinguished.
    pub(crate) fn validate(&self) -> Result<(), FieldViolation> {
        if self.0.is_empty() {
            return Err(FieldViolation::Empty(Field::ProtocolName));
        }
        if self.0.len() > MAX_PROTOCOL_NAME_BYTES {
            return Err(FieldViolation::TooLarge {
                field: Field::ProtocolName,
                length: self.0.len(),
                limit: MAX_PROTOCOL_NAME_BYTES,
            });
        }
        if self.0 != crate::PROTOCOL_NAME {
            return Err(FieldViolation::WrongName);
        }
        Ok(())
    }
}

impl Serialize for ProtocolName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProtocolName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

/// Host label inside a remote input destination. The codecs enforce
/// non-empty, at most [`MAX_HOST_LABEL_BYTES`] bytes, and a restricted
/// character set: ASCII letters, digits, `.`, `-`, `:` and `_`. That covers
/// DNS names, IPv4/IPv6 literals and service labels while excluding control
/// characters, ANSI escapes, NUL, bidi overrides and all non-ASCII, so a
/// peer-supplied label cannot forge log lines or spoof display order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostLabel(String);

/// Whether one byte is an allowed host-label character.
const fn is_label_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'_')
}

impl HostLabel {
    /// Wraps a host label. Validation happens in the codecs.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    /// Returns the wrapped label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), FieldViolation> {
        if self.0.is_empty() {
            return Err(FieldViolation::Empty(Field::HostLabel));
        }
        if self.0.len() > MAX_HOST_LABEL_BYTES {
            return Err(FieldViolation::TooLarge {
                field: Field::HostLabel,
                length: self.0.len(),
                limit: MAX_HOST_LABEL_BYTES,
            });
        }
        if !self.0.bytes().all(is_label_byte) {
            return Err(FieldViolation::InvalidCharacters(Field::HostLabel));
        }
        Ok(())
    }
}

impl Serialize for HostLabel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HostLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

/// Agent version label returned in the server Hello. The codecs enforce
/// non-empty, at most [`MAX_AGENT_VERSION_BYTES`] bytes, and a restricted
/// character set: ASCII letters, digits, `.`, `+`, `-` and `_`. That covers
/// semver and `git describe` labels while excluding control characters, ANSI
/// escapes, NUL, bidi overrides and all non-ASCII, so a build label cannot
/// forge log lines or spoof display order. A version label identifies a
/// build; it supplements native authentication and proves nothing about code
/// identity by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVersion(String);

/// Whether one byte is an allowed agent-version character.
const fn is_version_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_')
}

impl AgentVersion {
    /// Wraps an agent version label. Validation happens in the codecs.
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self(version.into())
    }

    /// Returns the wrapped label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), FieldViolation> {
        if self.0.is_empty() {
            return Err(FieldViolation::Empty(Field::AgentVersion));
        }
        if self.0.len() > MAX_AGENT_VERSION_BYTES {
            return Err(FieldViolation::TooLarge {
                field: Field::AgentVersion,
                length: self.0.len(),
                limit: MAX_AGENT_VERSION_BYTES,
            });
        }
        if !self.0.bytes().all(is_version_byte) {
            return Err(FieldViolation::InvalidCharacters(Field::AgentVersion));
        }
        Ok(())
    }
}

impl Serialize for AgentVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AgentVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_canonical_uuid, AgentVersion, HostLabel, InstanceId, ProtocolName,
        MAX_AGENT_VERSION_BYTES,
    };
    use crate::error::{Field, FieldViolation};
    use uuid::Uuid;

    #[test]
    fn rejects_nil_on_construction() {
        assert!(InstanceId::new(Uuid::nil()).is_err());
        assert!(InstanceId::new(Uuid::max()).is_ok());
    }

    #[test]
    fn standard_protocol_name_is_the_contract_name() {
        assert_eq!(ProtocolName::standard().as_str(), "software-kvm-agent");
        assert_eq!(HostLabel::new("").as_str(), "");
    }

    #[test]
    fn accepts_only_the_canonical_uuid_spelling() {
        assert!(parse_canonical_uuid("9d2c8a40-1f6b-4c3e-a3b5-7e8f9a0b1c2d").is_some());
        for text in [
            "9D2C8A40-1F6B-4C3E-A3B5-7E8F9A0B1C2D",
            "9d2c8a401f6b4c3ea3b57e8f9a0b1c2d",
            "{9d2c8a40-1f6b-4c3e-a3b5-7e8f9a0b1c2d}",
            "urn:uuid:9d2c8a40-1f6b-4c3e-a3b5-7e8f9a0b1c2d",
            "9d2c8a40-1f6b-4c3e-a3b5-7e8f9a0b1c2",
            "",
        ] {
            assert!(parse_canonical_uuid(text).is_none(), "case {text}");
        }
    }

    #[test]
    fn rejects_control_and_non_ascii_host_label_characters() {
        for label in [
            "a\nb",
            "a\tb",
            "a\u{0}b",
            "a\u{1b}[31mb",
            "a\u{200e}b",
            "a\u{202e}b",
            "café",
            "a b",
        ] {
            assert_eq!(
                HostLabel::new(label).validate(),
                Err(FieldViolation::InvalidCharacters(Field::HostLabel)),
                "case {label:?}"
            );
        }
        assert_eq!(
            HostLabel::new("desk-b.internal:5500").validate(),
            Ok(()),
            "ordinary labels stay accepted"
        );
    }

    #[test]
    fn agent_version_labels_are_bounded_and_restricted() {
        assert_eq!(
            AgentVersion::new("1.2.3-rc.1+5d3a9f0").validate(),
            Ok(()),
            "semver and git-describe labels stay accepted"
        );
        assert_eq!(
            AgentVersion::new("").validate(),
            Err(FieldViolation::Empty(Field::AgentVersion))
        );
        assert_eq!(
            AgentVersion::new("v".repeat(MAX_AGENT_VERSION_BYTES + 1)).validate(),
            Err(FieldViolation::TooLarge {
                field: Field::AgentVersion,
                length: MAX_AGENT_VERSION_BYTES + 1,
                limit: MAX_AGENT_VERSION_BYTES
            })
        );
        for label in ["1.0\n0", "1.0\t0", "1.0\u{0}", "v1\u{200e}", "vö"] {
            assert_eq!(
                AgentVersion::new(label).validate(),
                Err(FieldViolation::InvalidCharacters(Field::AgentVersion)),
                "case {label:?}"
            );
        }
    }
}
