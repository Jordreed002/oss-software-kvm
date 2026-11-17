//! Canonical decimal-string encoding for 64-bit identifiers and revisions.
//!
//! These values never travel as JSON numbers: JavaScript consumers cannot
//! represent every `u64` exactly, so the wire form is a canonical decimal
//! string. Canonical means non-empty, ASCII digits only, no leading zeros
//! unless the value is exactly zero, and within `u64` range. Canonicality
//! applies to the decoded string, not the raw JSON text: JSON escapes such
//! as `"42"` decode to `"42"` and are accepted, matching
//! `JSON.parse` semantics in TypeScript consumers.

use serde::{
    de::{Error as SerdeError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

/// Digit count of `u64::MAX`; longer strings are rejected without parsing.
const MAX_DIGITS: usize = 20;

/// Parses one canonical decimal string, or `None` for any noncanonical form:
/// empty, overlong, non-ASCII-digit, signed, whitespace-padded, leading-zero
/// or overflowing input.
#[must_use]
pub(crate) fn parse_canonical(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > MAX_DIGITS {
        return None;
    }
    let bytes = text.as_bytes();
    if !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if bytes[0] == b'0' {
        return if text.len() == 1 { Some(0) } else { None };
    }
    text.parse::<u64>().ok()
}

pub(crate) fn serialize_u64_as_string<S>(value: u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

pub(crate) fn deserialize_decimal<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct CanonicalDecimalVisitor;

    impl Visitor<'_> for CanonicalDecimalVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a canonical decimal string of an unsigned 64-bit integer")
        }

        fn visit_str<E>(self, text: &str) -> Result<Self::Value, E>
        where
            E: SerdeError,
        {
            parse_canonical(text)
                .ok_or_else(|| E::custom("noncanonical or out-of-range decimal string"))
        }
    }

    deserializer.deserialize_str(CanonicalDecimalVisitor)
}

macro_rules! decimal_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name(u64);

        impl $name {
            /// Wraps a 64-bit value. Every `u64` is representable; the
            /// canonical-string rule is a wire-format constraint only.
            #[must_use]
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Returns the wrapped 64-bit value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                $crate::decimal::serialize_u64_as_string(self.0, serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                $crate::decimal::deserialize_decimal(deserializer).map(Self)
            }
        }
    };
}

decimal_newtype! {
    /// Client-supplied correlation identifier, echoed by the server in the
    /// matching reply. Unique per client instance; never a JSON number.
    CorrelationId
}

decimal_newtype! {
    /// Monotonic snapshot revision. Observers resynchronize on gaps.
    Revision
}

decimal_newtype! {
    /// Session identifier of a remote input-authority target.
    SessionId
}

decimal_newtype! {
    /// Session generation of a remote input-authority target; late events
    /// from a retired generation cannot reactivate it.
    Generation
}

#[cfg(test)]
mod tests {
    use super::parse_canonical;

    #[test]
    fn accepts_canonical_forms_only() {
        assert_eq!(parse_canonical("0"), Some(0));
        assert_eq!(parse_canonical("1"), Some(1));
        assert_eq!(parse_canonical("18446744073709551615"), Some(u64::MAX));
    }

    #[test]
    fn rejects_noncanonical_forms() {
        for text in [
            "",
            "007",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1.0",
            "0x10",
            "1e3",
            "１",
            "18446744073709551616",
            "999999999999999999999999",
        ] {
            assert_eq!(parse_canonical(text), None, "case {text:?}");
        }
    }
}
