use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Returned when a strongly typed identifier cannot be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseIdError;

impl fmt::Display for ParseIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid UUID identifier")
    }
}

impl std::error::Error for ParseIdError {}

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new random identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Constructs an identifier from its canonical 16-byte form.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(Uuid::from_bytes(bytes))
            }

            /// Returns the canonical 16-byte form.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 16] {
                self.0.into_bytes()
            }

            /// Parses a hyphenated, simple, URN, or braced UUID string.
            ///
            /// # Errors
            ///
            /// Returns [`ParseIdError`] if `value` is not a valid UUID.
            pub fn parse(value: &str) -> Result<Self, ParseIdError> {
                Uuid::parse_str(value).map(Self).map_err(|_| ParseIdError)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

define_id!(/// Identifies a machine participating in a KVM workspace.
    HostId);
define_id!(/// Identifies one physical input device where the platform permits it.
    DeviceId);
define_id!(/// Identifies one display independently of its owning host.
    DisplayId);
define_id!(/// Identifies an authenticated network peer identity.
    PeerId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_round_trips_through_text() {
        let id = HostId::from_bytes([0x11; 16]);
        let parsed: HostId = id.to_string().parse().unwrap();

        assert_eq!(parsed, id);
        assert_eq!(parsed.into_bytes(), [0x11; 16]);
    }

    #[test]
    fn identifier_types_do_not_share_an_api_conversion() {
        let bytes = [0x22; 16];
        let host = HostId::from_bytes(bytes);
        let device = DeviceId::from_bytes(bytes);

        assert_eq!(host.into_bytes(), device.into_bytes());
        assert_eq!(host.to_string(), device.to_string());
    }

    #[test]
    fn invalid_identifier_has_a_domain_error() {
        assert_eq!(HostId::parse("not-an-id"), Err(ParseIdError));
    }

    #[test]
    fn identifier_serializes_as_a_uuid_string() {
        let id = DisplayId::from_bytes([0x33; 16]);
        let json = serde_json::to_string(&id).unwrap();
        let decoded: DisplayId = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, id);
        assert_eq!(json, format!("\"{id}\""));
    }

    #[test]
    fn default_generates_distinct_non_nil_identifiers() {
        let first = PeerId::default();
        let second = PeerId::default();

        assert_ne!(first, second);
        assert_ne!(first.into_bytes(), [0; 16]);
    }

    #[test]
    fn identifier_debug_omits_stable_bytes() {
        let marker = "71717171-7171-7171-7171-717171717171";
        let id = HostId::parse(marker).unwrap();

        assert_eq!(format!("{id:?}"), "HostId([REDACTED])");
        assert!(!format!("{id:?}").contains(marker));
    }
}
