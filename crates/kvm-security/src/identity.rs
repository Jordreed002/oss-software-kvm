use core::{fmt, str::FromStr};

use kvm_types::{HostId, PeerId};
use thiserror::Error;

const FINGERPRINT_BYTES: usize = 32;
const MAX_DISPLAY_NAME_BYTES: usize = 128;

/// SHA-256 fingerprint of a peer's long-term public identity credential.
///
/// Hashing is deliberately performed by the TLS/credential implementation;
/// this type only carries the resulting digest.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityFingerprint([u8; FINGERPRINT_BYTES]);

impl IdentityFingerprint {
    /// Creates a fingerprint from an already-computed SHA-256 digest.
    #[must_use]
    pub const fn from_sha256(bytes: [u8; FINGERPRINT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the fingerprint digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FINGERPRINT_BYTES] {
        &self.0
    }
}

impl fmt::Display for IdentityFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for IdentityFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("IdentityFingerprint")
            .field(&self.to_string())
            .finish()
    }
}

impl FromStr for IdentityFingerprint {
    type Err = ParseFingerprintError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != FINGERPRINT_BYTES * 2 {
            return Err(ParseFingerprintError::InvalidLength {
                actual: value.len(),
            });
        }

        let mut bytes = [0_u8; FINGERPRINT_BYTES];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex_digit(pair[0], index * 2)?;
            let low = decode_hex_digit(pair[1], index * 2 + 1)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

fn decode_hex_digit(value: u8, index: usize) -> Result<u8, ParseFingerprintError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ParseFingerprintError::InvalidHex { index }),
    }
}

/// Failure to parse a textual identity fingerprint.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ParseFingerprintError {
    /// The input was not the 64 hexadecimal characters required by SHA-256.
    #[error("fingerprint must contain 64 hexadecimal characters, got {actual}")]
    InvalidLength { actual: usize },
    /// A character at the given byte offset was not hexadecimal.
    #[error("fingerprint contains a non-hexadecimal character at byte {index}")]
    InvalidHex { index: usize },
}

/// Public metadata that identifies a peer and binds it to a long-term key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    peer_id: PeerId,
    host_id: HostId,
    display_name: String,
    fingerprint: IdentityFingerprint,
}

impl PeerIdentity {
    /// Creates validated public identity metadata.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] for an empty, oversized, or control-character
    /// containing display name.
    pub fn new(
        peer_id: PeerId,
        host_id: HostId,
        display_name: impl Into<String>,
        fingerprint: IdentityFingerprint,
    ) -> Result<Self, IdentityError> {
        let display_name = display_name.into();
        if display_name.trim().is_empty() {
            return Err(IdentityError::EmptyDisplayName);
        }
        if display_name.len() > MAX_DISPLAY_NAME_BYTES {
            return Err(IdentityError::DisplayNameTooLong {
                actual: display_name.len(),
                maximum: MAX_DISPLAY_NAME_BYTES,
            });
        }
        if display_name.chars().any(char::is_control) {
            return Err(IdentityError::ControlCharacterInDisplayName);
        }

        Ok(Self {
            peer_id,
            host_id,
            display_name,
            fingerprint,
        })
    }

    /// Stable peer identifier.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Host represented by this peer process.
    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    /// Human-readable name, never used for authentication.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Fingerprint of the long-term public credential.
    #[must_use]
    pub const fn fingerprint(&self) -> IdentityFingerprint {
        self.fingerprint
    }
}

/// Invalid public identity metadata.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IdentityError {
    /// The human-readable peer name was blank.
    #[error("peer display name must not be empty")]
    EmptyDisplayName,
    /// The human-readable peer name exceeded its storage bound.
    #[error("peer display name is {actual} bytes; the maximum is {maximum}")]
    DisplayNameTooLong { actual: usize, maximum: usize },
    /// The human-readable peer name contained a control character.
    #[error("peer display name must not contain control characters")]
    ControlCharacterInDisplayName,
}

/// An identity advertised through discovery, with no trust attached.
///
/// This type cannot be passed to input authorization. Discovery is only a way
/// to find a candidate peer for pairing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredPeer {
    identity: PeerIdentity,
}

impl DiscoveredPeer {
    /// Wraps identity metadata observed through an untrusted discovery channel.
    #[must_use]
    pub const fn new(identity: PeerIdentity) -> Self {
        Self { identity }
    }

    /// Returns the untrusted advertised identity.
    #[must_use]
    pub const fn identity(&self) -> &PeerIdentity {
        &self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_round_trips_through_hex() {
        let fingerprint = IdentityFingerprint::from_sha256([0xab; 32]);
        let encoded = fingerprint.to_string();

        assert_eq!(encoded.len(), 64);
        assert_eq!(encoded.parse(), Ok(fingerprint));
        assert_eq!(encoded.to_uppercase().parse(), Ok(fingerprint));
    }

    #[test]
    fn fingerprint_parser_reports_bad_input() {
        assert_eq!(
            "00".parse::<IdentityFingerprint>(),
            Err(ParseFingerprintError::InvalidLength { actual: 2 })
        );
        let invalid = format!("{}z", "0".repeat(63));
        assert_eq!(
            invalid.parse::<IdentityFingerprint>(),
            Err(ParseFingerprintError::InvalidHex { index: 63 })
        );
    }

    #[test]
    fn identity_validates_display_name() {
        let result = PeerIdentity::new(
            PeerId::from_bytes([1; 16]),
            HostId::from_bytes([2; 16]),
            "\n",
            IdentityFingerprint::from_sha256([3; 32]),
        );

        assert_eq!(result, Err(IdentityError::EmptyDisplayName));
    }
}
