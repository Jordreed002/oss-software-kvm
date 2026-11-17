//! Protocol version identity and inclusive-range negotiation.
//!
//! The protocol name and these schema versions are this contract's own
//! namespace, independent of legacy IPC and peer protocol versions. A
//! host/agent binary mismatch blocks unsafe mutations at the owner; it is
//! never resolved silently here.

use std::fmt;

use crate::message::ServerHello;

/// Lowest schema version this codec supports.
pub const MIN_SUPPORTED_VERSION: u32 = 1;

/// Highest schema version this codec supports.
pub const MAX_SUPPORTED_VERSION: u32 = 1;

/// Failure to negotiate or validate a schema version. Carries bounds only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionError {
    /// A version bound was zero; versions start at 1.
    Zero,
    /// A range was reversed (minimum greater than maximum).
    Reversed {
        /// The invalid minimum bound.
        min: u32,
        /// The invalid maximum bound.
        max: u32,
    },
    /// The client and server ranges have no overlap.
    NoOverlap {
        /// Client minimum bound.
        client_min: u32,
        /// Client maximum bound.
        client_max: u32,
        /// Server minimum bound.
        server_min: u32,
        /// Server maximum bound.
        server_max: u32,
    },
    /// A negotiated version fell outside the range a Hello advertised.
    NegotiatedOutsideAdvertised {
        /// The negotiated version.
        negotiated: u32,
        /// Advertised minimum bound.
        min: u32,
        /// Advertised maximum bound.
        max: u32,
    },
    /// A negotiated version is not supported by this codec.
    UnsupportedNegotiated {
        /// The unsupported negotiated version.
        version: u32,
    },
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => write!(f, "schema versions start at 1"),
            Self::Reversed { min, max } => {
                write!(
                    f,
                    "reversed version range: minimum {min} exceeds maximum {max}"
                )
            }
            Self::NoOverlap {
                client_min,
                client_max,
                server_min,
                server_max,
            } => write!(
                f,
                "no overlapping schema version between client [{client_min}, {client_max}] \
                 and server [{server_min}, {server_max}]"
            ),
            Self::NegotiatedOutsideAdvertised {
                negotiated,
                min,
                max,
            } => write!(
                f,
                "negotiated version {negotiated} falls outside the advertised range \
                 [{min}, {max}]"
            ),
            Self::UnsupportedNegotiated { version } => write!(
                f,
                "negotiated version {version} is not supported by this codec \
                 (supported range [{MIN_SUPPORTED_VERSION}, {MAX_SUPPORTED_VERSION}])"
            ),
        }
    }
}

impl std::error::Error for VersionError {}

/// Negotiates the highest schema version in the inclusive overlap of the
/// client's Hello range and this codec's supported range. Reversed or
/// zero-bearing client ranges are rejected explicitly rather than clamped.
///
/// # Errors
///
/// Returns [`VersionError::Zero`] for zero bounds, [`VersionError::Reversed`]
/// when the client minimum exceeds its maximum, and
/// [`VersionError::NoOverlap`] when the ranges share no version.
pub fn negotiate(client_min: u32, client_max: u32) -> Result<u32, VersionError> {
    validate_advertised_range(client_min, client_max)?;
    if client_min > MAX_SUPPORTED_VERSION || client_max < MIN_SUPPORTED_VERSION {
        return Err(VersionError::NoOverlap {
            client_min,
            client_max,
            server_min: MIN_SUPPORTED_VERSION,
            server_max: MAX_SUPPORTED_VERSION,
        });
    }
    Ok(client_max.min(MAX_SUPPORTED_VERSION))
}

/// Client-side acceptance of a server Hello: the client's own advertised
/// range must be well formed, the Hello must satisfy the invariants of
/// [`validate_negotiated`] (range valid, negotiated version inside the
/// server's advertised range and supported by this codec), and — the check
/// only the client can make — the chosen version must lie inside the range
/// the client offered. Protocol-name, instance and agent-version validation
/// belong to [`crate::codec::decode_server`]; this function is version-only.
///
/// # Errors
///
/// Returns [`VersionError::Zero`] or [`VersionError::Reversed`] for an
/// invalid client range or server range, [`VersionError::UnsupportedNegotiated`]
/// for a version this codec cannot speak, and
/// [`VersionError::NegotiatedOutsideAdvertised`] when the chosen version
/// falls outside either advertised range.
pub fn accept_server_hello(
    client_min: u32,
    client_max: u32,
    hello: &ServerHello,
) -> Result<u32, VersionError> {
    validate_advertised_range(client_min, client_max)?;
    validate_negotiated(
        hello.min_version,
        hello.max_version,
        hello.negotiated_version,
    )?;
    let negotiated = hello.negotiated_version;
    if negotiated < client_min || negotiated > client_max {
        return Err(VersionError::NegotiatedOutsideAdvertised {
            negotiated,
            min: client_min,
            max: client_max,
        });
    }
    Ok(negotiated)
}

/// Validates the inclusive range a Hello advertises: bounds at least 1 and
/// minimum not above maximum. Used by the codecs for both directions, so a
/// reversed or zero-bearing Hello is rejected even before negotiation runs.
pub(crate) fn validate_advertised_range(min: u32, max: u32) -> Result<(), VersionError> {
    if min == 0 || max == 0 {
        return Err(VersionError::Zero);
    }
    if min > max {
        return Err(VersionError::Reversed { min, max });
    }
    Ok(())
}

/// Validates a server Hello's advertised range and negotiated version: the
/// range satisfies [`validate_advertised_range`], the negotiated version lies
/// inside it, and this codec supports the negotiated version. Overlap policy
/// for client Hellos stays in [`negotiate`]; these are the invariants of the
/// message itself.
pub(crate) fn validate_negotiated(min: u32, max: u32, negotiated: u32) -> Result<(), VersionError> {
    validate_advertised_range(min, max)?;
    if negotiated < min || negotiated > max {
        return Err(VersionError::NegotiatedOutsideAdvertised {
            negotiated,
            min,
            max,
        });
    }
    if negotiated < MIN_SUPPORTED_VERSION || negotiated > MAX_SUPPORTED_VERSION {
        return Err(VersionError::UnsupportedNegotiated {
            version: negotiated,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{accept_server_hello, negotiate, validate_negotiated, VersionError};
    use crate::identity::{AgentVersion, InstanceId, ProtocolName};
    use crate::message::ServerHello;
    use uuid::Uuid;

    fn hello(min_version: u32, max_version: u32, negotiated_version: u32) -> ServerHello {
        ServerHello {
            protocol: ProtocolName::standard(),
            min_version,
            max_version,
            negotiated_version,
            instance: InstanceId::new(Uuid::from_u128(0x9d2c8a40_1f6b_4c3e_a3b5_7e8f9a0b1c2d))
                .expect("non-nil instance"),
            agent_version: AgentVersion::new("1.2.3-rc.1+5d3a9f0"),
        }
    }

    #[test]
    fn overlapping_ranges_negotiate_the_highest_common_version() {
        assert_eq!(negotiate(1, 1), Ok(1));
        assert_eq!(negotiate(1, 9), Ok(1));
    }

    #[test]
    fn malformed_and_disjoint_ranges_are_rejected_explicitly() {
        assert_eq!(negotiate(0, 1), Err(VersionError::Zero));
        assert_eq!(negotiate(1, 0), Err(VersionError::Zero));
        assert_eq!(
            negotiate(3, 1),
            Err(VersionError::Reversed { min: 3, max: 1 })
        );
        assert_eq!(
            negotiate(2, 3),
            Err(VersionError::NoOverlap {
                client_min: 2,
                client_max: 3,
                server_min: 1,
                server_max: 1
            })
        );
    }

    #[test]
    fn negotiated_versions_must_fit_the_advertised_and_supported_ranges() {
        assert_eq!(validate_negotiated(1, 5, 1), Ok(()));
        assert_eq!(
            validate_negotiated(1, 1, 2),
            Err(VersionError::NegotiatedOutsideAdvertised {
                negotiated: 2,
                min: 1,
                max: 1
            })
        );
        assert_eq!(
            validate_negotiated(1, 9, 3),
            Err(VersionError::UnsupportedNegotiated { version: 3 })
        );
        assert_eq!(
            validate_negotiated(3, 1, 1),
            Err(VersionError::Reversed { min: 3, max: 1 })
        );
    }

    #[test]
    fn client_accepts_only_a_chosen_version_inside_its_own_offered_range() {
        // The server Hello itself is valid: range 1..=3, chosen version 1.
        let reply = hello(1, 3, 1);
        assert_eq!(accept_server_hello(1, 1, &reply), Ok(1));
        assert_eq!(accept_server_hello(1, 3, &reply), Ok(1));

        // The same chosen version lies outside what a 2..=3 client offered.
        assert_eq!(
            accept_server_hello(2, 3, &reply),
            Err(VersionError::NegotiatedOutsideAdvertised {
                negotiated: 1,
                min: 2,
                max: 3
            })
        );

        // A server Hello whose internals are invalid is rejected too, and a
        // malformed client range never silently passes.
        assert_eq!(
            accept_server_hello(1, 1, &hello(1, 1, 2)),
            Err(VersionError::NegotiatedOutsideAdvertised {
                negotiated: 2,
                min: 1,
                max: 1
            })
        );
        assert_eq!(
            accept_server_hello(3, 1, &reply),
            Err(VersionError::Reversed { min: 3, max: 1 })
        );
        assert_eq!(
            accept_server_hello(1, 9, &hello(1, 9, 3)),
            Err(VersionError::UnsupportedNegotiated { version: 3 })
        );
    }
}
