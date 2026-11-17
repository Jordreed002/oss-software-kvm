//! Route identities for bounded input admission.
//!
//! A route epoch is the triple process instance, peer identity and generation,
//! compared only for exact equality. These values carry identity, not
//! cryptographic authentication and not installed application identity:
//! presenting a matching epoch proves only that the caller holds a value an
//! engine with this identity minted. Debug output never reveals raw identifiers.

use core::fmt;

/// A nonzero process instance identity, minted once per engine-owning process.
///
/// A replacement process requires a fresh instance identity: epochs minted by
/// engines with different instance identities never compare equal, even when
/// their generation numbers coincide. The field is private and `0` can never
/// name a process.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InstanceId(u64);

impl InstanceId {
    /// Wraps a raw process instance identity.
    ///
    /// Returns `None` for `0`, which is reserved to mean "no process" and can
    /// never take part in a route epoch.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    /// Returns the raw process instance identity the owner supplied.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for InstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstanceId([REDACTED])")
    }
}

/// A nonzero peer identity naming the remote side of this engine's route.
///
/// The value is opaque here: this crate never mints, orders or interprets it.
/// The field is private and `0` can never name a peer.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PeerId(u64);

impl PeerId {
    /// Wraps a raw peer identity.
    ///
    /// Returns `None` for `0`, which is reserved to mean "no peer" and can
    /// never take part in a route epoch.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    /// Returns the raw peer identity the owner supplied.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerId([REDACTED])")
    }
}

/// The exact identity of one admitted input route.
///
/// A route epoch binds process instance, peer identity and one generation
/// allocated at activation. Admission, consumption and close all require exact
/// equality with the engine's current epoch: a stale epoch is rejected without
/// state changes and cannot enqueue into, consume from or fault the route it
/// no longer matches.
///
/// Only engine activation mints epochs; there is no public constructor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RouteEpoch {
    pub(crate) instance: InstanceId,
    pub(crate) peer: PeerId,
    pub(crate) generation: u64,
}

impl RouteEpoch {
    /// Returns the generation component of this epoch.
    ///
    /// A bare generation does not identify a route: it names neither the
    /// process instance nor the peer, and must never be used as an
    /// authorization token.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for RouteEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RouteEpoch([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_identities_are_rejected_at_construction() {
        assert_eq!(InstanceId::new(0), None);
        assert_eq!(PeerId::new(0), None);
        assert!(InstanceId::new(1).is_some());
        assert!(PeerId::new(u64::MAX).is_some());
    }

    #[test]
    fn raw_accessors_round_trip() {
        let instance_raw = 0xA1B2_C3D4_E5F6_0718;
        let peer_raw = 42_u64;

        assert_eq!(
            InstanceId::new(instance_raw).map(InstanceId::raw),
            Some(instance_raw)
        );
        assert_eq!(PeerId::new(peer_raw).map(PeerId::raw), Some(peer_raw));
    }

    #[test]
    fn identities_compare_by_value() {
        let a = InstanceId::new(7).expect("nonzero");
        let b = InstanceId::new(7).expect("nonzero");
        let c = InstanceId::new(8).expect("nonzero");
        let peer = PeerId::new(9).expect("nonzero");

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a.raw(), peer.raw());
    }

    #[test]
    fn epochs_compare_by_exact_triple() {
        let instance = InstanceId::new(7).expect("nonzero");
        let other_instance = InstanceId::new(8).expect("nonzero");
        let peer = PeerId::new(9).expect("nonzero");
        let other_peer = PeerId::new(10).expect("nonzero");

        let base = RouteEpoch {
            instance,
            peer,
            generation: 1,
        };

        assert_eq!(
            base,
            RouteEpoch {
                instance,
                peer,
                generation: 1
            }
        );
        assert_ne!(
            base,
            RouteEpoch {
                instance: other_instance,
                peer,
                generation: 1
            },
            "instance identity must distinguish epochs"
        );
        assert_ne!(
            base,
            RouteEpoch {
                instance,
                peer: other_peer,
                generation: 1
            },
            "peer identity must distinguish epochs"
        );
        assert_ne!(
            base,
            RouteEpoch {
                instance,
                peer,
                generation: 2
            },
            "generation must distinguish epochs"
        );
    }

    #[test]
    fn debug_output_redacts_all_identities() {
        let instance_raw = 700_123_456_789_u64;
        let peer_raw = 700_987_654_321_u64;
        let instance = InstanceId::new(instance_raw).expect("nonzero");
        let peer = PeerId::new(peer_raw).expect("nonzero");
        let epoch = RouteEpoch {
            instance,
            peer,
            generation: 1,
        };

        assert_eq!(format!("{instance:?}"), "InstanceId([REDACTED])");
        assert_eq!(format!("{peer:?}"), "PeerId([REDACTED])");
        assert_eq!(format!("{epoch:?}"), "RouteEpoch([REDACTED])");

        for text in [
            format!("{instance:?}"),
            format!("{peer:?}"),
            format!("{epoch:?}"),
        ] {
            assert!(!text.contains(&instance_raw.to_string()), "leak: {text}");
            assert!(!text.contains(&peer_raw.to_string()), "leak: {text}");
        }
    }
}
