use std::cmp::Ordering;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use kvm_types::PeerId;

pub const SOFTWARE_KVM_SERVICE_TYPE: &str = "_software-kvm._tcp.local.";
pub const DISCOVERY_PROTOCOL_VERSION: &str = "1";

pub const MAX_FULLNAME_BYTES: usize = 255;
pub const MAX_HOSTNAME_BYTES: usize = 255;
pub const MAX_INSTANCE_NAME_BYTES: usize = 63;
pub const MAX_TXT_PROPERTIES: usize = 8;
pub const MAX_TXT_KEY_BYTES: usize = 16;
pub const MAX_TXT_VALUE_BYTES: usize = 128;
pub const MAX_ADDRESSES_PER_SERVICE: usize = 8;
pub const MAX_DISCOVERY_SERVICES: usize = 128;
pub const MAX_DISCOVERY_CANDIDATES: usize = MAX_DISCOVERY_SERVICES * MAX_ADDRESSES_PER_SERVICE;

/// One raw TXT property before validation. Values are bytes by DNS-SD design.
pub struct RawTxtProperty {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

impl fmt::Debug for RawTxtProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawTxtProperty")
            .field("key_bytes", &self.key.len())
            .field("value_bytes", &self.value.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

/// Hostile service-resolution input for the deterministic parser/cache.
pub struct RawDiscoveryRecord {
    pub service_type: Vec<u8>,
    pub fullname: Vec<u8>,
    pub hostname: Vec<u8>,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
    pub txt: Vec<RawTxtProperty>,
    pub ttl: Duration,
}

impl fmt::Debug for RawDiscoveryRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawDiscoveryRecord")
            .field("service_type_bytes", &self.service_type.len())
            .field("fullname_bytes", &self.fullname.len())
            .field("hostname_bytes", &self.hostname.len())
            .field("port_present", &(self.port != 0))
            .field("address_count", &self.addresses.len())
            .field("txt_property_count", &self.txt.len())
            .field("ttl_seconds", &self.ttl.as_secs())
            .finish_non_exhaustive()
    }
}

/// One deterministic untrusted reachability candidate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DiscoveryCandidate {
    peer_id_hint: PeerId,
    address: SocketAddr,
}

impl DiscoveryCandidate {
    pub(crate) const fn new(peer_id_hint: PeerId, address: SocketAddr) -> Self {
        Self {
            peer_id_hint,
            address,
        }
    }

    #[must_use]
    pub const fn peer_id_hint(self) -> PeerId {
        self.peer_id_hint
    }

    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.address
    }
}

impl fmt::Debug for DiscoveryCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryCandidate")
            .field("address_family", &address_family(self.address.ip()))
            .field("peer_id_hint", &"[REDACTED]")
            .field("address", &"[REDACTED]")
            .finish()
    }
}

impl Ord for DiscoveryCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.peer_id_hint
            .cmp(&other.peer_id_hint)
            .then_with(|| compare_socket_addresses(self.address, other.address))
    }
}

impl PartialOrd for DiscoveryCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Immutable, sorted, deduplicated discovery view for scheduler consumption.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct DiscoverySnapshot {
    candidates: Vec<DiscoveryCandidate>,
}

impl DiscoverySnapshot {
    pub(crate) fn from_candidates(mut candidates: Vec<DiscoveryCandidate>) -> Self {
        candidates.sort_unstable();
        candidates.dedup();
        candidates.truncate(MAX_DISCOVERY_CANDIDATES);
        Self { candidates }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Deterministic addresses for one untrusted peer-ID hint.
    pub fn candidates_for(&self, peer_id: PeerId) -> impl Iterator<Item = SocketAddr> + '_ {
        self.candidates
            .iter()
            .filter(move |candidate| candidate.peer_id_hint == peer_id)
            .map(|candidate| candidate.address)
    }

    /// All candidates, sorted by peer hint then IPv4/IPv6 address and port.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = DiscoveryCandidate> + '_ {
        self.candidates.iter().copied()
    }
}

impl fmt::Debug for DiscoverySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unique_peers = self
            .candidates
            .iter()
            .map(|candidate| candidate.peer_id_hint)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        formatter
            .debug_struct("DiscoverySnapshot")
            .field("peer_hint_count", &unique_peers)
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

#[must_use]
pub const fn is_supported_lan_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => (address.octets()[0] & 0xfe) == 0xfc,
    }
}

fn compare_socket_addresses(left: SocketAddr, right: SocketAddr) -> Ordering {
    match (left, right) {
        (SocketAddr::V4(left), SocketAddr::V4(right)) => left
            .ip()
            .octets()
            .cmp(&right.ip().octets())
            .then_with(|| left.port().cmp(&right.port())),
        (SocketAddr::V6(left), SocketAddr::V6(right)) => left
            .ip()
            .octets()
            .cmp(&right.ip().octets())
            .then_with(|| left.port().cmp(&right.port())),
        (SocketAddr::V4(_), SocketAddr::V6(_)) => Ordering::Less,
        (SocketAddr::V6(_), SocketAddr::V4(_)) => Ordering::Greater,
    }
}

const fn address_family(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "IPv4",
        IpAddr::V6(_) => "IPv6",
    }
}
