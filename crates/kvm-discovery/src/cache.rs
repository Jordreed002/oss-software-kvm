use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::str;
use std::time::Duration;

use kvm_types::PeerId;
use thiserror::Error;

use crate::model::{
    is_supported_lan_address, DiscoveryCandidate, DiscoverySnapshot, RawDiscoveryRecord,
    DISCOVERY_PROTOCOL_VERSION, MAX_ADDRESSES_PER_SERVICE, MAX_DISCOVERY_SERVICES,
    MAX_FULLNAME_BYTES, MAX_HOSTNAME_BYTES, MAX_INSTANCE_NAME_BYTES, MAX_TXT_KEY_BYTES,
    MAX_TXT_PROPERTIES, MAX_TXT_VALUE_BYTES, SOFTWARE_KVM_SERVICE_TYPE,
};

const MIN_CACHE_TTL: Duration = Duration::from_secs(1);
const MAX_CACHE_TTL: Duration = Duration::from_mins(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryCacheConfig {
    pub maximum_services: usize,
    pub minimum_ttl: Duration,
    pub maximum_ttl: Duration,
}

impl Default for DiscoveryCacheConfig {
    fn default() -> Self {
        Self {
            maximum_services: MAX_DISCOVERY_SERVICES,
            minimum_ttl: MIN_CACHE_TTL,
            maximum_ttl: MAX_CACHE_TTL,
        }
    }
}

impl DiscoveryCacheConfig {
    /// Validates every positive cache and expiry bound.
    ///
    /// # Errors
    ///
    /// Rejects zero, reversed, or compile-time-maximum-exceeding values.
    pub fn validate(self) -> Result<(), DiscoveryCacheError> {
        if self.maximum_services == 0 || self.maximum_services > MAX_DISCOVERY_SERVICES {
            return Err(DiscoveryCacheError::InvalidConfig);
        }
        if self.minimum_ttl < MIN_CACHE_TTL
            || self.minimum_ttl > self.maximum_ttl
            || self.maximum_ttl > MAX_CACHE_TTL
        {
            return Err(DiscoveryCacheError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryCacheChange {
    Changed,
    Unchanged,
    Saturated,
}

/// Coarse hostile-input rejection. Variants never retain raw record data.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DiscoveryCacheError {
    #[error("discovery cache configuration is invalid")]
    InvalidConfig,
    #[error("discovery record name is invalid")]
    InvalidName,
    #[error("discovery record TXT data is invalid")]
    InvalidTxt,
    #[error("discovery record protocol version is unsupported")]
    UnsupportedVersion,
    #[error("discovery record peer hint is invalid")]
    InvalidPeerHint,
    #[error("discovery record port is invalid")]
    InvalidPort,
    #[error("discovery record address data is invalid")]
    InvalidAddresses,
    #[error("discovery record expiry is invalid")]
    InvalidExpiry,
}

#[derive(Clone, Eq, PartialEq)]
struct CachedService {
    peer_id_hint: PeerId,
    addresses: Vec<SocketAddr>,
    expires_at: Duration,
}

/// Deterministic cache keyed by exact DNS-SD service fullname.
pub struct DiscoveryCache {
    config: DiscoveryCacheConfig,
    services: BTreeMap<String, CachedService>,
}

impl DiscoveryCache {
    /// Creates an empty cache with positive resource and TTL bounds.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryCacheError::InvalidConfig`] for invalid bounds.
    pub fn new(config: DiscoveryCacheConfig) -> Result<Self, DiscoveryCacheError> {
        config.validate()?;
        Ok(Self {
            config,
            services: BTreeMap::new(),
        })
    }

    /// Parses and applies one resolved service at monotonic `now`.
    ///
    /// A zero TTL is a goodbye for this exact fullname. At capacity, an update
    /// to an existing fullname is allowed but an unrelated new owner cannot
    /// evict a current record.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, unsupported, unsafe, or overflowing data
    /// without mutating the cache.
    pub fn apply_resolved(
        &mut self,
        record: RawDiscoveryRecord,
        now: Duration,
    ) -> Result<DiscoveryCacheChange, DiscoveryCacheError> {
        if record.service_type.as_slice() != SOFTWARE_KVM_SERVICE_TYPE.as_bytes() {
            return Err(DiscoveryCacheError::InvalidName);
        }
        let fullname = parse_fullname(&record)?.to_owned();
        if record.ttl == Duration::ZERO {
            return Ok(if self.services.remove(&fullname).is_some() {
                DiscoveryCacheChange::Changed
            } else {
                DiscoveryCacheChange::Unchanged
            });
        }

        let parsed = parse_record(record, now, self.config)?;
        if !self.services.contains_key(&fullname)
            && self.services.len() >= self.config.maximum_services
        {
            return Ok(DiscoveryCacheChange::Saturated);
        }
        let changed = self.services.get(&fullname) != Some(&parsed);
        if changed {
            self.services.insert(fullname, parsed);
            Ok(DiscoveryCacheChange::Changed)
        } else {
            Ok(DiscoveryCacheChange::Unchanged)
        }
    }

    /// Removes only the exact bounded service fullname from a goodbye event.
    ///
    /// # Errors
    ///
    /// Rejects malformed or oversized removal names without changing state.
    pub fn remove_fullname(
        &mut self,
        fullname: &[u8],
    ) -> Result<DiscoveryCacheChange, DiscoveryCacheError> {
        let fullname = validate_fullname_bytes(fullname)?;
        Ok(if self.services.remove(fullname).is_some() {
            DiscoveryCacheChange::Changed
        } else {
            DiscoveryCacheChange::Unchanged
        })
    }

    /// Expires every record whose clamped deadline is not newer than `now`.
    pub fn expire(&mut self, now: Duration) -> DiscoveryCacheChange {
        let before = self.services.len();
        self.services.retain(|_, service| service.expires_at > now);
        if self.services.len() == before {
            DiscoveryCacheChange::Unchanged
        } else {
            DiscoveryCacheChange::Changed
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> DiscoverySnapshot {
        let candidates = self
            .services
            .values()
            .flat_map(|service| {
                service
                    .addresses
                    .iter()
                    .copied()
                    .map(|address| DiscoveryCandidate::new(service.peer_id_hint, address))
            })
            .collect();
        DiscoverySnapshot::from_candidates(candidates)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.services.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }
}

impl fmt::Debug for DiscoveryCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryCache")
            .field("service_count", &self.services.len())
            .field("candidate_count", &self.snapshot().len())
            .finish_non_exhaustive()
    }
}

fn parse_record(
    record: RawDiscoveryRecord,
    now: Duration,
    config: DiscoveryCacheConfig,
) -> Result<CachedService, DiscoveryCacheError> {
    validate_record_shape(&record)?;
    let (version, peer_id_hint) = parse_txt(&record)?;
    if version != DISCOVERY_PROTOCOL_VERSION {
        return Err(DiscoveryCacheError::UnsupportedVersion);
    }

    let peer_id_hint = parse_canonical_peer_id(peer_id_hint)?;
    let mut addresses = BTreeSet::new();
    for address in record.addresses {
        if is_supported_lan_address(address) {
            addresses.insert(SocketAddr::new(address, record.port));
        }
    }
    if addresses.is_empty() {
        return Err(DiscoveryCacheError::InvalidAddresses);
    }

    let ttl = record.ttl.clamp(config.minimum_ttl, config.maximum_ttl);
    let expires_at = now
        .checked_add(ttl)
        .ok_or(DiscoveryCacheError::InvalidExpiry)?;
    Ok(CachedService {
        peer_id_hint,
        addresses: addresses.into_iter().collect(),
        expires_at,
    })
}

fn validate_record_shape(record: &RawDiscoveryRecord) -> Result<(), DiscoveryCacheError> {
    if record.service_type.as_slice() != SOFTWARE_KVM_SERVICE_TYPE.as_bytes()
        || !valid_hostname(&record.hostname)
    {
        return Err(DiscoveryCacheError::InvalidName);
    }
    parse_fullname(record)?;
    if record.port == 0 {
        return Err(DiscoveryCacheError::InvalidPort);
    }
    if record.addresses.is_empty() || record.addresses.len() > MAX_ADDRESSES_PER_SERVICE {
        return Err(DiscoveryCacheError::InvalidAddresses);
    }
    if record.txt.len() > MAX_TXT_PROPERTIES {
        return Err(DiscoveryCacheError::InvalidTxt);
    }
    for property in &record.txt {
        if property.key.is_empty()
            || property.key.len() > MAX_TXT_KEY_BYTES
            || property
                .value
                .as_ref()
                .is_none_or(|value| value.len() > MAX_TXT_VALUE_BYTES)
        {
            return Err(DiscoveryCacheError::InvalidTxt);
        }
    }
    Ok(())
}

fn valid_hostname(hostname: &[u8]) -> bool {
    if hostname.is_empty() || hostname.len() > MAX_HOSTNAME_BYTES {
        return false;
    }
    let Ok(hostname) = str::from_utf8(hostname) else {
        return false;
    };
    hostname
        .strip_suffix(".local.")
        .is_some_and(|label| !label.is_empty() && !label.chars().any(char::is_control))
}

fn parse_fullname(record: &RawDiscoveryRecord) -> Result<&str, DiscoveryCacheError> {
    validate_fullname_bytes(&record.fullname)
}

fn validate_fullname_bytes(fullname: &[u8]) -> Result<&str, DiscoveryCacheError> {
    if fullname.is_empty() || fullname.len() > MAX_FULLNAME_BYTES {
        return Err(DiscoveryCacheError::InvalidName);
    }
    let fullname = str::from_utf8(fullname).map_err(|_| DiscoveryCacheError::InvalidName)?;
    let instance = fullname
        .strip_suffix(SOFTWARE_KVM_SERVICE_TYPE)
        .ok_or(DiscoveryCacheError::InvalidName)?;
    if instance.is_empty()
        || instance.len() > MAX_INSTANCE_NAME_BYTES
        || instance.chars().any(char::is_control)
    {
        return Err(DiscoveryCacheError::InvalidName);
    }
    Ok(fullname)
}

fn parse_txt(record: &RawDiscoveryRecord) -> Result<(&str, &str), DiscoveryCacheError> {
    let mut version = None;
    let mut peer = None;
    for property in &record.txt {
        let key = str::from_utf8(&property.key).map_err(|_| DiscoveryCacheError::InvalidTxt)?;
        let value = property
            .value
            .as_deref()
            .ok_or(DiscoveryCacheError::InvalidTxt)?;
        let value = str::from_utf8(value).map_err(|_| DiscoveryCacheError::InvalidTxt)?;
        match key {
            "ver" if version.replace(value).is_none() => {}
            "peer" if peer.replace(value).is_none() => {}
            _ => return Err(DiscoveryCacheError::InvalidTxt),
        }
    }
    Ok((
        version.ok_or(DiscoveryCacheError::InvalidTxt)?,
        peer.ok_or(DiscoveryCacheError::InvalidTxt)?,
    ))
}

fn parse_canonical_peer_id(value: &str) -> Result<PeerId, DiscoveryCacheError> {
    if value.len() != 36 {
        return Err(DiscoveryCacheError::InvalidPeerHint);
    }
    let peer = PeerId::parse(value).map_err(|_| DiscoveryCacheError::InvalidPeerHint)?;
    if peer.into_bytes() == [0; 16] || peer.to_string() != value {
        return Err(DiscoveryCacheError::InvalidPeerHint);
    }
    Ok(peer)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::{RawTxtProperty, SOFTWARE_KVM_SERVICE_TYPE};

    const PEER: &str = "11111111-1111-1111-1111-111111111111";

    fn record(fullname: &str, peer: &str, address: IpAddr) -> RawDiscoveryRecord {
        RawDiscoveryRecord {
            service_type: SOFTWARE_KVM_SERVICE_TYPE.as_bytes().to_vec(),
            fullname: fullname.as_bytes().to_vec(),
            hostname: b"peer.local.".to_vec(),
            port: 4242,
            addresses: vec![address],
            txt: vec![
                RawTxtProperty {
                    key: b"ver".to_vec(),
                    value: Some(b"1".to_vec()),
                },
                RawTxtProperty {
                    key: b"peer".to_vec(),
                    value: Some(peer.as_bytes().to_vec()),
                },
            ],
            ttl: Duration::from_secs(30),
        }
    }

    fn cache() -> DiscoveryCache {
        DiscoveryCache::new(DiscoveryCacheConfig::default()).unwrap()
    }

    #[test]
    fn exact_record_produces_deterministic_private_candidates() {
        let mut cache = cache();
        let mut input = record(
            "one._software-kvm._tcp.local.",
            PEER,
            IpAddr::V6("fd00::2".parse::<Ipv6Addr>().unwrap()),
        );
        input.addresses.extend([
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
        ]);
        assert_eq!(
            cache.apply_resolved(input, Duration::ZERO),
            Ok(DiscoveryCacheChange::Changed)
        );

        let peer = PeerId::parse(PEER).unwrap();
        assert_eq!(
            cache.snapshot().candidates_for(peer).collect::<Vec<_>>(),
            vec![
                "10.0.0.3:4242".parse().unwrap(),
                "192.168.1.4:4242".parse().unwrap(),
                "[fd00::2]:4242".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn malformed_oversized_non_utf8_and_unknown_txt_are_rejected() {
        let cases = [
            {
                let mut value = record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.1".parse().unwrap(),
                );
                value.txt[0].value = Some(vec![0xff]);
                value
            },
            {
                let mut value = record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.1".parse().unwrap(),
                );
                value.txt[0].value = Some(vec![b'x'; MAX_TXT_VALUE_BYTES + 1]);
                value
            },
            {
                let mut value = record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.1".parse().unwrap(),
                );
                value.txt.push(RawTxtProperty {
                    key: b"fingerprint".to_vec(),
                    value: Some(b"forbidden".to_vec()),
                });
                value
            },
            {
                let mut value = record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.1".parse().unwrap(),
                );
                value.txt = (0..=MAX_TXT_PROPERTIES)
                    .map(|_| RawTxtProperty {
                        key: b"x".to_vec(),
                        value: Some(b"y".to_vec()),
                    })
                    .collect();
                value
            },
        ];
        for value in cases {
            assert!(matches!(
                cache().apply_resolved(value, Duration::ZERO),
                Err(DiscoveryCacheError::InvalidTxt)
            ));
        }
    }

    #[test]
    fn malformed_or_oversized_service_names_are_rejected() {
        let cases = [
            {
                let mut value = record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.1".parse().unwrap(),
                );
                value.fullname = b"one\n._software-kvm._tcp.local.".to_vec();
                value
            },
            {
                let mut value = record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.1".parse().unwrap(),
                );
                value.hostname = b"peer\n.local.".to_vec();
                value
            },
            {
                let mut value = record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.1".parse().unwrap(),
                );
                value.hostname = vec![b'x'; MAX_HOSTNAME_BYTES + 1];
                value
            },
        ];
        for value in cases {
            assert_eq!(
                cache().apply_resolved(value, Duration::ZERO),
                Err(DiscoveryCacheError::InvalidName)
            );
        }
    }

    #[test]
    fn nil_noncanonical_and_wrong_version_peer_hints_fail_closed() {
        for peer in [
            "00000000-0000-0000-0000-000000000000",
            "11111111111111111111111111111111",
            "11111111-1111-1111-1111-11111111111A",
        ] {
            assert!(matches!(
                cache().apply_resolved(
                    record(
                        "one._software-kvm._tcp.local.",
                        peer,
                        "10.0.0.1".parse().unwrap()
                    ),
                    Duration::ZERO
                ),
                Err(DiscoveryCacheError::InvalidPeerHint)
            ));
        }
        let mut wrong = record(
            "one._software-kvm._tcp.local.",
            PEER,
            "10.0.0.1".parse().unwrap(),
        );
        wrong.txt[0].value = Some(b"2".to_vec());
        assert_eq!(
            cache().apply_resolved(wrong, Duration::ZERO),
            Err(DiscoveryCacheError::UnsupportedVersion)
        );
    }

    #[test]
    fn unsafe_addresses_and_zero_port_are_rejected() {
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "8.8.8.8",
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
            "2001:4860:4860::8888",
        ] {
            let value = record(
                "one._software-kvm._tcp.local.",
                PEER,
                address.parse().unwrap(),
            );
            assert_eq!(
                cache().apply_resolved(value, Duration::ZERO),
                Err(DiscoveryCacheError::InvalidAddresses)
            );
        }
        let mut value = record(
            "one._software-kvm._tcp.local.",
            PEER,
            "10.0.0.1".parse().unwrap(),
        );
        value.port = 0;
        assert_eq!(
            cache().apply_resolved(value, Duration::ZERO),
            Err(DiscoveryCacheError::InvalidPort)
        );
    }

    #[test]
    fn duplicate_claims_remain_independently_owned_by_fullname() {
        let mut cache = cache();
        cache
            .apply_resolved(
                record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.2".parse().unwrap(),
                ),
                Duration::ZERO,
            )
            .unwrap();
        cache
            .apply_resolved(
                record(
                    "two._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.3".parse().unwrap(),
                ),
                Duration::ZERO,
            )
            .unwrap();
        let peer = PeerId::parse(PEER).unwrap();
        assert_eq!(cache.snapshot().candidates_for(peer).count(), 2);

        cache
            .remove_fullname(b"one._software-kvm._tcp.local.")
            .unwrap();
        assert_eq!(
            cache.snapshot().candidates_for(peer).collect::<Vec<_>>(),
            vec!["10.0.0.3:4242".parse().unwrap()]
        );
    }

    #[test]
    fn ttl_is_clamped_expires_and_unrelated_events_never_extend_it() {
        let mut cache = cache();
        let mut short = record(
            "one._software-kvm._tcp.local.",
            PEER,
            "10.0.0.2".parse().unwrap(),
        );
        short.ttl = Duration::from_millis(1);
        cache
            .apply_resolved(short, Duration::from_secs(10))
            .unwrap();

        assert_eq!(
            cache.expire(Duration::from_millis(10_999)),
            DiscoveryCacheChange::Unchanged
        );
        let _ = cache.remove_fullname(b"unrelated._software-kvm._tcp.local.");
        assert_eq!(
            cache.expire(Duration::from_secs(11)),
            DiscoveryCacheChange::Changed
        );
        assert!(cache.is_empty());

        let mut long = record(
            "two._software-kvm._tcp.local.",
            PEER,
            "10.0.0.3".parse().unwrap(),
        );
        long.ttl = Duration::from_secs(99_999);
        cache.apply_resolved(long, Duration::ZERO).unwrap();
        assert_eq!(
            cache.expire(Duration::from_secs(299)),
            DiscoveryCacheChange::Unchanged
        );
        assert_eq!(
            cache.expire(Duration::from_mins(5)),
            DiscoveryCacheChange::Changed
        );
    }

    #[test]
    fn goodbye_removes_exact_owner_without_parsing_hostile_txt() {
        let mut cache = cache();
        cache
            .apply_resolved(
                record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.2".parse().unwrap(),
                ),
                Duration::ZERO,
            )
            .unwrap();
        let mut goodbye = record(
            "one._software-kvm._tcp.local.",
            "not-a-peer",
            "8.8.8.8".parse().unwrap(),
        );
        goodbye.ttl = Duration::ZERO;
        goodbye.txt.clear();
        assert_eq!(
            cache.apply_resolved(goodbye, Duration::from_secs(1)),
            Ok(DiscoveryCacheChange::Changed)
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn wrong_service_type_goodbye_cannot_remove_existing_owner() {
        let mut cache = cache();
        cache
            .apply_resolved(
                record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.2".parse().unwrap(),
                ),
                Duration::ZERO,
            )
            .unwrap();
        let mut goodbye = record(
            "one._software-kvm._tcp.local.",
            PEER,
            "10.0.0.2".parse().unwrap(),
        );
        goodbye.service_type = b"_other._tcp.local.".to_vec();
        goodbye.ttl = Duration::ZERO;

        assert_eq!(
            cache.apply_resolved(goodbye, Duration::from_secs(1)),
            Err(DiscoveryCacheError::InvalidName)
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_saturation_never_evicts_existing_service() {
        let mut cache = DiscoveryCache::new(DiscoveryCacheConfig {
            maximum_services: 1,
            ..DiscoveryCacheConfig::default()
        })
        .unwrap();
        cache
            .apply_resolved(
                record(
                    "one._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.2".parse().unwrap(),
                ),
                Duration::ZERO,
            )
            .unwrap();
        assert_eq!(
            cache.apply_resolved(
                record(
                    "two._software-kvm._tcp.local.",
                    PEER,
                    "10.0.0.3".parse().unwrap()
                ),
                Duration::ZERO,
            ),
            Ok(DiscoveryCacheChange::Saturated)
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.snapshot().len(), 1);
    }

    #[test]
    fn debug_and_errors_never_echo_peer_controlled_metadata() {
        let marker = "SECRET-SERVICE-MARKER";
        let value = record(
            &format!("{marker}._software-kvm._tcp.local."),
            PEER,
            "10.0.0.2".parse().unwrap(),
        );
        let raw_debug = format!("{value:?}");
        assert!(!raw_debug.contains(marker));

        let mut cache = cache();
        cache.apply_resolved(value, Duration::ZERO).unwrap();
        let rendered = format!("{cache:?} {:?}", DiscoveryCacheError::InvalidTxt);
        assert!(!rendered.contains(marker));
        assert!(!rendered.contains(PEER));
        assert!(rendered.len() < 200);
    }
}
