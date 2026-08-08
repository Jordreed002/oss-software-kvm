use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::Serialize;

const CONSOLE_SERVICE_TYPE: &str = "_software-kvm-console._tcp.local.";
const CONSOLE_DISCOVERY_VERSION: &str = "1";
const MAX_NEARBY_MACHINES: usize = 32;
const MAX_NAME_BYTES: usize = 64;
const MAX_EVENT_DRAIN: usize = 128;
const STALE_AFTER: Duration = Duration::from_secs(150);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NearbyPresence {
    SettingUp,
    RuntimeActive,
}

impl NearbyPresence {
    const fn as_txt(self) -> &'static str {
        match self {
            Self::SettingUp => "setup",
            Self::RuntimeActive => "active",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NearbyMachineDto {
    name: String,
    platform: String,
    presence: NearbyPresence,
    address: String,
    paired: bool,
}

#[derive(Clone, Eq, PartialEq)]
struct AdvertisementState {
    name: String,
    platform: &'static str,
    presence: NearbyPresence,
}

struct NearbyRecord {
    peer_id: String,
    name: String,
    platform: String,
    presence: NearbyPresence,
    address: SocketAddr,
    last_seen: Instant,
}

/// Process-local mDNS presence beacon and bounded nearby-machine cache.
pub(crate) struct NearbyDiscovery {
    daemon: ServiceDaemon,
    events: mdns_sd::Receiver<ServiceEvent>,
    instance_name: String,
    hostname: String,
    addresses: Vec<IpAddr>,
    port: u16,
    advertised: Mutex<Option<AdvertisementState>>,
    records: Mutex<BTreeMap<String, NearbyRecord>>,
}

impl NearbyDiscovery {
    pub(crate) fn start(peer_id: &str, addresses: Vec<IpAddr>, port: u16) -> Result<Self, ()> {
        if peer_id.len() != 36
            || peer_id.chars().any(char::is_control)
            || addresses.is_empty()
            || addresses.len() > 8
            || port == 0
        {
            return Err(());
        }
        let daemon = ServiceDaemon::new().map_err(|_| ())?;
        let events = daemon.browse(CONSOLE_SERVICE_TYPE).map_err(|_| ())?;
        Ok(Self {
            daemon,
            events,
            instance_name: format!("software-kvm-{peer_id}"),
            hostname: format!("software-kvm-{peer_id}.local."),
            addresses,
            port,
            advertised: Mutex::new(None),
            records: Mutex::new(BTreeMap::new()),
        })
    }

    pub(crate) fn refresh(&self, name: &str, platform: &'static str, presence: NearbyPresence) {
        let name = bounded_name(name);
        let next = AdvertisementState {
            name,
            platform,
            presence,
        };
        let Ok(mut advertised) = self.advertised.lock() else {
            return;
        };
        if advertised.as_ref() == Some(&next) {
            return;
        }
        let properties = [
            ("ver", CONSOLE_DISCOVERY_VERSION),
            ("peer", instance_peer_id(&self.instance_name)),
            ("name", next.name.as_str()),
            ("platform", next.platform),
            ("state", next.presence.as_txt()),
        ];
        let Ok(service) = ServiceInfo::new(
            CONSOLE_SERVICE_TYPE,
            &self.instance_name,
            &self.hostname,
            self.addresses.as_slice(),
            self.port,
            properties.as_slice(),
        ) else {
            return;
        };
        if self.daemon.register(service).is_ok() {
            *advertised = Some(next);
        }
    }

    pub(crate) fn snapshot(&self, paired_peer_id: Option<&str>) -> Vec<NearbyMachineDto> {
        let now = Instant::now();
        let Ok(mut records) = self.records.lock() else {
            return Vec::new();
        };
        for _ in 0..MAX_EVENT_DRAIN {
            let Ok(event) = self.events.try_recv() else {
                break;
            };
            match event {
                ServiceEvent::ServiceResolved(service) => {
                    if service.get_fullname() == service_fullname(&self.instance_name) {
                        continue;
                    }
                    if let Some(record) = parse_service(&service, now) {
                        if records.contains_key(service.get_fullname())
                            || records.len() < MAX_NEARBY_MACHINES
                        {
                            records.insert(service.get_fullname().to_owned(), record);
                        }
                    }
                }
                ServiceEvent::ServiceRemoved(service_type, fullname)
                    if service_type == CONSOLE_SERVICE_TYPE =>
                {
                    records.remove(&fullname);
                }
                _ => {}
            }
        }
        records.retain(|_, record| now.duration_since(record.last_seen) < STALE_AFTER);
        records
            .values()
            .map(|record| NearbyMachineDto {
                name: record.name.clone(),
                platform: record.platform.clone(),
                presence: record.presence,
                address: record.address.to_string(),
                paired: paired_peer_id == Some(record.peer_id.as_str()),
            })
            .collect()
    }
}

impl fmt::Debug for NearbyDiscovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NearbyDiscovery")
            .field("address_count", &self.addresses.len())
            .field(
                "advertisement_present",
                &matches!(self.advertised.lock().as_deref(), Ok(Some(_))),
            )
            .field(
                "record_count",
                &self.records.lock().map_or(0, |map| map.len()),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for NearbyDiscovery {
    fn drop(&mut self) {
        let _ = self.daemon.stop_browse(CONSOLE_SERVICE_TYPE);
        let _ = self
            .daemon
            .unregister(&service_fullname(&self.instance_name));
        let _ = self.daemon.shutdown();
    }
}

fn parse_service(service: &ResolvedService, now: Instant) -> Option<NearbyRecord> {
    if service.ty_domain != CONSOLE_SERVICE_TYPE
        || service.get_properties().len() > 8
        || service.get_addresses().is_empty()
        || service.get_addresses().len() > 8
    {
        return None;
    }
    let property = |key: &str| {
        service
            .get_properties()
            .get_property_val_str(key)
            .map(str::to_owned)
    };
    if property("ver")?.as_str() != CONSOLE_DISCOVERY_VERSION {
        return None;
    }
    let peer_id = property("peer")?;
    if peer_id.len() != 36 || peer_id.chars().any(char::is_control) {
        return None;
    }
    let name = property("name")?;
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control) {
        return None;
    }
    let platform = match property("platform")?.as_str() {
        "macos" => "macos",
        "windows" => "windows",
        _ => return None,
    }
    .to_owned();
    let presence = match property("state")?.as_str() {
        "setup" => NearbyPresence::SettingUp,
        "active" => NearbyPresence::RuntimeActive,
        _ => return None,
    };
    let mut addresses: Vec<_> = service
        .get_addresses()
        .iter()
        .map(mdns_sd::ScopedIp::to_ip_addr)
        .filter(|address| private_address(*address))
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    let address = SocketAddr::new(*addresses.first()?, service.get_port());
    Some(NearbyRecord {
        peer_id,
        name,
        platform,
        presence,
        address,
        last_seen: now,
    })
}

fn bounded_name(name: &str) -> String {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control) {
        "Software KVM computer".to_owned()
    } else {
        name.to_owned()
    }
}

fn instance_peer_id(instance: &str) -> &str {
    instance
        .strip_prefix("software-kvm-")
        .unwrap_or("unavailable")
}

fn service_fullname(instance: &str) -> String {
    format!("{instance}.{CONSOLE_SERVICE_TYPE}")
}

fn private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.segments()[0] & 0xfe00 == 0xfc00,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_bounds_and_private_address_policy_are_stable() {
        assert_eq!(bounded_name(" Desk Mac "), "Desk Mac");
        assert_eq!(bounded_name(""), "Software KVM computer");
        assert!(private_address("192.168.1.20".parse().unwrap()));
        assert!(private_address("fd00::20".parse().unwrap()));
        assert!(!private_address("203.0.113.20".parse().unwrap()));
        assert_eq!(
            service_fullname("example"),
            "example._software-kvm-console._tcp.local."
        );
    }

    #[test]
    #[ignore = "manual multicast smoke probe"]
    fn advertises_for_manual_multicast_probe() {
        let discovery = NearbyDiscovery::start(
            "11111111-1111-4111-8111-111111111111",
            vec!["192.168.0.19".parse().unwrap()],
            24_800,
        )
        .unwrap();
        discovery.refresh("Software KVM smoke", "macos", NearbyPresence::SettingUp);
        std::thread::sleep(Duration::from_secs(15));
    }
}
