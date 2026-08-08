use std::collections::BTreeMap;
use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

const DISCOVERY_PORT: u16 = 24_801;
const BEACON_MAGIC: &str = "software-kvm-presence/1";
const MAX_NEARBY_MACHINES: usize = 32;
const MAX_NAME_BYTES: usize = 64;
const MAX_BEACON_BYTES: usize = 512;
const MAX_RECEIVE_DRAIN: usize = 64;
const BEACON_INTERVAL: Duration = Duration::from_secs(2);
const STALE_AFTER: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NearbyPresence {
    SettingUp,
    RuntimeActive,
}

impl NearbyPresence {
    const fn as_wire(self) -> &'static str {
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

struct Advertisement {
    state: AdvertisementState,
    last_sent: Option<Instant>,
}

/// Process-local, bounded, unauthenticated LAN presence beacon.
///
/// Presence can help a user find another setup console, but never authorizes a
/// connection or changes the certificate-pinned pairing boundary.
pub(crate) struct NearbyDiscovery {
    socket: UdpSocket,
    peer_id: String,
    runtime_port: u16,
    broadcast_targets: Vec<SocketAddr>,
    advertised: Mutex<Option<Advertisement>>,
    records: Mutex<BTreeMap<String, NearbyRecord>>,
}

impl NearbyDiscovery {
    pub(crate) fn start(
        peer_id: &str,
        broadcast_addresses: &[IpAddr],
        runtime_port: u16,
    ) -> Result<Self, ()> {
        if !valid_peer_id(peer_id)
            || broadcast_addresses.is_empty()
            || broadcast_addresses.len() > 8
            || broadcast_addresses
                .iter()
                .copied()
                .any(|address| !private_address(address))
            || runtime_port == 0
        {
            return Err(());
        }
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT)).map_err(|_| ())?;
        socket.set_nonblocking(true).map_err(|_| ())?;
        socket.set_broadcast(true).map_err(|_| ())?;
        Ok(Self {
            socket,
            peer_id: peer_id.to_owned(),
            runtime_port,
            broadcast_targets: broadcast_addresses
                .iter()
                .copied()
                .map(|address| SocketAddr::new(address, DISCOVERY_PORT))
                .collect(),
            advertised: Mutex::new(None),
            records: Mutex::new(BTreeMap::new()),
        })
    }

    pub(crate) fn refresh(&self, name: &str, platform: &'static str, presence: NearbyPresence) {
        let next = AdvertisementState {
            name: bounded_name(name),
            platform,
            presence,
        };
        let now = Instant::now();
        let Ok(mut advertised) = self.advertised.lock() else {
            return;
        };
        let should_send = advertised.as_ref().is_none_or(|advertisement| {
            advertisement.state != next
                || advertisement
                    .last_sent
                    .is_none_or(|last_sent| now.duration_since(last_sent) >= BEACON_INTERVAL)
        });
        if !should_send {
            return;
        }
        let packet = encode_beacon(&self.peer_id, &next);
        let limited_broadcast = SocketAddr::from((Ipv4Addr::BROADCAST, DISCOVERY_PORT));
        let mut sent = false;
        if packet.len() <= MAX_BEACON_BYTES {
            for target in self
                .broadcast_targets
                .iter()
                .copied()
                .chain(std::iter::once(limited_broadcast))
            {
                // Always attempt every interface. Short-circuiting after a
                // successful Hyper-V/VPN/WSL send can hide the beacon from
                // the physical Wi-Fi LAN.
                if self.socket.send_to(packet.as_bytes(), target).is_ok() {
                    sent = true;
                }
            }
        }
        if sent {
            *advertised = Some(Advertisement {
                state: next,
                last_sent: Some(now),
            });
        }
    }

    pub(crate) fn snapshot(&self, paired_peer_id: Option<&str>) -> Vec<NearbyMachineDto> {
        let now = Instant::now();
        let Ok(mut records) = self.records.lock() else {
            return Vec::new();
        };
        let mut buffer = [0_u8; MAX_BEACON_BYTES];
        for _ in 0..MAX_RECEIVE_DRAIN {
            match self.socket.recv_from(&mut buffer) {
                Ok((length, source)) => {
                    if let Some(record) =
                        parse_beacon(&buffer[..length], source, self.runtime_port, now)
                    {
                        if record.peer_id != self.peer_id
                            && (records.contains_key(&record.peer_id)
                                || records.len() < MAX_NEARBY_MACHINES)
                        {
                            records.insert(record.peer_id.clone(), record);
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
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
            .field("broadcast_target_count", &self.broadcast_targets.len())
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

fn encode_beacon(peer_id: &str, state: &AdvertisementState) -> String {
    format!(
        "{BEACON_MAGIC}\n{peer_id}\n{}\n{}\n{}\n",
        state.platform,
        state.presence.as_wire(),
        state.name
    )
}

fn parse_beacon(
    bytes: &[u8],
    source: SocketAddr,
    runtime_port: u16,
    now: Instant,
) -> Option<NearbyRecord> {
    if bytes.is_empty() || bytes.len() > MAX_BEACON_BYTES || !private_address(source.ip()) {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    if lines.next()? != BEACON_MAGIC {
        return None;
    }
    let peer_id = lines.next()?;
    if !valid_peer_id(peer_id) {
        return None;
    }
    let platform = match lines.next()? {
        "macos" => "macos",
        "windows" => "windows",
        _ => return None,
    };
    let presence = match lines.next()? {
        "setup" => NearbyPresence::SettingUp,
        "active" => NearbyPresence::RuntimeActive,
        _ => return None,
    };
    let name = lines.next()?;
    if lines.next().is_some()
        || name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return None;
    }
    Some(NearbyRecord {
        peer_id: peer_id.to_owned(),
        name: name.to_owned(),
        platform: platform.to_owned(),
        presence,
        address: SocketAddr::new(source.ip(), runtime_port),
        last_seen: now,
    })
}

fn valid_peer_id(peer_id: &str) -> bool {
    peer_id.len() == 36
        && peer_id
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
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
    fn beacon_round_trip_is_bounded_and_rejects_hostile_shapes() {
        let state = AdvertisementState {
            name: "Desk Mac".to_owned(),
            platform: "macos",
            presence: NearbyPresence::RuntimeActive,
        };
        let peer = "11111111-1111-4111-8111-111111111111";
        let encoded = encode_beacon(peer, &state);
        let parsed = parse_beacon(
            encoded.as_bytes(),
            "192.168.1.20:24801".parse().unwrap(),
            24_800,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(parsed.peer_id, peer);
        assert_eq!(parsed.name, "Desk Mac");
        assert_eq!(parsed.presence, NearbyPresence::RuntimeActive);
        assert!(parse_beacon(
            format!("{encoded}extra\n").as_bytes(),
            "192.168.1.20:24801".parse().unwrap(),
            24_800,
            Instant::now(),
        )
        .is_none());
        assert!(parse_beacon(
            encoded.as_bytes(),
            "203.0.113.20:24801".parse().unwrap(),
            24_800,
            Instant::now(),
        )
        .is_none());
    }

    #[test]
    fn helper_bounds_and_private_address_policy_are_stable() {
        assert_eq!(bounded_name(" Desk Mac "), "Desk Mac");
        assert_eq!(bounded_name(""), "Software KVM computer");
        assert!(valid_peer_id("11111111-1111-4111-8111-111111111111"));
        assert!(!valid_peer_id("11111111-1111-4111-8111-11111111111Z"));
        assert!(private_address("192.168.1.20".parse().unwrap()));
        assert!(private_address("fd00::20".parse().unwrap()));
        assert!(!private_address("203.0.113.20".parse().unwrap()));
    }
}
