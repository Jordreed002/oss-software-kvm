use std::collections::BTreeMap;
use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const DISCOVERY_PORT: u16 = 24_801;
const BEACON_MAGIC: &str = "software-kvm-presence/1";
const PAIRING_MAGIC: &str = "software-kvm-pairing/1";
const MAX_NEARBY_MACHINES: usize = 32;
const MAX_NAME_BYTES: usize = 64;
const MAX_BEACON_BYTES: usize = 512;
const MAX_PAIRING_PACKET_BYTES: usize = 24 * 1024;
const MAX_RECEIVE_DRAIN: usize = 64;
const BEACON_INTERVAL: Duration = Duration::from_secs(2);
const STALE_AFTER: Duration = Duration::from_secs(8);
const PAIRING_EXPIRES_AFTER: Duration = Duration::from_mins(2);
const CONFIRM_RETRY_AFTER: Duration = Duration::from_secs(15);

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
    peer_id: String,
    name: String,
    platform: String,
    presence: NearbyPresence,
    address: String,
    paired: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NearbyPairingStatus {
    IncomingRequest,
    WaitingForAcceptance,
    VerifyCode,
    WaitingForConfirmation,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NearbyPairingDto {
    request_id: String,
    peer_id: String,
    name: String,
    platform: String,
    address: String,
    status: NearbyPairingStatus,
    verification_code: Option<String>,
}

impl fmt::Debug for NearbyPairingDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // N-5: redact the verification SAS code. The other fields are non-secret
        // metadata already surfaced to the UI; this keeps the code out of {:?}
        // output, including transitively through SetupSnapshot.
        formatter
            .debug_struct("NearbyPairingDto")
            .field("request_id", &self.request_id)
            .field("peer_id", &self.peer_id)
            .field("name", &self.name)
            .field("platform", &self.platform)
            .field("address", &self.address)
            .field("status", &self.status)
            .field(
                "verification_code_present",
                &self.verification_code.is_some(),
            )
            .finish_non_exhaustive()
    }
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PairingPacket {
    Request {
        request_id: String,
        from_peer_id: String,
        to_peer_id: String,
        bundle: String,
    },
    Accept {
        request_id: String,
        from_peer_id: String,
        to_peer_id: String,
        bundle: String,
    },
    Confirm {
        request_id: String,
        from_peer_id: String,
        to_peer_id: String,
    },
    Decline {
        request_id: String,
        from_peer_id: String,
        to_peer_id: String,
    },
}

enum PairingSession {
    OutgoingRequested {
        request_id: String,
        peer_id: String,
        name: String,
        platform: String,
        address: SocketAddr,
        local_bundle: String,
        created: Instant,
        last_sent: Instant,
    },
    IncomingRequested {
        request_id: String,
        peer_id: String,
        name: String,
        platform: String,
        address: SocketAddr,
        remote_bundle: String,
        created: Instant,
    },
    IncomingAccepted {
        request_id: String,
        peer_id: String,
        name: String,
        platform: String,
        address: SocketAddr,
        remote_bundle: String,
        local_bundle: String,
        verification_code: String,
        created: Instant,
        last_sent: Instant,
    },
    OutgoingAccepted {
        request_id: String,
        peer_id: String,
        name: String,
        platform: String,
        address: SocketAddr,
        remote_bundle: String,
        verification_code: String,
        created: Instant,
    },
    OutgoingConfirmed {
        request_id: String,
        peer_id: String,
        name: String,
        platform: String,
        address: SocketAddr,
        created: Instant,
        last_sent: Instant,
    },
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
    pairing: Mutex<Option<PairingSession>>,
    completed_bundle: Mutex<Option<String>>,
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
            pairing: Mutex::new(None),
            completed_bundle: Mutex::new(None),
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
        if should_send {
            let packet = encode_beacon(&self.peer_id, &next);
            let mut sent = false;
            if packet.len() <= MAX_BEACON_BYTES {
                // N-1: send only to the per-private-interface directed broadcast
                // targets (RFC1918/ULA, validated at construction). The previous
                // blanket send to Ipv4Addr::BROADCAST (255.255.255.255) reached
                // every broadcast-capable adapter — including public Wi-Fi —
                // leaking hostname, OS, and a stable cross-LAN peer_id. Always
                // attempt every interface; short-circuiting after a successful
                // Hyper-V/VPN/WSL send can hide the beacon from the physical LAN.
                for target in self.broadcast_targets.iter().copied() {
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
        drop(advertised);
        self.retry_pairing_packet(now);
    }

    pub(crate) fn snapshot(&self, paired_peer_id: Option<&str>) -> Vec<NearbyMachineDto> {
        let now = Instant::now();
        let Ok(mut records) = self.records.lock() else {
            return Vec::new();
        };
        let mut buffer = vec![0_u8; MAX_PAIRING_PACKET_BYTES].into_boxed_slice();
        for _ in 0..MAX_RECEIVE_DRAIN {
            match self.socket.recv_from(&mut buffer) {
                Ok((length, source)) => {
                    if let Some(record) = parse_beacon(
                        &buffer[..length.min(MAX_BEACON_BYTES)],
                        source,
                        self.runtime_port,
                        now,
                    ) {
                        if record.peer_id != self.peer_id
                            && (records.contains_key(&record.peer_id)
                                || records.len() < MAX_NEARBY_MACHINES)
                        {
                            records.insert(record.peer_id.clone(), record);
                        }
                    } else if let Some(packet) = parse_pairing_packet(&buffer[..length]) {
                        self.handle_pairing_packet(
                            packet,
                            source,
                            &records,
                            now,
                            paired_peer_id.is_some(),
                        );
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
                peer_id: record.peer_id.clone(),
                name: record.name.clone(),
                platform: record.platform.clone(),
                presence: record.presence,
                address: record.address.to_string(),
                paired: paired_peer_id == Some(record.peer_id.as_str()),
            })
            .collect()
    }

    pub(crate) fn pairing_snapshot(&self) -> Option<NearbyPairingDto> {
        let now = Instant::now();
        let mut pairing = self.pairing.lock().ok()?;
        if pairing.as_ref().is_some_and(|session| session.expired(now)) {
            *pairing = None;
        }
        pairing
            .as_ref()
            .map(|session| session.dto(self.runtime_port))
    }

    pub(crate) fn observed_runtime_address(&self, peer_id: &str) -> Option<SocketAddr> {
        self.records
            .lock()
            .ok()?
            .get(peer_id)
            .map(|record| record.address)
    }

    pub(crate) fn request_pairing(&self, peer_id: &str, local_bundle: &str) -> Result<(), ()> {
        if !valid_peer_id(peer_id) || local_bundle.is_empty() {
            return Err(());
        }
        let records = self.records.lock().map_err(|_| ())?;
        let record = records.get(peer_id).ok_or(())?;
        let record_name = record.name.clone();
        let record_platform = record.platform.clone();
        let record_address = SocketAddr::new(record.address.ip(), DISCOVERY_PORT);
        drop(records);
        let mut pairing = self.pairing.lock().map_err(|_| ())?;
        if pairing.is_some() {
            return Err(());
        }
        let request_id = Uuid::new_v4().to_string();
        let packet = PairingPacket::Request {
            request_id: request_id.clone(),
            from_peer_id: self.peer_id.clone(),
            to_peer_id: peer_id.to_owned(),
            bundle: local_bundle.to_owned(),
        };
        send_pairing_packet(&self.socket, record_address, &packet)?;
        let now = Instant::now();
        let session = PairingSession::OutgoingRequested {
            request_id,
            peer_id: peer_id.to_owned(),
            name: record_name,
            platform: record_platform,
            address: record_address,
            local_bundle: local_bundle.to_owned(),
            created: now,
            last_sent: now,
        };
        *pairing = Some(session);
        Ok(())
    }

    pub(crate) fn accept_pairing(&self, request_id: &str, local_bundle: &str) -> Result<(), ()> {
        let mut pairing = self.pairing.lock().map_err(|_| ())?;
        let Some(PairingSession::IncomingRequested {
            request_id: expected_request,
            peer_id,
            name,
            platform,
            address,
            remote_bundle,
            created,
        }) = pairing.as_ref()
        else {
            return Err(());
        };
        if request_id != expected_request || local_bundle.is_empty() {
            return Err(());
        }
        let packet = PairingPacket::Accept {
            request_id: expected_request.clone(),
            from_peer_id: self.peer_id.clone(),
            to_peer_id: peer_id.clone(),
            bundle: local_bundle.to_owned(),
        };
        send_pairing_packet(&self.socket, *address, &packet)?;
        let now = Instant::now();
        *pairing = Some(PairingSession::IncomingAccepted {
            request_id: expected_request.clone(),
            peer_id: peer_id.clone(),
            name: name.clone(),
            platform: platform.clone(),
            address: *address,
            remote_bundle: remote_bundle.clone(),
            local_bundle: local_bundle.to_owned(),
            verification_code: verification_code(expected_request, remote_bundle, local_bundle),
            created: *created,
            last_sent: now,
        });
        Ok(())
    }

    pub(crate) fn incoming_pairing_bundle(&self, request_id: &str) -> Result<String, ()> {
        let pairing = self.pairing.lock().map_err(|_| ())?;
        let Some(PairingSession::IncomingRequested {
            request_id: expected_request,
            remote_bundle,
            ..
        }) = pairing.as_ref()
        else {
            return Err(());
        };
        if request_id != expected_request {
            return Err(());
        }
        Ok(remote_bundle.clone())
    }

    pub(crate) fn accepted_pairing_bundle(&self, request_id: &str) -> Result<String, ()> {
        let pairing = self.pairing.lock().map_err(|_| ())?;
        let Some(PairingSession::OutgoingAccepted {
            request_id: expected_request,
            remote_bundle,
            ..
        }) = pairing.as_ref()
        else {
            return Err(());
        };
        if request_id != expected_request {
            return Err(());
        }
        Ok(remote_bundle.clone())
    }

    pub(crate) fn confirm_pairing(&self, request_id: &str) -> Result<(), ()> {
        let mut pairing = self.pairing.lock().map_err(|_| ())?;
        let Some(PairingSession::OutgoingAccepted {
            request_id: expected_request,
            peer_id,
            name,
            platform,
            address,
            created,
            ..
        }) = pairing.as_ref()
        else {
            return Err(());
        };
        if request_id != expected_request {
            return Err(());
        }
        let packet = PairingPacket::Confirm {
            request_id: expected_request.clone(),
            from_peer_id: self.peer_id.clone(),
            to_peer_id: peer_id.clone(),
        };
        send_pairing_packet(&self.socket, *address, &packet)?;
        let now = Instant::now();
        *pairing = Some(PairingSession::OutgoingConfirmed {
            request_id: expected_request.clone(),
            peer_id: peer_id.clone(),
            name: name.clone(),
            platform: platform.clone(),
            address: *address,
            created: *created,
            last_sent: now,
        });
        Ok(())
    }

    pub(crate) fn decline_pairing(&self, request_id: &str) -> Result<(), ()> {
        let mut pairing = self.pairing.lock().map_err(|_| ())?;
        let session = pairing.as_ref().ok_or(())?;
        if session.request_id() != request_id {
            return Err(());
        }
        let packet = PairingPacket::Decline {
            request_id: request_id.to_owned(),
            from_peer_id: self.peer_id.clone(),
            to_peer_id: session.peer_id().to_owned(),
        };
        let _ = send_pairing_packet(&self.socket, session.address(), &packet);
        *pairing = None;
        Ok(())
    }

    pub(crate) fn take_completed_bundle(&self) -> Option<String> {
        self.completed_bundle.lock().ok()?.take()
    }

    pub(crate) fn clear_pairing(&self) {
        if let Ok(mut pairing) = self.pairing.lock() {
            if let Some(session) = pairing.as_ref() {
                let packet = PairingPacket::Decline {
                    request_id: session.request_id().to_owned(),
                    from_peer_id: self.peer_id.clone(),
                    to_peer_id: session.peer_id().to_owned(),
                };
                let _ = send_pairing_packet(&self.socket, session.address(), &packet);
            }
            *pairing = None;
        }
        if let Ok(mut completed) = self.completed_bundle.lock() {
            *completed = None;
        }
    }

    fn handle_pairing_packet(
        &self,
        packet: PairingPacket,
        source: SocketAddr,
        records: &BTreeMap<String, NearbyRecord>,
        now: Instant,
        peer_configured: bool,
    ) {
        if !private_address(source.ip()) || source.port() != DISCOVERY_PORT {
            return;
        }
        match packet {
            PairingPacket::Request {
                request_id,
                from_peer_id,
                to_peer_id,
                bundle,
            } => self.handle_pairing_request(
                request_id,
                from_peer_id,
                &to_peer_id,
                bundle,
                source,
                records,
                now,
                peer_configured,
            ),
            PairingPacket::Accept {
                request_id,
                from_peer_id,
                to_peer_id,
                bundle,
            } => {
                self.handle_pairing_accept(&request_id, &from_peer_id, &to_peer_id, bundle, source);
            }
            PairingPacket::Confirm {
                request_id,
                from_peer_id,
                to_peer_id,
            } => self.handle_pairing_confirm(&request_id, &from_peer_id, &to_peer_id, source),
            PairingPacket::Decline {
                request_id,
                from_peer_id,
                to_peer_id,
            } => self.handle_pairing_decline(&request_id, &from_peer_id, &to_peer_id, source),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_pairing_request(
        &self,
        request_id: String,
        from_peer_id: String,
        to_peer_id: &str,
        bundle: String,
        source: SocketAddr,
        records: &BTreeMap<String, NearbyRecord>,
        now: Instant,
        peer_configured: bool,
    ) {
        let Some(record) = records.get(&from_peer_id) else {
            return;
        };
        if to_peer_id != self.peer_id
            || record.address.ip() != source.ip()
            || !valid_request_id(&request_id)
            || !valid_bundle_shape(&bundle)
        {
            return;
        }
        // N-4: a peer is already configured. Ignore stale or replayed Request
        // packets so they cannot surface a phantom incoming-pairing prompt
        // after a completed pairing. Re-pairing clears the configured peer
        // first, which re-enables incoming requests. The 2-minute request
        // expiry already bounds this to a UX nuisance; this suppresses it.
        if peer_configured {
            return;
        }
        let Ok(mut pairing) = self.pairing.lock() else {
            return;
        };
        let may_replace = pairing.as_ref().is_none_or(|session| {
            matches!(session, PairingSession::OutgoingRequested { peer_id, .. }
                if peer_id == &from_peer_id && self.peer_id > from_peer_id)
        });
        if may_replace {
            // The lexical tie-break resolves simultaneous clicks so both
            // computers cannot wait on each other forever.
            *pairing = Some(PairingSession::IncomingRequested {
                request_id,
                peer_id: from_peer_id,
                name: record.name.clone(),
                platform: record.platform.clone(),
                address: source,
                remote_bundle: bundle,
                created: now,
            });
        }
    }

    fn handle_pairing_accept(
        &self,
        request_id: &str,
        from_peer_id: &str,
        to_peer_id: &str,
        bundle: String,
        source: SocketAddr,
    ) {
        let Ok(mut pairing) = self.pairing.lock() else {
            return;
        };
        let Some(PairingSession::OutgoingRequested {
            request_id: expected_request,
            peer_id,
            name,
            platform,
            address,
            local_bundle,
            created,
            ..
        }) = pairing.as_ref()
        else {
            return;
        };
        if request_id != expected_request
            || from_peer_id != peer_id
            || to_peer_id != self.peer_id
            || address.ip() != source.ip()
            || !valid_bundle_shape(&bundle)
        {
            return;
        }
        *pairing = Some(PairingSession::OutgoingAccepted {
            request_id: expected_request.clone(),
            peer_id: peer_id.clone(),
            name: name.clone(),
            platform: platform.clone(),
            address: *address,
            verification_code: verification_code(expected_request, local_bundle, &bundle),
            remote_bundle: bundle,
            created: *created,
        });
    }

    fn handle_pairing_confirm(
        &self,
        request_id: &str,
        from_peer_id: &str,
        to_peer_id: &str,
        source: SocketAddr,
    ) {
        let Ok(mut pairing) = self.pairing.lock() else {
            return;
        };
        let Some(PairingSession::IncomingAccepted {
            request_id: expected_request,
            peer_id,
            address,
            remote_bundle,
            ..
        }) = pairing.as_ref()
        else {
            return;
        };
        if request_id != expected_request
            || from_peer_id != peer_id
            || to_peer_id != self.peer_id
            || address.ip() != source.ip()
        {
            return;
        }
        let Ok(mut completed) = self.completed_bundle.lock() else {
            return;
        };
        if completed.is_none() {
            *completed = Some(remote_bundle.clone());
        }
        *pairing = None;
    }

    fn handle_pairing_decline(
        &self,
        request_id: &str,
        from_peer_id: &str,
        to_peer_id: &str,
        source: SocketAddr,
    ) {
        let Ok(mut pairing) = self.pairing.lock() else {
            return;
        };
        let Some(session) = pairing.as_ref() else {
            return;
        };
        if request_id == session.request_id()
            && from_peer_id == session.peer_id()
            && to_peer_id == self.peer_id
            && session.address().ip() == source.ip()
        {
            *pairing = None;
        }
    }

    fn retry_pairing_packet(&self, now: Instant) {
        let Ok(mut pairing) = self.pairing.lock() else {
            return;
        };
        if pairing.as_ref().is_some_and(|session| session.expired(now)) {
            *pairing = None;
            return;
        }
        let packet_and_target = match pairing.as_ref() {
            Some(PairingSession::OutgoingRequested {
                request_id,
                peer_id,
                address,
                local_bundle,
                last_sent,
                ..
            }) if now.duration_since(*last_sent) >= BEACON_INTERVAL => Some((
                PairingPacket::Request {
                    request_id: request_id.clone(),
                    from_peer_id: self.peer_id.clone(),
                    to_peer_id: peer_id.clone(),
                    bundle: local_bundle.clone(),
                },
                *address,
            )),
            Some(PairingSession::IncomingAccepted {
                request_id,
                peer_id,
                address,
                local_bundle,
                last_sent,
                ..
            }) if now.duration_since(*last_sent) >= BEACON_INTERVAL => Some((
                PairingPacket::Accept {
                    request_id: request_id.clone(),
                    from_peer_id: self.peer_id.clone(),
                    to_peer_id: peer_id.clone(),
                    bundle: local_bundle.clone(),
                },
                *address,
            )),
            Some(PairingSession::OutgoingConfirmed {
                request_id,
                peer_id,
                address,
                last_sent,
                ..
            }) if now.duration_since(*last_sent) >= BEACON_INTERVAL => Some((
                PairingPacket::Confirm {
                    request_id: request_id.clone(),
                    from_peer_id: self.peer_id.clone(),
                    to_peer_id: peer_id.clone(),
                },
                *address,
            )),
            _ => None,
        };
        if let Some((packet, target)) = packet_and_target {
            if send_pairing_packet(&self.socket, target, &packet).is_ok() {
                if let Some(session) = pairing.as_mut() {
                    session.set_last_sent(now);
                }
            }
        }
    }
}

impl PairingSession {
    fn request_id(&self) -> &str {
        match self {
            Self::OutgoingRequested { request_id, .. }
            | Self::IncomingRequested { request_id, .. }
            | Self::IncomingAccepted { request_id, .. }
            | Self::OutgoingAccepted { request_id, .. }
            | Self::OutgoingConfirmed { request_id, .. } => request_id,
        }
    }

    fn peer_id(&self) -> &str {
        match self {
            Self::OutgoingRequested { peer_id, .. }
            | Self::IncomingRequested { peer_id, .. }
            | Self::IncomingAccepted { peer_id, .. }
            | Self::OutgoingAccepted { peer_id, .. }
            | Self::OutgoingConfirmed { peer_id, .. } => peer_id,
        }
    }

    const fn address(&self) -> SocketAddr {
        match self {
            Self::OutgoingRequested { address, .. }
            | Self::IncomingRequested { address, .. }
            | Self::IncomingAccepted { address, .. }
            | Self::OutgoingAccepted { address, .. }
            | Self::OutgoingConfirmed { address, .. } => *address,
        }
    }

    const fn created(&self) -> Instant {
        match self {
            Self::OutgoingRequested { created, .. }
            | Self::IncomingRequested { created, .. }
            | Self::IncomingAccepted { created, .. }
            | Self::OutgoingAccepted { created, .. }
            | Self::OutgoingConfirmed { created, .. } => *created,
        }
    }

    fn expired(&self, now: Instant) -> bool {
        let lifetime = if matches!(self, Self::OutgoingConfirmed { .. }) {
            CONFIRM_RETRY_AFTER
        } else {
            PAIRING_EXPIRES_AFTER
        };
        now.duration_since(self.created()) >= lifetime
    }

    fn set_last_sent(&mut self, now: Instant) {
        match self {
            Self::OutgoingRequested { last_sent, .. }
            | Self::IncomingAccepted { last_sent, .. }
            | Self::OutgoingConfirmed { last_sent, .. } => *last_sent = now,
            Self::IncomingRequested { .. } | Self::OutgoingAccepted { .. } => {}
        }
    }

    fn dto(&self, runtime_port: u16) -> NearbyPairingDto {
        let (name, platform, status, verification_code) = match self {
            Self::OutgoingRequested { name, platform, .. } => (
                name,
                platform,
                NearbyPairingStatus::WaitingForAcceptance,
                None,
            ),
            Self::IncomingRequested { name, platform, .. } => {
                (name, platform, NearbyPairingStatus::IncomingRequest, None)
            }
            Self::IncomingAccepted {
                name,
                platform,
                verification_code,
                ..
            } => (
                name,
                platform,
                NearbyPairingStatus::WaitingForConfirmation,
                Some(verification_code.clone()),
            ),
            Self::OutgoingAccepted {
                name,
                platform,
                verification_code,
                ..
            } => (
                name,
                platform,
                NearbyPairingStatus::VerifyCode,
                Some(verification_code.clone()),
            ),
            Self::OutgoingConfirmed { name, platform, .. } => (
                name,
                platform,
                NearbyPairingStatus::WaitingForConfirmation,
                None,
            ),
        };
        NearbyPairingDto {
            request_id: self.request_id().to_owned(),
            peer_id: self.peer_id().to_owned(),
            name: name.clone(),
            platform: platform.clone(),
            address: SocketAddr::new(self.address().ip(), runtime_port).to_string(),
            status,
            verification_code,
        }
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
            .field(
                "pairing_pending",
                &self.pairing.lock().is_ok_and(|pairing| pairing.is_some()),
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

/// Sends one pairing handshake packet over the shared discovery socket.
///
/// # N-2: cleartext UDP pairing is accepted, documented here
///
/// Pairing packets (request / accept / confirm / decline) travel as cleartext
/// JSON over UDP on the LAN discovery port. This is deliberate and bounded:
///
/// - The transport is scoped: `target` must be on `DISCOVERY_PORT` and a
///   private/RFC1918 address, and packets are size-capped. A remote attacker
///   off-LAN cannot reach it.
/// - The handshake is mutual-consent: each side's operator must approve, and a
///   request carries an opaque peer bundle (identity/cert material) that is
///   *not* trusted on receipt — it becomes a credential only after the operator
///   confirms.
/// - Confidentiality of the actual session is not at stake: the data channel
///   is TLS 1.3 with TOFU leaf-cert pinning (exact SHA-256 `ct_eq`). An on-LAN
///   observer or active MITM can read or tamper with the *pairing* flow, but
///   cannot derive the pinned cert and therefore cannot intercept the session.
///   The worst realistic outcome is a denial/spoof of the pairing UX, which the
///   operator notices and re-runs.
///
/// Moving pairing behind TLS would be circular (TLS is what pairing bootstraps)
/// unless a separate authenticated channel existed; on a trusted LAN the
/// cleartext handshake plus operator confirmation plus cert pinning is the
/// proportionate control.
fn send_pairing_packet(
    socket: &UdpSocket,
    target: SocketAddr,
    packet: &PairingPacket,
) -> Result<(), ()> {
    if target.port() != DISCOVERY_PORT || !private_address(target.ip()) {
        return Err(());
    }
    let body = serde_json::to_vec(packet).map_err(|_| ())?;
    let length = PAIRING_MAGIC.len() + 1 + body.len();
    if length > MAX_PAIRING_PACKET_BYTES {
        return Err(());
    }
    let mut encoded = Vec::with_capacity(length);
    encoded.extend_from_slice(PAIRING_MAGIC.as_bytes());
    encoded.push(b'\n');
    encoded.extend_from_slice(&body);
    let sent = socket.send_to(&encoded, target).map_err(|_| ())?;
    (sent == encoded.len()).then_some(()).ok_or(())
}

fn parse_pairing_packet(bytes: &[u8]) -> Option<PairingPacket> {
    if bytes.is_empty() || bytes.len() > MAX_PAIRING_PACKET_BYTES {
        return None;
    }
    let body = bytes
        .strip_prefix(PAIRING_MAGIC.as_bytes())?
        .strip_prefix(b"\n")?;
    let packet: PairingPacket = serde_json::from_slice(body).ok()?;
    let (request_id, from_peer_id, to_peer_id, bundle) = match &packet {
        PairingPacket::Request {
            request_id,
            from_peer_id,
            to_peer_id,
            bundle,
        }
        | PairingPacket::Accept {
            request_id,
            from_peer_id,
            to_peer_id,
            bundle,
        } => (request_id, from_peer_id, to_peer_id, Some(bundle)),
        PairingPacket::Confirm {
            request_id,
            from_peer_id,
            to_peer_id,
        }
        | PairingPacket::Decline {
            request_id,
            from_peer_id,
            to_peer_id,
        } => (request_id, from_peer_id, to_peer_id, None),
    };
    if !valid_request_id(request_id)
        || !valid_peer_id(from_peer_id)
        || !valid_peer_id(to_peer_id)
        || from_peer_id == to_peer_id
        || bundle.is_some_and(|bundle| !valid_bundle_shape(bundle))
    {
        return None;
    }
    Some(packet)
}

fn valid_request_id(request_id: &str) -> bool {
    Uuid::parse_str(request_id).is_ok_and(|id| id.get_version_num() == 4)
}

fn valid_bundle_shape(bundle: &str) -> bool {
    !bundle.is_empty()
        && bundle.len() <= MAX_PAIRING_PACKET_BYTES / 2
        && bundle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
}

fn verification_code(request_id: &str, first_bundle: &str, second_bundle: &str) -> String {
    let (first, second) = if first_bundle <= second_bundle {
        (first_bundle, second_bundle)
    } else {
        (second_bundle, first_bundle)
    };
    let mut digest = Sha256::new();
    digest.update(b"software-kvm-pairing-code-v1\0");
    digest.update(request_id.as_bytes());
    digest.update(b"\0");
    digest.update(first.as_bytes());
    digest.update(b"\0");
    digest.update(second.as_bytes());
    let bytes = digest.finalize();
    let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 1_000_000;
    let digits = format!("{value:06}");
    format!("{} {}", &digits[..3], &digits[3..])
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

    #[test]
    fn pairing_packets_are_bounded_and_exactly_addressed() {
        let packet = PairingPacket::Request {
            request_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            from_peer_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            to_peer_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            bundle: "public_bundle-1".to_owned(),
        };
        let body = serde_json::to_vec(&packet).unwrap();
        let mut encoded = format!("{PAIRING_MAGIC}\n").into_bytes();
        encoded.extend_from_slice(&body);
        assert!(matches!(
            parse_pairing_packet(&encoded),
            Some(PairingPacket::Request { .. })
        ));

        let malformed = PairingPacket::Confirm {
            request_id: "not-a-request".to_owned(),
            from_peer_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            to_peer_id: "22222222-2222-4222-8222-222222222222".to_owned(),
        };
        let body = serde_json::to_vec(&malformed).unwrap();
        let mut encoded = format!("{PAIRING_MAGIC}\n").into_bytes();
        encoded.extend_from_slice(&body);
        assert!(parse_pairing_packet(&encoded).is_none());
    }

    #[test]
    fn verification_code_is_direction_independent_and_redacted() {
        let request = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let forward = verification_code(request, "first-bundle", "second-bundle");
        let reverse = verification_code(request, "second-bundle", "first-bundle");
        assert_eq!(forward, reverse);
        assert_eq!(forward.len(), 7);
        assert_eq!(forward.as_bytes()[3], b' ');
        assert!(forward
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 3 || byte.is_ascii_digit()));
    }
}
