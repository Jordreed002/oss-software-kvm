use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use kvm_protocol::{
    decode_frame_for_version, encode_frame_for_version, InputEventV1, WireDeviceId, WireHostId,
    WireInputPayloadV1, WireMessage, POINTER_DATAGRAM_PROTOCOL_VERSION,
};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;
use tokio::net::UdpSocket;

pub(crate) const POINTER_DATAGRAM_PORT: u16 = 24_802;
const MAGIC: [u8; 4] = *b"SKVU";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 13;
const MAX_DATAGRAM: usize = 1_200;
const KIND_PROBE: u8 = 0;
const KIND_POINTER: u8 = 1;
const KIND_FEEDBACK: u8 = 2;
const KIND_RELIABLE: u8 = 3;
const KIND_RELIABLE_ACK: u8 = 4;
const POINTER_PAYLOAD_LEN: usize = 1 + 16 + 8 + 8 + 8;
const MAX_TRACKED_DEVICES: usize = 64;
const POINTER_PACING_INTERVAL: Duration = Duration::from_millis(4);
const RELIABLE_RETRY_INTERVAL: Duration = Duration::from_millis(8);
const MAX_RELIABLE_PENDING: usize = 128;
const MAX_RELIABLE_ATTEMPTS: u8 = 4;

struct PendingPointer {
    timestamp_ns: u64,
    totals: (f64, f64),
}

struct PendingReliable {
    payload: Vec<u8>,
    last_sent: Instant,
    attempts: u8,
}

pub(crate) struct PointerDatagramPath {
    socket: UdpSocket,
    send_cipher: ChaCha20Poly1305,
    receive_cipher: ChaCha20Poly1305,
    send_sequence: u64,
    receive_sequence: Option<u64>,
    ready: bool,
    local_host: WireHostId,
    remote_host: WireHostId,
    sent_totals: HashMap<WireDeviceId, (f64, f64)>,
    pending: HashMap<WireDeviceId, PendingPointer>,
    last_pointer_send: Option<Instant>,
    recently_sent: usize,
    redundancy_budget: usize,
    pacing_interval: Duration,
    reliable_send_sequence: u64,
    reliable_receive_sequence: u64,
    reliable_pending: BTreeMap<u64, PendingReliable>,
    reliable_received: BTreeMap<u64, WireMessage>,
    received_totals: HashMap<WireDeviceId, (f64, f64)>,
    last_arrival: Option<Instant>,
    last_interval_us: Option<u64>,
    buffer: [u8; MAX_DATAGRAM],
}

impl std::fmt::Debug for PointerDatagramPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PointerDatagramPath")
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl PointerDatagramPath {
    #[allow(clippy::unused_async)] // Keeps construction uniform with Tokio socket setup callers.
    pub(crate) async fn bind(
        local: SocketAddr,
        peer: SocketAddr,
        session_id: [u8; 32],
        local_host: WireHostId,
        remote_host: WireHostId,
    ) -> io::Result<Self> {
        let local = SocketAddr::new(local.ip(), POINTER_DATAGRAM_PORT);
        let peer = SocketAddr::new(peer.ip(), POINTER_DATAGRAM_PORT);
        let raw = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))?;
        raw.set_nonblocking(true)?;
        // Keep local queues bounded and request the expedited-forwarding/WMM
        // access category where the OS and access point honor DSCP.
        let _ = raw.set_send_buffer_size(64 * 1024);
        let _ = raw.set_recv_buffer_size(256 * 1024);
        if local.is_ipv4() {
            let _ = raw.set_tos_v4(0xb8);
        }
        raw.bind(&local.into())?;
        raw.connect(&peer.into())?;
        let socket = UdpSocket::from_std(raw.into())?;
        Ok(Self {
            socket,
            send_cipher: cipher(&session_id, local_host),
            receive_cipher: cipher(&session_id, remote_host),
            send_sequence: 0,
            receive_sequence: None,
            ready: false,
            local_host,
            remote_host,
            sent_totals: HashMap::new(),
            pending: HashMap::new(),
            last_pointer_send: None,
            recently_sent: 0,
            redundancy_budget: 0,
            pacing_interval: POINTER_PACING_INTERVAL,
            reliable_send_sequence: 0,
            reliable_receive_sequence: 0,
            reliable_pending: BTreeMap::new(),
            reliable_received: BTreeMap::new(),
            received_totals: HashMap::new(),
            last_arrival: None,
            last_interval_us: None,
            buffer: [0; MAX_DATAGRAM],
        })
    }

    pub(crate) const fn is_ready(&self) -> bool {
        self.ready
    }

    pub(crate) async fn send_probe(&mut self) -> io::Result<()> {
        let packet = self.encode_payload(&[KIND_PROBE])?;
        let written = self.socket.send(&packet).await?;
        if written == packet.len() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::WriteZero, "partial datagram"))
        }
    }

    pub(crate) fn try_send_pointer(&mut self, message: &WireMessage) -> io::Result<bool> {
        if !self.ready || !is_pointer_move(message) {
            return Ok(false);
        }
        let WireMessage::Input(input) = message else {
            return Ok(false);
        };
        let WireInputPayloadV1::PointerMove { dx, dy } = input.payload else {
            return Ok(false);
        };
        if input.source_host != self.local_host {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pointer host mismatch",
            ));
        }
        let previous = self
            .sent_totals
            .get(&input.source_device)
            .copied()
            .unwrap_or_default();
        if !self.sent_totals.contains_key(&input.source_device)
            && self.sent_totals.len() >= MAX_TRACKED_DEVICES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pointer device capacity exceeded",
            ));
        }
        let totals = (previous.0 + dx, previous.1 + dy);
        self.sent_totals.insert(input.source_device, totals);
        self.pending.insert(
            input.source_device,
            PendingPointer {
                timestamp_ns: input.timestamp_ns,
                totals,
            },
        );
        if self
            .last_pointer_send
            .is_some_and(|last| last.elapsed() < self.pacing_interval)
        {
            return Ok(true);
        }
        self.flush_pending().map(|_| true)
    }

    pub(crate) fn flush_pending(&mut self) -> io::Result<usize> {
        if !self.ready || self.pending.is_empty() {
            return Ok(0);
        }
        let pending = std::mem::take(&mut self.pending);
        let mut sent = 0;
        for (device, pointer) in pending {
            let mut payload = Vec::with_capacity(POINTER_PAYLOAD_LEN);
            payload.push(KIND_POINTER);
            payload.extend_from_slice(&device.0);
            payload.extend_from_slice(&pointer.timestamp_ns.to_be_bytes());
            payload.extend_from_slice(&pointer.totals.0.to_bits().to_be_bytes());
            payload.extend_from_slice(&pointer.totals.1.to_bits().to_be_bytes());
            let packet = self.encode_payload(&payload)?;
            match self.socket.try_send(&packet) {
                Ok(written) if written == packet.len() => {
                    if self.redundancy_budget > 0 {
                        let _ = self.socket.try_send(&packet);
                        self.redundancy_budget -= 1;
                        if self.redundancy_budget == 0 {
                            self.pacing_interval = POINTER_PACING_INTERVAL;
                        }
                    }
                    sent += 1;
                }
                Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "partial datagram")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.pending.insert(device, pointer);
                }
                Err(error) => return Err(error),
            }
        }
        if sent > 0 {
            self.last_pointer_send = Some(Instant::now());
            self.recently_sent = self.recently_sent.saturating_add(sent);
        }
        Ok(sent)
    }

    pub(crate) fn take_recently_sent(&mut self) -> usize {
        std::mem::take(&mut self.recently_sent)
    }

    /// Sends a speculative ordered UDP copy while the caller retains the TLS
    /// copy as the authoritative reliability fallback.
    pub(crate) fn shadow_reliable(&mut self, message: &WireMessage) -> io::Result<bool> {
        if !self.ready || !is_stateful_input(message) {
            return Ok(false);
        }
        if self.reliable_pending.len() >= MAX_RELIABLE_PENDING {
            return Ok(false);
        }
        let frame = encode_frame_for_version(message, POINTER_DATAGRAM_PROTOCOL_VERSION)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "reliable encode failed"))?;
        let sequence = self.reliable_send_sequence;
        self.reliable_send_sequence = self
            .reliable_send_sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("reliable sequence exhausted"))?;
        let mut payload = Vec::with_capacity(9 + frame.len());
        payload.push(KIND_RELIABLE);
        payload.extend_from_slice(&sequence.to_be_bytes());
        payload.extend_from_slice(&frame);
        let packet = self.encode_payload(&payload)?;
        match self.socket.try_send(&packet) {
            Ok(written) if written == packet.len() => {}
            Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "partial datagram")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        self.reliable_pending.insert(
            sequence,
            PendingReliable {
                payload,
                last_sent: Instant::now(),
                attempts: 1,
            },
        );
        Ok(true)
    }

    pub(crate) fn maintain_reliable(&mut self) -> io::Result<usize> {
        let due: Vec<u64> = self
            .reliable_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.last_sent.elapsed() >= RELIABLE_RETRY_INTERVAL).then_some(*sequence)
            })
            .collect();
        let mut retransmitted = 0;
        for sequence in due {
            let Some(mut pending) = self.reliable_pending.remove(&sequence) else {
                continue;
            };
            if pending.attempts >= MAX_RELIABLE_ATTEMPTS {
                // TLS carries the same input and remains the final fallback.
                continue;
            }
            let packet = self.encode_payload(&pending.payload)?;
            match self.socket.try_send(&packet) {
                Ok(written) if written == packet.len() => {
                    retransmitted += 1;
                    pending.attempts += 1;
                    pending.last_sent = Instant::now();
                    self.reliable_pending.insert(sequence, pending);
                }
                Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "partial datagram")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.reliable_pending.insert(sequence, pending);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(retransmitted)
    }

    #[allow(clippy::too_many_lines)] // Packet kinds share one authenticated replay window.
    pub(crate) async fn receive(&mut self) -> io::Result<DatagramReceive> {
        let length = self.socket.recv(&mut self.buffer).await?;
        if length < HEADER_LEN || self.buffer[..4] != MAGIC || self.buffer[4] != VERSION {
            return Ok(DatagramReceive::default());
        }
        let sequence = u64::from_be_bytes(self.buffer[5..13].try_into().unwrap_or_default());
        if self.receive_sequence.is_some_and(|last| sequence <= last) {
            return Ok(DatagramReceive::default());
        }
        let plaintext = self
            .receive_cipher
            .decrypt(&nonce(sequence), &self.buffer[HEADER_LEN..length])
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "datagram authentication failed")
            })?;
        let gaps = self
            .receive_sequence
            .map_or(0, |last| sequence.saturating_sub(last).saturating_sub(1));
        self.receive_sequence = Some(sequence);
        let now = Instant::now();
        let interval_us = self
            .last_arrival
            .map(|last| u64::try_from(now.duration_since(last).as_micros()).unwrap_or(u64::MAX));
        let jitter_us = interval_us
            .zip(self.last_interval_us)
            .map_or(0, |(current, previous)| current.abs_diff(previous));
        self.last_arrival = Some(now);
        if let Some(interval) = interval_us {
            self.last_interval_us = Some(interval);
        }
        let silence_ms = interval_us.unwrap_or(0) / 1_000;
        if gaps > 0 {
            let feedback = self.encode_payload(&[KIND_FEEDBACK])?;
            let _ = self.socket.try_send(&feedback);
        }
        match plaintext.split_first() {
            Some((&KIND_PROBE, _)) => {
                self.ready = true;
                Ok(DatagramReceive {
                    gaps,
                    jitter_us,
                    silence_ms,
                    input: None,
                    recovery_milliunits: 0,
                    reliable_messages: Vec::new(),
                })
            }
            Some((&KIND_POINTER, body)) if plaintext.len() == POINTER_PAYLOAD_LEN => {
                let device = WireDeviceId(body[0..16].try_into().unwrap_or_default());
                let timestamp_ns = u64::from_be_bytes(body[16..24].try_into().unwrap_or_default());
                let total_x = f64::from_bits(u64::from_be_bytes(
                    body[24..32].try_into().unwrap_or_default(),
                ));
                let total_y = f64::from_bits(u64::from_be_bytes(
                    body[32..40].try_into().unwrap_or_default(),
                ));
                if !total_x.is_finite() || !total_y.is_finite() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid pointer totals",
                    ));
                }
                if !self.received_totals.contains_key(&device)
                    && self.received_totals.len() >= MAX_TRACKED_DEVICES
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "pointer device capacity exceeded",
                    ));
                }
                let previous = self
                    .received_totals
                    .insert(device, (total_x, total_y))
                    .unwrap_or_default();
                let dx = total_x - previous.0;
                let dy = total_y - previous.1;
                let recovery_milliunits = if gaps > 0 {
                    recovery_milliunits(dx, dy)
                } else {
                    0
                };
                Ok(DatagramReceive {
                    gaps,
                    jitter_us,
                    silence_ms,
                    recovery_milliunits,
                    input: Some(InputEventV1 {
                        sequence,
                        timestamp_ns,
                        source_host: self.remote_host,
                        source_device: device,
                        payload: WireInputPayloadV1::PointerMove { dx, dy },
                    }),
                    reliable_messages: Vec::new(),
                })
            }
            Some((&KIND_FEEDBACK, _)) => {
                self.redundancy_budget = 8;
                self.pacing_interval = Duration::from_millis(8);
                Ok(DatagramReceive {
                    gaps,
                    jitter_us,
                    silence_ms,
                    input: None,
                    recovery_milliunits: 0,
                    reliable_messages: Vec::new(),
                })
            }
            Some((&KIND_RELIABLE, body)) if body.len() > 8 => {
                let reliable_sequence =
                    u64::from_be_bytes(body[..8].try_into().unwrap_or_default());
                let message =
                    decode_frame_for_version(&body[8..], POINTER_DATAGRAM_PROTOCOL_VERSION)
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "reliable decode failed")
                        })?;
                if !is_stateful_input(&message) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid reliable message",
                    ));
                }
                if reliable_sequence >= self.reliable_receive_sequence
                    && self.reliable_received.len() < MAX_RELIABLE_PENDING
                {
                    self.reliable_received
                        .entry(reliable_sequence)
                        .or_insert(message);
                }
                let mut reliable_messages = Vec::new();
                while let Some(message) = self
                    .reliable_received
                    .remove(&self.reliable_receive_sequence)
                {
                    reliable_messages.push(message);
                    self.reliable_receive_sequence += 1;
                }
                if self.reliable_receive_sequence > 0 {
                    let acknowledged = self.reliable_receive_sequence - 1;
                    let mut ack = Vec::with_capacity(9);
                    ack.push(KIND_RELIABLE_ACK);
                    ack.extend_from_slice(&acknowledged.to_be_bytes());
                    let packet = self.encode_payload(&ack)?;
                    let _ = self.socket.try_send(&packet);
                }
                Ok(DatagramReceive {
                    gaps,
                    jitter_us,
                    silence_ms,
                    input: None,
                    recovery_milliunits: 0,
                    reliable_messages,
                })
            }
            Some((&KIND_RELIABLE_ACK, body)) if body.len() == 8 => {
                let acknowledged = u64::from_be_bytes(body.try_into().unwrap_or_default());
                self.reliable_pending
                    .retain(|sequence, _| *sequence > acknowledged);
                Ok(DatagramReceive {
                    gaps,
                    jitter_us,
                    silence_ms,
                    input: None,
                    recovery_milliunits: 0,
                    reliable_messages: Vec::new(),
                })
            }
            _ => Ok(DatagramReceive::default()),
        }
    }

    fn encode_payload(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let sequence = self.send_sequence;
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("datagram sequence exhausted"))?;
        let ciphertext = self
            .send_cipher
            .encrypt(&nonce(sequence), payload)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "datagram encryption failed")
            })?;
        if HEADER_LEN + ciphertext.len() > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram too large",
            ));
        }
        let mut packet = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        packet.extend_from_slice(&MAGIC);
        packet.push(VERSION);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
}

#[derive(Debug, Default)]
pub(crate) struct DatagramReceive {
    pub(crate) input: Option<InputEventV1>,
    pub(crate) gaps: u64,
    pub(crate) jitter_us: u64,
    pub(crate) silence_ms: u64,
    pub(crate) recovery_milliunits: u64,
    pub(crate) reliable_messages: Vec<WireMessage>,
}

fn cipher(session_id: &[u8; 32], sender: WireHostId) -> ChaCha20Poly1305 {
    let mut digest = Sha256::new();
    digest.update(b"software-kvm-pointer-datagram-v1\0");
    digest.update(session_id);
    digest.update(sender.0);
    let key: [u8; 32] = digest.finalize().into();
    ChaCha20Poly1305::new(Key::from_slice(&key))
}

fn nonce(sequence: u64) -> Nonce {
    let mut bytes = [0_u8; 12];
    bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

fn is_pointer_move(message: &WireMessage) -> bool {
    matches!(
        message,
        WireMessage::Input(input)
            if matches!(input.payload, WireInputPayloadV1::PointerMove { .. })
    )
}

fn is_stateful_input(message: &WireMessage) -> bool {
    matches!(message, WireMessage::Input(input) if !matches!(input.payload, WireInputPayloadV1::PointerMove { .. }))
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn recovery_milliunits(dx: f64, dy: f64) -> u64 {
    // Inputs are finite and non-negative after `hypot`; saturation is explicit.
    (dx.hypot(dy) * 1_000.0).clamp(0.0, u64::MAX as f64) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_protocol::{InputEventV1, WireDeviceId};
    use std::time::Duration;

    fn pointer(source: WireHostId) -> WireMessage {
        WireMessage::Input(InputEventV1 {
            sequence: 9,
            timestamp_ns: 11,
            source_host: source,
            source_device: WireDeviceId([3; 16]),
            payload: WireInputPayloadV1::PointerMove { dx: 2.5, dy: -1.0 },
        })
    }

    fn scroll(source: WireHostId, sequence: u64) -> WireMessage {
        WireMessage::Input(InputEventV1 {
            sequence,
            timestamp_ns: 12,
            source_host: source,
            source_device: WireDeviceId([4; 16]),
            payload: WireInputPayloadV1::Scroll {
                horizontal: 0.0,
                vertical: 1.0,
            },
        })
    }

    #[tokio::test]
    async fn exporter_bound_paths_exchange_pointer_after_probe() {
        let host_a = WireHostId([1; 16]);
        let host_b = WireHostId([2; 16]);
        let session = [7; 32];
        let mut a = PointerDatagramPath::bind(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.2:1".parse().unwrap(),
            session,
            host_a,
            host_b,
        )
        .await
        .unwrap();
        let mut b = PointerDatagramPath::bind(
            "127.0.0.2:1".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            session,
            host_b,
            host_a,
        )
        .await
        .unwrap();

        a.send_probe().await.unwrap();
        b.send_probe().await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), a.receive())
            .await
            .unwrap()
            .unwrap()
            .input
            .is_none());
        assert!(tokio::time::timeout(Duration::from_secs(1), b.receive())
            .await
            .unwrap()
            .unwrap()
            .input
            .is_none());
        assert!(a.is_ready() && b.is_ready());

        let sent = pointer(host_a);
        assert!(a.try_send_pointer(&sent).unwrap());
        let received = tokio::time::timeout(Duration::from_secs(1), b.receive())
            .await
            .unwrap()
            .unwrap();
        let received = received.input.unwrap();
        let WireMessage::Input(sent) = sent else {
            unreachable!()
        };
        assert_eq!(received.timestamp_ns, sent.timestamp_ns);
        assert_eq!(received.source_host, sent.source_host);
        assert_eq!(received.source_device, sent.source_device);
        assert_eq!(received.payload, sent.payload);
    }

    #[tokio::test]
    async fn path_does_not_send_non_pointer_or_unprobed_input() {
        let mut path = PointerDatagramPath::bind(
            "127.0.0.3:1".parse().unwrap(),
            "127.0.0.4:1".parse().unwrap(),
            [8; 32],
            WireHostId([1; 16]),
            WireHostId([2; 16]),
        )
        .await
        .unwrap();
        assert!(!path
            .try_send_pointer(&pointer(WireHostId([1; 16])))
            .unwrap());
        assert!(!path
            .try_send_pointer(&WireMessage::Ping(kvm_protocol::PingV1 {
                nonce: 1,
                sent_at_ns: 2,
            }))
            .unwrap());
    }

    #[tokio::test]
    async fn next_pointer_recovers_a_dropped_relative_move() {
        let host_a = WireHostId([5; 16]);
        let host_b = WireHostId([6; 16]);
        let mut a = PointerDatagramPath::bind(
            "127.0.0.5:1".parse().unwrap(),
            "127.0.0.6:1".parse().unwrap(),
            [9; 32],
            host_a,
            host_b,
        )
        .await
        .unwrap();
        let mut b = PointerDatagramPath::bind(
            "127.0.0.6:1".parse().unwrap(),
            "127.0.0.5:1".parse().unwrap(),
            [9; 32],
            host_b,
            host_a,
        )
        .await
        .unwrap();
        a.send_probe().await.unwrap();
        b.send_probe().await.unwrap();
        a.receive().await.unwrap();
        b.receive().await.unwrap();

        let movement = pointer(host_a);
        assert!(a.try_send_pointer(&movement).unwrap());
        // Model network loss by removing the first encrypted packet before the
        // path can decode it and update its receive baseline.
        let mut discarded = [0_u8; MAX_DATAGRAM];
        b.socket.recv(&mut discarded).await.unwrap();
        assert!(a.try_send_pointer(&movement).unwrap());
        a.flush_pending().unwrap();

        let recovered = b.receive().await.unwrap().input.unwrap();
        assert!(matches!(
            recovered.payload,
            WireInputPayloadV1::PointerMove { dx, dy }
                if (dx - 5.0).abs() < f64::EPSILON && (dy + 2.0).abs() < f64::EPSILON
        ));
    }

    #[tokio::test]
    async fn stateful_shadow_is_ordered_acknowledged_and_keeps_tls_fallback() {
        let host_a = WireHostId([7; 16]);
        let host_b = WireHostId([8; 16]);
        let mut a = PointerDatagramPath::bind(
            "127.0.0.7:1".parse().unwrap(),
            "127.0.0.8:1".parse().unwrap(),
            [10; 32],
            host_a,
            host_b,
        )
        .await
        .unwrap();
        let mut b = PointerDatagramPath::bind(
            "127.0.0.8:1".parse().unwrap(),
            "127.0.0.7:1".parse().unwrap(),
            [10; 32],
            host_b,
            host_a,
        )
        .await
        .unwrap();
        a.send_probe().await.unwrap();
        b.send_probe().await.unwrap();
        a.receive().await.unwrap();
        b.receive().await.unwrap();

        let first = scroll(host_a, 20);
        let second = scroll(host_a, 21);
        assert!(a.shadow_reliable(&first).unwrap());
        assert!(a.shadow_reliable(&second).unwrap());
        let received_first = b.receive().await.unwrap();
        let received_second = b.receive().await.unwrap();
        let mut received = received_first.reliable_messages;
        received.extend(received_second.reliable_messages);
        assert_eq!(received, vec![first, second]);
        a.receive().await.unwrap();
        a.receive().await.unwrap();
        assert!(a.reliable_pending.is_empty());
    }
}
