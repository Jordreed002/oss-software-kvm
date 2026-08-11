use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use kvm_protocol::{InputEventV1, WireDeviceId, WireHostId, WireInputPayloadV1, WireMessage};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub(crate) const POINTER_DATAGRAM_PORT: u16 = 24_802;
const MAGIC: [u8; 4] = *b"SKVU";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 13;
const MAX_DATAGRAM: usize = 1_200;
const KIND_PROBE: u8 = 0;
const KIND_POINTER: u8 = 1;
const POINTER_PAYLOAD_LEN: usize = 1 + 16 + 8 + 8 + 8;
const MAX_TRACKED_DEVICES: usize = 64;

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
    received_totals: HashMap<WireDeviceId, (f64, f64)>,
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
    pub(crate) async fn bind(
        local: SocketAddr,
        peer: SocketAddr,
        session_id: [u8; 32],
        local_host: WireHostId,
        remote_host: WireHostId,
    ) -> io::Result<Self> {
        let local = SocketAddr::new(local.ip(), POINTER_DATAGRAM_PORT);
        let peer = SocketAddr::new(peer.ip(), POINTER_DATAGRAM_PORT);
        let socket = UdpSocket::bind(local).await?;
        socket.connect(peer).await?;
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
            received_totals: HashMap::new(),
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
        let mut payload = Vec::with_capacity(POINTER_PAYLOAD_LEN);
        payload.push(KIND_POINTER);
        payload.extend_from_slice(&input.source_device.0);
        payload.extend_from_slice(&input.timestamp_ns.to_be_bytes());
        payload.extend_from_slice(&totals.0.to_bits().to_be_bytes());
        payload.extend_from_slice(&totals.1.to_bits().to_be_bytes());
        let packet = self.encode_payload(&payload)?;
        match self.socket.try_send(&packet) {
            Ok(written) if written == packet.len() => {
                self.sent_totals.insert(input.source_device, totals);
                Ok(true)
            }
            Ok(_) => Err(io::Error::new(io::ErrorKind::WriteZero, "partial datagram")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // Consume the move: the next cumulative datagram recovers it.
                self.sent_totals.insert(input.source_device, totals);
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn receive(&mut self) -> io::Result<Option<InputEventV1>> {
        let length = self.socket.recv(&mut self.buffer).await?;
        if length < HEADER_LEN || self.buffer[..4] != MAGIC || self.buffer[4] != VERSION {
            return Ok(None);
        }
        let sequence = u64::from_be_bytes(self.buffer[5..13].try_into().unwrap_or_default());
        if self.receive_sequence.is_some_and(|last| sequence <= last) {
            return Ok(None);
        }
        let plaintext = self
            .receive_cipher
            .decrypt(&nonce(sequence), &self.buffer[HEADER_LEN..length])
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "datagram authentication failed")
            })?;
        self.receive_sequence = Some(sequence);
        match plaintext.split_first() {
            Some((&KIND_PROBE, _)) => {
                self.ready = true;
                Ok(None)
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
                Ok(Some(InputEventV1 {
                    sequence,
                    timestamp_ns,
                    source_host: self.remote_host,
                    source_device: device,
                    payload: WireInputPayloadV1::PointerMove {
                        dx: total_x - previous.0,
                        dy: total_y - previous.1,
                    },
                }))
            }
            _ => Ok(None),
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
            .is_none());
        assert!(tokio::time::timeout(Duration::from_secs(1), b.receive())
            .await
            .unwrap()
            .unwrap()
            .is_none());
        assert!(a.is_ready() && b.is_ready());

        let sent = pointer(host_a);
        assert!(a.try_send_pointer(&sent).unwrap());
        let received = tokio::time::timeout(Duration::from_secs(1), b.receive())
            .await
            .unwrap()
            .unwrap();
        let received = received.unwrap();
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

        let recovered = b.receive().await.unwrap().unwrap();
        assert!(matches!(
            recovered.payload,
            WireInputPayloadV1::PointerMove { dx, dy }
                if (dx - 5.0).abs() < f64::EPSILON && (dy + 2.0).abs() < f64::EPSILON
        ));
    }
}
