use chacha20poly1305::aead::{AeadInPlace, KeyInit, Tag};
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
use zeroize::Zeroizing;

pub(crate) const POINTER_DATAGRAM_PORT: u16 = 24_802;
const MAGIC: [u8; 4] = *b"SKVU";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 13;
const TAG_LEN: usize = 16;
const MAX_DATAGRAM: usize = 1_200;
const KIND_PROBE: u8 = 0;
const KIND_POINTER: u8 = 1;
const KIND_FEEDBACK: u8 = 2;
const KIND_RELIABLE: u8 = 3;
const KIND_RELIABLE_ACK: u8 = 4;
// kind(1) + flags(1) + device(16) + timestamp(8) + totals(16). The flags byte
// widened the payload from 33 to 42 bytes; both peers gate the datagram path
// on the same negotiated pointer-datagram protocol version and ship the same
// build, so the layout change rolls out atomically per session.
const POINTER_PAYLOAD_LEN: usize = 1 + 1 + 16 + 8 + 8 + 8;
const POINTER_FLAGS_OFFSET: usize = 1;
const POINTER_DEVICE_OFFSET: usize = 2;
const POINTER_TIMESTAMP_OFFSET: usize = 18;
const POINTER_TOTAL_X_OFFSET: usize = 26;
const POINTER_TOTAL_Y_OFFSET: usize = 34;
/// Bit 0 of the `KIND_POINTER` flags byte marks a totals rebase: the sender's
/// cumulative totals had grown past `POINTER_TOTALS_REBASE_THRESHOLD`, so it
/// reset its per-device state to (0, 0) and the transmitted totals are
/// relative to that fresh origin. The receiver must therefore ignore its
/// stored baseline for this packet — it treats (0, 0) as the previous total,
/// emits a move equal to the transmitted totals, and stores them as the new
/// baseline so accumulation restarts at full f64 resolution.
const POINTER_FLAG_REBASE: u8 = 0x01;
// An f64 mantissa carries 52 bits; once cumulative pointer totals pass 2^40
// a pixel-scale addend is at risk of rounding away, so senders rebase.
const POINTER_TOTALS_REBASE_THRESHOLD: f64 = 1_099_511_627_776.0;
const MAX_TRACKED_DEVICES: usize = 64;
const POINTER_PACING_INTERVAL: Duration = Duration::from_millis(4);
const RELIABLE_RETRY_INTERVAL: Duration = Duration::from_millis(8);
const MAX_RELIABLE_PENDING: usize = 128;
const MAX_RELIABLE_ATTEMPTS: u8 = 4;

struct PendingPointer {
    timestamp_ns: u64,
    totals: (f64, f64),
    rebase: bool,
}

struct PendingReliable {
    payload: Vec<u8>,
    last_sent: Instant,
    attempts: u8,
}

pub(crate) struct PointerDatagramPath {
    socket: UdpSocket,
    // ChaCha20Poly1305 has no Zeroize impl and its key schedule would linger
    // for the session lifetime, so the durable key material lives only in
    // these `Zeroizing` fields and per-packet ciphers are rebuilt on use.
    // `Drop` scrubs both directions eagerly.
    send_key: Zeroizing<[u8; 32]>,
    receive_key: Zeroizing<[u8; 32]>,
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
    // Receive-side datagram storage; deliberately separate from the outbound
    // scratch so an in-flight retransmit can never observe receive state.
    buffer: [u8; MAX_DATAGRAM],
    // Reused outbound packet storage so the hot path allocates nothing per
    // datagram; `encode_payload` writes here and returns the packet length.
    encode_scratch: Vec<u8>,
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
        Self::open(local, peer, session_id, local_host, remote_host)
    }

    /// Test-only variant of [`Self::bind`] that honors the caller-supplied
    /// ports, letting both loopback endpoints share a single address on hosts
    /// where only `127.0.0.1` (or `::1`) is bindable.
    #[cfg(test)]
    #[allow(clippy::unused_async)] // Mirrors the async `bind` shape for call-site uniformity.
    async fn bind_with_explicit_ports(
        local: SocketAddr,
        peer: SocketAddr,
        session_id: [u8; 32],
        local_host: WireHostId,
        remote_host: WireHostId,
    ) -> io::Result<Self> {
        Self::open(local, peer, session_id, local_host, remote_host)
    }

    fn open(
        local: SocketAddr,
        peer: SocketAddr,
        session_id: [u8; 32],
        local_host: WireHostId,
        remote_host: WireHostId,
    ) -> io::Result<Self> {
        let raw = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))?;
        raw.set_nonblocking(true)?;
        // Keep local queues bounded and request the expedited-forwarding/WMM
        // access category where the OS and access point honor DSCP.
        let _ = raw.set_send_buffer_size(64 * 1024);
        let _ = raw.set_recv_buffer_size(256 * 1024);
        mark_expedited_forwarding(&raw, local.is_ipv4());
        raw.bind(&local.into())?;
        raw.connect(&peer.into())?;
        let socket = UdpSocket::from_std(raw.into())?;
        Ok(Self {
            socket,
            send_key: session_key(&session_id, local_host),
            receive_key: session_key(&session_id, remote_host),
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
            encode_scratch: Vec::with_capacity(MAX_DATAGRAM),
        })
    }

    pub(crate) const fn is_ready(&self) -> bool {
        self.ready
    }

    fn send_cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(self.send_key.as_ref()))
    }

    fn receive_cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(self.receive_key.as_ref()))
    }

    pub(crate) async fn send_probe(&mut self) -> io::Result<()> {
        let length = self.encode_payload(&[KIND_PROBE])?;
        let written = self.socket.send(&self.encode_scratch[..length]).await?;
        if written == length {
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
        let accumulated = (previous.0 + dx, previous.1 + dy);
        // Rebase before f64 addition silently drops pixel-scale addends: the
        // transmitted totals restart from a zero origin and the receiver
        // resets its baseline to match (see `POINTER_FLAG_REBASE`).
        let (totals, rebase) = if accumulated.0.abs() > POINTER_TOTALS_REBASE_THRESHOLD
            || accumulated.1.abs() > POINTER_TOTALS_REBASE_THRESHOLD
        {
            ((dx, dy), true)
        } else {
            (accumulated, false)
        };
        self.sent_totals.insert(input.source_device, totals);
        self.pending.insert(
            input.source_device,
            PendingPointer {
                timestamp_ns: input.timestamp_ns,
                totals,
                rebase,
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
            // Fixed-size pointer payload assembled on the stack; encryption
            // reuses the struct-owned scratch buffer.
            let mut payload = [0_u8; POINTER_PAYLOAD_LEN];
            payload[0] = KIND_POINTER;
            payload[POINTER_FLAGS_OFFSET] = u8::from(pointer.rebase) * POINTER_FLAG_REBASE;
            payload[POINTER_DEVICE_OFFSET..POINTER_TIMESTAMP_OFFSET].copy_from_slice(&device.0);
            payload[POINTER_TIMESTAMP_OFFSET..POINTER_TOTAL_X_OFFSET]
                .copy_from_slice(&pointer.timestamp_ns.to_be_bytes());
            payload[POINTER_TOTAL_X_OFFSET..POINTER_TOTAL_Y_OFFSET]
                .copy_from_slice(&pointer.totals.0.to_bits().to_be_bytes());
            payload[POINTER_TOTAL_Y_OFFSET..POINTER_PAYLOAD_LEN]
                .copy_from_slice(&pointer.totals.1.to_bits().to_be_bytes());
            let length = self.encode_payload(&payload)?;
            match self.socket.try_send(&self.encode_scratch[..length]) {
                Ok(written) if written == length => {
                    if self.redundancy_budget > 0 {
                        let _ = self.socket.try_send(&self.encode_scratch[..length]);
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
        let length = self.encode_payload(&payload)?;
        match self.socket.try_send(&self.encode_scratch[..length]) {
            Ok(written) if written == length => {}
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
            let length = self.encode_payload(&pending.payload)?;
            match self.socket.try_send(&self.encode_scratch[..length]) {
                Ok(written) if written == length => {
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

    /// Receives one datagram. Malformed, replayed, unauthenticated, or
    /// out-of-window datagrams are dropped (`Ok(DatagramReceive::default())`)
    /// so a single bad packet never tears down the fast path; only local
    /// transport failures surface as `Err`.
    #[allow(clippy::too_many_lines)] // Packet kinds share one authenticated replay window.
    pub(crate) async fn receive(&mut self) -> io::Result<DatagramReceive> {
        let length = self.socket.recv(&mut self.buffer).await?;
        if length < HEADER_LEN + TAG_LEN || self.buffer[..4] != MAGIC || self.buffer[4] != VERSION {
            return Ok(DatagramReceive::default());
        }
        let sequence = u64::from_be_bytes(self.buffer[5..13].try_into().unwrap_or_default());
        if self.receive_sequence.is_some_and(|last| sequence <= last) {
            return Ok(DatagramReceive::default());
        }
        let body_end = length - TAG_LEN;
        let receive_cipher = self.receive_cipher();
        let (ciphertext, tag) = self.buffer[HEADER_LEN..length].split_at_mut(body_end - HEADER_LEN);
        if receive_cipher
            .decrypt_in_place_detached(
                &nonce(sequence),
                b"",
                ciphertext,
                Tag::<ChaCha20Poly1305>::from_slice(tag),
            )
            .is_err()
        {
            // Corrupt or forged ciphertext: drop silently so later valid
            // datagrams keep flowing instead of downgrading the session to
            // the TLS path forever.
            return Ok(DatagramReceive::default());
        }
        // Parse into owned values so no borrow of the receive buffer outlives
        // the bookkeeping and control sends below.
        let received = parse_plaintext(&self.buffer[HEADER_LEN..body_end]);
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
            let length = self.encode_payload(&[KIND_FEEDBACK])?;
            let _ = self.socket.try_send(&self.encode_scratch[..length]);
        }
        match received {
            ReceivedDatagram::Probe => {
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
            ReceivedDatagram::Pointer {
                flags,
                device,
                timestamp_ns,
                total_x,
                total_y,
            } => {
                if !self.received_totals.contains_key(&device)
                    && self.received_totals.len() >= MAX_TRACKED_DEVICES
                {
                    // New device beyond the tracking budget: drop this packet
                    // only; already-tracked devices keep flowing.
                    return Ok(DatagramReceive::default());
                }
                let previous = self
                    .received_totals
                    .insert(device, (total_x, total_y))
                    .unwrap_or_default();
                // On a rebase the transmitted totals are relative to a zero
                // origin, so the stored baseline must not contribute.
                let (base_x, base_y) = if flags & POINTER_FLAG_REBASE != 0 {
                    (0.0, 0.0)
                } else {
                    previous
                };
                let dx = total_x - base_x;
                let dy = total_y - base_y;
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
            ReceivedDatagram::Feedback => {
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
            ReceivedDatagram::Reliable {
                reliable_sequence,
                message,
            } => {
                let ahead = reliable_sequence.saturating_sub(self.reliable_receive_sequence);
                if ahead >= MAX_RELIABLE_PENDING as u64 {
                    // A sequence parked far in the future could never drain
                    // (nothing before it would arrive to advance the window)
                    // and would pin the reorder buffer at capacity.
                    return Ok(DatagramReceive::default());
                }
                if self.reliable_received.len() < MAX_RELIABLE_PENDING {
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
                    let mut ack = [0_u8; 9];
                    ack[0] = KIND_RELIABLE_ACK;
                    ack[1..].copy_from_slice(&acknowledged.to_be_bytes());
                    let length = self.encode_payload(&ack)?;
                    let _ = self.socket.try_send(&self.encode_scratch[..length]);
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
            ReceivedDatagram::ReliableAck { acknowledged } => {
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
            // Authenticated garbage or an unknown kind; TLS still carries the
            // peer's authoritative copy of any real message.
            ReceivedDatagram::Invalid => Ok(DatagramReceive::default()),
        }
    }

    /// Encrypts `payload` as one datagram into the reusable outbound scratch
    /// buffer and returns the encrypted packet length; the packet is then
    /// `&self.encode_scratch[..length]` until the next encode call.
    fn encode_payload(&mut self, payload: &[u8]) -> io::Result<usize> {
        if HEADER_LEN + TAG_LEN + payload.len() > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram too large",
            ));
        }
        let sequence = self.send_sequence;
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("datagram sequence exhausted"))?;
        self.encode_scratch.clear();
        self.encode_scratch.extend_from_slice(&MAGIC);
        self.encode_scratch.push(VERSION);
        self.encode_scratch
            .extend_from_slice(&sequence.to_be_bytes());
        self.encode_scratch.extend_from_slice(payload);
        let tag = self
            .send_cipher()
            .encrypt_in_place_detached(
                &nonce(sequence),
                b"",
                &mut self.encode_scratch[HEADER_LEN..],
            )
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "datagram encryption failed")
            })?;
        self.encode_scratch.extend_from_slice(tag.as_slice());
        Ok(self.encode_scratch.len())
    }
}

impl Drop for PointerDatagramPath {
    fn drop(&mut self) {
        // ChaCha20Poly1305 cannot scrub its own key schedule, so the only
        // durable key copies are the `Zeroizing` direction keys. Replace them
        // eagerly (dropping the old values zeroizes them) so the session keys
        // are gone before the socket and buffers tear down; the per-packet
        // cipher temporaries never outlived a single call.
        self.send_key = Zeroizing::new([0; 32]);
        self.receive_key = Zeroizing::new([0; 32]);
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

/// One decrypted datagram's kind and fully validated fields. `Invalid` covers
/// any authenticated payload that fails structural or semantic validation;
/// callers drop those rather than tearing down the path.
enum ReceivedDatagram {
    Probe,
    Pointer {
        flags: u8,
        device: WireDeviceId,
        timestamp_ns: u64,
        total_x: f64,
        total_y: f64,
    },
    Feedback,
    Reliable {
        reliable_sequence: u64,
        message: WireMessage,
    },
    ReliableAck {
        acknowledged: u64,
    },
    Invalid,
}

/// Parses and validates one decrypted payload. Field offsets are relative to
/// the full payload (kind byte included), matching the encode side in
/// `flush_pending`.
fn parse_plaintext(plaintext: &[u8]) -> ReceivedDatagram {
    match plaintext.split_first() {
        Some((&KIND_PROBE, _)) => ReceivedDatagram::Probe,
        Some((&KIND_POINTER, _)) if plaintext.len() == POINTER_PAYLOAD_LEN => {
            let device = WireDeviceId(
                plaintext[POINTER_DEVICE_OFFSET..POINTER_TIMESTAMP_OFFSET]
                    .try_into()
                    .unwrap_or_default(),
            );
            let timestamp_ns = u64::from_be_bytes(
                plaintext[POINTER_TIMESTAMP_OFFSET..POINTER_TOTAL_X_OFFSET]
                    .try_into()
                    .unwrap_or_default(),
            );
            let total_x = f64::from_bits(u64::from_be_bytes(
                plaintext[POINTER_TOTAL_X_OFFSET..POINTER_TOTAL_Y_OFFSET]
                    .try_into()
                    .unwrap_or_default(),
            ));
            let total_y = f64::from_bits(u64::from_be_bytes(
                plaintext[POINTER_TOTAL_Y_OFFSET..POINTER_PAYLOAD_LEN]
                    .try_into()
                    .unwrap_or_default(),
            ));
            if !total_x.is_finite() || !total_y.is_finite() {
                // Nonsensical totals must never enter the delta math.
                return ReceivedDatagram::Invalid;
            }
            ReceivedDatagram::Pointer {
                flags: plaintext[POINTER_FLAGS_OFFSET],
                device,
                timestamp_ns,
                total_x,
                total_y,
            }
        }
        Some((&KIND_FEEDBACK, _)) => ReceivedDatagram::Feedback,
        Some((&KIND_RELIABLE, body)) if body.len() > 8 => {
            let reliable_sequence = u64::from_be_bytes(body[..8].try_into().unwrap_or_default());
            match decode_frame_for_version(&body[8..], POINTER_DATAGRAM_PROTOCOL_VERSION) {
                Ok(message) if is_stateful_input(&message) => ReceivedDatagram::Reliable {
                    reliable_sequence,
                    message,
                },
                _ => ReceivedDatagram::Invalid,
            }
        }
        Some((&KIND_RELIABLE_ACK, body)) if body.len() == 8 => ReceivedDatagram::ReliableAck {
            acknowledged: u64::from_be_bytes(body.try_into().unwrap_or_default()),
        },
        _ => ReceivedDatagram::Invalid,
    }
}

fn session_key(session_id: &[u8; 32], sender: WireHostId) -> Zeroizing<[u8; 32]> {
    // Direction-specific keys: both sides derive the same pair, but only the
    // sender's key ever encrypts, which keeps nonce misuse off the table.
    let mut digest = Sha256::new();
    digest.update(b"software-kvm-pointer-datagram-v1\0");
    digest.update(session_id);
    digest.update(sender.0);
    let key: [u8; 32] = digest.finalize().into();
    Zeroizing::new(key)
}

fn nonce(sequence: u64) -> Nonce {
    let mut bytes = [0_u8; 12];
    bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

/// Requests the expedited-forwarding marking (DSCP 46 / WMM video) on the
/// outgoing packets. IPv4 carries it in the TOS byte; IPv6 uses the
/// equivalent traffic-class field. Failures are tolerated: marking is a
/// preference the local OS and network may decline.
fn mark_expedited_forwarding(socket: &Socket, ipv4: bool) {
    if ipv4 {
        let _ = socket.set_tos_v4(0xb8);
    } else {
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd",
        ))]
        let _ = socket.set_tclass_v6(0xb8);
    }
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
        pointer_move(source, WireDeviceId([3; 16]), 2.5, -1.0)
    }

    fn pointer_move(source: WireHostId, device: WireDeviceId, dx: f64, dy: f64) -> WireMessage {
        WireMessage::Input(InputEventV1 {
            sequence: 9,
            timestamp_ns: 11,
            source_host: source,
            source_device: device,
            payload: WireInputPayloadV1::PointerMove { dx, dy },
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

    /// Binds a connected path pair on the given addresses. Tests pass distinct
    /// ports on one loopback address so the suite runs on hosts where only
    /// `127.0.0.1` (or `::1`) is bindable.
    async fn bound_pair(
        a_addr: &str,
        b_addr: &str,
        session: [u8; 32],
        host_a: WireHostId,
        host_b: WireHostId,
    ) -> (PointerDatagramPath, PointerDatagramPath) {
        let a_addr: SocketAddr = a_addr.parse().unwrap();
        let b_addr: SocketAddr = b_addr.parse().unwrap();
        let a =
            PointerDatagramPath::bind_with_explicit_ports(a_addr, b_addr, session, host_a, host_b)
                .await
                .unwrap();
        let b =
            PointerDatagramPath::bind_with_explicit_ports(b_addr, a_addr, session, host_b, host_a)
                .await
                .unwrap();
        (a, b)
    }

    #[tokio::test]
    async fn exporter_bound_paths_exchange_pointer_after_probe() {
        let host_a = WireHostId([1; 16]);
        let host_b = WireHostId([2; 16]);
        let (mut a, mut b) = bound_pair(
            "127.0.0.1:24810",
            "127.0.0.1:24811",
            [7; 32],
            host_a,
            host_b,
        )
        .await;

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
        let mut path = PointerDatagramPath::bind_with_explicit_ports(
            "127.0.0.1:24812".parse().unwrap(),
            "127.0.0.1:24813".parse().unwrap(),
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
        let (mut a, mut b) = bound_pair(
            "127.0.0.1:24814",
            "127.0.0.1:24815",
            [9; 32],
            host_a,
            host_b,
        )
        .await;
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
        let (mut a, mut b) = bound_pair(
            "127.0.0.1:24816",
            "127.0.0.1:24817",
            [10; 32],
            host_a,
            host_b,
        )
        .await;
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

    #[tokio::test]
    async fn corrupt_ciphertext_is_dropped_without_tearing_down_the_path() {
        let host_a = WireHostId([9; 16]);
        let host_b = WireHostId([10; 16]);
        let (mut a, mut b) = bound_pair(
            "127.0.0.1:24818",
            "127.0.0.1:24819",
            [11; 32],
            host_a,
            host_b,
        )
        .await;
        a.send_probe().await.unwrap();
        b.send_probe().await.unwrap();
        a.receive().await.unwrap();
        b.receive().await.unwrap();

        // Header-valid, sequence-fresh, but garbage ciphertext.
        let mut corrupt = Vec::with_capacity(HEADER_LEN + TAG_LEN);
        corrupt.extend_from_slice(&MAGIC);
        corrupt.push(VERSION);
        corrupt.extend_from_slice(&1_000_u64.to_be_bytes());
        corrupt.extend_from_slice(&[0xff_u8; TAG_LEN]);
        a.socket.send(&corrupt).await.unwrap();

        let observed = b.receive().await.unwrap();
        assert!(observed.input.is_none() && observed.reliable_messages.is_empty());

        let sent = pointer(host_a);
        assert!(a.try_send_pointer(&sent).unwrap());
        let received = b.receive().await.unwrap().input.unwrap();
        let WireMessage::Input(sent) = sent else {
            unreachable!()
        };
        assert_eq!(received.payload, sent.payload);
    }

    #[tokio::test]
    async fn receive_device_capacity_drops_new_devices_but_keeps_tracked_ones() {
        let host_a = WireHostId([11; 16]);
        let host_b = WireHostId([12; 16]);
        let (mut a, mut b) = bound_pair(
            "127.0.0.1:24820",
            "127.0.0.1:24821",
            [12; 32],
            host_a,
            host_b,
        )
        .await;
        a.send_probe().await.unwrap();
        b.send_probe().await.unwrap();
        a.receive().await.unwrap();
        b.receive().await.unwrap();

        // Fill the tracking table to capacity without crafting 64 datagrams.
        for index in 0..MAX_TRACKED_DEVICES {
            b.received_totals
                .insert(WireDeviceId([u8::try_from(index).unwrap(); 16]), (0.0, 0.0));
        }

        let novel = pointer_move(host_a, WireDeviceId([0xaa; 16]), 3.0, 1.0);
        assert!(a.try_send_pointer(&novel).unwrap());
        assert!(b.receive().await.unwrap().input.is_none());

        let tracked = pointer_move(host_a, WireDeviceId([0; 16]), 4.0, 2.0);
        assert!(a.try_send_pointer(&tracked).unwrap());
        // The pacing window queues rather than sends; flush explicitly.
        a.flush_pending().unwrap();
        let received = b.receive().await.unwrap().input.unwrap();
        assert_eq!(received.source_device, WireDeviceId([0; 16]));
        assert!(matches!(
            received.payload,
            WireInputPayloadV1::PointerMove { dx, dy }
                if (dx - 4.0).abs() < f64::EPSILON && (dy - 2.0).abs() < f64::EPSILON
        ));
    }

    #[tokio::test]
    async fn far_future_reliable_sequence_is_dropped_and_order_still_holds() {
        let host_a = WireHostId([13; 16]);
        let host_b = WireHostId([14; 16]);
        let (mut a, mut b) = bound_pair(
            "127.0.0.1:24822",
            "127.0.0.1:24823",
            [13; 32],
            host_a,
            host_b,
        )
        .await;
        a.send_probe().await.unwrap();
        b.send_probe().await.unwrap();
        a.receive().await.unwrap();
        b.receive().await.unwrap();

        // An authenticated reliable frame parked far beyond the reorder
        // window must not wedge the buffer ahead of drainable sequences.
        let frame =
            encode_frame_for_version(&scroll(host_a, 77), POINTER_DATAGRAM_PROTOCOL_VERSION)
                .unwrap();
        let mut payload = Vec::with_capacity(9 + frame.len());
        payload.push(KIND_RELIABLE);
        payload.extend_from_slice(&(u64::MAX - 3).to_be_bytes());
        payload.extend_from_slice(&frame);
        let length = a.encode_payload(&payload).unwrap();
        a.socket.send(&a.encode_scratch[..length]).await.unwrap();

        let observed = b.receive().await.unwrap();
        assert!(observed.reliable_messages.is_empty() && observed.input.is_none());

        let first = scroll(host_a, 20);
        let second = scroll(host_a, 21);
        assert!(a.shadow_reliable(&first).unwrap());
        assert!(a.shadow_reliable(&second).unwrap());
        let received_first = b.receive().await.unwrap();
        let received_second = b.receive().await.unwrap();
        let mut received = received_first.reliable_messages;
        received.extend(received_second.reliable_messages);
        assert_eq!(received, vec![first, second]);
    }

    #[tokio::test]
    async fn pointer_totals_rebase_preserves_small_deltas_at_huge_magnitudes() {
        let host_a = WireHostId([15; 16]);
        let host_b = WireHostId([16; 16]);
        let (mut a, mut b) = bound_pair(
            "127.0.0.1:24824",
            "127.0.0.1:24825",
            [14; 32],
            host_a,
            host_b,
        )
        .await;
        a.send_probe().await.unwrap();
        b.send_probe().await.unwrap();
        a.receive().await.unwrap();
        b.receive().await.unwrap();

        let device = WireDeviceId([3; 16]);
        // 2^60 + 2^20 is exactly representable, but its ulp is 256, so a
        // follow-up 1.0 delta would round away absent a rebase.
        let huge = 2.0_f64.powi(60) + 2.0_f64.powi(20);
        let first = pointer_move(host_a, device, huge, 0.0);
        assert!(a.try_send_pointer(&first).unwrap());
        let received = b.receive().await.unwrap().input.unwrap();
        assert!(matches!(
            received.payload,
            WireInputPayloadV1::PointerMove { dx, dy }
                if (dx - huge).abs() < f64::EPSILON && (dy - 0.0).abs() < f64::EPSILON
        ));
        // The sender restarted its accumulator at the transmitted totals.
        assert_eq!(a.sent_totals.get(&device), Some(&(huge, 0.0)));

        let followup = pointer_move(host_a, device, 1.0, -0.5);
        assert!(a.try_send_pointer(&followup).unwrap());
        a.flush_pending().unwrap();
        let received = b.receive().await.unwrap().input.unwrap();
        assert!(matches!(
            received.payload,
            WireInputPayloadV1::PointerMove { dx, dy }
                if (dx - 1.0).abs() < f64::EPSILON && (dy + 0.5).abs() < f64::EPSILON
        ));
        // The receiver adopted the rebased totals as its new baseline.
        assert_eq!(b.received_totals.get(&device), Some(&(1.0, -0.5)));
    }

    #[tokio::test]
    async fn sequence_exhaustion_surfaces_send_side_errors() {
        let mut a = PointerDatagramPath::bind_with_explicit_ports(
            "127.0.0.1:24826".parse().unwrap(),
            "127.0.0.1:24827".parse().unwrap(),
            [15; 32],
            WireHostId([17; 16]),
            WireHostId([18; 16]),
        )
        .await
        .unwrap();

        a.send_sequence = u64::MAX;
        assert_eq!(
            a.send_probe().await.unwrap_err().to_string(),
            "datagram sequence exhausted"
        );

        a.ready = true;
        a.reliable_send_sequence = u64::MAX;
        assert_eq!(
            a.shadow_reliable(&scroll(WireHostId([17; 16]), 5))
                .unwrap_err()
                .to_string(),
            "reliable sequence exhausted"
        );
    }

    #[tokio::test]
    async fn non_finite_pointer_totals_are_dropped_without_tearing_down() {
        let host_a = WireHostId([19; 16]);
        let host_b = WireHostId([20; 16]);
        let (mut a, mut b) = bound_pair(
            "127.0.0.1:24828",
            "127.0.0.1:24829",
            [16; 32],
            host_a,
            host_b,
        )
        .await;
        a.send_probe().await.unwrap();
        b.send_probe().await.unwrap();
        a.receive().await.unwrap();
        b.receive().await.unwrap();

        let craft = |x: f64, y: f64| {
            let mut payload = [0_u8; POINTER_PAYLOAD_LEN];
            payload[0] = KIND_POINTER;
            payload[POINTER_FLAGS_OFFSET] = 0;
            payload[POINTER_DEVICE_OFFSET..POINTER_TIMESTAMP_OFFSET]
                .copy_from_slice(&WireDeviceId([3; 16]).0);
            payload[POINTER_TIMESTAMP_OFFSET..POINTER_TOTAL_X_OFFSET]
                .copy_from_slice(&11_u64.to_be_bytes());
            payload[POINTER_TOTAL_X_OFFSET..POINTER_TOTAL_Y_OFFSET]
                .copy_from_slice(&x.to_bits().to_be_bytes());
            payload[POINTER_TOTAL_Y_OFFSET..POINTER_PAYLOAD_LEN]
                .copy_from_slice(&y.to_bits().to_be_bytes());
            payload
        };
        for totals in [craft(f64::NAN, 0.0), craft(0.0, f64::INFINITY)] {
            let length = a.encode_payload(&totals).unwrap();
            a.socket.send(&a.encode_scratch[..length]).await.unwrap();
            let observed = b.receive().await.unwrap();
            assert!(observed.input.is_none() && observed.reliable_messages.is_empty());
        }

        let sent = pointer(host_a);
        assert!(a.try_send_pointer(&sent).unwrap());
        let received = b.receive().await.unwrap().input.unwrap();
        let WireMessage::Input(sent) = sent else {
            unreachable!()
        };
        assert_eq!(received.payload, sent.payload);
    }

    #[tokio::test]
    async fn ipv6_loopback_paths_exchange_pointer_after_probe() {
        let host_a = WireHostId([21; 16]);
        let host_b = WireHostId([22; 16]);
        let (mut a, mut b) =
            bound_pair("[::1]:24830", "[::1]:24831", [17; 32], host_a, host_b).await;
        a.send_probe().await.unwrap();
        b.send_probe().await.unwrap();
        a.receive().await.unwrap();
        b.receive().await.unwrap();
        assert!(a.is_ready() && b.is_ready());

        let sent = pointer(host_a);
        assert!(a.try_send_pointer(&sent).unwrap());
        let received = b.receive().await.unwrap().input.unwrap();
        let WireMessage::Input(sent) = sent else {
            unreachable!()
        };
        assert_eq!(received.payload, sent.payload);
    }

    #[test]
    fn ipv6_sockets_mark_expedited_forwarding_traffic_class() {
        let raw = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        mark_expedited_forwarding(&raw, false);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(raw.tclass_v6().unwrap(), 0xb8);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = raw;
    }
}
