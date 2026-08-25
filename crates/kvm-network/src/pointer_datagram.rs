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
use thiserror::Error;
use tokio::net::UdpSocket;
use zeroize::Zeroizing;

/// UDP port both session peers bind for the pointer-datagram fast path.
pub const POINTER_DATAGRAM_PORT: u16 = 24_802;
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
/// Baseline pacing interval before any feedback has been observed. Matches
/// the receiving session's 2 ms pointer-release tick so the fold buffer is
/// fed at the finest cadence it can drain. Once the adaptive controller
/// engages, the interval moves within [`PACING_INTERVAL_MIN`]
/// ..=[`PACING_INTERVAL_MAX`].
const POINTER_PACING_INTERVAL: Duration = Duration::from_millis(2);
/// Fastest pacing the adaptive controller may select. Equal to the baseline:
/// a healthy link paces as fast as the release cadence allows.
const PACING_INTERVAL_MIN: Duration = Duration::from_millis(2);
/// Slowest pacing the adaptive controller may select under worst-case loss.
const PACING_INTERVAL_MAX: Duration = Duration::from_millis(16);
/// Redundant copies granted by the lowest adaptation level once the
/// controller engages. Before any feedback arrives the grant stays at zero:
/// a loss-free link sends no redundant datagrams at all.
const REDUNDANCY_BUDGET_MIN: usize = 2;
/// Redundant copies granted by the highest adaptation level.
const REDUNDANCY_BUDGET_MAX: usize = 16;
/// Gap feedback arriving at least this close to its predecessor extends the
/// storm streak that drives escalation.
const FEEDBACK_STORM_WINDOW: Duration = Duration::from_millis(48);
/// Consecutive stormy feedbacks required before parameters escalate. One
/// stray report changes nothing (hysteresis on the escalation side).
const FEEDBACK_STORM_THRESHOLD: u32 = 2;
/// Feedback silence required before parameters relax (hysteresis on the
/// relaxation side: escalation consumes events, relaxation consumes their
/// absence, so the two can never alternate off one observation).
const FEEDBACK_QUIET_WINDOW: Duration = Duration::from_millis(200);
/// Minimum spacing between any two parameter adjustments, either direction.
const ADAPTATION_COOLDOWN: Duration = Duration::from_millis(100);
const RELIABLE_RETRY_INTERVAL: Duration = Duration::from_millis(8);
const MAX_RELIABLE_PENDING: usize = 128;
const MAX_RELIABLE_ATTEMPTS: u8 = 4;

/// Configuration for the UDP pointer-datagram fast path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointerDatagramConfig {
    /// UDP port both session peers bind for the fast path. The default is the
    /// wire-negotiated [`POINTER_DATAGRAM_PORT`]; tests and multi-session
    /// hosts (where the default port is already occupied) override it with a
    /// port both peers of that session agree on out of band.
    pub port: u16,
}

impl Default for PointerDatagramConfig {
    fn default() -> Self {
        Self {
            port: POINTER_DATAGRAM_PORT,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PointerDatagramConfigError {
    #[error("pointer-datagram port must be nonzero")]
    ZeroPort,
}

impl PointerDatagramConfig {
    /// Validates the configurable fast-path parameters.
    ///
    /// # Errors
    ///
    /// Returns [`PointerDatagramConfigError::ZeroPort`] when the port is the
    /// wildcard value, which no remote peer could ever target.
    pub fn validate(self) -> Result<(), PointerDatagramConfigError> {
        if self.port == 0 {
            return Err(PointerDatagramConfigError::ZeroPort);
        }
        Ok(())
    }
}

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

/// Bounded adaptive controller for the fast path's pacing interval and
/// redundancy budget.
///
/// Escalation (more redundant copies, longer pacing interval) reacts to
/// feedback storms: the receiver's gap reports arriving close together.
/// Relaxation (fewer copies, shorter interval) requires a sustained feedback
/// silence, and only engages once at least one gap report has been observed —
/// before that the path keeps the fixed no-evidence baseline (2 ms pacing,
/// no redundancy), exactly matching the pre-adaptive behavior on a loss-free
/// link. Oscillation is prevented by construction:
///
/// - escalation consumes at least [`FEEDBACK_STORM_THRESHOLD`] feedbacks
///   inside [`FEEDBACK_STORM_WINDOW`] of each other;
/// - relaxation requires [`FEEDBACK_QUIET_WINDOW`] with *no* feedback;
/// - consecutive adjustments in the same direction are spaced by
///   [`ADAPTATION_COOLDOWN`], while the two directions respond to mutually
///   exclusive evidence (feedback present vs absent), so they can never
///   alternate off one observation.
///
/// An up→down→up cycle therefore always spans at least one full quiet window
/// plus a fresh storm — sustained loss, not controller churn. All values are
/// clamped to `REDUNDANCY_BUDGET_MIN..=REDUNDANCY_BUDGET_MAX` copies (zero
/// only before the first engagement) and `PACING_INTERVAL_MIN..=
/// PACING_INTERVAL_MAX` milliseconds.
///
/// Every entry point takes the elapsed time since path creation instead of
/// reading a clock, which keeps the whole controller deterministic and
/// unit-testable without sockets or sleeps.
#[derive(Clone, Copy, Debug)]
struct AdaptivePacing {
    /// Remaining redundant datagram copies granted by the current level.
    redundancy_budget: usize,
    pacing_interval: Duration,
    /// Feedbacks currently inside the storm window; reset when escalation
    /// consumes the signal or a slow feedback breaks the streak.
    storm_streak: u32,
    last_feedback: Option<Duration>,
    last_escalation: Option<Duration>,
    last_relaxation: Option<Duration>,
}

impl AdaptivePacing {
    fn new() -> Self {
        Self {
            redundancy_budget: 0,
            pacing_interval: POINTER_PACING_INTERVAL,
            storm_streak: 0,
            last_feedback: None,
            last_escalation: None,
            last_relaxation: None,
        }
    }

    fn pacing_interval(&self) -> Duration {
        self.pacing_interval
    }

    /// Records one received gap report at `elapsed` since path creation.
    fn note_feedback(&mut self, elapsed: Duration) {
        let stormy = self
            .last_feedback
            .is_some_and(|last| elapsed.saturating_sub(last) <= FEEDBACK_STORM_WINDOW);
        self.storm_streak = if stormy {
            self.storm_streak.saturating_add(1)
        } else {
            1
        };
        self.last_feedback = Some(elapsed);
        let cooled = self
            .last_escalation
            .is_none_or(|last| elapsed.saturating_sub(last) >= ADAPTATION_COOLDOWN);
        if self.storm_streak >= FEEDBACK_STORM_THRESHOLD && cooled {
            self.escalate(elapsed);
        }
    }

    /// Re-examines feedback cadence on the flush tick; relaxing requires the
    /// full quiet window and only runs once feedback has been observed at
    /// least once (no evidence yet means the baseline, not the floor).
    fn refresh(&mut self, elapsed: Duration) {
        let quiet = self
            .last_feedback
            .is_some_and(|last| elapsed.saturating_sub(last) >= FEEDBACK_QUIET_WINDOW);
        let cooled = self
            .last_relaxation
            .is_none_or(|last| elapsed.saturating_sub(last) >= ADAPTATION_COOLDOWN);
        if quiet && cooled {
            self.relax(elapsed);
        }
    }

    /// Doubles both parameters within their bounds and consumes the storm.
    fn escalate(&mut self, elapsed: Duration) {
        self.redundancy_budget = if self.redundancy_budget < REDUNDANCY_BUDGET_MIN {
            REDUNDANCY_BUDGET_MIN
        } else {
            (self.redundancy_budget * 2).min(REDUNDANCY_BUDGET_MAX)
        };
        self.pacing_interval = (self.pacing_interval * 2).min(PACING_INTERVAL_MAX);
        self.storm_streak = 0;
        self.last_escalation = Some(elapsed);
    }

    /// Halves both parameters within their bounds. A never-engaged budget
    /// stays at zero: relaxation never grants redundancy, only escalation
    /// does.
    fn relax(&mut self, elapsed: Duration) {
        let target_budget = if self.redundancy_budget == 0 {
            0
        } else {
            (self.redundancy_budget / 2).max(REDUNDANCY_BUDGET_MIN)
        };
        let target_pacing = (self.pacing_interval / 2).max(PACING_INTERVAL_MIN);
        if target_budget == self.redundancy_budget && target_pacing == self.pacing_interval {
            // Already relaxed; leave the adjustment clock untouched so a
            // later relaxation step is not delayed by a no-op.
            return;
        }
        self.redundancy_budget = target_budget;
        self.pacing_interval = target_pacing;
        self.last_relaxation = Some(elapsed);
    }

    /// Consumes one redundant-copy allowance for a just-sent datagram.
    fn spend_redundancy(&mut self) -> bool {
        if self.redundancy_budget == 0 {
            return false;
        }
        self.redundancy_budget -= 1;
        true
    }
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
    // Adaptive pacing/redundancy state; driven by elapsed time from
    // `started_at` so the controller itself stays deterministic.
    pacing: AdaptivePacing,
    started_at: Instant,
    reliable_send_sequence: u64,
    // Receive-side reorder buffer for the reliable shadow path.
    reliable_reorder: ReliableReorderBuffer,
    reliable_pending: BTreeMap<u64, PendingReliable>,
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
        config: PointerDatagramConfig,
    ) -> io::Result<Self> {
        let local = SocketAddr::new(local.ip(), config.port);
        let peer = SocketAddr::new(peer.ip(), config.port);
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
            pacing: AdaptivePacing::new(),
            started_at: Instant::now(),
            reliable_send_sequence: 0,
            reliable_reorder: ReliableReorderBuffer::new(),
            reliable_pending: BTreeMap::new(),
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
            .is_some_and(|last| last.elapsed() < self.pacing.pacing_interval())
        {
            return Ok(true);
        }
        self.flush_pending().map(|_| true)
    }

    pub(crate) fn flush_pending(&mut self) -> io::Result<usize> {
        // The flush tick is the controller's relaxation heartbeat: it fires
        // on the session's 2 ms cadence whether or not anything is pending,
        // so a feedback-free window relaxes pacing even on an idle path.
        self.pacing.refresh(self.started_at.elapsed());
        if !self.ready || self.pending.is_empty() {
            return Ok(0);
        }
        // The escalated pacing interval must govern the wire, not just the
        // event-driven path in `try_send_pointer`: without this gate the
        // 2 ms flush tick drains `pending` regardless of the controller's
        // decision and the 8/16 ms degraded states never materialize.
        // Pending stays queued for the next eligible tick.
        if self
            .last_pointer_send
            .is_some_and(|last| last.elapsed() < self.pacing.pacing_interval())
        {
            return Ok(0);
        }
        let pending = std::mem::take(&mut self.pending);
        let mut sent = 0;
        for (device, pointer) in pending {
            // Fixed-size pointer payload assembled on the stack; encryption
            // reuses the struct-owned scratch buffer.
            let flags = u8::from(pointer.rebase) * POINTER_FLAG_REBASE;
            let payload =
                encode_pointer_plaintext(flags, device, pointer.timestamp_ns, pointer.totals);
            let length = self.encode_payload(&payload)?;
            match self.socket.try_send(&self.encode_scratch[..length]) {
                Ok(written) if written == length => {
                    if self.pacing.spend_redundancy() {
                        let _ = self.socket.try_send(&self.encode_scratch[..length]);
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
        let sent = match self.socket.try_send(&self.encode_scratch[..length]) {
            Ok(written) if written == length => true,
            Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "partial datagram")),
            // Nothing went out, so this must not consume a retry attempt or
            // wait out a retry interval: `maintain_reliable` treats a
            // zero-attempt entry as immediately due.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
            Err(error) => return Err(error),
        };
        self.reliable_pending.insert(
            sequence,
            PendingReliable {
                payload,
                last_sent: Instant::now(),
                attempts: u8::from(sent),
            },
        );
        Ok(true)
    }

    pub(crate) fn maintain_reliable(&mut self) -> io::Result<usize> {
        let due: Vec<u64> = self
            .reliable_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.attempts == 0 || pending.last_sent.elapsed() >= RELIABLE_RETRY_INTERVAL)
                    .then_some(*sequence)
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
        let received = parse_pointer_datagram_plaintext(&self.buffer[HEADER_LEN..body_end]);
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
            PointerDatagramPlaintext::Probe => {
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
            PointerDatagramPlaintext::Pointer {
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
            PointerDatagramPlaintext::Feedback => {
                // The receiver saw receive-window gaps; feed the observed
                // cadence to the adaptive controller (parameters only, the
                // wire format is untouched).
                self.pacing.note_feedback(self.started_at.elapsed());
                Ok(DatagramReceive {
                    gaps,
                    jitter_us,
                    silence_ms,
                    input: None,
                    recovery_milliunits: 0,
                    reliable_messages: Vec::new(),
                })
            }
            PointerDatagramPlaintext::Reliable {
                reliable_sequence,
                message,
            } => {
                let Some((reliable_messages, acknowledged)) =
                    self.reliable_reorder.insert(reliable_sequence, message)
                else {
                    // A sequence parked far in the future could never drain
                    // (nothing before it would arrive to advance the window)
                    // and would pin the reorder buffer at capacity.
                    return Ok(DatagramReceive::default());
                };
                if let Some(acknowledged) = acknowledged {
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
            PointerDatagramPlaintext::ReliableAck { acknowledged } => {
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
            PointerDatagramPlaintext::Invalid => Ok(DatagramReceive::default()),
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

/// One decrypted datagram's kind and fully validated fields.
///
/// `Invalid` covers any authenticated payload that fails structural or
/// semantic validation; the session path drops those rather than tearing
/// down the fast path. Public so cargo-fuzz targets and criterion benches
/// can exercise the parser without a socket, session keys, or a peer.
#[derive(Clone, Debug, PartialEq)]
pub enum PointerDatagramPlaintext {
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

/// Receive-side reorder buffer for the reliable datagram shadow path.
///
/// Holds sequenced messages that arrived ahead of the next expected
/// sequence and drains them in order once the gap fills. Public for the
/// same tooling reason as [`PointerDatagramPlaintext`]; the session treats
/// it as an internal detail.
#[derive(Debug, Default)]
pub struct ReliableReorderBuffer {
    next_sequence: u64,
    buffered: BTreeMap<u64, WireMessage>,
}

impl ReliableReorderBuffer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_sequence: 0,
            buffered: BTreeMap::new(),
        }
    }

    /// Inserts one authenticated sequenced message and drains every message
    /// that is now deliverable in order.
    ///
    /// Sequences parked so far ahead that the buffer could never drain past
    /// them are ignored (`None`): nothing before them would arrive to
    /// advance the window and the buffer would pin at capacity. Sequences
    /// below `next_sequence` were already delivered — a retransmission
    /// landing there is acknowledged again without insertion, because no
    /// drain path can ever remove a below-window entry and 128 of them
    /// would wedge the buffer at capacity for the session's lifetime.
    ///
    /// Returns the drained messages plus the highest contiguous sequence
    /// received so far (the cumulative acknowledgement value), or `None`
    /// when the sequence was rejected as unreachably far in the future.
    pub fn insert(
        &mut self,
        sequence: u64,
        message: WireMessage,
    ) -> Option<(Vec<WireMessage>, Option<u64>)> {
        if sequence.saturating_sub(self.next_sequence) >= MAX_RELIABLE_PENDING as u64 {
            return None;
        }
        if sequence < self.next_sequence {
            return Some((Vec::new(), self.next_sequence.checked_sub(1)));
        }
        if self.buffered.len() < MAX_RELIABLE_PENDING {
            self.buffered.entry(sequence).or_insert(message);
        }
        let mut drained = Vec::new();
        while let Some(message) = self.buffered.remove(&self.next_sequence) {
            drained.push(message);
            self.next_sequence += 1;
        }
        Some((drained, self.next_sequence.checked_sub(1)))
    }
}

/// Assembles one `KIND_POINTER` plaintext payload from its fields.
///
/// This is the single encode-side source of truth for the pointer layout;
/// the session flush path and external tooling (fuzz round-trips, benches)
/// share it so the two sides cannot drift.
#[must_use]
pub fn encode_pointer_plaintext(
    flags: u8,
    device: WireDeviceId,
    timestamp_ns: u64,
    totals: (f64, f64),
) -> [u8; POINTER_PAYLOAD_LEN] {
    let mut payload = [0_u8; POINTER_PAYLOAD_LEN];
    payload[0] = KIND_POINTER;
    payload[POINTER_FLAGS_OFFSET] = flags;
    payload[POINTER_DEVICE_OFFSET..POINTER_TIMESTAMP_OFFSET].copy_from_slice(&device.0);
    payload[POINTER_TIMESTAMP_OFFSET..POINTER_TOTAL_X_OFFSET]
        .copy_from_slice(&timestamp_ns.to_be_bytes());
    payload[POINTER_TOTAL_X_OFFSET..POINTER_TOTAL_Y_OFFSET]
        .copy_from_slice(&totals.0.to_bits().to_be_bytes());
    payload[POINTER_TOTAL_Y_OFFSET..POINTER_PAYLOAD_LEN]
        .copy_from_slice(&totals.1.to_bits().to_be_bytes());
    payload
}

/// Parses and validates one decrypted payload. Field offsets are relative to
/// the full payload (kind byte included), matching the encode side in
/// [`encode_pointer_plaintext`].
#[must_use]
pub fn parse_pointer_datagram_plaintext(plaintext: &[u8]) -> PointerDatagramPlaintext {
    match plaintext.split_first() {
        Some((&KIND_PROBE, _)) => PointerDatagramPlaintext::Probe,
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
                return PointerDatagramPlaintext::Invalid;
            }
            PointerDatagramPlaintext::Pointer {
                flags: plaintext[POINTER_FLAGS_OFFSET],
                device,
                timestamp_ns,
                total_x,
                total_y,
            }
        }
        Some((&KIND_FEEDBACK, _)) => PointerDatagramPlaintext::Feedback,
        Some((&KIND_RELIABLE, body)) if body.len() > 8 => {
            let reliable_sequence = u64::from_be_bytes(body[..8].try_into().unwrap_or_default());
            match decode_frame_for_version(&body[8..], POINTER_DATAGRAM_PROTOCOL_VERSION) {
                Ok(message) if is_stateful_input(&message) => PointerDatagramPlaintext::Reliable {
                    reliable_sequence,
                    message,
                },
                _ => PointerDatagramPlaintext::Invalid,
            }
        }
        Some((&KIND_RELIABLE_ACK, body)) if body.len() == 8 => {
            PointerDatagramPlaintext::ReliableAck {
                acknowledged: u64::from_be_bytes(body.try_into().unwrap_or_default()),
            }
        }
        _ => PointerDatagramPlaintext::Invalid,
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

    /// Timeout-wraps every datagram receive: a bare `.await` against a lossy
    /// or wedged UDP peer hangs the suite outright (past incident in this
    /// repo), while the wrapper turns it into a test failure.
    async fn recv(path: &mut PointerDatagramPath) -> DatagramReceive {
        tokio::time::timeout(Duration::from_secs(2), path.receive())
            .await
            .expect("datagram receive timed out")
            .expect("datagram receive failed")
    }

    /// Timeout-wrapped raw receive used to model in-network loss by pulling a
    /// datagram off the socket and discarding it.
    async fn recv_raw(path: &mut PointerDatagramPath, buffer: &mut [u8]) -> usize {
        tokio::time::timeout(Duration::from_secs(2), path.socket.recv(buffer))
            .await
            .expect("raw datagram receive timed out")
            .expect("raw datagram receive failed")
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
        assert!(recv(&mut a).await.input.is_none());
        assert!(recv(&mut b).await.input.is_none());
        assert!(a.is_ready() && b.is_ready());

        let sent = pointer(host_a);
        assert!(a.try_send_pointer(&sent).unwrap());
        let received = recv(&mut b).await.input.unwrap();
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
        recv(&mut a).await;
        recv(&mut b).await;

        let movement = pointer(host_a);
        assert!(a.try_send_pointer(&movement).unwrap());
        // Model network loss by removing the first encrypted packet before the
        // path can decode it and update its receive baseline.
        let mut discarded = [0_u8; MAX_DATAGRAM];
        recv_raw(&mut b, &mut discarded).await;
        assert!(a.try_send_pointer(&movement).unwrap());
        a.last_pointer_send = None;
        a.flush_pending().unwrap();

        let recovered = recv(&mut b).await.input.unwrap();
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
        recv(&mut a).await;
        recv(&mut b).await;

        let first = scroll(host_a, 20);
        let second = scroll(host_a, 21);
        assert!(a.shadow_reliable(&first).unwrap());
        assert!(a.shadow_reliable(&second).unwrap());
        let received_first = recv(&mut b).await;
        let received_second = recv(&mut b).await;
        let mut received = received_first.reliable_messages;
        received.extend(received_second.reliable_messages);
        assert_eq!(received, vec![first, second]);
        recv(&mut a).await;
        recv(&mut a).await;
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
        recv(&mut a).await;
        recv(&mut b).await;

        // Header-valid, sequence-fresh, but garbage ciphertext.
        let mut corrupt = Vec::with_capacity(HEADER_LEN + TAG_LEN);
        corrupt.extend_from_slice(&MAGIC);
        corrupt.push(VERSION);
        corrupt.extend_from_slice(&1_000_u64.to_be_bytes());
        corrupt.extend_from_slice(&[0xff_u8; TAG_LEN]);
        a.socket.send(&corrupt).await.unwrap();

        let observed = recv(&mut b).await;
        assert!(observed.input.is_none() && observed.reliable_messages.is_empty());

        let sent = pointer(host_a);
        assert!(a.try_send_pointer(&sent).unwrap());
        let received = recv(&mut b).await.input.unwrap();
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
        recv(&mut a).await;
        recv(&mut b).await;

        // Fill the tracking table to capacity without crafting 64 datagrams.
        for index in 0..MAX_TRACKED_DEVICES {
            b.received_totals
                .insert(WireDeviceId([u8::try_from(index).unwrap(); 16]), (0.0, 0.0));
        }

        let novel = pointer_move(host_a, WireDeviceId([0xaa; 16]), 3.0, 1.0);
        assert!(a.try_send_pointer(&novel).unwrap());
        assert!(recv(&mut b).await.input.is_none());

        let tracked = pointer_move(host_a, WireDeviceId([0; 16]), 4.0, 2.0);
        assert!(a.try_send_pointer(&tracked).unwrap());
        // The pacing window queues rather than sends; simulate an elapsed
        // window, then flush explicitly.
        a.last_pointer_send = None;
        a.flush_pending().unwrap();
        let received = recv(&mut b).await.input.unwrap();
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
        recv(&mut a).await;
        recv(&mut b).await;

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

        let observed = recv(&mut b).await;
        assert!(observed.reliable_messages.is_empty() && observed.input.is_none());

        let first = scroll(host_a, 20);
        let second = scroll(host_a, 21);
        assert!(a.shadow_reliable(&first).unwrap());
        assert!(a.shadow_reliable(&second).unwrap());
        let received_first = recv(&mut b).await;
        let received_second = recv(&mut b).await;
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
        recv(&mut a).await;
        recv(&mut b).await;

        let device = WireDeviceId([3; 16]);
        // 2^60 + 2^20 is exactly representable, but its ulp is 256, so a
        // follow-up 1.0 delta would round away absent a rebase.
        let huge = 2.0_f64.powi(60) + 2.0_f64.powi(20);
        let first = pointer_move(host_a, device, huge, 0.0);
        assert!(a.try_send_pointer(&first).unwrap());
        let received = recv(&mut b).await.input.unwrap();
        assert!(matches!(
            received.payload,
            WireInputPayloadV1::PointerMove { dx, dy }
                if (dx - huge).abs() < f64::EPSILON && (dy - 0.0).abs() < f64::EPSILON
        ));
        // The sender restarted its accumulator at the transmitted totals.
        assert_eq!(a.sent_totals.get(&device), Some(&(huge, 0.0)));

        let followup = pointer_move(host_a, device, 1.0, -0.5);
        assert!(a.try_send_pointer(&followup).unwrap());
        a.last_pointer_send = None;
        a.flush_pending().unwrap();
        let received = recv(&mut b).await.input.unwrap();
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
        recv(&mut a).await;
        recv(&mut b).await;

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
            let observed = recv(&mut b).await;
            assert!(observed.input.is_none() && observed.reliable_messages.is_empty());
        }

        let sent = pointer(host_a);
        assert!(a.try_send_pointer(&sent).unwrap());
        let received = recv(&mut b).await.input.unwrap();
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
        recv(&mut a).await;
        recv(&mut b).await;
        assert!(a.is_ready() && b.is_ready());

        let sent = pointer(host_a);
        assert!(a.try_send_pointer(&sent).unwrap());
        let received = recv(&mut b).await.input.unwrap();
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

    // --- Configurable port --------------------------------------------------

    #[test]
    fn datagram_config_defaults_to_the_wire_port_and_validates() {
        let config = PointerDatagramConfig::default();
        assert_eq!(config.port, POINTER_DATAGRAM_PORT);
        assert_eq!(config.port, 24_802);
        assert!(config.validate().is_ok());
        assert_eq!(
            PointerDatagramConfig { port: 0 }.validate(),
            Err(PointerDatagramConfigError::ZeroPort)
        );
    }

    #[test]
    fn persistent_peer_config_carries_and_validates_the_datagram_port() {
        let config = crate::peer::PersistentPeerConfig::default();
        assert_eq!(config.pointer_datagram, PointerDatagramConfig::default());
        assert!(config.validate().is_ok());
        let invalid = crate::peer::PersistentPeerConfig {
            pointer_datagram: PointerDatagramConfig { port: 0 },
            ..crate::peer::PersistentPeerConfig::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[tokio::test]
    async fn overridden_port_is_threaded_through_bind() {
        // bind() must rewrite both endpoints to the configured port; the
        // local socket's bound address is the observable proof. (A full
        // two-path exchange cannot share one port on a single loopback
        // address, which is why the exchange tests use explicit ports.)
        let config = PointerDatagramConfig { port: 24_859 };
        let path = PointerDatagramPath::bind(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
            [19; 32],
            WireHostId([25; 16]),
            WireHostId([26; 16]),
            config,
        )
        .await
        .unwrap();
        assert_eq!(path.socket.local_addr().unwrap().port(), 24_859);
    }

    // --- Adaptive pacing and redundancy -------------------------------------

    #[test]
    fn pacing_starts_at_the_baseline_with_no_redundancy() {
        let pacing = AdaptivePacing::new();
        assert_eq!(pacing.pacing_interval(), POINTER_PACING_INTERVAL);
        assert_eq!(pacing.redundancy_budget, 0);
    }

    #[test]
    fn one_stray_feedback_does_not_escalate() {
        let mut pacing = AdaptivePacing::new();
        pacing.note_feedback(Duration::from_millis(10));
        assert_eq!(pacing.pacing_interval(), POINTER_PACING_INTERVAL);
        assert_eq!(pacing.redundancy_budget, 0);
    }

    #[test]
    fn slow_cadence_feedback_never_escalates() {
        let mut pacing = AdaptivePacing::new();
        // Feedback well outside the storm window resets the streak each time.
        for millis in [0_u64, 500, 1_000, 1_500, 2_000] {
            pacing.note_feedback(Duration::from_millis(millis));
        }
        assert_eq!(pacing.pacing_interval(), POINTER_PACING_INTERVAL);
        assert_eq!(pacing.redundancy_budget, 0);
    }

    #[test]
    fn first_storm_engages_at_the_minimum_adaptation_level() {
        let mut pacing = AdaptivePacing::new();
        pacing.note_feedback(Duration::from_millis(5));
        pacing.note_feedback(Duration::from_millis(10));
        assert_eq!(pacing.redundancy_budget, REDUNDANCY_BUDGET_MIN);
        assert_eq!(pacing.pacing_interval(), Duration::from_millis(4));
    }

    #[test]
    fn sustained_storms_escalate_only_up_to_the_bounds() {
        let mut pacing = AdaptivePacing::new();
        // Storm pairs spaced past the cooldown: 0+10, 200+210, 400+410, ...
        let mut elapsed = 0_u64;
        for _ in 0..6 {
            pacing.note_feedback(Duration::from_millis(elapsed));
            elapsed += 10;
            pacing.note_feedback(Duration::from_millis(elapsed));
            elapsed += 190;
        }
        assert_eq!(pacing.redundancy_budget, REDUNDANCY_BUDGET_MAX);
        assert_eq!(pacing.pacing_interval(), PACING_INTERVAL_MAX);
    }

    #[test]
    fn quiet_windows_relax_stepwise_and_never_below_the_floor() {
        let mut pacing = AdaptivePacing::new();
        let mut elapsed = 0_u64;
        for _ in 0..4 {
            pacing.note_feedback(Duration::from_millis(elapsed));
            elapsed += 10;
            pacing.note_feedback(Duration::from_millis(elapsed));
            elapsed += 190;
        }
        assert_eq!(pacing.redundancy_budget, REDUNDANCY_BUDGET_MAX);
        assert_eq!(pacing.pacing_interval(), PACING_INTERVAL_MAX);

        // Before the quiet window elapses nothing relaxes: 90 ms since the
        // last feedback is still inside the 200 ms window, and so is 140 ms.
        pacing.refresh(Duration::from_millis(700));
        pacing.refresh(Duration::from_millis(750));
        assert_eq!(pacing.redundancy_budget, REDUNDANCY_BUDGET_MAX);
        assert_eq!(pacing.pacing_interval(), PACING_INTERVAL_MAX);

        // Past the window each refresh relaxes one step, spaced by the
        // cooldown: 16 → 8 → 4 → 2, then the floor holds.
        pacing.refresh(Duration::from_millis(900));
        assert_eq!(pacing.redundancy_budget, 8);
        assert_eq!(pacing.pacing_interval(), Duration::from_millis(8));
        pacing.refresh(Duration::from_secs(1));
        assert_eq!(pacing.redundancy_budget, 4);
        assert_eq!(pacing.pacing_interval(), Duration::from_millis(4));
        pacing.refresh(Duration::from_millis(1_100));
        assert_eq!(pacing.redundancy_budget, REDUNDANCY_BUDGET_MIN);
        assert_eq!(pacing.pacing_interval(), PACING_INTERVAL_MIN);
        pacing.refresh(Duration::from_millis(1_200));
        pacing.refresh(Duration::from_millis(1_300));
        assert_eq!(pacing.redundancy_budget, REDUNDANCY_BUDGET_MIN);
        assert_eq!(pacing.pacing_interval(), PACING_INTERVAL_MIN);
    }

    #[test]
    fn relaxation_never_grants_redundancy_before_engagement() {
        let mut pacing = AdaptivePacing::new();
        // No feedback observed at all: the no-evidence baseline holds.
        pacing.refresh(Duration::from_secs(10));
        assert_eq!(pacing.redundancy_budget, 0);
        assert_eq!(pacing.pacing_interval, POINTER_PACING_INTERVAL);

        // Once any feedback has been seen, a quiet window relaxes pacing
        // toward the floor but never grants redundancy on its own.
        pacing.note_feedback(Duration::from_millis(10_010));
        pacing.refresh(Duration::from_millis(10_500));
        assert_eq!(pacing.redundancy_budget, 0);
        assert_eq!(pacing.pacing_interval, PACING_INTERVAL_MIN);
    }

    #[test]
    fn escalation_after_a_relaxation_requires_a_fresh_storm() {
        let mut pacing = AdaptivePacing::new();
        pacing.note_feedback(Duration::from_millis(5));
        pacing.note_feedback(Duration::from_millis(10));
        assert_eq!(pacing.pacing_interval(), Duration::from_millis(4));

        // One feedback after the quiet gap is not enough to re-escalate.
        pacing.note_feedback(Duration::from_millis(500));
        assert_eq!(pacing.pacing_interval(), Duration::from_millis(4));
        assert_eq!(pacing.redundancy_budget, REDUNDANCY_BUDGET_MIN);

        // A second feedback inside the storm window escalates one level.
        pacing.note_feedback(Duration::from_millis(520));
        assert_eq!(pacing.redundancy_budget, 4);
        assert_eq!(pacing.pacing_interval(), Duration::from_millis(8));
    }

    #[test]
    fn spend_redundancy_counts_down_the_grant() {
        let mut pacing = AdaptivePacing::new();
        assert!(!pacing.spend_redundancy());
        pacing.note_feedback(Duration::from_millis(5));
        pacing.note_feedback(Duration::from_millis(10));
        assert!(pacing.spend_redundancy());
        assert!(pacing.spend_redundancy());
        assert!(!pacing.spend_redundancy());
        assert_eq!(pacing.redundancy_budget, 0);
    }

    #[test]
    fn adaptive_bounds_hold_under_arbitrary_event_sequences() {
        // Deterministic LCG over strictly increasing timestamps: every event
        // is a random feedback or quiet tick. The bounds must hold for any
        // pattern, so oscillation cannot push a parameter out of range.
        let mut state = 0x0DDB_1A5E_5BAD_5EED_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        };
        let mut pacing = AdaptivePacing::new();
        let mut elapsed = Duration::ZERO;
        for _ in 0..20_000 {
            elapsed += Duration::from_millis((next() % 40) + 1);
            if next() % 2 == 0 {
                pacing.note_feedback(elapsed);
            } else {
                pacing.refresh(elapsed);
            }
            assert!(pacing.redundancy_budget <= REDUNDANCY_BUDGET_MAX);
            assert!(
                pacing.redundancy_budget == 0 || pacing.redundancy_budget >= REDUNDANCY_BUDGET_MIN
            );
            assert!(pacing.pacing_interval() >= PACING_INTERVAL_MIN);
            assert!(pacing.pacing_interval() <= PACING_INTERVAL_MAX);
        }
    }

    #[tokio::test]
    async fn receiver_gap_reports_escalate_sender_pacing_and_redundancy() {
        let host_a = WireHostId([27; 16]);
        let host_b = WireHostId([28; 16]);
        let (mut a, mut b) = bound_pair(
            "127.0.0.1:24834",
            "127.0.0.1:24835",
            [20; 32],
            host_a,
            host_b,
        )
        .await;
        a.send_probe().await.unwrap();
        b.send_probe().await.unwrap();
        recv(&mut a).await;
        recv(&mut b).await;

        // Establish b's receive baseline with one normally delivered move.
        let movement = pointer(host_a);
        assert!(a.try_send_pointer(&movement).unwrap());
        recv(&mut b).await;

        // Two separated single-datagram drops each make b's next received
        // sequence jump, so b emits two gap reports the sender drains
        // back-to-back: a storm, one bounded escalation.
        let mut discarded = [0_u8; MAX_DATAGRAM];
        for _ in 0..2 {
            assert!(a.try_send_pointer(&movement).unwrap());
            a.last_pointer_send = None;
            a.flush_pending().unwrap();
            recv_raw(&mut b, &mut discarded).await;
            assert!(a.try_send_pointer(&movement).unwrap());
            a.last_pointer_send = None;
            a.flush_pending().unwrap();
            assert!(recv(&mut b).await.gaps > 0);
        }
        recv(&mut a).await;
        recv(&mut a).await;

        assert_eq!(a.pacing.redundancy_budget, REDUNDANCY_BUDGET_MIN);
        assert_eq!(a.pacing.pacing_interval(), Duration::from_millis(4));

        // The escalation's redundant copies are actually spent on the wire,
        // and the escalated interval genuinely gates the flush: only an
        // elapsed window (or its absence) may transmit.
        assert!(a.try_send_pointer(&movement).unwrap());
        assert_eq!(
            a.flush_pending().unwrap(),
            0,
            "escalated pacing gates the flush"
        );
        a.last_pointer_send = None;
        let redundant = a.flush_pending().unwrap();
        assert!(redundant >= 1);
    }

    // --- Reliable reorder buffer ---------------------------------------------

    #[test]
    fn reorder_buffer_delivers_in_order_despite_reordering() {
        let first = scroll(WireHostId([1; 16]), 1);
        let second = scroll(WireHostId([1; 16]), 2);
        let mut buffer = ReliableReorderBuffer::new();
        let (drained, acknowledged) = buffer.insert(1, second.clone()).unwrap();
        assert!(drained.is_empty());
        // Nothing contiguous has been delivered yet, so there is no
        // cumulative acknowledgement to report.
        assert_eq!(acknowledged, None);
        let (drained, acknowledged) = buffer.insert(0, first.clone()).unwrap();
        assert_eq!(drained, vec![first, second]);
        assert_eq!(acknowledged, Some(1));
    }

    #[test]
    fn reorder_buffer_ignores_unreachably_far_sequences() {
        let mut buffer = ReliableReorderBuffer::new();
        assert!(buffer
            .insert(u64::MAX - 3, scroll(WireHostId([1; 16]), 5))
            .is_none());
        let (drained, acknowledged) = buffer.insert(0, scroll(WireHostId([1; 16]), 6)).unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(acknowledged, Some(0));
    }

    // A retransmission of an already-delivered sequence (the exact
    // ACK-loss condition retransmission exists for) must not park an entry
    // no drain can remove: 128 of those would wedge the buffer at capacity
    // for the session's lifetime.
    #[test]
    fn reorder_buffer_re_acknowledges_delivered_retransmissions_without_parking() {
        let host = WireHostId([1; 16]);
        let mut buffer = ReliableReorderBuffer::new();
        let (drained, _) = buffer.insert(0, scroll(host, 1)).unwrap();
        assert_eq!(drained.len(), 1);
        for _ in 0..MAX_RELIABLE_PENDING {
            let (drained, acknowledged) = buffer.insert(0, scroll(host, 2)).unwrap();
            assert!(drained.is_empty());
            assert_eq!(acknowledged, Some(0));
        }
        // The window is not consumed: in-order delivery still works.
        let (drained, acknowledged) = buffer.insert(1, scroll(host, 3)).unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(acknowledged, Some(1));
    }

    #[test]
    fn reorder_buffer_withholds_acknowledgement_before_any_delivery() {
        let mut buffer = ReliableReorderBuffer::new();
        let (drained, acknowledged) = buffer.insert(3, scroll(WireHostId([1; 16]), 7)).unwrap();
        assert!(drained.is_empty());
        assert_eq!(acknowledged, None);
    }

    // --- Plaintext codec invariants (mirrors the fuzz targets) ---------------

    #[test]
    fn parse_pointer_plaintext_round_trips_encoded_fields() {
        let device = WireDeviceId([0x5a; 16]);
        let payload = encode_pointer_plaintext(0x01, device, 123_456, (12.5, -7.25));
        assert_eq!(
            parse_pointer_datagram_plaintext(&payload),
            PointerDatagramPlaintext::Pointer {
                flags: 0x01,
                device,
                timestamp_ns: 123_456,
                total_x: 12.5,
                total_y: -7.25,
            }
        );
    }

    #[test]
    fn parse_pointer_plaintext_never_panics_on_arbitrary_input() {
        // Deterministic stand-in for the fuzz_datagram_plaintext target so
        // the no-panic and round-trip invariants run even where libFuzzer
        // cannot.
        let mut state = 0x0DDB_1A5E_5BAD_5EED_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        };
        let mut bytes = [0_u8; 256];
        for _ in 0..100_000 {
            for byte in &mut bytes {
                *byte = u8::try_from(next() % 256).unwrap();
            }
            let length = usize::try_from(next() % 200).unwrap();
            let parsed = parse_pointer_datagram_plaintext(&bytes[..length]);
            if let PointerDatagramPlaintext::Pointer {
                flags,
                device,
                timestamp_ns,
                total_x,
                total_y,
            } = &parsed
            {
                let encoded =
                    encode_pointer_plaintext(*flags, *device, *timestamp_ns, (*total_x, *total_y));
                assert_eq!(parse_pointer_datagram_plaintext(&encoded), parsed);
            }
        }
    }
}
