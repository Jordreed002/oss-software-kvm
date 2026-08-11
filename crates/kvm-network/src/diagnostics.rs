//! Separate-channel diagnostics transport (spec §31 surface).
//!
//! This is intentionally a *separate connection* from the active KVM switch.
//! The KVM data path is a single multiplexed authenticated TLS stream on
//! `DEFAULT_KVM_PORT` (24800) that carries framed postcard `WireMessage`s under
//! a three-lane priority queue. Diagnostics ride a different, advisory, read-only
//! TCP listener on [`DEFAULT_DIAGNOSTICS_PORT`] (24801): each accepted connection
//! receives exactly one length-prefixed UTF-8 JSON [`DiagnosticsReport`] and the
//! server then closes the socket.
//!
//! The channel is deliberately unauthenticated and one-way. It carries only
//! aggregate counters and already-redacted distributions (latency percentiles,
//! drop counts, byte totals) — never input payloads, credentials, or peer
//! addresses — and a client can only *pull* a snapshot. It cannot enqueue input,
//! influence routing, or alter the switch state, so the fail-open input-safety
//! invariant is unaffected. The pull model matches the control panel's existing
//! poll cadence and keeps the KVM streaming hot path untouched: publishing a
//! snapshot is a non-blocking `Arc<RwLock>` swap, and serving it is a dedicated
//! `std::thread` with no `tokio` runtime coupling.
//!
//! Framing is a 4-byte big-endian length prefix followed by UTF-8 JSON, which is
//! deliberately distinct from the 12-byte `SKVM` postcard frame on the KVM wire
//! so the two sockets can never be confused.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kvm_types::{HostId, PeerId, Platform};
use serde::{Deserialize, Serialize};

use crate::queue::{DropCounters, SessionTelemetry};

/// Schema version of the [`DiagnosticsReport`] wire object. Bumped only on a
/// backwards-incompatible change to the report shape.
pub const DIAGNOSTICS_SCHEMA_VERSION: u16 = 1;

/// Default port for the separate diagnostics connection. One above the KVM
/// switch port (`24800`) so the two listening sockets are unambiguous and a
/// single host can serve both without collision.
pub const DEFAULT_DIAGNOSTICS_PORT: u16 = 24_801;

/// Upper bound on a single length-prefixed JSON diagnostics payload, matching
/// the KVM frame cap. Defends a hostile or buggy client from triggering an
/// unbounded allocation in [`read_report`].
pub const MAX_DIAGNOSTICS_PAYLOAD: usize = 1024 * 1024;
const MAX_PERSISTENT_DIAGNOSTICS_CLIENTS: usize = 8;
const REFRESH_REQUEST: u8 = 1;

/// Serializable view of the live authenticated-session [`SessionTelemetry`].
///
/// `SessionTelemetry` itself is not `Serialize` (it holds a [`Duration`] for the
/// last RTT, and its byte totals are intended as advisory counters), so this DTO
/// flattens RTT to an integer millisecond field and reuses the already-serializable
/// [`DropCounters`] for the per-lane drop and channel-rejection tallies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDiagnostics {
    /// Cumulative framed application bytes flushed to the TLS stream.
    pub outbound_bytes: u64,
    /// Cumulative framed messages flushed to the TLS stream.
    pub outbound_frames: u64,
    /// Cumulative framed application bytes read from the TLS stream.
    pub inbound_bytes: u64,
    /// Cumulative framed messages read from the TLS stream.
    pub inbound_frames: u64,
    /// Last authenticated ping/pong round-trip, in milliseconds. `None` until
    /// the first pong is observed for this session.
    pub last_rtt_ms: Option<u64>,
    /// Per-lane outbound-queue backpressure rejections (spec §35 "dropped packets").
    pub dropped: DropCounters,
    /// Per-lane mpsc-channel-full rejections (before the queue is even reached).
    pub channel_rejections: DropCounters,
    /// Cumulative same-source `PointerMove` frames coalesced on enqueue (spec §23).
    pub coalesced_moves: u64,
    pub pointer_datagram_active: bool,
    pub pointer_datagrams_outbound: u64,
    pub pointer_datagrams_inbound: u64,
    pub pointer_datagram_gaps: u64,
    pub pointer_datagram_jitter_us: u64,
    pub pointer_jitter_p50_us: u64,
    pub pointer_jitter_p95_us: u64,
    pub pointer_jitter_p99_us: u64,
    pub pointer_datagram_max_silence_ms: u64,
    pub pointer_recovery_milliunits: u64,
    pub reliable_datagrams_outbound: u64,
    pub reliable_datagrams_inbound: u64,
    pub reliable_datagram_retransmits: u64,
}

impl NetworkDiagnostics {
    /// Builds the serializable view from a live telemetry snapshot.
    ///
    /// RTT is flattened via saturating conversion: a `Duration` larger than
    /// `u64::MAX` milliseconds (effectively never for a LAN RTT) saturates rather
    /// than panics.
    #[must_use]
    pub fn from_telemetry(telemetry: SessionTelemetry) -> Self {
        Self {
            outbound_bytes: telemetry.outbound_bytes,
            outbound_frames: telemetry.outbound_frames,
            inbound_bytes: telemetry.inbound_bytes,
            inbound_frames: telemetry.inbound_frames,
            last_rtt_ms: telemetry
                .last_rtt
                .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
            dropped: telemetry.queue.dropped,
            channel_rejections: telemetry.channel_rejections,
            coalesced_moves: telemetry.queue.coalesced_moves,
            pointer_datagram_active: telemetry.pointer_datagram_active,
            pointer_datagrams_outbound: telemetry.pointer_datagrams_outbound,
            pointer_datagrams_inbound: telemetry.pointer_datagrams_inbound,
            pointer_datagram_gaps: telemetry.pointer_datagram_gaps,
            pointer_datagram_jitter_us: telemetry.pointer_datagram_jitter_us,
            pointer_jitter_p50_us: telemetry.pointer_jitter_p50_us,
            pointer_jitter_p95_us: telemetry.pointer_jitter_p95_us,
            pointer_jitter_p99_us: telemetry.pointer_jitter_p99_us,
            pointer_datagram_max_silence_ms: telemetry.pointer_datagram_max_silence_ms,
            pointer_recovery_milliunits: telemetry.pointer_recovery_milliunits,
            reliable_datagrams_outbound: telemetry.reliable_datagrams_outbound,
            reliable_datagrams_inbound: telemetry.reliable_datagrams_inbound,
            reliable_datagram_retransmits: telemetry.reliable_datagram_retransmits,
        }
    }
}

/// Serializable view of the native input-capture supervisor's aggregate
/// counters (spec §35 surface).
///
/// Every field is an aggregate counter — observed events, suppression and
/// fail-open tallies, pointer/cursor activity — never input payloads, key
/// values, coordinates, or peer addresses. Like the network DTO, this is safe
/// to serve over the unauthenticated read-only diagnostics channel: a reader
/// can observe coarse activity volume but cannot reconstruct any input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureDiagnostics {
    /// Total native input events observed by the capture callback.
    pub observed: u64,
    /// Events suppressed because routing is remote (input forwarded, not local).
    pub suppressed: u64,
    /// Events allowed to pass through to the local OS (fail-open / local owner).
    pub allowed_local: u64,
    /// Times the shared metrics/state lock was contended (coarse contention signal).
    pub lock_contention: u64,
    /// Capture callback invocations that panicked (recovered; non-fatal).
    pub callback_panics: u64,
    /// Pointer observations recorded by the native pipeline.
    pub pointer_observations: u64,
    /// Cross-edge pointer handoffs (transitions between local and remote routing).
    pub pointer_transitions: u64,
    /// Pointer observations that could not be sampled.
    pub pointer_observation_failures: u64,
    /// Times the local cursor was hidden for remote ownership.
    pub cursor_hides: u64,
    /// Times the local cursor was restored.
    pub cursor_shows: u64,
    /// Programmatic cursor repositions (warp-to-edge on handoff).
    pub cursor_warps: u64,
}

/// Cross-task shared holder for the latest capture-metrics snapshot.
///
/// The native capture supervisor (which owns the counters) writes; the network
/// session task that publishes [`DiagnosticsReport`] reads. Both sides use
/// non-blocking `try_read`/`try_write`-style access so the advisory diagnostics
/// path can never stall the real-time input or streaming hot paths.
pub type CaptureDiagnosticsCell = Arc<RwLock<Option<CaptureDiagnostics>>>;

/// Creates an empty capture-metrics cell, seeded to `None` (no capture has
/// reported yet).
#[must_use]
pub fn empty_capture_cell() -> CaptureDiagnosticsCell {
    Arc::new(RwLock::new(None))
}

/// One redacted, versioned read of a host's diagnostics state, served over the
/// separate diagnostics connection.
///
/// Fields are `Option` where the underlying signal may be absent before the first
/// event or before a session is established, so a freshly-started host still
/// serves a well-formed report rather than blocking the control panel.
///
/// Additional sections (capture metrics, daemon-level §35/§36 snapshot, latency
/// distributions) are layered onto this envelope in later revisions; each is an
/// optional field so older control panels tolerate a report that omits it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsReport {
    /// Wire schema version, currently [`DIAGNOSTICS_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// The host this report describes.
    pub host_id: HostId,
    /// The authenticated network peer identity of the host, when one has been
    /// established. Absent before pairing completes.
    pub peer_id: Option<PeerId>,
    /// Operating-system family of the reporting host.
    pub platform: Platform,
    /// Human-readable host name, when known.
    pub host_name: Option<String>,
    /// Wall-clock capture time, milliseconds since the Unix epoch. `None` when
    /// the producing host has no stable clock reference.
    pub captured_at_unix_ms: Option<u64>,
    /// Elapsed time since the reporting process started, in milliseconds.
    pub uptime_ms: u64,
    /// Live authenticated-session network telemetry. `None` when no session is
    /// currently active.
    pub network: Option<NetworkDiagnostics>,
    /// Aggregate native input-capture counters. `None` until the capture
    /// supervisor reports its first snapshot (e.g. on a transport-only host).
    pub capture: Option<CaptureDiagnostics>,
}

impl DiagnosticsReport {
    /// Returns the current wall-clock time as Unix milliseconds, or `None` if the
    /// system clock is before the epoch (as in some tests).
    #[must_use]
    pub fn now_unix_ms() -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
    }
}

/// Errors raised by the diagnostics transport.
#[derive(Debug, thiserror::Error)]
pub enum DiagnosticsError {
    /// A length-prefixed payload could not be read or written.
    #[error("diagnostics framing failed: {0}")]
    Framing(String),
    /// A payload exceeded [`MAX_DIAGNOSTICS_PAYLOAD`] bytes.
    #[error("diagnostics payload exceeded {MAX_DIAGNOSTICS_PAYLOAD} bytes ({0})")]
    Oversized(usize),
    /// JSON (de)serialization of a report failed.
    #[error("diagnostics json: {0}")]
    Json(#[from] serde_json::Error),
    /// An underlying socket I/O operation failed.
    #[error("diagnostics io: {0}")]
    Io(#[from] std::io::Error),
}

/// Thread-safe holder of the latest diagnostics snapshot.
///
/// The runtime updates it on its telemetry tick (a non-blocking write under an
/// `RwLock`); each accepted connection reads the current value. Cloning a
/// publisher shares the single underlying cell, so any number of producers and
/// the server share one source of truth.
#[derive(Debug, Clone)]
pub struct DiagnosticsPublisher {
    inner: Arc<RwLock<DiagnosticsReport>>,
}

impl DiagnosticsPublisher {
    /// Creates a publisher seeded with `initial`.
    #[must_use]
    pub fn new(initial: DiagnosticsReport) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    /// Replaces the published snapshot. Cheap and non-blocking for readers.
    pub fn publish(&self, report: DiagnosticsReport) {
        if let Ok(mut guard) = self.inner.write() {
            *guard = report;
        }
    }

    /// Refreshes only the capture portion of the current report. Updating the
    /// existing value under one lock prevents an idle-transport refresh from
    /// overwriting network telemetry published concurrently by a session.
    pub fn publish_capture(
        &self,
        capture: Option<CaptureDiagnostics>,
        captured_at_unix_ms: Option<u64>,
        uptime_ms: u64,
    ) {
        if let Ok(mut guard) = self.inner.write() {
            guard.captured_at_unix_ms = captured_at_unix_ms;
            guard.uptime_ms = uptime_ms;
            guard.capture = capture;
        }
    }

    /// Marks session telemetry unavailable without disturbing independently
    /// published capture counters.
    pub fn clear_network(&self) {
        if let Ok(mut guard) = self.inner.write() {
            guard.network = None;
        }
    }

    /// Returns a clone of the current published snapshot.
    ///
    /// Returns the seed report if a writer is contended, rather than blocking
    /// the diagnostics server thread.
    #[must_use]
    pub fn snapshot(&self) -> DiagnosticsReport {
        match self.inner.read() {
            Ok(guard) => (*guard).clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// Writes `report` to `writer` as a 4-byte big-endian length prefix followed by
/// UTF-8 JSON.
///
/// # Errors
///
/// Returns [`DiagnosticsError::Oversized`] if the serialized JSON exceeds
/// [`MAX_DIAGNOSTICS_PAYLOAD`], [`DiagnosticsError::Json`] on serialization
/// failure, or [`DiagnosticsError::Io`] on a write failure.
pub fn write_report(
    writer: &mut impl Write,
    report: &DiagnosticsReport,
) -> Result<(), DiagnosticsError> {
    let json = serde_json::to_string(report)?;
    if json.len() > MAX_DIAGNOSTICS_PAYLOAD {
        return Err(DiagnosticsError::Oversized(json.len()));
    }
    let length = u32::try_from(json.len()).map_err(|_| DiagnosticsError::Oversized(json.len()))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(json.as_bytes())?;
    writer.flush()?;
    Ok(())
}

/// Reads one length-prefixed JSON report from `reader`.
///
/// # Errors
///
/// Returns [`DiagnosticsError::Oversized`] if the advertised length exceeds
/// [`MAX_DIAGNOSTICS_PAYLOAD`], [`DiagnosticsError::Framing`] on a truncated
/// prefix or body, [`DiagnosticsError::Json`] on a deserialization failure, or
/// [`DiagnosticsError::Io`] on a read failure.
pub fn read_report(reader: &mut impl Read) -> Result<DiagnosticsReport, DiagnosticsError> {
    let mut prefix = [0u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|error| framing_error("length prefix", &error))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_DIAGNOSTICS_PAYLOAD {
        return Err(DiagnosticsError::Oversized(length));
    }
    let mut buffer = vec![0u8; length];
    reader
        .read_exact(&mut buffer)
        .map_err(|error| framing_error("payload body", &error))?;
    let report = serde_json::from_slice(&buffer)?;
    Ok(report)
}

fn framing_error(segment: &str, error: &std::io::Error) -> DiagnosticsError {
    DiagnosticsError::Framing(format!("truncated {segment}: {error}"))
}

/// Binds a dedicated diagnostics listener on `addr`, accepts connections on a
/// spawned `std::thread`, and serves the current [`DiagnosticsPublisher`]
/// snapshot to each. Returns the bound local address (useful when `addr`
/// requests an OS-assigned port via `:0`) and the server thread handle.
///
/// Each accepted connection is given a short read/write timeout so a stuck
/// client cannot pin a server iteration. Connection-level failures are logged to
/// stderr and swallowed: the diagnostics channel is advisory and must never tear
/// down the KVM runtime.
///
/// # Errors
///
/// Returns an error only if the initial `TcpListener::bind` fails.
pub fn spawn_diagnostics_server(
    addr: SocketAddr,
    publisher: DiagnosticsPublisher,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(addr)?;
    let local_addr = listener.local_addr()?;
    listener.set_nonblocking(false)?;
    let handle = thread::Builder::new()
        .name("skvm-diagnostics".to_owned())
        .spawn(move || serve(&listener, &publisher))?;
    Ok((local_addr, handle))
}

fn serve(listener: &TcpListener, publisher: &DiagnosticsPublisher) {
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else {
            continue;
        };
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_PERSISTENT_DIAGNOSTICS_CLIENTS {
            active.fetch_sub(1, Ordering::AcqRel);
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }
        let publisher = publisher.clone();
        let active_for_client = active.clone();
        if thread::Builder::new()
            .name("skvm-diagnostics-client".to_owned())
            .spawn(move || {
                serve_client(stream, &publisher);
                active_for_client.fetch_sub(1, Ordering::AcqRel);
            })
            .is_err()
        {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn serve_client(mut stream: TcpStream, publisher: &DiagnosticsPublisher) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    loop {
        if let Err(error) = write_report(&mut stream, &publisher.snapshot()) {
            eprintln!("[diagnostics] failed to serve report: {error}");
            break;
        }
        let mut request = [0_u8; 1];
        if stream.read_exact(&mut request).is_err() || request[0] != REFRESH_REQUEST {
            break;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

/// Connects to `addr`, reads exactly one length-prefixed JSON report, and returns
/// it. The connection is given a `timeout` cap on both connect and read so a
/// non-responsive peer cannot stall the caller.
///
/// # Errors
///
/// See [`DiagnosticsError`].
pub fn fetch_report(
    addr: SocketAddr,
    timeout: Duration,
) -> Result<DiagnosticsReport, DiagnosticsError> {
    let stream = connect_with_timeout(addr, timeout)?;
    let mut stream = stream;
    let _ = stream.set_read_timeout(Some(timeout));
    read_report(&mut stream)
}

/// Reuses one low-priority diagnostics connection across dashboard refreshes.
#[derive(Debug)]
pub struct PersistentDiagnosticsClient {
    addr: SocketAddr,
    timeout: Duration,
    stream: Option<TcpStream>,
}

impl PersistentDiagnosticsClient {
    #[must_use]
    pub const fn new(addr: SocketAddr, timeout: Duration) -> Self {
        Self {
            addr,
            timeout,
            stream: None,
        }
    }

    /// Requests the next snapshot on the existing connection, reconnecting on
    /// the following call if this exchange fails.
    ///
    /// # Errors
    ///
    /// Returns a bounded connection, framing, or JSON diagnostics error.
    pub fn fetch(&mut self) -> Result<DiagnosticsReport, DiagnosticsError> {
        if self.stream.is_none() {
            self.stream = Some(connect_with_timeout(self.addr, self.timeout)?);
            if let Some(stream) = self.stream.as_mut() {
                let _ = stream.set_read_timeout(Some(self.timeout));
                let _ = stream.set_write_timeout(Some(self.timeout));
                return read_report(stream);
            }
        }
        let result = self.stream.as_mut().map_or_else(
            || {
                Err(DiagnosticsError::Io(std::io::Error::other(
                    "diagnostics disconnected",
                )))
            },
            |stream| {
                stream.write_all(&[REFRESH_REQUEST])?;
                read_report(stream)
            },
        );
        if result.is_err() {
            self.stream = None;
        }
        result
    }
}

/// Retries a non-blocking connect within `timeout`, matching the deterministic
/// retry cadence used elsewhere in this crate rather than relying on the OS
/// `connect` timeout.
fn connect_with_timeout(
    addr: SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, DiagnosticsError> {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(DiagnosticsError::Io(error));
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::{DropCounters, SessionStats, SessionTelemetry};
    use kvm_types::{HostId, Platform};

    fn sample_report() -> DiagnosticsReport {
        let dropped = DropCounters {
            input: 3,
            control: 1,
            background: 0,
        };
        DiagnosticsReport {
            schema_version: DIAGNOSTICS_SCHEMA_VERSION,
            host_id: HostId::from_bytes([0x11; 16]),
            peer_id: None,
            platform: Platform::Windows,
            host_name: Some("desk-pc".to_owned()),
            captured_at_unix_ms: Some(1_700_000_000_000),
            uptime_ms: 12_345,
            network: Some(NetworkDiagnostics {
                outbound_bytes: 1_000,
                outbound_frames: 10,
                inbound_bytes: 2_000,
                inbound_frames: 20,
                last_rtt_ms: Some(5),
                dropped,
                channel_rejections: DropCounters::default(),
                coalesced_moves: 42,
                pointer_datagram_active: true,
                pointer_datagrams_outbound: 100,
                pointer_datagrams_inbound: 90,
                pointer_datagram_gaps: 2,
                pointer_datagram_jitter_us: 750,
                pointer_jitter_p50_us: 500,
                pointer_jitter_p95_us: 2_000,
                pointer_jitter_p99_us: 5_000,
                pointer_datagram_max_silence_ms: 12,
                pointer_recovery_milliunits: 40,
                reliable_datagrams_outbound: 8,
                reliable_datagrams_inbound: 7,
                reliable_datagram_retransmits: 1,
            }),
            capture: Some(CaptureDiagnostics {
                observed: 1_000,
                suppressed: 120,
                allowed_local: 880,
                lock_contention: 2,
                callback_panics: 0,
                pointer_observations: 510,
                pointer_transitions: 7,
                pointer_observation_failures: 1,
                cursor_hides: 7,
                cursor_shows: 7,
                cursor_warps: 14,
            }),
        }
    }

    #[test]
    fn network_dto_flattens_telemetry_rtt_to_millis() {
        let telemetry = SessionTelemetry {
            queue: SessionStats {
                dropped: DropCounters {
                    input: 7,
                    control: 0,
                    background: 0,
                },
                coalesced_moves: 9,
            },
            channel_rejections: DropCounters::default(),
            outbound_frames: 10,
            outbound_bytes: 1_000,
            inbound_frames: 20,
            inbound_bytes: 2_000,
            last_rtt: Some(Duration::from_micros(4_200)),
            pointer_datagram_active: true,
            pointer_datagrams_outbound: 100,
            pointer_datagrams_inbound: 90,
            pointer_datagram_gaps: 2,
            pointer_datagram_jitter_us: 750,
            pointer_jitter_p50_us: 500,
            pointer_jitter_p95_us: 2_000,
            pointer_jitter_p99_us: 5_000,
            pointer_datagram_max_silence_ms: 12,
            pointer_recovery_milliunits: 40,
            reliable_datagrams_outbound: 8,
            reliable_datagrams_inbound: 7,
            reliable_datagram_retransmits: 1,
        };
        let dto = NetworkDiagnostics::from_telemetry(telemetry);
        assert_eq!(dto.last_rtt_ms, Some(4));
        assert_eq!(dto.dropped.input, 7);
        assert_eq!(dto.coalesced_moves, 9);
        assert_eq!(dto.outbound_bytes, 1_000);
    }

    #[test]
    fn report_round_trips_through_framing() {
        let report = sample_report();
        let mut buffer = Vec::new();
        write_report(&mut buffer, &report).expect("write");
        let decoded = read_report(&mut buffer.as_slice()).expect("read");
        assert_eq!(report, decoded);
    }

    #[test]
    fn report_serializes_stable_field_names() {
        let json = serde_json::to_string(&sample_report()).expect("serialize");
        assert!(json.contains("\"schemaVersion\""));
        assert!(json.contains("\"hostId\""));
        assert!(json.contains("\"platform\":\"windows\""));
        assert!(json.contains("\"network\""));
        assert!(json.contains("\"lastRttMs\":5"));
        assert!(json.contains("\"coalescedMoves\":42"));
        assert!(json.contains("\"capture\""));
        assert!(json.contains("\"allowedLocal\":880"));
        assert!(json.contains("\"pointerTransitions\":7"));
    }

    #[test]
    fn read_report_rejects_oversized_advertised_length() {
        // A 4-byte BE prefix claiming 2 MiB must be refused before allocation.
        let mut bomb = Vec::new();
        bomb.extend_from_slice(&(2 * 1024 * 1024u32).to_be_bytes());
        let error = read_report(&mut bomb.as_slice()).expect_err("must reject");
        assert!(matches!(error, DiagnosticsError::Oversized(_)));
    }

    #[test]
    fn capture_refresh_preserves_session_network_telemetry() {
        let initial = sample_report();
        let expected_network = initial.network;
        let publisher = DiagnosticsPublisher::new(initial);
        let capture = CaptureDiagnostics {
            observed: 7,
            ..CaptureDiagnostics::default()
        };

        publisher.publish_capture(Some(capture), Some(123), 456);

        let refreshed = publisher.snapshot();
        assert_eq!(refreshed.network, expected_network);
        assert_eq!(refreshed.capture, Some(capture));
        assert_eq!(refreshed.captured_at_unix_ms, Some(123));
        assert_eq!(refreshed.uptime_ms, 456);
    }

    #[test]
    fn clearing_network_preserves_capture_telemetry() {
        let initial = sample_report();
        let expected_capture = initial.capture;
        let publisher = DiagnosticsPublisher::new(initial);

        publisher.clear_network();

        let refreshed = publisher.snapshot();
        assert_eq!(refreshed.network, None);
        assert_eq!(refreshed.capture, expected_capture);
    }

    #[test]
    fn server_serves_one_snapshot_per_connection() {
        // OS-assigned port on loopback: the "different connection" end-to-end.
        let publisher = DiagnosticsPublisher::new(sample_report());
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (bound, _handle) =
            spawn_diagnostics_server(bind_addr, publisher.clone()).expect("bind");

        let fetched = fetch_report(bound, Duration::from_secs(2)).expect("fetch");
        assert_eq!(fetched, sample_report());

        // An update is observable on the next pull without restarting the server.
        let mut updated = sample_report();
        updated.uptime_ms = 99_999;
        publisher.publish(updated.clone());
        let refetched = fetch_report(bound, Duration::from_secs(2)).expect("refetch");
        assert_eq!(refetched.uptime_ms, 99_999);
    }

    #[test]
    fn persistent_client_reuses_connection_and_observes_updates() {
        let publisher = DiagnosticsPublisher::new(sample_report());
        let (bound, _server) =
            spawn_diagnostics_server("127.0.0.1:0".parse().unwrap(), publisher.clone()).unwrap();
        let mut client = PersistentDiagnosticsClient::new(bound, Duration::from_secs(2));
        let first = client.fetch().unwrap();
        let mut updated = first.clone();
        updated.uptime_ms += 1;
        publisher.publish(updated.clone());
        assert_eq!(client.fetch().unwrap(), updated);
    }
}
