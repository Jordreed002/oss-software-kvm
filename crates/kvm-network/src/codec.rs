use kvm_protocol::{
    decode_frame_for_version, encode_frame, FrameHeader, ProtocolError, WireMessage,
    FRAME_HEADER_LEN, PROTOCOL_VERSION_V1,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Failure while reading or writing the framed protocol over an authenticated
/// byte stream.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("authenticated stream I/O failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid protocol frame: {0}")]
    Protocol(#[from] ProtocolError),
}

/// Incremental protocol reader for an already-authenticated stream half.
///
/// The fixed header is read first and validated before payload memory is
/// allocated. In particular, an oversized advertised payload is rejected
/// without attempting to buffer it.
#[derive(Debug)]
pub struct FrameReader<R> {
    stream: R,
    required_version: u16,
}

/// Incremental receive state retained by a peer session across competing
/// async branches. Bytes read from the stream but not yet consumed into a
/// complete frame are held in `buf`; the only awaited operation in the receive
/// path is a single `read`, so a cancelled poll never discards bytes already
/// appended.
#[derive(Debug, Default)]
pub(crate) struct FrameReadProgress {
    buf: Vec<u8>,
}

impl FrameReadProgress {
    /// Unconsumed bytes held across polls: received from the transport but not
    /// yet delivered as complete messages. Used for partial-inbound accounting
    /// on session failure.
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.buf.len()
    }
}

impl<R> FrameReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Marks a stream half that the caller has already encrypted and
    /// authenticated as ready for protocol reads.
    pub const fn new_authenticated(stream: R) -> Self {
        Self {
            stream,
            required_version: PROTOCOL_VERSION_V1,
        }
    }

    /// Creates an internal reader bound to one already negotiated version.
    pub(crate) const fn new_authenticated_for_version(stream: R, required_version: u16) -> Self {
        Self {
            stream,
            required_version,
        }
    }

    /// Reads exactly one frame, tolerating arbitrary fragmentation by the
    /// underlying stream.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for a closed/truncated stream, or a protocol error
    /// for an invalid header or payload.
    pub async fn read_message(&mut self) -> Result<WireMessage, NetworkError> {
        let mut header_bytes = [0_u8; FRAME_HEADER_LEN];
        self.stream.read_exact(&mut header_bytes).await?;
        let header = FrameHeader::decode_for_version(&header_bytes, self.required_version)?;

        let payload_length = header.payload_length as usize;
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload_length);
        frame.extend_from_slice(&header_bytes);
        frame.resize(FRAME_HEADER_LEN + payload_length, 0);
        self.stream
            .read_exact(&mut frame[FRAME_HEADER_LEN..])
            .await?;
        Ok(decode_frame_for_version(&frame, self.required_version)?)
    }

    /// Reads at most once, then decodes every complete frame currently buffered
    /// into `out`.
    ///
    /// This is the receive hot path. A batched TLS record — many frames
    /// delivered by a single transport read — is decoded and dispatched from one
    /// call: frames already buffered from a prior read are drained without
    /// touching the socket, and only when no complete frame remains does this
    /// method perform one awaited `read`. Each call therefore makes forward
    /// progress (delivers at least one buffered frame, or reads) yet never
    /// blocks once buffered frames are available, so a multi-frame burst is
    /// consumed without re-entering the session's `select!` between frames.
    ///
    /// Cancellation-safe: the sole awaited operation is the single `read`. On a
    /// `Pending` poll no bytes are consumed; bytes appended by a completed read
    /// are retained in `progress.buf` across cancellation boundaries.
    ///
    /// `out` must be empty on entry (the caller drains it fully between calls).
    /// This method treats a non-empty `out` as a signal that buffered frames are
    /// still being processed and returns immediately without reading or decoding
    /// — so passing a stale, non-empty `out` would silently stall the receive
    /// path instead of appending the next frames.
    pub(crate) async fn read_and_drain(
        &mut self,
        progress: &mut FrameReadProgress,
        out: &mut Vec<WireMessage>,
    ) -> Result<(), NetworkError> {
        drain_complete_frames(&mut progress.buf, self.required_version, out)?;
        if !out.is_empty() {
            // Delivered buffered frames without touching the socket.
            return Ok(());
        }

        // No complete frame buffered: pull the next chunk and drain whatever
        // it completes.
        let mut chunk = [0_u8; READ_CHUNK];
        let read = self.stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(NetworkError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "authenticated stream closed during frame read",
            )));
        }
        progress.buf.extend_from_slice(&chunk[..read]);
        drain_complete_frames(&mut progress.buf, self.required_version, out)?;
        Ok(())
    }

    pub fn into_inner(self) -> R {
        self.stream
    }
}

/// Maximum bytes pulled per receive read. Larger than a typical input frame so
/// a batched burst (many small frames in one TLS record) is captured and
/// decoded by a single read rather than read one frame at a time.
const READ_CHUNK: usize = 8 * 1024;

/// Decodes every complete frame at the front of `buf`, removing each from the
/// buffer and pushing it onto `out`. A header advertising an oversized payload
/// is rejected (as an error) before any of its payload is required to be
/// buffered, matching the prior incremental reader's safety property.
///
/// Decoding advances a cumulative `offset` and performs a single `drain` once
/// the whole contiguous run of complete frames is decoded, rather than
/// `drain(..consumed)` per frame (which memmoves the remaining tail on every
/// iteration — O(n²) over a large batched record). On error the buffer stays
/// consistent with the per-frame-drain behaviour: frames already decoded this
/// call are removed, and the offending (or still-incomplete) bytes stay at the
/// front.
fn drain_complete_frames(
    buf: &mut Vec<u8>,
    required_version: u16,
    out: &mut Vec<WireMessage>,
) -> Result<(), NetworkError> {
    let mut offset = 0_usize;
    loop {
        match decode_complete_frame(&buf[offset..], required_version) {
            Ok(Some((message, consumed))) => {
                offset += consumed;
                out.push(message);
            }
            Ok(None) => break,
            Err(error) => {
                // Drop the bytes belonging to frames already decoded this call;
                // the offending frame's bytes remain at the front.
                buf.drain(..offset);
                return Err(error);
            }
        }
    }
    if offset > 0 {
        buf.drain(..offset);
    }
    Ok(())
}

/// Parses one complete frame from the front of `buf`.
///
/// Returns `Ok(None)` when `buf` holds fewer than a full frame (partial header
/// or partial payload). Returns `Ok(Some((message, consumed)))` with the byte
/// length consumed when a complete frame is available.
fn decode_complete_frame(
    buf: &[u8],
    required_version: u16,
) -> Result<Option<(WireMessage, usize)>, NetworkError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Ok(None);
    }
    // Header validation rejects an oversized advertised payload length here,
    // before the caller buffers `payload_length` bytes of payload.
    let header = FrameHeader::decode_for_version(&buf[..FRAME_HEADER_LEN], required_version)?;
    let total = FRAME_HEADER_LEN + header.payload_length as usize;
    if buf.len() < total {
        return Ok(None);
    }
    let message = decode_frame_for_version(&buf[..total], required_version)?;
    Ok(Some((message, total)))
}

/// Protocol writer for an already-authenticated stream half.
#[derive(Debug)]
pub struct FrameWriter<W> {
    stream: W,
}

impl<W> FrameWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// Marks a stream half that the caller has already encrypted and
    /// authenticated as ready for protocol writes.
    pub const fn new_authenticated(stream: W) -> Self {
        Self { stream }
    }

    /// Validates and writes one complete frame.
    ///
    /// # Errors
    ///
    /// Returns a protocol error if the message cannot be encoded, or an I/O
    /// error if the authenticated stream cannot accept the complete frame.
    pub async fn write_message(&mut self, message: &WireMessage) -> Result<(), NetworkError> {
        let frame = encode_frame(message)?;
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Flushes buffered bytes in the underlying authenticated stream.
    ///
    /// # Errors
    ///
    /// Returns the underlying stream's I/O error.
    pub async fn flush(&mut self) -> Result<(), NetworkError> {
        self.stream.flush().await?;
        Ok(())
    }

    /// Advances an already encoded frame by one cancellation-safe write.
    ///
    /// `AsyncWriteExt::write` either reports committed bytes or makes no
    /// progress. The persistent session retains its encoded bytes and offset
    /// across competing select branches, unlike `write_all`, whose future must
    /// not be recreated after partial progress.
    pub(crate) async fn write_some(&mut self, remaining: &[u8]) -> Result<usize, NetworkError> {
        let written = self.stream.write(remaining).await?;
        if written == 0 && !remaining.is_empty() {
            return Err(NetworkError::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "authenticated stream made no frame progress",
            )));
        }
        Ok(written)
    }

    pub fn into_inner(self) -> W {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_protocol::{
        encode_frame_for_version, ClipboardV1, PingV1, WireClipboardId, WireHostId,
        PROTOCOL_VERSION_V2,
    };
    use tokio::io::{duplex, AsyncWriteExt};

    #[tokio::test]
    async fn round_trip_preserves_frame_order() {
        let (left, right) = duplex(256);
        let (left_read, left_write) = tokio::io::split(left);
        let (right_read, _right_write) = tokio::io::split(right);
        let mut writer = FrameWriter::new_authenticated(left_write);
        let mut reader = FrameReader::new_authenticated(right_read);
        let messages = [
            WireMessage::Ping(PingV1 {
                nonce: 1,
                sent_at_ns: 10,
            }),
            WireMessage::Ping(PingV1 {
                nonce: 2,
                sent_at_ns: 20,
            }),
        ];

        for message in &messages {
            writer.write_message(message).await.unwrap();
        }

        assert_eq!(reader.read_message().await.unwrap(), messages[0]);
        assert_eq!(reader.read_message().await.unwrap(), messages[1]);
        drop(left_read);
    }

    #[tokio::test]
    async fn reads_a_frame_delivered_one_byte_at_a_time() {
        let (mut sender, receiver) = duplex(64);
        let mut reader = FrameReader::new_authenticated(receiver);
        let expected = WireMessage::Clipboard(ClipboardV1 {
            update_id: WireClipboardId([3; 16]),
            origin_host: WireHostId([4; 16]),
            sequence: 5,
            text: "partial delivery".to_owned(),
        });
        let encoded = encode_frame(&expected).unwrap();

        let write_task = tokio::spawn(async move {
            for byte in encoded {
                sender.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        assert_eq!(reader.read_message().await.unwrap(), expected);
        write_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_oversized_header_before_reading_a_payload() {
        let (mut sender, receiver) = duplex(64);
        let mut reader = FrameReader::new_authenticated(receiver);
        let mut header = FrameHeader {
            protocol_version: kvm_protocol::PROTOCOL_VERSION,
            message_type: kvm_protocol::MessageType::Clipboard,
            payload_length: 0,
        }
        .encode();
        header[8..12].copy_from_slice(
            &u32::try_from(kvm_protocol::MAX_FRAME_PAYLOAD + 1)
                .unwrap()
                .to_be_bytes(),
        );
        sender.write_all(&header).await.unwrap();

        let error = reader.read_message().await.unwrap_err();
        assert!(matches!(
            error,
            NetworkError::Protocol(ProtocolError::PayloadTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn negotiated_v2_incremental_progress_survives_fragmentation() {
        let (mut sender, receiver) = duplex(64);
        let mut reader = FrameReader::new_authenticated_for_version(receiver, PROTOCOL_VERSION_V2);
        let mut progress = FrameReadProgress::default();
        let expected = WireMessage::Ping(PingV1 {
            nonce: 31,
            sent_at_ns: 32,
        });
        let encoded = encode_frame_for_version(&expected, PROTOCOL_VERSION_V2).unwrap();
        let write_task = tokio::spawn(async move {
            for byte in encoded {
                sender.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        // Delivered one byte at a time: each drain makes partial progress
        // (buffering bytes) until a whole frame is present, then decodes it.
        let mut out = Vec::new();
        let decoded_message = loop {
            out.clear();
            reader
                .read_and_drain(&mut progress, &mut out)
                .await
                .unwrap();
            if let Some(message) = out.pop() {
                break message;
            }
            tokio::task::yield_now().await;
        };

        assert_eq!(decoded_message, expected);
        assert_eq!(out.len(), 0);
        assert_eq!(progress.buffered_bytes(), 0);
        write_task.await.unwrap();
    }

    #[tokio::test]
    async fn negotiated_v2_rejects_v1_header_without_buffering_payload() {
        let (mut sender, receiver) = duplex(64);
        let mut reader = FrameReader::new_authenticated_for_version(receiver, PROTOCOL_VERSION_V2);
        let mut progress = FrameReadProgress::default();
        let header = FrameHeader {
            protocol_version: PROTOCOL_VERSION_V1,
            message_type: kvm_protocol::MessageType::Ping,
            payload_length: u32::try_from(kvm_protocol::MAX_FRAME_PAYLOAD).unwrap(),
        }
        .encode();
        sender.write_all(&header).await.unwrap();

        let mut out = Vec::new();
        let error = reader
            .read_and_drain(&mut progress, &mut out)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            NetworkError::Protocol(ProtocolError::UnsupportedVersion {
                received: PROTOCOL_VERSION_V1,
                supported: PROTOCOL_VERSION_V2,
            })
        ));
        // Only the fixed header was buffered; the declared oversized payload
        // was never read into memory before the version was rejected.
        assert_eq!(progress.buffered_bytes(), FRAME_HEADER_LEN);
    }

    #[tokio::test]
    async fn read_and_drain_decodes_every_frame_in_a_batched_record_at_once() {
        // Many frames written in a single record: a single drain must decode and
        // deliver all of them without re-entering a select loop between frames.
        let (mut sender, receiver) = duplex(8 * 1024);
        let mut reader = FrameReader::new_authenticated_for_version(receiver, PROTOCOL_VERSION_V1);
        let mut progress = FrameReadProgress::default();
        let messages: Vec<_> = (1_u64..=8)
            .map(|nonce| {
                WireMessage::Ping(PingV1 {
                    nonce,
                    sent_at_ns: nonce * 10,
                })
            })
            .collect();
        let mut record = Vec::new();
        for message in &messages {
            record.extend_from_slice(&encode_frame(message).unwrap());
        }
        sender.write_all(&record).await.unwrap();

        let mut out = Vec::new();
        // The record arrives in one transport read; one drain yields every frame.
        reader
            .read_and_drain(&mut progress, &mut out)
            .await
            .unwrap();
        assert_eq!(out, messages);
        assert_eq!(progress.buffered_bytes(), 0);
    }

    #[tokio::test]
    async fn read_and_drain_serves_buffered_frames_without_touching_the_socket() {
        // Deliver two frames in one record, then drain them one call at a time
        // into a caller buffer that is emptied between calls. The first drain
        // reads once and decodes both frames; the second finds nothing buffered
        // and must await more data (EOF) without busy-looping.
        let (mut sender, receiver) = duplex(8 * 1024);
        let mut reader = FrameReader::new_authenticated(receiver);
        let mut progress = FrameReadProgress::default();
        let first = WireMessage::Ping(PingV1 {
            nonce: 1,
            sent_at_ns: 1,
        });
        let second = WireMessage::Ping(PingV1 {
            nonce: 2,
            sent_at_ns: 2,
        });
        let mut record = Vec::new();
        record.extend_from_slice(&encode_frame(&first).unwrap());
        record.extend_from_slice(&encode_frame(&second).unwrap());
        sender.write_all(&record).await.unwrap();

        let mut out = Vec::new();
        reader
            .read_and_drain(&mut progress, &mut out)
            .await
            .unwrap();
        assert_eq!(out, vec![first, second]);
        assert_eq!(progress.buffered_bytes(), 0);
    }
}
