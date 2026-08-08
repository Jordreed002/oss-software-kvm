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
/// async branches. A cancelled `read` poll never discards previously committed
/// header or payload bytes.
#[derive(Debug)]
pub(crate) struct FrameReadProgress {
    header: [u8; FRAME_HEADER_LEN],
    header_read: usize,
    decoded_header: Option<FrameHeader>,
    payload: Vec<u8>,
    payload_read: usize,
}

impl Default for FrameReadProgress {
    fn default() -> Self {
        Self {
            header: [0; FRAME_HEADER_LEN],
            header_read: 0,
            decoded_header: None,
            payload: Vec::new(),
            payload_read: 0,
        }
    }
}

impl FrameReadProgress {
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.header_read + self.payload_read
    }

    fn reset(&mut self) {
        self.header = [0; FRAME_HEADER_LEN];
        self.header_read = 0;
        self.decoded_header = None;
        self.payload.clear();
        self.payload_read = 0;
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

    /// Advances one frame by at most one cancellation-safe `read` operation.
    ///
    /// The caller must retain `progress` until a message or error is returned.
    /// A successful partial read is committed before this method completes;
    /// when its future is cancelled after `Pending`, no bytes were consumed.
    pub(crate) async fn read_some(
        &mut self,
        progress: &mut FrameReadProgress,
    ) -> Result<Option<WireMessage>, NetworkError> {
        if progress.header_read < FRAME_HEADER_LEN {
            let read = self
                .stream
                .read(&mut progress.header[progress.header_read..])
                .await?;
            if read == 0 {
                return Err(NetworkError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "authenticated stream closed during frame header",
                )));
            }
            progress.header_read += read;
            if progress.header_read < FRAME_HEADER_LEN {
                return Ok(None);
            }
            let header = FrameHeader::decode_for_version(&progress.header, self.required_version)?;
            progress.payload.resize(header.payload_length as usize, 0);
            progress.decoded_header = Some(header);
            if progress.payload.is_empty() {
                return finish_progress(progress, self.required_version).map(Some);
            }
            return Ok(None);
        }

        let read = self
            .stream
            .read(&mut progress.payload[progress.payload_read..])
            .await?;
        if read == 0 {
            return Err(NetworkError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "authenticated stream closed during frame payload",
            )));
        }
        progress.payload_read += read;
        if progress.payload_read < progress.payload.len() {
            return Ok(None);
        }
        finish_progress(progress, self.required_version).map(Some)
    }

    pub fn into_inner(self) -> R {
        self.stream
    }
}

fn finish_progress(
    progress: &mut FrameReadProgress,
    required_version: u16,
) -> Result<WireMessage, NetworkError> {
    debug_assert!(progress.decoded_header.is_some());
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + progress.payload.len());
    frame.extend_from_slice(&progress.header);
    frame.extend_from_slice(&progress.payload);
    let message = decode_frame_for_version(&frame, required_version)?;
    progress.reset();
    Ok(message)
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

        let decoded_message = loop {
            if let Some(message) = reader.read_some(&mut progress).await.unwrap() {
                break message;
            }
            tokio::task::yield_now().await;
        };

        assert_eq!(decoded_message, expected);
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

        let error = loop {
            match reader.read_some(&mut progress).await {
                Ok(None) => {}
                Ok(Some(message)) => panic!("unexpected message: {message:?}"),
                Err(error) => break error,
            }
        };

        assert!(matches!(
            error,
            NetworkError::Protocol(ProtocolError::UnsupportedVersion {
                received: PROTOCOL_VERSION_V1,
                supported: PROTOCOL_VERSION_V2,
            })
        ));
        assert_eq!(progress.payload.capacity(), 0);
    }
}
