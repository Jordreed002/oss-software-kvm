//! Bounded framing for the replacement local control transport.
//!
//! These helpers do not authenticate endpoints or clients. The native transport
//! owner must establish authorization before parsing commands, and must enforce
//! read/write deadlines and connection limits. This is not the peer input wire.

use std::{fmt, io};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Framing failures never include payload contents.
#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    InvalidLength,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("local control frame I/O failed"),
            Self::InvalidLength => formatter.write_str("local control frame length rejected"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reads one big-endian length-prefixed payload into caller-owned storage.
///
/// The buffer length defines the limit; pass the negotiated API limit. Empty or
/// oversized lengths are rejected BEFORE reading body bytes. No allocation is
/// performed here. Clean EOF between frames returns None; partial frames fail.
///
/// # Errors
/// Returns an I/O or length error; the caller must close the connection after
/// either. Cancellation during a read also requires closing the connection,
/// since its stream may contain a partially consumed frame.
pub async fn read_frame<'a, R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &'a mut [u8],
) -> Result<Option<&'a [u8]>, FrameError> {
    let mut header = [0_u8; 4];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let length =
        usize::try_from(u32::from_be_bytes(header)).map_err(|_| FrameError::InvalidLength)?;
    if length == 0 || length > buffer.len() {
        return Err(FrameError::InvalidLength);
    }
    reader.read_exact(&mut buffer[..length]).await?;
    Ok(Some(&buffer[..length]))
}

/// Writes one frame. The caller owns serialization and any flush policy.
///
/// # Errors
/// Rejects empty/oversized payloads before any write. A partial write or a
/// cancelled write requires closing the connection, never retrying the frame
/// on that same stream. Apply an owner-level deadline to avoid stalled peers.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
    maximum: usize,
) -> Result<(), FrameError> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(FrameError::InvalidLength);
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::InvalidLength)?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn fragmented_frame_and_clean_eof() {
        let (mut client, mut server) = tokio::io::duplex(1);
        let writer = tokio::spawn(async move {
            write_frame(&mut client, b"hello", 5).await.unwrap();
        });
        let mut storage = [0_u8; 5];
        assert_eq!(
            read_frame(&mut server, &mut storage).await.unwrap(),
            Some(b"hello".as_slice())
        );
        writer.await.unwrap();
        assert_eq!(read_frame(&mut server, &mut storage).await.unwrap(), None);
    }

    #[tokio::test]
    async fn successive_frames_keep_exact_boundaries() {
        let (mut client, mut server) = tokio::io::duplex(64);
        write_frame(&mut client, b"one", 8).await.unwrap();
        write_frame(&mut client, b"two", 8).await.unwrap();
        let mut storage = [0_u8; 8];
        assert_eq!(
            read_frame(&mut server, &mut storage).await.unwrap(),
            Some(b"one".as_slice())
        );
        assert_eq!(
            read_frame(&mut server, &mut storage).await.unwrap(),
            Some(b"two".as_slice())
        );
    }

    #[tokio::test]
    async fn invalid_lengths_reject_without_waiting_for_body() {
        for length in [0_u32, 9, u32::MAX] {
            let (mut client, mut server) = tokio::io::duplex(8);
            client.write_all(&length.to_be_bytes()).await.unwrap();
            let mut storage = [0_u8; 8];
            let result = tokio::time::timeout(
                Duration::from_millis(100),
                read_frame(&mut server, &mut storage),
            )
            .await
            .unwrap();
            assert!(matches!(result, Err(FrameError::InvalidLength)));
            // Writer stays open, so successful return cannot depend on EOF.
            drop(client);
        }
    }

    #[tokio::test]
    async fn partial_header_or_body_is_never_clean_eof() {
        for bytes in [vec![0], vec![0, 0, 0, 3, b'x']] {
            let mut reader = bytes.as_slice();
            let mut storage = [0_u8; 8];
            assert!(
                matches!(read_frame(&mut reader, &mut storage).await, Err(FrameError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
            );
        }
    }

    #[tokio::test]
    async fn rejected_write_emits_no_header_or_payload() {
        for payload in [b"".as_slice(), b"large".as_slice()] {
            let mut output = Vec::new();
            assert!(matches!(
                write_frame(&mut output, payload, 2).await,
                Err(FrameError::InvalidLength)
            ));
            assert!(output.is_empty());
        }
    }
}
