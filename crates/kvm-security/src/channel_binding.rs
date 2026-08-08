use core::fmt;

use thiserror::Error;

/// Unique, non-secret context for one pairing attempt.
///
/// The transport should source these bytes from its cryptographically secure
/// handshake/session randomness. Reusing a context across attempts is unsafe.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PairingContext([u8; 32]);

impl PairingContext {
    /// Creates a context from transport-provided session randomness.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the context bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PairingContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingContext(..)")
    }
}

/// Supplies keying material bound to the authenticated pairing TLS channel.
///
/// A rustls adapter should implement this using the TLS exporter with the exact
/// label and context supplied by the caller. It must fail unless the handshake
/// has completed and the peer has proved possession of its presented ephemeral
/// pairing identity. It must never substitute discovery metadata or random
/// application bytes for exporter output.
pub trait PairingChannelBinding {
    /// Exports 32 bytes bound to the current TLS session.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel is absent, unauthenticated, or cannot
    /// export keying material.
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
    ) -> Result<[u8; 32], ChannelBindingError>;
}

/// Failure to obtain authenticated channel-bound keying material.
#[derive(Clone, Eq, Error, PartialEq)]
pub enum ChannelBindingError {
    /// No completed authenticated TLS channel exists.
    #[error("an authenticated TLS channel is required for pairing")]
    Unauthenticated,
    /// The TLS implementation rejected or failed the exporter operation.
    #[error("TLS exporter operation failed")]
    ExportFailed(String),
}

impl fmt::Debug for ChannelBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Unauthenticated => "Unauthenticated",
            Self::ExportFailed(_) => "ExportFailed",
        };
        formatter
            .debug_struct("ChannelBindingError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}
