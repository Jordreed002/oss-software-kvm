use core::{fmt, str::FromStr};

use thiserror::Error;

use crate::{ChannelBindingError, PairedPeer, PairingChannelBinding, PairingContext, PeerIdentity};

const PAIRING_EXPORTER_LABEL: &[u8] = b"EXPORTER-software-kvm-pairing-code-v1";
const VERIFICATION_CODE_MODULUS: u32 = 1_000_000;

/// Six-digit short authentication string shown on both machines.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VerificationCode(u32);

impl VerificationCode {
    fn from_exporter_output(output: [u8; 32]) -> Self {
        let value = u32::from_be_bytes(output[..4].try_into().expect("slice has four bytes"));
        Self(value % VERIFICATION_CODE_MODULUS)
    }

    /// Numeric representation in the range `000000..=999999`.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl fmt::Display for VerificationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:06}", self.0)
    }
}

impl fmt::Debug for VerificationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerificationCode([REDACTED])")
    }
}

impl FromStr for VerificationCode {
    type Err = VerificationCodeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 6 {
            return Err(VerificationCodeParseError::InvalidLength);
        }
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(VerificationCodeParseError::InvalidCharacter);
        }
        let number = value
            .parse::<u32>()
            .map_err(|_| VerificationCodeParseError::InvalidCharacter)?;
        Ok(Self(number))
    }
}

/// Invalid user-facing verification-code text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VerificationCodeParseError {
    /// The text did not contain exactly six ASCII digits.
    #[error("verification code must contain exactly six digits")]
    InvalidLength,
    /// The text contained a non-decimal character.
    #[error("verification code must contain only ASCII digits")]
    InvalidCharacter,
}

/// Externally visible state of an explicit two-sided pairing decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingState {
    /// Neither machine has approved the matching code.
    AwaitingBothApprovals,
    /// This machine approved; the peer has not yet approved.
    AwaitingRemoteApproval,
    /// The peer approved; this machine has not yet approved.
    AwaitingLocalApproval,
    /// Both machines explicitly approved the matching code.
    Complete,
    /// A user or peer cancelled the attempt.
    Cancelled,
    /// A user reported that the two displayed codes differed.
    VerificationFailed,
}

/// One pairing attempt bound to an authenticated TLS transcript/exporter.
pub struct PairingSession {
    remote_identity: PeerIdentity,
    verification_code: VerificationCode,
    state: PairingState,
}

impl fmt::Debug for PairingSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingSession")
            .field("remote_identity", &"[REDACTED]")
            .field("verification_code", &"[REDACTED]")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl PairingSession {
    /// Starts a pairing attempt and derives its display code from TLS exporter
    /// material bound to both identities and the unique attempt context.
    ///
    /// # Errors
    ///
    /// Returns an error for self-pairing or when authenticated exporter material
    /// cannot be obtained.
    pub fn start(
        local_identity: &PeerIdentity,
        remote_identity: PeerIdentity,
        pairing_context: PairingContext,
        channel_binding: &impl PairingChannelBinding,
    ) -> Result<Self, PairingError> {
        if local_identity.peer_id() == remote_identity.peer_id() {
            return Err(PairingError::SelfPairing);
        }

        let exporter_context = exporter_context(local_identity, &remote_identity, pairing_context);
        let material = channel_binding
            .export_keying_material(PAIRING_EXPORTER_LABEL, &exporter_context)
            .map_err(PairingError::ChannelBinding)?;

        Ok(Self {
            remote_identity,
            verification_code: VerificationCode::from_exporter_output(material),
            state: PairingState::AwaitingBothApprovals,
        })
    }

    /// Code that must be visibly compared on both machines.
    #[must_use]
    pub const fn verification_code(&self) -> VerificationCode {
        self.verification_code
    }

    /// Current decision state.
    #[must_use]
    pub const fn state(&self) -> PairingState {
        self.state
    }

    /// Records this machine's explicit user approval after the user visibly
    /// confirms that both machines show the same code.
    ///
    /// Repeated approval is idempotent to tolerate UI retries.
    ///
    /// # Errors
    ///
    /// Returns an error after cancellation or verification failure.
    pub fn approve_local(&mut self) -> Result<(), PairingError> {
        self.state = match self.state {
            PairingState::AwaitingBothApprovals => PairingState::AwaitingRemoteApproval,
            PairingState::AwaitingLocalApproval => PairingState::Complete,
            PairingState::AwaitingRemoteApproval | PairingState::Complete => self.state,
            PairingState::Cancelled | PairingState::VerificationFailed => {
                return Err(PairingError::TerminalState(self.state));
            }
        };
        Ok(())
    }

    /// Records the peer's authenticated statement that its local user approved.
    ///
    /// The verification code is deliberately not accepted or transmitted here:
    /// sending it over the not-yet-trusted channel would let an intermediary
    /// forge a successful comparison. Humans compare the two displays, and this
    /// method carries only the peer's approval decision.
    ///
    /// # Errors
    ///
    /// Returns a terminal-state error after cancellation/failure.
    pub fn approve_remote(&mut self) -> Result<(), PairingError> {
        if matches!(
            self.state,
            PairingState::Cancelled | PairingState::VerificationFailed
        ) {
            return Err(PairingError::TerminalState(self.state));
        }

        self.state = match self.state {
            PairingState::AwaitingBothApprovals => PairingState::AwaitingLocalApproval,
            PairingState::AwaitingRemoteApproval => PairingState::Complete,
            PairingState::AwaitingLocalApproval | PairingState::Complete => self.state,
            PairingState::Cancelled | PairingState::VerificationFailed => unreachable!(),
        };
        Ok(())
    }

    /// Records that the human-visible codes did not match and permanently fails
    /// this attempt. A retry requires a fresh TLS session and pairing context.
    ///
    /// # Errors
    ///
    /// Returns a terminal-state error if the attempt already completed or was
    /// cancelled. Repeated mismatch reports are idempotent.
    pub fn report_verification_mismatch(&mut self) -> Result<(), PairingError> {
        self.state = match self.state {
            PairingState::AwaitingBothApprovals
            | PairingState::AwaitingLocalApproval
            | PairingState::AwaitingRemoteApproval
            | PairingState::VerificationFailed => PairingState::VerificationFailed,
            PairingState::Complete | PairingState::Cancelled => {
                return Err(PairingError::TerminalState(self.state));
            }
        };
        Ok(())
    }

    /// Cancels an incomplete attempt. Cancellation is idempotent.
    ///
    /// Completed pairing cannot be retroactively cancelled; revoke its allowlist
    /// entry instead.
    ///
    /// # Errors
    ///
    /// Returns an error if pairing has already completed or verification failed.
    pub fn cancel(&mut self) -> Result<(), PairingError> {
        self.state = match self.state {
            PairingState::AwaitingBothApprovals
            | PairingState::AwaitingLocalApproval
            | PairingState::AwaitingRemoteApproval
            | PairingState::Cancelled => PairingState::Cancelled,
            PairingState::Complete | PairingState::VerificationFailed => {
                return Err(PairingError::TerminalState(self.state));
            }
        };
        Ok(())
    }

    /// Converts a fully approved session into public allowlist metadata.
    ///
    /// # Errors
    ///
    /// Returns an error until both machines have approved the matching code.
    pub fn finish(self) -> Result<PairedPeer, PairingError> {
        if self.state != PairingState::Complete {
            return Err(PairingError::NotFullyApproved(self.state));
        }
        Ok(PairedPeer::new(self.remote_identity))
    }
}

fn exporter_context(
    local: &PeerIdentity,
    remote: &PeerIdentity,
    pairing_context: PairingContext,
) -> Vec<u8> {
    let mut identities = [local, remote];
    identities.sort_unstable_by_key(|identity| identity.peer_id());

    let mut context = Vec::with_capacity(1 + 2 * (16 + 16 + 32) + 32);
    context.push(1); // Context format version.
    for identity in identities {
        context.extend_from_slice(&identity.peer_id().into_bytes());
        context.extend_from_slice(&identity.host_id().into_bytes());
        context.extend_from_slice(identity.fingerprint().as_bytes());
    }
    context.extend_from_slice(pairing_context.as_bytes());
    context
}

/// Pairing state-machine or authenticated channel-binding failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PairingError {
    /// A peer attempted to pair with the same stable peer ID.
    #[error("cannot pair an identity with itself")]
    SelfPairing,
    /// Authenticated TLS exporter material was unavailable.
    #[error(transparent)]
    ChannelBinding(ChannelBindingError),
    /// An operation was attempted after a terminal state.
    #[error("pairing is already in terminal state {0:?}")]
    TerminalState(PairingState),
    /// The caller tried to persist the peer before both approvals arrived.
    #[error("pairing is not fully approved (state: {0:?})")]
    NotFullyApproved(PairingState),
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_types::{HostId, PeerId};

    use crate::IdentityFingerprint;

    #[derive(Debug)]
    struct FakeBinding([u8; 32]);

    impl PairingChannelBinding for FakeBinding {
        fn export_keying_material(
            &self,
            label: &[u8],
            context: &[u8],
        ) -> Result<[u8; 32], ChannelBindingError> {
            assert_eq!(label, PAIRING_EXPORTER_LABEL);
            assert!(!context.is_empty());
            Ok(self.0)
        }
    }

    fn identities() -> (PeerIdentity, PeerIdentity) {
        let local = PeerIdentity::new(
            PeerId::from_bytes([1; 16]),
            HostId::from_bytes([2; 16]),
            "Windows",
            IdentityFingerprint::from_sha256([3; 32]),
        )
        .unwrap();
        let remote = PeerIdentity::new(
            PeerId::from_bytes([4; 16]),
            HostId::from_bytes([5; 16]),
            "MacBook",
            IdentityFingerprint::from_sha256([6; 32]),
        )
        .unwrap();
        (local, remote)
    }

    fn session() -> PairingSession {
        let (local, remote) = identities();
        let mut exporter_output = [0_u8; 32];
        exporter_output[..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        PairingSession::start(
            &local,
            remote,
            PairingContext::from_bytes([7; 32]),
            &FakeBinding(exporter_output),
        )
        .unwrap()
    }

    #[test]
    fn both_approvals_are_required_before_finishing() {
        let mut incomplete = session();
        incomplete.approve_local().unwrap();
        assert_eq!(
            incomplete.finish(),
            Err(PairingError::NotFullyApproved(
                PairingState::AwaitingRemoteApproval
            ))
        );

        let mut pairing = session();
        let code = pairing.verification_code();
        assert_eq!(pairing.state(), PairingState::AwaitingBothApprovals);

        pairing.approve_local().unwrap();
        assert_eq!(pairing.state(), PairingState::AwaitingRemoteApproval);
        assert_eq!(pairing.verification_code(), code);
        pairing.approve_remote().unwrap();
        assert_eq!(pairing.state(), PairingState::Complete);
        assert_eq!(
            pairing.finish().unwrap().identity().display_name(),
            "MacBook"
        );
    }

    #[test]
    fn approvals_can_arrive_in_either_order() {
        let mut pairing = session();
        pairing.approve_remote().unwrap();
        assert_eq!(pairing.state(), PairingState::AwaitingLocalApproval);

        pairing.approve_local().unwrap();
        assert_eq!(pairing.state(), PairingState::Complete);
    }

    #[test]
    fn matching_and_mismatching_codes_are_detectable_and_mismatch_fails_closed() {
        let (local, remote) = identities();
        let mut pairing = session();
        let same_peer_view = PairingSession::start(
            &remote,
            local.clone(),
            PairingContext::from_bytes([7; 32]),
            &FakeBinding({
                let mut output = [0_u8; 32];
                output[..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
                output
            }),
        )
        .unwrap();
        let different_peer_view = PairingSession::start(
            &remote,
            local,
            PairingContext::from_bytes([7; 32]),
            &FakeBinding([0xff; 32]),
        )
        .unwrap();

        assert_eq!(
            pairing.verification_code(),
            same_peer_view.verification_code()
        );
        assert_ne!(
            pairing.verification_code(),
            different_peer_view.verification_code()
        );

        pairing.report_verification_mismatch().unwrap();
        assert_eq!(pairing.state(), PairingState::VerificationFailed);
        assert_eq!(
            pairing.approve_local(),
            Err(PairingError::TerminalState(
                PairingState::VerificationFailed
            ))
        );
    }

    #[test]
    fn cancelled_session_cannot_be_approved_or_finished() {
        let mut pairing = session();
        pairing.cancel().unwrap();
        pairing.cancel().unwrap();
        assert_eq!(pairing.state(), PairingState::Cancelled);
        assert_eq!(
            pairing.approve_local(),
            Err(PairingError::TerminalState(PairingState::Cancelled))
        );
        assert_eq!(
            pairing.finish(),
            Err(PairingError::NotFullyApproved(PairingState::Cancelled))
        );
    }

    #[test]
    fn code_is_six_digits_and_round_trips() {
        let code = session().verification_code();
        assert_eq!(code.to_string().len(), 6);
        assert_eq!(code.to_string().parse(), Ok(code));
    }

    #[test]
    fn pairing_debug_redacts_code_and_identity() {
        let pairing = session();
        let code = pairing.verification_code().to_string();
        let rendered = format!("{pairing:?} {:?}", pairing.verification_code());

        assert!(!rendered.contains(&code));
        assert!(!rendered.contains("MacBook"));
    }

    #[test]
    fn pairing_error_redacts_channel_binding_backend_details() {
        const MARKER: &str = "SECRET-TLS-EXPORTER-MARKER";
        let error =
            PairingError::ChannelBinding(ChannelBindingError::ExportFailed(MARKER.to_owned()));
        let rendered = format!("{error:?} {error}");

        assert!(!rendered.contains(MARKER));
    }
}
