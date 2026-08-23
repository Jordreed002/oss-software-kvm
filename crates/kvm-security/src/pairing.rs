use core::{fmt, str::FromStr};
use std::time::Duration;

use thiserror::Error;

use crate::{ChannelBindingError, PairedPeer, PairingChannelBinding, PairingContext, PeerIdentity};

const PAIRING_EXPORTER_LABEL: &[u8] = b"EXPORTER-software-kvm-pairing-code-v1";
const VERIFICATION_CODE_MODULUS: u32 = 1_000_000;

/// Default failed verification attempts allowed before lockout engages.
pub const DEFAULT_MAX_FAILED_VERIFICATION_ATTEMPTS: u32 = 5;

/// Default cooldown rejecting further pairing attempts after lockout.
pub const DEFAULT_VERIFICATION_LOCKOUT_COOLDOWN: Duration = Duration::from_mins(1);

/// Six-digit short authentication string shown on both machines.
///
/// Derived equality exists for tests and UI plumbing only. The secret is
/// never compared programmatically across the untrusted channel: humans
/// compare the two displays, so no timing-equality requirement applies.
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
        // Peer IDs are public non-secret identifiers; a short-circuit
        // comparison cannot leak credential material here.
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
            // F-12/F-25: every remaining state is a no-op. AwaitingLocalApproval
            // and Complete are legitimate idempotent re-approvals; Cancelled and
            // VerificationFailed are structurally guarded by the early return
            // above, but use `self.state` instead of unreachable!() so a future
            // enum change can't panic the daemon via a peer-driven call.
            PairingState::AwaitingLocalApproval
            | PairingState::Complete
            | PairingState::Cancelled
            | PairingState::VerificationFailed => self.state,
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

    /// Records that the human-visible codes did not match and permanently fails
    /// this attempt. A retry requires a fresh TLS session and pairing context.
    ///
    /// Session owners that enforce brute-force resistance should also pass the
    /// failure to their [`PairingAttemptTracker`] so repeated mismatches
    /// eventually engage its cooldown.
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

/// Lockout policy for failed pairing verification attempts.
///
/// Each [`PairingSession`] is single-use, so failures are aggregated across
/// attempts by the daemon-held [`PairingAttemptTracker`] using this policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingLockoutPolicy {
    max_failed_attempts: u32,
    cooldown: Duration,
}

impl PairingLockoutPolicy {
    /// Creates a validated lockout policy.
    ///
    /// # Errors
    ///
    /// Returns an error when either bound is zero.
    pub fn new(
        max_failed_attempts: u32,
        cooldown: Duration,
    ) -> Result<Self, PairingLockoutPolicyError> {
        if max_failed_attempts == 0 {
            return Err(PairingLockoutPolicyError::ZeroMaxFailedAttempts);
        }
        if cooldown.is_zero() {
            return Err(PairingLockoutPolicyError::ZeroCooldown);
        }
        Ok(Self {
            max_failed_attempts,
            cooldown,
        })
    }

    /// Failed attempts tolerated before lockout engages.
    #[must_use]
    pub const fn max_failed_attempts(self) -> u32 {
        self.max_failed_attempts
    }

    /// Cooldown rejecting further attempts once lockout engages.
    #[must_use]
    pub const fn cooldown(self) -> Duration {
        self.cooldown
    }
}

impl Default for PairingLockoutPolicy {
    fn default() -> Self {
        Self {
            max_failed_attempts: DEFAULT_MAX_FAILED_VERIFICATION_ATTEMPTS,
            cooldown: DEFAULT_VERIFICATION_LOCKOUT_COOLDOWN,
        }
    }
}

/// Invalid pairing lockout policy bounds.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PairingLockoutPolicyError {
    /// The failure allowance was zero.
    #[error("maximum failed pairing attempts must be non-zero")]
    ZeroMaxFailedAttempts,
    /// The cooldown was zero.
    #[error("pairing lockout cooldown must be non-zero")]
    ZeroCooldown,
}

/// Cross-attempt brute-force tracker for pairing verification.
///
/// The session owner calls [`Self::check`] before offering a new pairing
/// attempt, feeds every human mismatch report into
/// [`Self::record_verification_failure`], and resets after a legitimately
/// successful pairing with [`Self::record_verification_success`].
///
/// Time is injected as nanoseconds since a caller-chosen monotonic epoch
/// (`now_ns`), matching the workspace convention; the tracker performs no
/// I/O and reads no clocks itself. Once a cooldown elapses, the lock clears
/// and the full failure budget is restored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingAttemptTracker {
    policy: PairingLockoutPolicy,
    failed_attempts: u32,
    locked_until_ns: Option<u64>,
}

impl Default for PairingAttemptTracker {
    fn default() -> Self {
        Self::new(PairingLockoutPolicy::default())
    }
}

impl PairingAttemptTracker {
    /// Creates a tracker enforcing an already-validated policy.
    #[must_use]
    pub const fn new(policy: PairingLockoutPolicy) -> Self {
        Self {
            policy,
            failed_attempts: 0,
            locked_until_ns: None,
        }
    }

    /// Policy currently in force.
    #[must_use]
    pub const fn policy(&self) -> PairingLockoutPolicy {
        self.policy
    }

    /// Failures recorded since the last success or expired lockout.
    #[must_use]
    pub const fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    /// Remaining cooldown at `now_ns`, or zero when not locked out.
    #[must_use]
    pub fn remaining_cooldown(&self, now_ns: u64) -> Duration {
        self.locked_until_ns.map_or(Duration::ZERO, |until| {
            Duration::from_nanos(until.saturating_sub(now_ns))
        })
    }

    /// Clears an expired lockout together with its failure budget.
    fn clear_expired(&mut self, now_ns: u64) {
        if self.locked_until_ns.is_some_and(|until| now_ns >= until) {
            self.locked_until_ns = None;
            self.failed_attempts = 0;
        }
    }

    /// Admits or rejects a new pairing attempt.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::LockedOut`] while the cooldown has not yet
    /// elapsed, carrying the remaining cooldown.
    pub fn check(&mut self, now_ns: u64) -> Result<(), PairingError> {
        self.clear_expired(now_ns);
        if self.locked_until_ns.is_some() {
            return Err(PairingError::LockedOut {
                remaining_cooldown: self.remaining_cooldown(now_ns),
            });
        }
        Ok(())
    }

    /// Records one failed human verification (the displayed codes differed).
    ///
    /// Failures arriving while a lockout is active are ignored: those attempts
    /// were already rejected by [`Self::check`] and must not extend the
    /// cooldown into an unbounded lockout.
    pub fn record_verification_failure(&mut self, now_ns: u64) {
        self.clear_expired(now_ns);
        if self.locked_until_ns.is_some() {
            return;
        }
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if self.failed_attempts >= self.policy.max_failed_attempts {
            self.locked_until_ns = Some(now_ns.saturating_add(cooldown_ns(self.policy.cooldown)));
        }
    }

    /// Resets tracking after a legitimately successful pairing.
    pub fn record_verification_success(&mut self) {
        self.failed_attempts = 0;
        self.locked_until_ns = None;
    }
}

fn cooldown_ns(cooldown: Duration) -> u64 {
    u64::try_from(cooldown.as_nanos()).unwrap_or(u64::MAX)
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
    /// Too many failed verification attempts; further attempts are rejected
    /// until the remaining cooldown elapses.
    #[error(
        "pairing attempts are locked out for {} more seconds",
        remaining_cooldown.as_secs()
    )]
    LockedOut {
        /// Time until further attempts are admitted again.
        remaining_cooldown: Duration,
    },
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

    const SECOND_NS: u64 = 1_000_000_000;

    #[test]
    fn lockout_engages_at_the_configured_failure_count() {
        let mut tracker = PairingAttemptTracker::default();
        assert_eq!(tracker.policy(), PairingLockoutPolicy::default());

        for attempt in 0_u64..4 {
            tracker.record_verification_failure(attempt * SECOND_NS);
            assert_eq!(
                tracker.failed_attempts(),
                u32::try_from(attempt + 1).unwrap()
            );
            assert_eq!(tracker.check(attempt * SECOND_NS), Ok(()));
        }

        tracker.record_verification_failure(4 * SECOND_NS);
        assert_eq!(
            tracker.check(4 * SECOND_NS),
            Err(PairingError::LockedOut {
                remaining_cooldown: Duration::from_mins(1)
            })
        );
    }

    #[test]
    fn lockout_rejects_during_cooldown_and_admits_after_it_elapses() {
        let mut tracker = PairingAttemptTracker::default();
        for _ in 0..5 {
            tracker.record_verification_failure(0);
        }

        assert_eq!(
            tracker.check(SECOND_NS),
            Err(PairingError::LockedOut {
                remaining_cooldown: Duration::from_secs(59)
            })
        );
        assert_eq!(
            tracker.check(59 * SECOND_NS),
            Err(PairingError::LockedOut {
                remaining_cooldown: Duration::from_secs(1)
            })
        );
        assert_eq!(
            tracker.remaining_cooldown(59 * SECOND_NS),
            Duration::from_secs(1)
        );

        assert_eq!(tracker.check(60 * SECOND_NS), Ok(()));
        assert_eq!(tracker.remaining_cooldown(60 * SECOND_NS), Duration::ZERO);
        assert_eq!(
            tracker.failed_attempts(),
            0,
            "cooldown expiry restores the budget"
        );
    }

    #[test]
    fn successful_pairing_resets_the_failure_budget() {
        let mut tracker = PairingAttemptTracker::default();
        for _ in 0..3 {
            tracker.record_verification_failure(0);
        }
        tracker.record_verification_success();
        assert_eq!(tracker.failed_attempts(), 0);

        for failure in 1_u64..5 {
            tracker.record_verification_failure(failure * SECOND_NS);
        }
        assert_eq!(tracker.check(4 * SECOND_NS), Ok(()));

        tracker.record_verification_failure(4 * SECOND_NS);
        assert!(matches!(
            tracker.check(4 * SECOND_NS),
            Err(PairingError::LockedOut { .. })
        ));
    }

    #[test]
    fn failures_during_active_lockout_do_not_extend_the_cooldown() {
        let mut tracker = PairingAttemptTracker::default();
        for _ in 0..5 {
            tracker.record_verification_failure(0);
        }

        tracker.record_verification_failure(10 * SECOND_NS);
        assert_eq!(
            tracker.remaining_cooldown(10 * SECOND_NS),
            Duration::from_secs(50)
        );
    }

    #[test]
    fn lockout_policy_is_configurable_and_validated() {
        assert_eq!(
            PairingLockoutPolicy::new(0, Duration::from_mins(1)),
            Err(PairingLockoutPolicyError::ZeroMaxFailedAttempts)
        );
        assert_eq!(
            PairingLockoutPolicy::new(5, Duration::ZERO),
            Err(PairingLockoutPolicyError::ZeroCooldown)
        );

        let policy = PairingLockoutPolicy::new(2, Duration::from_secs(30)).unwrap();
        assert_eq!(policy.max_failed_attempts(), 2);
        assert_eq!(policy.cooldown(), Duration::from_secs(30));

        let mut tracker = PairingAttemptTracker::new(policy);
        tracker.record_verification_failure(0);
        assert_eq!(tracker.check(0), Ok(()));
        tracker.record_verification_failure(0);
        assert_eq!(
            tracker.check(0),
            Err(PairingError::LockedOut {
                remaining_cooldown: Duration::from_secs(30)
            })
        );
        assert_eq!(tracker.check(30 * SECOND_NS), Ok(()));
    }

    #[test]
    fn mismatching_sessions_drive_the_tracker_until_lockout_blocks_new_attempts() {
        let (local, remote) = identities();
        let mut tracker = PairingAttemptTracker::default();

        for attempt in 1_u64..=5 {
            assert_eq!(tracker.check(attempt * SECOND_NS), Ok(()));
            let mut pairing = PairingSession::start(
                &local,
                remote.clone(),
                PairingContext::from_bytes([u8::try_from(attempt).unwrap(); 32]),
                &FakeBinding([0xff; 32]),
            )
            .unwrap();
            pairing.report_verification_mismatch().unwrap();
            tracker.record_verification_failure(attempt * SECOND_NS);
        }

        assert_eq!(
            tracker.check(6 * SECOND_NS),
            Err(PairingError::LockedOut {
                remaining_cooldown: Duration::from_secs(59)
            })
        );
    }
}
