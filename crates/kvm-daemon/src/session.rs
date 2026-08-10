//! Synchronous composition of one admitted network peer and daemon safety state.
//!
//! This module deliberately does not start capture, install suppression, open a
//! socket, or run a native injection backend. Production composition may feed
//! it events only from `kvm-network`; deterministic tests use recording output
//! and outbound implementations.

use std::collections::BTreeMap;
use std::fmt;

use kvm_config::Config;
use kvm_input::{ButtonState, InputEvent, InputPayload, KeyState, PressedState};
use kvm_network::{
    AdmittedPeer, ConnectionGeneration, ConnectionState, OutboundSendError, PeerEvent, PeerSender,
    TransportPeerIdentity,
};
use kvm_protocol::{HelloV1, MessageType, ReleaseInputV1, ValidationError, WireMessage};
use kvm_security::{IdentityFingerprint, PeerIdentity};
use kvm_types::{DeviceId, HostId, PeerId, WorkspaceState};
use thiserror::Error;

use crate::core::{
    CaptureDecision, CaptureOutcome, CoreCaptureError, RemoteInputEffect, RoutePolicyUpdateError,
    RoutePolicyUpdateStatus,
};
use crate::session_endpoint::SessionEndpoint;
use crate::wire::{key_code_from_wire, pointer_button_from_wire};
use crate::CapturedInput;
#[cfg(test)]
use crate::CoreAction;
use crate::{
    input_from_wire, input_to_wire, release_to_wire, DaemonCore, DaemonError,
    OutputInjectionBackend, PeerState, WireConversionError,
};

/// Maximum number of source devices allowed to retain inbound held state.
pub const MAX_INBOUND_PRESSED_DEVICES: usize = 64;
/// Maximum combined keys and pointer buttons retained for one source device.
pub const MAX_INBOUND_HELD_PER_DEVICE: usize = 256;
/// Maximum combined keys and pointer buttons retained across the peer session.
pub const MAX_INBOUND_HELD_TOTAL: usize = 1_024;

/// A bounded, non-blocking outbound session boundary.
pub trait OutboundPeer: Send {
    /// Offers one message without waiting or silently dropping it.
    ///
    /// # Errors
    ///
    /// Returns whether the bounded channel is full or permanently closed.
    fn try_send(&mut self, message: WireMessage) -> Result<(), OutboundPeerError>;
}

/// Opaque manager-owned outbound facade for a production peer session.
///
/// The facade begins detached and can receive a network-minted sender only
/// through `PeerManager::install_prepared_session`. Downstream code can
/// therefore drive the runner and event pump without acquiring a cloneable
/// authority to enqueue privileged protocol messages independently.
pub struct ManagedSessionOutbound {
    binding: Option<(ConnectionGeneration, PeerSender)>,
}

impl ManagedSessionOutbound {
    /// Creates an outbound facade with no authorized session FIFO.
    #[must_use]
    pub const fn detached() -> Self {
        Self { binding: None }
    }

    pub(crate) fn install(
        &mut self,
        generation: ConnectionGeneration,
        sender: PeerSender,
    ) -> Result<(), PeerSender> {
        if self
            .binding
            .as_ref()
            .is_some_and(|(current, _)| *current == generation)
        {
            return Err(sender);
        }
        self.binding = Some((generation, sender));
        Ok(())
    }
}

impl Default for ManagedSessionOutbound {
    fn default() -> Self {
        Self::detached()
    }
}

impl fmt::Debug for ManagedSessionOutbound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSessionOutbound")
            .field("attached", &self.binding.is_some())
            .finish_non_exhaustive()
    }
}

impl OutboundPeer for ManagedSessionOutbound {
    fn try_send(&mut self, message: WireMessage) -> Result<(), OutboundPeerError> {
        let (_, sender) = self.binding.as_mut().ok_or(OutboundPeerError::Closed)?;
        PeerSender::try_send(sender, message).map_err(|error| match error {
            OutboundSendError::Full(_) => OutboundPeerError::Full,
            OutboundSendError::Closed(_) => OutboundPeerError::Closed,
        })
    }
}

impl OutboundPeer for PeerSender {
    fn try_send(&mut self, message: WireMessage) -> Result<(), OutboundPeerError> {
        PeerSender::try_send(self, message).map_err(|error| match error {
            OutboundSendError::Full(_) => OutboundPeerError::Full,
            OutboundSendError::Closed(_) => OutboundPeerError::Closed,
        })
    }
}

/// Lossless result of a non-blocking outbound offer.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OutboundPeerError {
    #[error("peer outbound channel is full")]
    Full,
    #[error("peer outbound channel is closed")]
    Closed,
}

/// Observable result of consuming one persistent-session event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerEventOutcome {
    Applied,
    Deferred(MessageType),
    Ignored,
}

/// Coarse failure while a retained route-policy candidate is being settled.
#[derive(Clone, Copy)]
pub(crate) enum RoutePolicyCoordinatorError {
    Policy(RoutePolicyUpdateError),
    Delivery,
}

impl fmt::Debug for RoutePolicyCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Policy(_) => "RoutePolicyCoordinatorError::Policy",
            Self::Delivery => "RoutePolicyCoordinatorError::Delivery",
        })
    }
}

/// Fail-closed composition error. Callers should terminate the corresponding
/// peer task after any error except an explicitly returned deferred outcome.
#[derive(Error)]
pub enum CoordinatorError {
    #[error("the expected peer is not present in daemon configuration")]
    ExpectedPeerNotConfigured,
    #[error("the configured peer fingerprint is not a canonical SHA-256 fingerprint")]
    InvalidConfiguredFingerprint,
    #[error("the configured peer fingerprint does not match the expected identity")]
    ConfiguredFingerprintMismatch,
    #[error("peer input was received without an exact admitted session")]
    NotAdmitted,
    #[error("the admitted identity does not match the expected peer")]
    IdentityMismatch,
    #[error("input sequence is not newer than the previous admitted record")]
    StaleSequence { previous: u64, received: u64 },
    #[error(transparent)]
    Wire(#[from] WireConversionError),
    #[error(transparent)]
    InvalidMessage(#[from] ValidationError),
    #[error("input injection failed")]
    Injection,
    #[error(transparent)]
    Outbound(#[from] OutboundPeerError),
    #[error("a core action targeted a different peer")]
    WrongActionTarget,
    #[error("previously injected input could not be released; re-admission is unsafe")]
    CleanupIncomplete,
    #[error("inbound held-input state exceeded its configured safety bound")]
    InboundPressedStateOverflow,
    #[error("outbound session sequence space is exhausted")]
    OutboundSequenceExhausted,
    #[error("synthetic cleanup sequence space is exhausted")]
    SyntheticSequenceExhausted,
    #[error("a key repeat was received without an exact held key")]
    UnmatchedRepeat,
    #[error("release-proof traffic is unavailable until its exact session state is installed")]
    UnsupportedReleaseProof,
    #[error("the core produced a non-release action during cleanup")]
    UnexpectedCleanupAction,
    #[error("pointer workspace update failed")]
    WorkspaceUpdate,
    #[error("captured input routing failed")]
    Core(#[from] CoreCaptureError),
    #[error("multiple cleanup operations failed ({first}; {second})")]
    MultipleCleanupFailures {
        first: Box<CoordinatorError>,
        second: Box<CoordinatorError>,
    },
    #[error("session failed ({trigger}) and cleanup also failed ({cleanup})")]
    SessionFailureWithCleanup {
        trigger: Box<CoordinatorError>,
        cleanup: Box<CoordinatorError>,
    },
}

impl fmt::Debug for CoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::ExpectedPeerNotConfigured => "ExpectedPeerNotConfigured",
            Self::InvalidConfiguredFingerprint => "InvalidConfiguredFingerprint",
            Self::ConfiguredFingerprintMismatch => "ConfiguredFingerprintMismatch",
            Self::NotAdmitted => "NotAdmitted",
            Self::IdentityMismatch => "IdentityMismatch",
            Self::StaleSequence { .. } => "StaleSequence",
            Self::Wire(_) => "Wire",
            Self::InvalidMessage(_) => "InvalidMessage",
            Self::Injection => "Injection",
            Self::Outbound(_) => "Outbound",
            Self::WrongActionTarget => "WrongActionTarget",
            Self::CleanupIncomplete => "CleanupIncomplete",
            Self::InboundPressedStateOverflow => "InboundPressedStateOverflow",
            Self::OutboundSequenceExhausted => "OutboundSequenceExhausted",
            Self::SyntheticSequenceExhausted => "SyntheticSequenceExhausted",
            Self::UnmatchedRepeat => "UnmatchedRepeat",
            Self::UnsupportedReleaseProof => "UnsupportedReleaseProof",
            Self::UnexpectedCleanupAction => "UnexpectedCleanupAction",
            Self::WorkspaceUpdate => "WorkspaceUpdate",
            Self::Core(_) => "Core",
            Self::MultipleCleanupFailures { .. } => "MultipleCleanupFailures",
            Self::SessionFailureWithCleanup { .. } => "SessionFailureWithCleanup",
        };
        formatter
            .debug_struct("CoordinatorError")
            .field("kind", &kind)
            .finish()
    }
}

/// Internal result of a capture failure after the core may already have made
/// a safe local or quarantined disposition. Diagnostics deliberately expose
/// neither the input nor its destination.
pub(crate) struct CoordinatorCaptureFailure {
    outcome: Option<CaptureOutcome>,
    error: CoordinatorError,
}

impl CoordinatorCaptureFailure {
    #[must_use]
    pub(crate) const fn outcome(&self) -> Option<CaptureOutcome> {
        self.outcome
    }

    #[must_use]
    pub(crate) fn into_error(self) -> CoordinatorError {
        self.error
    }
}

impl fmt::Debug for CoordinatorCaptureFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorCaptureFailure")
            .field("has_safe_outcome", &self.outcome.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PresentedPeer {
    host_id: HostId,
    peer_id: PeerId,
    fingerprint: [u8; 32],
    local_host_id: HostId,
}

/// Exact public projection of an unforgeable `AdmittedPeer`.
///
/// Keeping every field makes equality equivalent to `AdmittedPeer` equality,
/// including both fresh Hello nonces. Identity alone must never authorize a
/// message from a previous admitted transport session.
#[derive(Clone, PartialEq)]
struct AdmittedSessionBinding {
    transport_identity: TransportPeerIdentity,
    local_hello: HelloV1,
    remote_hello: HelloV1,
    selected_protocol_version: u16,
    session_id: [u8; 32],
}

impl fmt::Debug for AdmittedSessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmittedSessionBinding([REDACTED])")
    }
}

impl AdmittedSessionBinding {
    fn presented_peer(&self) -> PresentedPeer {
        PresentedPeer {
            host_id: HostId::from_bytes(self.remote_hello.host_id.0),
            peer_id: PeerId::from_bytes(self.remote_hello.peer_id.0),
            fingerprint: self.transport_identity.credential_fingerprint,
            local_host_id: HostId::from_bytes(self.local_hello.host_id.0),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct AuthorizedSession {
    endpoint: SessionEndpoint,
    binding: AdmittedSessionBinding,
    last_sequence: Option<u64>,
    accepts_input: bool,
}

/// Safety coordinator for exactly one configured peer session.
///
/// The only public activation path requires an [`AdmittedPeer`], whose fields
/// cannot be constructed by downstream safe code. A bare `Connected` event is
/// consequently insufficient to authorize input.
pub struct PeerSessionCoordinator<I, O> {
    core: DaemonCore,
    expected: PeerIdentity,
    injection: I,
    outbound: O,
    authorized: Option<AuthorizedSession>,
    inbound_pressed: BTreeMap<DeviceId, PressedState>,
    synthetic_sequence: u64,
    outbound_sequence: u64,
    /// §36 capture→injection latency ring; present only with the `diagnostics` feature.
    #[cfg(feature = "diagnostics")]
    injection_latency: kvm_input::LatencyHistory,
    /// §36 source-side capture→network-send latency ring; present only with the
    /// `diagnostics` feature. Spans physical capture to the frame being handed
    /// to the outbound channel at this host. Together with the core-owned
    /// capture→routing span it isolates dispatch/queue latency
    /// (routing→send = capture→send − capture→routing).
    #[cfg(feature = "diagnostics")]
    network_send_latency: kvm_input::LatencyHistory,
    /// §35 cumulative count of inbound events injected at this peer; present
    /// only with the `diagnostics` feature. Mirrors the capture-side
    /// input-event-rate total so a diagnostics surface can detect one-way
    /// delivery asymmetry (events captured but not injected).
    #[cfg(feature = "diagnostics")]
    injected_events: u64,
}

/// Borrow-only routing composition for one exact current session.
///
/// The facade deliberately exposes neither its coordinator nor its core. Its
/// private representation can therefore become two disjoint borrows when the
/// core moves to `PeerManager`, without changing workspace-control APIs.
pub(crate) struct SessionRoutingContext<'a, I, O> {
    coordinator: &'a mut PeerSessionCoordinator<I, O>,
    endpoint: SessionEndpoint,
}

impl<I, O> fmt::Debug for SessionRoutingContext<'_, I, O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRoutingContext")
            .field("has_current_endpoint", &true)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<'a, I, O> SessionRoutingContext<'a, I, O>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    /// Borrows routing composition only when the supplied endpoint is exactly
    /// the coordinator's current authenticated authority. Offline operations
    /// deliberately have no `SessionRoutingContext` construction path.
    pub(crate) fn new(
        coordinator: &'a mut PeerSessionCoordinator<I, O>,
        endpoint: SessionEndpoint,
    ) -> Result<Self, CoordinatorError> {
        let context = Self {
            coordinator,
            endpoint,
        };
        context.validate_fresh()?;
        Ok(context)
    }

    pub(crate) fn require_endpoint(
        &self,
        endpoint: SessionEndpoint,
    ) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        if self.endpoint == endpoint {
            Ok(())
        } else {
            Err(CoordinatorError::NotAdmitted)
        }
    }

    pub(crate) fn core_workspace(&self) -> Result<WorkspaceState, CoordinatorError> {
        self.validate_fresh()?;
        Ok(self.coordinator.core.workspace())
    }

    pub(crate) fn try_send_control(
        &mut self,
        message: WireMessage,
    ) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.try_send_control(message)
    }

    pub(crate) fn clear_workspace_routing_ready(
        &mut self,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.clear_workspace_routing_ready(now_ns)
    }

    pub(crate) fn mark_workspace_routing_ready(
        &mut self,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.mark_workspace_routing_ready(now_ns)
    }

    pub(crate) fn trigger_capture_emergency(
        &mut self,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.trigger_capture_emergency(now_ns)
    }

    pub(crate) fn restore_local_device(
        &mut self,
        device: DeviceId,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.restore_local_device(device, now_ns)
    }

    pub(crate) fn release_inbound_device(
        &mut self,
        device: DeviceId,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.release_inbound_device(device, now_ns)
    }

    pub(crate) fn begin_pointer_handoff(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.begin_pointer_handoff(now_ns)
    }

    pub(crate) fn begin_destination_handoff_barrier(
        &mut self,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.begin_destination_handoff_barrier(now_ns)
    }

    pub(crate) fn cancel_pointer_handoff(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.cancel_pointer_handoff(now_ns);
        Ok(())
    }

    pub(crate) fn abort_destination_handoff_barrier(
        &mut self,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.abort_destination_handoff_barrier(now_ns);
        Ok(())
    }

    pub(crate) fn finish_pointer_handoff(
        &mut self,
        workspace: WorkspaceState,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.validate_fresh()?;
        self.coordinator.finish_pointer_handoff(workspace, now_ns)
    }

    fn validate_fresh(&self) -> Result<(), CoordinatorError> {
        let current = self
            .coordinator
            .authorized
            .as_ref()
            .map(|session| session.endpoint);
        if current == Some(self.endpoint) {
            Ok(())
        } else {
            Err(CoordinatorError::NotAdmitted)
        }
    }
}

impl<I, O> fmt::Debug for PeerSessionCoordinator<I, O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerSessionCoordinator")
            .field("expected_identity", &"[REDACTED]")
            .field("admitted", &self.authorized.is_some())
            .field(
                "accepts_input",
                &self
                    .authorized
                    .as_ref()
                    .is_some_and(|session| session.accepts_input),
            )
            .field("inbound_pressed_devices", &self.inbound_pressed.len())
            .field(
                "inbound_held_items",
                &self
                    .inbound_pressed
                    .values()
                    .map(pressed_state_len)
                    .sum::<usize>(),
            )
            .finish_non_exhaustive()
    }
}

impl<I, O> PeerSessionCoordinator<I, O>
where
    I: OutputInjectionBackend,
    O: OutboundPeer,
{
    /// Binds a coordinator to one identity already loaded from the paired
    /// allowlist and to a core configured for that host.
    ///
    /// # Errors
    ///
    /// Fails when the core does not contain the expected host/peer pair.
    pub fn new(
        core: DaemonCore,
        expected: PeerIdentity,
        injection: I,
        outbound: O,
    ) -> Result<Self, CoordinatorError> {
        let configured =
            core.config().paired_hosts.iter().find(|peer| {
                peer.host_id == expected.host_id() && peer.peer_id == expected.peer_id()
            });
        let Some(configured) = configured else {
            return Err(CoordinatorError::ExpectedPeerNotConfigured);
        };
        let configured_fingerprint = configured
            .identity_fingerprint
            .parse::<IdentityFingerprint>()
            .map_err(|_| CoordinatorError::InvalidConfiguredFingerprint)?;
        if configured_fingerprint != expected.fingerprint() {
            return Err(CoordinatorError::ConfiguredFingerprintMismatch);
        }
        Ok(Self {
            core,
            expected,
            injection,
            outbound,
            authorized: None,
            inbound_pressed: BTreeMap::new(),
            synthetic_sequence: 0,
            outbound_sequence: 1,
            #[cfg(feature = "diagnostics")]
            injection_latency: kvm_input::LatencyHistory::default(),
            #[cfg(feature = "diagnostics")]
            network_send_latency: kvm_input::LatencyHistory::default(),
            #[cfg(feature = "diagnostics")]
            injected_events: 0,
        })
    }

    pub(crate) const fn outbound_mut(&mut self) -> &mut O {
        &mut self.outbound
    }

    /// §36 capture→injection latency statistics for the diagnostics surface.
    ///
    /// `None` until at least one injected event has been recorded. Only present
    /// with the `diagnostics` feature; absent in release builds.
    #[cfg(feature = "diagnostics")]
    #[must_use]
    pub fn injection_latency_stats(&self) -> Option<kvm_input::LatencyStats> {
        self.injection_latency.stats()
    }

    /// §36 source-side capture→network-send latency statistics for the
    /// diagnostics surface — the span from physical capture to the frame being
    /// handed to the outbound channel at this host. `None` until at least one
    /// remotely-dispatched event has been recorded. Only present with the
    /// `diagnostics` feature; absent in release builds. Subtracting the
    /// core-owned capture→routing span from this isolates the dispatch/queue
    /// latency on the source host.
    #[cfg(feature = "diagnostics")]
    #[must_use]
    pub fn network_send_latency_stats(&self) -> Option<kvm_input::LatencyStats> {
        self.network_send_latency.stats()
    }

    /// §35 cumulative count of inbound events injected at this peer. Only
    /// present with the `diagnostics` feature; absent in release builds.
    /// Pairs with the capture-side input-event-rate total so a diagnostics
    /// surface can detect one-way delivery asymmetry.
    #[cfg(feature = "diagnostics")]
    #[must_use]
    pub const fn injected_events(&self) -> u64 {
        self.injected_events
    }

    #[must_use]
    pub const fn core(&self) -> &DaemonCore {
        &self.core
    }

    #[must_use]
    pub(crate) const fn expected_host_id(&self) -> HostId {
        self.expected.host_id()
    }

    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        self.authorized.is_some()
    }

    pub(crate) fn authorizes_endpoint(&self, endpoint: SessionEndpoint) -> bool {
        self.authorized
            .as_ref()
            .is_some_and(|session| session.endpoint == endpoint)
    }

    #[cfg(test)]
    pub(crate) fn test_injection_mut(&mut self) -> &mut I {
        &mut self.injection
    }

    #[cfg(test)]
    pub(crate) fn test_hold_inbound(
        &mut self,
        event: InputEvent,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.inject_received(event, now_ns)
    }

    #[cfg(test)]
    pub(crate) fn test_handle_authorized_message(
        &mut self,
        message: WireMessage,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, CoordinatorError> {
        self.handle_authorized_message(message, now_ns)
    }

    #[cfg(test)]
    pub(crate) fn activate_workspace_test_binding(
        &mut self,
        endpoint: SessionEndpoint,
        transport_identity: TransportPeerIdentity,
        local_hello: HelloV1,
        remote_hello: HelloV1,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.activate_binding(
            endpoint,
            AdmittedSessionBinding {
                transport_identity,
                local_hello,
                remote_hello,
                selected_protocol_version: kvm_protocol::PROTOCOL_VERSION_V1,
                session_id: [0xa5; 32],
            },
            now_ns,
        )?;
        Ok(())
    }

    /// Offers one already validated control-plane message on the same bounded
    /// admitted session without consuming the input-event sequence domain.
    ///
    /// Pointer handoff owns a separate checked transition sequence. The
    /// caller must reconcile its affine effect on both success and failure.
    pub(crate) fn try_send_control(
        &mut self,
        message: WireMessage,
    ) -> Result<(), CoordinatorError> {
        if !self
            .authorized
            .as_ref()
            .is_some_and(|session| session.accepts_input)
        {
            return Err(CoordinatorError::NotAdmitted);
        }
        message.validate()?;
        self.outbound.try_send(message).map_err(Into::into)
    }

    pub(crate) fn validate_workspace_message(
        &self,
        peer: &AdmittedPeer,
        message: &WireMessage,
    ) -> Result<(), CoordinatorError> {
        let binding = admitted_binding(peer);
        if self
            .authorized
            .as_ref()
            .is_none_or(|session| session.binding != binding || !session.accepts_input)
        {
            return Err(CoordinatorError::NotAdmitted);
        }
        message.validate()?;
        Ok(())
    }

    pub(crate) fn begin_pointer_handoff(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        self.core.begin_pointer_handoff(now_ns)?;
        if let Err(error) = self.drain_remote_cleanup(now_ns) {
            self.core.cancel_pointer_handoff(now_ns);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn begin_destination_handoff_barrier(
        &mut self,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.core.begin_pointer_handoff(now_ns)?;
        if let Err(error) = self.drain_remote_cleanup(now_ns) {
            self.core.abort_destination_handoff_barrier(now_ns);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn cancel_pointer_handoff(&mut self, now_ns: u64) {
        self.core.cancel_pointer_handoff(now_ns);
    }

    pub(crate) fn abort_destination_handoff_barrier(&mut self, now_ns: u64) {
        self.core.abort_destination_handoff_barrier(now_ns);
    }

    pub(crate) fn finish_pointer_handoff(
        &mut self,
        workspace: kvm_types::WorkspaceState,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        match self.core.finish_pointer_handoff(workspace, now_ns) {
            Ok(()) => Ok(()),
            Err(DaemonError::CleanupPending) => {
                self.drain_remote_cleanup(now_ns)?;
                self.core
                    .finish_pointer_handoff(workspace, now_ns)
                    .map_err(|_| CoordinatorError::WorkspaceUpdate)
            }
            Err(_) => Err(CoordinatorError::WorkspaceUpdate),
        }
    }

    /// Routes one captured record through the exact admitted FIFO. A remote
    /// disposition is returned only after that FIFO accepted the frame.
    pub(crate) fn route_captured(
        &mut self,
        captured: CapturedInput,
        now_ns: u64,
    ) -> Result<CaptureOutcome, CoordinatorCaptureFailure> {
        let decision = self
            .core
            .prepare_captured(captured, now_ns)
            .map_err(|error| CoordinatorCaptureFailure {
                outcome: None,
                error: CoordinatorError::Core(error),
            })?;
        match decision {
            CaptureDecision::Fault { outcome, error } => Err(CoordinatorCaptureFailure {
                outcome: Some(outcome),
                error: CoordinatorError::Core(error),
            }),
            CaptureDecision::Local(outcome) | CaptureDecision::Inert(outcome) => {
                // §25 / F-02: the emergency chord failsafe must release
                // peer-injected inbound modifiers too, not just drain outbound —
                // otherwise the user regains control of the machine with the
                // peer's modifiers still physically held. Mirrors
                // trigger_capture_emergency (the capture-discontinuation path),
                // which exists for exactly this reason.
                let inbound_result = if outcome.failsafe_activated() {
                    self.release_all_inbound(now_ns)
                } else {
                    Ok(())
                };
                let outbound_result = self.drain_remote_cleanup(now_ns);
                combine_cleanup_results(inbound_result, outbound_result)
                    .map_err(|error| CoordinatorCaptureFailure {
                        outcome: Some(outcome),
                        error,
                    })?;
                Ok(outcome)
            }
            CaptureDecision::Remote(effect) => {
                let dispatch = self.dispatch_remote_effect(&effect);
                match dispatch {
                    Ok(accepted_sequence) => {
                        // §36 capture→network-send: dispatch just handed the
                        // frame to the outbound channel, so `now_ns` is the send
                        // instant and the event's source-capture timestamp is
                        // the capture instant. Read before `effect` moves into
                        // confirmation. Dev-only; absent without `diagnostics`.
                        #[cfg(feature = "diagnostics")]
                        {
                            let stamps = kvm_input::LatencyStamps::new()
                                .with_capture(effect.event().timestamp_ns)
                                .with_network_send(now_ns);
                            if let Some(span) = stamps.span_ns(
                                kvm_input::LatencyStage::Capture,
                                kvm_input::LatencyStage::NetworkSend,
                            ) {
                                self.network_send_latency.push(span);
                            }
                        }
                        self.core
                            .confirm_remote_input(effect, accepted_sequence, now_ns)
                            .map_err(|error| CoordinatorCaptureFailure {
                                // The frame already entered the exact FIFO. Local
                                // delivery would duplicate it even if the later
                                // in-memory confirmation failed.
                                outcome: Some(CaptureOutcome::remote_queued()),
                                error: CoordinatorError::Core(error),
                            })
                    }
                    Err(error) => {
                        let outcome = self.core.fail_remote_input(effect, now_ns).ok();
                        Err(CoordinatorCaptureFailure { outcome, error })
                    }
                }
            }
        }
    }

    pub(crate) fn clear_workspace_routing_ready(
        &mut self,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.core.clear_workspace_routing_ready(now_ns)?;
        self.drain_remote_cleanup(now_ns)
    }

    pub(crate) fn mark_workspace_routing_ready(
        &mut self,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.core.mark_workspace_routing_ready(now_ns)?;
        Ok(())
    }

    pub(crate) fn lifecycle_tick(&mut self, now_ns: u64) -> bool {
        self.core.tick(now_ns)
    }

    fn trigger_capture_emergency(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        self.core.trigger_emergency(now_ns)?;
        // Emergency chord must release locally-injected inbound keys too, not just
        // drain outbound cleanup — otherwise the user regains control of the machine
        // with the peer's injected modifiers still physically held (F-02). Mirrors the
        // shutdown path (session.rs:978), running both and combining so neither masks.
        let injection_result = self.release_all_inbound(now_ns);
        let outbound_result = self.drain_remote_cleanup(now_ns);
        combine_cleanup_results(injection_result, outbound_result)
    }

    pub(crate) const fn route_policy_revision(&self) -> u64 {
        self.core.route_policy_revision()
    }

    pub(crate) const fn route_policy_update_pending(&self) -> bool {
        self.core.route_policy_update_pending()
    }

    pub(crate) fn route_policy_config(&self) -> Config {
        self.core.config().clone()
    }

    pub(crate) fn prepare_route_policy_update(
        &mut self,
        candidate: Config,
        expected_revision: u64,
        now_ns: u64,
    ) -> Result<RoutePolicyUpdateStatus, RoutePolicyCoordinatorError> {
        let mut status = self
            .core
            .prepare_route_policy_update(candidate, expected_revision, now_ns)
            .map_err(RoutePolicyCoordinatorError::Policy)?;
        if status == RoutePolicyUpdateStatus::CleanupPending {
            self.drain_remote_cleanup(now_ns)
                .map_err(|_| RoutePolicyCoordinatorError::Delivery)?;
            status = self
                .core
                .retry_route_policy_update(now_ns)
                .map_err(RoutePolicyCoordinatorError::Policy)?;
        }
        Ok(status)
    }

    pub(crate) fn retry_route_policy_update(
        &mut self,
        now_ns: u64,
    ) -> Result<RoutePolicyUpdateStatus, RoutePolicyCoordinatorError> {
        self.drain_remote_cleanup(now_ns)
            .map_err(|_| RoutePolicyCoordinatorError::Delivery)?;
        self.core
            .retry_route_policy_update(now_ns)
            .map_err(RoutePolicyCoordinatorError::Policy)
    }

    pub(crate) fn staged_route_policy(&self) -> Option<(u64, Config)> {
        self.core
            .staged_route_policy()
            .map(|staged| (staged.revision(), staged.config().clone()))
    }

    pub(crate) fn commit_route_policy_update(
        &mut self,
        revision: u64,
        now_ns: u64,
    ) -> Result<u64, RoutePolicyUpdateError> {
        self.core.commit_route_policy_update(revision, now_ns)
    }

    pub(crate) fn abort_route_policy_update(
        &mut self,
        revision: u64,
        now_ns: u64,
    ) -> Result<(), RoutePolicyUpdateError> {
        self.core.abort_route_policy_update(revision, now_ns)
    }

    pub(crate) fn gate_local_devices(
        &mut self,
        devices: &[DeviceId],
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.core.gate_local_devices(devices, now_ns)?;
        self.drain_remote_cleanup(now_ns)
    }

    pub(crate) fn restore_local_device(
        &mut self,
        device: DeviceId,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        self.core.restore_local_device(device, now_ns)?;
        Ok(())
    }

    /// Consumes one event from the persistent task bound to this expected peer.
    ///
    /// # Errors
    ///
    /// Fails closed on identity, sequence, conversion, injection, or outbound
    /// delivery errors. The session is reconciled before the error returns.
    pub fn handle_event(
        &mut self,
        event: PeerEvent,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, CoordinatorError> {
        match event {
            rejected @ (PeerEvent::Admitted(_)
            | PeerEvent::Message { .. }
            | PeerEvent::Disconnected { .. }) => {
                drop(rejected);
                Err(self.fail_session(CoordinatorError::NotAdmitted, now_ns))
            }
            PeerEvent::StateChanged(state) => Ok(self.handle_unbound_state(state, now_ns)),
            PeerEvent::ReconnectScheduled(_) => Ok(PeerEventOutcome::Ignored),
        }
    }

    /// Dispatches transport effects previously produced by [`DaemonCore`].
    /// This does not invoke capture or make a suppression decision.
    ///
    /// # Errors
    ///
    /// Fails closed when no admitted session exists, an action targets another
    /// host, conversion fails, or the bounded outbound channel rejects work.
    #[cfg(test)]
    pub(crate) fn dispatch_actions(
        &mut self,
        actions: impl IntoIterator<Item = CoreAction>,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        if !self
            .authorized
            .as_ref()
            .is_some_and(|session| session.accepts_input)
        {
            return Err(self.fail_session(CoordinatorError::NotAdmitted, now_ns));
        }
        for action in actions {
            let message = match action {
                CoreAction::Forward { target, event } => {
                    if target != self.expected.host_id() {
                        return Err(self.fail_session(CoordinatorError::WrongActionTarget, now_ns));
                    }
                    let mut input = input_to_wire(&event).map_err(|error| {
                        self.fail_session(CoordinatorError::Wire(error), now_ns)
                    })?;
                    input.sequence = self
                        .next_outbound_sequence()
                        .map_err(|error| self.fail_session(error, now_ns))?;
                    WireMessage::Input(input)
                }
                CoreAction::Release(release) => {
                    if release.target != self.expected.host_id() {
                        return Err(self.fail_session(CoordinatorError::WrongActionTarget, now_ns));
                    }
                    let sequence = self
                        .next_outbound_sequence()
                        .map_err(|error| self.fail_session(error, now_ns))?;
                    let wire = release_to_wire(release, sequence, self.core.workspace().local_host)
                        .map_err(|error| {
                            self.fail_session(CoordinatorError::Wire(error), now_ns)
                        })?;
                    WireMessage::ReleaseInput(wire)
                }
            };
            if let Err(error) = self.outbound.try_send(message) {
                return Err(self.fail_session(CoordinatorError::Outbound(error), now_ns));
            }
        }
        Ok(())
    }

    /// Reconciles the active peer when the event channel closes unexpectedly.
    ///
    /// # Errors
    ///
    /// Returns a cleanup error while retaining any inbound held state whose
    /// synthetic release could not be injected.
    pub fn channel_closed(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        self.disconnect(now_ns)
    }

    /// Revokes the in-memory authorization immediately and releases all state.
    ///
    /// # Errors
    ///
    /// Returns a cleanup error while retaining any inbound held state whose
    /// synthetic release could not be injected.
    pub fn revoke(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        self.session_fatal_cleanup(now_ns)
    }

    /// Reconciles both directions and permanently shuts down the owned core.
    ///
    /// # Errors
    ///
    /// Reports a cleanup injection or outbound error after performing all
    /// possible local state transitions.
    pub fn shutdown(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        if let Some(session) = &mut self.authorized {
            session.accepts_input = false;
        }
        let injection_result = self.release_all_inbound(now_ns);
        let transition_result = self.core.shutdown(now_ns).map_err(CoordinatorError::Core);
        let outbound_result = if self.authorized.is_some() {
            transition_result.and_then(|()| self.drain_remote_cleanup(now_ns))
        } else {
            transition_result
        };
        let result = combine_cleanup_results(injection_result, outbound_result);
        if result.is_ok() {
            self.authorized = None;
        }
        result
    }

    /// Returns owned components for deterministic test inspection or orderly
    /// outer-composition teardown.
    #[must_use]
    pub fn into_parts(self) -> (DaemonCore, I, O) {
        (self.core, self.injection, self.outbound)
    }

    pub(crate) fn activate_admitted_endpoint(
        &mut self,
        endpoint: SessionEndpoint,
        peer: &AdmittedPeer,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, CoordinatorError> {
        let binding = admitted_binding(peer);
        let identity = binding.presented_peer();
        if endpoint.host_id() != identity.host_id
            || endpoint.peer_id() != identity.peer_id
            || endpoint.selected_protocol_version() != binding.selected_protocol_version
            || endpoint.session_id() != binding.session_id
        {
            return Err(self.fail_session(CoordinatorError::IdentityMismatch, now_ns));
        }
        self.activate_binding(endpoint, binding, now_ns)
    }

    fn activate_binding(
        &mut self,
        endpoint: SessionEndpoint,
        binding: AdmittedSessionBinding,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, CoordinatorError> {
        let identity = binding.presented_peer();
        let matches = identity.host_id == self.expected.host_id()
            && identity.peer_id == self.expected.peer_id()
            && identity.fingerprint == *self.expected.fingerprint().as_bytes()
            && identity.local_host_id == self.core.workspace().local_host;
        // An admission event during an active capability is a protocol fault,
        // even when it repeats the same token. Revoke and reconcile first so
        // held input can never remain active behind a CleanupIncomplete error.
        if !matches || self.authorized.is_some() {
            return Err(self.fail_session(CoordinatorError::IdentityMismatch, now_ns));
        }
        if !self.inbound_pressed.is_empty() {
            return Err(CoordinatorError::CleanupIncomplete);
        }
        self.core.install_session_endpoint(endpoint, now_ns)?;
        self.authorized = Some(AuthorizedSession {
            endpoint,
            binding,
            last_sequence: None,
            accepts_input: true,
        });
        Ok(PeerEventOutcome::Applied)
    }

    fn handle_unbound_state(&mut self, state: ConnectionState, now_ns: u64) -> PeerEventOutcome {
        match state {
            ConnectionState::Connecting => {
                if self.authorized.is_none() {
                    let _ = self.core.set_peer_state(
                        self.expected.host_id(),
                        PeerState::Connecting,
                        now_ns,
                    );
                }
            }
            ConnectionState::Authenticating => {
                if self.authorized.is_none() {
                    let _ = self.core.set_peer_state(
                        self.expected.host_id(),
                        PeerState::Authenticating,
                        now_ns,
                    );
                }
            }
            ConnectionState::Connected
            | ConnectionState::Degraded
            | ConnectionState::Disconnected => {
                return PeerEventOutcome::Ignored;
            }
        }
        PeerEventOutcome::Applied
    }

    pub(crate) fn handle_endpoint_state(
        &mut self,
        endpoint: SessionEndpoint,
        state: ConnectionState,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, CoordinatorError> {
        if self
            .authorized
            .as_ref()
            .is_none_or(|session| session.endpoint != endpoint)
        {
            return Err(self.fail_session(CoordinatorError::NotAdmitted, now_ns));
        }
        match state {
            ConnectionState::Connected => {
                if let Some(session) = &mut self.authorized {
                    session.accepts_input = true;
                }
                self.core
                    .set_endpoint_state(endpoint, PeerState::Connected, now_ns)?;
            }
            ConnectionState::Degraded => {
                if let Some(session) = &mut self.authorized {
                    session.accepts_input = false;
                }
                let injection_result = self.release_all_inbound(now_ns);
                let transition_result = self
                    .core
                    .set_endpoint_state(endpoint, PeerState::Degraded, now_ns)
                    .map_err(CoordinatorError::Core);
                let outbound_result =
                    transition_result.and_then(|()| self.drain_remote_cleanup(now_ns));
                if let Err(error) = combine_cleanup_results(injection_result, outbound_result) {
                    return Err(self.fail_session(error, now_ns));
                }
            }
            ConnectionState::Disconnected => self.disconnect(now_ns)?,
            ConnectionState::Connecting | ConnectionState::Authenticating => {
                return Ok(PeerEventOutcome::Ignored);
            }
        }
        Ok(PeerEventOutcome::Applied)
    }

    fn handle_authorized_message(
        &mut self,
        message: WireMessage,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, CoordinatorError> {
        if !self
            .authorized
            .as_ref()
            .is_some_and(|session| session.accepts_input)
        {
            return Err(self.fail_session(CoordinatorError::NotAdmitted, now_ns));
        }
        message
            .validate()
            .map_err(|error| self.fail_session(CoordinatorError::InvalidMessage(error), now_ns))?;
        match message {
            WireMessage::Input(input) => {
                if HostId::from_bytes(input.source_host.0) != self.expected.host_id() {
                    return Err(self.fail_session(CoordinatorError::IdentityMismatch, now_ns));
                }
                self.accept_sequence(input.sequence, now_ns)?;
                let event = input_from_wire(&input)
                    .map_err(|error| self.fail_session(CoordinatorError::Wire(error), now_ns))?;
                self.inject_received(event, now_ns)?;
                Ok(PeerEventOutcome::Applied)
            }
            WireMessage::ReleaseInput(release) => {
                self.handle_release(&release, now_ns)?;
                Ok(PeerEventOutcome::Applied)
            }
            WireMessage::ReleaseInputV2(_) | WireMessage::ReleaseAppliedAckV2(_) => {
                Err(self.fail_session(CoordinatorError::UnsupportedReleaseProof, now_ns))
            }
            other => Ok(PeerEventOutcome::Deferred(other.message_type())),
        }
    }

    pub(crate) fn handle_endpoint_message(
        &mut self,
        endpoint: SessionEndpoint,
        peer: &AdmittedPeer,
        message: WireMessage,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, CoordinatorError> {
        let binding = admitted_binding(peer);
        if self
            .authorized
            .as_ref()
            .is_none_or(|session| session.endpoint != endpoint || session.binding != binding)
        {
            return Err(self.fail_session(CoordinatorError::IdentityMismatch, now_ns));
        }
        self.handle_authorized_message(message, now_ns)
    }

    fn accept_sequence(&mut self, received: u64, now_ns: u64) -> Result<(), CoordinatorError> {
        let Some(session) = self.authorized.as_mut() else {
            return Err(self.fail_session(CoordinatorError::NotAdmitted, now_ns));
        };
        if let Some(previous) = session.last_sequence {
            if received <= previous {
                return Err(self.fail_session(
                    CoordinatorError::StaleSequence { previous, received },
                    now_ns,
                ));
            }
        }
        session.last_sequence = Some(received);
        Ok(())
    }

    fn inject_received(&mut self, event: InputEvent, now_ns: u64) -> Result<(), CoordinatorError> {
        let repeated = match event.payload {
            InputPayload::Key {
                code,
                state: KeyState::Repeated,
            } => Some(code),
            _ => None,
        };
        if repeated.is_some_and(|code| {
            self.inbound_pressed
                .get(&event.source_device)
                .is_none_or(|state| !state.key_is_pressed(code))
        }) {
            return Err(self.fail_session(CoordinatorError::UnmatchedRepeat, now_ns));
        }
        let release = matches!(
            event.payload,
            InputPayload::Key {
                state: KeyState::Released,
                ..
            } | InputPayload::PointerButton {
                state: ButtonState::Released,
                ..
            }
        );
        let press = matches!(
            event.payload,
            InputPayload::Key {
                state: KeyState::Pressed,
                ..
            } | InputPayload::PointerButton {
                state: ButtonState::Pressed,
                ..
            }
        );
        if press {
            if let Err(error) =
                self.ensure_inbound_press_capacity(event.source_device, &event.payload)
            {
                return Err(self.fail_session(error, now_ns));
            }
            self.inbound_pressed
                .entry(event.source_device)
                .or_default()
                .apply(&event.payload);
        }
        if self.injection.inject(&event).is_err() {
            return Err(self.fail_session(CoordinatorError::Injection, now_ns));
        }
        // §36 capture→injection latency: the destination's `now_ns` minus the
        // event's source-capture timestamp is the end-to-end span. Dev-only;
        // absent without the `diagnostics` feature. The intermediate routing /
        // network sub-spans are source-side and not measurable at this host.
        #[cfg(feature = "diagnostics")]
        self.injection_latency.push_stamps(
            kvm_input::LatencyStamps::new()
                .with_capture(event.timestamp_ns)
                .with_injection_request(now_ns),
        );
        // §35 injected-event counter: one per event successfully injected at
        // this peer. Dev-only; absent without the `diagnostics` feature.
        #[cfg(feature = "diagnostics")]
        {
            self.injected_events = self.injected_events.saturating_add(1);
        }
        if release {
            if let Some(state) = self.inbound_pressed.get_mut(&event.source_device) {
                state.apply(&event.payload);
                if state.is_empty() {
                    self.inbound_pressed.remove(&event.source_device);
                }
            }
        }
        Ok(())
    }

    fn ensure_inbound_press_capacity(
        &self,
        device: DeviceId,
        payload: &InputPayload,
    ) -> Result<(), CoordinatorError> {
        let existing = self.inbound_pressed.get(&device);
        let already_held = existing.is_some_and(|state| match *payload {
            InputPayload::Key {
                code,
                state: KeyState::Pressed,
            } => state.key_is_pressed(code),
            InputPayload::PointerButton {
                button,
                state: ButtonState::Pressed,
            } => state.pressed_buttons().any(|held| held == button),
            InputPayload::Key { .. }
            | InputPayload::PointerButton { .. }
            | InputPayload::PointerMove { .. }
            | InputPayload::Scroll { .. } => false,
        });
        if already_held {
            return Ok(());
        }
        if existing.is_none() && self.inbound_pressed.len() >= MAX_INBOUND_PRESSED_DEVICES {
            return Err(CoordinatorError::InboundPressedStateOverflow);
        }
        if existing.is_some_and(|state| pressed_state_len(state) >= MAX_INBOUND_HELD_PER_DEVICE) {
            return Err(CoordinatorError::InboundPressedStateOverflow);
        }
        let total = self
            .inbound_pressed
            .values()
            .map(pressed_state_len)
            .sum::<usize>();
        if total >= MAX_INBOUND_HELD_TOTAL {
            return Err(CoordinatorError::InboundPressedStateOverflow);
        }
        Ok(())
    }

    fn handle_release(
        &mut self,
        release: &ReleaseInputV1,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        if HostId::from_bytes(release.source_host.0) != self.expected.host_id() {
            return Err(self.fail_session(CoordinatorError::IdentityMismatch, now_ns));
        }
        self.accept_sequence(release.sequence, now_ns)?;
        let selected = release.source_device.map(|id| DeviceId::from_bytes(id.0));
        if release.keys.is_empty() && release.buttons.is_empty() {
            return self.release_selected_inbound(selected, now_ns);
        }
        let devices: Vec<_> = match selected {
            Some(device) => vec![device],
            None => self.inbound_pressed.keys().copied().collect(),
        };
        for device in devices {
            for key in &release.keys {
                let event = self.synthetic_event(
                    device,
                    InputPayload::Key {
                        code: key_code_from_wire(*key),
                        state: KeyState::Released,
                    },
                    now_ns,
                )?;
                self.inject_received(event, now_ns)?;
            }
            for button in &release.buttons {
                let event = self.synthetic_event(
                    device,
                    InputPayload::PointerButton {
                        button: pointer_button_from_wire(*button),
                        state: ButtonState::Released,
                    },
                    now_ns,
                )?;
                self.inject_received(event, now_ns)?;
            }
        }
        Ok(())
    }

    fn release_selected_inbound(
        &mut self,
        selected: Option<DeviceId>,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        let releases = self.inbound_releases(selected);
        for (device, payload) in releases {
            let event = self.synthetic_event(device, payload, now_ns)?;
            self.inject_received(event, now_ns)?;
        }
        Ok(())
    }

    /// Releases every injected control attributed to one authenticated remote
    /// device before its inventory record is removed or replaced.
    pub(crate) fn release_inbound_device(
        &mut self,
        device: DeviceId,
        now_ns: u64,
    ) -> Result<(), CoordinatorError> {
        if self.authorized.is_none() {
            return Err(CoordinatorError::NotAdmitted);
        }
        self.release_selected_inbound(Some(device), now_ns)
    }

    fn release_all_inbound(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        let releases = self.inbound_releases(None);
        let mut first_error = None;
        for (device, payload) in releases {
            let event = match self.synthetic_event(device, payload, now_ns) {
                Ok(event) => event,
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    break;
                }
            };
            match self.injection.inject(&event) {
                Ok(()) => {
                    if let Some(state) = self.inbound_pressed.get_mut(&device) {
                        state.apply(&event.payload);
                    }
                }
                Err(_) if first_error.is_none() => {
                    first_error = Some(CoordinatorError::Injection);
                }
                Err(_) => {}
            }
        }
        self.inbound_pressed.retain(|_, state| !state.is_empty());
        first_error.map_or(Ok(()), Err)
    }

    /// Releases every locally-injected inbound key immediately, independent of any
    /// outbound or transport cleanup. Used by terminal reconciliation (fatal /
    /// shutdown) to guarantee the release-all-keys invariant even when the
    /// subsequent workspace `retire` fails on an in-flight affine capture decision
    /// (F-03). Idempotent: a second call finds no pressed inbound state.
    pub(crate) fn release_all_inbound_keys(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        self.release_all_inbound(now_ns)
    }

    fn inbound_releases(&self, selected: Option<DeviceId>) -> Vec<(DeviceId, InputPayload)> {
        let mut releases = Vec::new();
        for (&device, state) in &self.inbound_pressed {
            if selected.is_some_and(|wanted| wanted != device) {
                continue;
            }
            releases.extend(state.pressed_keys().map(|code| {
                (
                    device,
                    InputPayload::Key {
                        code,
                        state: KeyState::Released,
                    },
                )
            }));
            releases.extend(state.pressed_buttons().map(|button| {
                (
                    device,
                    InputPayload::PointerButton {
                        button,
                        state: ButtonState::Released,
                    },
                )
            }));
        }
        releases
    }

    fn synthetic_event(
        &mut self,
        device: DeviceId,
        payload: InputPayload,
        now_ns: u64,
    ) -> Result<InputEvent, CoordinatorError> {
        let sequence = self.synthetic_sequence;
        self.synthetic_sequence = self
            .synthetic_sequence
            .checked_add(1)
            .ok_or(CoordinatorError::SyntheticSequenceExhausted)?;
        Ok(InputEvent::new(
            sequence,
            now_ns,
            self.expected.host_id(),
            device,
            payload,
        ))
    }

    fn next_outbound_sequence(&mut self) -> Result<u64, CoordinatorError> {
        let sequence = self.outbound_sequence;
        self.outbound_sequence = sequence
            .checked_add(1)
            .ok_or(CoordinatorError::OutboundSequenceExhausted)?;
        Ok(sequence)
    }

    fn dispatch_remote_effect(
        &mut self,
        effect: &RemoteInputEffect,
    ) -> Result<u64, CoordinatorError> {
        let Some(session) = self.authorized.as_ref() else {
            return Err(CoordinatorError::NotAdmitted);
        };
        if !session.accepts_input {
            return Err(CoordinatorError::NotAdmitted);
        }
        if effect.endpoint() != session.endpoint
            || effect.endpoint().host_id() != self.expected.host_id()
        {
            return Err(CoordinatorError::WrongActionTarget);
        }
        let mut input = input_to_wire(&effect.event())?;
        let accepted_sequence = self.next_outbound_sequence()?;
        input.sequence = accepted_sequence;
        self.outbound
            .try_send(WireMessage::Input(input))
            .map_err(CoordinatorError::from)?;
        Ok(accepted_sequence)
    }

    fn drain_remote_cleanup(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        while let Some(effect) = self.core.take_next_cleanup_release() {
            let release = effect.release();
            let send = (|| {
                let Some(session) = self.authorized.as_ref() else {
                    return Err(CoordinatorError::NotAdmitted);
                };
                if effect.endpoint() != session.endpoint
                    || release.target != effect.endpoint().host_id()
                    || release.target != self.expected.host_id()
                {
                    return Err(CoordinatorError::WrongActionTarget);
                }
                let sequence = self.next_outbound_sequence()?;
                if effect.covered_input_sequence() == 0
                    || sequence <= effect.covered_input_sequence()
                {
                    return Err(CoordinatorError::UnexpectedCleanupAction);
                }
                let wire = release_to_wire(release, sequence, self.core.workspace().local_host)?;
                self.outbound
                    .try_send(WireMessage::ReleaseInput(wire))
                    .map_err(CoordinatorError::Outbound)
            })();
            match send {
                Ok(()) => self.core.confirm_cleanup_release(effect, now_ns)?,
                Err(error) => {
                    self.core.retry_cleanup_release(effect, now_ns)?;
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn disconnect(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        let endpoint = self.authorized.as_ref().map(|session| session.endpoint);
        if let Some(session) = &mut self.authorized {
            session.accepts_input = false;
        }
        let injection_result = self.release_all_inbound(now_ns);
        let transition_result = endpoint.map_or(Ok(()), |endpoint| {
            self.core
                .set_endpoint_state(endpoint, PeerState::Disconnected, now_ns)
                .map_err(CoordinatorError::Core)
        });
        if self.authorized.is_some() && transition_result.is_ok() {
            let _ = self.drain_remote_cleanup(now_ns);
        }
        self.authorized = None;
        if let Some(endpoint) = endpoint {
            self.core.confirm_transport_invalidated(endpoint, now_ns);
        }
        // Once the exact transport is certainly gone, any outbound Full,
        // Closed, sequence, or core cleanup failure is settled by terminal
        // invalidation. Only local synthetic injection remains retryable.
        injection_result
    }

    /// Gates new input while retaining the exact admitted cleanup capability
    /// until every release has entered its FIFO. Unlike `disconnect`, this
    /// must not assert that the underlying transport has ended.
    pub(crate) fn session_fatal_cleanup(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        let endpoint = self.authorized.as_ref().map(|session| session.endpoint);
        if let Some(session) = &mut self.authorized {
            session.accepts_input = false;
        }
        let injection_result = self.release_all_inbound(now_ns);
        let transition_result = endpoint.map_or(Ok(()), |endpoint| {
            self.core
                .set_endpoint_state(endpoint, PeerState::Disconnected, now_ns)
                .map_err(CoordinatorError::Core)
        });
        let outbound_result = if self.authorized.is_some() {
            transition_result.and_then(|()| self.drain_remote_cleanup(now_ns))
        } else {
            transition_result
        };
        let result = combine_cleanup_results(injection_result, outbound_result).and_then(|()| {
            endpoint.map_or(Ok(()), |endpoint| {
                self.core
                    .retire_session_endpoint(endpoint, now_ns)
                    .map_err(CoordinatorError::Core)
            })
        });
        if result.is_ok() {
            self.authorized = None;
        }
        result
    }

    fn fail_session(&mut self, trigger: CoordinatorError, now_ns: u64) -> CoordinatorError {
        match self.session_fatal_cleanup(now_ns) {
            Ok(()) => trigger,
            Err(cleanup) => CoordinatorError::SessionFailureWithCleanup {
                trigger: Box::new(trigger),
                cleanup: Box::new(cleanup),
            },
        }
    }
}

fn admitted_binding(peer: &AdmittedPeer) -> AdmittedSessionBinding {
    AdmittedSessionBinding {
        transport_identity: peer.transport_identity().clone(),
        local_hello: peer.local_hello().clone(),
        remote_hello: peer.hello().clone(),
        selected_protocol_version: peer.selected_protocol_version(),
        session_id: peer.session_id(),
    }
}

fn pressed_state_len(state: &PressedState) -> usize {
    state.pressed_keys().len() + state.pressed_buttons().len()
}

fn combine_cleanup_results(
    first: Result<(), CoordinatorError>,
    second: Result<(), CoordinatorError>,
) -> Result<(), CoordinatorError> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(CoordinatorError::MultipleCleanupFailures {
            first: Box::new(first),
            second: Box::new(second),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use kvm_config::{Config, PairedHostConfig};
    use kvm_input::{KeyCode, PointerButton};
    use kvm_network::ConnectionGenerationGate;
    use kvm_protocol::{
        InputEventV1, ReleaseAppliedAckV2, ReleaseInputV2, ReleaseReasonV1, ReleaseReasonV2,
        WireButtonState, WireDeviceId, WireHostId, WireInputPayloadV1, WireKeyCode, WireKeyState,
        WirePeerId, WirePlatform, WirePointerButton,
    };
    use kvm_security::IdentityFingerprint;
    use kvm_types::{DisplayId, LogicalPointer, Platform, WorkspaceState};

    use super::*;
    use crate::PlatformError;

    const LOCAL: HostId = HostId::from_bytes([1; 16]);
    const REMOTE: HostId = HostId::from_bytes([2; 16]);
    const PEER: PeerId = PeerId::from_bytes([3; 16]);
    const DEVICE: DeviceId = DeviceId::from_bytes([4; 16]);
    const OTHER_DEVICE: DeviceId = DeviceId::from_bytes([5; 16]);
    const DISPLAY: DisplayId = DisplayId::from_bytes([6; 16]);
    const FINGERPRINT: [u8; 32] = [7; 32];

    #[derive(Debug, Default)]
    struct RecordingInjection {
        events: Vec<InputEvent>,
        fail_next: bool,
        fail_always: bool,
        error_marker: Option<&'static str>,
    }

    impl OutputInjectionBackend for RecordingInjection {
        fn inject(&mut self, event: &InputEvent) -> Result<(), PlatformError> {
            if self.fail_always || self.fail_next {
                self.fail_next = false;
                return Err(Box::new(io::Error::other(
                    self.error_marker.unwrap_or("simulated injection failure"),
                )));
            }
            self.events.push(*event);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct RecordingOutbound {
        messages: Vec<WireMessage>,
        fail: Option<OutboundPeerError>,
        debug_marker: Option<&'static str>,
    }

    impl OutboundPeer for RecordingOutbound {
        fn try_send(&mut self, message: WireMessage) -> Result<(), OutboundPeerError> {
            if let Some(error) = self.fail.take() {
                return Err(error);
            }
            self.messages.push(message);
            Ok(())
        }
    }

    fn expected_for(host: HostId) -> PeerIdentity {
        PeerIdentity::new(
            PEER,
            host,
            "remote",
            IdentityFingerprint::from_sha256(FINGERPRINT),
        )
        .unwrap()
    }

    fn expected() -> PeerIdentity {
        expected_for(REMOTE)
    }

    fn coordinator_between(
        local: HostId,
        remote: HostId,
    ) -> PeerSessionCoordinator<RecordingInjection, RecordingOutbound> {
        let mut config = Config::default();
        config.paired_hosts.push(PairedHostConfig {
            host_id: remote,
            peer_id: PEER,
            name: "remote".into(),
            platform: Platform::Windows,
            identity_fingerprint: IdentityFingerprint::from_sha256(FINGERPRINT).to_string(),
            last_address: None,
        });
        let workspace = WorkspaceState::new(local, local, LogicalPointer::new(DISPLAY, 0.0, 0.0));
        PeerSessionCoordinator::new(
            DaemonCore::new(config, workspace).unwrap(),
            expected_for(remote),
            RecordingInjection::default(),
            RecordingOutbound::default(),
        )
        .unwrap()
    }

    fn coordinator() -> PeerSessionCoordinator<RecordingInjection, RecordingOutbound> {
        coordinator_between(LOCAL, REMOTE)
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn diagnostics_capture_to_injection_latency_is_recorded() {
        // §36 wiring smoke test: inject_received stamps capture (event timestamp)
        // and injection (dest now_ns), so injection_latency_stats reflects the
        // end-to-end span once at least one event has been injected.
        let mut coord = coordinator();
        assert!(coord.injection_latency_stats().is_none());

        // Capture at t=1_000ns; inject at now=5_000ns → 4_000ns span.
        let event = InputEvent::new(
            1,
            1_000,
            REMOTE,
            DEVICE,
            InputPayload::Key {
                code: KeyCode::KeyA,
                state: KeyState::Pressed,
            },
        );
        coord.test_hold_inbound(event, 5_000).unwrap();

        let stats = coord
            .injection_latency_stats()
            .expect("latency recorded after an injected event");
        assert!(stats.count >= 1, "at least one sample: {stats:?}");
        assert_eq!(stats.max_ns, 4_000, "capture→injection span: {stats:?}");
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn diagnostics_injected_events_counts_each_injected_event() {
        // §35 wiring: inject_received tallies one per successfully injected
        // event, mirroring the capture-side event-rate total.
        let mut coord = coordinator();
        assert_eq!(coord.injected_events(), 0, "fresh coordinator injects nothing");

        for seq in 1..=3 {
            let event = InputEvent::new(
                seq,
                1_000,
                REMOTE,
                DEVICE,
                InputPayload::Key {
                    code: KeyCode::KeyA,
                    state: KeyState::Pressed,
                },
            );
            coord.test_hold_inbound(event, 5_000).unwrap();
        }
        assert_eq!(coord.injected_events(), 3, "three events injected");
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn diagnostics_capture_to_network_send_latency_is_recorded() {
        // §36 wiring: route_captured stamps capture (event timestamp) and
        // network-send (dispatch now_ns) when a captured event is dispatched to
        // the admitted remote peer, so network_send_latency_stats reflects the
        // source-side pipeline span once at least one event has been sent.
        let mut coord = coordinator();
        assert!(
            coord.network_send_latency_stats().is_none(),
            "no samples before the first dispatched event"
        );
        admit(&mut coord);
        coord.core.mark_workspace_routing_ready(0).unwrap();
        // Active host = REMOTE so a default FollowActiveHost device routes
        // outbound to the admitted peer.
        coord
            .core
            .update_workspace(
                WorkspaceState::new(LOCAL, REMOTE, LogicalPointer::new(DISPLAY, 1.0, 1.0)),
                1,
            )
            .unwrap();

        // Capture at t=1_000ns; dispatch at now=5_000ns → 4_000ns span.
        let captured = CapturedInput::new(
            InputEvent::new(
                1,
                1_000,
                LOCAL,
                DEVICE,
                InputPayload::Key {
                    code: KeyCode::KeyA,
                    state: KeyState::Pressed,
                },
            ),
            crate::EventClassification::Physical,
        );
        coord.route_captured(captured, 5_000).unwrap();

        let stats = coord
            .network_send_latency_stats()
            .expect("latency recorded after a dispatched event");
        assert!(stats.count >= 1, "at least one sample: {stats:?}");
        assert_eq!(stats.max_ns, 4_000, "capture→network-send span: {stats:?}");
    }

    #[test]
    fn failsafe_chord_releases_peer_injected_inbound_modifiers() {
        // §25 / F-02: when the local user presses the escape chord while this
        // host is the destination (active_host == local) and a peer has injected
        // a held modifier into us, the chord must release that inbound modifier
        // — not just drain outbound cleanup. The capture-discontinuation path
        // already does this (trigger_capture_emergency); this test pins the
        // chord path to the same invariant. Default chord: Ctrl+Alt+Shift+Backspace.
        let mut coord = coordinator();
        admit(&mut coord);
        coord.core.mark_workspace_routing_ready(0).unwrap();
        // coordinator() starts with active_host == LOCAL: we are the
        // destination. Have the remote peer inject a held modifier.
        let injected = InputEvent::new(
            1,
            1_000,
            REMOTE,
            DEVICE,
            InputPayload::Key {
                code: KeyCode::ControlLeft,
                state: KeyState::Pressed,
            },
        );
        coord.test_hold_inbound(injected, 1_000).unwrap();
        assert!(
            !coord.inbound_pressed.is_empty(),
            "peer-injected modifier is held before the chord"
        );

        // Local user presses the failsafe chord: the three modifiers build the
        // physical pressed state, then Backspace completes it.
        for code in [KeyCode::ControlLeft, KeyCode::AltLeft, KeyCode::ShiftLeft] {
            coord
                .route_captured(
                    CapturedInput::new(
                        InputEvent::new(
                            1,
                            2_000,
                            LOCAL,
                            DEVICE,
                            InputPayload::Key {
                                code,
                                state: KeyState::Pressed,
                            },
                        ),
                        crate::EventClassification::Physical,
                    ),
                    2_000,
                )
                .unwrap();
        }
        let outcome = coord
            .route_captured(
                CapturedInput::new(
                    InputEvent::new(
                        2,
                        3_000,
                        LOCAL,
                        DEVICE,
                        InputPayload::Key {
                            code: KeyCode::Backspace,
                            state: KeyState::Pressed,
                        },
                    ),
                    crate::EventClassification::Physical,
                ),
                3_000,
            )
            .unwrap();
        assert!(
            outcome.failsafe_activated(),
            "the chord must activate the failsafe"
        );
        assert!(
            coord.inbound_pressed.is_empty(),
            "failsafe must release the peer-injected inbound modifier (F-02)"
        );
    }

    fn binding_between(local: HostId, remote: HostId, nonce: u8) -> AdmittedSessionBinding {
        let hello = |host_id: HostId, peer_id: [u8; 16], nonce: u8| HelloV1 {
            host_id: WireHostId(host_id.into_bytes()),
            peer_id: WirePeerId(peer_id),
            host_name: "test".to_owned(),
            platform: WirePlatform::Linux,
            minimum_protocol_version: 1,
            maximum_protocol_version: 1,
            daemon_version: "test".to_owned(),
            nonce: [nonce; 32],
        };
        AdmittedSessionBinding {
            transport_identity: TransportPeerIdentity {
                host_id: WireHostId(remote.into_bytes()),
                peer_id: WirePeerId(PEER.into_bytes()),
                credential_fingerprint: FINGERPRINT,
            },
            local_hello: hello(local, [9; 16], nonce.wrapping_add(1)),
            remote_hello: hello(remote, PEER.into_bytes(), nonce),
            selected_protocol_version: kvm_protocol::PROTOCOL_VERSION_V1,
            session_id: [nonce.max(1); 32],
        }
    }

    fn binding(nonce: u8) -> AdmittedSessionBinding {
        binding_between(LOCAL, REMOTE, nonce)
    }

    fn endpoint_between(local: HostId, remote: HostId, nonce: u8) -> SessionEndpoint {
        let mut gate = ConnectionGenerationGate::new(
            WirePeerId(local.into_bytes()),
            WirePeerId(remote.into_bytes()),
        )
        .unwrap();
        let direction = gate.role().direction();
        let pending = gate.begin_pending(direction).unwrap();
        SessionEndpoint::for_test(
            PEER,
            remote,
            pending.generation(),
            kvm_protocol::PROTOCOL_VERSION_V1,
            [nonce.max(1); 32],
        )
        .unwrap()
    }

    fn endpoint(nonce: u8) -> SessionEndpoint {
        endpoint_between(LOCAL, REMOTE, nonce)
    }

    fn authorized_endpoint(
        coordinator: &PeerSessionCoordinator<RecordingInjection, RecordingOutbound>,
    ) -> SessionEndpoint {
        coordinator.authorized.as_ref().unwrap().endpoint
    }

    fn input(sequence: u64, device: DeviceId, payload: WireInputPayloadV1) -> WireMessage {
        WireMessage::Input(InputEventV1 {
            sequence,
            timestamp_ns: sequence * 10,
            source_host: WireHostId(REMOTE.into_bytes()),
            source_device: WireDeviceId(device.into_bytes()),
            payload,
        })
    }

    fn key(sequence: u64, device: DeviceId, usage: u16, state: WireKeyState) -> WireMessage {
        input(
            sequence,
            device,
            WireInputPayloadV1::Key {
                code: WireKeyCode {
                    usage_page: 0x07,
                    usage,
                },
                state,
            },
        )
    }

    fn unidentified_press(sequence: u64, device: DeviceId, usage: u16) -> WireMessage {
        input(
            sequence,
            device,
            WireInputPayloadV1::Key {
                code: WireKeyCode {
                    usage_page: 0xff,
                    usage,
                },
                state: WireKeyState::Down,
            },
        )
    }

    fn indexed_device(index: usize) -> DeviceId {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
        DeviceId::from_bytes(bytes)
    }

    fn admit(coordinator: &mut PeerSessionCoordinator<RecordingInjection, RecordingOutbound>) {
        assert_eq!(
            coordinator
                .activate_binding(endpoint(1), binding(1), 0)
                .unwrap(),
            PeerEventOutcome::Applied
        );
    }

    #[test]
    fn connected_notification_alone_never_authorizes_input() {
        let mut coordinator = coordinator();
        assert_eq!(
            coordinator.handle_unbound_state(ConnectionState::Connected, 0),
            PeerEventOutcome::Ignored
        );
        assert!(!coordinator.is_admitted());
        assert!(matches!(
            coordinator.handle_authorized_message(key(1, DEVICE, 0x04, WireKeyState::Down), 1),
            Err(CoordinatorError::NotAdmitted)
        ));
    }

    #[test]
    fn exact_identity_is_required_before_ordered_input_is_injected() {
        let mut coordinator = coordinator();
        let mut wrong = binding(1);
        wrong.transport_identity.credential_fingerprint[0] ^= 1;
        assert!(matches!(
            coordinator.activate_binding(endpoint(1), wrong, 0),
            Err(CoordinatorError::IdentityMismatch)
        ));

        admit(&mut coordinator);
        for message in [
            key(10, DEVICE, 0xe0, WireKeyState::Down),
            key(11, DEVICE, 0x04, WireKeyState::Down),
            key(12, DEVICE, 0x04, WireKeyState::Up),
            key(13, DEVICE, 0xe0, WireKeyState::Up),
        ] {
            coordinator.handle_authorized_message(message, 1).unwrap();
        }
        let (_, injection, _) = coordinator.into_parts();
        let payloads: Vec<_> = injection.events.iter().map(|event| event.payload).collect();
        assert_eq!(
            payloads,
            vec![
                InputPayload::Key {
                    code: KeyCode::ControlLeft,
                    state: KeyState::Pressed,
                },
                InputPayload::Key {
                    code: KeyCode::KeyA,
                    state: KeyState::Pressed,
                },
                InputPayload::Key {
                    code: KeyCode::KeyA,
                    state: KeyState::Released,
                },
                InputPayload::Key {
                    code: KeyCode::ControlLeft,
                    state: KeyState::Released,
                },
            ]
        );
    }

    #[test]
    fn authenticated_repeat_requires_and_preserves_the_exact_held_key() {
        let mut matched = coordinator();
        admit(&mut matched);
        for (sequence, state) in [
            (1, WireKeyState::Down),
            (2, WireKeyState::Repeat),
            (3, WireKeyState::Up),
        ] {
            matched
                .handle_authorized_message(key(sequence, DEVICE, 0x04, state), sequence)
                .unwrap();
        }
        assert!(matched.inbound_pressed.is_empty());
        assert!(matches!(
            matched.injection.events.as_slice(),
            [
                InputEvent {
                    payload: InputPayload::Key {
                        state: KeyState::Pressed,
                        ..
                    },
                    ..
                },
                InputEvent {
                    payload: InputPayload::Key {
                        state: KeyState::Repeated,
                        ..
                    },
                    ..
                },
                InputEvent {
                    payload: InputPayload::Key {
                        state: KeyState::Released,
                        ..
                    },
                    ..
                }
            ]
        ));

        let mut unmatched = coordinator();
        admit(&mut unmatched);
        assert!(matches!(
            unmatched.handle_authorized_message(key(1, DEVICE, 0x04, WireKeyState::Repeat), 1,),
            Err(CoordinatorError::UnmatchedRepeat)
        ));
        assert!(unmatched.injection.events.is_empty());
        assert!(unmatched.inbound_pressed.is_empty());
    }

    #[test]
    fn repeated_or_mismatched_admission_releases_held_input_and_revokes() {
        for mismatched in [false, true] {
            let mut coordinator = coordinator();
            admit(&mut coordinator);
            coordinator
                .handle_authorized_message(key(1, DEVICE, 0x04, WireKeyState::Down), 1)
                .unwrap();
            let mut next = binding(1);
            if mismatched {
                next.transport_identity.credential_fingerprint[0] ^= 1;
            }

            assert!(matches!(
                coordinator.activate_binding(endpoint(1), next, 2),
                Err(CoordinatorError::IdentityMismatch)
            ));
            assert!(!coordinator.is_admitted());
            assert!(coordinator.inbound_pressed.is_empty());
            assert_eq!(coordinator.core().workspace().active_host, LOCAL);
            assert!(matches!(
                coordinator
                    .injection
                    .events
                    .last()
                    .map(|event| event.payload),
                Some(InputPayload::Key {
                    code: KeyCode::KeyA,
                    state: KeyState::Released,
                })
            ));
        }
    }

    #[test]
    fn inbound_pressed_device_bound_fails_closed_before_overflow_mutation() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        for index in 0..MAX_INBOUND_PRESSED_DEVICES {
            coordinator
                .handle_authorized_message(
                    key(
                        index as u64 + 1,
                        indexed_device(index),
                        0x04,
                        WireKeyState::Down,
                    ),
                    1,
                )
                .unwrap();
        }
        let overflow_device = indexed_device(MAX_INBOUND_PRESSED_DEVICES);
        assert!(matches!(
            coordinator.handle_authorized_message(
                key(
                    MAX_INBOUND_PRESSED_DEVICES as u64 + 1,
                    overflow_device,
                    0x04,
                    WireKeyState::Down,
                ),
                2,
            ),
            Err(CoordinatorError::InboundPressedStateOverflow)
        ));
        assert!(!coordinator.is_admitted());
        assert!(coordinator.inbound_pressed.is_empty());
        assert!(coordinator
            .injection
            .events
            .iter()
            .all(|event| event.source_device != overflow_device));
    }

    #[test]
    fn inbound_per_device_held_bound_fails_closed() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        for index in 0..MAX_INBOUND_HELD_PER_DEVICE {
            coordinator
                .handle_authorized_message(
                    unidentified_press(index as u64 + 1, DEVICE, u16::try_from(index).unwrap()),
                    1,
                )
                .unwrap();
        }
        assert!(matches!(
            coordinator.handle_authorized_message(
                unidentified_press(
                    MAX_INBOUND_HELD_PER_DEVICE as u64 + 1,
                    DEVICE,
                    u16::try_from(MAX_INBOUND_HELD_PER_DEVICE).unwrap(),
                ),
                2,
            ),
            Err(CoordinatorError::InboundPressedStateOverflow)
        ));
        assert!(!coordinator.is_admitted());
        assert!(coordinator.inbound_pressed.is_empty());
    }

    #[test]
    fn inbound_total_held_bound_fails_closed() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        let mut sequence = 1_u64;
        for device_index in 0..(MAX_INBOUND_HELD_TOTAL / MAX_INBOUND_HELD_PER_DEVICE) {
            for usage in 0..MAX_INBOUND_HELD_PER_DEVICE {
                coordinator
                    .handle_authorized_message(
                        unidentified_press(
                            sequence,
                            indexed_device(device_index),
                            u16::try_from(usage).unwrap(),
                        ),
                        1,
                    )
                    .unwrap();
                sequence += 1;
            }
        }
        let overflow_device = indexed_device(MAX_INBOUND_PRESSED_DEVICES - 1);
        assert!(matches!(
            coordinator
                .handle_authorized_message(unidentified_press(sequence, overflow_device, 1), 2,),
            Err(CoordinatorError::InboundPressedStateOverflow)
        ));
        assert!(!coordinator.is_admitted());
        assert!(coordinator.inbound_pressed.is_empty());
        assert!(coordinator
            .injection
            .events
            .iter()
            .all(|event| event.source_device != overflow_device));
    }

    #[test]
    fn repeated_press_at_capacity_is_idempotent() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        for index in 0..MAX_INBOUND_HELD_PER_DEVICE {
            coordinator
                .handle_authorized_message(
                    unidentified_press(index as u64 + 1, DEVICE, u16::try_from(index).unwrap()),
                    1,
                )
                .unwrap();
        }
        coordinator
            .handle_authorized_message(
                unidentified_press(MAX_INBOUND_HELD_PER_DEVICE as u64 + 1, DEVICE, 0),
                2,
            )
            .unwrap();
        assert!(coordinator.is_admitted());
        assert_eq!(
            pressed_state_len(coordinator.inbound_pressed.get(&DEVICE).unwrap()),
            MAX_INBOUND_HELD_PER_DEVICE
        );
    }

    #[test]
    fn stale_sequence_disconnects_and_releases_held_input() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        coordinator
            .handle_authorized_message(key(5, DEVICE, 0xe0, WireKeyState::Down), 1)
            .unwrap();
        assert!(matches!(
            coordinator.handle_authorized_message(key(5, DEVICE, 0x04, WireKeyState::Down), 2),
            Err(CoordinatorError::StaleSequence { .. })
        ));
        assert!(!coordinator.is_admitted());
        let (core, injection, _) = coordinator.into_parts();
        assert_eq!(core.workspace().active_host, LOCAL);
        assert!(matches!(
            injection.events.last().unwrap().payload,
            InputPayload::Key {
                code: KeyCode::ControlLeft,
                state: KeyState::Released
            }
        ));
    }

    #[test]
    fn release_input_can_clear_one_device_or_every_device() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        coordinator
            .handle_authorized_message(key(1, DEVICE, 0xe0, WireKeyState::Down), 1)
            .unwrap();
        coordinator
            .handle_authorized_message(
                input(
                    2,
                    OTHER_DEVICE,
                    WireInputPayloadV1::PointerButton {
                        button: WirePointerButton::Primary,
                        state: WireButtonState::Down,
                    },
                ),
                2,
            )
            .unwrap();
        coordinator
            .handle_authorized_message(
                WireMessage::ReleaseInput(ReleaseInputV1 {
                    sequence: 3,
                    source_host: WireHostId(REMOTE.into_bytes()),
                    source_device: Some(WireDeviceId(DEVICE.into_bytes())),
                    reason: ReleaseReasonV1::StateResynchronization,
                    keys: Vec::new(),
                    buttons: Vec::new(),
                }),
                3,
            )
            .unwrap();
        assert!(!coordinator.inbound_pressed.contains_key(&DEVICE));
        assert!(coordinator.inbound_pressed.contains_key(&OTHER_DEVICE));

        coordinator
            .handle_authorized_message(
                WireMessage::ReleaseInput(ReleaseInputV1 {
                    sequence: 4,
                    source_host: WireHostId(REMOTE.into_bytes()),
                    source_device: None,
                    reason: ReleaseReasonV1::StateResynchronization,
                    keys: Vec::new(),
                    buttons: Vec::new(),
                }),
                4,
            )
            .unwrap();
        assert!(coordinator.inbound_pressed.is_empty());
        let (_, injection, _) = coordinator.into_parts();
        assert!(injection.events.iter().any(|event| matches!(
            event.payload,
            InputPayload::PointerButton {
                button: PointerButton::Left,
                state: ButtonState::Released
            }
        )));
    }

    #[test]
    fn release_proof_messages_fail_closed_until_exact_state_is_installed() {
        let release = ReleaseInputV2 {
            transaction_id: 1,
            release_token: [8; 32],
            old_session_id: [9; 32],
            sequence: 2,
            covered_input_sequence: 1,
            source_host: WireHostId(REMOTE.into_bytes()),
            applying_host: WireHostId(LOCAL.into_bytes()),
            source_device: Some(WireDeviceId(DEVICE.into_bytes())),
            reason: ReleaseReasonV2::StateResynchronization,
            keys: Vec::new(),
            buttons: Vec::new(),
        };
        let acknowledgement = ReleaseAppliedAckV2 {
            transaction_id: release.transaction_id,
            release_token: release.release_token,
            old_session_id: release.old_session_id,
            sequence: 1,
            release_sequence: release.sequence,
            covered_input_sequence: release.covered_input_sequence,
            source_host: WireHostId(LOCAL.into_bytes()),
            applying_host: WireHostId(REMOTE.into_bytes()),
        };

        for message in [
            WireMessage::ReleaseInputV2(release),
            WireMessage::ReleaseAppliedAckV2(acknowledgement),
        ] {
            let mut coordinator = coordinator();
            admit(&mut coordinator);
            assert!(matches!(
                coordinator.handle_authorized_message(message, 1),
                Err(CoordinatorError::UnsupportedReleaseProof)
            ));
            assert!(!coordinator.is_admitted());
        }
    }

    #[test]
    fn degraded_disconnect_revocation_and_channel_close_reconcile() {
        for operation in 0..3 {
            let mut coordinator = coordinator();
            admit(&mut coordinator);
            let endpoint = authorized_endpoint(&coordinator);
            coordinator
                .handle_authorized_message(key(1, DEVICE, 0xe0, WireKeyState::Down), 1)
                .unwrap();
            match operation {
                0 => {
                    coordinator
                        .handle_endpoint_state(endpoint, ConnectionState::Degraded, 2)
                        .unwrap();
                    assert!(coordinator.is_admitted());
                }
                1 => coordinator.revoke(2).unwrap(),
                _ => coordinator.channel_closed(2).unwrap(),
            }
            assert!(coordinator.inbound_pressed.is_empty());
            assert_eq!(coordinator.core().workspace().active_host, LOCAL);
        }
    }

    #[test]
    fn injection_and_outbound_failures_fail_closed() {
        let mut injection_failure = coordinator();
        admit(&mut injection_failure);
        injection_failure.injection.fail_next = true;
        assert!(matches!(
            injection_failure
                .handle_authorized_message(key(1, DEVICE, 0x04, WireKeyState::Down), 1),
            Err(CoordinatorError::Injection)
        ));
        assert!(!injection_failure.is_admitted());

        let mut outbound_failure = coordinator();
        admit(&mut outbound_failure);
        outbound_failure.outbound.fail = Some(OutboundPeerError::Full);
        let action = CoreAction::Forward {
            target: REMOTE,
            event: InputEvent::new(
                1,
                1,
                LOCAL,
                DEVICE,
                InputPayload::PointerMove { dx: 1.0, dy: 2.0 },
            ),
        };
        assert!(matches!(
            outbound_failure.dispatch_actions([action], 2),
            Err(CoordinatorError::Outbound(OutboundPeerError::Full))
        ));
        assert!(!outbound_failure.is_admitted());
        assert_eq!(outbound_failure.core().workspace().active_host, LOCAL);
    }

    #[test]
    fn coordinator_and_failure_diagnostics_redact_backend_and_input_payloads() {
        const INJECTION_SECRET: &str = "INJECTION_BACKEND_SECRET_7f3a";
        const OUTBOUND_SECRET: &str = "OUTBOUND_BACKEND_SECRET_9c2d";

        let mut active = coordinator();
        admit(&mut active);
        active.injection.error_marker = Some(INJECTION_SECRET);
        active.outbound.debug_marker = Some(OUTBOUND_SECRET);
        active
            .handle_authorized_message(key(1, DEVICE, 0x04, WireKeyState::Down), 1)
            .unwrap();
        active
            .handle_authorized_message(
                input(
                    2,
                    DEVICE,
                    WireInputPayloadV1::PointerButton {
                        button: WirePointerButton::Primary,
                        state: WireButtonState::Down,
                    },
                ),
                2,
            )
            .unwrap();
        assert!(format!("{:?}", active.injection).contains(INJECTION_SECRET));
        assert!(format!("{:?}", active.outbound).contains(OUTBOUND_SECRET));
        let coordinator_debug = format!("{active:?}");
        let remote_id = REMOTE.to_string();
        let peer_id = PEER.to_string();
        for sensitive in [
            INJECTION_SECRET,
            OUTBOUND_SECRET,
            "KeyA",
            "Primary",
            "PointerButton",
            remote_id.as_str(),
            peer_id.as_str(),
        ] {
            assert!(!coordinator_debug.contains(sensitive));
        }

        let mut injection_failure = coordinator();
        admit(&mut injection_failure);
        injection_failure.injection.error_marker = Some(INJECTION_SECRET);
        injection_failure.injection.fail_next = true;
        let error = injection_failure
            .handle_authorized_message(key(1, DEVICE, 0x04, WireKeyState::Down), 1)
            .unwrap_err();
        let diagnostics = format!("{error:?} {error}");
        assert!(!diagnostics.contains(INJECTION_SECRET));

        let mut outbound_failure = coordinator();
        admit(&mut outbound_failure);
        outbound_failure.outbound.debug_marker = Some(OUTBOUND_SECRET);
        outbound_failure.outbound.fail = Some(OutboundPeerError::Full);
        let error = outbound_failure
            .dispatch_actions(
                [CoreAction::Forward {
                    target: REMOTE,
                    event: InputEvent::new(
                        1,
                        1,
                        LOCAL,
                        DEVICE,
                        InputPayload::PointerMove { dx: 1.0, dy: 1.0 },
                    ),
                }],
                2,
            )
            .unwrap_err();
        let diagnostics = format!("{error:?} {error} {outbound_failure:?}");
        assert!(!diagnostics.contains(OUTBOUND_SECRET));

        let stale = CoordinatorError::StaleSequence {
            previous: 8_765_432_101,
            received: 8_765_432_100,
        };
        let diagnostics = format!("{stale:?} {stale}");
        assert!(!diagnostics.contains("8765432101"));
        assert!(!diagnostics.contains("8765432100"));
    }

    #[test]
    fn dispatch_converts_forward_and_cleanup_without_capture_wiring() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        let forward = CoreAction::Forward {
            target: REMOTE,
            event: InputEvent::new(
                8,
                9,
                LOCAL,
                DEVICE,
                InputPayload::Key {
                    code: KeyCode::KeyA,
                    state: KeyState::Pressed,
                },
            ),
        };
        let release = CoreAction::Release(crate::RemoteRelease {
            target: REMOTE,
            source_device: DEVICE,
            payload: InputPayload::Key {
                code: KeyCode::KeyA,
                state: KeyState::Released,
            },
        });
        coordinator.dispatch_actions([forward, release], 1).unwrap();
        let (_, _, outbound) = coordinator.into_parts();
        let WireMessage::Input(input) = &outbound.messages[0] else {
            panic!("expected input frame")
        };
        assert_eq!(input.sequence, 1);
        let WireMessage::ReleaseInput(release) = &outbound.messages[1] else {
            panic!("expected release frame")
        };
        assert_eq!(release.sequence, 2);
        assert_eq!(release.source_host, WireHostId(LOCAL.into_bytes()));
        assert_eq!(release.reason, ReleaseReasonV1::StateResynchronization);
    }

    #[test]
    fn exact_cleanup_fifo_retains_first_sequence_until_graceful_replacement() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        let first = authorized_endpoint(&coordinator);
        coordinator.core.mark_workspace_routing_ready(0).unwrap();
        coordinator
            .core
            .update_workspace(
                WorkspaceState::new(LOCAL, REMOTE, LogicalPointer::new(DISPLAY, 1.0, 1.0)),
                1,
            )
            .unwrap();
        let captured = CapturedInput::new(
            InputEvent::new(
                1,
                1,
                LOCAL,
                DEVICE,
                InputPayload::Key {
                    code: KeyCode::KeyA,
                    state: KeyState::Pressed,
                },
            ),
            crate::EventClassification::Physical,
        );
        coordinator.route_captured(captured, 1).unwrap();
        let WireMessage::Input(input) = &coordinator.outbound.messages[0] else {
            panic!("expected input frame")
        };
        assert_eq!(input.sequence, 1);
        let input_sequence = input.sequence;

        coordinator.outbound.fail = Some(OutboundPeerError::Full);
        assert!(matches!(
            coordinator.session_fatal_cleanup(2),
            Err(CoordinatorError::Outbound(OutboundPeerError::Full))
        ));
        assert_eq!(authorized_endpoint(&coordinator), first);
        assert!(coordinator.core.cleanup_pending());

        coordinator.session_fatal_cleanup(3).unwrap();
        assert!(!coordinator.is_admitted());
        let WireMessage::ReleaseInput(release) = &coordinator.outbound.messages[1] else {
            panic!("expected cleanup frame")
        };
        assert_eq!(release.sequence, 3);
        assert!(release.sequence > input_sequence);

        let second = endpoint(2);
        coordinator.activate_binding(second, binding(2), 4).unwrap();
        coordinator.core.confirm_transport_invalidated(first, 5);
        assert_eq!(authorized_endpoint(&coordinator), second);
        coordinator
            .core
            .set_endpoint_state(second, PeerState::Connected, 6)
            .unwrap();
    }

    #[test]
    fn forwarded_input_then_release_share_sequence_space_and_are_accepted() {
        let mut sender = coordinator_between(LOCAL, REMOTE);
        sender
            .activate_binding(
                endpoint_between(LOCAL, REMOTE, 1),
                binding_between(LOCAL, REMOTE, 1),
                0,
            )
            .unwrap();
        sender
            .dispatch_actions(
                [
                    CoreAction::Forward {
                        target: REMOTE,
                        event: InputEvent::new(
                            900,
                            1,
                            LOCAL,
                            DEVICE,
                            InputPayload::Key {
                                code: KeyCode::KeyA,
                                state: KeyState::Pressed,
                            },
                        ),
                    },
                    CoreAction::Release(crate::RemoteRelease {
                        target: REMOTE,
                        source_device: DEVICE,
                        payload: InputPayload::Key {
                            code: KeyCode::KeyA,
                            state: KeyState::Released,
                        },
                    }),
                ],
                2,
            )
            .unwrap();
        let (_, _, sender_outbound) = sender.into_parts();

        let mut receiver = coordinator_between(REMOTE, LOCAL);
        receiver
            .activate_binding(
                endpoint_between(REMOTE, LOCAL, 2),
                binding_between(REMOTE, LOCAL, 2),
                0,
            )
            .unwrap();
        for message in sender_outbound.messages {
            receiver.handle_authorized_message(message, 3).unwrap();
        }
        assert!(receiver.inbound_pressed.is_empty());
        let (_, injection, _) = receiver.into_parts();
        assert_eq!(injection.events.len(), 2);
    }

    #[test]
    fn prior_endpoint_cannot_change_a_new_session() {
        let mut coordinator = coordinator();
        let current = binding(2);
        coordinator
            .activate_binding(endpoint(2), current, 0)
            .unwrap();

        assert!(matches!(
            coordinator.handle_endpoint_state(endpoint(1), ConnectionState::Connected, 1),
            Err(CoordinatorError::NotAdmitted)
        ));
        assert!(!coordinator.is_admitted());
    }

    #[test]
    fn admission_binding_equality_includes_version_and_session_id_and_redacts_them() {
        let binding = binding(17);
        let mut different_version = binding.clone();
        different_version.selected_protocol_version = kvm_protocol::PROTOCOL_VERSION_V2;
        let mut different_session = binding.clone();
        different_session.session_id = [99; 32];

        assert_ne!(binding, different_version);
        assert_ne!(binding, different_session);
        assert_eq!(format!("{binding:?}"), "AdmittedSessionBinding([REDACTED])");
    }

    #[test]
    fn coordinator_revalidates_wire_messages_before_conversion() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        let invalid = input(
            1,
            DEVICE,
            WireInputPayloadV1::PointerMove {
                dx: f64::NAN,
                dy: 0.0,
            },
        );
        assert!(matches!(
            coordinator.handle_authorized_message(invalid, 1),
            Err(CoordinatorError::InvalidMessage(_))
        ));
        assert!(!coordinator.is_admitted());
    }

    #[test]
    fn pointer_motion_does_not_create_empty_pressed_state() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        coordinator
            .handle_authorized_message(
                input(
                    1,
                    DEVICE,
                    WireInputPayloadV1::PointerMove { dx: 1.0, dy: 2.0 },
                ),
                1,
            )
            .unwrap();
        assert!(coordinator.inbound_pressed.is_empty());
    }

    #[test]
    fn outbound_sequence_exhaustion_fails_closed_without_wrapping() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        coordinator.outbound_sequence = u64::MAX;
        let action = CoreAction::Forward {
            target: REMOTE,
            event: InputEvent::new(
                1,
                1,
                LOCAL,
                DEVICE,
                InputPayload::PointerMove { dx: 1.0, dy: 1.0 },
            ),
        };
        assert!(matches!(
            coordinator.dispatch_actions([action], 1),
            Err(CoordinatorError::OutboundSequenceExhausted)
        ));
        assert_eq!(coordinator.outbound_sequence, u64::MAX);
        assert!(!coordinator.is_admitted());
    }

    #[test]
    fn unsupported_application_messages_are_explicitly_deferred() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        let message = WireMessage::DeviceRemoved(kvm_protocol::DeviceRemovedV1 {
            revision: 1,
            host_id: WireHostId(REMOTE.into_bytes()),
            device_id: WireDeviceId(DEVICE.into_bytes()),
        });
        assert_eq!(
            coordinator.handle_authorized_message(message, 1).unwrap(),
            PeerEventOutcome::Deferred(MessageType::DeviceRemoved)
        );
    }

    #[test]
    fn shutdown_releases_inbound_state_and_closes_core() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        coordinator
            .handle_authorized_message(key(1, DEVICE, 0xe0, WireKeyState::Down), 1)
            .unwrap();
        coordinator.shutdown(2).unwrap();
        assert!(!coordinator.is_admitted());
        assert!(coordinator.inbound_pressed.is_empty());
        assert_eq!(coordinator.core().workspace().active_host, LOCAL);
    }

    #[test]
    fn configured_peer_is_required_at_construction() {
        let core = DaemonCore::new(
            Config::default(),
            WorkspaceState::new(LOCAL, LOCAL, LogicalPointer::new(DISPLAY, 0.0, 0.0)),
        )
        .unwrap();
        assert!(matches!(
            PeerSessionCoordinator::new(
                core,
                expected(),
                RecordingInjection::default(),
                RecordingOutbound::default()
            ),
            Err(CoordinatorError::ExpectedPeerNotConfigured)
        ));
    }

    #[test]
    fn configured_fingerprint_must_match_expected() {
        let mut config = Config::default();
        config.paired_hosts.push(PairedHostConfig {
            host_id: REMOTE,
            peer_id: PEER,
            name: "remote".into(),
            platform: Platform::Windows,
            identity_fingerprint: IdentityFingerprint::from_sha256([9; 32]).to_string(),
            last_address: None,
        });
        let core = DaemonCore::new(
            config,
            WorkspaceState::new(LOCAL, LOCAL, LogicalPointer::new(DISPLAY, 0.0, 0.0)),
        )
        .unwrap();
        assert!(matches!(
            PeerSessionCoordinator::new(
                core,
                expected(),
                RecordingInjection::default(),
                RecordingOutbound::default(),
            ),
            Err(CoordinatorError::ConfiguredFingerprintMismatch)
        ));
    }

    #[test]
    fn failed_cleanup_blocks_re_admission() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        coordinator
            .handle_authorized_message(key(1, DEVICE, 0xe0, WireKeyState::Down), 1)
            .unwrap();
        coordinator.injection.fail_next = true;
        assert!(matches!(
            coordinator.channel_closed(2),
            Err(CoordinatorError::Injection)
        ));
        assert!(!coordinator.inbound_pressed.is_empty());
        assert!(matches!(
            coordinator.activate_binding(endpoint(2), binding(2), 3),
            Err(CoordinatorError::CleanupIncomplete)
        ));
        assert!(!coordinator.is_admitted());
    }

    #[test]
    fn terminal_cleanup_errors_are_returned_without_discarding_held_state() {
        for operation in 0..3 {
            let mut coordinator = coordinator();
            admit(&mut coordinator);
            let endpoint = authorized_endpoint(&coordinator);
            coordinator
                .handle_authorized_message(key(1, DEVICE, 0xe0, WireKeyState::Down), 1)
                .unwrap();
            coordinator.injection.fail_always = true;

            let result = match operation {
                0 => coordinator
                    .handle_endpoint_state(endpoint, ConnectionState::Disconnected, 2)
                    .map(drop),
                1 => coordinator.revoke(2),
                _ => coordinator.channel_closed(2),
            };
            assert!(matches!(result, Err(CoordinatorError::Injection)));
            assert_eq!(coordinator.is_admitted(), operation == 1);
            assert!(!coordinator.inbound_pressed.is_empty());
        }
    }

    #[test]
    fn synthetic_release_sequence_exhaustion_is_checked_and_retryable() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        coordinator
            .handle_authorized_message(key(1, DEVICE, 0x04, WireKeyState::Down), 1)
            .unwrap();
        coordinator.synthetic_sequence = u64::MAX;

        for now_ns in [2, 3] {
            assert!(matches!(
                coordinator.channel_closed(now_ns),
                Err(CoordinatorError::SyntheticSequenceExhausted)
            ));
            assert_eq!(coordinator.synthetic_sequence, u64::MAX);
            assert!(!coordinator.inbound_pressed.is_empty());
            assert_eq!(coordinator.injection.events.len(), 1);
        }
    }

    #[test]
    fn fail_session_reports_both_trigger_and_failed_cleanup() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        coordinator
            .handle_authorized_message(key(5, DEVICE, 0xe0, WireKeyState::Down), 1)
            .unwrap();
        coordinator.injection.fail_always = true;

        let error = coordinator
            .handle_authorized_message(key(5, DEVICE, 0x04, WireKeyState::Down), 2)
            .unwrap_err();
        assert!(matches!(
            error,
            CoordinatorError::SessionFailureWithCleanup { trigger, cleanup }
                if matches!(*trigger, CoordinatorError::StaleSequence { .. })
                    && matches!(*cleanup, CoordinatorError::Injection)
        ));
        assert!(!coordinator.inbound_pressed.is_empty());
    }

    #[test]
    fn failed_degraded_cleanup_revokes_the_session_before_recovery() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        let endpoint = authorized_endpoint(&coordinator);
        coordinator
            .handle_authorized_message(key(1, DEVICE, 0xe0, WireKeyState::Down), 1)
            .unwrap();
        coordinator.injection.fail_next = true;
        assert!(matches!(
            coordinator.handle_endpoint_state(endpoint, ConnectionState::Degraded, 2),
            Err(CoordinatorError::Injection)
        ));
        assert!(!coordinator.is_admitted());
        assert_eq!(
            coordinator.handle_unbound_state(ConnectionState::Connected, 3),
            PeerEventOutcome::Ignored
        );
        assert!(!coordinator.is_admitted());
    }

    #[test]
    fn wire_peer_id_shape_matches_domain_test_identity() {
        assert_eq!(WirePeerId(PEER.into_bytes()).0, PEER.into_bytes());
    }
}
