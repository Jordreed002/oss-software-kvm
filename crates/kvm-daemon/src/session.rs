//! Synchronous composition of one admitted network peer and daemon safety state.
//!
//! This module deliberately does not start capture, install suppression, open a
//! socket, or run a native injection backend. Production composition may feed
//! it events only from `kvm-network`; deterministic tests use recording output
//! and outbound implementations.

use std::collections::BTreeMap;
use std::fmt;

use kvm_input::{ButtonState, InputEvent, InputPayload, KeyState, PressedState};
use kvm_network::{
    AdmittedPeer, ConnectionState, OutboundSendError, PeerEvent, PeerSender, TransportPeerIdentity,
};
use kvm_protocol::{HelloV1, MessageType, ReleaseInputV1, ValidationError, WireMessage};
use kvm_security::{IdentityFingerprint, PeerIdentity};
use kvm_types::{DeviceId, HostId, PeerId};
use thiserror::Error;

use crate::wire::{key_code_from_wire, pointer_button_from_wire};
use crate::{
    input_from_wire, input_to_wire, release_to_wire, CoreAction, DaemonCore,
    OutputInjectionBackend, PeerState, PlatformError, WireConversionError,
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

/// Fail-closed composition error. Callers should terminate the corresponding
/// peer task after any error except an explicitly returned deferred outcome.
#[derive(Debug, Error)]
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
    #[error("input sequence {received} is not newer than {previous}")]
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
    #[error("the core produced a non-release action during cleanup")]
    UnexpectedCleanupAction,
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
#[derive(Clone, Debug, PartialEq)]
struct AdmittedSessionBinding {
    transport_identity: TransportPeerIdentity,
    local_hello: HelloV1,
    remote_hello: HelloV1,
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
}

impl<I, O> fmt::Debug for PeerSessionCoordinator<I, O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerSessionCoordinator")
            .field("expected_host_id", &self.expected.host_id())
            .field("expected_peer_id", &self.expected.peer_id())
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
            outbound_sequence: 0,
        })
    }

    #[must_use]
    pub const fn core(&self) -> &DaemonCore {
        &self.core
    }

    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        self.authorized.is_some()
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
            PeerEvent::Admitted(peer) => self.activate_admitted(&peer, now_ns),
            PeerEvent::Message { peer, message } => {
                self.handle_bound_message(&admitted_binding(&peer), message, now_ns)
            }
            PeerEvent::StateChanged(state) => self.handle_state(state, now_ns),
            PeerEvent::Disconnected { .. } => {
                self.disconnect(now_ns)?;
                Ok(PeerEventOutcome::Applied)
            }
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
    pub fn dispatch_actions(
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
        self.disconnect(now_ns)
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
        let injection_result = self
            .release_all_inbound(now_ns)
            .map_err(|_| CoordinatorError::Injection);
        let actions = self.core.shutdown(now_ns);
        let outbound_result = if self.authorized.is_some() {
            self.send_cleanup_actions(actions)
        } else {
            Ok(())
        };
        self.authorized = None;
        combine_cleanup_results(injection_result, outbound_result)
    }

    /// Returns owned components for deterministic test inspection or orderly
    /// outer-composition teardown.
    #[must_use]
    pub fn into_parts(self) -> (DaemonCore, I, O) {
        (self.core, self.injection, self.outbound)
    }

    fn activate_admitted(
        &mut self,
        peer: &AdmittedPeer,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, CoordinatorError> {
        self.activate_binding(admitted_binding(peer), now_ns)
    }

    fn activate_binding(
        &mut self,
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
        self.authorized = Some(AuthorizedSession {
            binding,
            last_sequence: None,
            accepts_input: true,
        });
        let actions =
            self.core
                .set_peer_state(self.expected.host_id(), PeerState::Connected, now_ns);
        debug_assert!(actions.is_empty());
        Ok(PeerEventOutcome::Applied)
    }

    fn handle_state(
        &mut self,
        state: ConnectionState,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, CoordinatorError> {
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
            ConnectionState::Connected => {
                let Some(session) = &mut self.authorized else {
                    // A state notification is not an authorization capability.
                    return Ok(PeerEventOutcome::Ignored);
                };
                session.accepts_input = true;
                let actions =
                    self.core
                        .set_peer_state(self.expected.host_id(), PeerState::Connected, now_ns);
                debug_assert!(actions.is_empty());
            }
            ConnectionState::Degraded => {
                if let Some(session) = &mut self.authorized {
                    session.accepts_input = false;
                }
                let injection_result = self
                    .release_all_inbound(now_ns)
                    .map_err(|_| CoordinatorError::Injection);
                let actions =
                    self.core
                        .set_peer_state(self.expected.host_id(), PeerState::Degraded, now_ns);
                let outbound_result = if self.authorized.is_some() {
                    self.send_cleanup_actions(actions)
                } else {
                    Ok(())
                };
                if let Err(error) = combine_cleanup_results(injection_result, outbound_result) {
                    return Err(self.fail_session(error, now_ns));
                }
            }
            ConnectionState::Disconnected => self.disconnect(now_ns)?,
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
            other => Ok(PeerEventOutcome::Deferred(other.message_type())),
        }
    }

    fn handle_bound_message(
        &mut self,
        binding: &AdmittedSessionBinding,
        message: WireMessage,
        now_ns: u64,
    ) -> Result<PeerEventOutcome, CoordinatorError> {
        if self
            .authorized
            .as_ref()
            .is_none_or(|session| &session.binding != binding)
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
            } => state.pressed_keys().any(|held| held == code),
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
                );
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
                );
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
            let event = self.synthetic_event(device, payload, now_ns);
            self.inject_received(event, now_ns)?;
        }
        Ok(())
    }

    fn release_all_inbound(&mut self, now_ns: u64) -> Result<(), PlatformError> {
        let releases = self.inbound_releases(None);
        let mut first_error = None;
        for (device, payload) in releases {
            let event = self.synthetic_event(device, payload, now_ns);
            match self.injection.inject(&event) {
                Ok(()) => {
                    if let Some(state) = self.inbound_pressed.get_mut(&device) {
                        state.apply(&event.payload);
                    }
                }
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        self.inbound_pressed.retain(|_, state| !state.is_empty());
        first_error.map_or(Ok(()), Err)
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
    ) -> InputEvent {
        let sequence = self.synthetic_sequence;
        self.synthetic_sequence = self.synthetic_sequence.saturating_add(1);
        InputEvent::new(sequence, now_ns, self.expected.host_id(), device, payload)
    }

    fn next_outbound_sequence(&mut self) -> Result<u64, CoordinatorError> {
        let sequence = self.outbound_sequence;
        self.outbound_sequence = sequence
            .checked_add(1)
            .ok_or(CoordinatorError::OutboundSequenceExhausted)?;
        Ok(sequence)
    }

    fn send_cleanup_actions(&mut self, actions: Vec<CoreAction>) -> Result<(), CoordinatorError> {
        for action in actions {
            let CoreAction::Release(release) = action else {
                return Err(CoordinatorError::UnexpectedCleanupAction);
            };
            if release.target != self.expected.host_id() {
                return Err(CoordinatorError::WrongActionTarget);
            }
            let sequence = self.next_outbound_sequence()?;
            let wire = release_to_wire(release, sequence, self.core.workspace().local_host)?;
            if let Err(error) = self.outbound.try_send(WireMessage::ReleaseInput(wire)) {
                return Err(CoordinatorError::Outbound(error));
            }
        }
        Ok(())
    }

    fn disconnect(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        if let Some(session) = &mut self.authorized {
            session.accepts_input = false;
        }
        let injection_result = self
            .release_all_inbound(now_ns)
            .map_err(|_| CoordinatorError::Injection);
        let actions =
            self.core
                .set_peer_state(self.expected.host_id(), PeerState::Disconnected, now_ns);
        let outbound_result = if self.authorized.is_some() {
            self.send_cleanup_actions(actions)
        } else if actions.is_empty() {
            Ok(())
        } else {
            Err(CoordinatorError::NotAdmitted)
        };
        self.authorized = None;
        combine_cleanup_results(injection_result, outbound_result)
    }

    fn fail_session(&mut self, trigger: CoordinatorError, now_ns: u64) -> CoordinatorError {
        match self.disconnect(now_ns) {
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
    use kvm_protocol::{
        InputEventV1, ReleaseReasonV1, WireButtonState, WireDeviceId, WireHostId,
        WireInputPayloadV1, WireKeyCode, WireKeyState, WirePeerId, WirePlatform, WirePointerButton,
    };
    use kvm_security::IdentityFingerprint;
    use kvm_types::{DisplayId, LogicalPointer, Platform, WorkspaceState};

    use super::*;

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
        let workspace = WorkspaceState::new(local, remote, LogicalPointer::new(DISPLAY, 0.0, 0.0));
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
        }
    }

    fn binding(nonce: u8) -> AdmittedSessionBinding {
        binding_between(LOCAL, REMOTE, nonce)
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
            coordinator.activate_binding(binding(1), 0).unwrap(),
            PeerEventOutcome::Applied
        );
    }

    #[test]
    fn connected_notification_alone_never_authorizes_input() {
        let mut coordinator = coordinator();
        assert_eq!(
            coordinator
                .handle_state(ConnectionState::Connected, 0)
                .unwrap(),
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
            coordinator.activate_binding(wrong, 0),
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
                coordinator.activate_binding(next, 2),
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
    fn degraded_disconnect_revocation_and_channel_close_reconcile() {
        for operation in 0..3 {
            let mut coordinator = coordinator();
            admit(&mut coordinator);
            coordinator
                .handle_authorized_message(key(1, DEVICE, 0xe0, WireKeyState::Down), 1)
                .unwrap();
            match operation {
                0 => {
                    coordinator
                        .handle_state(ConnectionState::Degraded, 2)
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
        for sensitive in [
            INJECTION_SECRET,
            OUTBOUND_SECRET,
            "KeyA",
            "Primary",
            "PointerButton",
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
        assert_eq!(input.sequence, 0);
        let WireMessage::ReleaseInput(release) = &outbound.messages[1] else {
            panic!("expected release frame")
        };
        assert_eq!(release.sequence, 1);
        assert_eq!(release.source_host, WireHostId(LOCAL.into_bytes()));
        assert_eq!(release.reason, ReleaseReasonV1::StateResynchronization);
    }

    #[test]
    fn forwarded_input_then_release_share_sequence_space_and_are_accepted() {
        let mut sender = coordinator_between(LOCAL, REMOTE);
        sender
            .activate_binding(binding_between(LOCAL, REMOTE, 1), 0)
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
            .activate_binding(binding_between(REMOTE, LOCAL, 2), 0)
            .unwrap();
        for message in sender_outbound.messages {
            receiver.handle_authorized_message(message, 3).unwrap();
        }
        assert!(receiver.inbound_pressed.is_empty());
        let (_, injection, _) = receiver.into_parts();
        assert_eq!(injection.events.len(), 2);
    }

    #[test]
    fn prior_admission_binding_cannot_send_into_a_new_session() {
        let mut coordinator = coordinator();
        let old = binding(1);
        let current = binding(2);
        coordinator.activate_binding(current, 0).unwrap();

        assert!(matches!(
            coordinator.handle_bound_message(&old, key(1, DEVICE, 0x04, WireKeyState::Down), 1,),
            Err(CoordinatorError::IdentityMismatch)
        ));
        assert!(!coordinator.is_admitted());
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
    fn cleanup_rejects_an_unexpected_forward_action() {
        let mut coordinator = coordinator();
        admit(&mut coordinator);
        let unexpected = CoreAction::Forward {
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
            coordinator.send_cleanup_actions(vec![unexpected]),
            Err(CoordinatorError::UnexpectedCleanupAction)
        ));
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
    fn configured_fingerprint_must_be_canonical_and_match_expected() {
        for (fingerprint, expected_error) in [
            ("not-a-fingerprint".to_owned(), 0_u8),
            (IdentityFingerprint::from_sha256([9; 32]).to_string(), 1_u8),
        ] {
            let mut config = Config::default();
            config.paired_hosts.push(PairedHostConfig {
                host_id: REMOTE,
                peer_id: PEER,
                name: "remote".into(),
                platform: Platform::Windows,
                identity_fingerprint: fingerprint,
                last_address: None,
            });
            let core = DaemonCore::new(
                config,
                WorkspaceState::new(LOCAL, LOCAL, LogicalPointer::new(DISPLAY, 0.0, 0.0)),
            )
            .unwrap();
            let result = PeerSessionCoordinator::new(
                core,
                expected(),
                RecordingInjection::default(),
                RecordingOutbound::default(),
            );
            match expected_error {
                0 => assert!(matches!(
                    result,
                    Err(CoordinatorError::InvalidConfiguredFingerprint)
                )),
                _ => assert!(matches!(
                    result,
                    Err(CoordinatorError::ConfiguredFingerprintMismatch)
                )),
            }
        }
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
            coordinator.activate_binding(binding(2), 3),
            Err(CoordinatorError::CleanupIncomplete)
        ));
        assert!(!coordinator.is_admitted());
    }

    #[test]
    fn terminal_cleanup_errors_are_returned_without_discarding_held_state() {
        for operation in 0..3 {
            let mut coordinator = coordinator();
            admit(&mut coordinator);
            coordinator
                .handle_authorized_message(key(1, DEVICE, 0xe0, WireKeyState::Down), 1)
                .unwrap();
            coordinator.injection.fail_always = true;

            let result = match operation {
                0 => coordinator
                    .handle_state(ConnectionState::Disconnected, 2)
                    .map(drop),
                1 => coordinator.revoke(2),
                _ => coordinator.channel_closed(2),
            };
            assert!(matches!(result, Err(CoordinatorError::Injection)));
            assert!(!coordinator.is_admitted());
            assert!(!coordinator.inbound_pressed.is_empty());
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
        coordinator
            .handle_authorized_message(key(1, DEVICE, 0xe0, WireKeyState::Down), 1)
            .unwrap();
        coordinator.injection.fail_next = true;
        assert!(matches!(
            coordinator.handle_state(ConnectionState::Degraded, 2),
            Err(CoordinatorError::Injection)
        ));
        assert!(!coordinator.is_admitted());
        assert_eq!(
            coordinator
                .handle_state(ConnectionState::Connected, 3)
                .unwrap(),
            PeerEventOutcome::Ignored
        );
        assert!(!coordinator.is_admitted());
    }

    #[test]
    fn wire_peer_id_shape_matches_domain_test_identity() {
        assert_eq!(WirePeerId(PEER.into_bytes()).0, PEER.into_bytes());
    }
}
