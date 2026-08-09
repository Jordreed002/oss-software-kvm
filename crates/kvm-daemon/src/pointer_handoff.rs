//! Deterministic, generation-bound two-phase logical pointer handoff.
//!
//! This module deliberately performs no socket or native-input work. Every
//! outbound protocol message is returned as an affine effect which the daemon
//! must report as sent or failed. Routing authority remains local until the
//! exact configured transition is acknowledged.

#![allow(
    dead_code,
    reason = "session dispatch calls are staged for milestone 06 workstream D"
)]

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use kvm_network::{ConnectionGeneration, TransportPeerIdentity};
use kvm_protocol::{
    HelloV1, PointerEnterV1, PointerLeaveV1, PointerTransitionAckV1, PointerTransitionCommitV1,
    PointerTransitionOutcomeV1, WireEdge, WireHostId, WireMessage,
};
use kvm_topology::{ConfiguredWorkspace, WorkspaceTransition};
use kvm_types::{DisplayId, Edge, HostId, LogicalPointer, Point, WorkspaceState};

use crate::supervisor::CurrentAdmittedSession;

/// A handoff cannot remain pending beyond this local safety bound.
pub const MAX_POINTER_HANDOFF_TIMEOUT: Duration = Duration::from_secs(30);

const EDGES: [Edge; 4] = [Edge::Left, Edge::Right, Edge::Top, Edge::Bottom];

/// Positive bounded configuration for one peer's handoff coordinator.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PointerHandoffConfig {
    timeout: Duration,
}

impl PointerHandoffConfig {
    /// Creates a bounded handoff configuration.
    ///
    /// # Errors
    ///
    /// Rejects zero, sub-nanosecond, or excessive timeout values.
    pub fn new(timeout: Duration) -> Result<Self, PointerHandoffError> {
        let nanos = timeout.as_nanos();
        if nanos == 0
            || nanos > MAX_POINTER_HANDOFF_TIMEOUT.as_nanos()
            || u64::try_from(nanos).is_err()
        {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidConfig,
            ));
        }
        Ok(Self { timeout })
    }

    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }
}

impl fmt::Debug for PointerHandoffConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PointerHandoffConfig")
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Coarse, payload-free handoff failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerHandoffErrorKind {
    InvalidConfig,
    InvalidWorkspaceState,
    Unavailable,
    NoCurrentSession,
    StaleSession,
    NotAuthoritative,
    NotRemoteTransition,
    PendingConflict,
    InvalidWorkspaceEpoch,
    InvalidHost,
    InvalidDisplay,
    InvalidTransition,
    InvalidSequence,
    StaleSequence,
    FutureSequence,
    ConflictingReplay,
    SequenceExhausted,
    ClockRegressed,
    ClockOverflow,
    InvalidEffect,
    StaleEffect,
}

/// Redacted coordinator error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PointerHandoffError {
    kind: PointerHandoffErrorKind,
}

impl PointerHandoffError {
    const fn new(kind: PointerHandoffErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> PointerHandoffErrorKind {
        self.kind
    }
}

impl fmt::Debug for PointerHandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PointerHandoffError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for PointerHandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            PointerHandoffErrorKind::InvalidConfig => "pointer handoff configuration is invalid",
            PointerHandoffErrorKind::InvalidWorkspaceState => {
                "pointer handoff workspace state is invalid"
            }
            PointerHandoffErrorKind::Unavailable => "pointer handoff is unavailable",
            PointerHandoffErrorKind::NoCurrentSession => {
                "pointer handoff has no current admitted session"
            }
            PointerHandoffErrorKind::StaleSession => "pointer handoff session binding is stale",
            PointerHandoffErrorKind::NotAuthoritative => {
                "pointer handoff source is not authoritative"
            }
            PointerHandoffErrorKind::NotRemoteTransition => {
                "pointer handoff does not cross to the admitted peer"
            }
            PointerHandoffErrorKind::PendingConflict => {
                "pointer handoff conflicts with pending work"
            }
            PointerHandoffErrorKind::InvalidWorkspaceEpoch => {
                "pointer handoff workspace epoch is invalid"
            }
            PointerHandoffErrorKind::InvalidHost => "pointer handoff host is invalid",
            PointerHandoffErrorKind::InvalidDisplay => "pointer handoff display is invalid",
            PointerHandoffErrorKind::InvalidTransition => "pointer handoff transition is invalid",
            PointerHandoffErrorKind::InvalidSequence => "pointer handoff sequence is invalid",
            PointerHandoffErrorKind::StaleSequence => "pointer handoff sequence is stale",
            PointerHandoffErrorKind::FutureSequence => "pointer handoff sequence has a gap",
            PointerHandoffErrorKind::ConflictingReplay => {
                "pointer handoff reuses a transition inconsistently"
            }
            PointerHandoffErrorKind::SequenceExhausted => "pointer handoff sequence is exhausted",
            PointerHandoffErrorKind::ClockRegressed => "pointer handoff monotonic clock regressed",
            PointerHandoffErrorKind::ClockOverflow => "pointer handoff deadline overflowed",
            PointerHandoffErrorKind::InvalidEffect => "pointer handoff effect is invalid",
            PointerHandoffErrorKind::StaleEffect => "pointer handoff effect is stale",
        })
    }
}

impl Error for PointerHandoffError {}

/// Result of an idempotent control-plane operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerHandoffStatus {
    Applied,
    Duplicate,
    Cleared,
    NoChange,
}

/// Which bounded pending operations expired during a timer poll.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PointerHandoffTimeouts {
    pub outbound: bool,
    pub inbound: bool,
    pub reply: bool,
}

/// Completion of one affine outbound effect.
#[must_use]
pub enum PointerEffectCompletion {
    Sent,
    AuthorityCommitted,
    Next(Box<PointerHandoffEffect>),
}

#[must_use]
pub enum PointerAckOutcome {
    Duplicate,
    Rejected,
    Commit(Box<PointerHandoffEffect>),
}

impl fmt::Debug for PointerAckOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Duplicate => "Duplicate",
            Self::Rejected => "Rejected",
            Self::Commit(_) => "Commit",
        };
        formatter
            .debug_struct("PointerAckOutcome")
            .field("kind", &kind)
            .finish()
    }
}

pub(crate) enum PointerDispatchError<E> {
    Handoff(PointerHandoffError),
    Outbound(E),
}

impl fmt::Debug for PointerEffectCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Sent => "Sent",
            Self::AuthorityCommitted => "AuthorityCommitted",
            Self::Next(_) => "Next",
        };
        formatter
            .debug_struct("PointerEffectCompletion")
            .field("kind", &kind)
            .finish()
    }
}

trait SessionBinding: Clone + Eq {
    fn local_host_id(&self) -> HostId;
    fn remote_host_id(&self) -> HostId;
}

/// Retained pointer state is identity-neutral and never authorizes by itself.
/// Every externally driven operation re-derives this exact, gate-bound value
/// from the supervisor's live non-Clone admission capability.
#[derive(Clone, PartialEq)]
struct PointerSessionBinding {
    generation: ConnectionGeneration,
    local_host_id: HostId,
    remote_host_id: HostId,
    transport_identity: TransportPeerIdentity,
    local_hello: HelloV1,
    remote_hello: HelloV1,
}

impl Eq for PointerSessionBinding {}

impl PointerSessionBinding {
    fn from_current(session: &CurrentAdmittedSession) -> Self {
        Self {
            generation: session.generation(),
            local_host_id: session.local_host_id(),
            remote_host_id: session.remote_host_id(),
            transport_identity: session.transport_identity().clone(),
            local_hello: session.local_hello().clone(),
            remote_hello: session.remote_hello().clone(),
        }
    }
}

impl fmt::Debug for PointerSessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PointerSessionBinding([REDACTED])")
    }
}

impl SessionBinding for PointerSessionBinding {
    fn local_host_id(&self) -> HostId {
        self.local_host_id
    }

    fn remote_host_id(&self) -> HostId {
        self.remote_host_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoordinatorLifecycle {
    Running,
    Revoked,
    ShuttingDown,
}

#[derive(Clone, Copy, PartialEq)]
struct ResolvedTransition {
    source_display: DisplayId,
    source_host: HostId,
    source_edge: Edge,
    destination_display: DisplayId,
    destination_host: HostId,
    destination_edge: Edge,
    normalized_position: f64,
    destination_pointer: LogicalPointer,
}

impl From<WorkspaceTransition> for ResolvedTransition {
    fn from(value: WorkspaceTransition) -> Self {
        let destination_point = value.destination_point();
        Self {
            source_display: value.source_display(),
            source_host: value.source_host(),
            source_edge: value.source_edge(),
            destination_display: value.destination_display(),
            destination_host: value.destination_host(),
            destination_edge: value.destination_edge(),
            normalized_position: value.normalized_position(),
            destination_pointer: LogicalPointer::new(
                value.destination_display(),
                destination_point.x,
                destination_point.y,
            ),
        }
    }
}

impl fmt::Debug for ResolvedTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResolvedTransition([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutboundPhase {
    LeaveQueued,
    EnterQueued,
    AwaitingAck,
    CommitQueued,
    CommitDispatching,
}

struct PendingOutbound<B> {
    session: B,
    transition_id: u64,
    deadline_ns: u64,
    leave: PointerLeaveV1,
    enter: PointerEnterV1,
    accepted_ack: Option<PointerTransitionAckV1>,
    transition: ResolvedTransition,
    phase: OutboundPhase,
}

enum PendingInbound<B> {
    Hint {
        session: B,
        deadline_ns: u64,
        leave: PointerLeaveV1,
        expected_enter: PointerEnterV1,
        transition: ResolvedTransition,
    },
    Proposal {
        session: B,
        deadline_ns: u64,
        expected_leave: PointerLeaveV1,
        enter: PointerEnterV1,
        ack: PointerTransitionAckV1,
        transition: ResolvedTransition,
    },
    Prepared {
        session: B,
        deadline_ns: u64,
        expected_leave: PointerLeaveV1,
        enter: PointerEnterV1,
        ack: PointerTransitionAckV1,
        commit: PointerTransitionCommitV1,
        transition: ResolvedTransition,
    },
}

impl<B> PendingInbound<B> {
    const fn deadline_ns(&self) -> u64 {
        match self {
            Self::Hint { deadline_ns, .. }
            | Self::Proposal { deadline_ns, .. }
            | Self::Prepared { deadline_ns, .. } => *deadline_ns,
        }
    }
}

struct CompletedOutbound<B> {
    session: B,
    ack: PointerTransitionAckV1,
}

struct CompletedInbound<B> {
    session: B,
    expected_leave: Option<PointerLeaveV1>,
    enter: PointerEnterV1,
    ack: PointerTransitionAckV1,
    commit: Option<PointerTransitionCommitV1>,
}

struct ExpiredInbound<B> {
    session: B,
    leave: PointerLeaveV1,
    enter: PointerEnterV1,
}

struct PendingReply<B> {
    session: B,
    transition_id: u64,
    deadline_ns: u64,
    purpose: EffectPurpose,
    enter: PointerEnterV1,
    message: PointerControlMessage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectPurpose {
    Leave,
    Enter,
    AcceptedAck,
    DuplicateAcceptedAck,
    RejectedAck,
    Commit,
}

#[derive(Clone, Copy)]
enum PointerControlMessage {
    Leave(PointerLeaveV1),
    Enter(PointerEnterV1),
    Ack(PointerTransitionAckV1),
    Commit(PointerTransitionCommitV1),
}

impl PointerControlMessage {
    fn wire_message(self) -> WireMessage {
        match self {
            Self::Leave(message) => WireMessage::PointerLeave(message),
            Self::Enter(message) => WireMessage::PointerEnter(message),
            Self::Ack(message) => WireMessage::PointerTransitionAck(message),
            Self::Commit(message) => WireMessage::PointerTransitionCommit(message),
        }
    }
}

struct CoreEffect<B> {
    owner: Arc<()>,
    session: B,
    transition_id: u64,
    purpose: EffectPurpose,
    message: PointerControlMessage,
}

impl<B> CoreEffect<B> {
    fn wire_message(&self) -> WireMessage {
        self.message.wire_message()
    }
}

impl<B> fmt::Debug for CoreEffect<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PointerHandoffEffect")
            .field("kind", &self.purpose)
            .finish_non_exhaustive()
    }
}

/// Affine message dispatch capability returned by the coordinator.
///
/// Read the wire value, attempt one bounded queue insertion, then return this
/// capability through `effect_sent` or `effect_failed`. It is intentionally
/// neither `Clone` nor publicly constructible.
#[must_use]
pub struct PointerHandoffEffect(CoreEffect<PointerSessionBinding>);

impl PointerHandoffEffect {
    fn wire_message(&self) -> WireMessage {
        self.0.wire_message()
    }

    pub(crate) fn is_accepted_ack(&self) -> bool {
        self.0.purpose == EffectPurpose::AcceptedAck
            && matches!(
                self.0.message,
                PointerControlMessage::Ack(PointerTransitionAckV1 {
                    outcome: PointerTransitionOutcomeV1::Accepted,
                    ..
                })
            )
    }
}

impl fmt::Debug for PointerHandoffEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

enum CoreEffectCompletion<B> {
    Sent,
    AuthorityCommitted,
    Next(CoreEffect<B>),
}

enum CoreAckOutcome<B> {
    Duplicate,
    Rejected,
    Commit(CoreEffect<B>),
}

impl<B> fmt::Debug for CoreAckOutcome<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Duplicate => "Duplicate",
            Self::Rejected => "Rejected",
            Self::Commit(_) => "Commit",
        };
        formatter
            .debug_struct("CoreAckOutcome")
            .field("kind", &kind)
            .finish()
    }
}

#[derive(Debug)]
enum CoreDispatchError<E> {
    Handoff(PointerHandoffError),
    Outbound(E),
}

struct CoordinatorCore<B> {
    owner: Arc<()>,
    config: PointerHandoffConfig,
    lifecycle: CoordinatorLifecycle,
    session: Option<B>,
    session_healthy: bool,
    workspace: ConfiguredWorkspace,
    workspace_state: WorkspaceState,
    local_fallback: LogicalPointer,
    last_now_ns: u64,
    last_outbound_sequence: u64,
    last_inbound_sequence: u64,
    outbound: Option<PendingOutbound<B>>,
    inbound: Option<PendingInbound<B>>,
    completed_outbound: Option<CompletedOutbound<B>>,
    completed_inbound: Option<CompletedInbound<B>>,
    expired_inbound: Option<ExpiredInbound<B>>,
    reply: Option<PendingReply<B>>,
}

impl<B> fmt::Debug for CoordinatorCore<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PointerHandoffCoordinator")
            .field("lifecycle", &self.lifecycle)
            .field("admitted", &self.session.is_some())
            .field("healthy", &self.session_healthy)
            .field(
                "local_authority",
                &(self.workspace_state.active_host == self.workspace_state.local_host),
            )
            .field("outbound_pending", &self.outbound.is_some())
            .field("inbound_pending", &self.inbound.is_some())
            .finish_non_exhaustive()
    }
}

impl<B> CoordinatorCore<B>
where
    B: SessionBinding,
{
    fn new(
        config: PointerHandoffConfig,
        workspace: ConfiguredWorkspace,
        workspace_state: WorkspaceState,
        local_fallback: LogicalPointer,
    ) -> Result<Self, PointerHandoffError> {
        validate_state(&workspace, workspace_state, local_fallback)?;
        Ok(Self {
            owner: Arc::new(()),
            config,
            lifecycle: CoordinatorLifecycle::Running,
            session: None,
            session_healthy: false,
            workspace,
            workspace_state,
            local_fallback,
            last_now_ns: 0,
            last_outbound_sequence: 0,
            last_inbound_sequence: 0,
            outbound: None,
            inbound: None,
            completed_outbound: None,
            completed_inbound: None,
            expired_inbound: None,
            reply: None,
        })
    }

    const fn workspace_state(&self) -> WorkspaceState {
        self.workspace_state
    }

    fn has_local_authority(&self) -> bool {
        self.workspace_state.active_host == self.workspace_state.local_host
            && !self
                .outbound
                .as_ref()
                .is_some_and(|pending| pending.phase == OutboundPhase::CommitDispatching)
    }

    fn next_deadline_ns(&self) -> Option<u64> {
        self.outbound
            .as_ref()
            .map(|pending| pending.deadline_ns)
            .into_iter()
            .chain(self.inbound.as_ref().map(PendingInbound::deadline_ns))
            .chain(self.reply.as_ref().map(|reply| reply.deadline_ns))
            .min()
    }

    fn bind_session(&mut self, session: &B) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.ensure_running()?;
        if session.local_host_id() != self.workspace_state.local_host
            || session.remote_host_id() == self.workspace_state.local_host
        {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidHost,
            ));
        }
        if self.session.as_ref() == Some(session) {
            return Ok(PointerHandoffStatus::Duplicate);
        }
        if self.session.is_some() {
            self.fail_local();
            self.clear_transition_state();
        }
        self.session = Some(session.clone());
        self.session_healthy = true;
        self.last_outbound_sequence = 0;
        self.last_inbound_sequence = 0;
        Ok(PointerHandoffStatus::Applied)
    }

    fn mark_session_healthy(
        &mut self,
        session: &B,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.ensure_running()?;
        self.require_session(session)?;
        if self.session_healthy {
            Ok(PointerHandoffStatus::Duplicate)
        } else {
            self.session_healthy = true;
            Ok(PointerHandoffStatus::Applied)
        }
    }

    fn degrade_session(
        &mut self,
        session: &B,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.require_session(session)?;
        let changed = self.session_healthy || self.outbound.is_some() || self.inbound.is_some();
        self.session_healthy = false;
        self.fail_local();
        self.clear_transition_state();
        Ok(if changed {
            PointerHandoffStatus::Cleared
        } else {
            PointerHandoffStatus::Duplicate
        })
    }

    fn disconnect_session(
        &mut self,
        session: &B,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.require_session(session)?;
        self.fail_local();
        self.clear_transition_state();
        self.session = None;
        self.session_healthy = false;
        Ok(PointerHandoffStatus::Cleared)
    }

    fn replace_workspace(
        &mut self,
        workspace: ConfiguredWorkspace,
        local_fallback: LogicalPointer,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.ensure_running()?;
        if workspace.epoch() <= self.workspace.epoch() {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidWorkspaceEpoch,
            ));
        }
        validate_local_fallback(self.workspace_state.local_host, &workspace, local_fallback)?;
        self.workspace = workspace;
        self.local_fallback = local_fallback;
        self.fail_local();
        self.clear_transition_state();
        Ok(PointerHandoffStatus::Cleared)
    }

    fn revoke(&mut self) -> PointerHandoffStatus {
        self.fail_local();
        self.clear_transition_state();
        self.session = None;
        self.session_healthy = false;
        self.lifecycle = CoordinatorLifecycle::Revoked;
        PointerHandoffStatus::Cleared
    }

    fn shutdown(&mut self) -> PointerHandoffStatus {
        self.fail_local();
        self.clear_transition_state();
        self.session = None;
        self.session_healthy = false;
        self.lifecycle = CoordinatorLifecycle::ShuttingDown;
        PointerHandoffStatus::Cleared
    }

    fn propose_leave(
        &mut self,
        session: &B,
        source_edge: Edge,
        normalized_position: f64,
        now_ns: u64,
    ) -> Result<CoreEffect<B>, PointerHandoffError> {
        self.prepare_operation(now_ns)?;
        self.require_available_session(session)?;
        if self.outbound.is_some() || self.inbound.is_some() {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::PendingConflict,
            ));
        }
        if !self.has_local_authority()
            || self.workspace_state.active_display != self.workspace_state.pointer.display_id
        {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::NotAuthoritative,
            ));
        }
        let source_display = self.workspace_state.active_display;
        let transition = self
            .workspace
            .transition(source_display, source_edge, normalized_position)
            .map(ResolvedTransition::from)
            .map_err(|_| PointerHandoffError::new(PointerHandoffErrorKind::InvalidTransition))?;
        if transition.source_host != self.workspace_state.local_host
            || transition.destination_host != session.remote_host_id()
        {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::NotRemoteTransition,
            ));
        }
        let transition_id = self.next_outbound_sequence()?;
        let deadline_ns = self.deadline(now_ns)?;
        let leave = make_leave(transition_id, self.workspace.protocol_epoch(), transition);
        let enter = make_enter(transition_id, self.workspace.protocol_epoch(), transition);
        self.last_outbound_sequence = transition_id;
        self.outbound = Some(PendingOutbound {
            session: session.clone(),
            transition_id,
            deadline_ns,
            leave,
            enter,
            accepted_ack: None,
            transition,
            phase: OutboundPhase::LeaveQueued,
        });
        Ok(self.effect(
            session,
            transition_id,
            EffectPurpose::Leave,
            PointerControlMessage::Leave(leave),
        ))
    }

    fn receive_leave(
        &mut self,
        session: &B,
        message: PointerLeaveV1,
        now_ns: u64,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.prepare_operation(now_ns)?;
        self.require_available_session(session)?;
        if self.reply.is_some() {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::PendingConflict,
            ));
        }
        match self.classify_inbound_sequence(message.transition_id, message.sequence)? {
            InboundSequence::Duplicate => return self.duplicate_leave(session, message),
            InboundSequence::Next => {}
        }
        if self.outbound.is_some() {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::PendingConflict,
            ));
        }
        if let Some(pending) = &self.inbound {
            return if pending_leave(pending) == message {
                Ok(PointerHandoffStatus::Duplicate)
            } else {
                Err(PointerHandoffError::new(
                    PointerHandoffErrorKind::ConflictingReplay,
                ))
            };
        }
        self.validate_leave_authority(session, message)?;
        let transition = self.resolve_leave(message)?;
        let expected_enter = make_enter(
            message.transition_id,
            self.workspace.protocol_epoch(),
            transition,
        );
        let deadline_ns = self.deadline(now_ns)?;
        self.inbound = Some(PendingInbound::Hint {
            session: session.clone(),
            deadline_ns,
            leave: message,
            expected_enter,
            transition,
        });
        Ok(PointerHandoffStatus::Applied)
    }

    fn receive_enter(
        &mut self,
        session: &B,
        message: PointerEnterV1,
        now_ns: u64,
    ) -> Result<CoreEffect<B>, PointerHandoffError> {
        self.prepare_operation(now_ns)?;
        self.require_available_session(session)?;
        if let Some(reply) = &self.reply {
            return Err(PointerHandoffError::new(
                if reply.session == *session && reply.enter == message {
                    PointerHandoffErrorKind::StaleEffect
                } else {
                    PointerHandoffErrorKind::PendingConflict
                },
            ));
        }
        match self.classify_inbound_sequence(message.transition_id, message.sequence)? {
            InboundSequence::Duplicate => return self.duplicate_enter(session, message),
            InboundSequence::Next => {}
        }
        if self.outbound.is_some() {
            return self.rejection_effect(session, message, PointerTransitionOutcomeV1::Rejected);
        }
        if let Some(pending) = &self.inbound {
            let hint_matches = matches!(pending, PendingInbound::Hint {
                session: pending_session,
                expected_enter,
                ..
            } if pending_session == session && *expected_enter == message);
            let proposal_matches = matches!(pending, PendingInbound::Proposal {
                session: pending_session,
                enter,
                ..
            } if pending_session == session && *enter == message);
            if hint_matches {
                return self.accept_enter_from_hint(session, message);
            }
            if proposal_matches {
                return Err(PointerHandoffError::new(
                    PointerHandoffErrorKind::StaleEffect,
                ));
            }
            return self.rejection_effect(session, message, PointerTransitionOutcomeV1::Rejected);
        }
        let outcome = match self.validate_enter_authority(session, message) {
            Ok(()) => None,
            Err(PointerHandoffErrorKind::InvalidWorkspaceEpoch) => {
                Some(PointerTransitionOutcomeV1::StaleWorkspaceEpoch)
            }
            Err(PointerHandoffErrorKind::InvalidDisplay) => {
                Some(PointerTransitionOutcomeV1::UnknownDisplay)
            }
            Err(
                PointerHandoffErrorKind::NotAuthoritative | PointerHandoffErrorKind::InvalidHost,
            ) => Some(PointerTransitionOutcomeV1::NotAuthoritative),
            Err(_) => Some(PointerTransitionOutcomeV1::Rejected),
        };
        if let Some(outcome) = outcome {
            return self.rejection_effect(session, message, outcome);
        }
        let transition = match self.resolve_enter(message) {
            Ok(transition) => transition,
            Err(error) => {
                let outcome = if error.kind() == PointerHandoffErrorKind::InvalidDisplay {
                    PointerTransitionOutcomeV1::UnknownDisplay
                } else {
                    PointerTransitionOutcomeV1::Rejected
                };
                return self.rejection_effect(session, message, outcome);
            }
        };
        Ok(self.accept_enter(session, message, transition, self.deadline(now_ns)?))
    }

    fn receive_ack(
        &mut self,
        session: &B,
        ack: PointerTransitionAckV1,
        now_ns: u64,
    ) -> Result<CoreAckOutcome<B>, PointerHandoffError> {
        self.prepare_operation(now_ns)?;
        self.require_available_session(session)?;
        if let Some(completed) = &self.completed_outbound {
            if ack.transition_id == completed.ack.transition_id {
                return if completed.session == *session && completed.ack == ack {
                    Ok(CoreAckOutcome::Duplicate)
                } else {
                    Err(PointerHandoffError::new(
                        PointerHandoffErrorKind::ConflictingReplay,
                    ))
                };
            }
        }
        let Some(pending) = self.outbound.as_ref() else {
            return Err(Self::sequence_relation_error(
                ack.transition_id,
                self.last_outbound_sequence,
            ));
        };
        if ack.transition_id != pending.transition_id {
            return Err(Self::sequence_relation_error(
                ack.transition_id,
                pending.transition_id,
            ));
        }
        if pending.session != *session || pending.phase != OutboundPhase::AwaitingAck {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        }
        let expected_receiver = wire_host(pending.transition.destination_host);
        let expected_display = pending.enter.destination_display;
        if ack.workspace_epoch != pending.enter.workspace_epoch
            || ack.receiver_host != expected_receiver
            || ack.active_display != expected_display
        {
            self.fail_local();
            self.outbound = None;
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::ConflictingReplay,
            ));
        }
        if ack.outcome != PointerTransitionOutcomeV1::Accepted {
            let Some(_pending) = self.outbound.take() else {
                return Err(PointerHandoffError::new(
                    PointerHandoffErrorKind::StaleEffect,
                ));
            };
            self.fail_local();
            self.completed_outbound = Some(CompletedOutbound {
                session: session.clone(),
                ack,
            });
            return Ok(CoreAckOutcome::Rejected);
        }
        let commit = make_commit(pending.enter, pending.transition);
        let transition_id = pending.transition_id;
        let effect_session = pending.session.clone();
        let Some(pending) = self.outbound.as_mut() else {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        };
        pending.phase = OutboundPhase::CommitQueued;
        pending.accepted_ack = Some(ack);
        Ok(CoreAckOutcome::Commit(self.effect(
            &effect_session,
            transition_id,
            EffectPurpose::Commit,
            PointerControlMessage::Commit(commit),
        )))
    }

    fn receive_commit(
        &mut self,
        session: &B,
        commit: PointerTransitionCommitV1,
        now_ns: u64,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.prepare_operation(now_ns)?;
        self.require_available_session(session)?;
        if commit.transition_id == 0 || commit.transition_id != commit.sequence {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidSequence,
            ));
        }
        if let Some(completed) = &self.completed_inbound {
            if completed
                .commit
                .is_some_and(|previous| previous.transition_id == commit.transition_id)
            {
                return if completed.session == *session && completed.commit == Some(commit) {
                    Ok(PointerHandoffStatus::Duplicate)
                } else {
                    Err(PointerHandoffError::new(
                        PointerHandoffErrorKind::ConflictingReplay,
                    ))
                };
            }
        }
        let Some(PendingInbound::Prepared {
            session: prepared_session,
            commit: expected,
            ..
        }) = self.inbound.as_ref()
        else {
            return Err(Self::sequence_relation_error(
                commit.transition_id,
                self.last_inbound_sequence,
            ));
        };
        if prepared_session != session || commit != *expected {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::ConflictingReplay,
            ));
        }
        let Some(PendingInbound::Prepared {
            session,
            expected_leave,
            enter,
            ack,
            commit,
            transition,
            ..
        }) = self.inbound.take()
        else {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        };
        self.workspace_state
            .set_active_pointer(transition.destination_host, transition.destination_pointer);
        self.local_fallback = transition.destination_pointer;
        self.completed_inbound = Some(CompletedInbound {
            session,
            expected_leave: Some(expected_leave),
            enter,
            ack,
            commit: Some(commit),
        });
        Ok(PointerHandoffStatus::Applied)
    }

    // Consuming the affine effect prevents a successful completion from being
    // replayed by safe callers even though every field is read by reference.
    #[allow(clippy::needless_pass_by_value)]
    fn effect_sent(
        &mut self,
        effect: CoreEffect<B>,
        now_ns: u64,
    ) -> Result<CoreEffectCompletion<B>, PointerHandoffError> {
        self.prepare_operation(now_ns)?;
        self.validate_effect_owner(&effect)?;
        self.require_available_session(&effect.session)?;
        match effect.purpose {
            EffectPurpose::Leave => self.leave_effect_sent(&effect),
            EffectPurpose::Enter => self.enter_effect_sent(&effect),
            EffectPurpose::AcceptedAck => self.accepted_ack_sent(&effect),
            EffectPurpose::Commit => self.commit_effect_sent(&effect),
            EffectPurpose::DuplicateAcceptedAck | EffectPurpose::RejectedAck => {
                self.reply_effect_sent(&effect)
            }
        }
    }

    fn dispatch_effect<E>(
        &mut self,
        effect: CoreEffect<B>,
        now_ns: u64,
        dispatch: impl FnOnce(WireMessage, bool) -> Result<(), E>,
    ) -> Result<CoreEffectCompletion<B>, CoreDispatchError<E>> {
        self.validate_effect_ready(&effect, now_ns)
            .map_err(CoreDispatchError::Handoff)?;
        if effect.purpose == EffectPurpose::Commit {
            self.begin_commit_dispatch(&effect)
                .map_err(CoreDispatchError::Handoff)?;
        }
        if let Err(error) = dispatch(effect.wire_message(), self.has_local_authority()) {
            self.effect_failed(&effect)
                .map_err(CoreDispatchError::Handoff)?;
            return Err(CoreDispatchError::Outbound(error));
        }
        self.effect_sent(effect, now_ns)
            .map_err(CoreDispatchError::Handoff)
    }

    fn effect_failed(
        &mut self,
        effect: &CoreEffect<B>,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.validate_effect_owner(effect)?;
        if self.session.as_ref() != Some(&effect.session) {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        }
        match effect.purpose {
            EffectPurpose::Leave | EffectPurpose::Enter | EffectPurpose::Commit => {
                if !self.matches_outbound_effect(effect) {
                    return Err(PointerHandoffError::new(
                        PointerHandoffErrorKind::StaleEffect,
                    ));
                }
                self.outbound = None;
                self.fail_local();
                Ok(PointerHandoffStatus::Cleared)
            }
            EffectPurpose::AcceptedAck => {
                if !self.matches_inbound_ack_effect(effect) {
                    return Err(PointerHandoffError::new(
                        PointerHandoffErrorKind::StaleEffect,
                    ));
                }
                self.inbound = None;
                Ok(PointerHandoffStatus::Cleared)
            }
            EffectPurpose::DuplicateAcceptedAck | EffectPurpose::RejectedAck => {
                if !self.matches_reply_effect(effect) {
                    return Err(PointerHandoffError::new(
                        PointerHandoffErrorKind::StaleEffect,
                    ));
                }
                self.reply = None;
                Ok(PointerHandoffStatus::NoChange)
            }
        }
    }

    fn poll_timeout(&mut self, now_ns: u64) -> Result<PointerHandoffTimeouts, PointerHandoffError> {
        self.advance_clock(now_ns)?;
        Ok(self.expire(now_ns))
    }

    fn accept_enter_from_hint(
        &mut self,
        session: &B,
        message: PointerEnterV1,
    ) -> Result<CoreEffect<B>, PointerHandoffError> {
        let Some(PendingInbound::Hint {
            session: pending_session,
            deadline_ns,
            leave,
            expected_enter,
            transition,
        }) = self.inbound.take()
        else {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidTransition,
            ));
        };
        if pending_session != *session || expected_enter != message {
            self.inbound = Some(PendingInbound::Hint {
                session: pending_session,
                deadline_ns,
                leave,
                expected_enter,
                transition,
            });
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::ConflictingReplay,
            ));
        }
        Ok(self.accept_enter(session, message, transition, deadline_ns))
    }

    fn accept_enter(
        &mut self,
        session: &B,
        message: PointerEnterV1,
        transition: ResolvedTransition,
        deadline_ns: u64,
    ) -> CoreEffect<B> {
        let expected_leave = make_leave(
            message.transition_id,
            self.workspace.protocol_epoch(),
            transition,
        );
        let ack = make_ack(
            message,
            self.workspace_state.local_host,
            PointerTransitionOutcomeV1::Accepted,
        );
        self.last_inbound_sequence = message.transition_id;
        self.inbound = Some(PendingInbound::Proposal {
            session: session.clone(),
            deadline_ns,
            expected_leave,
            enter: message,
            ack,
            transition,
        });
        self.effect(
            session,
            message.transition_id,
            EffectPurpose::AcceptedAck,
            PointerControlMessage::Ack(ack),
        )
    }

    fn duplicate_leave(
        &self,
        session: &B,
        message: PointerLeaveV1,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        let matches_pending = self.inbound.as_ref().is_some_and(|pending| {
            pending_session(pending) == session && pending_leave(pending) == message
        });
        let matches_completed = self.completed_inbound.as_ref().is_some_and(|completed| {
            completed.session == *session && completed.expected_leave == Some(message)
        });
        let matches_expired = self
            .expired_inbound
            .as_ref()
            .is_some_and(|expired| expired.session == *session && expired.leave == message);
        if matches_pending || matches_completed || matches_expired {
            Ok(PointerHandoffStatus::Duplicate)
        } else {
            Err(PointerHandoffError::new(
                PointerHandoffErrorKind::ConflictingReplay,
            ))
        }
    }

    fn duplicate_enter(
        &mut self,
        session: &B,
        message: PointerEnterV1,
    ) -> Result<CoreEffect<B>, PointerHandoffError> {
        if let Some(expired) = &self.expired_inbound {
            if expired.session == *session && expired.enter == message {
                return Err(PointerHandoffError::new(
                    PointerHandoffErrorKind::StaleEffect,
                ));
            }
        }
        if let Some(PendingInbound::Proposal {
            session: pending_session,
            enter,
            ..
        }) = &self.inbound
        {
            if pending_session == session && *enter == message {
                return Err(PointerHandoffError::new(
                    PointerHandoffErrorKind::StaleEffect,
                ));
            }
        }
        if let Some(PendingInbound::Prepared {
            session: prepared_session,
            enter,
            ack,
            ..
        }) = &self.inbound
        {
            if prepared_session == session && *enter == message {
                let ack = *ack;
                let effect = self.effect(
                    session,
                    message.transition_id,
                    EffectPurpose::DuplicateAcceptedAck,
                    PointerControlMessage::Ack(ack),
                );
                self.reply = Some(PendingReply {
                    session: session.clone(),
                    transition_id: message.transition_id,
                    deadline_ns: self.deadline(self.last_now_ns)?,
                    purpose: EffectPurpose::DuplicateAcceptedAck,
                    enter: message,
                    message: PointerControlMessage::Ack(ack),
                });
                return Ok(effect);
            }
        }
        if let Some(completed) = &self.completed_inbound {
            if completed.session == *session && completed.enter == message {
                if self.reply.is_some() {
                    return Err(PointerHandoffError::new(
                        PointerHandoffErrorKind::PendingConflict,
                    ));
                }
                let effect = self.effect(
                    session,
                    message.transition_id,
                    EffectPurpose::DuplicateAcceptedAck,
                    PointerControlMessage::Ack(completed.ack),
                );
                self.reply = Some(PendingReply {
                    session: session.clone(),
                    transition_id: message.transition_id,
                    deadline_ns: self.deadline(self.last_now_ns)?,
                    purpose: EffectPurpose::DuplicateAcceptedAck,
                    enter: message,
                    message: PointerControlMessage::Ack(completed.ack),
                });
                return Ok(effect);
            }
        }
        Err(PointerHandoffError::new(
            PointerHandoffErrorKind::ConflictingReplay,
        ))
    }

    fn validate_leave_authority(
        &self,
        session: &B,
        message: PointerLeaveV1,
    ) -> Result<(), PointerHandoffError> {
        if message.workspace_epoch != self.workspace.protocol_epoch() {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidWorkspaceEpoch,
            ));
        }
        if message.source_host != wire_host(session.remote_host_id()) {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidHost,
            ));
        }
        let source_display = display_from_wire(message.source_display);
        let remote_is_authoritative = self.workspace_state.active_host == session.remote_host_id()
            && self.workspace_state.active_display == source_display;
        if !remote_is_authoritative && !self.has_local_authority() {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::NotAuthoritative,
            ));
        }
        Ok(())
    }

    fn validate_enter_authority(
        &self,
        session: &B,
        message: PointerEnterV1,
    ) -> Result<(), PointerHandoffErrorKind> {
        if message.workspace_epoch != self.workspace.protocol_epoch() {
            return Err(PointerHandoffErrorKind::InvalidWorkspaceEpoch);
        }
        if message.source_host != wire_host(session.remote_host_id())
            || message.destination_host != wire_host(self.workspace_state.local_host)
        {
            return Err(PointerHandoffErrorKind::InvalidHost);
        }
        let source_display = display_from_wire(message.source_display);
        let destination_display = display_from_wire(message.destination_display);
        if self.workspace.owner_of(source_display) != Some(session.remote_host_id())
            || self.workspace.owner_of(destination_display) != Some(self.workspace_state.local_host)
        {
            return Err(PointerHandoffErrorKind::InvalidDisplay);
        }
        let remote_is_authoritative = self.workspace_state.active_host == session.remote_host_id()
            && self.workspace_state.active_display == source_display;
        if !remote_is_authoritative && !self.has_local_authority() {
            return Err(PointerHandoffErrorKind::NotAuthoritative);
        }
        Ok(())
    }

    fn resolve_leave(
        &self,
        message: PointerLeaveV1,
    ) -> Result<ResolvedTransition, PointerHandoffError> {
        let transition = self
            .workspace
            .transition(
                display_from_wire(message.source_display),
                edge_from_wire(message.edge),
                message.normalized_position,
            )
            .map(ResolvedTransition::from)
            .map_err(|_| PointerHandoffError::new(PointerHandoffErrorKind::InvalidTransition))?;
        self.validate_resolved_destination(transition)?;
        Ok(transition)
    }

    fn resolve_enter(
        &self,
        message: PointerEnterV1,
    ) -> Result<ResolvedTransition, PointerHandoffError> {
        let mut matched = None;
        for edge in EDGES {
            let Ok(candidate) = self.workspace.transition(
                display_from_wire(message.source_display),
                edge,
                message.normalized_position,
            ) else {
                continue;
            };
            let candidate = ResolvedTransition::from(candidate);
            if wire_display(candidate.destination_display) == message.destination_display
                && edge_to_wire(candidate.destination_edge) == message.destination_edge
                && wire_host(candidate.destination_host) == message.destination_host
                && wire_host(candidate.source_host) == message.source_host
                && matched.replace(candidate).is_some()
            {
                return Err(PointerHandoffError::new(
                    PointerHandoffErrorKind::InvalidTransition,
                ));
            }
        }
        let transition = matched
            .ok_or_else(|| PointerHandoffError::new(PointerHandoffErrorKind::InvalidTransition))?;
        self.validate_resolved_destination(transition)?;
        Ok(transition)
    }

    fn validate_resolved_destination(
        &self,
        transition: ResolvedTransition,
    ) -> Result<(), PointerHandoffError> {
        let Some(session) = &self.session else {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::NoCurrentSession,
            ));
        };
        if transition.source_host != session.remote_host_id()
            || transition.destination_host != self.workspace_state.local_host
        {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::NotRemoteTransition,
            ));
        }
        Ok(())
    }

    fn rejection_effect(
        &mut self,
        session: &B,
        enter: PointerEnterV1,
        outcome: PointerTransitionOutcomeV1,
    ) -> Result<CoreEffect<B>, PointerHandoffError> {
        if self.reply.is_some() {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::PendingConflict,
            ));
        }
        let ack = make_ack(enter, self.workspace_state.local_host, outcome);
        let deadline_ns = match self.deadline(self.last_now_ns) {
            Ok(deadline) => deadline,
            Err(error) => {
                self.clear_transition_state();
                return Err(error);
            }
        };
        self.last_inbound_sequence = enter.transition_id;
        self.inbound = None;
        let effect = self.effect(
            session,
            enter.transition_id,
            EffectPurpose::RejectedAck,
            PointerControlMessage::Ack(ack),
        );
        self.reply = Some(PendingReply {
            session: session.clone(),
            transition_id: enter.transition_id,
            deadline_ns,
            purpose: EffectPurpose::RejectedAck,
            enter,
            message: PointerControlMessage::Ack(ack),
        });
        Ok(effect)
    }

    fn leave_effect_sent(
        &mut self,
        effect: &CoreEffect<B>,
    ) -> Result<CoreEffectCompletion<B>, PointerHandoffError> {
        let Some(pending) = self.outbound.as_mut() else {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        };
        if pending.session != effect.session
            || pending.transition_id != effect.transition_id
            || pending.phase != OutboundPhase::LeaveQueued
            || !matches!(effect.message, PointerControlMessage::Leave(message) if message == pending.leave)
        {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidEffect,
            ));
        }
        pending.phase = OutboundPhase::EnterQueued;
        let enter = pending.enter;
        let session = pending.session.clone();
        let transition_id = pending.transition_id;
        Ok(CoreEffectCompletion::Next(self.effect(
            &session,
            transition_id,
            EffectPurpose::Enter,
            PointerControlMessage::Enter(enter),
        )))
    }

    fn enter_effect_sent(
        &mut self,
        effect: &CoreEffect<B>,
    ) -> Result<CoreEffectCompletion<B>, PointerHandoffError> {
        let Some(pending) = self.outbound.as_mut() else {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        };
        if pending.session != effect.session
            || pending.transition_id != effect.transition_id
            || pending.phase != OutboundPhase::EnterQueued
            || !matches!(effect.message, PointerControlMessage::Enter(message) if message == pending.enter)
        {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidEffect,
            ));
        }
        pending.phase = OutboundPhase::AwaitingAck;
        Ok(CoreEffectCompletion::Sent)
    }

    fn accepted_ack_sent(
        &mut self,
        effect: &CoreEffect<B>,
    ) -> Result<CoreEffectCompletion<B>, PointerHandoffError> {
        let Some(PendingInbound::Proposal {
            session,
            deadline_ns,
            expected_leave,
            enter,
            ack,
            transition,
            ..
        }) = self.inbound.take()
        else {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        };
        if session != effect.session
            || enter.transition_id != effect.transition_id
            || !matches!(effect.message, PointerControlMessage::Ack(message) if message == ack)
        {
            self.inbound = Some(PendingInbound::Proposal {
                session,
                deadline_ns,
                expected_leave,
                enter,
                ack,
                transition,
            });
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidEffect,
            ));
        }
        let commit = make_commit(enter, transition);
        self.inbound = Some(PendingInbound::Prepared {
            session,
            deadline_ns,
            expected_leave,
            enter,
            ack,
            commit,
            transition,
        });
        Ok(CoreEffectCompletion::Sent)
    }

    fn commit_effect_sent(
        &mut self,
        effect: &CoreEffect<B>,
    ) -> Result<CoreEffectCompletion<B>, PointerHandoffError> {
        if !self.matches_outbound_effect(effect)
            || !self
                .outbound
                .as_ref()
                .is_some_and(|pending| pending.phase == OutboundPhase::CommitDispatching)
        {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        }
        let Some(pending) = self.outbound.take() else {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        };
        let Some(ack) = pending.accepted_ack else {
            self.fail_local();
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidEffect,
            ));
        };
        self.workspace_state.set_active_pointer(
            pending.transition.destination_host,
            pending.transition.destination_pointer,
        );
        self.completed_outbound = Some(CompletedOutbound {
            session: pending.session,
            ack,
        });
        Ok(CoreEffectCompletion::AuthorityCommitted)
    }

    fn begin_commit_dispatch(&mut self, effect: &CoreEffect<B>) -> Result<(), PointerHandoffError> {
        let Some(pending) = self.outbound.as_mut() else {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        };
        if pending.phase != OutboundPhase::CommitQueued
            || pending.session != effect.session
            || pending.transition_id != effect.transition_id
            || !matches!(effect.message, PointerControlMessage::Commit(message)
                if message == make_commit(pending.enter, pending.transition))
        {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        }
        pending.phase = OutboundPhase::CommitDispatching;
        Ok(())
    }

    fn reply_effect_sent(
        &mut self,
        effect: &CoreEffect<B>,
    ) -> Result<CoreEffectCompletion<B>, PointerHandoffError> {
        if !self.matches_reply_effect(effect) {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        }
        let Some(reply) = self.reply.take() else {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        };
        if reply.purpose == EffectPurpose::RejectedAck {
            let PointerControlMessage::Ack(ack) = reply.message else {
                return Err(PointerHandoffError::new(
                    PointerHandoffErrorKind::InvalidEffect,
                ));
            };
            let PointerControlMessage::Ack(_) = effect.message else {
                return Err(PointerHandoffError::new(
                    PointerHandoffErrorKind::InvalidEffect,
                ));
            };
            self.completed_inbound = Some(CompletedInbound {
                session: reply.session,
                expected_leave: None,
                enter: reply.enter,
                ack,
                commit: None,
            });
        }
        Ok(CoreEffectCompletion::Sent)
    }

    fn matches_outbound_effect(&self, effect: &CoreEffect<B>) -> bool {
        self.outbound.as_ref().is_some_and(|pending| {
            pending.session == effect.session
                && pending.transition_id == effect.transition_id
                && (matches!(
                    (pending.phase, effect.purpose, effect.message),
                    (
                        OutboundPhase::LeaveQueued,
                        EffectPurpose::Leave,
                        PointerControlMessage::Leave(message)
                    ) if message == pending.leave
                ) || matches!(
                    (pending.phase, effect.purpose, effect.message),
                    (
                        OutboundPhase::EnterQueued,
                        EffectPurpose::Enter,
                        PointerControlMessage::Enter(message)
                    ) if message == pending.enter
                ) || matches!(
                    (pending.phase, effect.purpose, effect.message),
                    (
                        OutboundPhase::CommitQueued | OutboundPhase::CommitDispatching,
                        EffectPurpose::Commit,
                        PointerControlMessage::Commit(message)
                    ) if message == make_commit(pending.enter, pending.transition)
                ))
        })
    }

    fn matches_inbound_ack_effect(&self, effect: &CoreEffect<B>) -> bool {
        self.inbound.as_ref().is_some_and(|pending| {
            matches!(pending, PendingInbound::Proposal { session, enter, ack, .. }
                if *session == effect.session
                    && enter.transition_id == effect.transition_id
                    && matches!(effect.message, PointerControlMessage::Ack(message) if message == *ack))
        })
    }

    fn matches_reply_effect(&self, effect: &CoreEffect<B>) -> bool {
        self.reply.as_ref().is_some_and(|reply| {
            reply.session == effect.session
                && reply.transition_id == effect.transition_id
                && reply.purpose == effect.purpose
                && matches!(
                    (reply.message, effect.message),
                    (PointerControlMessage::Ack(expected), PointerControlMessage::Ack(actual))
                        if expected == actual
                )
        })
    }

    fn effect(
        &self,
        session: &B,
        transition_id: u64,
        purpose: EffectPurpose,
        message: PointerControlMessage,
    ) -> CoreEffect<B> {
        CoreEffect {
            owner: Arc::clone(&self.owner),
            session: session.clone(),
            transition_id,
            purpose,
            message,
        }
    }

    fn validate_effect_owner(&self, effect: &CoreEffect<B>) -> Result<(), PointerHandoffError> {
        if Arc::ptr_eq(&self.owner, &effect.owner) {
            Ok(())
        } else {
            Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidEffect,
            ))
        }
    }

    fn validate_effect_ready(
        &mut self,
        effect: &CoreEffect<B>,
        now_ns: u64,
    ) -> Result<(), PointerHandoffError> {
        self.prepare_operation(now_ns)?;
        self.validate_effect_owner(effect)?;
        self.require_available_session(&effect.session)?;
        let matches = match effect.purpose {
            EffectPurpose::Leave | EffectPurpose::Enter => self.matches_outbound_effect(effect),
            EffectPurpose::AcceptedAck => self.matches_inbound_ack_effect(effect),
            EffectPurpose::Commit => {
                self.matches_outbound_effect(effect)
                    && self
                        .outbound
                        .as_ref()
                        .is_some_and(|pending| pending.phase == OutboundPhase::CommitQueued)
            }
            EffectPurpose::DuplicateAcceptedAck | EffectPurpose::RejectedAck => {
                self.matches_reply_effect(effect)
            }
        };
        if matches {
            Ok(())
        } else {
            Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ))
        }
    }

    fn classify_inbound_sequence(
        &mut self,
        transition_id: u64,
        sequence: u64,
    ) -> Result<InboundSequence, PointerHandoffError> {
        if transition_id == 0 || transition_id != sequence {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::InvalidSequence,
            ));
        }
        if transition_id == self.last_inbound_sequence {
            return Ok(InboundSequence::Duplicate);
        }
        let Some(expected) = self.last_inbound_sequence.checked_add(1) else {
            self.clear_transition_state();
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::SequenceExhausted,
            ));
        };
        match transition_id.cmp(&expected) {
            std::cmp::Ordering::Less => Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleSequence,
            )),
            std::cmp::Ordering::Greater => Err(PointerHandoffError::new(
                PointerHandoffErrorKind::FutureSequence,
            )),
            std::cmp::Ordering::Equal => Ok(InboundSequence::Next),
        }
    }

    fn next_outbound_sequence(&mut self) -> Result<u64, PointerHandoffError> {
        let Some(next) = self.last_outbound_sequence.checked_add(1) else {
            self.fail_local();
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::SequenceExhausted,
            ));
        };
        Ok(next)
    }

    fn sequence_relation_error(received: u64, current: u64) -> PointerHandoffError {
        let kind = if received == 0 {
            PointerHandoffErrorKind::InvalidSequence
        } else if received <= current {
            PointerHandoffErrorKind::StaleSequence
        } else {
            PointerHandoffErrorKind::FutureSequence
        };
        PointerHandoffError::new(kind)
    }

    fn require_available_session(&self, session: &B) -> Result<(), PointerHandoffError> {
        self.ensure_running()?;
        self.require_session(session)?;
        if self.session_healthy {
            Ok(())
        } else {
            Err(PointerHandoffError::new(
                PointerHandoffErrorKind::Unavailable,
            ))
        }
    }

    fn require_session(&self, session: &B) -> Result<(), PointerHandoffError> {
        match &self.session {
            None => Err(PointerHandoffError::new(
                PointerHandoffErrorKind::NoCurrentSession,
            )),
            Some(current) if current != session => Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleSession,
            )),
            Some(_) => Ok(()),
        }
    }

    fn ensure_running(&self) -> Result<(), PointerHandoffError> {
        if self.lifecycle == CoordinatorLifecycle::Running {
            Ok(())
        } else {
            Err(PointerHandoffError::new(
                PointerHandoffErrorKind::Unavailable,
            ))
        }
    }

    fn deadline(&self, now_ns: u64) -> Result<u64, PointerHandoffError> {
        let timeout_ns = u64::try_from(self.config.timeout.as_nanos())
            .map_err(|_| PointerHandoffError::new(PointerHandoffErrorKind::InvalidConfig))?;
        now_ns
            .checked_add(timeout_ns)
            .ok_or_else(|| PointerHandoffError::new(PointerHandoffErrorKind::ClockOverflow))
    }

    fn prepare_operation(&mut self, now_ns: u64) -> Result<(), PointerHandoffError> {
        self.advance_clock(now_ns)?;
        self.expire(now_ns);
        Ok(())
    }

    fn advance_clock(&mut self, now_ns: u64) -> Result<(), PointerHandoffError> {
        if now_ns < self.last_now_ns {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::ClockRegressed,
            ));
        }
        self.last_now_ns = now_ns;
        Ok(())
    }

    fn expire(&mut self, now_ns: u64) -> PointerHandoffTimeouts {
        let outbound = self
            .outbound
            .as_ref()
            .is_some_and(|pending| now_ns >= pending.deadline_ns);
        let inbound = self
            .inbound
            .as_ref()
            .is_some_and(|pending| now_ns >= pending.deadline_ns());
        let reply = self
            .reply
            .as_ref()
            .is_some_and(|pending| now_ns >= pending.deadline_ns);
        if outbound {
            self.outbound = None;
        }
        if inbound {
            if let Some(pending) = self.inbound.take() {
                let (session, leave, enter) = match pending {
                    PendingInbound::Hint {
                        session,
                        leave,
                        expected_enter,
                        ..
                    } => {
                        self.last_inbound_sequence = leave.transition_id;
                        (session, leave, expected_enter)
                    }
                    PendingInbound::Proposal {
                        session,
                        expected_leave,
                        enter,
                        ..
                    }
                    | PendingInbound::Prepared {
                        session,
                        expected_leave,
                        enter,
                        ..
                    } => (session, expected_leave, enter),
                };
                self.expired_inbound = Some(ExpiredInbound {
                    session,
                    leave,
                    enter,
                });
            }
        }
        if reply {
            self.reply = None;
        }
        if outbound {
            self.fail_local();
        }
        PointerHandoffTimeouts {
            outbound,
            inbound,
            reply,
        }
    }

    fn fail_local(&mut self) {
        self.workspace_state
            .set_active_pointer(self.workspace_state.local_host, self.local_fallback);
    }

    fn clear_transition_state(&mut self) {
        self.outbound = None;
        self.inbound = None;
        self.completed_outbound = None;
        self.completed_inbound = None;
        self.expired_inbound = None;
        self.reply = None;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InboundSequence {
    Duplicate,
    Next,
}

/// Coordinator bound to the daemon supervisor's exact admitted-session token.
pub struct PointerHandoffCoordinator {
    core: CoordinatorCore<PointerSessionBinding>,
}

impl fmt::Debug for PointerHandoffCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.core.fmt(formatter)
    }
}

impl PointerHandoffCoordinator {
    /// Creates a coordinator over one immutable compiled workspace.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent authority/display state or a non-local fallback.
    pub fn new(
        config: PointerHandoffConfig,
        workspace: ConfiguredWorkspace,
        workspace_state: WorkspaceState,
        local_fallback: LogicalPointer,
    ) -> Result<Self, PointerHandoffError> {
        CoordinatorCore::new(config, workspace, workspace_state, local_fallback)
            .map(|core| Self { core })
    }

    #[must_use]
    pub const fn workspace_state(&self) -> WorkspaceState {
        self.core.workspace_state()
    }

    #[must_use]
    pub fn workspace_epoch(&self) -> kvm_topology::WorkspaceEpoch {
        self.core.workspace.epoch()
    }

    #[must_use]
    pub(crate) fn protocol_epoch(&self) -> u64 {
        self.core.workspace.protocol_epoch()
    }

    #[must_use]
    pub fn has_local_authority(&self) -> bool {
        self.core.has_local_authority()
    }

    #[must_use]
    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.core.next_deadline_ns()
    }

    pub(crate) fn bind_session(
        &mut self,
        session: &CurrentAdmittedSession,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.core
            .bind_session(&PointerSessionBinding::from_current(session))
    }

    pub(crate) fn mark_session_healthy(
        &mut self,
        session: &CurrentAdmittedSession,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.core
            .mark_session_healthy(&PointerSessionBinding::from_current(session))
    }

    pub(crate) fn degrade_session(
        &mut self,
        session: &CurrentAdmittedSession,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.core
            .degrade_session(&PointerSessionBinding::from_current(session))
    }

    pub(crate) fn disconnect_session(
        &mut self,
        session: &CurrentAdmittedSession,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.core
            .disconnect_session(&PointerSessionBinding::from_current(session))
    }

    /// Replaces the immutable topology with a strictly newer epoch.
    ///
    /// # Errors
    ///
    /// Rejects stale epochs, invalid local fallback coordinates, and terminal
    /// coordinator lifecycle state without mutating the active workspace.
    pub fn replace_workspace(
        &mut self,
        workspace: ConfiguredWorkspace,
        local_fallback: LogicalPointer,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.core.replace_workspace(workspace, local_fallback)
    }

    pub fn revoke(&mut self) -> PointerHandoffStatus {
        self.core.revoke()
    }

    pub fn shutdown(&mut self) -> PointerHandoffStatus {
        self.core.shutdown()
    }

    pub(crate) fn propose_leave(
        &mut self,
        session: &CurrentAdmittedSession,
        source_edge: Edge,
        normalized_position: f64,
        now_ns: u64,
    ) -> Result<PointerHandoffEffect, PointerHandoffError> {
        self.core
            .propose_leave(
                &PointerSessionBinding::from_current(session),
                source_edge,
                normalized_position,
                now_ns,
            )
            .map(PointerHandoffEffect)
    }

    pub(crate) fn receive_leave(
        &mut self,
        session: &CurrentAdmittedSession,
        message: PointerLeaveV1,
        now_ns: u64,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.core.receive_leave(
            &PointerSessionBinding::from_current(session),
            message,
            now_ns,
        )
    }

    pub(crate) fn receive_enter(
        &mut self,
        session: &CurrentAdmittedSession,
        message: PointerEnterV1,
        now_ns: u64,
    ) -> Result<PointerHandoffEffect, PointerHandoffError> {
        self.core
            .receive_enter(
                &PointerSessionBinding::from_current(session),
                message,
                now_ns,
            )
            .map(PointerHandoffEffect)
    }

    pub(crate) fn receive_ack(
        &mut self,
        session: &CurrentAdmittedSession,
        ack: PointerTransitionAckV1,
        now_ns: u64,
    ) -> Result<PointerAckOutcome, PointerHandoffError> {
        self.core
            .receive_ack(&PointerSessionBinding::from_current(session), ack, now_ns)
            .map(|outcome| match outcome {
                CoreAckOutcome::Duplicate => PointerAckOutcome::Duplicate,
                CoreAckOutcome::Rejected => PointerAckOutcome::Rejected,
                CoreAckOutcome::Commit(effect) => {
                    PointerAckOutcome::Commit(Box::new(PointerHandoffEffect(effect)))
                }
            })
    }

    pub(crate) fn receive_commit(
        &mut self,
        session: &CurrentAdmittedSession,
        commit: PointerTransitionCommitV1,
        now_ns: u64,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        self.core.receive_commit(
            &PointerSessionBinding::from_current(session),
            commit,
            now_ns,
        )
    }

    pub(crate) fn effect_sent(
        &mut self,
        session: &CurrentAdmittedSession,
        effect: PointerHandoffEffect,
        now_ns: u64,
    ) -> Result<PointerEffectCompletion, PointerHandoffError> {
        let binding = PointerSessionBinding::from_current(session);
        if effect.0.session != binding || self.core.session.as_ref() != Some(&binding) {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        }
        self.core
            .effect_sent(effect.0, now_ns)
            .map(|completion| match completion {
                CoreEffectCompletion::Sent => PointerEffectCompletion::Sent,
                CoreEffectCompletion::AuthorityCommitted => {
                    PointerEffectCompletion::AuthorityCommitted
                }
                CoreEffectCompletion::Next(effect) => {
                    PointerEffectCompletion::Next(Box::new(PointerHandoffEffect(effect)))
                }
            })
    }

    // This consumes the non-Clone effect capability even though reconciliation
    // only needs to inspect it.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn effect_failed(
        &mut self,
        session: &CurrentAdmittedSession,
        effect: PointerHandoffEffect,
    ) -> Result<PointerHandoffStatus, PointerHandoffError> {
        let binding = PointerSessionBinding::from_current(session);
        if effect.0.session != binding || self.core.session.as_ref() != Some(&binding) {
            return Err(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            ));
        }
        self.core.effect_failed(&effect.0)
    }

    pub(crate) fn dispatch_effect<E>(
        &mut self,
        session: &CurrentAdmittedSession,
        effect: PointerHandoffEffect,
        now_ns: u64,
        dispatch: impl FnOnce(WireMessage) -> Result<(), E>,
    ) -> Result<PointerEffectCompletion, PointerDispatchError<E>> {
        let binding = PointerSessionBinding::from_current(session);
        if effect.0.session != binding || self.core.session.as_ref() != Some(&binding) {
            return Err(PointerDispatchError::Handoff(PointerHandoffError::new(
                PointerHandoffErrorKind::StaleEffect,
            )));
        }
        self.core
            .dispatch_effect(effect.0, now_ns, |message, _has_local_authority| {
                dispatch(message)
            })
            .map(|completion| match completion {
                CoreEffectCompletion::Sent => PointerEffectCompletion::Sent,
                CoreEffectCompletion::AuthorityCommitted => {
                    PointerEffectCompletion::AuthorityCommitted
                }
                CoreEffectCompletion::Next(effect) => {
                    PointerEffectCompletion::Next(Box::new(PointerHandoffEffect(effect)))
                }
            })
            .map_err(|error| match error {
                CoreDispatchError::Handoff(error) => PointerDispatchError::Handoff(error),
                CoreDispatchError::Outbound(error) => PointerDispatchError::Outbound(error),
            })
    }

    /// Expires bounded in-flight phases at the supplied monotonic timestamp.
    ///
    /// # Errors
    ///
    /// Returns a coarse error for clock rollback/overflow, sequence exhaustion,
    /// or terminal coordinator lifecycle state.
    pub fn poll_timeout(
        &mut self,
        now_ns: u64,
    ) -> Result<PointerHandoffTimeouts, PointerHandoffError> {
        self.core.poll_timeout(now_ns)
    }
}

fn validate_state(
    workspace: &ConfiguredWorkspace,
    state: WorkspaceState,
    local_fallback: LogicalPointer,
) -> Result<(), PointerHandoffError> {
    if state.pointer.display_id != state.active_display
        || !state.pointer.x.is_finite()
        || !state.pointer.y.is_finite()
        || workspace.owner_of(state.active_display) != Some(state.active_host)
        || !workspace.contains_local_point(
            state.active_display,
            Point::new(state.pointer.x, state.pointer.y),
        )
    {
        return Err(PointerHandoffError::new(
            PointerHandoffErrorKind::InvalidWorkspaceState,
        ));
    }
    validate_local_fallback(state.local_host, workspace, local_fallback)
}

fn validate_local_fallback(
    local_host: HostId,
    workspace: &ConfiguredWorkspace,
    fallback: LogicalPointer,
) -> Result<(), PointerHandoffError> {
    if local_host.into_bytes() == [0; 16]
        || !fallback.x.is_finite()
        || !fallback.y.is_finite()
        || workspace.owner_of(fallback.display_id) != Some(local_host)
        || !workspace.contains_local_point(fallback.display_id, Point::new(fallback.x, fallback.y))
    {
        Err(PointerHandoffError::new(
            PointerHandoffErrorKind::InvalidWorkspaceState,
        ))
    } else {
        Ok(())
    }
}

fn pending_session<B>(pending: &PendingInbound<B>) -> &B {
    match pending {
        PendingInbound::Hint { session, .. }
        | PendingInbound::Proposal { session, .. }
        | PendingInbound::Prepared { session, .. } => session,
    }
}

fn pending_leave<B>(pending: &PendingInbound<B>) -> PointerLeaveV1 {
    match pending {
        PendingInbound::Hint { leave, .. } => *leave,
        PendingInbound::Proposal { expected_leave, .. }
        | PendingInbound::Prepared { expected_leave, .. } => *expected_leave,
    }
}

fn make_leave(
    transition_id: u64,
    workspace_epoch: u64,
    transition: ResolvedTransition,
) -> PointerLeaveV1 {
    PointerLeaveV1 {
        transition_id,
        workspace_epoch,
        sequence: transition_id,
        source_host: wire_host(transition.source_host),
        source_display: wire_display(transition.source_display),
        edge: edge_to_wire(transition.source_edge),
        normalized_position: transition.normalized_position,
    }
}

fn make_enter(
    transition_id: u64,
    workspace_epoch: u64,
    transition: ResolvedTransition,
) -> PointerEnterV1 {
    PointerEnterV1 {
        transition_id,
        workspace_epoch,
        sequence: transition_id,
        source_host: wire_host(transition.source_host),
        destination_host: wire_host(transition.destination_host),
        source_display: wire_display(transition.source_display),
        destination_display: wire_display(transition.destination_display),
        destination_edge: edge_to_wire(transition.destination_edge),
        normalized_position: transition.normalized_position,
    }
}

fn make_ack(
    enter: PointerEnterV1,
    receiver_host: HostId,
    outcome: PointerTransitionOutcomeV1,
) -> PointerTransitionAckV1 {
    PointerTransitionAckV1 {
        transition_id: enter.transition_id,
        workspace_epoch: enter.workspace_epoch,
        receiver_host: wire_host(receiver_host),
        active_display: enter.destination_display,
        outcome,
    }
}

fn make_commit(enter: PointerEnterV1, transition: ResolvedTransition) -> PointerTransitionCommitV1 {
    PointerTransitionCommitV1 {
        transition_id: enter.transition_id,
        workspace_epoch: enter.workspace_epoch,
        sequence: enter.transition_id,
        source_host: wire_host(transition.source_host),
        destination_host: wire_host(transition.destination_host),
        source_display: wire_display(transition.source_display),
        destination_display: wire_display(transition.destination_display),
    }
}

const fn wire_host(host: HostId) -> WireHostId {
    WireHostId(host.into_bytes())
}

const fn display_from_wire(display: kvm_protocol::WireDisplayId) -> DisplayId {
    DisplayId::from_bytes(display.0)
}

const fn wire_display(display: DisplayId) -> kvm_protocol::WireDisplayId {
    kvm_protocol::WireDisplayId(display.into_bytes())
}

const fn edge_to_wire(edge: Edge) -> WireEdge {
    match edge {
        Edge::Left => WireEdge::Left,
        Edge::Right => WireEdge::Right,
        Edge::Top => WireEdge::Top,
        Edge::Bottom => WireEdge::Bottom,
    }
}

const fn edge_from_wire(edge: WireEdge) -> Edge {
    match edge {
        WireEdge::Left => Edge::Left,
        WireEdge::Right => Edge::Right,
        WireEdge::Top => Edge::Top,
        WireEdge::Bottom => Edge::Bottom,
    }
}

#[cfg(test)]
mod tests {
    use kvm_topology::{ConfiguredWorkspaceCompiler, WorkspaceLink, WorkspacePlacement};
    use kvm_types::{Display, Point, Rect, Size};

    use super::*;

    const HOST_A: HostId = HostId::from_bytes([0x11; 16]);
    const HOST_B: HostId = HostId::from_bytes([0x22; 16]);
    const DISPLAY_A: DisplayId = DisplayId::from_bytes([0x33; 16]);
    const DISPLAY_B: DisplayId = DisplayId::from_bytes([0x44; 16]);

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestSession {
        instance: u64,
        local: HostId,
        remote: HostId,
    }

    impl SessionBinding for TestSession {
        fn local_host_id(&self) -> HostId {
            self.local
        }

        fn remote_host_id(&self) -> HostId {
            self.remote
        }
    }

    struct Pair {
        a: CoordinatorCore<TestSession>,
        b: CoordinatorCore<TestSession>,
        session_a: TestSession,
        session_b: TestSession,
    }

    fn display(id: DisplayId, host_id: HostId, width: f64, height: f64) -> Display {
        Display {
            id,
            host_id,
            name: "diagnostic-marker-display-name".into(),
            logical_size: Size::new(width, height),
            physical_size: None,
            scale_factor: 1.0,
            refresh_rate: None,
            native_bounds: Rect::new(0.0, 0.0, width, height),
            primary: true,
        }
    }

    fn workspace(compiler: &mut ConfiguredWorkspaceCompiler) -> ConfiguredWorkspace {
        compiler
            .compile_candidate(
                [
                    display(DISPLAY_A, HOST_A, 100.0, 100.0),
                    display(DISPLAY_B, HOST_B, 100.0, 200.0),
                ],
                [
                    WorkspacePlacement::new(DISPLAY_A, Point::new(0.0, 0.0)),
                    WorkspacePlacement::new(DISPLAY_B, Point::new(100.0, 0.0)),
                ],
                [
                    WorkspaceLink::new(DISPLAY_A, Edge::Right, DISPLAY_B, Edge::Left),
                    WorkspaceLink::new(DISPLAY_B, Edge::Left, DISPLAY_A, Edge::Right),
                ],
            )
            .unwrap()
    }

    fn pair() -> Pair {
        let mut compiler = ConfiguredWorkspaceCompiler::new();
        let workspace = workspace(&mut compiler);
        pair_with_workspaces(workspace.clone(), workspace)
    }

    fn pair_with_workspaces(
        workspace_a: ConfiguredWorkspace,
        workspace_b: ConfiguredWorkspace,
    ) -> Pair {
        let config = PointerHandoffConfig::new(Duration::from_nanos(100)).unwrap();
        let state_a =
            WorkspaceState::new(HOST_A, HOST_A, LogicalPointer::new(DISPLAY_A, 99.0, 37.5));
        let state_b =
            WorkspaceState::new(HOST_B, HOST_A, LogicalPointer::new(DISPLAY_A, 99.0, 37.5));
        let mut a = CoordinatorCore::new(
            config,
            workspace_a,
            state_a,
            LogicalPointer::new(DISPLAY_A, 50.0, 50.0),
        )
        .unwrap();
        let mut b = CoordinatorCore::new(
            config,
            workspace_b,
            state_b,
            LogicalPointer::new(DISPLAY_B, 0.0, 75.0),
        )
        .unwrap();
        let session_a = TestSession {
            instance: 1,
            local: HOST_A,
            remote: HOST_B,
        };
        let session_b = TestSession {
            instance: 1,
            local: HOST_B,
            remote: HOST_A,
        };
        a.bind_session(&session_a).unwrap();
        b.bind_session(&session_b).unwrap();
        Pair {
            a,
            b,
            session_a,
            session_b,
        }
    }

    #[test]
    fn equivalent_workspaces_handoff_across_divergent_local_compile_epochs() {
        let mut compiler_a = ConfiguredWorkspaceCompiler::new();
        let workspace_a = workspace(&mut compiler_a);
        let mut compiler_b = ConfiguredWorkspaceCompiler::new();
        let _ = workspace(&mut compiler_b);
        let workspace_b = workspace(&mut compiler_b);
        assert_ne!(workspace_a.epoch(), workspace_b.epoch());
        assert_eq!(workspace_a.protocol_epoch(), workspace_b.protocol_epoch());
        let mut pair = pair_with_workspaces(workspace_a, workspace_b);

        handoff_a_to_b(&mut pair, 1);

        assert_eq!(pair.a.workspace_state.active_host, HOST_B);
        assert_eq!(pair.b.workspace_state.active_host, HOST_B);
    }

    #[test]
    fn first_authenticated_handoff_converges_dual_local_startup_authority() {
        let mut pair = pair();
        pair.b
            .workspace_state
            .set_active_pointer(HOST_B, LogicalPointer::new(DISPLAY_B, 0.0, 75.0));
        assert!(pair.a.has_local_authority());
        assert!(pair.b.has_local_authority());

        handoff_a_to_b(&mut pair, 1);

        assert_eq!(pair.a.workspace_state.active_host, HOST_B);
        assert_eq!(pair.b.workspace_state.active_host, HOST_B);
        assert!(!pair.a.has_local_authority());
        assert!(pair.b.has_local_authority());
    }

    fn leave_message<B>(effect: &CoreEffect<B>) -> PointerLeaveV1 {
        match effect.message {
            PointerControlMessage::Leave(message) => message,
            PointerControlMessage::Enter(_)
            | PointerControlMessage::Ack(_)
            | PointerControlMessage::Commit(_) => {
                panic!("expected leave effect")
            }
        }
    }

    fn enter_message<B>(effect: &CoreEffect<B>) -> PointerEnterV1 {
        match effect.message {
            PointerControlMessage::Enter(message) => message,
            PointerControlMessage::Leave(_)
            | PointerControlMessage::Ack(_)
            | PointerControlMessage::Commit(_) => {
                panic!("expected enter effect")
            }
        }
    }

    fn ack_message<B>(effect: &CoreEffect<B>) -> PointerTransitionAckV1 {
        match effect.message {
            PointerControlMessage::Ack(message) => message,
            PointerControlMessage::Leave(_)
            | PointerControlMessage::Enter(_)
            | PointerControlMessage::Commit(_) => {
                panic!("expected acknowledgement effect")
            }
        }
    }

    fn commit_message<B>(effect: &CoreEffect<B>) -> PointerTransitionCommitV1 {
        match effect.message {
            PointerControlMessage::Commit(message) => message,
            PointerControlMessage::Leave(_)
            | PointerControlMessage::Enter(_)
            | PointerControlMessage::Ack(_) => panic!("expected commit effect"),
        }
    }

    fn commit_effect<B>(outcome: CoreAckOutcome<B>) -> CoreEffect<B> {
        match outcome {
            CoreAckOutcome::Commit(effect) => effect,
            CoreAckOutcome::Duplicate | CoreAckOutcome::Rejected => {
                panic!("expected commit effect")
            }
        }
    }

    fn next_effect<B>(completion: CoreEffectCompletion<B>) -> CoreEffect<B> {
        match completion {
            CoreEffectCompletion::Next(effect) => effect,
            CoreEffectCompletion::Sent | CoreEffectCompletion::AuthorityCommitted => {
                panic!("expected next effect")
            }
        }
    }

    fn handoff_a_to_b(pair: &mut Pair, now_ns: u64) -> PointerTransitionAckV1 {
        let leave_effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.375, now_ns)
            .unwrap();
        let leave = leave_message(&leave_effect);
        assert_eq!(
            pair.b
                .receive_leave(&pair.session_b, leave, now_ns)
                .unwrap(),
            PointerHandoffStatus::Applied
        );
        let enter_effect = next_effect(pair.a.effect_sent(leave_effect, now_ns).unwrap());
        let enter = enter_message(&enter_effect);
        let ack_effect = pair
            .b
            .receive_enter(&pair.session_b, enter, now_ns)
            .unwrap();
        assert!(matches!(
            pair.a.effect_sent(enter_effect, now_ns).unwrap(),
            CoreEffectCompletion::Sent
        ));
        let ack = ack_message(&ack_effect);
        assert!(matches!(
            pair.b.effect_sent(ack_effect, now_ns).unwrap(),
            CoreEffectCompletion::Sent
        ));
        let commit_effect =
            commit_effect(pair.a.receive_ack(&pair.session_a, ack, now_ns).unwrap());
        let commit = commit_message(&commit_effect);
        assert!(matches!(
            pair.a
                .dispatch_effect(commit_effect, now_ns, |_message, local| {
                    assert!(!local);
                    Ok::<(), ()>(())
                })
                .unwrap(),
            CoreEffectCompletion::AuthorityCommitted
        ));
        assert_eq!(
            pair.b
                .receive_commit(&pair.session_b, commit, now_ns)
                .unwrap(),
            PointerHandoffStatus::Applied
        );
        ack
    }

    fn proposed_enter(pair: &mut Pair, now_ns: u64) -> PointerEnterV1 {
        let leave = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.5, now_ns)
            .unwrap();
        let enter = next_effect(pair.a.effect_sent(leave, now_ns).unwrap());
        enter_message(&enter)
    }

    #[test]
    fn two_hosts_commit_only_after_exact_accepted_ack_in_both_directions() {
        let mut pair = self::pair();
        let leave_effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.375, 10)
            .unwrap();
        assert!(pair.a.has_local_authority());
        let leave = leave_message(&leave_effect);
        pair.b.receive_leave(&pair.session_b, leave, 10).unwrap();
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
        let enter_effect = next_effect(pair.a.effect_sent(leave_effect, 10).unwrap());
        let enter = enter_message(&enter_effect);
        let ack_effect = pair.b.receive_enter(&pair.session_b, enter, 10).unwrap();
        assert!(pair.a.has_local_authority());
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
        assert!(matches!(
            pair.a.effect_sent(enter_effect, 10).unwrap(),
            CoreEffectCompletion::Sent
        ));
        let ack = ack_message(&ack_effect);
        assert!(matches!(
            pair.b.effect_sent(ack_effect, 10).unwrap(),
            CoreEffectCompletion::Sent
        ));
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
        let commit_to_b = commit_effect(pair.a.receive_ack(&pair.session_a, ack, 10).unwrap());
        let commit = commit_message(&commit_to_b);
        assert!(pair.a.has_local_authority());
        assert!(matches!(
            pair.a
                .dispatch_effect(commit_to_b, 10, |_message, local| {
                    assert!(!local);
                    Ok::<(), ()>(())
                })
                .unwrap(),
            CoreEffectCompletion::AuthorityCommitted
        ));
        pair.b.receive_commit(&pair.session_b, commit, 10).unwrap();

        for coordinator in [&pair.a, &pair.b] {
            assert_eq!(coordinator.workspace_state.active_host, HOST_B);
            assert_eq!(coordinator.workspace_state.active_display, DISPLAY_B);
            assert!(coordinator.workspace_state.pointer.x.abs() < f64::EPSILON);
            assert!((coordinator.workspace_state.pointer.y - 75.0).abs() < f64::EPSILON);
        }

        let leave_effect = pair
            .b
            .propose_leave(&pair.session_b, Edge::Left, 0.375, 20)
            .unwrap();
        let leave = leave_message(&leave_effect);
        pair.a.receive_leave(&pair.session_a, leave, 20).unwrap();
        let enter_effect = next_effect(pair.b.effect_sent(leave_effect, 20).unwrap());
        let enter = enter_message(&enter_effect);
        let ack_effect = pair.a.receive_enter(&pair.session_a, enter, 20).unwrap();
        assert!(matches!(
            pair.b.effect_sent(enter_effect, 20).unwrap(),
            CoreEffectCompletion::Sent
        ));
        let ack = ack_message(&ack_effect);
        assert!(matches!(
            pair.a.effect_sent(ack_effect, 20).unwrap(),
            CoreEffectCompletion::Sent
        ));
        let commit_to_a = commit_effect(pair.b.receive_ack(&pair.session_b, ack, 20).unwrap());
        let commit = commit_message(&commit_to_a);
        assert!(matches!(
            pair.b
                .dispatch_effect(commit_to_a, 20, |_message, local| {
                    assert!(!local);
                    Ok::<(), ()>(())
                })
                .unwrap(),
            CoreEffectCompletion::AuthorityCommitted
        ));
        pair.a.receive_commit(&pair.session_a, commit, 20).unwrap();

        for coordinator in [&pair.a, &pair.b] {
            assert_eq!(coordinator.workspace_state.active_host, HOST_A);
            assert_eq!(coordinator.workspace_state.active_display, DISPLAY_A);
            assert!((coordinator.workspace_state.pointer.x - 100.0).abs() < f64::EPSILON);
            assert!((coordinator.workspace_state.pointer.y - 37.5).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn leave_is_only_a_hint_and_exact_duplicates_are_idempotent() {
        let mut pair = self::pair();
        let leave_effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.25, 5)
            .unwrap();
        let leave = leave_message(&leave_effect);
        pair.b.receive_leave(&pair.session_b, leave, 5).unwrap();
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
        assert_eq!(
            pair.b.receive_leave(&pair.session_b, leave, 5).unwrap(),
            PointerHandoffStatus::Duplicate
        );
        let enter_effect = next_effect(pair.a.effect_sent(leave_effect, 5).unwrap());
        let enter = enter_message(&enter_effect);
        let ack_effect = pair.b.receive_enter(&pair.session_b, enter, 5).unwrap();
        assert!(matches!(
            pair.a.effect_sent(enter_effect, 5).unwrap(),
            CoreEffectCompletion::Sent
        ));
        let ack = ack_message(&ack_effect);
        assert!(matches!(
            pair.b.effect_sent(ack_effect, 5).unwrap(),
            CoreEffectCompletion::Sent
        ));
        let commit_effect = commit_effect(pair.a.receive_ack(&pair.session_a, ack, 5).unwrap());
        let commit = commit_message(&commit_effect);
        pair.a
            .dispatch_effect(commit_effect, 5, |_message, _local| Ok::<(), ()>(()))
            .unwrap();
        pair.b.receive_commit(&pair.session_b, commit, 5).unwrap();

        let duplicate_ack = pair.b.receive_enter(&pair.session_b, enter, 6).unwrap();
        assert_eq!(ack_message(&duplicate_ack), ack);
        assert!(matches!(
            pair.b.effect_sent(duplicate_ack, 6).unwrap(),
            CoreEffectCompletion::Sent
        ));
        assert!(matches!(
            pair.a.receive_ack(&pair.session_a, ack, 6).unwrap(),
            CoreAckOutcome::Duplicate
        ));
        assert_eq!(
            pair.b.receive_leave(&pair.session_b, leave, 6).unwrap(),
            PointerHandoffStatus::Duplicate
        );
    }

    #[test]
    fn simultaneous_proposals_are_rejected_without_split_authority() {
        let mut pair = self::pair();
        pair.b
            .workspace_state
            .set_active_pointer(HOST_B, LogicalPointer::new(DISPLAY_B, 0.0, 50.0));
        let leave_a = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.25, 1)
            .unwrap();
        let leave_b = pair
            .b
            .propose_leave(&pair.session_b, Edge::Left, 0.25, 1)
            .unwrap();
        let enter_a = next_effect(pair.a.effect_sent(leave_a, 1).unwrap());
        let enter_b = next_effect(pair.b.effect_sent(leave_b, 1).unwrap());
        let reject_at_b = pair
            .b
            .receive_enter(&pair.session_b, enter_message(&enter_a), 1)
            .unwrap();
        let reject_at_a = pair
            .a
            .receive_enter(&pair.session_a, enter_message(&enter_b), 1)
            .unwrap();
        assert_eq!(
            ack_message(&reject_at_a).outcome,
            PointerTransitionOutcomeV1::Rejected
        );
        assert_eq!(
            ack_message(&reject_at_b).outcome,
            PointerTransitionOutcomeV1::Rejected
        );
        pair.a.effect_sent(enter_a, 1).unwrap();
        pair.b.effect_sent(enter_b, 1).unwrap();
        let ack_at_a = ack_message(&reject_at_a);
        let ack_at_b = ack_message(&reject_at_b);
        pair.a.effect_sent(reject_at_a, 1).unwrap();
        pair.b.effect_sent(reject_at_b, 1).unwrap();
        pair.a.receive_ack(&pair.session_a, ack_at_b, 1).unwrap();
        pair.b.receive_ack(&pair.session_b, ack_at_a, 1).unwrap();
        assert!(pair.a.has_local_authority());
        assert!(pair.b.has_local_authority());
    }

    #[test]
    fn wrong_epoch_host_display_and_future_sequence_cannot_activate() {
        let mut pair = self::pair();
        let valid = proposed_enter(&mut pair, 1);

        let mut wrong_epoch = valid;
        wrong_epoch.workspace_epoch += 1;
        let rejection = pair
            .b
            .receive_enter(&pair.session_b, wrong_epoch, 1)
            .unwrap();
        assert_eq!(
            ack_message(&rejection).outcome,
            PointerTransitionOutcomeV1::StaleWorkspaceEpoch
        );
        pair.b.effect_sent(rejection, 1).unwrap();

        let mut pair = self::pair();
        let valid = proposed_enter(&mut pair, 1);
        let mut wrong_host = valid;
        wrong_host.destination_host = wire_host(HOST_A);
        let rejection = pair
            .b
            .receive_enter(&pair.session_b, wrong_host, 1)
            .unwrap();
        assert_eq!(
            ack_message(&rejection).outcome,
            PointerTransitionOutcomeV1::NotAuthoritative
        );
        pair.b.effect_sent(rejection, 1).unwrap();

        let mut pair = self::pair();
        let valid = proposed_enter(&mut pair, 1);
        let mut wrong_display = valid;
        wrong_display.destination_display = wire_display(DISPLAY_A);
        let rejection = pair
            .b
            .receive_enter(&pair.session_b, wrong_display, 1)
            .unwrap();
        assert_eq!(
            ack_message(&rejection).outcome,
            PointerTransitionOutcomeV1::UnknownDisplay
        );
        pair.b.effect_sent(rejection, 1).unwrap();

        let mut pair = self::pair();
        let valid = proposed_enter(&mut pair, 1);
        let mut future = valid;
        future.transition_id = 2;
        future.sequence = 2;
        assert_eq!(
            pair.b
                .receive_enter(&pair.session_b, future, 1)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::FutureSequence
        );
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
    }

    #[test]
    fn old_session_replay_and_cross_coordinator_effect_are_rejected() {
        let mut pair = pair();
        let old_session = pair.session_a.clone();
        let old_effect = pair
            .a
            .propose_leave(&old_session, Edge::Right, 0.5, 1)
            .unwrap();
        let mut other = self::pair();
        assert_eq!(
            other.a.effect_failed(&old_effect).unwrap_err().kind(),
            PointerHandoffErrorKind::InvalidEffect
        );

        pair.a.degrade_session(&old_session).unwrap();
        let replacement = TestSession {
            instance: 2,
            ..old_session.clone()
        };
        pair.a.bind_session(&replacement).unwrap();
        assert_eq!(
            pair.a
                .propose_leave(&old_session, Edge::Right, 0.5, 2)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::StaleSession
        );
    }

    #[test]
    fn timeout_send_failure_degradation_and_disconnect_restore_local_authority() {
        let mut pair = pair();
        let effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.5, 1)
            .unwrap();
        assert_eq!(
            pair.a.effect_failed(&effect).unwrap(),
            PointerHandoffStatus::Cleared
        );
        assert!(pair.a.has_local_authority());

        let effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.5, 2)
            .unwrap();
        assert!(matches!(
            pair.a.effect_sent(effect, 2).unwrap(),
            CoreEffectCompletion::Next(_)
        ));
        assert_eq!(
            pair.a.poll_timeout(102).unwrap(),
            PointerHandoffTimeouts {
                outbound: true,
                inbound: false,
                reply: false,
            }
        );
        assert!(pair.a.has_local_authority());

        let effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.5, 103)
            .unwrap();
        pair.a.degrade_session(&pair.session_a).unwrap();
        assert!(pair.a.has_local_authority());
        assert_eq!(
            pair.a
                .propose_leave(&pair.session_a, Edge::Right, 0.5, 104)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::Unavailable
        );
        assert_eq!(
            pair.a.effect_failed(&effect).unwrap_err().kind(),
            PointerHandoffErrorKind::StaleEffect
        );
        pair.a.mark_session_healthy(&pair.session_a).unwrap();
        let effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.5, 105)
            .unwrap();
        pair.a.effect_failed(&effect).unwrap();
        pair.a.disconnect_session(&pair.session_a).unwrap();
        assert!(pair.a.has_local_authority());
        assert_eq!(
            pair.a
                .propose_leave(&pair.session_a, Edge::Right, 0.5, 106)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::NoCurrentSession
        );
    }

    #[test]
    fn reconfiguration_and_exhaustion_fail_closed_without_reusing_ids() {
        let mut pair = pair();
        handoff_a_to_b(&mut pair, 1);
        let mut compiler = ConfiguredWorkspaceCompiler::new();
        let _epoch_one = workspace(&mut compiler);
        let replacement = workspace(&mut compiler);
        pair.a
            .replace_workspace(replacement, LogicalPointer::new(DISPLAY_A, 50.0, 50.0))
            .unwrap();
        assert!(pair.a.has_local_authority());

        pair.a.last_outbound_sequence = u64::MAX;
        assert_eq!(
            pair.a
                .propose_leave(&pair.session_a, Edge::Right, 0.5, 2)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::SequenceExhausted
        );
        assert!(pair.a.has_local_authority());
    }

    #[test]
    fn conflicting_ack_clears_pending_and_diagnostics_are_redacted() {
        let mut pair = pair();
        let leave = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.375, 1)
            .unwrap();
        let enter = next_effect(pair.a.effect_sent(leave, 1).unwrap());
        let message = enter_message(&enter);
        pair.a.effect_sent(enter, 1).unwrap();
        let mut ack = make_ack(message, HOST_B, PointerTransitionOutcomeV1::Accepted);
        ack.active_display = wire_display(DISPLAY_A);
        assert_eq!(
            pair.a
                .receive_ack(&pair.session_a, ack, 1)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::ConflictingReplay
        );
        assert!(pair.a.has_local_authority());

        let rendered = format!(
            "{:?} {:?} {:?}",
            pair.a,
            PointerHandoffError::new(PointerHandoffErrorKind::InvalidTransition),
            pair.a.workspace
        );
        for marker in [
            "diagnostic-marker-display-name",
            &DISPLAY_A.to_string(),
            &HOST_A.to_string(),
            "0.375",
        ] {
            assert!(!rendered.contains(marker));
        }
        assert!(rendered.len() < 512);
    }

    #[test]
    fn timeout_config_and_monotonic_clock_are_bounded() {
        assert_eq!(
            PointerHandoffConfig::new(Duration::ZERO)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::InvalidConfig
        );
        assert_eq!(
            PointerHandoffConfig::new(MAX_POINTER_HANDOFF_TIMEOUT + Duration::from_nanos(1))
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::InvalidConfig
        );
        let mut pair = pair();
        pair.a.poll_timeout(10).unwrap();
        assert_eq!(
            pair.a.poll_timeout(9).unwrap_err().kind(),
            PointerHandoffErrorKind::ClockRegressed
        );
    }

    #[test]
    fn rejected_id_is_consumed_and_conflicting_correction_is_rejected() {
        let mut pair = pair();
        let valid = proposed_enter(&mut pair, 1);
        let mut invalid = valid;
        invalid.workspace_epoch += 1;
        let first = pair.b.receive_enter(&pair.session_b, invalid, 1).unwrap();
        let first_ack = ack_message(&first);
        pair.b.effect_sent(first, 1).unwrap();

        let duplicate = pair.b.receive_enter(&pair.session_b, invalid, 2).unwrap();
        assert_eq!(ack_message(&duplicate), first_ack);
        pair.b.effect_sent(duplicate, 2).unwrap();
        assert_eq!(
            pair.b
                .receive_enter(&pair.session_b, valid, 3)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::ConflictingReplay
        );
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
    }

    #[test]
    fn inbound_exhaustion_preserves_remote_authority_for_fatal_session_cleanup() {
        let mut pair = pair();
        pair.b.last_inbound_sequence = u64::MAX;
        let mut message = leave_message(
            &pair
                .a
                .propose_leave(&pair.session_a, Edge::Right, 0.5, 1)
                .unwrap(),
        );
        message.transition_id = u64::MAX - 1;
        message.sequence = u64::MAX - 1;
        assert_eq!(
            pair.b
                .receive_leave(&pair.session_b, message, 1)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::SequenceExhausted
        );
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
        assert!(!pair.b.has_local_authority());
        assert!(pair.b.inbound.is_none());
        assert!(pair.b.reply.is_none());
    }

    #[test]
    fn stale_effect_is_validated_before_any_outbound_side_effect() {
        use std::cell::Cell;

        fn assert_not_dispatched(
            coordinator: &mut CoordinatorCore<TestSession>,
            effect: CoreEffect<TestSession>,
            now_ns: u64,
        ) {
            let calls = Cell::new(0_u8);
            let result = coordinator.dispatch_effect(effect, now_ns, |_, _local| {
                calls.set(calls.get() + 1);
                Ok::<(), ()>(())
            });
            assert!(matches!(result, Err(CoreDispatchError::Handoff(_))));
            assert_eq!(calls.get(), 0);
        }

        let mut timed_out = pair();
        let effect = timed_out
            .a
            .propose_leave(&timed_out.session_a, Edge::Right, 0.5, 1)
            .unwrap();
        timed_out.a.poll_timeout(101).unwrap();
        assert_not_dispatched(&mut timed_out.a, effect, 101);

        let mut degraded = pair();
        let effect = degraded
            .a
            .propose_leave(&degraded.session_a, Edge::Right, 0.5, 1)
            .unwrap();
        degraded.a.degrade_session(&degraded.session_a).unwrap();
        assert_not_dispatched(&mut degraded.a, effect, 1);

        let mut reconfigured = pair();
        let effect = reconfigured
            .a
            .propose_leave(&reconfigured.session_a, Edge::Right, 0.5, 1)
            .unwrap();
        let mut compiler = ConfiguredWorkspaceCompiler::new();
        let _first = workspace(&mut compiler);
        reconfigured
            .a
            .replace_workspace(
                workspace(&mut compiler),
                LogicalPointer::new(DISPLAY_A, 50.0, 50.0),
            )
            .unwrap();
        assert_not_dispatched(&mut reconfigured.a, effect, 1);
    }

    #[test]
    fn lost_ack_and_prepared_timeout_never_activate_destination() {
        let mut pair = pair();
        let leave_effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.5, 1)
            .unwrap();
        let leave = leave_message(&leave_effect);
        pair.b.receive_leave(&pair.session_b, leave, 1).unwrap();
        let enter_effect = next_effect(pair.a.effect_sent(leave_effect, 1).unwrap());
        let enter = enter_message(&enter_effect);
        let ack_effect = pair.b.receive_enter(&pair.session_b, enter, 1).unwrap();
        pair.a.effect_sent(enter_effect, 1).unwrap();
        pair.b.effect_sent(ack_effect, 1).unwrap();

        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
        assert_eq!(
            pair.a.poll_timeout(101).unwrap(),
            PointerHandoffTimeouts {
                outbound: true,
                inbound: false,
                reply: false,
            }
        );
        assert_eq!(
            pair.b.poll_timeout(101).unwrap(),
            PointerHandoffTimeouts {
                outbound: false,
                inbound: true,
                reply: false,
            }
        );
        assert!(pair.a.has_local_authority());
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
        assert!(!pair.b.has_local_authority());
    }

    #[test]
    fn commit_dispatch_is_inert_until_queue_success_and_rolls_back_on_failure() {
        let mut pair = pair();
        let leave_effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.5, 1)
            .unwrap();
        let leave = leave_message(&leave_effect);
        pair.b.receive_leave(&pair.session_b, leave, 1).unwrap();
        let enter_effect = next_effect(pair.a.effect_sent(leave_effect, 1).unwrap());
        let enter = enter_message(&enter_effect);
        let ack_effect = pair.b.receive_enter(&pair.session_b, enter, 1).unwrap();
        pair.a.effect_sent(enter_effect, 1).unwrap();
        let ack = ack_message(&ack_effect);
        pair.b.effect_sent(ack_effect, 1).unwrap();
        let commit = commit_effect(pair.a.receive_ack(&pair.session_a, ack, 1).unwrap());

        let error = pair.a.dispatch_effect(commit, 1, |_message, local| {
            assert!(!local);
            Err("queue-full-marker")
        });
        assert!(matches!(error, Err(CoreDispatchError::Outbound(_))));
        assert!(pair.a.has_local_authority());
        assert_eq!(pair.a.workspace_state.active_host, HOST_A);
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
    }

    #[test]
    fn commit_is_exact_idempotent_and_conflicting_reuse_is_rejected() {
        let mut pair = pair();
        let leave_effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.5, 1)
            .unwrap();
        let leave = leave_message(&leave_effect);
        pair.b.receive_leave(&pair.session_b, leave, 1).unwrap();
        let enter_effect = next_effect(pair.a.effect_sent(leave_effect, 1).unwrap());
        let enter = enter_message(&enter_effect);
        let ack_effect = pair.b.receive_enter(&pair.session_b, enter, 1).unwrap();
        pair.a.effect_sent(enter_effect, 1).unwrap();
        let ack = ack_message(&ack_effect);
        pair.b.effect_sent(ack_effect, 1).unwrap();
        let commit_effect = commit_effect(pair.a.receive_ack(&pair.session_a, ack, 1).unwrap());
        let commit = commit_message(&commit_effect);
        pair.a
            .dispatch_effect(commit_effect, 1, |_message, local| {
                assert!(!local);
                Ok::<(), ()>(())
            })
            .unwrap();
        pair.b.receive_commit(&pair.session_b, commit, 1).unwrap();
        assert_eq!(
            pair.b.receive_commit(&pair.session_b, commit, 2).unwrap(),
            PointerHandoffStatus::Duplicate
        );

        let mut conflicting = commit;
        conflicting.destination_display = wire_display(DISPLAY_A);
        assert_eq!(
            pair.b
                .receive_commit(&pair.session_b, conflicting, 3)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::ConflictingReplay
        );
        let mut future = commit;
        future.transition_id += 1;
        future.sequence += 1;
        assert_eq!(
            pair.b
                .receive_commit(&pair.session_b, future, 4)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::FutureSequence
        );
    }

    #[test]
    fn expired_hint_tombstones_id_and_conflicting_reuse() {
        let mut pair = pair();
        let leave_effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.5, 1)
            .unwrap();
        let leave = leave_message(&leave_effect);
        pair.b.receive_leave(&pair.session_b, leave, 1).unwrap();
        pair.b.poll_timeout(101).unwrap();
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
        assert_eq!(
            pair.b.receive_leave(&pair.session_b, leave, 101).unwrap(),
            PointerHandoffStatus::Duplicate
        );
        let mut conflicting = leave;
        conflicting.normalized_position = 0.25;
        assert_eq!(
            pair.b
                .receive_leave(&pair.session_b, conflicting, 101)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::ConflictingReplay
        );
        let enter_effect = next_effect(pair.a.effect_sent(leave_effect, 100).unwrap());
        assert_eq!(
            pair.b
                .receive_enter(&pair.session_b, enter_message(&enter_effect), 101)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::StaleEffect
        );
    }

    #[test]
    fn workspace_epoch_and_pointer_bounds_are_transactional() {
        let mut compiler = ConfiguredWorkspaceCompiler::new();
        let epoch_one = workspace(&mut compiler);
        let epoch_two = workspace(&mut compiler);
        let config = PointerHandoffConfig::new(Duration::from_nanos(100)).unwrap();
        let state =
            WorkspaceState::new(HOST_A, HOST_A, LogicalPointer::new(DISPLAY_A, 100.0, 100.0));
        let mut coordinator = CoordinatorCore::<TestSession>::new(
            config,
            epoch_two.clone(),
            state,
            LogicalPointer::new(DISPLAY_A, 100.0, 100.0),
        )
        .unwrap();
        let before = coordinator.workspace_state();
        for stale in [epoch_one, epoch_two] {
            assert_eq!(
                coordinator
                    .replace_workspace(stale, LogicalPointer::new(DISPLAY_A, 50.0, 50.0))
                    .unwrap_err()
                    .kind(),
                PointerHandoffErrorKind::InvalidWorkspaceEpoch
            );
            assert_eq!(coordinator.workspace_state(), before);
        }

        let epoch_three = workspace(&mut compiler);
        assert_eq!(
            coordinator
                .replace_workspace(
                    epoch_three.clone(),
                    LogicalPointer::new(DISPLAY_A, 100.1, 50.0),
                )
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::InvalidWorkspaceState
        );
        assert_eq!(coordinator.workspace_state(), before);
        coordinator
            .replace_workspace(epoch_three, LogicalPointer::new(DISPLAY_A, 100.0, 100.0))
            .unwrap();
    }

    #[test]
    fn duplicate_bind_does_not_heal_degraded_session() {
        let mut pair = pair();
        pair.a.degrade_session(&pair.session_a).unwrap();
        assert_eq!(
            pair.a.bind_session(&pair.session_a).unwrap(),
            PointerHandoffStatus::Duplicate
        );
        assert_eq!(
            pair.a
                .propose_leave(&pair.session_a, Edge::Right, 0.5, 1)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::Unavailable
        );
    }

    #[test]
    fn failed_accepted_ack_preserves_destination_remote_authority() {
        let mut pair = pair();
        let enter = proposed_enter(&mut pair, 1);
        let ack_effect = pair.b.receive_enter(&pair.session_b, enter, 1).unwrap();
        assert_eq!(
            pair.b.effect_failed(&ack_effect).unwrap(),
            PointerHandoffStatus::Cleared
        );
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
        assert!(!pair.b.has_local_authority());
        assert!(pair.b.inbound.is_none());
    }

    #[test]
    fn late_commit_after_prepared_timeout_is_rejected_without_destination_activation() {
        let mut pair = pair();
        let leave_effect = pair
            .a
            .propose_leave(&pair.session_a, Edge::Right, 0.5, 1)
            .unwrap();
        let leave = leave_message(&leave_effect);
        pair.b.receive_leave(&pair.session_b, leave, 1).unwrap();
        let enter_effect = next_effect(pair.a.effect_sent(leave_effect, 1).unwrap());
        let enter = enter_message(&enter_effect);
        let ack_effect = pair.b.receive_enter(&pair.session_b, enter, 1).unwrap();
        pair.a.effect_sent(enter_effect, 1).unwrap();
        let ack = ack_message(&ack_effect);
        pair.b.effect_sent(ack_effect, 1).unwrap();
        let commit_effect = commit_effect(pair.a.receive_ack(&pair.session_a, ack, 1).unwrap());
        let commit = commit_message(&commit_effect);
        pair.b.poll_timeout(101).unwrap();
        pair.a
            .dispatch_effect(commit_effect, 100, |_message, local| {
                assert!(!local);
                Ok::<(), ()>(())
            })
            .unwrap();
        assert_eq!(
            pair.b
                .receive_commit(&pair.session_b, commit, 101)
                .unwrap_err()
                .kind(),
            PointerHandoffErrorKind::StaleSequence
        );
        assert_eq!(pair.b.workspace_state.active_host, HOST_A);
        assert!(!pair.b.has_local_authority());
    }

    #[test]
    fn nonfinite_and_off_display_initial_points_are_rejected() {
        let mut compiler = ConfiguredWorkspaceCompiler::new();
        let workspace = workspace(&mut compiler);
        let config = PointerHandoffConfig::new(Duration::from_nanos(100)).unwrap();
        for invalid in [
            LogicalPointer::new(DISPLAY_A, 100.1, 50.0),
            LogicalPointer::new(DISPLAY_A, f64::MAX, 50.0),
        ] {
            assert_eq!(
                CoordinatorCore::<TestSession>::new(
                    config,
                    workspace.clone(),
                    WorkspaceState::new(HOST_A, HOST_A, invalid),
                    LogicalPointer::new(DISPLAY_A, 50.0, 50.0),
                )
                .unwrap_err()
                .kind(),
                PointerHandoffErrorKind::InvalidWorkspaceState
            );
            assert_eq!(
                CoordinatorCore::<TestSession>::new(
                    config,
                    workspace.clone(),
                    WorkspaceState::new(
                        HOST_A,
                        HOST_A,
                        LogicalPointer::new(DISPLAY_A, 50.0, 50.0),
                    ),
                    invalid,
                )
                .unwrap_err()
                .kind(),
                PointerHandoffErrorKind::InvalidWorkspaceState
            );
        }
    }
}
