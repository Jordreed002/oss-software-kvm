use kvm_protocol::WirePeerId;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

static NEXT_GATE_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

/// Canonical responsibility for establishing a connection to one paired peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionRole {
    /// This endpoint owns the sole permitted outbound connection.
    Dialer,
    /// This endpoint accepts the sole permitted inbound connection.
    Listener,
}

/// Transport direction as observed by the local endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionDirection {
    Outbound,
    Inbound,
}

/// Failure to derive or enforce deterministic connection ownership.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ConnectionRoleError {
    #[error("local and remote peer identities must be distinct")]
    IdentityCollision,
    #[error("connection direction is not canonical for this peer pair")]
    NoncanonicalDirection,
}

impl ConnectionRole {
    /// Derives the local endpoint's role from stable peer identifiers.
    ///
    /// The lexicographically lower identifier always dials. Both endpoints
    /// therefore derive mirror-image roles without a timing-dependent race.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRoleError::IdentityCollision`] for equal IDs.
    pub fn for_peers(
        local_peer_id: WirePeerId,
        remote_peer_id: WirePeerId,
    ) -> Result<Self, ConnectionRoleError> {
        match local_peer_id.cmp(&remote_peer_id) {
            std::cmp::Ordering::Less => Ok(Self::Dialer),
            std::cmp::Ordering::Greater => Ok(Self::Listener),
            std::cmp::Ordering::Equal => Err(ConnectionRoleError::IdentityCollision),
        }
    }

    #[must_use]
    pub const fn direction(self) -> ConnectionDirection {
        match self {
            Self::Dialer => ConnectionDirection::Outbound,
            Self::Listener => ConnectionDirection::Inbound,
        }
    }

    /// Checks an observed transport direction against this canonical role.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRoleError::NoncanonicalDirection`] on mismatch.
    pub fn validate(self, direction: ConnectionDirection) -> Result<(), ConnectionRoleError> {
        if self.direction() == direction {
            Ok(())
        } else {
            Err(ConnectionRoleError::NoncanonicalDirection)
        }
    }
}

/// Local monotonic metadata used to discard events from obsolete sessions.
///
/// A generation is not evidence of remote identity or authorization.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionGeneration {
    gate_instance_id: u64,
    sequence: u64,
}

impl ConnectionGeneration {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.sequence
    }
}

impl std::fmt::Debug for ConnectionGeneration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConnectionGeneration([REDACTED])")
    }
}

/// Unique pending-connection capability produced by a generation gate.
#[derive(Eq, PartialEq)]
pub struct PendingConnection {
    gate_instance_id: u64,
    generation: ConnectionGeneration,
    direction: ConnectionDirection,
}

impl std::fmt::Debug for PendingConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingConnection")
            .field("has_generation", &true)
            .field("direction", &self.direction)
            .finish_non_exhaustive()
    }
}

impl PendingConnection {
    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    #[must_use]
    pub const fn direction(&self) -> ConnectionDirection {
        self.direction
    }
}

/// Unique active-connection capability produced only by successful promotion.
#[derive(Eq, PartialEq)]
pub struct ActiveConnection {
    gate_instance_id: u64,
    generation: ConnectionGeneration,
    direction: ConnectionDirection,
}

impl std::fmt::Debug for ActiveConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActiveConnection")
            .field("has_generation", &true)
            .field("direction", &self.direction)
            .finish_non_exhaustive()
    }
}

impl ActiveConnection {
    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    #[must_use]
    pub const fn direction(&self) -> ConnectionDirection {
        self.direction
    }
}

/// Bounded per-peer state for authorizing one connection generation at a time.
///
/// Tokens are deliberately non-cloneable. A supervisor must finish or cancel
/// the current token before the gate will allocate another generation.
pub struct ConnectionGenerationGate {
    gate_instance_id: u64,
    role: ConnectionRole,
    next_generation: u64,
    pending: Option<ConnectionGeneration>,
    active: Option<ConnectionGeneration>,
}

impl std::fmt::Debug for ConnectionGenerationGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionGenerationGate")
            .field("role", &self.role)
            .field("has_pending", &self.pending.is_some())
            .field("has_active", &self.active.is_some())
            .finish_non_exhaustive()
    }
}

/// Rejection from the bounded generation state machine.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ConnectionGenerationError {
    #[error(transparent)]
    Role(#[from] ConnectionRoleError),
    #[error("a connection generation is already pending")]
    PendingExists,
    #[error("an active connection must be reconciled before replacement")]
    ActiveExists,
    #[error("connection generation is stale or does not own the pending slot")]
    StalePending,
    #[error("connection generation is stale or does not own the active slot")]
    StaleActive,
    #[error("connection generation counter is exhausted")]
    Exhausted,
    #[error("connection generation gate identifier space is exhausted")]
    GateIdentifiersExhausted,
}

impl ConnectionGenerationGate {
    /// Creates an idle gate and derives the canonical local role.
    ///
    /// # Errors
    ///
    /// Returns an error for an identity collision or process-local gate
    /// identifier exhaustion.
    pub fn new(
        local_peer_id: WirePeerId,
        remote_peer_id: WirePeerId,
    ) -> Result<Self, ConnectionGenerationError> {
        let role = ConnectionRole::for_peers(local_peer_id, remote_peer_id)?;
        let gate_instance_id = NEXT_GATE_INSTANCE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ConnectionGenerationError::GateIdentifiersExhausted)?;
        Ok(Self {
            gate_instance_id,
            role,
            // Zero is reserved so default/uninitialized metadata cannot match
            // a generation issued by this gate.
            next_generation: 1,
            pending: None,
            active: None,
        })
    }

    #[must_use]
    pub const fn role(&self) -> ConnectionRole {
        self.role
    }

    /// Reserves the only pending slot for a canonical connection direction.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical directions, duplicates, unreconciled active
    /// sessions, and monotonic-counter exhaustion.
    pub fn begin_pending(
        &mut self,
        direction: ConnectionDirection,
    ) -> Result<PendingConnection, ConnectionGenerationError> {
        self.role.validate(direction)?;
        if self.pending.is_some() {
            return Err(ConnectionGenerationError::PendingExists);
        }
        if self.active.is_some() {
            return Err(ConnectionGenerationError::ActiveExists);
        }
        let generation = ConnectionGeneration {
            gate_instance_id: self.gate_instance_id,
            sequence: self.next_generation,
        };
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(ConnectionGenerationError::Exhausted)?;
        self.pending = Some(generation);
        Ok(PendingConnection {
            gate_instance_id: self.gate_instance_id,
            generation,
            direction,
        })
    }

    /// Promotes the exact pending token into the active slot.
    ///
    /// # Errors
    ///
    /// Rejects stale tokens and an occupied active slot.
    // Consuming the affine token prevents callers from attempting another
    // transition with the same capability.
    #[allow(clippy::needless_pass_by_value)]
    pub fn activate(
        &mut self,
        pending: PendingConnection,
    ) -> Result<ActiveConnection, ConnectionGenerationError> {
        let PendingConnection {
            gate_instance_id,
            generation,
            direction,
        } = pending;
        if gate_instance_id != self.gate_instance_id || self.pending != Some(generation) {
            return Err(ConnectionGenerationError::StalePending);
        }
        if self.active.is_some() {
            return Err(ConnectionGenerationError::ActiveExists);
        }
        self.pending = None;
        self.active = Some(generation);
        Ok(ActiveConnection {
            gate_instance_id,
            generation,
            direction,
        })
    }

    /// Cancels the exact pending token after bounded loser shutdown.
    ///
    /// # Errors
    ///
    /// Rejects a stale token without changing current state.
    // Consuming the affine token prevents callers from attempting another
    // transition with the same capability.
    #[allow(clippy::needless_pass_by_value)]
    pub fn cancel_pending(
        &mut self,
        pending: PendingConnection,
    ) -> Result<(), ConnectionGenerationError> {
        let PendingConnection {
            gate_instance_id,
            generation,
            ..
        } = pending;
        if gate_instance_id != self.gate_instance_id || self.pending != Some(generation) {
            return Err(ConnectionGenerationError::StalePending);
        }
        self.pending = None;
        Ok(())
    }

    /// Abandons an exact pending generation after its owning task was lost.
    ///
    /// This is a fail-closed recovery path for executor panic, abort, or
    /// channel loss after the affine token entered a task. It can only cancel;
    /// it cannot activate a generation or authorize application traffic.
    ///
    /// # Errors
    ///
    /// Rejects stale and cross-gate generations without changing current
    /// state.
    pub fn abandon_pending(
        &mut self,
        generation: ConnectionGeneration,
    ) -> Result<(), ConnectionGenerationError> {
        if self.pending != Some(generation) {
            return Err(ConnectionGenerationError::StalePending);
        }
        self.pending = None;
        Ok(())
    }

    /// Clears the exact active token after the caller has reconciled state.
    ///
    /// # Errors
    ///
    /// Rejects a stale token without authorizing replacement.
    // Consuming the affine token prevents callers from attempting another
    // transition with the same capability.
    #[allow(clippy::needless_pass_by_value)]
    pub fn finish_active(
        &mut self,
        active: ActiveConnection,
    ) -> Result<(), ConnectionGenerationError> {
        let ActiveConnection {
            gate_instance_id,
            generation,
            ..
        } = active;
        if gate_instance_id != self.gate_instance_id || self.active != Some(generation) {
            return Err(ConnectionGenerationError::StaleActive);
        }
        self.active = None;
        Ok(())
    }

    /// Generation reserved by the sole in-flight connection task, if any.
    #[must_use]
    pub const fn pending_generation(&self) -> Option<ConnectionGeneration> {
        self.pending
    }

    #[must_use]
    pub const fn active_generation(&self) -> Option<ConnectionGeneration> {
        self.active
    }

    #[must_use]
    pub fn is_active(&self, generation: ConnectionGeneration) -> bool {
        self.active == Some(generation)
    }

    pub(crate) fn validate_active_generation(
        &self,
        generation: ConnectionGeneration,
    ) -> Result<(), ConnectionGenerationError> {
        if self.active == Some(generation) {
            Ok(())
        } else {
            Err(ConnectionGenerationError::StaleActive)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn peer(value: u8) -> WirePeerId {
        WirePeerId([value; 16])
    }

    #[test]
    fn roles_are_mirror_images() {
        assert_eq!(
            ConnectionRole::for_peers(peer(1), peer(2)),
            Ok(ConnectionRole::Dialer)
        );
        assert_eq!(
            ConnectionRole::for_peers(peer(2), peer(1)),
            Ok(ConnectionRole::Listener)
        );
    }

    #[test]
    fn equal_peer_ids_fail_closed() {
        assert_eq!(
            ConnectionRole::for_peers(peer(1), peer(1)),
            Err(ConnectionRoleError::IdentityCollision)
        );
        assert!(matches!(
            ConnectionGenerationGate::new(peer(1), peer(1)),
            Err(ConnectionGenerationError::Role(
                ConnectionRoleError::IdentityCollision
            ))
        ));
    }

    #[test]
    fn direction_validation_is_exact() {
        assert_eq!(
            ConnectionRole::Dialer.validate(ConnectionDirection::Outbound),
            Ok(())
        );
        assert_eq!(
            ConnectionRole::Dialer.validate(ConnectionDirection::Inbound),
            Err(ConnectionRoleError::NoncanonicalDirection)
        );
        assert_eq!(
            ConnectionRole::Listener.validate(ConnectionDirection::Inbound),
            Ok(())
        );
        assert_eq!(
            ConnectionRole::Listener.validate(ConnectionDirection::Outbound),
            Err(ConnectionRoleError::NoncanonicalDirection)
        );
    }

    #[test]
    fn gate_rejects_noncanonical_and_duplicate_pending_connections() {
        let mut gate = ConnectionGenerationGate::new(peer(1), peer(2)).unwrap();
        assert!(matches!(
            gate.begin_pending(ConnectionDirection::Inbound),
            Err(ConnectionGenerationError::Role(
                ConnectionRoleError::NoncanonicalDirection
            ))
        ));

        let pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        assert_eq!(pending.generation().get(), 1);
        assert_eq!(gate.pending_generation(), Some(pending.generation()));
        assert!(matches!(
            gate.begin_pending(ConnectionDirection::Outbound),
            Err(ConnectionGenerationError::PendingExists)
        ));
        gate.cancel_pending(pending).unwrap();
        assert_eq!(gate.pending_generation(), None);

        let next = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        assert_eq!(next.generation().get(), 2);
    }

    #[test]
    fn exact_generation_abandonment_recovers_task_loss_only_for_its_gate() {
        let mut gate = ConnectionGenerationGate::new(peer(1), peer(2)).unwrap();
        let pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        let generation = pending.generation();
        let mut other = ConnectionGenerationGate::new(peer(1), peer(2)).unwrap();
        let other_pending = other.begin_pending(ConnectionDirection::Outbound).unwrap();

        assert_eq!(
            gate.abandon_pending(other_pending.generation()),
            Err(ConnectionGenerationError::StalePending)
        );
        assert_eq!(gate.abandon_pending(generation), Ok(()));
        assert!(gate.begin_pending(ConnectionDirection::Outbound).is_ok());
    }

    #[test]
    fn active_generation_blocks_replacement_until_finished() {
        let mut gate = ConnectionGenerationGate::new(peer(2), peer(1)).unwrap();
        let pending = gate.begin_pending(ConnectionDirection::Inbound).unwrap();
        let generation = pending.generation();
        let active = gate.activate(pending).unwrap();

        assert_eq!(gate.active_generation(), Some(generation));
        assert!(gate.is_active(generation));
        assert!(matches!(
            gate.begin_pending(ConnectionDirection::Inbound),
            Err(ConnectionGenerationError::ActiveExists)
        ));

        gate.finish_active(active).unwrap();
        assert_eq!(gate.active_generation(), None);
        assert!(!gate.is_active(generation));
        assert_eq!(
            gate.begin_pending(ConnectionDirection::Inbound)
                .unwrap()
                .generation()
                .get(),
            2
        );
    }

    #[test]
    fn stale_tokens_never_change_current_state() {
        let mut gate = ConnectionGenerationGate::new(peer(1), peer(2)).unwrap();
        let stale_pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        let stale_generation = stale_pending.generation();
        gate.cancel_pending(stale_pending).unwrap();

        let current_pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        let forged_stale = PendingConnection {
            gate_instance_id: gate.gate_instance_id,
            generation: stale_generation,
            direction: ConnectionDirection::Outbound,
        };
        assert_eq!(
            gate.cancel_pending(forged_stale),
            Err(ConnectionGenerationError::StalePending)
        );
        let active = gate.activate(current_pending).unwrap();

        let forged_stale = ActiveConnection {
            gate_instance_id: gate.gate_instance_id,
            generation: stale_generation,
            direction: ConnectionDirection::Outbound,
        };
        assert_eq!(
            gate.finish_active(forged_stale),
            Err(ConnectionGenerationError::StaleActive)
        );
        assert!(gate.is_active(active.generation()));
    }

    #[test]
    fn capabilities_from_another_gate_are_always_stale() {
        let mut first = ConnectionGenerationGate::new(peer(1), peer(2)).unwrap();
        let foreign_pending = first.begin_pending(ConnectionDirection::Outbound).unwrap();
        let mut second = ConnectionGenerationGate::new(peer(1), peer(2)).unwrap();
        let own_pending = second.begin_pending(ConnectionDirection::Outbound).unwrap();

        assert_eq!(
            second.activate(foreign_pending),
            Err(ConnectionGenerationError::StalePending)
        );
        let active = second.activate(own_pending).unwrap();

        let first_active = first
            .activate(PendingConnection {
                gate_instance_id: first.gate_instance_id,
                generation: ConnectionGeneration {
                    gate_instance_id: first.gate_instance_id,
                    sequence: 1,
                },
                direction: ConnectionDirection::Outbound,
            })
            .unwrap();
        assert_eq!(
            second.finish_active(first_active),
            Err(ConnectionGenerationError::StaleActive)
        );
        assert!(second.is_active(active.generation()));
    }

    #[test]
    fn recreated_gate_rejects_a_capability_from_the_old_instance() {
        let stale = {
            let mut old = ConnectionGenerationGate::new(peer(1), peer(2)).unwrap();
            old.begin_pending(ConnectionDirection::Outbound).unwrap()
        };
        let mut replacement = ConnectionGenerationGate::new(peer(1), peer(2)).unwrap();
        let current = replacement
            .begin_pending(ConnectionDirection::Outbound)
            .unwrap();

        assert_eq!(
            replacement.cancel_pending(stale),
            Err(ConnectionGenerationError::StalePending)
        );
        assert!(replacement.activate(current).is_ok());
    }

    #[test]
    fn capability_debug_omits_gate_and_generation_identifiers() {
        let mut gate = ConnectionGenerationGate::new(peer(1), peer(2)).unwrap();
        let instance_marker = gate.gate_instance_id.to_string();
        gate.next_generation = 987_654_321;
        let generation_marker = gate.next_generation.to_string();
        let pending = gate.begin_pending(ConnectionDirection::Outbound).unwrap();
        let pending_debug = format!("{pending:?}");
        let active = gate.activate(pending).unwrap();
        let active_debug = format!("{active:?}");
        let gate_debug = format!("{gate:?}");

        for marker in [instance_marker, generation_marker] {
            for rendered in [&pending_debug, &active_debug, &gate_debug] {
                assert!(!rendered.contains(&marker));
            }
        }
    }
}
