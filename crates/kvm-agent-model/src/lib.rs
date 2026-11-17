//! Allocation-free lifecycle decisions for the replacement agent.
//!
//! This model performs no capture, injection, transport or cleanup. The agent
//! owner must execute effects and report actual completion. Queue admission and
//! process existence are never evidence that sharing or cleanup completed.

/// Opaque operation identity within one model instance.
///
/// The control transport must additionally bind this to an authenticated agent
/// instance. Tickets from different instances must never be compared directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket(u64);

/// Required preconditions, supplied by the authoritative agent owner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Prerequisite {
    /// Missing, stale or not yet verified by the owner.
    #[default]
    Unconfirmed,
    Confirmed,
}

/// Independent preparation checks; no check implies any other check passed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Readiness {
    pub configuration: Prerequisite,
    pub permissions: Prerequisite,
    pub authenticated_peer: Prerequisite,
    pub topology: Prerequisite,
}

impl Readiness {
    /// Whether all preparation preconditions are currently satisfied.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self.configuration, Prerequisite::Confirmed)
            && matches!(self.permissions, Prerequisite::Confirmed)
            && matches!(self.authenticated_peer, Prerequisite::Confirmed)
            && matches!(self.topology, Prerequisite::Confirmed)
    }
}

/// Lifecycle knowledge, independent of peer health and input destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Paused,
    Preparing,
    Sharing,
    Draining,
    SafetyLatched,
}

/// Work the owner must execute outside this pure state model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    /// No further work is requested by this transition.
    None,
    Prepare(Ticket),
    /// Gate admission immediately and reconcile all resources/held input.
    Drain(Ticket),
}

/// A rejected request never mutates the model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    NotReady,
    Busy,
    SafetyLatched,
    TicketExhausted,
    StaleCompletion,
}

/// Single-owner lifecycle state. This type has no synchronization or I/O.
///
/// A failed or cancelled preparation must drain, since it may already have
/// acquired native resources. A drain failure leaves admission closed and does
/// not declare local or remote held state clean. Create a new instance paused
/// only after process-level restart and preflight; there is no unlatch method.
#[derive(Debug)]
pub struct Lifecycle {
    phase: Phase,
    pending: Option<Ticket>,
    next_ticket: u64,
    latch_after_drain: bool,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    /// Starts paused with no native resources or pending effects.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: Phase::Paused,
            pending: None,
            next_ticket: 0,
            latch_after_drain: false,
        }
    }

    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Only confirmed preparation permits the owner to consider admission.
    ///
    /// This alone never authorizes suppression: current peer health, routing
    /// authority and exact-session queue reservation are additional checks.
    #[must_use]
    pub fn permits_admission(&self) -> bool {
        self.phase == Phase::Sharing
    }

    /// Requests preparation without claiming that sharing has started.
    ///
    /// # Errors
    /// Rejects blocked readiness, a latch, concurrent work or exhausted IDs.
    pub fn resume(&mut self, readiness: Readiness) -> Result<Effect, Rejected> {
        if self.phase == Phase::SafetyLatched || self.latch_after_drain {
            return Err(Rejected::SafetyLatched);
        }
        if self.phase != Phase::Paused {
            return Err(Rejected::Busy);
        }
        if !readiness.is_ready() {
            return Err(Rejected::NotReady);
        }
        let ticket = self.allocate_ticket()?;
        self.pending = Some(ticket);
        self.phase = Phase::Preparing;
        Ok(Effect::Prepare(ticket))
    }

    /// Confirms preparation after the owner rechecks readiness.
    ///
    /// # Errors
    /// A stale/cancelled ticket cannot reopen admission. Failed preparation or
    /// lost readiness produces a drain effect, never a successful start.
    pub fn prepared(
        &mut self,
        ticket: Ticket,
        successful: bool,
        readiness: Readiness,
    ) -> Result<Effect, Rejected> {
        self.require_completion(Phase::Preparing, ticket)?;
        if !successful || !readiness.is_ready() {
            // Reuse the preparation ticket for its cleanup. A new preparation
            // cannot start until this drain is confirmed.
            self.phase = Phase::Draining;
            return Ok(Effect::Drain(ticket));
        }
        self.pending = None;
        self.phase = Phase::Sharing;
        Ok(Effect::None)
    }

    /// Closes admission; repeated pauses return the same pending drain.
    ///
    /// Pause cannot fail because IDs are exhausted. Cleanup uses the current
    /// generation, whose ticket was reserved before preparation started.
    #[must_use]
    pub fn pause(&mut self) -> Effect {
        match self.phase {
            Phase::Paused | Phase::SafetyLatched => Effect::None,
            Phase::Preparing | Phase::Sharing | Phase::Draining => {
                let ticket = self.pending.unwrap_or(Ticket(self.next_ticket));
                self.pending = Some(ticket);
                self.phase = Phase::Draining;
                Effect::Drain(ticket)
            }
        }
    }

    /// Latches immediately and requires cleanup before reporting the latch idle.
    #[must_use]
    pub fn failsafe(&mut self) -> Effect {
        self.latch_after_drain = true;
        let effect = self.pause();
        if effect == Effect::None {
            self.phase = Phase::SafetyLatched;
        }
        effect
    }

    /// Reports acknowledged cleanup; call only after the owner verifies it.
    ///
    /// # Errors
    /// Stale reports cannot clear a newer operation. A failed cleanup retains
    /// the drain ticket and closed admission for retry/recovery.
    pub fn drained(&mut self, ticket: Ticket, successful: bool) -> Result<Effect, Rejected> {
        self.require_completion(Phase::Draining, ticket)?;
        if !successful {
            return Ok(Effect::Drain(ticket));
        }
        self.pending = None;
        self.phase = if self.latch_after_drain {
            Phase::SafetyLatched
        } else {
            Phase::Paused
        };
        Ok(Effect::None)
    }

    fn allocate_ticket(&mut self) -> Result<Ticket, Rejected> {
        let next = self
            .next_ticket
            .checked_add(1)
            .ok_or(Rejected::TicketExhausted)?;
        self.next_ticket = next;
        Ok(Ticket(next))
    }

    fn require_completion(&self, phase: Phase, ticket: Ticket) -> Result<(), Rejected> {
        if self.phase == phase && self.pending == Some(ticket) {
            Ok(())
        } else {
            Err(Rejected::StaleCompletion)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const READY: Readiness = Readiness {
        configuration: Prerequisite::Confirmed,
        permissions: Prerequisite::Confirmed,
        authenticated_peer: Prerequisite::Confirmed,
        topology: Prerequisite::Confirmed,
    };

    fn start(model: &mut Lifecycle) -> Ticket {
        let Effect::Prepare(ticket) = model.resume(READY).unwrap() else {
            panic!("prepare required")
        };
        ticket
    }

    #[test]
    fn acceptance_does_not_mean_active() {
        let mut model = Lifecycle::new();
        assert_eq!(model.phase(), Phase::Paused);
        let ticket = start(&mut model);
        assert!(!model.permits_admission());
        assert_eq!(model.resume(READY), Err(Rejected::Busy));
        model.prepared(ticket, true, READY).unwrap();
        assert!(model.permits_admission());
        assert_eq!(model.pause(), Effect::Drain(ticket));
        assert!(!model.permits_admission());
    }

    #[test]
    fn blocked_readiness_does_not_consume_ticket() {
        let mut model = Lifecycle::new();
        assert_eq!(model.resume(Readiness::default()), Err(Rejected::NotReady));
        assert_eq!(model.phase(), Phase::Paused);
        assert_eq!(start(&mut model), Ticket(1));
    }

    #[test]
    fn cancelled_prepare_cannot_reopen_admission() {
        let mut model = Lifecycle::new();
        let old = start(&mut model);
        assert_eq!(model.pause(), Effect::Drain(old));
        assert_eq!(
            model.prepared(old, true, READY),
            Err(Rejected::StaleCompletion)
        );
        model.drained(old, true).unwrap();
        let new = start(&mut model);
        assert_ne!(old, new);
        assert_eq!(model.drained(old, true), Err(Rejected::StaleCompletion));
        assert_eq!(
            model.prepared(old, true, READY),
            Err(Rejected::StaleCompletion)
        );
        assert_eq!(model.phase(), Phase::Preparing);
    }

    #[test]
    fn failure_or_lost_readiness_requires_cleanup() {
        for (success, readiness) in [(false, READY), (true, Readiness::default())] {
            let mut model = Lifecycle::new();
            let ticket = start(&mut model);
            assert_eq!(
                model.prepared(ticket, success, readiness),
                Ok(Effect::Drain(ticket))
            );
            assert_eq!(model.phase(), Phase::Draining);
            assert_eq!(model.drained(ticket, false), Ok(Effect::Drain(ticket)));
            assert_eq!(model.phase(), Phase::Draining);
            model.drained(ticket, true).unwrap();
            assert_eq!(model.phase(), Phase::Paused);
        }
    }

    #[test]
    fn failsafe_escalates_existing_drain_and_cannot_resume() {
        let mut model = Lifecycle::new();
        let ticket = start(&mut model);
        model.prepared(ticket, true, READY).unwrap();
        assert_eq!(model.pause(), Effect::Drain(ticket));
        assert_eq!(model.failsafe(), Effect::Drain(ticket));
        assert_eq!(model.failsafe(), Effect::Drain(ticket));
        assert_eq!(model.resume(READY), Err(Rejected::SafetyLatched));
        model.drained(ticket, true).unwrap();
        assert_eq!(model.phase(), Phase::SafetyLatched);
        assert_eq!(model.pause(), Effect::None);
        assert_eq!(model.resume(READY), Err(Rejected::SafetyLatched));
    }

    #[test]
    fn failsafe_while_idle_is_latched_without_resources() {
        let mut model = Lifecycle::new();
        assert_eq!(model.failsafe(), Effect::None);
        assert_eq!(model.phase(), Phase::SafetyLatched);
        assert_eq!(model.resume(READY), Err(Rejected::SafetyLatched));
    }

    #[test]
    fn failsafe_cancels_preparation_and_late_completion() {
        let mut model = Lifecycle::new();
        let ticket = start(&mut model);
        assert_eq!(model.failsafe(), Effect::Drain(ticket));
        assert_eq!(
            model.prepared(ticket, true, READY),
            Err(Rejected::StaleCompletion)
        );
        assert_eq!(model.drained(ticket, false), Ok(Effect::Drain(ticket)));
        assert!(!model.permits_admission());
        model.drained(ticket, true).unwrap();
        assert_eq!(model.phase(), Phase::SafetyLatched);
        assert_eq!(model.drained(ticket, true), Err(Rejected::StaleCompletion));
    }

    #[test]
    fn ticket_exhaustion_never_blocks_cleanup_or_wraps() {
        let mut model = Lifecycle {
            next_ticket: u64::MAX - 1,
            ..Lifecycle::new()
        };
        let ticket = start(&mut model);
        model.prepared(ticket, true, READY).unwrap();
        assert_eq!(model.pause(), Effect::Drain(ticket));
        model.drained(ticket, true).unwrap();
        assert_eq!(model.resume(READY), Err(Rejected::TicketExhausted));
        assert_eq!(model.phase(), Phase::Paused);
        assert_eq!(model.pause(), Effect::None);
    }
}
