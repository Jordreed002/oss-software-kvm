//! Pure, allocation-free lifecycle decisions for the rebuilt agent.
//!
//! The owner executes effects and reports actual completion. This model performs
//! no I/O, capture, injection or resource cleanup.

/// Operation identity, bound to an owner-supplied agent instance epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    instance: u128,
    generation: u64,
}

/// Unique cleanup attempt within a preparation/session generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainTicket {
    ticket: Ticket,
    attempt: u64,
}

/// A precondition verified by the authoritative owner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Prerequisite {
    #[default]
    Unconfirmed,
    Confirmed,
}

/// Independent checks; no check implies any other check passed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Readiness {
    pub configuration: Prerequisite,
    pub permissions: Prerequisite,
    pub authenticated_peer: Prerequisite,
    pub topology: Prerequisite,
}

impl Readiness {
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self.configuration, Prerequisite::Confirmed)
            && matches!(self.permissions, Prerequisite::Confirmed)
            && matches!(self.authenticated_peer, Prerequisite::Confirmed)
            && matches!(self.topology, Prerequisite::Confirmed)
    }
}

/// Lifecycle knowledge, separate from safety and input destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Paused,
    Preparing,
    Sharing,
    Draining,
    SafetyLatched,
}

/// Work to execute outside the state model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    None,
    Prepare(Ticket),
    /// Cancel and fence preparation. Report `prepared` only after no further
    /// resource acquisition can occur for this ticket. Then execute its drain.
    CancelPrepare(Ticket),
    /// Reconcile held input and native resources after preparation is fenced.
    /// Repeated pause requests do not issue duplicate drain effects.
    Drain(DrainTicket),
}

/// Rejections leave the model unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    NotReady,
    Busy,
    SafetyLatched,
    TicketExhausted,
    StaleCompletion,
    PreparationOutstanding,
    NoCleanupRetry,
    DrainAttemptExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Paused,
    Preparing(Ticket),
    Sharing(Ticket),
    Draining {
        ticket: Ticket,
        preparing: bool,
        pending: Option<DrainTicket>,
    },
    SafetyLatched,
}

/// Single-owner state; no synchronization, allocation or I/O.
///
/// The owner must cancel AND join/fence resource acquisition before reporting a
/// cancelled preparation complete. A successful drain additionally means that
/// no resource acquisition for that generation can occur later. A stale result
/// cannot substitute for cancellation/fencing of the underlying native work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lifecycle {
    instance: u128,
    next_generation: u64,
    drain_attempt: u64,
    state: State,
    latched: bool,
    cleanup_failed: bool,
}

impl Lifecycle {
    /// Starts paused. Supply a fresh epoch for every owner instance, including
    /// in-process replacements. Do not reuse an epoch while old tasks/results
    /// may exist. The installed agent should use a cryptographically random
    /// instance identifier; this pure model does not generate identities.
    #[must_use]
    pub const fn new(instance: u128) -> Self {
        Self {
            instance,
            next_generation: 0,
            drain_attempt: 0,
            state: State::Paused,
            latched: false,
            cleanup_failed: false,
        }
    }

    #[must_use]
    pub const fn phase(&self) -> Phase {
        match self.state {
            State::Paused => Phase::Paused,
            State::Preparing(_) => Phase::Preparing,
            State::Sharing(_) => Phase::Sharing,
            State::Draining { .. } => Phase::Draining,
            State::SafetyLatched => Phase::SafetyLatched,
        }
    }

    /// Visible immediately, including while a drain is pending or failing.
    #[must_use]
    pub const fn is_latched(&self) -> bool {
        self.latched
    }

    /// Whether cleanup failed and its outcome remains unconfirmed.
    #[must_use]
    pub const fn cleanup_failed(&self) -> bool {
        self.cleanup_failed
    }

    /// Necessary but insufficient for suppression: current peer health,
    /// authority and exact-session queue reservation are additional checks.
    #[must_use]
    pub const fn permits_admission(&self) -> bool {
        matches!(self.state, State::Sharing(_))
    }

    /// Requests preparation without claiming sharing has started.
    ///
    /// # Errors
    /// Rejects a latch, concurrent work, readiness blockers or exhausted IDs.
    pub fn resume(&mut self, readiness: Readiness) -> Result<Effect, Rejected> {
        if self.latched {
            return Err(Rejected::SafetyLatched);
        }
        if self.state != State::Paused {
            return Err(Rejected::Busy);
        }
        if !readiness.is_ready() {
            return Err(Rejected::NotReady);
        }
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or(Rejected::TicketExhausted)?;
        let ticket = Ticket {
            instance: self.instance,
            generation,
        };
        self.next_generation = generation;
        self.state = State::Preparing(ticket);
        Ok(Effect::Prepare(ticket))
    }

    /// Reports preparation finished AND fenced against further acquisition.
    ///
    /// # Errors
    /// Rejects stale/duplicate results. Cancellation always starts a final
    /// drain, even if preparation reports successful. It never opens admission.
    pub fn prepared(
        &mut self,
        ticket: Ticket,
        successful: bool,
        readiness: Readiness,
    ) -> Result<Effect, Rejected> {
        match self.state {
            State::Preparing(expected) if expected == ticket => {
                if successful && readiness.is_ready() {
                    self.state = State::Sharing(ticket);
                    Ok(Effect::None)
                } else {
                    Ok(self.begin_drain(ticket))
                }
            }
            State::Draining {
                ticket: expected,
                preparing: true,
                ..
            } if expected == ticket => Ok(self.begin_drain(ticket)),
            _ => Err(Rejected::StaleCompletion),
        }
    }

    /// Closes admission immediately. Repeated requests do not start overlapping
    /// drains or retries. Pausing never allocates another generation ID.
    #[must_use]
    pub fn pause(&mut self) -> Effect {
        match self.state {
            State::Preparing(ticket) => {
                self.state = State::Draining {
                    ticket,
                    preparing: true,
                    pending: None,
                };
                Effect::CancelPrepare(ticket)
            }
            State::Sharing(ticket) => self.begin_drain(ticket),
            _ => Effect::None,
        }
    }

    /// Latches immediately, independently of cleanup progress.
    #[must_use]
    pub fn failsafe(&mut self) -> Effect {
        self.latched = true;
        let effect = self.pause();
        if self.state == State::Paused {
            self.state = State::SafetyLatched;
        }
        effect
    }

    /// Reports one cleanup attempt. Success requires actual acknowledged local
    /// teardown after fenced preparation, not just a sweep or process kill.
    ///
    /// # Errors
    /// Rejects outstanding preparation, stale generations and stale attempts.
    /// Failed cleanup stays gated and must be explicitly retried.
    pub fn drained(&mut self, drain: DrainTicket, successful: bool) -> Result<Effect, Rejected> {
        match self.state {
            State::Draining {
                ticket,
                preparing,
                pending,
            } if ticket == drain.ticket => {
                if preparing {
                    return Err(Rejected::PreparationOutstanding);
                }
                if pending != Some(drain) {
                    return Err(Rejected::StaleCompletion);
                }
                if successful {
                    self.cleanup_failed = false;
                    self.state = if self.latched {
                        State::SafetyLatched
                    } else {
                        State::Paused
                    };
                } else {
                    self.cleanup_failed = true;
                    self.state = State::Draining {
                        ticket,
                        preparing: false,
                        pending: None,
                    };
                }
                Ok(Effect::None)
            }
            _ => Err(Rejected::StaleCompletion),
        }
    }

    /// Explicitly retries failed cleanup with a new attempt identity.
    ///
    /// # Errors
    /// Rejects concurrent/nonfailed cleanup and exhausted attempt IDs. Exhaustion
    /// stays gated for manual recovery; an old attempt can never become current.
    pub fn retry_cleanup(&mut self) -> Result<Effect, Rejected> {
        let State::Draining {
            ticket,
            preparing: false,
            pending: None,
        } = self.state
        else {
            return Err(Rejected::NoCleanupRetry);
        };
        if !self.cleanup_failed {
            return Err(Rejected::NoCleanupRetry);
        }
        let attempt = self
            .drain_attempt
            .checked_add(1)
            .ok_or(Rejected::DrainAttemptExhausted)?;
        let drain = DrainTicket { ticket, attempt };
        self.drain_attempt = attempt;
        self.state = State::Draining {
            ticket,
            preparing: false,
            pending: Some(drain),
        };
        Ok(Effect::Drain(drain))
    }

    fn begin_drain(&mut self, ticket: Ticket) -> Effect {
        let drain = DrainTicket { ticket, attempt: 1 };
        self.drain_attempt = 1;
        self.state = State::Draining {
            ticket,
            preparing: false,
            pending: Some(drain),
        };
        Effect::Drain(drain)
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
            panic!("expected preparation")
        };
        ticket
    }
    fn drain(effect: Effect) -> DrainTicket {
        let Effect::Drain(ticket) = effect else {
            panic!("expected drain")
        };
        ticket
    }
    fn active() -> (Lifecycle, Ticket) {
        let mut model = Lifecycle::new(1);
        let ticket = start(&mut model);
        model.prepared(ticket, true, READY).unwrap();
        (model, ticket)
    }
    #[test]
    fn acceptance_is_not_active_and_sharing_retains_generation() {
        let mut model = Lifecycle::new(1);
        let ticket = start(&mut model);
        assert!(!model.permits_admission());
        let before = model.clone();
        assert_eq!(model.resume(READY), Err(Rejected::Busy));
        assert_eq!(model, before);
        model.prepared(ticket, true, READY).unwrap();
        assert!(model.permits_admission());
        assert_eq!(drain(model.pause()).ticket, ticket);
        assert!(!model.permits_admission());
    }
    #[test]
    fn rejected_readiness_does_not_mutate_or_consume_ticket() {
        let mut model = Lifecycle::new(1);
        let before = model.clone();
        assert_eq!(model.resume(Readiness::default()), Err(Rejected::NotReady));
        assert_eq!(model, before);
        assert_eq!(start(&mut model).generation, 1);
    }
    #[test]
    fn cancellation_must_fence_preparation_before_drain_can_complete() {
        let mut model = Lifecycle::new(1);
        let ticket = start(&mut model);
        assert_eq!(model.pause(), Effect::CancelPrepare(ticket));
        let invented = DrainTicket { ticket, attempt: 1 };
        let before = model.clone();
        assert_eq!(
            model.drained(invented, true),
            Err(Rejected::PreparationOutstanding)
        );
        assert_eq!(model, before);
        assert_eq!(model.pause(), Effect::None);
        let final_drain = drain(model.prepared(ticket, true, READY).unwrap());
        assert_eq!(model.phase(), Phase::Draining);
        assert!(!model.permits_admission());
        model.drained(final_drain, true).unwrap();
        assert_eq!(model.phase(), Phase::Paused);
    }
    #[test]
    fn preparation_failure_and_lost_readiness_both_drain() {
        for (success, readiness) in [(false, READY), (true, Readiness::default())] {
            let mut model = Lifecycle::new(1);
            let ticket = start(&mut model);
            let cleanup = drain(model.prepared(ticket, success, readiness).unwrap());
            assert_eq!(cleanup.ticket, ticket);
            model.drained(cleanup, true).unwrap();
            assert_eq!(model.phase(), Phase::Paused);
        }
    }
    #[test]
    fn cleanup_retry_has_distinct_identity_and_no_duplicate_effects() {
        let (mut model, _) = active();
        let first = drain(model.pause());
        assert_eq!(model.pause(), Effect::None);
        model.drained(first, false).unwrap();
        assert!(model.cleanup_failed());
        let second = drain(model.retry_cleanup().unwrap());
        assert_ne!(first, second);
        let before = model.clone();
        assert_eq!(model.drained(first, true), Err(Rejected::StaleCompletion));
        assert_eq!(model.retry_cleanup(), Err(Rejected::NoCleanupRetry));
        assert_eq!(model, before);
        assert!(model.cleanup_failed());
        model.drained(second, true).unwrap();
        assert!(!model.cleanup_failed());
    }
    #[test]
    fn old_generation_drain_cannot_complete_new_generation_cleanup() {
        let (mut model, _) = active();
        let old = drain(model.pause());
        model.drained(old, true).unwrap();
        let ticket = start(&mut model);
        model.prepared(ticket, true, READY).unwrap();
        let new = drain(model.pause());
        let before = model.clone();
        assert_eq!(model.drained(old, true), Err(Rejected::StaleCompletion));
        assert_eq!(model, before);
        model.drained(new, true).unwrap();
    }
    #[test]
    fn old_instance_prepare_and_drain_are_rejected() {
        let (mut old, old_ticket) = active();
        let old_drain = drain(old.pause());
        let mut new = Lifecycle::new(2);
        let ticket = start(&mut new);
        let before = new.clone();
        assert_eq!(
            new.prepared(old_ticket, true, READY),
            Err(Rejected::StaleCompletion)
        );
        assert_eq!(new, before);
        new.prepared(ticket, true, READY).unwrap();
        let current = drain(new.pause());
        let before = new.clone();
        assert_eq!(new.drained(old_drain, true), Err(Rejected::StaleCompletion));
        assert_eq!(new, before);
        new.drained(current, true).unwrap();
    }
    #[test]
    fn failsafe_is_visible_during_failed_cleanup_and_never_clears() {
        let (mut model, _) = active();
        let first = drain(model.failsafe());
        assert!(model.is_latched());
        assert_eq!(model.phase(), Phase::Draining);
        model.drained(first, false).unwrap();
        assert_eq!(model.failsafe(), Effect::None);
        assert!(model.is_latched());
        let before = model.clone();
        assert_eq!(model.resume(READY), Err(Rejected::SafetyLatched));
        assert_eq!(model, before);
        let retry = drain(model.retry_cleanup().unwrap());
        model.drained(retry, true).unwrap();
        assert_eq!(model.phase(), Phase::SafetyLatched);
        assert!(model.is_latched());
    }
    #[test]
    fn failsafe_fences_preparation_and_cannot_make_drain_idle_early() {
        let mut model = Lifecycle::new(1);
        let ticket = start(&mut model);
        assert_eq!(model.failsafe(), Effect::CancelPrepare(ticket));
        assert_eq!(model.failsafe(), Effect::None);
        assert!(model.is_latched());
        assert_eq!(model.phase(), Phase::Draining);
        let cleanup = drain(model.prepared(ticket, true, READY).unwrap());
        model.drained(cleanup, true).unwrap();
        assert_eq!(model.phase(), Phase::SafetyLatched);
    }
    #[test]
    fn idle_failsafe_latches_without_work() {
        let mut model = Lifecycle::new(1);
        assert_eq!(model.failsafe(), Effect::None);
        assert_eq!(model.phase(), Phase::SafetyLatched);
        assert!(model.is_latched());
    }
    #[test]
    fn generation_exhaustion_cannot_prevent_cleanup() {
        let mut model = Lifecycle::new(1);
        model.next_generation = u64::MAX - 1;
        let ticket = start(&mut model);
        model.prepared(ticket, true, READY).unwrap();
        let cleanup = drain(model.pause());
        assert_eq!(cleanup.ticket, ticket);
        model.drained(cleanup, true).unwrap();
        let before = model.clone();
        assert_eq!(model.resume(READY), Err(Rejected::TicketExhausted));
        assert_eq!(model, before);
    }
    #[test]
    fn cleanup_attempt_exhaustion_stays_gated_without_mutation() {
        let (mut model, _) = active();
        let cleanup = drain(model.pause());
        model.drained(cleanup, false).unwrap();
        model.drain_attempt = u64::MAX;
        let before = model.clone();
        assert_eq!(model.retry_cleanup(), Err(Rejected::DrainAttemptExhausted));
        assert_eq!(model, before);
        assert!(!model.permits_admission());
    }
}
