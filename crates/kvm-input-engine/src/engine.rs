//! Synchronous bounded input admission for one owning session context.
//!
//! [`InputEngine`] stages physical input events from [`kvm_foundation`]
//! behind an exact route epoch. Activation requires local state and an empty
//! queue; admission validates finiteness and host-local age, while consumption
//! rechecks age using a reading of the same monotonic clock; a full
//! queue, an invalid current-generation event or an event that expires while
//! queued latches a terminal fault that preserves all held entries for
//! explicit bounded discard.
//!
//! This module is deliberately not a router, transport or native suppression
//! layer, and it makes no coalescing, priority, delivery or suppression
//! claims. See the crate documentation for the standing invariants.

use core::fmt;

use crate::identity::{InstanceId, PeerId, RouteEpoch};
use kvm_foundation::{EventKind, InputEvent, RingFifo, Timestamp};

/// A nonzero maximum event age, in nanoseconds on the host-local clock.
///
/// Zero is rejected because the contract requires a nonzero age bound. A zero
/// bound would accept only current-instant events and is effectively unusable
/// for a queue whose events spend time awaiting consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaxEventAge(u64);

impl MaxEventAge {
    /// Builds a maximum event age from host-local nanoseconds.
    ///
    /// Returns `None` for zero; see the type documentation.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Option<Self> {
        if nanos == 0 {
            None
        } else {
            Some(Self(nanos))
        }
    }

    /// Returns the configured maximum age in host-local nanoseconds.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

/// Why admission faulted and latched closed.
///
/// Reasons name the violated bound only. They never include input content,
/// device identifiers, instance identities or peer identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultReason {
    /// A motion or scroll delta was not finite at admission.
    NonFiniteInput,
    /// The event timestamp followed the supplied current time.
    FutureTimestamp,
    /// The event exceeded the configured maximum age at admission.
    ExcessiveAge,
    /// The queue held its full complement of events when a valid
    /// current-generation event arrived.
    QueueFull,
    /// The oldest held event no longer satisfied the age limit when
    /// consumption was attempted, including a supplied current time that
    /// precedes the event, which one monotonic clock cannot produce.
    StaleQueuedInput,
}

/// Why an activation was refused. Every refusal leaves the engine unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivateError {
    /// Admission is already open; close the active route first.
    NotLocal,
    /// The engine is local, but queued input from the closed route remains;
    /// discard it explicitly first.
    QueueNotEmpty,
    /// A fault is latched. There is no unlatch in this increment, so this
    /// engine can never admit again.
    FaultLatched,
    /// The generation counter reached its upper bound while allocating the
    /// next generation; nothing changed.
    GenerationExhausted,
}

/// Why an enqueue was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueError {
    /// A route is active, but the presented epoch is not its exact identity.
    /// Nothing changed, and the active route was not faulted.
    StaleEpoch,
    /// No admission is open: the engine is local (never activated or closed)
    /// or fault-latched.
    NoActiveRoute,
    /// The current route faulted and latched closed. The rejected event was
    /// neither queued nor forwarded, and all held entries are preserved for
    /// explicit discard.
    Faulted(FaultReason),
}

/// Why a consumption was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumeError {
    /// A route is active, but the presented epoch is not its exact identity.
    /// Nothing changed, and the active route was not faulted.
    StaleEpoch,
    /// No admission is open: the engine is local (never activated or closed)
    /// or fault-latched. Queued input is never forwarded after close or fault.
    NoActiveRoute,
    /// The current route faulted and latched closed. The offending event was
    /// not dequeued and not forwarded; it and every later entry remain held
    /// for explicit discard.
    Faulted(FaultReason),
}

/// Why a close was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseError {
    /// A route is active, but the presented epoch is not its exact identity.
    /// Admission stays open and unchanged.
    StaleEpoch,
    /// No admission is open to revoke.
    NoActiveRoute,
}

/// Why an explicit discard was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscardError {
    /// Admission is still open; held input leaves only through consumption,
    /// or through a close followed by discard.
    AdmissionOpen,
}

/// The admission lifecycle state of an [`InputEngine`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineState {
    /// No route is active: the initial state, and the state after a clean
    /// close. Held leftovers can only be discarded.
    Local,
    /// Admission is open under exactly this generation of the engine's route.
    /// A bare generation is not route identity and authorizes nothing.
    Active {
        /// The generation allocated by the activating call.
        generation: u64,
    },
    /// A fault latched admission closed. Terminal: there is no unlatch, so
    /// this engine can never admit again.
    Faulted {
        /// The bound that was violated.
        reason: FaultReason,
    },
}

/// A `Copy` snapshot of engine state for owner diagnostics.
///
/// Contains only lifecycle state and counts. Input content and the process
/// instance and peer identities are never included, here or in any `Debug`
/// output of this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineSnapshot {
    /// Current admission lifecycle state.
    pub state: EngineState,
    /// Events currently held, head stage and ring together.
    pub queued: usize,
    /// The fixed maximum number of held events.
    pub capacity: usize,
}

/// Synchronous bounded input admission state for exactly one owner.
///
/// The engine holds at most `QUEUE_CAPACITY` events, all inline: the oldest
/// held event occupies one head stage and the remainder occupy the
/// foundation's fixed-capacity [`RingFifo`]. There is no heap allocation, no
/// `unsafe` code, no I/O and no synchronization of any kind; one owning
/// session context serializes every call.
///
/// Deliberately not `Clone`: a copy would duplicate live route epochs under
/// one identity, which is exactly the confusion epochs exist to prevent.
///
/// # Capacity
///
/// A capacity of zero is well defined: every admission attempt faults with
/// [`FaultReason::QueueFull`] immediately. Before that fault, consumption under
/// an active epoch reports an empty queue; afterward it reports no active route.
/// Sizing storage for peek-less age checks costs one slot: the
/// ring is declared with `QUEUE_CAPACITY` slots but never holds more than
/// `QUEUE_CAPACITY - 1` entries, because the oldest event occupies the head
/// stage whenever anything is held.
///
/// # Example lifecycle
///
/// Activate while local and empty, admit and consume under the returned
/// [`RouteEpoch`], close to revoke admission, discard leftovers one bounded
/// operation at a time, then activate again. A fault anywhere latches closed
/// for the life of the engine; the owner must run its independent failsafe
/// and held-input reconciliation, and must not claim any rejected event was
/// forwarded.
pub struct InputEngine<const QUEUE_CAPACITY: usize> {
    instance: InstanceId,
    peer: PeerId,
    max_age: MaxEventAge,
    /// The most recent generation allocated, or the floor inherited from a
    /// predecessor engine; `0` before any activation of a fresh counter.
    last_generation: u64,
    state: EngineState,
    /// The oldest held event, staged ahead of the ring so its age can be
    /// rechecked without dequeueing it.
    head: Option<InputEvent>,
    /// The remaining held events, newest last.
    queue: RingFifo<InputEvent, QUEUE_CAPACITY>,
}

impl<const QUEUE_CAPACITY: usize> fmt::Debug for InputEngine<QUEUE_CAPACITY> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snapshot = self.snapshot();
        formatter
            .debug_struct("InputEngine")
            .field("state", &snapshot.state)
            .field("queued", &snapshot.queued)
            .field("capacity", &snapshot.capacity)
            .finish_non_exhaustive()
    }
}

impl<const QUEUE_CAPACITY: usize> InputEngine<QUEUE_CAPACITY> {
    /// Builds a local engine with an empty queue, starting its generation
    /// counter at one.
    ///
    /// The process instance, peer identity and maximum event age bind every
    /// route epoch this engine mints. Identities and the age limit are nonzero
    /// by construction. A replacement process must supply a fresh instance
    /// identity. A replacement engine reusing the same identities in the same
    /// process must instead continue the counter with
    /// [`InputEngine::new_with_generation_floor`]: with this constructor, an
    /// epoch minted by the dropped engine would still match this one.
    #[must_use]
    pub const fn new(instance: InstanceId, peer: PeerId, max_age: MaxEventAge) -> Self {
        Self::new_with_generation_floor(instance, peer, max_age, 0)
    }

    /// Builds a local engine with an empty queue, continuing the generation
    /// counter above `generation_floor`.
    ///
    /// The first activation allocates `generation_floor + 1`. Pass the last
    /// generation a predecessor engine allocated, readable as
    /// `predecessor.last_generation()`, so that a replacement engine reusing
    /// the same process instance and peer refuses every predecessor epoch as
    /// stale from its first activation. A `generation_floor` of `u64::MAX`
    /// leaves every activation refused with
    /// [`ActivateError::GenerationExhausted`], exactly as counter exhaustion
    /// behaves anywhere else, with state unchanged.
    #[must_use]
    pub const fn new_with_generation_floor(
        instance: InstanceId,
        peer: PeerId,
        max_age: MaxEventAge,
        generation_floor: u64,
    ) -> Self {
        Self {
            instance,
            peer,
            max_age,
            last_generation: generation_floor,
            state: EngineState::Local,
            head: None,
            queue: RingFifo::new(),
        }
    }

    /// Returns a redacted snapshot of the current state.
    #[must_use]
    pub const fn snapshot(&self) -> EngineSnapshot {
        EngineSnapshot {
            state: self.state,
            queued: self.held_len(),
            capacity: self.queue.capacity(),
        }
    }

    /// Returns the last generation this engine allocated, or the floor it
    /// inherited from a predecessor engine.
    ///
    /// Before any activation this is the construction floor (`0` for
    /// [`InputEngine::new`]). Pass it as the generation floor when building a
    /// same-identity replacement engine, so predecessor epochs stay stale; a
    /// bare generation is not route identity and authorizes nothing.
    #[must_use]
    pub const fn last_generation(&self) -> u64 {
        self.last_generation
    }

    /// Opens admission by allocating the next route epoch.
    ///
    /// Requires local state and an empty queue, so an active route must be
    /// closed and any held leftovers discarded first. Each activation
    /// allocates a checked, increasing nonzero generation binding this
    /// engine's process instance and peer.
    ///
    /// # Errors
    ///
    /// * [`ActivateError::NotLocal`] while a route is active.
    /// * [`ActivateError::QueueNotEmpty`] when held input remains.
    /// * [`ActivateError::FaultLatched`] after any fault; terminal.
    /// * [`ActivateError::GenerationExhausted`] when the generation counter
    ///   can no longer increase; the engine is left unchanged.
    pub fn activate(&mut self) -> Result<RouteEpoch, ActivateError> {
        match self.state {
            EngineState::Active { .. } => return Err(ActivateError::NotLocal),
            EngineState::Faulted { .. } => return Err(ActivateError::FaultLatched),
            EngineState::Local => {}
        }
        if self.held_len() != 0 {
            return Err(ActivateError::QueueNotEmpty);
        }
        let Some(generation) = self.last_generation.checked_add(1) else {
            return Err(ActivateError::GenerationExhausted);
        };
        self.last_generation = generation;
        self.state = EngineState::Active { generation };
        Ok(self.epoch_at(generation))
    }

    /// Admits one event under the exact active epoch.
    ///
    /// `now` must be a reading of the same host-local monotonic clock that
    /// produced `event.timestamp`. Admission validates that motion and scroll
    /// deltas are finite, that the timestamp is not in the future, and that
    /// its age is at most the configured maximum, before checking that room
    /// remains. Success proves only bounded local admission: it does not
    /// establish peer delivery and does not by itself authorize native
    /// suppression.
    ///
    /// # Errors
    ///
    /// * [`EnqueueError::NoActiveRoute`] when no admission is open.
    /// * [`EnqueueError::StaleEpoch`] when a route is active but the epoch is
    ///   not its exact identity; nothing changes and the route is not faulted.
    /// * [`EnqueueError::Faulted`] when the event is invalid, or the queue is
    ///   full: the route latches closed, the event is neither queued nor
    ///   forwarded, and all held entries are preserved for explicit discard.
    pub fn enqueue(
        &mut self,
        epoch: RouteEpoch,
        now: Timestamp,
        event: InputEvent,
    ) -> Result<(), EnqueueError> {
        let EngineState::Active { generation } = self.state else {
            return Err(EnqueueError::NoActiveRoute);
        };
        if epoch != self.epoch_at(generation) {
            return Err(EnqueueError::StaleEpoch);
        }
        if let Some(reason) = admission_fault(&event, now, self.max_age) {
            self.state = EngineState::Faulted { reason };
            return Err(EnqueueError::Faulted(reason));
        }
        if self.held_len() == QUEUE_CAPACITY {
            self.state = EngineState::Faulted {
                reason: FaultReason::QueueFull,
            };
            return Err(EnqueueError::Faulted(FaultReason::QueueFull));
        }
        if self.head.is_none() {
            self.head = Some(event);
            return Ok(());
        }
        match self.queue.push(event) {
            Ok(()) => Ok(()),
            Err(_unreachable_while_invariants_hold) => {
                // The held-length bound guarantees the ring holds at most
                // QUEUE_CAPACITY - 1 entries whenever the head stage is
                // occupied, so this arm is unreachable. Treat it defensively
                // as a full-queue fault rather than dropping the event
                // silently or panicking.
                self.state = EngineState::Faulted {
                    reason: FaultReason::QueueFull,
                };
                Err(EnqueueError::Faulted(FaultReason::QueueFull))
            }
        }
    }

    /// Removes and returns the oldest held event under the exact active epoch.
    ///
    /// `now` must be a reading of the same host-local monotonic clock that
    /// produced event timestamps. The age limit is checked again at the
    /// supplied time before the event is dequeued; removing an event from the
    /// queue is not delivery, and the owner must separately fence the
    /// returned work.
    ///
    /// # Errors
    ///
    /// * [`ConsumeError::NoActiveRoute`] when no admission is open; held
    ///   input is never forwarded after close or fault.
    /// * [`ConsumeError::StaleEpoch`] when a route is active but the epoch is
    ///   not its exact identity; nothing changes and the route is not faulted.
    /// * [`ConsumeError::Faulted`] when the oldest event no longer satisfies
    ///   the age bound: the route latches closed and the expired event stays
    ///   held, in order, for explicit discard.
    pub fn consume(
        &mut self,
        epoch: RouteEpoch,
        now: Timestamp,
    ) -> Result<Option<InputEvent>, ConsumeError> {
        let EngineState::Active { generation } = self.state else {
            return Err(ConsumeError::NoActiveRoute);
        };
        if epoch != self.epoch_at(generation) {
            return Err(ConsumeError::StaleEpoch);
        }
        let Some(oldest) = self.head.as_ref() else {
            return Ok(None);
        };
        if age_violation(
            oldest.timestamp.as_nanos(),
            now.as_nanos(),
            self.max_age.as_nanos(),
        ) {
            self.state = EngineState::Faulted {
                reason: FaultReason::StaleQueuedInput,
            };
            return Err(ConsumeError::Faulted(FaultReason::StaleQueuedInput));
        }
        let event = self.head.take();
        self.head = self.queue.pop();
        Ok(event)
    }

    /// Revokes admission immediately, preserving held input.
    ///
    /// Held events are never forwarded after the close; they remain for
    /// explicit discard through [`InputEngine::discard_one`]. The epoch is
    /// required so that a stale epoch cannot revoke someone else's active
    /// route.
    ///
    /// # Errors
    ///
    /// * [`CloseError::NoActiveRoute`] when no admission is open.
    /// * [`CloseError::StaleEpoch`] when a route is active but the epoch is
    ///   not its exact identity; admission stays open and unchanged.
    pub fn close(&mut self, epoch: RouteEpoch) -> Result<(), CloseError> {
        match self.state {
            EngineState::Active { generation } => {
                if epoch != self.epoch_at(generation) {
                    return Err(CloseError::StaleEpoch);
                }
                self.state = EngineState::Local;
                Ok(())
            }
            _ => Err(CloseError::NoActiveRoute),
        }
    }

    /// Discards exactly one held event, oldest first, one bounded operation.
    ///
    /// Explicit discard is the only exit for held input once admission is
    /// closed or faulted, and there is deliberately no drain: the owner
    /// reconciles each discarded event itself, and clearing the queue is not
    /// cleanup confirmation.
    ///
    /// # Errors
    ///
    /// * [`DiscardError::AdmissionOpen`] while a route is active; held input
    ///   leaves only through consumption, or through a close followed by
    ///   discard.
    pub fn discard_one(&mut self) -> Result<Option<InputEvent>, DiscardError> {
        if matches!(self.state, EngineState::Active { .. }) {
            return Err(DiscardError::AdmissionOpen);
        }
        match self.head.take() {
            Some(discarded) => {
                self.head = self.queue.pop();
                Ok(Some(discarded))
            }
            None => Ok(None),
        }
    }

    /// The epoch binding the given generation of this engine's route.
    fn epoch_at(&self, generation: u64) -> RouteEpoch {
        RouteEpoch {
            instance: self.instance,
            peer: self.peer,
            generation,
        }
    }

    /// Held events: the head stage plus the ring.
    const fn held_len(&self) -> usize {
        (self.head.is_some() as usize) + self.queue.len()
    }
}

/// Whether `timestamp` violates the age bound at `now` on the shared clock.
///
/// Both a timestamp after `now` (a clock regression that one monotonic clock
/// cannot produce, treated as a violation rather than trusting wrapping
/// arithmetic) and an age above the limit are violations. An age exactly at
/// the limit is not.
fn age_violation(timestamp: u64, now: u64, max_age: u64) -> bool {
    timestamp > now || now - timestamp > max_age
}

/// The admission bound an event violates, if any.
///
/// Finiteness is decided first, then future timestamps, then age, so a
/// reported reason always names the defect regardless of queue occupancy.
/// Keys and pointer buttons carry no deltas and cannot be non-finite.
fn admission_fault(
    event: &InputEvent,
    now: Timestamp,
    max_age: MaxEventAge,
) -> Option<FaultReason> {
    if let EventKind::PointerMove { dx, dy } | EventKind::Scroll { dx, dy } = &event.kind {
        if !dx.is_finite() || !dy.is_finite() {
            return Some(FaultReason::NonFiniteInput);
        }
    }
    if event.timestamp.as_nanos() > now.as_nanos() {
        return Some(FaultReason::FutureTimestamp);
    }
    if age_violation(
        event.timestamp.as_nanos(),
        now.as_nanos(),
        max_age.as_nanos(),
    ) {
        return Some(FaultReason::ExcessiveAge);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_foundation::{DeviceId, KeyCode, PointerButton, Transition};
    use std::collections::VecDeque;

    const INSTANCE_RAW: u64 = 700_111_222_333;
    const PEER_RAW: u64 = 700_444_555_666;

    fn instance() -> InstanceId {
        InstanceId::new(INSTANCE_RAW).expect("nonzero instance")
    }

    fn peer() -> PeerId {
        PeerId::new(PEER_RAW).expect("nonzero peer")
    }

    fn engine<const QUEUE_CAPACITY: usize>(max_age_nanos: u64) -> InputEngine<QUEUE_CAPACITY> {
        InputEngine::new(
            instance(),
            peer(),
            MaxEventAge::from_nanos(max_age_nanos).expect("nonzero age"),
        )
    }

    #[test]
    fn zero_capacity_consumes_empty_before_first_admission() {
        let mut engine = engine::<0>(100);
        let epoch = engine.activate().unwrap();
        assert_eq!(engine.consume(epoch, at(10)), Ok(None));
        assert_eq!(
            engine.snapshot().state,
            EngineState::Active { generation: 1 }
        );
    }

    #[test]
    fn never_activated_engine_rejects_enqueue_without_changes() {
        let epoch = engine::<1>(100).activate().unwrap();
        let mut local = engine::<1>(100);
        let before = local.snapshot();
        assert_eq!(
            local.enqueue(epoch, at(10), key(10, 1, Transition::Down)),
            Err(EnqueueError::NoActiveRoute)
        );
        assert_eq!(local.snapshot(), before);
    }

    fn engine_with<const QUEUE_CAPACITY: usize>(
        instance_raw: u64,
        peer_raw: u64,
        max_age_nanos: u64,
    ) -> InputEngine<QUEUE_CAPACITY> {
        InputEngine::new(
            InstanceId::new(instance_raw).expect("nonzero instance"),
            PeerId::new(peer_raw).expect("nonzero peer"),
            MaxEventAge::from_nanos(max_age_nanos).expect("nonzero age"),
        )
    }

    fn at(nanos: u64) -> Timestamp {
        Timestamp::from_nanos(nanos)
    }

    fn key(nanos: u64, code: u16, transition: Transition) -> InputEvent {
        InputEvent::new(
            DeviceId::from_raw(1),
            Timestamp::from_nanos(nanos),
            EventKind::Key {
                code: KeyCode::from_raw(code),
                transition,
            },
        )
    }

    fn moved(nanos: u64, dx: f32, dy: f32) -> InputEvent {
        InputEvent::new(
            DeviceId::from_raw(1),
            Timestamp::from_nanos(nanos),
            EventKind::PointerMove { dx, dy },
        )
    }

    fn scroll(nanos: u64, dx: f32, dy: f32) -> InputEvent {
        InputEvent::new(
            DeviceId::from_raw(1),
            Timestamp::from_nanos(nanos),
            EventKind::Scroll { dx, dy },
        )
    }

    fn button(nanos: u64, pointer: PointerButton, transition: Transition) -> InputEvent {
        InputEvent::new(
            DeviceId::from_raw(1),
            Timestamp::from_nanos(nanos),
            EventKind::PointerButton {
                button: pointer,
                transition,
            },
        )
    }

    #[test]
    fn new_engine_is_local_empty_and_unfaulted() {
        let mut engine: InputEngine<4> = engine(1_000);

        assert_eq!(
            engine.snapshot(),
            EngineSnapshot {
                state: EngineState::Local,
                queued: 0,
                capacity: 4,
            }
        );
        assert!(engine.activate().is_ok());
    }

    #[test]
    fn max_age_zero_is_rejected() {
        assert_eq!(MaxEventAge::from_nanos(0), None);
        assert_eq!(
            MaxEventAge::from_nanos(1).map(MaxEventAge::as_nanos),
            Some(1)
        );
    }

    #[test]
    fn mixed_families_share_one_fifo_in_order() {
        let mut engine: InputEngine<8> = engine(10_000);
        let epoch = engine.activate().expect("activate");
        let now = at(10_000);

        let events = [
            key(10_000, 30, Transition::Down),
            moved(10_000, 1.5, -2.5),
            button(10_000, PointerButton::Primary, Transition::Up),
            scroll(10_000, 0.0, 3.0),
        ];
        for event in events {
            engine.enqueue(epoch, now, event).expect("admit");
        }
        assert_eq!(engine.snapshot().queued, 4);

        for event in events {
            assert_eq!(engine.consume(epoch, now), Ok(Some(event)));
        }
        assert_eq!(engine.consume(epoch, now), Ok(None));
    }

    #[test]
    fn sustained_cycles_wrap_the_ring_preserving_order() {
        let mut engine: InputEngine<3> = engine(10_000);
        let epoch = engine.activate().expect("activate");
        let now = at(10_000);

        let mut next_code: u16 = 1;
        let mut expected: VecDeque<u16> = VecDeque::new();
        for _ in 0..8 {
            // Fill the engine, then alternate pops and pushes so the ring's
            // head and tail indices advance past the boundary repeatedly.
            for _ in 0..3 {
                let code = next_code;
                next_code = next_code.wrapping_add(1);
                engine
                    .enqueue(epoch, now, key(10_000, code, Transition::Down))
                    .expect("fill");
                expected.push_back(code);
            }
            assert_eq!(engine.snapshot().queued, 3);
            for _ in 0..2 {
                // Free the oldest slot first, then wrap the tail into it.
                let oldest = expected.pop_front().expect("reference order");
                let event = engine.consume(epoch, now).expect("consume").expect("held");
                assert_eq!(
                    event,
                    key(10_000, oldest, Transition::Down),
                    "FIFO order broke at code {oldest}"
                );
                let code = next_code;
                next_code = next_code.wrapping_add(1);
                engine
                    .enqueue(epoch, now, key(10_000, code, Transition::Down))
                    .expect("wrap into freed slot");
                expected.push_back(code);
            }
            while let Some(oldest) = expected.pop_front() {
                let event = engine.consume(epoch, now).expect("consume").expect("held");
                assert_eq!(event, key(10_000, oldest, Transition::Down));
            }
            assert_eq!(engine.consume(epoch, now), Ok(None));
            assert_eq!(engine.snapshot().queued, 0);
        }
    }

    #[test]
    fn zero_capacity_faults_the_first_admission() {
        let mut engine: InputEngine<0> = engine(10_000);
        let epoch = engine.activate().expect("activate");

        assert_eq!(
            engine.enqueue(epoch, at(10_000), key(10_000, 30, Transition::Down)),
            Err(EnqueueError::Faulted(FaultReason::QueueFull))
        );
        assert_eq!(
            engine.snapshot().state,
            EngineState::Faulted {
                reason: FaultReason::QueueFull
            }
        );
        assert_eq!(engine.snapshot().queued, 0);
        assert_eq!(
            engine.consume(epoch, at(10_000)),
            Err(ConsumeError::NoActiveRoute)
        );
        assert_eq!(engine.activate(), Err(ActivateError::FaultLatched));
        assert_eq!(engine.discard_one(), Ok(None));
    }

    #[test]
    fn full_queue_fault_preserves_the_queued_release() {
        let mut engine: InputEngine<3> = engine(10_000);
        let epoch = engine.activate().expect("activate");
        let now = at(10_000);

        let press = key(10_000, 30, Transition::Down);
        let release = key(10_000, 30, Transition::Up);
        let scroll_delta = scroll(10_000, 0.5, -0.5);
        engine.enqueue(epoch, now, press).expect("press");
        engine.enqueue(epoch, now, release).expect("release");
        engine.enqueue(epoch, now, scroll_delta).expect("scroll");

        // The queue is full: one more valid event must fault, not overwrite.
        let overflow = key(10_000, 31, Transition::Down);
        assert_eq!(
            engine.enqueue(epoch, now, overflow),
            Err(EnqueueError::Faulted(FaultReason::QueueFull))
        );

        // Nothing is forwarded after the fault, and nothing was overwritten.
        assert_eq!(engine.consume(epoch, now), Err(ConsumeError::NoActiveRoute));
        assert_eq!(engine.snapshot().queued, 3);
        assert_eq!(engine.discard_one(), Ok(Some(press)));
        assert_eq!(engine.discard_one(), Ok(Some(release)));
        assert_eq!(engine.discard_one(), Ok(Some(scroll_delta)));
        assert_eq!(engine.discard_one(), Ok(None));
    }

    #[test]
    fn activations_allocate_increasing_distinct_generations() {
        let mut engine: InputEngine<2> = engine(1_000);

        let first = engine.activate().expect("first");
        assert_eq!(first.generation(), 1);
        engine.close(first).expect("close first");

        let second = engine.activate().expect("second");
        assert_eq!(second.generation(), 2);
        engine.close(second).expect("close second");

        let third = engine.activate().expect("third");
        assert_eq!(third.generation(), 3);

        assert_ne!(first, second);
        assert_ne!(second, third);
        assert_ne!(first, third);
    }

    #[test]
    fn stale_producer_epoch_is_rejected_without_faulting_the_route() {
        let mut engine: InputEngine<4> = engine(1_000);
        let first = engine.activate().expect("first");
        engine.close(first).expect("close first");
        let second = engine.activate().expect("second");
        assert_ne!(first, second);

        let event = key(100, 30, Transition::Down);
        assert_eq!(
            engine.enqueue(first, at(100), event),
            Err(EnqueueError::StaleEpoch)
        );

        // The active route is untouched: still open, still empty, not faulted.
        assert_eq!(
            engine.snapshot().state,
            EngineState::Active {
                generation: second.generation()
            }
        );
        assert_eq!(engine.snapshot().queued, 0);
        assert_eq!(engine.enqueue(second, at(100), event), Ok(()));
        assert_eq!(engine.snapshot().queued, 1);
    }

    #[test]
    fn stale_consumer_epoch_cannot_consume_the_new_generation() {
        let mut engine: InputEngine<4> = engine(1_000);
        let first = engine.activate().expect("first");
        engine.close(first).expect("close first");
        let second = engine.activate().expect("second");

        let event = key(100, 30, Transition::Down);
        engine.enqueue(second, at(100), event).expect("admit");

        assert_eq!(
            engine.consume(first, at(100)),
            Err(ConsumeError::StaleEpoch)
        );
        assert_eq!(engine.snapshot().queued, 1);

        assert_eq!(engine.consume(second, at(100)), Ok(Some(event)));
        assert_eq!(engine.consume(second, at(100)), Ok(None));
    }

    #[test]
    fn epochs_bind_instance_and_peer_identity() {
        let mut other_instance: InputEngine<2> = engine_with(111, 555, 10);
        let mut base: InputEngine<2> = engine_with(999, 555, 10);
        let mut other_peer: InputEngine<2> = engine_with(999, 777, 10);

        let base_epoch = base.activate().expect("base activation");
        let other_instance_epoch = other_instance
            .activate()
            .expect("other instance activation");
        let other_peer_epoch = other_peer.activate().expect("other peer activation");

        // Identical generation numbers never make epochs interchangeable.
        assert_eq!(base_epoch.generation(), other_instance_epoch.generation());
        assert_ne!(base_epoch, other_instance_epoch);
        assert_ne!(base_epoch, other_peer_epoch);

        let now = at(5);
        let event = key(5, 30, Transition::Down);
        assert_eq!(
            other_instance.enqueue(base_epoch, now, event),
            Err(EnqueueError::StaleEpoch),
            "an epoch minted by another instance must be stale here"
        );
        assert_eq!(
            other_instance.enqueue(other_instance_epoch, now, event),
            Ok(())
        );
        // A peer-only mismatch is stale at the engine's own checks, for every
        // epoch-gated operation, even against an empty queue.
        assert_eq!(
            other_peer.enqueue(base_epoch, now, event),
            Err(EnqueueError::StaleEpoch),
            "an epoch differing only in peer must be stale here"
        );
        assert_eq!(
            other_peer.consume(base_epoch, now),
            Err(ConsumeError::StaleEpoch)
        );
        assert_eq!(other_peer.close(base_epoch), Err(CloseError::StaleEpoch));
        assert_eq!(base.enqueue(base_epoch, now, event), Ok(()));
    }

    #[test]
    fn stale_close_is_rejected_and_admission_stays_open() {
        let mut engine: InputEngine<2> = engine(1_000);
        let mut other: InputEngine<2> = engine_with(999, 556, 1_000);
        let epoch = engine.activate().expect("activate");
        let foreign = other.activate().expect("foreign activate");

        assert_eq!(engine.close(foreign), Err(CloseError::StaleEpoch));
        assert_eq!(
            engine.snapshot().state,
            EngineState::Active {
                generation: epoch.generation()
            }
        );

        // The still-active route keeps working, then closes on its own epoch.
        assert_eq!(
            engine.enqueue(epoch, at(100), key(100, 30, Transition::Down)),
            Ok(())
        );
        assert_eq!(engine.close(epoch), Ok(()));
        assert_eq!(engine.close(epoch), Err(CloseError::NoActiveRoute));
        assert_eq!(other.close(foreign), Ok(()));
    }

    #[test]
    fn close_on_never_activated_engine_has_no_route() {
        let mut engine: InputEngine<2> = engine(1_000);
        let epoch = RouteEpoch {
            instance: instance(),
            peer: peer(),
            generation: 1,
        };

        assert_eq!(engine.close(epoch), Err(CloseError::NoActiveRoute));
    }

    #[test]
    fn generation_exhaustion_refuses_activation_leaving_state_unchanged() {
        let mut engine: InputEngine<2> = InputEngine::new_with_generation_floor(
            instance(),
            peer(),
            MaxEventAge::from_nanos(1_000).expect("nonzero age"),
            u64::MAX,
        );
        assert_eq!(engine.last_generation(), u64::MAX);

        assert_eq!(engine.activate(), Err(ActivateError::GenerationExhausted));
        assert_eq!(
            engine.snapshot(),
            EngineSnapshot {
                state: EngineState::Local,
                queued: 0,
                capacity: 2,
            }
        );
        assert_eq!(engine.activate(), Err(ActivateError::GenerationExhausted));
        assert_eq!(engine.last_generation(), u64::MAX, "nothing changed");

        // u64::MAX itself remains allocatable; only the step beyond it fails.
        let mut boundary: InputEngine<2> = InputEngine::new_with_generation_floor(
            instance(),
            peer(),
            MaxEventAge::from_nanos(1_000).expect("nonzero age"),
            u64::MAX - 1,
        );
        let epoch = boundary.activate().expect("allocate MAX");
        assert_eq!(epoch.generation(), u64::MAX);
        assert_eq!(boundary.last_generation(), u64::MAX);
        boundary.close(epoch).expect("close");
        assert_eq!(boundary.activate(), Err(ActivateError::GenerationExhausted));
    }

    #[test]
    fn close_stops_forwarding_and_requires_discard_before_reactivation() {
        let mut engine: InputEngine<4> = engine(10_000);
        let epoch = engine.activate().expect("activate");
        let now = at(10_000);
        let first = key(10_000, 30, Transition::Down);
        let second = scroll(10_000, 0.25, 0.75);
        engine.enqueue(epoch, now, first).expect("first");
        engine.enqueue(epoch, now, second).expect("second");

        assert_eq!(engine.close(epoch), Ok(()));
        assert_eq!(
            engine.snapshot(),
            EngineSnapshot {
                state: EngineState::Local,
                queued: 2,
                capacity: 4,
            }
        );

        // Held input is never forwarded after close, under any epoch.
        assert_eq!(
            engine.enqueue(epoch, now, key(10_000, 31, Transition::Down)),
            Err(EnqueueError::NoActiveRoute)
        );
        assert_eq!(engine.consume(epoch, now), Err(ConsumeError::NoActiveRoute));

        // Reactivation waits for explicit, ordered discard.
        assert_eq!(engine.activate(), Err(ActivateError::QueueNotEmpty));
        assert_eq!(engine.discard_one(), Ok(Some(first)));
        assert_eq!(engine.discard_one(), Ok(Some(second)));
        assert_eq!(engine.discard_one(), Ok(None));

        let reopened = engine.activate().expect("reactivate");
        assert_eq!(reopened.generation(), 2);
        assert_eq!(
            engine.enqueue(reopened, now, key(10_000, 32, Transition::Down)),
            Ok(())
        );
        assert_eq!(
            engine.consume(reopened, now),
            Ok(Some(key(10_000, 32, Transition::Down)))
        );
    }

    #[test]
    fn activation_while_active_is_refused_unchanged() {
        let mut engine: InputEngine<2> = engine(1_000);
        let epoch = engine.activate().expect("activate");

        assert_eq!(engine.activate(), Err(ActivateError::NotLocal));
        assert_eq!(
            engine.snapshot().state,
            EngineState::Active {
                generation: epoch.generation()
            }
        );
        assert_eq!(
            engine.enqueue(epoch, at(100), key(100, 30, Transition::Down)),
            Ok(())
        );
    }

    #[test]
    fn non_finite_motion_and_scroll_fault_admission_and_preserve_entries() {
        let cases = [
            moved(100, f32::NAN, 0.0),
            moved(100, 0.0, f32::NEG_INFINITY),
            moved(100, f32::INFINITY, f32::INFINITY),
            scroll(100, f32::NAN, f32::NAN),
            scroll(100, f32::INFINITY, 0.0),
        ];
        for case in cases {
            let mut engine: InputEngine<2> = engine(10_000);
            let epoch = engine.activate().expect("activate");
            assert_eq!(
                engine.enqueue(epoch, at(100), case),
                Err(EnqueueError::Faulted(FaultReason::NonFiniteInput)),
                "case {case:?} must fault as non-finite"
            );
            assert_eq!(
                engine.snapshot().state,
                EngineState::Faulted {
                    reason: FaultReason::NonFiniteInput
                }
            );
        }

        // Validity is decided before capacity: a non-finite event names the
        // defect even when the queue is already full, and the earlier entry
        // survives for discard.
        let mut engine: InputEngine<1> = engine(10_000);
        let epoch = engine.activate().expect("activate");
        let valid = key(100, 30, Transition::Down);
        engine.enqueue(epoch, at(100), valid).expect("fill");
        assert_eq!(
            engine.enqueue(epoch, at(100), moved(100, f32::NAN, 0.0)),
            Err(EnqueueError::Faulted(FaultReason::NonFiniteInput))
        );
        assert_eq!(engine.discard_one(), Ok(Some(valid)));
    }

    #[test]
    fn future_timestamps_fault_and_now_is_the_inclusive_boundary() {
        let mut engine: InputEngine<2> = engine(10_000);
        let epoch = engine.activate().expect("activate");

        assert_eq!(
            engine.enqueue(epoch, at(1_000), key(1_001, 30, Transition::Down)),
            Err(EnqueueError::Faulted(FaultReason::FutureTimestamp))
        );
        assert_eq!(
            engine.snapshot().state,
            EngineState::Faulted {
                reason: FaultReason::FutureTimestamp
            }
        );

        let mut boundary: InputEngine<2> = engine_with(INSTANCE_RAW, PEER_RAW, 10_000);
        let epoch = boundary.activate().expect("activate");
        assert_eq!(
            boundary.enqueue(epoch, at(1_000), key(1_000, 30, Transition::Down)),
            Ok(()),
            "an event captured exactly at now is not future"
        );
    }

    #[test]
    fn admission_age_boundary_is_inclusive() {
        let mut at_limit: InputEngine<2> = engine(500);
        let at_limit_epoch = at_limit.activate().expect("activate");
        assert_eq!(
            at_limit.enqueue(at_limit_epoch, at(1_500), key(1_000, 30, Transition::Down)),
            Ok(()),
            "age exactly at the limit must be admitted"
        );

        let mut over_limit: InputEngine<2> = engine(500);
        let over_limit_epoch = over_limit.activate().expect("activate");
        assert_eq!(
            over_limit.enqueue(
                over_limit_epoch,
                at(1_501),
                key(1_000, 30, Transition::Down)
            ),
            Err(EnqueueError::Faulted(FaultReason::ExcessiveAge))
        );
        assert_eq!(
            over_limit.snapshot().state,
            EngineState::Faulted {
                reason: FaultReason::ExcessiveAge
            }
        );
    }

    #[test]
    fn expiry_while_queued_faults_without_dequeueing_or_forwarding() {
        let mut engine: InputEngine<4> = engine(1_000);
        let epoch = engine.activate().expect("activate");
        let expired = key(1_000, 30, Transition::Down);
        let later = scroll(1_100, 0.5, 0.5);
        engine.enqueue(epoch, at(1_000), expired).expect("first");
        engine.enqueue(epoch, at(1_100), later).expect("second");

        // One nanosecond past the limit while still held: fault, no dequeue.
        assert_eq!(
            engine.consume(epoch, at(2_501)),
            Err(ConsumeError::Faulted(FaultReason::StaleQueuedInput))
        );
        assert_eq!(
            engine.snapshot().state,
            EngineState::Faulted {
                reason: FaultReason::StaleQueuedInput
            }
        );
        assert_eq!(engine.snapshot().queued, 2, "expired entry stays held");

        // No forwarding and no reactivation after the fault.
        assert_eq!(
            engine.consume(epoch, at(2_501)),
            Err(ConsumeError::NoActiveRoute)
        );
        assert_eq!(
            engine.enqueue(epoch, at(2_501), key(2_501, 31, Transition::Down)),
            Err(EnqueueError::NoActiveRoute)
        );
        assert_eq!(engine.activate(), Err(ActivateError::FaultLatched));

        // Both entries remain, in order, for explicit discard.
        assert_eq!(engine.discard_one(), Ok(Some(expired)));
        assert_eq!(engine.discard_one(), Ok(Some(later)));
        assert_eq!(engine.discard_one(), Ok(None));
    }

    #[test]
    fn consumption_age_boundary_is_inclusive() {
        let mut engine: InputEngine<4> = engine(1_000);
        let epoch = engine.activate().expect("activate");
        let first = key(1_000, 30, Transition::Down);
        let second = key(1_100, 31, Transition::Down);
        engine.enqueue(epoch, at(1_000), first).expect("first");
        engine.enqueue(epoch, at(1_100), second).expect("second");

        assert_eq!(
            engine.consume(epoch, at(2_000)),
            Ok(Some(first)),
            "age exactly at the limit must still consume"
        );
        assert_eq!(engine.consume(epoch, at(2_100)), Ok(Some(second)));
        assert_eq!(engine.consume(epoch, at(2_100)), Ok(None));
    }

    #[test]
    fn fault_latches_with_no_unlatch_path() {
        let mut engine: InputEngine<2> = engine(10_000);
        let epoch = engine.activate().expect("activate");
        let held = key(10_000, 30, Transition::Down);
        let second = key(10_000, 31, Transition::Down);
        engine.enqueue(epoch, at(10_000), held).expect("first");
        engine.enqueue(epoch, at(10_000), second).expect("second");
        // The third admission attempt overflows and latches the fault.
        engine
            .enqueue(epoch, at(10_000), key(10_000, 32, Transition::Down))
            .expect_err("full queue");

        // Every reopening path is refused; only discard still functions.
        assert_eq!(engine.activate(), Err(ActivateError::FaultLatched));
        assert_eq!(engine.close(epoch), Err(CloseError::NoActiveRoute));
        assert_eq!(engine.discard_one(), Ok(Some(held)));
        assert_eq!(engine.discard_one(), Ok(Some(second)));
        assert_eq!(engine.activate(), Err(ActivateError::FaultLatched));
        assert_eq!(engine.discard_one(), Ok(None));
    }

    #[test]
    fn empty_consumption_succeeds_but_only_with_the_exact_epoch() {
        let mut engine: InputEngine<2> = engine(1_000);
        let epoch = engine.activate().expect("activate");
        let mut other: InputEngine<2> = engine_with(999, 556, 1_000);
        let foreign = other.activate().expect("foreign activate");

        assert_eq!(engine.consume(epoch, at(100)), Ok(None));
        assert_eq!(
            engine.consume(foreign, at(100)),
            Err(ConsumeError::StaleEpoch),
            "the epoch is checked even when the queue is empty"
        );
        assert_eq!(engine.snapshot().queued, 0);
    }

    #[test]
    fn former_epoch_after_close_is_no_active_route() {
        let mut engine: InputEngine<2> = engine(1_000);
        let epoch = engine.activate().expect("activate");
        engine.close(epoch).expect("close");

        // The route is gone entirely; this is not a stale-epoch case.
        assert_eq!(
            engine.enqueue(epoch, at(100), key(100, 30, Transition::Down)),
            Err(EnqueueError::NoActiveRoute)
        );
        assert_eq!(
            engine.consume(epoch, at(100)),
            Err(ConsumeError::NoActiveRoute)
        );
    }

    #[test]
    fn discard_is_refused_while_admission_is_open() {
        let mut engine: InputEngine<2> = engine(1_000);
        let epoch = engine.activate().expect("activate");
        engine
            .enqueue(epoch, at(100), key(100, 30, Transition::Down))
            .expect("admit");

        assert_eq!(engine.discard_one(), Err(DiscardError::AdmissionOpen));
        assert_eq!(engine.snapshot().queued, 1);
        assert_eq!(
            engine.consume(epoch, at(100)),
            Ok(Some(key(100, 30, Transition::Down))),
            "consumption still functions after the refused discard"
        );
    }

    #[test]
    fn debug_and_snapshots_redact_content_and_identities() {
        let mut engine: InputEngine<4> = engine_with(700_111_222_333, 700_444_555_666, 5_000);
        let epoch = engine.activate().expect("activate");
        engine
            .enqueue(
                epoch,
                at(999_999_999),
                InputEvent::new(
                    DeviceId::from_raw(48_879),
                    at(999_999_999),
                    EventKind::Key {
                        code: KeyCode::from_raw(48_879),
                        transition: Transition::Down,
                    },
                ),
            )
            .expect("admit");
        engine
            .enqueue(epoch, at(999_999_999), moved(999_999_999, 123.25, -0.5))
            .expect("admit");

        let engine_text = format!("{engine:?}");
        let snapshot_text = format!("{:?}", engine.snapshot());
        let epoch_text = format!("{epoch:?}");
        let texts = [&engine_text, &snapshot_text, &epoch_text];

        for text in texts {
            assert!(!text.contains("700111222333"), "instance leak: {text}");
            assert!(!text.contains("700444555666"), "peer leak: {text}");
            assert!(!text.contains("48879"), "device or key leak: {text}");
            assert!(!text.contains("999999999"), "timestamp leak: {text}");
            assert!(!text.contains("123.25"), "motion leak: {text}");
        }
        assert_eq!(epoch_text, "RouteEpoch([REDACTED])");
        assert!(engine_text.contains("InputEngine"));
        assert!(snapshot_text.contains("queued: 2"));
    }

    #[test]
    fn stale_epoch_with_a_defective_event_cannot_fault_the_route() {
        let mut engine: InputEngine<2> = engine(1_000);
        let first = engine.activate().expect("first");
        engine.close(first).expect("close first");
        let second = engine.activate().expect("second");

        // Each stale call carries a defect that would fault if it were ever
        // validated: non-finite, future, and excessive age.
        assert_eq!(
            engine.enqueue(first, at(100), moved(100, f32::NAN, 0.0)),
            Err(EnqueueError::StaleEpoch)
        );
        assert_eq!(
            engine.enqueue(first, at(100), key(101, 30, Transition::Down)),
            Err(EnqueueError::StaleEpoch)
        );
        assert_eq!(
            engine.enqueue(first, at(2_000), key(100, 30, Transition::Down)),
            Err(EnqueueError::StaleEpoch)
        );
        assert_eq!(
            engine.snapshot().state,
            EngineState::Active {
                generation: second.generation()
            }
        );
        assert_eq!(engine.snapshot().queued, 0);

        // A stale enqueue onto a full queue must not fault either.
        let mut full: InputEngine<1> = engine_with(INSTANCE_RAW, PEER_RAW, 1_000);
        let old = full.activate().expect("first");
        full.close(old).expect("close first");
        let live = full.activate().expect("second");
        full.enqueue(live, at(100), key(100, 30, Transition::Down))
            .expect("fill");
        assert_eq!(
            full.enqueue(old, at(100), key(100, 31, Transition::Down)),
            Err(EnqueueError::StaleEpoch),
            "a stale epoch onto a full queue must not fault the route"
        );
        assert_eq!(
            full.snapshot().state,
            EngineState::Active {
                generation: live.generation()
            }
        );
        assert_eq!(full.snapshot().queued, 1);
    }

    #[test]
    fn stale_consumer_meeting_an_expired_head_cannot_fault_the_route() {
        let mut engine: InputEngine<2> = engine(1_000);
        let first = engine.activate().expect("first");
        engine.close(first).expect("close first");
        let second = engine.activate().expect("second");
        engine
            .enqueue(second, at(1_000), key(1_000, 30, Transition::Down))
            .expect("admit");

        // The head has expired by this later time, but the epoch is checked
        // before the age check can fault.
        assert_eq!(
            engine.consume(first, at(5_000)),
            Err(ConsumeError::StaleEpoch)
        );
        assert_eq!(
            engine.snapshot().state,
            EngineState::Active {
                generation: second.generation()
            }
        );
        assert_eq!(engine.snapshot().queued, 1);

        // The live epoch then faults on the same expired head.
        assert_eq!(
            engine.consume(second, at(5_000)),
            Err(ConsumeError::Faulted(FaultReason::StaleQueuedInput))
        );
    }

    #[test]
    fn replacement_engine_continuing_the_counter_refuses_predecessor_epochs() {
        let mut predecessor: InputEngine<2> = engine_with(999, 555, 1_000);
        let old_epoch = predecessor.activate().expect("predecessor route");
        predecessor
            .enqueue(old_epoch, at(100), key(100, 30, Transition::Down))
            .expect("fill");
        predecessor
            .enqueue(old_epoch, at(100), key(100, 31, Transition::Down))
            .expect("fill");
        predecessor
            .enqueue(old_epoch, at(100), key(100, 32, Transition::Down))
            .expect_err("overflow latches the terminal fault");

        // Same process, same identities: the replacement must continue the
        // counter, not restart it. The floor comes from the predecessor's own
        // accessor, the documented recovery path.
        assert_eq!(predecessor.last_generation(), old_epoch.generation());
        let mut replacement: InputEngine<2> = InputEngine::new_with_generation_floor(
            InstanceId::new(999).expect("nonzero instance"),
            PeerId::new(555).expect("nonzero peer"),
            MaxEventAge::from_nanos(1_000).expect("nonzero age"),
            predecessor.last_generation(),
        );
        let fresh = replacement.activate().expect("replacement route");
        assert_eq!(fresh.generation(), 2);
        assert_ne!(fresh, old_epoch);

        let now = at(100);
        let event = key(100, 33, Transition::Down);
        assert_eq!(
            replacement.enqueue(old_epoch, now, event),
            Err(EnqueueError::StaleEpoch),
            "a predecessor epoch must be stale on its replacement"
        );
        assert_eq!(
            replacement.consume(old_epoch, now),
            Err(ConsumeError::StaleEpoch)
        );
        assert_eq!(replacement.close(old_epoch), Err(CloseError::StaleEpoch));
        assert_eq!(replacement.enqueue(fresh, now, event), Ok(()));
        assert_eq!(replacement.consume(fresh, now), Ok(Some(event)));

        // A floor at the counter bound refuses every activation, unchanged.
        let mut exhausted: InputEngine<2> = InputEngine::new_with_generation_floor(
            InstanceId::new(999).expect("nonzero instance"),
            PeerId::new(555).expect("nonzero peer"),
            MaxEventAge::from_nanos(1_000).expect("nonzero age"),
            u64::MAX,
        );
        assert_eq!(
            exhausted.activate(),
            Err(ActivateError::GenerationExhausted)
        );
        assert_eq!(exhausted.snapshot().state, EngineState::Local);
    }

    #[test]
    fn invalid_event_faults_leave_nothing_queued_and_preserve_earlier_entries() {
        // A rejected invalid event is not queued on an empty engine.
        let mut empty: InputEngine<2> = engine(1_000);
        let epoch = empty.activate().expect("activate");
        assert_eq!(
            empty.enqueue(epoch, at(100), moved(100, f32::NAN, 0.0)),
            Err(EnqueueError::Faulted(FaultReason::NonFiniteInput))
        );
        assert_eq!(empty.snapshot().queued, 0);
        assert_eq!(empty.discard_one(), Ok(None));

        // Future and too-old faults preserve earlier valid entries, and the
        // rejected event never enters the queue.
        let cases = [
            (
                key(2_000, 31, Transition::Down),
                at(1_500),
                FaultReason::FutureTimestamp,
            ),
            (
                key(0, 31, Transition::Down),
                at(1_500),
                FaultReason::ExcessiveAge,
            ),
        ];
        for (rejected, now, reason) in cases {
            let mut engine: InputEngine<2> = engine(1_000);
            let epoch = engine.activate().expect("activate");
            let held = key(1_000, 30, Transition::Down);
            engine.enqueue(epoch, at(1_000), held).expect("admit");
            assert_eq!(
                engine.enqueue(epoch, now, rejected),
                Err(EnqueueError::Faulted(reason))
            );
            assert_eq!(engine.snapshot().queued, 1, "earlier entry preserved");
            assert_eq!(engine.discard_one(), Ok(Some(held)));
            assert_eq!(
                engine.discard_one(),
                Ok(None),
                "the rejected event was never queued"
            );
        }
    }

    #[test]
    fn clock_regression_at_consumption_faults_without_forwarding() {
        let mut engine: InputEngine<2> = engine(1_000);
        let epoch = engine.activate().expect("activate");
        let held = key(1_000, 30, Transition::Down);
        engine.enqueue(epoch, at(1_000), held).expect("admit");

        // A supplied now before the event violates the one-clock contract;
        // the consumption-side check treats it as an age violation and faults
        // rather than trusting wrapping arithmetic.
        assert_eq!(
            engine.consume(epoch, at(999)),
            Err(ConsumeError::Faulted(FaultReason::StaleQueuedInput))
        );
        assert_eq!(engine.snapshot().queued, 1);
        assert_eq!(engine.discard_one(), Ok(Some(held)));
        assert_eq!(engine.discard_one(), Ok(None));
    }

    #[test]
    fn capacity_one_full_queue_fault_preserves_the_held_event() {
        let mut engine: InputEngine<1> = engine(1_000);
        let epoch = engine.activate().expect("activate");
        let held = key(100, 30, Transition::Down);
        engine.enqueue(epoch, at(100), held).expect("fill");

        assert_eq!(
            engine.enqueue(epoch, at(100), key(100, 31, Transition::Down)),
            Err(EnqueueError::Faulted(FaultReason::QueueFull))
        );
        assert_eq!(engine.snapshot().queued, 1);
        assert_eq!(
            engine.consume(epoch, at(100)),
            Err(ConsumeError::NoActiveRoute)
        );
        assert_eq!(engine.discard_one(), Ok(Some(held)));
        assert_eq!(engine.discard_one(), Ok(None));
    }
}
