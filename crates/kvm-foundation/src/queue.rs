//! Fixed-capacity, single-owner FIFO storage for `Copy` values.

/// A fixed-capacity FIFO ring buffer for `Copy` values, with all `N` slots
/// stored inline.
///
/// This is plain storage for exactly one owner. It performs no allocation (all
/// storage is inline), uses no `unsafe` code, and contains no synchronization.
/// There is intentionally no iteration, draining or coalescing API: any drop,
/// coalescing or backpressure policy belongs to the caller, not to this queue.
///
/// # Single owner, no synchronization
///
/// This queue is **not synchronized**: it holds no locks or atomics, and its
/// methods must not be called concurrently from several threads. Its owner
/// serializes every access; it is not a cross-thread queue.
///
/// # Full queues never lose ordered values
///
/// Pushing onto a full queue returns the value unchanged and never overwrites,
/// replaces or drops anything already queued, so ordered key and button
/// transitions cannot disappear silently. The caller decides what to do with a
/// rejected value.
///
/// Capacity zero is well defined: the queue is always full, every push is
/// rejected with the value unchanged, and every pop returns `None`. No method
/// panics.
#[derive(Clone)]
pub struct RingFifo<T, const N: usize> {
    slots: [Option<T>; N],
    head: usize,
    len: usize,
}

impl<T, const N: usize> core::fmt::Debug for RingFifo<T, N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RingFifo")
            .field("len", &self.len)
            .field("capacity", &N)
            .finish_non_exhaustive()
    }
}

impl<T: Copy, const N: usize> RingFifo<T, N> {
    /// Creates an empty queue with capacity `N`.
    #[must_use]
    pub const fn new() -> Self {
        // An inline const repeat initializes any capacity, including zero,
        // without requiring `Copy` on the slot type.
        Self {
            slots: [const { None }; N],
            head: 0,
            len: 0,
        }
    }

    /// Returns the number of values currently queued.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no values are queued.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the fixed capacity `N`.
    #[must_use]
    #[allow(
        clippy::unused_self,
        reason = "instance accessor matches len/is_full without exposing storage"
    )]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns `true` when the queue holds exactly `N` values.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Appends `value` as the newest entry.
    ///
    /// # Errors
    ///
    /// Returns the original `value` unchanged in `Err` when the queue is
    /// already full. Queued values are never overwritten or dropped.
    pub fn push(&mut self, value: T) -> Result<(), T> {
        // A zero-capacity queue is always full, so the modulo below is only
        // ever evaluated with `N >= 1`.
        if self.len == N {
            return Err(value);
        }
        let tail = (self.head + self.len) % N;
        self.slots[tail] = Some(value);
        self.len += 1;
        Ok(())
    }

    /// Removes and returns the oldest queued value, or `None` when the queue
    /// is empty.
    pub fn pop(&mut self) -> Option<T> {
        // A zero-capacity queue is always empty, so the modulo below is only
        // ever evaluated with `N >= 1`.
        if self.len == 0 {
            return None;
        }
        let value = self.slots[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        value
    }
}

impl<T: Copy, const N: usize> Default for RingFifo<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::RingFifo;
    use crate::event::{DeviceId, EventKind, InputEvent, KeyCode, Timestamp, Transition};
    use std::collections::VecDeque;

    fn key_event(nanos: u64, code: u16) -> InputEvent {
        InputEvent::new(
            DeviceId::from_raw(1),
            Timestamp::from_nanos(nanos),
            EventKind::Key {
                code: KeyCode::from_raw(code),
                transition: Transition::Down,
            },
        )
    }

    /// A tiny deterministic xorshift generator so the reference test needs no
    /// random-number dependency.
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn new_queue_is_empty_and_reports_its_capacity() {
        let queue: RingFifo<u32, 5> = RingFifo::new();

        assert_eq!(queue.capacity(), 5);
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
        assert!(!queue.is_full());
    }

    #[test]
    fn default_is_an_empty_queue() {
        let queue: RingFifo<u16, 3> = RingFifo::default();

        assert!(queue.is_empty());
        assert_eq!(queue.capacity(), 3);
    }

    #[test]
    fn zero_capacity_is_well_defined() {
        let mut queue: RingFifo<InputEvent, 0> = RingFifo::new();

        assert_eq!(queue.capacity(), 0);
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
        assert!(queue.is_full());

        let rejected = key_event(1, 30);
        assert_eq!(queue.push(rejected), Err(rejected));
        assert_eq!(queue.pop(), None);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn one_capacity_round_trips_repeatedly() {
        let mut queue: RingFifo<_, 1> = RingFifo::new();

        for round in 0..10u64 {
            let accepted = key_event(round, 7);
            let refused = key_event(round, 8);

            assert_eq!(queue.push(accepted), Ok(()));
            assert!(queue.is_full());
            assert_eq!(queue.push(refused), Err(refused));
            assert_eq!(queue.pop(), Some(accepted));
            assert!(queue.is_empty());
            assert_eq!(queue.pop(), None);
        }
    }

    #[test]
    fn full_push_is_rejected_without_disturbing_queued_events() {
        let mut queue: RingFifo<_, 3> = RingFifo::new();
        let first = key_event(10, 30);
        let second = key_event(11, 31);
        let third = key_event(12, 32);

        queue.push(first).unwrap();
        queue.push(second).unwrap();
        queue.push(third).unwrap();
        assert!(queue.is_full());
        assert_eq!(queue.len(), 3);

        // The rejected item comes back unchanged, and nothing already queued
        // is overwritten, reordered or dropped.
        let overflow = key_event(13, 33);
        assert_eq!(queue.push(overflow), Err(overflow));
        assert_eq!(queue.len(), 3);

        assert_eq!(queue.pop(), Some(first));
        assert_eq!(queue.pop(), Some(second));
        assert_eq!(queue.pop(), Some(third));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn wraps_around_the_ring_preserving_fifo_order() {
        let mut queue: RingFifo<u32, 3> = RingFifo::new();

        for value in 0..3 {
            queue.push(value).unwrap();
        }
        assert_eq!(queue.pop(), Some(0));

        // This write lands in the freed slot 0: the tail wraps.
        queue.push(3).unwrap();
        assert_eq!(queue.pop(), Some(1));
        queue.push(4).unwrap();

        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), Some(4));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn head_wraps_repeatedly_while_values_stay_queued() {
        let mut queue: RingFifo<u64, 3> = RingFifo::new();
        let mut pushed = 0_u64;
        let mut popped = 0_u64;

        for _ in 0..64 {
            // Six steps per cycle: occupancy rises to two and falls back to
            // empty while three pops advance `head` one full lap around the
            // ring, with the tail wrapping into a freed slot on the way.
            queue.push(pushed).unwrap();
            pushed += 1;
            assert_eq!(queue.pop(), Some(popped));
            popped += 1;
            queue.push(pushed).unwrap();
            pushed += 1;
            queue.push(pushed).unwrap();
            pushed += 1;
            assert!(!queue.is_empty());
            assert_eq!(queue.pop(), Some(popped));
            popped += 1;
            assert_eq!(queue.pop(), Some(popped));
            popped += 1;
        }

        assert!(queue.is_empty());
        assert_eq!(pushed, popped);
    }

    #[test]
    fn sustained_full_drain_cycles_keep_fifo_order() {
        let mut queue: RingFifo<u64, 4> = RingFifo::new();
        let mut pushed = 0_u64;
        let mut popped = 0_u64;

        for _ in 0..64 {
            for _ in 0..4 {
                queue.push(pushed).unwrap();
                pushed += 1;
            }
            assert!(queue.is_full());
            for _ in 0..4 {
                assert_eq!(queue.pop(), Some(popped));
                popped += 1;
            }
            assert!(queue.is_empty());
        }
        assert_eq!(pushed, popped);
    }

    #[test]
    fn interleaved_operations_match_a_vecdeque_reference() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut queue: RingFifo<u64, 8> = RingFifo::new();
        let mut reference: VecDeque<u64> = VecDeque::new();
        let mut next_value = 0_u64;

        for _ in 0..10_000 {
            match xorshift(&mut state) % 4 {
                0 | 1 => {
                    let value = next_value;
                    next_value += 1;
                    match queue.push(value) {
                        Ok(()) => reference.push_back(value),
                        Err(returned) => {
                            assert_eq!(returned, value);
                            assert_eq!(reference.len(), 8);
                        }
                    }
                }
                2 => {
                    assert_eq!(queue.pop(), reference.pop_front());
                }
                _ => {}
            }
            assert_eq!(queue.len(), reference.len());
            assert_eq!(queue.is_empty(), reference.is_empty());
            assert_eq!(queue.is_full(), reference.len() == 8);
        }

        while let Some(expected) = reference.pop_front() {
            assert_eq!(queue.pop(), Some(expected));
        }
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn clone_duplicates_contents_independently() {
        let mut queue: RingFifo<u32, 4> = RingFifo::new();
        queue.push(0).unwrap();
        queue.push(1).unwrap();

        let mut duplicate = queue.clone();
        assert_eq!(queue.pop(), Some(0));
        assert_eq!(duplicate.pop(), Some(0));
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(duplicate.pop(), Some(1));
        assert_eq!(queue.pop(), None);
        assert_eq!(duplicate.pop(), None);
    }

    #[test]
    fn debug_output_redacts_queued_values() {
        let mut queue: RingFifo<u32, 2> = RingFifo::new();
        queue.push(987_654).unwrap();

        let text = format!("{queue:?}");
        assert!(!text.contains("987654"), "queued payload leaked: {text}");
        assert!(text.contains("len: 1"));
        assert!(text.contains("capacity: 2"));
    }

    #[test]
    fn queues_staging_real_events_in_fifo_order() {
        let mut queue: RingFifo<_, 8> = RingFifo::new();
        let key = key_event(1, 30);
        let release = InputEvent::new(
            DeviceId::from_raw(1),
            Timestamp::from_nanos(2),
            EventKind::Key {
                code: KeyCode::from_raw(30),
                transition: Transition::Up,
            },
        );
        let move_delta = InputEvent::new(
            DeviceId::from_raw(1),
            Timestamp::from_nanos(3),
            EventKind::PointerMove { dx: 4.5, dy: -1.25 },
        );

        queue.push(key).unwrap();
        queue.push(release).unwrap();
        queue.push(move_delta).unwrap();

        assert_eq!(queue.pop(), Some(key));
        assert_eq!(queue.pop(), Some(release));
        assert_eq!(queue.pop(), Some(move_delta));
        assert_eq!(queue.pop(), None);
    }
}
