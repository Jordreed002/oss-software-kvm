//! Dependency-free microbenchmark for the bounded input admission hot path.
//!
//! Times the foundation [`RingFifo`], the accepted [`InputEngine`] admission
//! and consumption path, and the [`HeldSet`] press/release ledger on synthetic
//! events under a synthetic monotonic clock. Run with
//! `cargo bench -p kvm-input-engine --bench input_path`.
//!
//! # Measurement contract
//!
//! * Whole batches are timed with `Instant`; no individual event is ever
//!   timed, and no per-event latency or tail distribution is reported.
//! * Each scenario prints its exact warmup batch count, measured sample
//!   count, operations per batch, whole-batch min/median/p95 nanoseconds, and
//!   the amortized ns/op derived by explicit division of those numbers.
//! * Inputs and mutable state cross a `std::hint::black_box` boundary on every
//!   operation; outcomes feed an asserted checksum. Per-op figures include
//!   those boundaries and the loop overhead.
//! * Semantic checks (FIFO order, fault latching, retention of held entries)
//!   run only outside timed batches, after measurement completes.
//!
//! # Scope limits
//!
//! This microbenchmark exercises userspace data-structure calls on one thread
//! of one process. It measures no physical capture, no network transport, no
//! native input injection and no encryption, and its numbers must not be read
//! as claims about any of those paths.

use std::hint::black_box;
use std::time::Instant;

use kvm_foundation::{
    DeviceId, EventKind, HeldControl, HeldSet, InputEvent, KeyCode, PointerButton, RingFifo,
    Timestamp, Transition,
};
use kvm_input_engine::{
    ConsumeError, EngineState, EnqueueError, FaultReason, InputEngine, InstanceId, MaxEventAge,
    PeerId, RouteEpoch,
};

/// Untimed batches run before measurement, to warm caches and the timer.
const WARMUP_BATCHES: usize = 3;
/// Timed batches per scenario; every batch yields one whole-batch sample.
const SAMPLES: usize = 30;
/// Distinct synthetic events per pool, cycled through by index.
const POOL_LEN: usize = 64;
/// Queue capacity of every benchmarked engine.
const ENGINE_CAP: usize = 16;
/// Engines per batch for one-shot fault scenarios (each faults exactly once).
const FAULT_ENGINES: usize = 512;
/// Synthetic "now" on the host-local monotonic clock, in nanoseconds.
const NOW_NANOS: u64 = 10_000_000_000_000;
/// Synthetic admission age bound: 100 ms in nanoseconds.
const MAX_AGE_NANOS: u64 = 100_000_000;

fn main() {
    println!("input-path microbenchmark: synthetic events, synthetic clock, one thread");
    println!("timing unit: whole batch; stats: min/median/p95 (nearest-rank p95)");
    println!("scope: userspace admission data structures only; no physical capture,");
    println!("network, native injection or encryption is measured or claimed");
    println!();
    bench_ring_fifo_pair();
    bench_ring_fifo_wraparound();
    bench_engine_enqueue_consume_mixed_pair();
    bench_engine_stale_epoch_rejection();
    bench_engine_full_rejection();
    bench_engine_queued_age_expiry();
    bench_held_set_press_release_pair();
    println!();
    println!("done: every semantic check passed outside the timed batches");
}

/// Runs `run_batch` for warmup then samples, collecting each batch's
/// self-reported elapsed nanoseconds and an exact outcome checksum.
///
/// Each scenario times only its own hot loop inside the closure, so
/// per-batch engine reconstruction can stay outside the timed window.
fn measure_batches(mut run_batch: impl FnMut() -> (u128, u64)) -> (Vec<u128>, u64) {
    let mut checksum = 0_u64;
    for _ in 0..WARMUP_BATCHES {
        let (elapsed, contribution) = run_batch();
        checksum = checksum.wrapping_add(contribution);
        black_box((elapsed, checksum));
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (elapsed, contribution) = run_batch();
        checksum = checksum.wrapping_add(contribution);
        samples.push(elapsed);
    }
    (samples, checksum)
}

/// Whole-batch min, median (mean of the middle pair) and nearest-rank p95.
fn batch_stats(samples: &mut [u128]) -> (u128, u128, u128) {
    samples.sort_unstable();
    let count = samples.len();
    let min = samples[0];
    let median = samples[count / 2 - 1].midpoint(samples[count / 2]);
    let p95 = samples[(count * 95).div_ceil(100) - 1];
    (min, median, p95)
}

/// Groups an integer nanosecond count with `_` separators for readability.
fn fmt_ns(value: u128) -> String {
    let digits = value.to_string();
    let len = digits.len();
    if len <= 3 {
        return digits;
    }
    let mut grouped = String::with_capacity(len + len / 3);
    let head = len % 3;
    if head > 0 {
        grouped.push_str(&digits[..head]);
        grouped.push('_');
    }
    let mut index = head;
    while index < len {
        if index > head {
            grouped.push('_');
        }
        grouped.push_str(&digits[index..index + 3]);
        index += 3;
    }
    grouped
}

/// Prints one scenario's exact counts, whole-batch statistics and the
/// amortized ns/op derived from each statistic by explicit division.
fn report(
    name: &str,
    op_unit: &str,
    ops_per_batch: usize,
    samples: &[u128],
    stats: (u128, u128, u128),
) {
    let (min, median, p95) = stats;
    let ops = ops_per_batch as u128;
    println!("[{name}] 1 op = {op_unit}");
    if name == "engine_full_rejection" || name == "engine_queued_age_expiry_retention" {
        println!("  caution: observed Windows batches span about 7-10 QPC ticks (100 ns each)");
        println!(
            "  fault-batch statistics are coarse timer quantization, not event-tail distributions"
        );
    }
    println!(
        "  warmup_batches={} measured_samples={} ops_per_batch={ops_per_batch}",
        WARMUP_BATCHES,
        samples.len()
    );
    println!(
        "  whole_batch_ns: min={} median={} p95={}",
        fmt_ns(min),
        fmt_ns(median),
        fmt_ns(p95)
    );
    println!(
        "  amortized_ns_per_op: min {} / {ops} = {}",
        fmt_ns(min),
        per_op(min, ops)
    );
    println!(
        "  amortized_ns_per_op: median {} / {ops} = {}",
        fmt_ns(median),
        per_op(median, ops)
    );
    println!(
        "  amortized_ns_per_op: p95 {} / {ops} = {}",
        fmt_ns(p95),
        per_op(p95, ops)
    );
}

/// Exact `nanos / ops` in nanoseconds with two decimal places, computed in
/// integer centi-nanoseconds, truncated to 0.01 ns. This is display precision,
/// not a claim about the timer's resolution or measurement accuracy.
fn per_op(nanos: u128, ops: u128) -> String {
    let centis = nanos * 100 / ops;
    format!("{}.{:02}", centis / 100, centis % 100)
}

fn instance() -> InstanceId {
    InstanceId::new(0x5A5A_1111_2222_3333).expect("nonzero instance")
}

fn peer() -> PeerId {
    PeerId::new(0x5A5A_4444_5555_6666).expect("nonzero peer")
}

fn max_age() -> MaxEventAge {
    MaxEventAge::from_nanos(MAX_AGE_NANOS).expect("nonzero age bound")
}

fn now() -> Timestamp {
    Timestamp::from_nanos(NOW_NANOS)
}

fn key_event(code: u16, transition: Transition, age: u64) -> InputEvent {
    InputEvent::new(
        DeviceId::from_raw(1),
        Timestamp::from_nanos(NOW_NANOS - age),
        EventKind::Key {
            code: KeyCode::from_raw(code),
            transition,
        },
    )
}

fn move_event(index: u16, age: u64) -> InputEvent {
    let delta = f32::from(index % 64);
    InputEvent::new(
        DeviceId::from_raw(2),
        Timestamp::from_nanos(NOW_NANOS - age),
        EventKind::PointerMove {
            dx: delta,
            dy: -delta,
        },
    )
}

fn button_event(index: u16, transition: Transition, age: u64) -> InputEvent {
    let button = match index % 5 {
        0 => PointerButton::Primary,
        1 => PointerButton::Secondary,
        2 => PointerButton::Middle,
        3 => PointerButton::Back,
        _ => PointerButton::Forward,
    };
    InputEvent::new(
        DeviceId::from_raw(3),
        Timestamp::from_nanos(NOW_NANOS - age),
        EventKind::PointerButton { button, transition },
    )
}

fn scroll_event(index: u16, age: u64) -> InputEvent {
    let delta = f32::from(index % 64);
    InputEvent::new(
        DeviceId::from_raw(2),
        Timestamp::from_nanos(NOW_NANOS - age),
        EventKind::Scroll {
            dx: delta,
            dy: -delta,
        },
    )
}

/// A pool of valid events cycling all four families with varying payloads.
fn mixed_pool() -> Vec<InputEvent> {
    let mut pool = Vec::with_capacity(POOL_LEN);
    for index in 0..POOL_LEN {
        let age = u64::try_from(index % 1_000).expect("pool index fits u64");
        let code = u16::try_from(index).expect("pool index fits u16");
        pool.push(match index % 4 {
            0 => key_event(code, Transition::Down, age),
            1 => move_event(code, age),
            2 => button_event(code, Transition::Up, age),
            _ => scroll_event(code, age),
        });
    }
    pool
}

/// A fresh active engine holding exactly `fill` (valid, in-order) events.
fn new_filled_engine(fill: &[InputEvent]) -> (InputEngine<ENGINE_CAP>, RouteEpoch) {
    let mut engine = InputEngine::new(instance(), peer(), max_age());
    let epoch = engine.activate().expect("activation");
    let now = now();
    for event in fill {
        engine
            .enqueue(epoch, now, *event)
            .expect("valid fill event enqueues");
    }
    (engine, epoch)
}

/// Steady enqueue/consume at the storage layer: one push + one pop per op.
fn bench_ring_fifo_pair() {
    const OPS: usize = 4096;
    const CAP: usize = 64;
    let pool: Vec<InputEvent> = (0..POOL_LEN)
        .map(|index| {
            key_event(
                u16::try_from(index).expect("pool index fits u16"),
                Transition::Down,
                u64::try_from(index).expect("pool index fits u64"),
            )
        })
        .collect();
    let mut fifo: RingFifo<InputEvent, CAP> = RingFifo::new();

    let (mut samples, checksum) = measure_batches(|| {
        let start = Instant::now();
        let mut completed = 0_u64;
        for index in 0..OPS {
            let event = pool[index % POOL_LEN];
            if black_box(&mut fifo).push(black_box(event)).is_ok() {
                completed += 1;
            }
            if black_box(&mut fifo).pop().is_some() {
                completed += 1;
            }
        }
        (start.elapsed().as_nanos(), completed)
    });

    let expected = u64::try_from(2 * OPS * (WARMUP_BATCHES + SAMPLES)).expect("fits u64");
    assert_eq!(checksum, expected, "every push and pop must succeed");
    let stats = batch_stats(&mut samples);
    report(
        "ring_fifo_enqueue_consume_pair",
        "one push + one pop (capacity 64, best-case occupancy 0 to 1)",
        OPS,
        &samples,
        stats,
    );

    // Untimed semantics: drained empty, order preserved on a fresh sequence.
    assert!(fifo.is_empty());
    assert_eq!(fifo.len(), 0);
    let first = pool[1];
    let second = pool[2];
    let third = pool[3];
    fifo.push(first).expect("push after drain");
    fifo.push(second).expect("push after drain");
    fifo.push(third).expect("push after drain");
    assert_eq!(fifo.pop(), Some(first));
    assert_eq!(fifo.pop(), Some(second));
    assert_eq!(fifo.pop(), Some(third));
    assert_eq!(fifo.pop(), None);
}

/// Ring indices lapping the storage repeatedly: pop-then-push at full
/// occupancy, so head and tail cross slot 0 every CAP ops.
fn bench_ring_fifo_wraparound() {
    const OPS: usize = 4096;
    const CAP: usize = 8;
    let pool: Vec<InputEvent> = (0..POOL_LEN)
        .map(|index| {
            key_event(
                u16::try_from(index).expect("pool index fits u16"),
                Transition::Down,
                u64::try_from(index).expect("pool index fits u64"),
            )
        })
        .collect();
    let mut fifo: RingFifo<InputEvent, CAP> = RingFifo::new();
    for index in 0..CAP {
        fifo.push(pool[index % POOL_LEN]).expect("prime the ring");
    }

    let (mut samples, checksum) = measure_batches(|| {
        let start = Instant::now();
        let mut completed = 0_u64;
        for index in 0..OPS {
            let event = pool[(CAP + index) % POOL_LEN];
            if black_box(&mut fifo).pop().is_some() {
                completed += 1;
            }
            if black_box(&mut fifo).push(black_box(event)).is_ok() {
                completed += 1;
            }
        }
        (start.elapsed().as_nanos(), completed)
    });

    let expected = u64::try_from(2 * OPS * (WARMUP_BATCHES + SAMPLES)).expect("fits u64");
    assert_eq!(checksum, expected, "wraparound must never reject or starve");
    let stats = batch_stats(&mut samples);
    report(
        "ring_fifo_sustained_wraparound",
        "one pop + one push at full occupancy (capacity 8)",
        OPS,
        &samples,
        stats,
    );

    // Untimed semantics: the ring stayed full and FIFO order survived 512 laps.
    assert!(fifo.is_full());
    assert_eq!(fifo.len(), CAP);
    for slot in 0..CAP {
        let expected_event = pool[((WARMUP_BATCHES + SAMPLES) * OPS + slot) % POOL_LEN];
        assert_eq!(
            fifo.pop(),
            Some(expected_event),
            "FIFO order broke at slot {slot}"
        );
    }
    assert_eq!(fifo.pop(), None);
}

/// Steady admission round trip: one enqueue + one consume per op across all
/// four event families, exercising epoch check, finiteness and age recheck.
fn bench_engine_enqueue_consume_mixed_pair() {
    const OPS: usize = 4096;
    let pool = mixed_pool();
    let now = now();
    let mut engine: InputEngine<ENGINE_CAP> = InputEngine::new(instance(), peer(), max_age());
    let epoch = engine.activate().expect("activate");

    let (mut samples, checksum) = measure_batches(|| {
        let start = Instant::now();
        let mut completed = 0_u64;
        for index in 0..OPS {
            let event = pool[index % POOL_LEN];
            if black_box(&mut engine)
                .enqueue(black_box(epoch), black_box(now), black_box(event))
                .is_ok()
            {
                completed += 1;
            }
            if black_box(&mut engine)
                .consume(black_box(epoch), black_box(now))
                .is_ok()
            {
                completed += 1;
            }
        }
        (start.elapsed().as_nanos(), completed)
    });

    let expected = u64::try_from(2 * OPS * (WARMUP_BATCHES + SAMPLES)).expect("fits u64");
    assert_eq!(
        checksum, expected,
        "steady-state admission must never fault"
    );
    let stats = batch_stats(&mut samples);
    report(
        "engine_enqueue_consume_mixed_pair",
        "one enqueue + one consume (capacity 16, mixed families, occupancy 0 to 1, head-stage path only)",
        OPS,
        &samples,
        stats,
    );

    // Untimed semantics: empty, still active, exact round trip still works.
    assert_eq!(engine.snapshot().queued, 0);
    assert_eq!(
        engine.snapshot().state,
        EngineState::Active {
            generation: epoch.generation()
        }
    );
    assert_eq!(engine.consume(epoch, now), Ok(None));
    let probe = pool[5];
    assert_eq!(engine.enqueue(epoch, now, probe), Ok(()));
    assert_eq!(engine.consume(epoch, now), Ok(Some(probe)));
}

/// Stale-epoch rejection: one stale enqueue + one stale consume per op against
/// an active route holding one event. Both must return `StaleEpoch` and leave
/// the live route open and unfaulted.
fn bench_engine_stale_epoch_rejection() {
    const OPS: usize = 2048;
    let pool = mixed_pool();
    let now = now();
    let mut engine: InputEngine<ENGINE_CAP> = InputEngine::new(instance(), peer(), max_age());
    let stale = engine.activate().expect("first activation");
    engine.close(stale).expect("close first route");
    let live = engine.activate().expect("second activation");
    let held = key_event(99, Transition::Down, 0);
    engine
        .enqueue(live, now, held)
        .expect("pre-queue one event");

    let (mut samples, checksum) = measure_batches(|| {
        let start = Instant::now();
        let mut rejected = 0_u64;
        for index in 0..OPS {
            let event = pool[index % POOL_LEN];
            if matches!(
                black_box(&mut engine).enqueue(black_box(stale), black_box(now), black_box(event)),
                Err(EnqueueError::StaleEpoch)
            ) {
                rejected += 1;
            }
            if matches!(
                black_box(&mut engine).consume(black_box(stale), black_box(now)),
                Err(ConsumeError::StaleEpoch)
            ) {
                rejected += 1;
            }
        }
        (start.elapsed().as_nanos(), rejected)
    });

    let expected = u64::try_from(2 * OPS * (WARMUP_BATCHES + SAMPLES)).expect("fits u64");
    assert_eq!(checksum, expected, "every stale call must be rejected");
    let stats = batch_stats(&mut samples);
    report(
        "engine_stale_epoch_rejection",
        "one stale enqueue + one stale consume (valid event, queue holds 1)",
        OPS,
        &samples,
        stats,
    );

    // Untimed semantics: no fault, live route intact and still functional.
    assert_eq!(
        engine.snapshot().state,
        EngineState::Active {
            generation: live.generation()
        }
    );
    assert_eq!(engine.snapshot().queued, 1);
    assert_eq!(engine.consume(live, now), Ok(Some(held)));
    assert_eq!(engine.consume(live, now), Ok(None));
}

/// The fill for the full-rejection scenario: a key press, its release, then
/// moves and scrolls up to capacity, mirroring a saturated route.
fn full_rejection_fill() -> Vec<InputEvent> {
    let mut fill = Vec::with_capacity(ENGINE_CAP);
    fill.push(key_event(30, Transition::Down, 0));
    fill.push(key_event(30, Transition::Up, 0));
    while fill.len() < ENGINE_CAP {
        let index = u16::try_from(fill.len()).expect("fill index fits u16");
        fill.push(move_event(index, 0));
        if fill.len() < ENGINE_CAP {
            fill.push(scroll_event(index, 0));
        }
    }
    fill
}

/// Full-queue rejection: one overflow enqueue per saturated engine; engines
/// are rebuilt outside the timed window because the fault is terminal.
fn bench_engine_full_rejection() {
    let fill = full_rejection_fill();
    let overflow = key_event(31, Transition::Down, 0);
    let now = now();
    let (_, epoch) = new_filled_engine(&fill);

    let (mut samples, checksum) = measure_batches(|| {
        let mut engines = Vec::with_capacity(FAULT_ENGINES);
        for _ in 0..FAULT_ENGINES {
            engines.push(new_filled_engine(&fill).0);
        }
        let start = Instant::now();
        let mut faults = 0_u64;
        for engine in &mut engines {
            let outcome =
                black_box(engine).enqueue(black_box(epoch), black_box(now), black_box(overflow));
            if matches!(outcome, Err(EnqueueError::Faulted(FaultReason::QueueFull))) {
                faults += 1;
            }
        }
        (start.elapsed().as_nanos(), faults)
    });

    let expected = u64::try_from(FAULT_ENGINES * (WARMUP_BATCHES + SAMPLES)).expect("fits u64");
    assert_eq!(checksum, expected, "every overflow enqueue must fault");
    let stats = batch_stats(&mut samples);
    report(
        "engine_full_rejection",
        "one overflow enqueue into a full queue (capacity 16)",
        FAULT_ENGINES,
        &samples,
        stats,
    );

    // Untimed semantics: the fault preserves every held entry, including the
    // queued release, in order, for explicit discard.
    let (mut engine, epoch) = new_filled_engine(&fill);
    assert_eq!(
        engine.enqueue(epoch, now, overflow),
        Err(EnqueueError::Faulted(FaultReason::QueueFull))
    );
    assert_eq!(engine.consume(epoch, now), Err(ConsumeError::NoActiveRoute));
    assert_eq!(
        engine.snapshot().state,
        EngineState::Faulted {
            reason: FaultReason::QueueFull
        }
    );
    assert_eq!(engine.snapshot().queued, fill.len());
    for expected_event in &fill {
        assert_eq!(engine.discard_one(), Ok(Some(*expected_event)));
    }
    assert_eq!(engine.discard_one(), Ok(None));
    assert_eq!(
        fill[0],
        key_event(30, Transition::Down, 0),
        "fill starts with the press"
    );
    assert_eq!(
        fill[1],
        key_event(30, Transition::Up, 0),
        "queued release preserved second"
    );
}

/// Queued-age expiry at consumption: engines hold a press and its release at
/// time NOW; one consume one nanosecond past the age bound per engine faults
/// without dequeueing or forwarding. Engines are rebuilt outside the timed
/// window because the fault is terminal.
fn bench_engine_queued_age_expiry() {
    let held = [
        key_event(30, Transition::Down, 0),
        key_event(30, Transition::Up, 0),
    ];
    let late = Timestamp::from_nanos(NOW_NANOS + MAX_AGE_NANOS + 1);
    let (_, epoch) = new_filled_engine(&held);

    let (mut samples, checksum) = measure_batches(|| {
        let mut engines = Vec::with_capacity(FAULT_ENGINES);
        for _ in 0..FAULT_ENGINES {
            engines.push(new_filled_engine(&held).0);
        }
        let start = Instant::now();
        let mut faults = 0_u64;
        for engine in &mut engines {
            let outcome = black_box(engine).consume(black_box(epoch), black_box(late));
            if matches!(
                outcome,
                Err(ConsumeError::Faulted(FaultReason::StaleQueuedInput))
            ) {
                faults += 1;
            }
        }
        (start.elapsed().as_nanos(), faults)
    });

    let expected = u64::try_from(FAULT_ENGINES * (WARMUP_BATCHES + SAMPLES)).expect("fits u64");
    assert_eq!(checksum, expected, "every late consume must fault");
    let stats = batch_stats(&mut samples);
    report(
        "engine_queued_age_expiry_retention",
        "one consume one nanosecond past the age bound (2 entries held)",
        FAULT_ENGINES,
        &samples,
        stats,
    );

    // Untimed semantics: the expired entries stay held, in order, for discard.
    let (mut engine, epoch) = new_filled_engine(&held);
    assert_eq!(
        engine.consume(epoch, late),
        Err(ConsumeError::Faulted(FaultReason::StaleQueuedInput))
    );
    assert_eq!(
        engine.snapshot().state,
        EngineState::Faulted {
            reason: FaultReason::StaleQueuedInput
        }
    );
    assert_eq!(engine.snapshot().queued, 2, "expired entries stay held");
    assert_eq!(engine.discard_one(), Ok(Some(held[0])));
    assert_eq!(engine.discard_one(), Ok(Some(held[1])));
    assert_eq!(engine.discard_one(), Ok(None));
}

/// Held-controls ledger round trip: one press of a fresh key plus its release
/// per op, the pattern the session owner runs on key down/up admission.
fn bench_held_set_press_release_pair() {
    const OPS: usize = 2048;
    let controls: Vec<HeldControl> = (0..POOL_LEN)
        .map(|index| HeldControl::Key {
            device: DeviceId::from_raw(1),
            code: KeyCode::from_raw(u16::try_from(index).expect("pool index fits u16")),
        })
        .collect();
    let mut set = HeldSet::<u64, 16>::new();

    let (mut samples, checksum) = measure_batches(|| {
        let start = Instant::now();
        let mut completed = 0_u64;
        for index in 0..OPS {
            let control = controls[index % POOL_LEN];
            if black_box(&mut set).press(black_box(control)) == Ok(true) {
                completed += 1;
            }
            if black_box(&mut set).release(black_box(control)) == Ok(true) {
                completed += 1;
            }
        }
        (start.elapsed().as_nanos(), completed)
    });

    let expected = u64::try_from(2 * OPS * (WARMUP_BATCHES + SAMPLES)).expect("fits u64");
    assert_eq!(checksum, expected, "press/release pairs must always match");
    let stats = batch_stats(&mut samples);
    report(
        "held_set_press_release_pair",
        "one press + one release of a fresh key (capacity 16, best-case occupancy 0 to 1)",
        OPS,
        &samples,
        stats,
    );

    // Untimed semantics: empty ledger, duplicates and unknowns behave.
    assert!(set.is_empty());
    assert_eq!(set.len(), 0);
    let control = controls[7];
    assert_eq!(set.press(control), Ok(true));
    assert_eq!(set.press(control), Ok(false));
    assert_eq!(set.release(control), Ok(true));
    assert_eq!(set.release(control), Ok(false));
    assert_eq!(set.press(controls[8]), Ok(true));
    assert_eq!(set.begin_cleanup(1), Ok(()));
    assert_eq!(set.press(controls[9]), Err(kvm_foundation::HeldError::Busy));
    assert_eq!(set.peek_release(), Some(controls[8]));
    assert_eq!(set.confirm_release(1, controls[8]), Ok(()));
    assert_eq!(set.finish_cleanup(1), Ok(()));
    assert!(set.is_empty());
}
