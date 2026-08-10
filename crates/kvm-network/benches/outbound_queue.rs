//! Outbound-queue throughput benchmarks for the high-rate input hot path.
//!
//! These measure the per-event cost of the source-side enqueue + pointer-move
//! coalescing path (spec §23) that gates how many captured events per second
//! the daemon can accept before the bounded outbound queue fills. They are
//! intended as headroom checks (orders of magnitude above a 175 Hz display
//! rate) and as regression guards for the zero-allocation / coalescing work on
//! this path.
//!
//! Run with `cargo bench -p kvm-network`. Bench targets are not built by
//! `cargo test`, so these never run in CI and add no test-suite flakiness.
//!
//! Zero external dependencies by design: each scenario runs a warmup, then
//! repeats and reports median / p95 throughput in events per second. Swap in
//! `criterion` if statistically rigorous microbenchmarking is later required.
//!
//! `clippy::pedantic` is relaxed here because benchmark ergonomics (closure
//! capture, float percentile math) routinely trip style lints that are not
//! meaningful for measurement code; `clippy::all` correctness lints stay on.

#![allow(clippy::pedantic)]

use std::cmp::Ordering;
use std::time::{Duration, Instant};

use kvm_network::{OutboundQueue, QueueConfig};
use kvm_protocol::{InputEventV1, WireDeviceId, WireHostId, WireInputPayloadV1, WireMessage};

/// Target sustained event rate: a single 175 Hz display (spec §37).
const DISPLAY_HZ: f64 = 175.0;
/// Wall-clock warmup before sampling, to stabilize caches / branch prediction.
const WARMUP: Duration = Duration::from_millis(300);
/// Number of timed samples per scenario; drives the median / p95 estimates.
const SAMPLE_RUNS: usize = 31;
/// Events processed per timed sample.
const EVENTS_PER_RUN: usize = 100_000;
/// Queue capacity used for pure-push scenarios (must exceed `EVENTS_PER_RUN`).
const BENCH_CAPACITY: usize = 2 * EVENTS_PER_RUN + 1_024;

fn main() {
    println!(
        "kvm-network outbound-queue throughput  ({} events/sample, {} samples)\n",
        EVENTS_PER_RUN, SAMPLE_RUNS
    );
    println!(
        "{:<38} {:>15}   {:>15}   {:>9}   scenario",
        "path", "median ev/s", "p95 ev/s", "x175Hz"
    );
    println!("{}", "-".repeat(108));

    // 1. Realistic 175 Hz burst: same-source pointer moves with coalescing ON.
    //    Every move after the first folds into the single tail frame, so the
    //    queue never grows and the cost is the coalescing check (peek tail,
    //    compare host+device, sum deltas). This is the hot path.
    measure(
        "push: same-source, coalesced",
        true,
        "high-rate same-device move burst (the 175 Hz case)",
        |queue| push_burst(queue, same_source),
    );

    // 2. Coalescing OFF, same source: each move occupies its own slot. Measures
    //    raw push cost (no coalescing shortcut) plus internal VecDeque growth.
    measure(
        "push: same-source, no coalesce",
        false,
        "same burst with coalescing disabled (isolates the coalescing win)",
        |queue| push_burst(queue, same_source),
    );

    // 3. Distinct sources, coalescing ON: coalescing cannot fire (sources
    //    differ), so every move is enqueued. Measures push cost when the
    //    coalescing check always misses — the worst case for a mixed-device
    //    environment.
    measure(
        "push: distinct sources, coalesced cfg",
        true,
        "every move from a different device (coalescing never fires)",
        |queue| push_burst(queue, distinct_sources),
    );

    // 4. Full enqueue + dequeue cycle with distinct sources: the closest
    //    analogue to steady-state drain, where the runtime pops each frame for
    //    encoding as fast as it is pushed.
    measure(
        "push + drain: distinct sources",
        true,
        "enqueue then pop every frame (steady-state drain analogue)",
        |queue| {
            push_burst(queue, distinct_sources);
            while queue.pop_next().is_some() {}
        },
    );

    println!(
        "\nAll four paths should show multiple orders of magnitude of headroom above\n\
         {DISPLAY_HZ:.0} Hz; a regression below ~100x is worth investigating."
    );
}

/// Builds a same-source pointer move (host=1, device=2), matching the
/// production capture signature so the coalescing key is exercised identically.
fn same_source(index: usize) -> WireMessage {
    pointer_move(index as u64, 1, 2)
}

/// Builds a pointer move whose source device varies per index, defeating
/// coalescing (the host+device key differs every frame).
fn distinct_sources(index: usize) -> WireMessage {
    pointer_move(index as u64, 1, ((index % 256) as u8).max(1))
}

/// Constructs a `PointerMove` input frame with the given sequence and source.
fn pointer_move(sequence: u64, host: u8, device: u8) -> WireMessage {
    WireMessage::Input(InputEventV1 {
        sequence,
        timestamp_ns: sequence,
        source_host: WireHostId([host; 16]),
        source_device: WireDeviceId([device; 16]),
        payload: WireInputPayloadV1::PointerMove { dx: 1.0, dy: 0.0 },
    })
}

/// Pushes `EVENTS_PER_RUN` frames built by `make` into `queue`, ignoring any
/// capacity overflow (the bench queue is sized to hold them all).
fn push_burst<F>(queue: &mut OutboundQueue, make: F)
where
    F: Fn(usize) -> WireMessage,
{
    for index in 0..EVENTS_PER_RUN {
        let _ = queue.try_push(make(index));
    }
}

/// Runs one benchmark scenario and prints median / p95 throughput.
///
/// `coalesce` selects the `QueueConfig::coalesce_pointer_moves` setting; `body`
/// performs one timed run against a freshly-drained queue of the chosen config.
fn measure(name: &str, coalesce: bool, scenario: &str, mut body: impl FnMut(&mut OutboundQueue)) {
    let config = QueueConfig {
        input: BENCH_CAPACITY,
        control: 128,
        background: 32,
        maximum_input_burst: 64,
        coalesce_pointer_moves: coalesce,
    };
    let mut queue = OutboundQueue::new(config);

    // Warmup: run the body until WARMUP elapses, draining between runs.
    let warmup_start = Instant::now();
    while warmup_start.elapsed() < WARMUP {
        drain(&mut queue);
        body(&mut queue);
    }

    // Sample: timed runs.
    let mut samples: Vec<f64> = Vec::with_capacity(SAMPLE_RUNS);
    for _ in 0..SAMPLE_RUNS {
        drain(&mut queue);
        let start = Instant::now();
        body(&mut queue);
        let elapsed = start.elapsed().as_secs_f64();
        samples.push(EVENTS_PER_RUN as f64 / elapsed.max(f64::MIN_POSITIVE));
    }

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let median = samples[SAMPLE_RUNS / 2];
    let p95_idx = (((SAMPLE_RUNS as f64) * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(SAMPLE_RUNS - 1);
    let p95 = samples[p95_idx];

    println!(
        "{name:<38} {median:>15.0}   {p95:>15.0}   {headroom:>8.0}x   {scenario}",
        headroom = median / DISPLAY_HZ
    );
}

/// Pops every queued frame so the next run starts from an empty queue.
fn drain(queue: &mut OutboundQueue) {
    while queue.pop_next().is_some() {}
}
