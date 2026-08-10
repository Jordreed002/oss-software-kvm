//! Wire-codec throughput benchmarks for the per-event serialization hot path.
//!
//! These measure the CPU cost of serializing and deserializing one input frame
//! — the work that bounds events/sec on *both* the outbound (encode) and
//! inbound (decode) directions before TLS and the socket. They complement the
//! `kvm-network` outbound-queue benchmarks (which measure enqueue/coalescing)
//! by isolating the per-frame postcard/codec cost, and quantify the
//! reuse-buffer win of `encode_frame_for_version_into`.
//!
//! Run with `cargo bench -p kvm-protocol`. Not built by `cargo test`, so these
//! never run in CI and add no test-suite flakiness.
//!
//! Zero external dependencies by design (see the sibling `outbound_queue`
//! bench). `clippy::pedantic` is relaxed for benchmark ergonomics; `clippy::all`
//! correctness lints stay on.

#![allow(clippy::pedantic)]

use std::cmp::Ordering;
use std::time::{Duration, Instant};

use kvm_protocol::{
    decode_frame_for_version, encode_frame_for_version, encode_frame_for_version_into,
    InputEventV1, WireDeviceId, WireHostId, WireInputPayloadV1, WireMessage,
    CURRENT_PROTOCOL_VERSION,
};

/// Target sustained event rate: a single 175 Hz display (spec §37).
const DISPLAY_HZ: f64 = 175.0;
/// Wall-clock warmup before sampling.
const WARMUP: Duration = Duration::from_millis(300);
/// Timed samples per scenario.
const SAMPLE_RUNS: usize = 31;
/// Frames processed per timed sample.
const FRAMES_PER_RUN: usize = 100_000;

fn main() {
    println!(
        "kvm-protocol frame-codec throughput  ({} frames/sample, {} samples, v{})\n",
        FRAMES_PER_RUN, SAMPLE_RUNS, CURRENT_PROTOCOL_VERSION
    );
    println!(
        "{:<34} {:>15}   {:>15}   {:>9}   scenario",
        "path", "median fr/s", "p95 fr/s", "x175Hz"
    );
    println!("{}", "-".repeat(105));

    let message = pointer_move();

    // 1. Allocating encode: one fresh Vec per frame (the pre-iter-4 baseline).
    measure(
        "encode: allocating",
        "encode_frame_for_version (fresh Vec per frame)",
        |_| {
            for _ in 0..FRAMES_PER_RUN {
                let _ = encode_frame_for_version(&message, CURRENT_PROTOCOL_VERSION);
            }
        },
    );

    // 2. Reused-buffer encode: encode into a single buffer whose capacity is
    //    retained across frames (the iter-4 zero-alloc hot path). The clear()
    //    keeps the allocation; postcard appends in place.
    measure(
        "encode: reused buffer",
        "encode_frame_for_version_into (capacity retained across frames)",
        |_| {
            let mut buf = Vec::with_capacity(4 * 1024);
            for _ in 0..FRAMES_PER_RUN {
                buf.clear();
                let _ = encode_frame_for_version_into(&message, CURRENT_PROTOCOL_VERSION, &mut buf);
            }
        },
    );

    // 3. Decode: one pre-encoded exact frame decoded repeatedly. Isolates the
    //    inbound per-frame deserialization cost.
    let encoded = encode_frame_for_version(&message, CURRENT_PROTOCOL_VERSION)
        .expect("benchmark message encodes");
    measure(
        "decode",
        "decode_frame_for_version (inbound per-frame deserialize)",
        |_| {
            for _ in 0..FRAMES_PER_RUN {
                let _ = decode_frame_for_version(&encoded, CURRENT_PROTOCOL_VERSION);
            }
        },
    );

    // 4. Full roundtrip: encode_into then decode the just-encoded slice. The
    //    closest single-frame analogue to serialize → socket → deserialize.
    measure(
        "roundtrip: encode + decode",
        "encode_frame_for_version_into then decode the result",
        |_| {
            let mut buf = Vec::with_capacity(4 * 1024);
            for _ in 0..FRAMES_PER_RUN {
                buf.clear();
                encode_frame_for_version_into(&message, CURRENT_PROTOCOL_VERSION, &mut buf)
                    .expect("encode");
                let _ = decode_frame_for_version(&buf, CURRENT_PROTOCOL_VERSION).expect("decode");
            }
        },
    );

    println!(
        "\nPer-frame codec cost is dwarfed by the queue throughput (sibling bench),\n\
         so the wire layer is not the 175 Hz bottleneck either; a regression below\n\
         ~100x headroom is worth investigating."
    );
}

/// Constructs the benchmark `PointerMove` input frame (the 175 Hz hot path).
fn pointer_move() -> WireMessage {
    WireMessage::Input(InputEventV1 {
        sequence: 1,
        timestamp_ns: 1,
        source_host: WireHostId([1; 16]),
        source_device: WireDeviceId([2; 16]),
        payload: WireInputPayloadV1::PointerMove { dx: 1.0, dy: 0.0 },
    })
}

/// Runs one benchmark scenario and prints median / p95 throughput in frames/s.
fn measure(name: &str, scenario: &str, mut body: impl FnMut(usize)) {
    // Warmup.
    let warmup_start = Instant::now();
    while warmup_start.elapsed() < WARMUP {
        body(FRAMES_PER_RUN);
    }

    // Sample.
    let mut samples: Vec<f64> = Vec::with_capacity(SAMPLE_RUNS);
    for _ in 0..SAMPLE_RUNS {
        let start = Instant::now();
        body(FRAMES_PER_RUN);
        let elapsed = start.elapsed().as_secs_f64();
        samples.push(FRAMES_PER_RUN as f64 / elapsed.max(f64::MIN_POSITIVE));
    }

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let median = samples[SAMPLE_RUNS / 2];
    let p95_idx = (((SAMPLE_RUNS as f64) * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(SAMPLE_RUNS - 1);
    let p95 = samples[p95_idx];

    println!(
        "{name:<34} {median:>15.0}   {p95:>15.0}   {headroom:>8.0}x   {scenario}",
        headroom = median / DISPLAY_HZ
    );
}
