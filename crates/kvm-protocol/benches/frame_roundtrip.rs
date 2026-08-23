//! Criterion benchmarks for the frame codec hot path.
//!
//! This is the criterion analogue of the sibling hand-rolled `frame_codec`
//! bench, reusing the same codec functions (`encode_frame_for_version`,
//! `encode_frame_for_version_into`, `decode_frame_for_version`) so the two
//! harnesses cross-check each other's numbers: allocating vs reused-buffer
//! encode, inbound decode, and the full round-trip.
//!
//! Run with `cargo bench -p kvm-protocol --bench frame_roundtrip`.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use kvm_protocol::{
    decode_frame_for_version, encode_frame_for_version, encode_frame_for_version_into,
    InputEventV1, WireDeviceId, WireHostId, WireInputPayloadV1, WireMessage,
    CURRENT_PROTOCOL_VERSION,
};
use std::hint::black_box;

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

fn frame_codec(c: &mut Criterion) {
    let message = pointer_move();
    let mut group = c.benchmark_group("frame_codec");
    group.throughput(Throughput::Elements(1));

    group.bench_function("encode: allocating", |b| {
        b.iter(|| {
            black_box(encode_frame_for_version(
                black_box(&message),
                CURRENT_PROTOCOL_VERSION,
            ))
        });
    });

    group.bench_function("encode: reused buffer", |b| {
        let mut buffer = Vec::with_capacity(4 * 1024);
        b.iter(|| {
            buffer.clear();
            encode_frame_for_version_into(
                black_box(&message),
                CURRENT_PROTOCOL_VERSION,
                &mut buffer,
            )
            .expect("encode");
            black_box(&buffer);
        });
    });

    let encoded = encode_frame_for_version(&message, CURRENT_PROTOCOL_VERSION).expect("encode");
    group.bench_function("decode", |b| {
        b.iter(|| {
            black_box(decode_frame_for_version(
                black_box(&encoded),
                CURRENT_PROTOCOL_VERSION,
            ))
        });
    });

    group.bench_function("roundtrip: encode + decode", |b| {
        let mut buffer = Vec::with_capacity(4 * 1024);
        b.iter(|| {
            buffer.clear();
            encode_frame_for_version_into(
                black_box(&message),
                CURRENT_PROTOCOL_VERSION,
                &mut buffer,
            )
            .expect("encode");
            let decoded = decode_frame_for_version(black_box(&buffer), CURRENT_PROTOCOL_VERSION)
                .expect("decode");
            black_box(decoded);
        });
    });

    group.finish();
}

criterion_group!(benches, frame_codec);
criterion_main!(benches);
