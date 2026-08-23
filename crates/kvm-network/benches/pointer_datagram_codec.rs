//! Criterion benchmarks for the pointer-datagram fast path's pure work:
//! plaintext encode/parse round-trips and reliable reassembly.
//!
//! These isolate the per-datagram CPU cost before encryption and the socket
//! (the AEAD record path is covered by the sibling `tls_record` bench). They
//! complement `outbound_queue` (enqueue/coalescing) and the `kvm-protocol`
//! frame benches by measuring the datagram-path codec that wraps them.
//!
//! Run with `cargo bench -p kvm-network --bench pointer_datagram_codec`.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use kvm_network::{
    encode_pointer_plaintext, parse_pointer_datagram_plaintext, ReliableReorderBuffer,
};
use kvm_protocol::{
    encode_frame_for_version, InputEventV1, WireDeviceId, WireHostId, WireInputPayloadV1,
    WireMessage, POINTER_DATAGRAM_PROTOCOL_VERSION,
};
use std::hint::black_box;

/// Deterministic device identity for the benchmark payloads.
const DEVICE: [u8; 16] = [0x42; 16];
/// Sequences per reassembly batch: half arrive reordered around the other
/// half, the dominant lossy-network shape the reorder buffer exists for.
const REORDER_WINDOW: u64 = 32;

fn scroll_message() -> WireMessage {
    WireMessage::Input(InputEventV1 {
        sequence: 12,
        timestamp_ns: 13,
        source_host: WireHostId([1; 16]),
        source_device: WireDeviceId([2; 16]),
        payload: WireInputPayloadV1::Scroll {
            horizontal: 0.0,
            vertical: 1.0,
        },
    })
}

/// Builds one `KIND_RELIABLE` plaintext payload exactly as the session's
/// shadow path does: kind byte + big-endian sequence + one encoded frame.
fn reliable_plaintext(sequence: u64) -> Vec<u8> {
    let frame = encode_frame_for_version(&scroll_message(), POINTER_DATAGRAM_PROTOCOL_VERSION)
        .expect("benchmark scroll frame encodes");
    let mut payload = Vec::with_capacity(9 + frame.len());
    payload.push(3); // KIND_RELIABLE
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(&frame);
    payload
}

fn datagram_codec(c: &mut Criterion) {
    let mut group = c.benchmark_group("pointer_datagram_plaintext");
    group.throughput(Throughput::Elements(1));

    let device = WireDeviceId(DEVICE);
    group.bench_function("encode pointer plaintext", |b| {
        b.iter(|| {
            black_box(encode_pointer_plaintext(
                black_box(0),
                black_box(device),
                black_box(11),
                black_box((12.5, -7.25)),
            ))
        });
    });

    let encoded = encode_pointer_plaintext(0, device, 11, (12.5, -7.25));
    group.bench_function("parse pointer plaintext", |b| {
        b.iter(|| black_box(parse_pointer_datagram_plaintext(black_box(&encoded))));
    });

    group.bench_function("roundtrip: encode + parse pointer", |b| {
        b.iter(|| {
            let payload = encode_pointer_plaintext(0, device, 11, (12.5, -7.25));
            black_box(parse_pointer_datagram_plaintext(black_box(&payload)))
        });
    });

    let reliable = reliable_plaintext(7);
    group.bench_function("parse reliable plaintext (frame decode included)", |b| {
        b.iter(|| black_box(parse_pointer_datagram_plaintext(black_box(&reliable))));
    });

    group.finish();
}

fn reliable_reassembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("reliable_reassembly");
    group.throughput(Throughput::Elements(REORDER_WINDOW));

    group.bench_function("insert 32 half-rotated sequences", |b| {
        b.iter_batched(
            || {
                let message = scroll_message();
                let order: Vec<u64> = (REORDER_WINDOW / 2..REORDER_WINDOW)
                    .chain(0..REORDER_WINDOW / 2)
                    .collect();
                (message, order)
            },
            |(message, order)| {
                let mut buffer = ReliableReorderBuffer::new();
                let mut delivered = 0_usize;
                for sequence in order {
                    if let Some((drained, _acknowledged)) = buffer.insert(sequence, message.clone())
                    {
                        delivered += drained.len();
                    }
                }
                black_box(delivered);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, datagram_codec, reliable_reassembly);
criterion_main!(benches);
