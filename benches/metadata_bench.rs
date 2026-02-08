//! Benchmarks for Structured Metadata Extension.
//!
//! Measures latency of metadata commitment computation to ensure ≤15µs.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pq_aggregate::causal::{CausalEvent, StructuredMetadata, risk_flags};
use pq_aggregate::causal::metadata::compute_metadata_commitment;

fn bench_metadata_commitment(c: &mut Criterion) {
    let nonce = 42u64;
    let payload_hash = [0xABu8; 32];
    let metadata = StructuredMetadata::new(1500_00, 137, risk_flags::CROSS_CHAIN);

    c.bench_function("compute_metadata_commitment", |b| {
        b.iter(|| {
            compute_metadata_commitment(
                black_box(nonce),
                black_box(&payload_hash),
                black_box(&metadata),
            )
        })
    });
}

fn bench_event_creation_legacy(c: &mut Criterion) {
    let agent_id = [0xAAu8; 32];
    let payload = b"test payload for benchmarking";

    c.bench_function("CausalEvent::new (v0.01 legacy)", |b| {
        b.iter(|| {
            CausalEvent::new(
                black_box(1),
                black_box(1000),
                black_box(agent_id),
                black_box(0x01),
                black_box(payload),
            )
        })
    });
}

fn bench_event_creation_with_metadata(c: &mut Criterion) {
    let agent_id = [0xAAu8; 32];
    let payload = b"test payload for benchmarking";
    let metadata = StructuredMetadata::new(1500_00, 137, risk_flags::CROSS_CHAIN);

    c.bench_function("CausalEvent::new_with_metadata (v0.02)", |b| {
        b.iter(|| {
            CausalEvent::new_with_metadata(
                black_box(1),
                black_box(1000),
                black_box(agent_id),
                black_box(0x01),
                black_box(payload),
                black_box(&metadata),
            )
        })
    });
}

fn bench_fingerprint_verification(c: &mut Criterion) {
    let metadata = StructuredMetadata::new(1500_00, 137, risk_flags::CROSS_CHAIN);
    let event = CausalEvent::new_with_metadata(
        1,
        1000,
        [0xAAu8; 32],
        0x01,
        b"test payload",
        &metadata,
    );

    c.bench_function("CausalEvent::verify_fingerprint", |b| {
        b.iter(|| {
            black_box(&event).verify_fingerprint()
        })
    });
}

fn bench_structured_metadata_to_bytes(c: &mut Criterion) {
    let metadata = StructuredMetadata::new(1500_00, 137, risk_flags::CROSS_CHAIN | risk_flags::HIGH_VALUE);

    c.bench_function("StructuredMetadata::to_bytes", |b| {
        b.iter(|| {
            black_box(&metadata).to_bytes()
        })
    });
}

criterion_group!(
    benches,
    bench_metadata_commitment,
    bench_event_creation_legacy,
    bench_event_creation_with_metadata,
    bench_fingerprint_verification,
    bench_structured_metadata_to_bytes,
);
criterion_main!(benches);
