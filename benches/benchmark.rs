//! Benchmarks for PQ-Aggregate operations.
//!
//! Measures performance for Table II comparison:
//! - ML-DSA-65 baseline vs PQ-Aggregate
//! - Batch sizes: 1, 10, 100 transactions
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pq_aggregate::{aggregate_proofs, aggregate_sign, setup, verify};

/// Benchmark the setup phase.
fn bench_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("setup");

    for n in [3, 5, 10, 20].iter() {
        group.throughput(Throughput::Elements(*n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, &n| {
            b.iter(|| {
                let (sks, pks, root) = setup(n);
                black_box((sks, pks, root))
            });
        });
    }

    group.finish();
}

/// Benchmark aggregate signing.
fn bench_aggregate_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate_sign");

    // Pre-generate keys for different configurations
    let configs = vec![
        (5, 3),   // Section III-C example
        (10, 7),  // Level 2 adaptive threshold
        (20, 15), // Larger committee
    ];

    for (n, t) in configs {
        let (sks, pks, _root) = setup(n);
        let msg = b"benchmark message for signing";

        group.throughput(Throughput::Elements(t as u64));
        group.bench_with_input(
            BenchmarkId::new("n_t", format!("{}_{}", n, t)),
            &(&sks, &pks, msg, t),
            |b, (sks, pks, msg, t)| {
                b.iter(|| {
                    let (sigs, proofs) = aggregate_sign(sks, pks, *msg, *t);
                    black_box((sigs, proofs))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark proof aggregation.
fn bench_aggregate_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate_proofs");

    let configs = vec![
        (5, 3, "basic"),
        (10, 7, "medium"),
        (20, 15, "large"),
    ];

    for (n, t, name) in configs {
        let (sks, pks, pk_root) = setup(n);
        let msg = b"benchmark message for aggregation";
        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, t);

        group.throughput(Throughput::Elements(t as u64));
        group.bench_with_input(
            BenchmarkId::new("config", name),
            &(sigs.clone(), proofs.clone(), pk_root, msg),
            |b, (sigs, proofs, pk_root, msg)| {
                b.iter(|| {
                    let proof = aggregate_proofs(
                        sigs.clone(),
                        proofs.clone(),
                        *pk_root,
                        *msg,
                    );
                    black_box(proof)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark verification.
fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");

    let configs = vec![
        (5, 3, "t3"),
        (10, 7, "t7"),
        (20, 15, "t15"),
    ];

    for (n, t, name) in configs {
        let (sks, pks, pk_root) = setup(n);
        let msg = b"benchmark message for verification";
        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, t);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();

        group.bench_with_input(
            BenchmarkId::new("threshold", name),
            &(pk_root, msg, &proof),
            |b, (pk_root, msg, proof)| {
                b.iter(|| {
                    let valid = verify(*pk_root, *msg, proof);
                    black_box(valid)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark full flow (Table II comparison).
fn bench_full_flow(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_flow");

    // Table II batch sizes
    let batch_sizes = [1, 10, 100];

    for batch in batch_sizes.iter() {
        let n = 5;
        let t = 3;

        group.throughput(Throughput::Elements(*batch as u64));
        group.bench_with_input(
            BenchmarkId::new("batch", batch),
            batch,
            |b, &batch| {
                b.iter(|| {
                    // Setup once per batch
                    let (sks, pks, pk_root) = setup(n);

                    // Process batch transactions
                    for i in 0..batch {
                        let msg = format!("transaction {}", i);
                        let msg_bytes = msg.as_bytes();

                        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg_bytes, t);
                        let proof = aggregate_proofs(sigs, proofs, pk_root, msg_bytes).unwrap();
                        let valid = verify(pk_root, msg_bytes, &proof);

                        black_box(valid);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark proof size validation.
fn bench_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_size");

    let thresholds = [3, 5, 10, 20, 50];

    for t in thresholds.iter() {
        let n = *t + 2; // Slightly more participants than threshold
        if n > 100 {
            continue;
        }

        let (sks, pks, pk_root) = setup(n);
        let msg = b"size test message";
        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, *t);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();

        println!("Threshold {}: proof size = {} bytes", t, proof.size());

        group.bench_with_input(
            BenchmarkId::new("threshold", t),
            &(proof.size()),
            |b, _size| {
                b.iter(|| {
                    // Just measure the aggregation which produces the proof
                    let (sks, pks, pk_root) = setup(n);
                    let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, *t);
                    let proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();
                    black_box(proof.size())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_setup,
    bench_aggregate_sign,
    bench_aggregate_proofs,
    bench_verify,
    bench_full_flow,
    bench_proof_size,
);

#[cfg(feature = "nova")]
mod nova_benches {
    use super::*;
    use pq_aggregate::nova::{params::gen_params, prover::{prove_batch, setup_keys, verify_proof}};
    use pasta_curves::pallas;
    use ff::Field;

    /// Benchmark Nova O(1) verification.
    pub fn bench_nova_verify(c: &mut Criterion) {
        let mut group = c.benchmark_group("nova_verify");

        // Generate params once (expensive)
        println!("Generating Nova public parameters...");
        let params = gen_params();
        let (pk, vk) = setup_keys(&params).expect("Key setup failed");

        // Pre-generate proof for different step counts
        for steps in [1, 3, 5, 10].iter() {
            println!("Generating proof for {} steps...", steps);
            let proof = prove_batch(&params, *steps, &pk).expect("Proving failed");

            let z0 = vec![pallas::Scalar::ZERO; 2];
            let zn = z0.clone();

            group.bench_with_input(
                BenchmarkId::new("steps", steps),
                &(&vk, &proof, *steps, &z0, &zn),
                |b, (vk, proof, steps, z0, zn)| {
                    b.iter(|| {
                        let valid = verify_proof(vk, proof, *steps, z0, zn);
                        black_box(valid)
                    });
                },
            );
        }

        group.finish();
    }
}

#[cfg(feature = "nova")]
criterion_group!(
    nova_bench_group,
    nova_benches::bench_nova_verify,
);

#[cfg(not(feature = "nova"))]
criterion_main!(benches);

#[cfg(feature = "nova")]
criterion_main!(benches, nova_bench_group);

