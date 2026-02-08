use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pq_aggregate::hsm::SoftwareHSM;
use std::path::PathBuf;
use std::fs;

fn hsm_signing_benchmark(c: &mut Criterion) {
    // Setup
    let path = PathBuf::from("bench_keystore.enc");
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let hsm = SoftwareHSM::new(path.clone(), mnemonic).unwrap();
    let _pk = hsm.generate_and_save().unwrap();
    let msg = b"benchmark payload";

    c.bench_function("hsm_sign_dilithium_level3", |b| {
        b.iter(|| {
            hsm.sign(black_box(msg)).unwrap()
        })
    });
    
    // Cleanup
    let _ = fs::remove_file(path);
}

criterion_group!(benches, hsm_signing_benchmark);
criterion_main!(benches);
