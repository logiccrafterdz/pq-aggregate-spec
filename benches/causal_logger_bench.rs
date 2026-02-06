use pq_aggregate::causal::{CausalEventLogger, ActionType};
use std::time::Instant;

fn main() {
    println!("--- Causal Event Logger Microbenchmarks ---");
    
    benchmark_insertion_latency();
    benchmark_memory_estimate();
}

fn benchmark_insertion_latency() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xAA; 32];
    let payload = b"transaction_data_subset_for_benchmarking";
    
    let iterations = 1000;
    let start = Instant::now();
    
    for i in 0..iterations {
        let _ = logger.log_event(&agent_id, ActionType::SignatureRequest as u8, payload, 1000 + i as u64).unwrap();
    }
    
    let duration = start.elapsed();
    let per_insertion = duration.as_micros() as f64 / iterations as f64;
    
    println!("Insertion Latency (Avg over {} events): {:.2} µs", iterations, per_insertion);
}

fn benchmark_memory_estimate() {
    // Estimate based on the structure sizes
    // CausalEvent: nonce(8) + ts(8) + agent_id(32) + type(1) + payload_hash(32) + fingerprint(32) = 113 bytes
    // Plus alignment: approx 120-128 bytes.
    
    // IncrementalMerkleTree Frontier: depth (max 64) * 32 bytes = 2048 bytes
    
    println!("Memory Estimate (Internal State):");
    println!("- Merkle Frontier (Depth 64): 2048 bytes");
    println!("- Total per 1,000 events (excluding log storage): ~2.1 KB");
}
