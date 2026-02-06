use pq_aggregate::causal::CausalEvent;
use pq_aggregate::policy::{PolicyEngine, BehavioralPolicy, PolicyCondition, RiskTier, Currency};
use std::time::Instant;

fn main() {
    println!("--- Behavioral Policy Engine Microbenchmarks ---");
    
    benchmark_evaluation_latency();
}

fn benchmark_evaluation_latency() {
    let agent_id = [0xAA; 32];
    let policy = BehavioralPolicy {
        name: "Benchmark Policy",
        conditions: vec![
            PolicyCondition::MaxDailyOutflow { max_amount: 5000, currency: Currency::USD },
            PolicyCondition::MinTimeBetweenActions { action_type: 0x01, min_seconds: 60 },
            PolicyCondition::NoConcurrentRequests { window_seconds: 10 },
        ],
        risk_tier: RiskTier::High,
    };
    let engine = PolicyEngine::new(vec![policy]);

    let counts = vec![10, 100, 1000];
    
    for count in counts {
        let mut events = Vec::new();
        for i in 1..=count {
            events.push(CausalEvent::new(
                i as u64,
                1000 * i as u64, // 1s spacing
                agent_id,
                0x01,
                b"payload",
            ));
        }
        
        // Compute root for the chain
        let leaves: Vec<[u8; 32]> = events.iter().map(|e| e.to_leaf()).collect();
        let tree = pq_aggregate::utils::MerkleTree::from_leaves(&leaves);
        let root = tree.root();

        let iterations = 100;
        let start = Instant::now();
        
        for _ in 0..iterations {
            let _ = engine.evaluate_chain(&events, &root).unwrap();
        }
        
        let duration = start.elapsed();
        let per_eval = duration.as_micros() as f64 / iterations as f64;
        
        println!("Evaluation Latency (Chain size {}): {:.2} µs", count, per_eval);
    }
}
