//! Basic example demonstrating PQ-Aggregate threshold signatures.
//!
//! This example implements the Section III-C scenario:
//! - n = 5 participants
//! - t = 3 threshold
//!
//! Run with: cargo run --example basic

use pq_aggregate::{
    aggregate_proofs, aggregate_sign, calculate_adaptive_threshold, setup, verify,
};

fn main() {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║          PQ-Aggregate: Threshold Signature Demo            ║");
    println!("║     Post-Quantum Secure • ML-DSA-65 • Merkle Aggregation   ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // Configuration
    let n = 5; // Total participants
    let t = 3; // Threshold (minimum signatures required)

    println!("📋 Configuration:");
    println!("   • Participants (n): {}", n);
    println!("   • Threshold (t): {}", t);
    println!("   • Security Level: ML-DSA-65 (NIST Level 3)");
    println!();

    // Step 1: Setup - Generate independent keypairs
    println!("🔑 Step 1: Generating {} independent ML-DSA-65 keypairs...", n);
    let start = std::time::Instant::now();
    let (secret_keys, public_keys, pk_root) = setup(n);
    let setup_time = start.elapsed();

    println!("   ✓ Generated {} secret keys (zeroized on drop)", secret_keys.len());
    println!("   ✓ Generated {} public keys", public_keys.len());
    println!("   ✓ Merkle root: 0x{}...", hex_prefix(&pk_root, 8));
    println!("   ⏱ Setup time: {:?}", setup_time);
    println!();

    // Step 2: Sign - Collect threshold signatures
    let message = b"Transfer 100 SOL to address ABC123";
    println!("✍️  Step 2: Signing message with {} of {} signers...", t, n);
    println!("   Message: \"{}\"", String::from_utf8_lossy(message));

    let start = std::time::Instant::now();
    let (signatures, merkle_proofs) = aggregate_sign(&secret_keys, &public_keys, message, t);
    let sign_time = start.elapsed();

    println!("   ✓ Collected {} signatures", signatures.len());
    println!("   ✓ Generated {} Merkle proofs", merkle_proofs.len());
    println!("   ⏱ Signing time: {:?}", sign_time);
    println!();

    // Step 3: Aggregate - Combine into ZK proof
    println!("🔗 Step 3: Aggregating signatures into ZK proof...");
    let start = std::time::Instant::now();
    let proof = aggregate_proofs(signatures, merkle_proofs, pk_root, message, &public_keys)
        .expect("Aggregation should succeed");
    let aggregate_time = start.elapsed();

    println!("   ✓ Proof created successfully");
    println!("   ✓ Proof size: {} bytes (target: ≤1228)", proof.size());
    println!("   ✓ Signatures aggregated: {}", proof.num_signatures());
    println!("   ⏱ Aggregation time: {:?}", aggregate_time);
    println!();

    // Step 4: Verify - Check the proof
    println!("✅ Step 4: Verifying aggregated proof...");
    let start = std::time::Instant::now();
    let is_valid = verify(pk_root, message, &proof);
    let verify_time = start.elapsed();

    println!("   Result: {}", if is_valid { "✓ VALID" } else { "✗ INVALID" });
    println!("   ⏱ Verification time: {:?}", verify_time);
    println!();

    // Demonstrate tamper detection
    println!("🔒 Security Demonstration:");
    
    // Wrong message
    let tampered_msg = b"Transfer 999 SOL to attacker";
    let valid_tampered = verify(pk_root, tampered_msg, &proof);
    println!("   • Tampered message: {}", if !valid_tampered { "✓ Rejected" } else { "✗ Accepted!" });

    // Wrong root
    let wrong_root = [0xFFu8; 32];
    let valid_wrong_root = verify(wrong_root, message, &proof);
    println!("   • Wrong pk_root: {}", if !valid_wrong_root { "✓ Rejected" } else { "✗ Accepted!" });
    println!();

    // Adaptive threshold demo
    println!("📊 Adaptive Threshold Calculation (Appendix B):");
    for level in 1..=3 {
        let threshold = calculate_adaptive_threshold(n, level);
        let desc = match level {
            1 => "Simple Majority (51%)",
            2 => "Two-Thirds (67%)",
            3 => "Three-Quarters (75%)",
            _ => "Unknown",
        };
        println!("   Level {}: {} signers needed - {}", level, threshold, desc);
    }
    println!();

    // Summary
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║                        Summary                             ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║  Setup:       {:>10?} ({} keypairs)              ║", setup_time, n);
    println!("║  Signing:     {:>10?} ({}/{} threshold)           ║", sign_time, t, n);
    println!("║  Aggregation: {:>10?} (→ {} bytes)              ║", aggregate_time, proof.size());
    println!("║  Verification:{:>10?}                             ║", verify_time);
    println!("╚════════════════════════════════════════════════════════════╝");

    assert!(is_valid, "Proof should be valid");
    println!("\n🎉 Demo completed successfully!");
}

/// Format bytes as hex prefix
fn hex_prefix(bytes: &[u8], len: usize) -> String {
    bytes.iter()
        .take(len)
        .map(|b| format!("{:02x}", b))
        .collect()
}
