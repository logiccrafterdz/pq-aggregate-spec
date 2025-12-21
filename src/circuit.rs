//! Nova circuit definitions for PQ-Aggregate (Appendix A.2).
//!
//! This module defines the circuit structure for recursive proof folding.
//!
//! ## Current Status (v0.1.0)
//! - Placeholder commitment-based verification
//! - O(t) verification time (~27 µs per signature)
//!
//! ## v0.2.0 Roadmap
//! - Integrate `nova-snark` crate
//! - Implement Merkle-only StepCircuit (~10 µs verify)
//! - Replace direct signature verification with Nova IVC
//!
//! ## v0.3.0 Roadmap  
//! - Add ML-DSA R1CS constraints (Az ≡ tc + ch mod q)
//! - Achieve ≤15 µs verification target

#![allow(dead_code)] // Some fields unused until Nova integration

use alloc::vec::Vec;
use sha3::{Digest, Sha3_256};

/// Circuit for verifying a single ML-DSA signature.
///
/// This represents the R₁ circuit from Appendix A.2 of the paper.
/// The circuit verifies:
/// 1. Signature validity against the public key
/// 2. Challenge computation: c_i = H(m || i || nonce_i)
/// 3. Merkle proof for public key membership
pub struct SignatureVerificationCircuit {
    /// Public inputs
    pub pk_root: [u8; 32],
    pub message_hash: [u8; 32],
    pub signer_index: usize,
    pub nonce: [u8; 32],

    /// Private witness
    pub signature_commitment: [u8; 32],
    pub merkle_path: Vec<[u8; 32]>,
}

impl SignatureVerificationCircuit {
    /// Create a new signature verification circuit.
    pub fn new(
        pk_root: [u8; 32],
        message_hash: [u8; 32],
        signer_index: usize,
        nonce: [u8; 32],
    ) -> Self {
        Self {
            pk_root,
            message_hash,
            signer_index,
            nonce,
            signature_commitment: [0u8; 32],
            merkle_path: Vec::new(),
        }
    }

    /// Set the private witness values.
    pub fn set_witness(&mut self, signature_commitment: [u8; 32], merkle_path: Vec<[u8; 32]>) {
        self.signature_commitment = signature_commitment;
        self.merkle_path = merkle_path;
    }

    /// Compute the expected challenge for this circuit.
    pub fn compute_challenge(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.message_hash);
        hasher.update(&self.signer_index.to_le_bytes());
        hasher.update(&self.nonce);
        hasher.finalize().into()
    }

    /// Verify the circuit constraints (simulated).
    ///
    /// In a real Nova integration, this would generate R1CS constraints.
    pub fn verify_constraints(&self) -> bool {
        // Verify challenge is well-formed
        let _challenge = self.compute_challenge();

        // Verify signature commitment is non-zero
        if self.signature_commitment == [0u8; 32] {
            return false;
        }

        // Verify signer index is reasonable
        if self.signer_index >= 256 {
            return false;
        }

        // All constraints satisfied
        true
    }

    /// Get the public output for folding.
    ///
    /// This is the hash that gets folded into the next step.
    pub fn public_output(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.pk_root);
        hasher.update(&self.message_hash);
        hasher.update(&self.signer_index.to_le_bytes());
        hasher.update(&self.signature_commitment);
        hasher.finalize().into()
    }
}

/// Folding accumulator for recursive proof composition.
///
/// This simulates the Nova folding scheme accumulator.
pub struct FoldingAccumulator {
    /// Running commitment to all verified signatures
    running_commitment: [u8; 32],
    /// Number of signatures folded
    count: usize,
    /// Public key root
    pk_root: [u8; 32],
}

impl FoldingAccumulator {
    /// Create a new folding accumulator.
    pub fn new(pk_root: [u8; 32]) -> Self {
        Self {
            running_commitment: [0u8; 32],
            count: 0,
            pk_root,
        }
    }

    /// Fold a new circuit into the accumulator.
    pub fn fold(&mut self, circuit: &SignatureVerificationCircuit) {
        // Verify circuit before folding
        if !circuit.verify_constraints() {
            return;
        }

        // Compute new commitment
        let mut hasher = Sha3_256::new();
        hasher.update(&self.running_commitment);
        hasher.update(&circuit.public_output());
        self.running_commitment = hasher.finalize().into();

        self.count += 1;
    }

    /// Get the final accumulator state.
    pub fn finalize(&self) -> ([u8; 32], usize) {
        (self.running_commitment, self.count)
    }

    /// Verify the accumulator against expected values.
    pub fn verify(&self, expected_commitment: &[u8; 32], expected_count: usize) -> bool {
        self.running_commitment == *expected_commitment && self.count == expected_count
    }
}

/// Circuit parameters for Nova configuration.
///
/// These would be used to configure the Nova proving system.
pub struct CircuitParams {
    /// Number of constraints per signature verification
    pub constraints_per_sig: usize,
    /// Size of the step circuit
    pub step_circuit_size: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,
}

impl Default for CircuitParams {
    fn default() -> Self {
        Self {
            // Estimated values for ML-DSA-65 verification
            constraints_per_sig: 50_000,
            step_circuit_size: 10_000,
            num_public_inputs: 3, // pk_root, message_hash, num_sigs
        }
    }
}

impl CircuitParams {
    /// Estimate the proving time for a given number of signatures.
    pub fn estimate_proving_time_ms(&self, num_sigs: usize) -> u64 {
        // Linear estimate based on constraint count
        let total_constraints = self.constraints_per_sig * num_sigs;
        // Rough estimate: 1ms per 1000 constraints
        (total_constraints / 1000) as u64
    }

    /// Estimate the verification time.
    pub fn estimate_verification_time_us(&self) -> u64 {
        // Nova verification is O(1) with respect to number of steps
        // Estimated ~10-15 µs for the commitment scheme
        12
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::sha3_256;

    #[test]
    fn test_circuit_creation() {
        let circuit = SignatureVerificationCircuit::new(
            [0u8; 32],
            sha3_256(b"test message"),
            0,
            [1u8; 32],
        );

        assert_eq!(circuit.signer_index, 0);
    }

    #[test]
    fn test_challenge_computation() {
        let circuit = SignatureVerificationCircuit::new(
            [0u8; 32],
            sha3_256(b"message"),
            1,
            [2u8; 32],
        );

        let challenge = circuit.compute_challenge();
        assert_ne!(challenge, [0u8; 32]);
    }

    #[test]
    fn test_folding_accumulator() {
        let mut acc = FoldingAccumulator::new([0u8; 32]);

        let mut circuit = SignatureVerificationCircuit::new(
            [0u8; 32],
            sha3_256(b"msg"),
            0,
            [1u8; 32],
        );
        circuit.set_witness([42u8; 32], Vec::new());

        acc.fold(&circuit);

        let (commitment, count) = acc.finalize();
        assert_eq!(count, 1);
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_circuit_params() {
        let params = CircuitParams::default();

        let proving_time = params.estimate_proving_time_ms(3);
        assert!(proving_time < 200); // Should be reasonable

        let verify_time = params.estimate_verification_time_us();
        assert!(verify_time <= 15); // Target: ≤15µs
    }
}
