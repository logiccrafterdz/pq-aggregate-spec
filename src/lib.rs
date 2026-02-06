//! # PQ-Aggregate
//!
//! Post-quantum threshold signatures via independent key aggregation.
//!
//! This crate implements the PQ-Aggregate protocol (IACR ePrint xxxx/107115),
//! using ML-DSA-65 (CRYSTALS-Dilithium Level 3) for post-quantum security
//! and commitment-based proof aggregation.
//!
//! ## Features
//!
//! - **Independent Keypairs**: No secret sharing required
//! - **Merkle Aggregation**: Compact public key representation
//! - **Adaptive Thresholds**: Configurable security levels
//! - **`no_std` Compatible**: Works in embedded and WASM environments
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use pq_aggregate::{setup, aggregate_sign, aggregate_proofs, verify};
//!
//! // Setup: Generate n=5 independent keypairs
//! let (secret_keys, public_keys, pk_root) = setup(5);
//!
//! // Sign: Collect t=3 threshold signatures
//! let msg = b"transaction data";
//! let (sigs, proofs) = aggregate_sign(&secret_keys, &public_keys, msg, 3);
//!
//! // Aggregate: Combine into a single ZK proof
//! let zk_proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();
//!
//! // Verify: Check the aggregated proof
//! assert!(verify(pk_root, msg, &zk_proof));
//! ```
//!
//! ## Security
//!
//! - All secret keys are zeroized on drop
//! - Per-signer challenges prevent replay attacks
//! - Merkle proofs validate key membership

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// Module declarations
pub mod circuit;
pub mod core;
pub mod error;
pub mod types;
pub mod utils;
pub mod verifier;
pub mod adapters;
pub mod causal;
pub mod policy;
pub mod runtime;
pub mod agents;

#[cfg(feature = "nova")]
pub mod nova;

// Re-export core functionality
pub use core::aggregation::aggregate_proofs;
pub use core::keygen::setup;
pub use core::signing::aggregate_sign;
pub use verifier::verify;

// Re-export utility functions
pub use utils::{calculate_adaptive_threshold, MerkleTree};

// Re-export types
pub use error::{PQAggregateError, Result};
pub use types::{MerkleProof, PublicKey, SecretKey, Signature, ZKSNARKProof};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ML-DSA security level (Level 3 = ML-DSA-65)
pub const SECURITY_LEVEL: u8 = 3;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_flow() {
        // Setup
        let n = 5;
        let t = 3;
        let (sks, pks, pk_root) = setup(n);

        assert_eq!(sks.len(), n);
        assert_eq!(pks.len(), n);

        // Sign
        let msg = b"integration test message";
        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, t);

        assert_eq!(sigs.len(), t);
        assert_eq!(proofs.len(), t);

        // Aggregate
        let zk_proof = aggregate_proofs(sigs, proofs, pk_root, msg);
        assert!(zk_proof.is_ok());

        let proof = zk_proof.unwrap();
        assert_eq!(proof.num_signatures(), t);

        // Verify
        assert!(verify(pk_root, msg, &proof));
    }

    #[test]
    fn test_wrong_message_fails() {
        let (sks, pks, pk_root) = setup(3);
        let msg = b"original";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 2);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();

        // Verify with wrong message should fail
        assert!(!verify(pk_root, b"tampered", &proof));
    }

    #[test]
    fn test_wrong_root_fails() {
        let (sks, pks, pk_root) = setup(3);
        let msg = b"test";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 2);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();

        // Verify with wrong root should fail
        let wrong_root = [0xFFu8; 32];
        assert!(!verify(wrong_root, msg, &proof));
    }

    #[test]
    fn test_adaptive_threshold_integration() {
        let n = 10;
        let t = calculate_adaptive_threshold(n, 2); // Level 2 = 67%

        assert_eq!(t, 7); // 67% of 10 = 6.7 -> 7

        let (sks, pks, pk_root) = setup(n);
        let msg = b"adaptive test";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, t);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();

        assert!(verify(pk_root, msg, &proof));
    }
}
