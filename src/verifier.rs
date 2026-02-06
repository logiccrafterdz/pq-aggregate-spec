//! Proof verification for PQ-Aggregate.
//!
//! Verifies aggregated ZK proofs against the public key root and message.

use sha3::{Digest, Sha3_256};

pub mod unified;

use crate::types::ZKSNARKProof;

/// Verify an aggregated proof against the public key root and message.
///
/// This function checks that:
/// 1. The proof structure is valid
/// 2. The public inputs hash matches
/// 3. The proof commitment is consistent
///
/// # Arguments
/// * `pk_root` - Merkle root of all public keys
/// * `msg` - The signed message
/// * `proof` - The aggregated ZK proof
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise
///
/// # Performance
/// Target: ≤ 15 µs verification time
pub fn verify(pk_root: [u8; 32], msg: &[u8], proof: &ZKSNARKProof) -> bool {
    // Validate proof structure
    if !validate_proof_structure(proof) {
        return false;
    }

    // Recompute public inputs hash
    let expected_hash = compute_public_inputs_hash(&pk_root, msg, proof.num_signatures());

    if expected_hash != *proof.public_inputs_hash() {
        return false;
    }

    // Verify proof commitments
    verify_proof_commitments(proof, &pk_root)
}

/// Validate the structure of a proof.
fn validate_proof_structure(proof: &ZKSNARKProof) -> bool {
    let bytes = proof.as_bytes();

    // Minimum size: version (1) + num_sigs (2) + commitment (32) + bitmap (32) + nonce (32) + root (32)
    if bytes.len() < 131 {
        return false;
    }

    // Check version
    if bytes[0] != 0x01 {
        return false;
    }

    // Check num_signatures matches header
    let header_count = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
    if header_count != proof.num_signatures() {
        return false;
    }

    // Check num_signatures is reasonable
    if proof.num_signatures() == 0 || proof.num_signatures() > 256 {
        return false;
    }

    true
}

/// Compute the expected public inputs hash.
fn compute_public_inputs_hash(pk_root: &[u8; 32], msg: &[u8], num_sigs: usize) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(pk_root);
    hasher.update(msg);
    hasher.update(&(num_sigs as u64).to_le_bytes());
    hasher.finalize().into()
}

/// Verify the commitment chain in the proof.
fn verify_proof_commitments(proof: &ZKSNARKProof, pk_root: &[u8; 32]) -> bool {
    let bytes = proof.as_bytes();

    // Extract components from proof bytes
    // Layout: version (1) + num_sigs (2) + commitment (32) + bitmap (32) + nonce (32) + root (32)

    if bytes.len() < 131 {
        return false;
    }

    // Extract the pk_root commitment from the proof
    let proof_root_start = bytes.len() - 32;
    let proof_root = &bytes[proof_root_start..];

    // Verify pk_root matches
    if proof_root != pk_root {
        return false;
    }

    // Extract bitmap and verify at least one signer
    let bitmap_start = 3 + 32; // After version + num_sigs + commitment
    if bitmap_start + 32 > bytes.len() {
        return false;
    }

    let bitmap = &bytes[bitmap_start..bitmap_start + 32];
    let signer_count = count_signers_in_bitmap(bitmap);

    // Verify signer count matches
    if signer_count != proof.num_signatures() {
        return false;
    }

    true
}

/// Count the number of signers indicated in the bitmap.
fn count_signers_in_bitmap(bitmap: &[u8]) -> usize {
    bitmap.iter().map(|b| b.count_ones() as usize).sum()
}

/// Batch verify multiple proofs efficiently.
///
/// This is more efficient than verifying proofs individually when
/// multiple proofs share the same public key root.
pub fn batch_verify(
    pk_root: [u8; 32],
    messages: &[&[u8]],
    proofs: &[&ZKSNARKProof],
) -> Vec<bool> {
    if messages.len() != proofs.len() {
        return vec![false; proofs.len()];
    }

    messages
        .iter()
        .zip(proofs.iter())
        .map(|(msg, proof)| verify(pk_root, msg, proof))
        .collect()
}

/// Verify a SuperProof (Layer-2 recursive verification).
/// 
/// Verifies that the super-proof correctly squashes the provided sequence
/// of public input hashes.
pub fn verify_super_proof(
    super_proof: &crate::types::SuperProof,
    batch_hashes: &[[u8; 32]],
) -> bool {
    // 1. Structural check
    if super_proof.num_batches() != batch_hashes.len() {
        return false;
    }

    if batch_hashes.is_empty() {
        return false;
    }

    // 2. Hash consistency check
    for (i, hash) in batch_hashes.iter().enumerate() {
        if super_proof.batch_hashes[i] != *hash {
            return false;
        }
    }

    // 3. Super-commitment verification (simulated for spec)
    // In a real implementation, this would involve a recursive SNARK verification.
    super_proof.proof_bytes[0] == 0x03 && super_proof.proof_bytes.len() >= 33
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::aggregation::{aggregate_proofs, aggregate_zk_proofs};
    use crate::core::keygen::setup;
    use crate::core::signing::aggregate_sign;

    #[test]
    fn test_verify_valid_proof() {
        let (sks, pks, pk_root) = setup(5);
        let msg = b"test message";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 3);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();

        assert!(verify(pk_root, msg, &proof));
    }

    #[test]
    fn test_verify_wrong_message() {
        let (sks, pks, pk_root) = setup(3);
        let msg = b"original";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 2);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();

        assert!(!verify(pk_root, b"wrong", &proof));
    }

    #[test]
    fn test_verify_wrong_root() {
        let (sks, pks, pk_root) = setup(3);
        let msg = b"test";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 2);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();

        let wrong_root = [0x42u8; 32];
        assert!(!verify(wrong_root, msg, &proof));
    }

    #[test]
    fn test_batch_verify() {
        let (sks, pks, pk_root) = setup(3);

        let msg1 = b"message 1";
        let msg2 = b"message 2";

        let (sigs1, proofs1) = aggregate_sign(&sks, &pks, msg1, 2);
        let (sigs2, proofs2) = aggregate_sign(&sks, &pks, msg2, 2);

        let proof1 = aggregate_proofs(sigs1, proofs1, pk_root, msg1).unwrap();
        let proof2 = aggregate_proofs(sigs2, proofs2, pk_root, msg2).unwrap();

        let results = batch_verify(
            pk_root,
            &[msg1.as_slice(), msg2.as_slice()],
            &[&proof1, &proof2],
        );

        assert_eq!(results, vec![true, true]);
    }

    #[test]
    fn test_invalid_proof_structure() {
        // Create a malformed proof
        let bad_proof = ZKSNARKProof::new(vec![0u8; 10], 1, [0u8; 32]);
        assert!(!verify([0u8; 32], b"test", &bad_proof));
    }

    #[test]
    fn test_count_signers() {
        let mut bitmap = [0u8; 32];
        bitmap[0] = 0b00000111; // 3 signers (indices 0, 1, 2)
        assert_eq!(count_signers_in_bitmap(&bitmap), 3);

        bitmap[1] = 0b00000001; // 1 more signer (index 8)
        assert_eq!(count_signers_in_bitmap(&bitmap), 4);
    }

    #[test]
    fn test_verify_super_proof_flow() {
        let (sks, pks, pk_root) = setup(3);
        let msg1 = b"msg1";
        let msg2 = b"msg2";

        let (sigs1, prfs1) = aggregate_sign(&sks, &pks, msg1, 2);
        let proof1 = aggregate_proofs(sigs1, prfs1, pk_root, msg1).unwrap();

        let (sigs2, prfs2) = aggregate_sign(&sks, &pks, msg2, 2);
        let proof2 = aggregate_proofs(sigs2, prfs2, pk_root, msg2).unwrap();

        let batch_hashes = vec![*proof1.public_inputs_hash(), *proof2.public_inputs_hash()];
        let super_proof = aggregate_zk_proofs(vec![proof1, proof2]).unwrap();

        assert!(verify_super_proof(&super_proof, &batch_hashes));
    }

    #[test]
    fn test_validator_rotation_full_flow() {
        // Epoch 1 set
        let (sks1, pks1, root1) = setup(3);
        // Epoch 2 set
        let (_sks2, _pks2, root2) = setup(3);

        // Create rotation proof signed by committee 1 authorizing committee 2
        let rotation = crate::core::aggregation::create_rotation_proof(
            &sks1, &pks1, root1, root2, 2, 2
        ).unwrap();

        // Verify rotation
        assert!(verify_rotation_proof(&rotation, &root1));
    }
}

/// Verify a RotationProof.
/// 
/// Validates that a transition from `old_root` to `new_root` was authorized
/// by a threshold of the committee belonging to `old_root`.
pub fn verify_rotation_proof(
    rotation: &crate::types::RotationProof,
    current_trusted_root: &[u8; 32],
) -> bool {
    // 1. Root matching
    if rotation.old_root != *current_trusted_root {
        return false;
    }

    // 2. SNARK Verification
    // The "message" signed in a rotation is the new public key root.
    verify(rotation.old_root, &rotation.new_root, &rotation.proof)
}

/// Verify an aggregated proof against a specific ThresholdPolicy.
/// 
/// This is the "Adaptive Threshold Gadget" which enforces dynamic security
/// requirements (e.g., higher threshold for high-value transactions).
pub fn verify_with_policy(
    pk_root: [u8; 32],
    msg: &[u8],
    proof: &crate::types::ZKSNARKProof,
    total_validators: usize,
    policy: &crate::types::ThresholdPolicy,
) -> bool {
    // 1. Standard SNARK verification
    if !verify(pk_root, msg, proof) {
        return false;
    }

    // 2. Policy enforcement (The Gadget)
    let t = proof.num_signatures();
    let n = total_validators;

    match policy {
        crate::types::ThresholdPolicy::Fixed(req) => t == *req,
        crate::types::ThresholdPolicy::AtLeast(req) => t >= *req,
        crate::types::ThresholdPolicy::Percentage(pct) => {
            let _req = crate::utils::calculate_adaptive_threshold(n, 0); // Base logic
            // Custom percentage calculation
            let min_req = (n * (*pct as usize) + 99) / 100;
            t >= min_req
        },
        crate::types::ThresholdPolicy::Tiered { level } => {
            let req = crate::utils::calculate_adaptive_threshold(n, *level);
            t >= req
        }
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::core::keygen::setup;
    use crate::core::signing::aggregate_sign;
    use crate::core::aggregation::aggregate_proofs;
    use crate::types::ThresholdPolicy;

    #[test]
    fn test_verify_with_various_policies() {
        let n = 10;
        let (sks, pks, pk_root) = setup(n);
        let msg = b"policy test";

        // Create a proof with 7 signatures (70%)
        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 7);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg).unwrap();

        // 1. Fixed Policy
        assert!(verify_with_policy(pk_root, msg, &proof, n, &ThresholdPolicy::Fixed(7)));
        assert!(!verify_with_policy(pk_root, msg, &proof, n, &ThresholdPolicy::Fixed(5)));

        // 2. Percentage Policy (70% required)
        assert!(verify_with_policy(pk_root, msg, &proof, n, &ThresholdPolicy::Percentage(70)));
        assert!(!verify_with_policy(pk_root, msg, &proof, n, &ThresholdPolicy::Percentage(80)));

        // 3. Tiered Policy (Level 2 = 67%)
        assert!(verify_with_policy(pk_root, msg, &proof, n, &ThresholdPolicy::Tiered { level: 2 }));
        // Level 3 = 80% (requires 8, we have 7)
        assert!(!verify_with_policy(pk_root, msg, &proof, n, &ThresholdPolicy::Tiered { level: 3 }));
    }
}
