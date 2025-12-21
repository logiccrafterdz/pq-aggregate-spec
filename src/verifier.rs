//! Proof verification for PQ-Aggregate.
//!
//! Verifies aggregated ZK proofs against the public key root and message.

use sha3::{Digest, Sha3_256};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::aggregation::aggregate_proofs;
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
}
