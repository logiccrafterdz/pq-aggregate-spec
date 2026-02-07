//! Proof aggregation for PQ-Aggregate.
//!
//! Aggregates multiple ML-DSA signatures into a compact proof using
//! a commitment-based scheme (simulating Nova recursive folding for v0.1.0).

use alloc::string::ToString;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_256};

use crate::error::{PQAggregateError, Result};
use crate::types::{MerkleProof, PublicKey, Signature, ZKSNARKProof};
use crate::utils::MerkleTree;

/// Maximum proof size in bytes (target: ≤1.2 KB).
pub const MAX_PROOF_SIZE: usize = 1228;

/// Aggregate multiple signatures into a single ZK proof.
///
/// This function validates Merkle proofs and creates a commitment-based
/// aggregated proof. In v0.1.0, this simulates Nova recursive folding.
///
/// # Arguments
/// * `sigs` - Individual signatures from threshold signers
/// * `proofs` - Merkle proofs for each signer's public key
/// * `pk_root` - The Merkle root of all public keys
/// * `msg` - The signed message
///
/// # Returns
/// * `Ok(ZKSNARKProof)` - The aggregated proof
/// * `Err(PQAggregateError)` - If validation or aggregation fails
///
/// # Security
/// - All Merkle proofs must verify against `pk_root`
/// - Each signature is verified against its corresponding public key
/// - The proof commits to all signatures and the message
pub fn aggregate_proofs(
    sigs: Vec<Signature>,
    proofs: Vec<MerkleProof>,
    pk_root: [u8; 32],
    msg: &[u8],
    pks: &[PublicKey],
) -> Result<ZKSNARKProof> {
    // Validate inputs
    if sigs.is_empty() {
        return Err(PQAggregateError::InsufficientSignatures {
            required: 1,
            provided: 0,
        });
    }

    if sigs.len() != proofs.len() {
        return Err(PQAggregateError::InvalidInput {
            reason: "Signature and proof count mismatch".to_string(),
        });
    }

    // Validate all Merkle proofs
    for (i, proof) in proofs.iter().enumerate() {
        if !MerkleTree::verify_proof(&pk_root, proof) {
            return Err(PQAggregateError::MerkleProofInvalid {
                index: i,
                reason: "Proof does not verify against pk_root".to_string(),
            });
        }
    }

    // Verify each ML-DSA signature against its public key
    for (i, sig) in sigs.iter().enumerate() {
        let signer_idx = sig.signer_index();
        if signer_idx >= pks.len() {
            return Err(PQAggregateError::InvalidInput {
                reason: alloc::format!("Signer index {} out of bounds (have {} keys)", signer_idx, pks.len()),
            });
        }
        if !crate::core::signing::verify_single(&pks[signer_idx], msg, sig) {
            return Err(PQAggregateError::InvalidInput {
                reason: alloc::format!("Signature from signer {} failed ML-DSA verification", signer_idx),
            });
        }
    }

    // Create aggregated proof using commitment scheme
    // This simulates Nova folding for v0.1.0
    let proof = create_aggregated_commitment(&sigs, &proofs, &pk_root, msg)?;

    Ok(proof)
}

/// Create a commitment-based aggregated proof.
///
/// The proof structure (simulating Nova):
/// - Commitment to all signature data
/// - Accumulator of signer indices
/// - Public inputs hash
fn create_aggregated_commitment(
    sigs: &[Signature],
    proofs: &[MerkleProof],
    pk_root: &[u8; 32],
    msg: &[u8],
) -> Result<ZKSNARKProof> {
    let mut hasher = Sha3_256::new();

    // Commit to public inputs
    hasher.update(pk_root);
    hasher.update(msg);
    hasher.update(&(sigs.len() as u64).to_le_bytes());

    let public_inputs_hash: [u8; 32] = hasher.finalize_reset().into();

    // Create proof bytes: commitments + compressed signature data
    let mut proof_bytes = Vec::new();

    // Header: version (1 byte) + num_sigs (2 bytes)
    proof_bytes.push(0x01); // Version 1
    proof_bytes.extend_from_slice(&(sigs.len() as u16).to_le_bytes());

    // Commitment chain (simulating Nova folding)
    // Each step: commit to previous commitment + current signature
    let mut running_commitment = [0u8; 32];

    for (sig, proof) in sigs.iter().zip(proofs.iter()) {
        hasher.update(&running_commitment);
        hasher.update(&sig.signer_index().to_le_bytes());
        hasher.update(sig.nonce());
        hasher.update(proof.leaf_hash());

        // Compress signature to 32 bytes (hash of full signature)
        let sig_commitment: [u8; 32] = {
            let mut sig_hasher = Sha3_256::new();
            sig_hasher.update(sig.as_bytes());
            sig_hasher.finalize().into()
        };
        hasher.update(&sig_commitment);

        running_commitment = hasher.finalize_reset().into();
    }

    // Final commitment
    proof_bytes.extend_from_slice(&running_commitment);

    // Add compressed signer bitmap (for efficient verification)
    let bitmap = create_signer_bitmap(sigs);
    proof_bytes.extend_from_slice(&bitmap);

    // Add aggregated nonce commitment
    let nonce_commitment = compute_nonce_commitment(sigs);
    proof_bytes.extend_from_slice(&nonce_commitment);

    // Add Merkle root commitment (redundant but useful for verification)
    proof_bytes.extend_from_slice(pk_root);

    // Ensure proof size is within bounds
    if proof_bytes.len() > MAX_PROOF_SIZE {
        return Err(PQAggregateError::AggregationFailed {
            reason: "Proof exceeds maximum size".to_string(),
        });
    }

    Ok(ZKSNARKProof::new(
        proof_bytes,
        sigs.len(),
        public_inputs_hash,
    ))
}

/// Create a bitmap of which signers participated.
fn create_signer_bitmap(sigs: &[Signature]) -> [u8; 32] {
    let mut bitmap = [0u8; 32];

    for sig in sigs {
        let index = sig.signer_index();
        if index < 256 {
            bitmap[index / 8] |= 1 << (index % 8);
        }
    }

    bitmap
}

/// Compute a commitment to all nonces.
fn compute_nonce_commitment(sigs: &[Signature]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    for sig in sigs {
        hasher.update(sig.nonce());
    }

    hasher.finalize().into()
}

/// Verify that an aggregated proof is well-formed.
///
/// This performs structural validation without full verification.
pub fn validate_proof_structure(proof: &ZKSNARKProof) -> bool {
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

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::keygen::setup;
    use crate::core::signing::aggregate_sign;

    #[test]
    fn test_aggregate_proofs_basic() {
        let (sks, pks, pk_root) = setup(5);
        let msg = b"test message";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 3);
        let result = aggregate_proofs(sigs, proofs, pk_root, msg, &pks);

        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.num_signatures(), 3);
        assert!(proof.size() <= MAX_PROOF_SIZE);
    }

    #[test]
    fn test_aggregate_proofs_validates_merkle() {
        let (sks, pks, _pk_root) = setup(3);
        let msg = b"test";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 2);

        // Use wrong root
        let wrong_root = [0xFFu8; 32];
        let result = aggregate_proofs(sigs, proofs, wrong_root, msg, &pks);

        assert!(matches!(
            result,
            Err(PQAggregateError::MerkleProofInvalid { .. })
        ));
    }

    #[test]
    fn test_aggregate_proofs_empty_fails() {
        let result = aggregate_proofs(Vec::new(), Vec::new(), [0u8; 32], b"msg", &[]);

        assert!(matches!(
            result,
            Err(PQAggregateError::InsufficientSignatures { .. })
        ));
    }

    #[test]
    fn test_aggregate_proofs_mismatched_counts() {
        let (sks, pks, pk_root) = setup(3);
        let msg = b"test";

        let (sigs, mut proofs) = aggregate_sign(&sks, &pks, msg, 3);
        proofs.pop(); // Remove one proof

        let result = aggregate_proofs(sigs, proofs, pk_root, msg, &pks);

        assert!(matches!(
            result,
            Err(PQAggregateError::InvalidInput { .. })
        ));
    }

    #[test]
    fn test_proof_structure_validation() {
        let (sks, pks, pk_root) = setup(3);
        let msg = b"test";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 2);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg, &pks).unwrap();

        assert!(validate_proof_structure(&proof));
    }

    #[test]
    fn test_proof_size_constraint() {
        let (sks, pks, pk_root) = setup(10);
        let msg = b"test message for size check";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 10);
        let proof = aggregate_proofs(sigs, proofs, pk_root, msg, &pks).unwrap();

        // Proof should be compact
        println!("Proof size: {} bytes", proof.size());
        assert!(proof.size() <= MAX_PROOF_SIZE);
    }

    #[test]
    fn test_super_proof_aggregation() {
        let (sks, pks, pk_root) = setup(5);
        let msg1 = b"batch 1";
        let msg2 = b"batch 2";

        let (sigs1, proofs1) = aggregate_sign(&sks, &pks, msg1, 3);
        let proof1 = aggregate_proofs(sigs1, proofs1, pk_root, msg1, &pks).unwrap();

        let (sigs2, proofs2) = aggregate_sign(&sks, &pks, msg2, 3);
        let proof2 = aggregate_proofs(sigs2, proofs2, pk_root, msg2, &pks).unwrap();

        let super_proof = aggregate_zk_proofs(vec![proof1, proof2]).unwrap();

        assert_eq!(super_proof.num_batches(), 2);
        assert_eq!(super_proof.total_signatures, 6);
    }
}

/// Squash multiple ZKSNARKProofs into a single SuperProof.
/// 
/// In the "ideal result", this would use a SuperCircuit to verify the 
/// compressed SNARKs recursively. In this spec, we simulate the aggregation
/// via a secondary commitment chain.
pub fn aggregate_zk_proofs(proofs: Vec<ZKSNARKProof>) -> Result<crate::types::SuperProof> {
    if proofs.is_empty() {
        return Err(PQAggregateError::InvalidInput { 
            reason: "Cannot aggregate empty proof list".to_string() 
        });
    }

    let mut hasher = Sha3_256::new();
    let mut total_signatures = 0;
    let mut batch_hashes = Vec::new();

    for proof in &proofs {
        hasher.update(proof.as_bytes());
        batch_hashes.push(*proof.public_inputs_hash());
        total_signatures += proof.num_signatures();
    }

    let super_commitment: [u8; 32] = hasher.finalize().into();

    // The SuperProof bytes contain the commitment and the packed sub-proofs
    let mut proof_bytes = Vec::new();
    proof_bytes.push(0x03); // SuperProof version
    proof_bytes.extend_from_slice(&super_commitment);

    Ok(crate::types::SuperProof::new(
        proof_bytes,
        batch_hashes,
        total_signatures,
    ))
}

/// Create a RotationProof to transition between committee sets.
/// 
/// A rotation involves proving that t-of-n validators of the *old* root
/// signed a message containing the *new* root.
pub fn create_rotation_proof(
    old_sks: &[crate::types::SecretKey],
    old_pks: &[crate::types::PublicKey],
    old_root: [u8; 32],
    new_root: [u8; 32],
    epoch: u64,
    threshold: usize,
) -> Result<crate::types::RotationProof> {
    // 1. Sign the new root as the message
    let (sigs, proofs) = crate::core::signing::aggregate_sign(
        old_sks, old_pks, &new_root, threshold
    );

    // 2. Aggregate into a SNARK proof
    let zksnark = aggregate_proofs(sigs, proofs, old_root, &new_root, old_pks)?;

    // 3. Construct rotation proof
    Ok(crate::types::RotationProof::new(
        old_root,
        new_root,
        zksnark,
        epoch,
    ))
}

#[cfg(test)]
mod rotation_tests {
    use super::*;
    use crate::core::keygen::setup;

    #[test]
    fn test_rotation_proof_creation() {
        let (sks_old, pks_old, root_old) = setup(5);
        let (_sks_new, _pks_new, root_new) = setup(5);

        let result = create_rotation_proof(
            &sks_old, &pks_old, root_old, root_new, 1, 3
        );

        assert!(result.is_ok());
        let rotation = result.unwrap();
        assert_eq!(rotation.old_root, root_old);
        assert_eq!(rotation.new_root, root_new);
        assert_eq!(rotation.epoch, 1);
    }
}
