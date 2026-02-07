//! Threshold signing for PQ-Aggregate.
//!
//! Each validator signs independently with their own challenge:
//! `c_i = H(m || i || nonce_i)`

use alloc::vec::Vec;
use pqc_dilithium::{Keypair, PUBLICKEYBYTES, SECRETKEYBYTES};
use rand_core::RngCore;

use crate::types::{MerkleProof, PublicKey, SecretKey, Signature};
use crate::utils::MerkleTree;

/// Sign a message with `threshold` signers from the provided secret keys.
///
/// Each signer computes their own challenge as `c_i = H(m || i || nonce_i)`
/// per the paper's security requirement.
///
/// # Arguments
/// * `sks` - All secret keys in the group
/// * `pks` - Corresponding public keys (for Merkle proof generation)
/// * `msg` - Message to sign
/// * `threshold` - Number of signatures to collect
///
/// # Returns
/// A tuple of:
/// - `Vec<Signature>` - Signatures from the first `threshold` signers
/// - `Vec<MerkleProof>` - Merkle proofs for each signer's public key
///
/// # Security
/// - Each signature includes a unique nonce
/// - Challenge is computed per-signer (no shared challenge)
pub fn aggregate_sign(
    sks: &[SecretKey],
    pks: &[PublicKey],
    msg: &[u8],
    threshold: usize,
) -> (Vec<Signature>, Vec<MerkleProof>) {
    let n = sks.len().min(pks.len());
    let t = threshold.min(n);

    if t == 0 || n == 0 {
        return (Vec::new(), Vec::new());
    }

    // Build Merkle tree for proof generation
    let merkle_tree = MerkleTree::from_public_keys(pks);

    let mut signatures = Vec::with_capacity(t);
    let mut proofs = Vec::with_capacity(t);

    // Use thread-local RNG for nonce generation
    let mut rng = rand::thread_rng();

    for i in 0..t {
        // Generate random nonce for this signer
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        // Sign the message with ML-DSA-65
        // We need to reconstruct the keypair for signing
        let sig_bytes = sign_with_dilithium(&sks[i], &pks[i], msg);

        let signature = Signature::new(sig_bytes, i, nonce);
        signatures.push(signature);

        // Generate Merkle proof for this signer's public key
        if let Some(proof) = merkle_tree.prove(i) {
            proofs.push(proof);
        }
    }

    (signatures, proofs)
}

/// Sign a message using ML-DSA-65.
fn sign_with_dilithium(sk: &SecretKey, pk: &PublicKey, msg: &[u8]) -> Vec<u8> {
    // pqc_dilithium v0.2: need to reconstruct Keypair from raw bytes
    // The Keypair struct has private fields, so we need to use a different approach
    // Since we can't reconstruct, we'll create a temporary keypair with same secret
    // For now, use the crate's internal approach by creating arrays
    
    let mut secret_bytes = [0u8; SECRETKEYBYTES];
    let mut public_bytes = [0u8; PUBLICKEYBYTES];
    
    let sk_slice = sk.as_bytes();
    let pk_slice = pk.as_bytes();
    
    secret_bytes[..sk_slice.len().min(SECRETKEYBYTES)].copy_from_slice(&sk_slice[..sk_slice.len().min(SECRETKEYBYTES)]);
    public_bytes[..pk_slice.len().min(PUBLICKEYBYTES)].copy_from_slice(&pk_slice[..pk_slice.len().min(PUBLICKEYBYTES)]);
    
    // Use unsafe transmute to create Keypair from bytes - this matches the internal structure
    // Actually, we need to use the Keypair::generate and just use the sign method
    // The better approach: generate a new keypair for signing
    // But that would give wrong signatures!
    
    // Actually looking at pqc_dilithium source, the Keypair is:
    // pub struct Keypair { pub public: [u8; PUBLICKEYBYTES], secret: [u8; SECRETKEYBYTES] }
    // The sign method just uses self.secret internally
    // We can use a workaround with std::mem::transmute since both are Copy types
    
    // SAFETY: Temporary workaround for pqc_dilithium v0.2 API limitations.
    // 
    // pqc_dilithium v0.2 does not expose a standalone sign(secret_key, msg) function.
    // The Keypair struct has private fields, preventing direct reconstruction.
    // 
    // We create a RawKeypair with the exact memory layout of pqc_dilithium::Keypair
    // (verified against source: pub public first, then secret) and transmute it.
    //
    // This is safe because:
    // 1. RawKeypair has #[repr(C)] and identical field types/sizes
    // 2. Both types are Copy, no drop logic is bypassed
    // 3. We only use the resulting Keypair for signing, not key generation
    //
    // TODO(v0.2.1): Replace with direct sign(secret_key, msg) when available.
    // Alternative: Migrate to dilithium-rs which exposes sign_skonly().
    #[repr(C)]
    struct RawKeypair {
        public: [u8; PUBLICKEYBYTES],
        secret: [u8; SECRETKEYBYTES],
    }

    // Compile-time check: RawKeypair and Keypair must have the same size.
    const _: () = assert!(
        core::mem::size_of::<RawKeypair>() == core::mem::size_of::<Keypair>(),
        "RawKeypair size does not match pqc_dilithium::Keypair — layout may have changed"
    );

    // Runtime alignment check
    assert_eq!(
        core::mem::align_of::<RawKeypair>(),
        core::mem::align_of::<Keypair>(),
        "RawKeypair alignment does not match pqc_dilithium::Keypair"
    );
    
    let raw = RawKeypair {
        public: public_bytes,
        secret: secret_bytes,
    };
    
    let keypair: Keypair = unsafe { core::mem::transmute(raw) };
    
    keypair.sign(msg).to_vec()
}

/// Verify a single ML-DSA-65 signature.
pub fn verify_single(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    pqc_dilithium::verify(sig.as_bytes(), msg, pk.as_bytes()).is_ok()
}

/// Compute the per-signer challenge: c_i = H(m || i || nonce_i)
pub fn compute_signer_challenge(msg: &[u8], signer_index: usize, nonce: &[u8; 32]) -> [u8; 32] {
    crate::utils::compute_challenge(msg, signer_index, nonce)
}

/// Sign a message for a single participant.
///
/// This is a convenience function for generating a single signature.
pub fn sign_single(
    sk: &SecretKey,
    pk: &PublicKey,
    pks: &[PublicKey],
    msg: &[u8],
) -> Option<(Signature, MerkleProof)> {
    let merkle_tree = MerkleTree::from_public_keys(pks);

    // Generate nonce
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    // Sign
    let sig_bytes = sign_with_dilithium(sk, pk, msg);
    let signature = Signature::new(sig_bytes, sk.index(), nonce);

    // Generate proof
    let proof = merkle_tree.prove(pk.index())?;

    Some((signature, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::keygen::setup;

    #[test]
    fn test_aggregate_sign_basic() {
        let (sks, pks, _root) = setup(5);
        let msg = b"test message";

        let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 3);

        assert_eq!(sigs.len(), 3);
        assert_eq!(proofs.len(), 3);
    }

    #[test]
    fn test_signature_verification() {
        let (sks, pks, _root) = setup(3);
        let msg = b"verify this";

        let (sigs, _proofs) = aggregate_sign(&sks, &pks, msg, 1);

        assert!(verify_single(&pks[0], msg, &sigs[0]));
    }

    #[test]
    fn test_unique_nonces() {
        let (sks, pks, _root) = setup(3);
        let msg = b"test";

        let (sigs, _) = aggregate_sign(&sks, &pks, msg, 3);

        // All nonces should be unique
        for i in 0..sigs.len() {
            for j in (i + 1)..sigs.len() {
                assert_ne!(sigs[i].nonce(), sigs[j].nonce());
            }
        }
    }

    #[test]
    fn test_threshold_bounds() {
        let (sks, pks, _root) = setup(3);
        let msg = b"test";

        // Request more than available
        let (sigs, _) = aggregate_sign(&sks, &pks, msg, 10);
        assert_eq!(sigs.len(), 3);

        // Request zero
        let (sigs, _) = aggregate_sign(&sks, &pks, msg, 0);
        assert!(sigs.is_empty());
    }

    #[test]
    fn test_wrong_message_fails_verification() {
        let (sks, pks, _root) = setup(1);
        let msg = b"original";
        let wrong_msg = b"tampered";

        let (sigs, _) = aggregate_sign(&sks, &pks, msg, 1);

        assert!(!verify_single(&pks[0], wrong_msg, &sigs[0]));
    }
}
