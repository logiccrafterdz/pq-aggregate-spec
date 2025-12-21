//! Key generation for PQ-Aggregate.
//!
//! Generates independent ML-DSA-65 keypairs and computes the Merkle root
//! for public key aggregation.

use alloc::vec::Vec;
use pqc_dilithium::{Keypair, PUBLICKEYBYTES, SECRETKEYBYTES};

use crate::types::{PublicKey, SecretKey};
use crate::utils::MerkleTree;

/// ML-DSA-65 public key size in bytes (from pqc_dilithium mode3).
pub const PUBLIC_KEY_SIZE: usize = PUBLICKEYBYTES;

/// ML-DSA-65 secret key size in bytes (from pqc_dilithium mode3).
pub const SECRET_KEY_SIZE: usize = SECRETKEYBYTES;

/// Setup the threshold signature scheme for `n` participants.
///
/// Generates `n` independent ML-DSA-65 keypairs and computes the Merkle root
/// of all public keys.
///
/// # Arguments
/// * `n` - Number of participants (must be >= 1)
///
/// # Returns
/// A tuple of:
/// - `Vec<SecretKey>` - Secret keys for all participants (zeroized on drop)
/// - `Vec<PublicKey>` - Public keys for all participants
/// - `[u8; 32]` - Merkle root of all public keys (pk_root)
///
/// # Example
/// ```
/// use pq_aggregate::core::keygen::setup;
///
/// let (secret_keys, public_keys, pk_root) = setup(5);
/// assert_eq!(secret_keys.len(), 5);
/// assert_eq!(public_keys.len(), 5);
/// ```
pub fn setup(n: usize) -> (Vec<SecretKey>, Vec<PublicKey>, [u8; 32]) {
    if n == 0 {
        return (Vec::new(), Vec::new(), [0u8; 32]);
    }

    let mut secret_keys = Vec::with_capacity(n);
    let mut public_keys = Vec::with_capacity(n);

    for i in 0..n {
        // Generate ML-DSA-65 keypair
        let keypair = Keypair::generate();

        // Extract and wrap keys with index metadata
        // pqc_dilithium v0.2: use expose_secret() method and public field
        let sk = SecretKey::from_bytes(keypair.expose_secret().to_vec(), i);
        let pk = PublicKey::from_bytes(keypair.public.to_vec(), i);

        secret_keys.push(sk);
        public_keys.push(pk);
    }

    // Build Merkle tree from public keys
    let merkle_tree = MerkleTree::from_public_keys(&public_keys);
    let pk_root = merkle_tree.root();

    (secret_keys, public_keys, pk_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_generates_correct_count() {
        let (sks, pks, _root) = setup(5);
        assert_eq!(sks.len(), 5);
        assert_eq!(pks.len(), 5);
    }

    #[test]
    fn test_setup_unique_keys() {
        let (_, pks, _) = setup(3);
        // All public keys should be unique
        for i in 0..pks.len() {
            for j in (i + 1)..pks.len() {
                assert_ne!(pks[i].as_bytes(), pks[j].as_bytes());
            }
        }
    }

    #[test]
    fn test_setup_key_sizes() {
        let (sks, pks, _) = setup(1);
        assert_eq!(sks[0].as_bytes().len(), SECRET_KEY_SIZE);
        assert_eq!(pks[0].as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_setup_zero_participants() {
        let (sks, pks, root) = setup(0);
        assert!(sks.is_empty());
        assert!(pks.is_empty());
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        // Note: This test verifies structure, not determinism
        // (keypairs are random each time)
        let (_, pks, root) = setup(4);
        let tree = MerkleTree::from_public_keys(&pks);
        assert_eq!(tree.root(), root);
    }
}
