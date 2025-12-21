//! Utility functions and structures for PQ-Aggregate.
//!
//! Includes Merkle tree implementation and adaptive threshold calculation.

use alloc::vec;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_256};

use crate::types::MerkleProof;

/// SHA3-256 hash helper.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute challenge hash: c_i = H(m || i || nonce_i)
/// Per the paper's security requirement: every validator computes their own challenge.
pub fn compute_challenge(message: &[u8], signer_index: usize, nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    hasher.update(&signer_index.to_le_bytes());
    hasher.update(nonce);
    hasher.finalize().into()
}

/// Merkle tree for public key aggregation.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// All nodes in the tree (leaves at the end, root at index 0)
    nodes: Vec<[u8; 32]>,
    /// Number of leaves
    num_leaves: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data (public key hashes).
    pub fn from_leaves(leaves: &[[u8; 32]]) -> Self {
        let num_leaves = leaves.len();
        if num_leaves == 0 {
            return Self {
                nodes: vec![[0u8; 32]],
                num_leaves: 0,
            };
        }

        // Pad to next power of 2
        let padded_size = num_leaves.next_power_of_two();
        let mut padded_leaves = leaves.to_vec();
        padded_leaves.resize(padded_size, [0u8; 32]);

        // Total nodes = 2 * padded_size - 1
        let total_nodes = 2 * padded_size - 1;
        let mut nodes = vec![[0u8; 32]; total_nodes];

        // Place leaves at the end
        let leaf_start = padded_size - 1;
        for (i, leaf) in padded_leaves.iter().enumerate() {
            nodes[leaf_start + i] = *leaf;
        }

        // Build internal nodes bottom-up
        for i in (0..leaf_start).rev() {
            let left = nodes[2 * i + 1];
            let right = nodes[2 * i + 2];
            nodes[i] = hash_pair(&left, &right);
        }

        Self { nodes, num_leaves }
    }

    /// Build a Merkle tree from public keys.
    pub fn from_public_keys(public_keys: &[crate::types::PublicKey]) -> Self {
        let leaves: Vec<[u8; 32]> = public_keys
            .iter()
            .map(|pk| sha3_256(pk.as_bytes()))
            .collect();
        Self::from_leaves(&leaves)
    }

    /// Get the Merkle root.
    pub fn root(&self) -> [u8; 32] {
        self.nodes.first().copied().unwrap_or([0u8; 32])
    }

    /// Generate a Merkle proof for a leaf at the given index.
    pub fn prove(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.num_leaves {
            return None;
        }

        let padded_size = self.num_leaves.next_power_of_two();
        let leaf_start = padded_size - 1;
        let mut node_index = leaf_start + leaf_index;
        let leaf_hash = self.nodes[node_index];

        let mut siblings = Vec::new();

        while node_index > 0 {
            let sibling_index = if node_index % 2 == 1 {
                node_index + 1
            } else {
                node_index - 1
            };

            if sibling_index < self.nodes.len() {
                siblings.push(self.nodes[sibling_index]);
            }

            node_index = (node_index - 1) / 2;
        }

        Some(MerkleProof::new(siblings, leaf_index, leaf_hash))
    }

    /// Verify a Merkle proof against the root.
    pub fn verify_proof(root: &[u8; 32], proof: &MerkleProof) -> bool {
        let mut current_hash = proof.leaf_hash;
        let mut index = proof.leaf_index;

        for sibling in &proof.siblings {
            current_hash = if index % 2 == 0 {
                hash_pair(&current_hash, sibling)
            } else {
                hash_pair(sibling, &current_hash)
            };
            index /= 2;
        }

        &current_hash == root
    }
}

/// Hash two nodes together.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Calculate adaptive threshold based on Appendix B of the paper.
///
/// The adaptive threshold adjusts based on:
/// - Number of participants (n)
/// - Security level (1-3, where 3 is highest)
///
/// Returns the minimum number of signatures required.
pub fn calculate_adaptive_threshold(n: usize, security_level: u8) -> usize {
    if n == 0 {
        return 0;
    }

    // Base threshold ratios per security level
    let ratio = match security_level {
        1 => 0.51, // Simple majority
        2 => 0.67, // Two-thirds
        3 => 0.75, // Three-quarters
        _ => 0.67, // Default to level 2
    };

    let threshold = (n as f64 * ratio).ceil() as usize;

    // Ensure at least 1 and at most n
    threshold.max(1).min(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let hash = sha3_256(b"test");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaves = [sha3_256(b"leaf0")];
        let tree = MerkleTree::from_leaves(&leaves);
        assert_eq!(tree.root(), leaves[0]);
    }

    #[test]
    fn test_merkle_tree_multiple_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| sha3_256(&[i as u8])).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        
        // Verify all proofs
        for i in 0..4 {
            let proof = tree.prove(i).unwrap();
            assert!(MerkleTree::verify_proof(&tree.root(), &proof));
        }
    }

    #[test]
    fn test_adaptive_threshold() {
        assert_eq!(calculate_adaptive_threshold(5, 1), 3); // 51% of 5 = 2.55 -> 3
        assert_eq!(calculate_adaptive_threshold(5, 2), 4); // 67% of 5 = 3.35 -> 4
        assert_eq!(calculate_adaptive_threshold(5, 3), 4); // 75% of 5 = 3.75 -> 4
        assert_eq!(calculate_adaptive_threshold(10, 2), 7); // 67% of 10 = 6.7 -> 7
    }

    #[test]
    fn test_compute_challenge() {
        let msg = b"test message";
        let nonce = [1u8; 32];
        
        let c1 = compute_challenge(msg, 0, &nonce);
        let c2 = compute_challenge(msg, 1, &nonce);
        
        // Different indices should produce different challenges
        assert_ne!(c1, c2);
    }
}
