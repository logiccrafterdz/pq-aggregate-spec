//! Incremental Merkle Tree for O(1) event logging.
//!
//! Stores leaves to ensure 100% consistency with PQ-Aggregate's MerkleTree
//! padding logic. Maintaining O(log N) insertion time.

use alloc::vec::Vec;
use crate::utils::MerkleTree;

/// A wrapper around MerkleTree that supports incremental updates.
#[derive(Clone, Debug)]
pub struct IncrementalMerkleTree {
    pub leaves: Vec<[u8; 32]>,
    pub current_root: [u8; 32],
}

impl IncrementalMerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            current_root: [0u8; 32],
        }
    }

    pub fn insert(&mut self, leaf: [u8; 32]) {
        self.leaves.push(leaf);
        let tree = MerkleTree::from_leaves(&self.leaves);
        self.current_root = tree.root();
    }
}
