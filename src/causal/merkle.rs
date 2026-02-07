//! Incremental Merkle Tree for causal event logging.
//!
//! # Performance (v0.1.0)
//!
//! Each `insert()` call rebuilds the entire tree from all leaves via
//! `MerkleTree::from_leaves()`, making insertion **O(N)** per call and
//! **O(N²)** amortized for N sequential inserts. This is acceptable for
//! the spec prototype but must be replaced with an O(log N) incremental
//! algorithm (e.g., sparse Merkle tree or hash-path update) before
//! production use.

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
