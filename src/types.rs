//! Core types for PQ-Aggregate cryptographic operations.
//!
//! All sensitive cryptographic material implements `Zeroize` for secure memory handling.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-DSA-65 secret key wrapper with automatic zeroization on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// Raw secret key bytes (ML-DSA-65: 4032 bytes)
    pub(crate) bytes: Vec<u8>,
    /// Index of this key in the participant set
    pub(crate) index: usize,
}

impl SecretKey {
    /// Create a new secret key from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>, index: usize) -> Self {
        Self { bytes, index }
    }

    /// Get the raw key bytes (use with caution).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the participant index.
    pub fn index(&self) -> usize {
        self.index
    }
}

/// ML-DSA-65 public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    /// Raw public key bytes (ML-DSA-65: 1952 bytes)
    pub(crate) bytes: Vec<u8>,
    /// Index of this key in the participant set
    pub(crate) index: usize,
}

impl PublicKey {
    /// Create a new public key from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>, index: usize) -> Self {
        Self { bytes, index }
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the participant index.
    pub fn index(&self) -> usize {
        self.index
    }
}

/// ML-DSA-65 signature with signer metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    /// Raw signature bytes (ML-DSA-65: 3293 bytes)
    pub(crate) bytes: Vec<u8>,
    /// Index of the signer
    pub(crate) signer_index: usize,
    /// Per-signer nonce used in challenge computation
    pub(crate) nonce: [u8; 32],
}

impl Signature {
    /// Create a new signature.
    pub fn new(bytes: Vec<u8>, signer_index: usize, nonce: [u8; 32]) -> Self {
        Self { bytes, signer_index, nonce }
    }

    /// Get the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the signer's index.
    pub fn signer_index(&self) -> usize {
        self.signer_index
    }

    /// Get the nonce used for this signature.
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
}

/// Merkle proof for public key inclusion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Sibling hashes along the path to the root
    pub(crate) siblings: Vec<[u8; 32]>,
    /// Index of the leaf in the tree
    pub(crate) leaf_index: usize,
    /// The public key hash at this leaf
    pub(crate) leaf_hash: [u8; 32],
}

impl MerkleProof {
    /// Create a new Merkle proof.
    pub fn new(siblings: Vec<[u8; 32]>, leaf_index: usize, leaf_hash: [u8; 32]) -> Self {
        Self { siblings, leaf_index, leaf_hash }
    }

    /// Get the sibling hashes.
    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }

    /// Get the leaf index.
    pub fn leaf_index(&self) -> usize {
        self.leaf_index
    }

    /// Get the leaf hash.
    pub fn leaf_hash(&self) -> &[u8; 32] {
        &self.leaf_hash
    }
}

/// Aggregated ZKSNARK proof from Nova recursive folding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZKSNARKProof {
    /// Compressed proof bytes (target: ≤1.2 KB)
    pub(crate) proof_bytes: Vec<u8>,
    /// Number of signatures aggregated
    pub(crate) num_signatures: usize,
    /// Commitment to the public inputs
    pub(crate) public_inputs_hash: [u8; 32],
}

impl ZKSNARKProof {
    /// Create a new ZKSNARK proof.
    pub fn new(proof_bytes: Vec<u8>, num_signatures: usize, public_inputs_hash: [u8; 32]) -> Self {
        Self { proof_bytes, num_signatures, public_inputs_hash }
    }

    /// Get the raw proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }

    /// Get the number of aggregated signatures.
    pub fn num_signatures(&self) -> usize {
        self.num_signatures
    }

    /// Get the public inputs hash.
    pub fn public_inputs_hash(&self) -> &[u8; 32] {
        &self.public_inputs_hash
    }

    /// Get the proof size in bytes.
    pub fn size(&self) -> usize {
        self.proof_bytes.len()
    }
}
