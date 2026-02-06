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

    /// Serialize to compact binary format for on-chain submission.
    /// 
    /// Format: [version:1][num_sigs:2][inputs_hash:32][proof_len:4][proof_bytes:N]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(39 + self.proof_bytes.len());
        
        // Version byte
        out.push(0x02);
        
        // Number of signatures (2 bytes, little-endian)
        out.extend_from_slice(&(self.num_signatures as u16).to_le_bytes());
        
        // Public inputs hash (32 bytes)
        out.extend_from_slice(&self.public_inputs_hash);
        
        // Proof length (4 bytes, little-endian)
        out.extend_from_slice(&(self.proof_bytes.len() as u32).to_le_bytes());
        
        // Proof bytes
        out.extend_from_slice(&self.proof_bytes);
        
        out
    }

    /// Deserialize from compact binary format.
    /// 
    /// Returns `None` if the bytes are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // Minimum size: version(1) + num_sigs(2) + hash(32) + len(4) = 39
        if bytes.len() < 39 {
            return None;
        }

        // Check version
        if bytes[0] != 0x02 {
            return None;
        }

        // Parse num_signatures
        let num_signatures = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;

        // Parse public_inputs_hash
        let mut public_inputs_hash = [0u8; 32];
        public_inputs_hash.copy_from_slice(&bytes[3..35]);

        // Parse proof length
        let proof_len = u32::from_le_bytes([bytes[35], bytes[36], bytes[37], bytes[38]]) as usize;

        // Validate total length
        if bytes.len() != 39 + proof_len {
            return None;
        }

        // Extract proof bytes
        let proof_bytes = bytes[39..].to_vec();

        Some(Self {
            proof_bytes,
            num_signatures,
            public_inputs_hash,
        })
    }

    /// Compress the proof bytes using DEFLATE (miniz_oxide).
    /// 
    /// Only available if the `compression` feature is enabled.
    #[cfg(feature = "compression")]
    pub fn compress(&self) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec(&self.to_bytes(), 6)
    }

    /// Decompress a proof from DEFLATE bytes.
    #[cfg(feature = "compression")]
    pub fn decompress(bytes: &[u8]) -> Option<Self> {
        let decompressed = miniz_oxide::inflate::decompress_to_vec(bytes).ok()?;
        Self::from_bytes(&decompressed)
    }
}

/// A creative "ProofBatch" for high-density multi-proof storage.
/// 
/// Instead of storing individual proofs, we aggregate them into a single blob
/// and apply layer-2 compression for massive space savings in rollups.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBatch {
    pub proofs: Vec<ZKSNARKProof>,
    pub metadata: Vec<u8>,
}

impl ProofBatch {
    pub fn new(proofs: Vec<ZKSNARKProof>) -> Self {
        Self { proofs, metadata: Vec::new() }
    }

    /// Serialize and compress the entire batch.
    #[cfg(feature = "compression")]
    pub fn to_compressed_blob(&self) -> Vec<u8> {
        // Serialization of Vec<ZKSNARKProof> is already handled by serde
        let bincode = serde_json::to_vec(self).unwrap_or_default();
        miniz_oxide::deflate::compress_to_vec(&bincode, 9) // Max compression
    }
}

/// A "SuperProof" squashes multiple ZKSNARKProofs into a single one.
/// 
/// This is the "ideal result" for L2 rollups, where thousands of signatures
/// from different epochs/batches are verified in a single O(1) step.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuperProof {
    /// Compressed super-proof bytes
    pub(crate) proof_bytes: Vec<u8>,
    /// List of public input hashes verified by this super-proof
    pub(crate) batch_hashes: Vec<[u8; 32]>,
    /// Total signatures covered
    pub(crate) total_signatures: usize,
}

impl SuperProof {
    pub fn new(proof_bytes: Vec<u8>, batch_hashes: Vec<[u8; 32]>, total_signatures: usize) -> Self {
        Self { proof_bytes, batch_hashes, total_signatures }
    }

    pub fn size(&self) -> usize {
        self.proof_bytes.len()
    }

    pub fn num_batches(&self) -> usize {
        self.batch_hashes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zksnark_proof_serialization_roundtrip() {
        let original = ZKSNARKProof::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            42,
            [0xAB; 32],
        );

        let bytes = original.to_bytes();
        let recovered = ZKSNARKProof::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(recovered.num_signatures(), 42);
        assert_eq!(recovered.public_inputs_hash(), &[0xAB; 32]);
        assert_eq!(recovered.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_zksnark_proof_compression() {
        // Create a proof with redundant data to test compression
        let original = ZKSNARKProof::new(
            vec![0u8; 1000],
            100,
            [0; 32],
        );

        let compressed = original.compress();
        let decompressed = ZKSNARKProof::decompress(&compressed).expect("Decompression failed");

        assert_eq!(decompressed.num_signatures(), 100);
        assert!(compressed.len() < original.to_bytes().len());
    }

    #[test]
    fn test_zksnark_proof_from_bytes_invalid() {
        // Too short
        assert!(ZKSNARKProof::from_bytes(&[0x02; 10]).is_none());
        
        // Wrong version
        let mut bad_version = vec![0x01]; // Wrong version
        bad_version.extend_from_slice(&[0; 38]);
        assert!(ZKSNARKProof::from_bytes(&bad_version).is_none());
    }
}

