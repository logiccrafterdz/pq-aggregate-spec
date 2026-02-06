//! Blockchain adapter traits for cross-chain proof submission.
//!
//! Provides a unified interface for encoding proofs for different blockchains.

use alloc::vec::Vec;
use crate::types::ZKSNARKProof;
use crate::error::Result;

/// Trait for blockchain-specific proof encoding and verification hints.
///
/// Implementors provide chain-specific serialization and instruction generation
/// for on-chain proof verification.
pub trait BlockchainAdapter {
    /// The instruction type for this blockchain (e.g., Solana Instruction, EVM calldata).
    type Instruction;
    
    /// The account/address type for this blockchain.
    type Address;
    
    /// Encode a proof for on-chain submission.
    ///
    /// Returns bytes suitable for the target blockchain's transaction format.
    fn encode_proof(&self, proof: &ZKSNARKProof) -> Vec<u8>;
    
    /// Decode a proof from on-chain bytes.
    ///
    /// Returns `None` if the bytes are malformed.
    fn decode_proof(&self, bytes: &[u8]) -> Option<ZKSNARKProof>;
    
    /// Generate a verification instruction for on-chain verification.
    ///
    /// # Arguments
    /// * `proof` - The proof to verify
    /// * `program_id` - The verifier program address
    /// * `pk_root` - The public key Merkle root
    /// * `msg_hash` - Hash of the signed message
    fn create_verify_instruction(
        &self,
        proof: &ZKSNARKProof,
        program_id: &Self::Address,
        pk_root: &[u8; 32],
        msg_hash: &[u8; 32],
    ) -> Result<Self::Instruction>;
    
    /// Get the expected proof size for this adapter.
    fn expected_proof_size(&self) -> usize {
        // Default: use the compact encoding size
        39 // header size, actual proof bytes are variable
    }
    
    /// Get the chain identifier string.
    fn chain_id(&self) -> &'static str;
}

/// Verification hint for lightweight on-chain verifiers.
///
/// Contains precomputed values that speed up on-chain verification.
#[derive(Clone, Debug)]
pub struct VerificationHint {
    /// Commitment to the proof (for deferred verification)
    pub proof_commitment: [u8; 32],
    /// Number of signatures in the aggregate
    pub num_signatures: u16,
    /// Merkle root of public keys
    pub pk_root: [u8; 32],
    /// Hash of the signed message
    pub msg_hash: [u8; 32],
    /// Chain-specific metadata
    pub metadata: Vec<u8>,
}

impl VerificationHint {
    /// Create a new verification hint.
    pub fn new(
        proof: &ZKSNARKProof,
        pk_root: [u8; 32],
        msg_hash: [u8; 32],
    ) -> Self {
        use sha3::{Digest, Sha3_256};
        
        let mut hasher = Sha3_256::new();
        hasher.update(proof.as_bytes());
        let proof_commitment: [u8; 32] = hasher.finalize().into();
        
        Self {
            proof_commitment,
            num_signatures: proof.num_signatures() as u16,
            pk_root,
            msg_hash,
            metadata: Vec::new(),
        }
    }
    
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(98 + self.metadata.len());
        out.extend_from_slice(&self.proof_commitment);
        out.extend_from_slice(&self.num_signatures.to_le_bytes());
        out.extend_from_slice(&self.pk_root);
        out.extend_from_slice(&self.msg_hash);
        out.extend_from_slice(&self.metadata);
        out
    }
}

pub mod solana;
pub mod ethereum;

/// A default adapter for systems that don't need chain-specific encoding.
pub struct DefaultAdapter;

impl BlockchainAdapter for DefaultAdapter {
    type Instruction = Vec<u8>;
    type Address = [u8; 32];
    
    fn encode_proof(&self, proof: &ZKSNARKProof) -> Vec<u8> {
        proof.to_bytes()
    }
    
    fn decode_proof(&self, bytes: &[u8]) -> Option<ZKSNARKProof> {
        ZKSNARKProof::from_bytes(bytes)
    }
    
    fn create_verify_instruction(
        &self,
        proof: &ZKSNARKProof,
        _program_id: &Self::Address,
        pk_root: &[u8; 32],
        msg_hash: &[u8; 32],
    ) -> Result<Self::Instruction> {
        let hint = VerificationHint::new(proof, *pk_root, *msg_hash);
        Ok(hint.to_bytes())
    }
    
    fn chain_id(&self) -> &'static str {
        "generic"
    }
}
