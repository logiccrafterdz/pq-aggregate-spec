//! Basic Solana adapter (no RPC, encoding only).
//!
//! This module is used when the `solana-devnet` feature is not enabled.

use alloc::vec::Vec;
use crate::types::ZKSNARKProof;
use crate::error::Result;
use crate::adapters::{BlockchainAdapter, VerificationHint};

/// Adapter for the Solana blockchain (encoding only, no RPC).
pub struct SolanaAdapter;

/// A simple representation of a Solana Instruction.
#[derive(Clone, Debug)]
pub struct SolanaInstruction {
    pub program_id: [u8; 32],
    pub accounts: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

impl BlockchainAdapter for SolanaAdapter {
    type Instruction = SolanaInstruction;
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
        program_id: &Self::Address,
        pk_root: &[u8; 32],
        msg_hash: &[u8; 32],
    ) -> Result<Self::Instruction> {
        let hint = VerificationHint::new(proof, *pk_root, *msg_hash);
        
        let mut data = Vec::with_capacity(hint.to_bytes().len() + 1);
        data.push(0); // Instruction discriminator
        data.extend_from_slice(&hint.to_bytes());
        
        Ok(SolanaInstruction {
            program_id: *program_id,
            accounts: Vec::new(), 
            data,
        })
    }
    
    fn chain_id(&self) -> &'static str {
        "solana"
    }
}

impl SolanaAdapter {
    /// Generate a pseudo-PDA for a proof commitment.
    pub fn derive_proof_address(
        &self,
        program_id: &[u8; 32],
        proof_commitment: &[u8; 32],
    ) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        
        let mut hasher = Sha3_256::new();
        hasher.update(b"pq_proof");
        hasher.update(program_id);
        hasher.update(proof_commitment);
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&hasher.finalize()[..32]);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_adapter_encoding() {
        let adapter = SolanaAdapter;
        let proof = ZKSNARKProof::new(vec![1, 2, 3], 10, [0xFF; 32]);
        
        let encoded = adapter.encode_proof(&proof);
        let decoded = adapter.decode_proof(&encoded).expect("Decode failed");
        
        assert_eq!(decoded.num_signatures(), 10);
        assert_eq!(decoded.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_solana_instruction_gen() {
        let adapter = SolanaAdapter;
        let proof = ZKSNARKProof::new(vec![0; 100], 5, [1; 32]);
        let program_id = [0xAA; 32];
        let pk_root = [0xBB; 32];
        let msg_hash = [0xCC; 32];
        
        let ix = adapter.create_verify_instruction(
            &proof, &program_id, &pk_root, &msg_hash
        ).expect("Create instruction failed");
        
        assert_eq!(ix.program_id, program_id);
        assert_eq!(ix.data[0], 0); // Discriminator
    }

    #[test]
    fn test_solana_pda_derivation() {
        let adapter = SolanaAdapter;
        let addr1 = adapter.derive_proof_address(&[0; 32], &[1; 32]);
        let addr2 = adapter.derive_proof_address(&[0; 32], &[1; 32]);
        let addr3 = adapter.derive_proof_address(&[0; 32], &[2; 32]);
        
        assert_eq!(addr1, addr2);
        assert_ne!(addr1, addr3);
    }
}
