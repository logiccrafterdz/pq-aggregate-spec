//! Ethereum-specific blockchain adapter.
//!
//! Provides encoding for EVM-based blockchains using ABI-compatible formatting.

use alloc::vec::Vec;
use crate::types::ZKSNARKProof;
use crate::error::Result;
use crate::adapters::{BlockchainAdapter, VerificationHint};

/// Adapter for Ethereum and EVM-compatible blockchains.
pub struct EthereumAdapter;

/// A simple representation of an Ethereum transaction data (calldata).
#[derive(Clone, Debug)]
pub struct EVMCalldata {
    pub contract_address: [u8; 20],
    pub selector: [u8; 4],
    pub data: Vec<u8>,
}

impl BlockchainAdapter for EthereumAdapter {
    type Instruction = EVMCalldata;
    type Address = [u8; 20];
    
    fn encode_proof(&self, proof: &ZKSNARKProof) -> Vec<u8> {
        // Ethereum prefers ABI-packed data.
        // For a simple proof, we'll prefix with length for ABI compatibility.
        let mut out = Vec::with_capacity(4 + proof.size());
        out.extend_from_slice(&(proof.size() as u32).to_be_bytes()); // Length as uint32 (big-endian for EVM)
        out.extend_from_slice(proof.as_bytes());
        out
    }
    
    fn decode_proof(&self, bytes: &[u8]) -> Option<ZKSNARKProof> {
        if bytes.len() < 4 { return None; }
        // Simple heuristic: if it looks like ZKSNARKProof binary, use that
        if bytes[0] == 0x02 {
            return ZKSNARKProof::from_bytes(bytes);
        }
        // Otherwise try to strip EVM length prefix
        ZKSNARKProof::from_bytes(&bytes[4..])
    }
    
    fn create_verify_instruction(
        &self,
        proof: &ZKSNARKProof,
        contract_address: &Self::Address,
        pk_root: &[u8; 32],
        msg_hash: &[u8; 32],
    ) -> Result<Self::Instruction> {
        let hint = VerificationHint::new(proof, *pk_root, *msg_hash);
        
        // ABI Selector for `verify(bytes32 proof_commitment, uint16 num_sigs, bytes32 pk_root, bytes32 msg_hash)`
        // This is a common pattern for ZK verifiers on Ethereum.
        let selector = [0x41, 0x6e, 0x1d, 0x4f]; // Mock selector for `verify(bytes32,uint16,bytes32,bytes32)`
        
        let mut data = Vec::with_capacity(32 + 32 + 32 + 32);
        data.extend_from_slice(&hint.proof_commitment);
        
        let mut sigs_padded = [0u8; 32];
        sigs_padded[30..32].copy_from_slice(&(hint.num_signatures).to_be_bytes());
        data.extend_from_slice(&sigs_padded); // uint256 padded
        
        data.extend_from_slice(&hint.pk_root);
        data.extend_from_slice(&hint.msg_hash);
        
        Ok(EVMCalldata {
            contract_address: *contract_address,
            selector,
            data,
        })
    }
    
    fn chain_id(&self) -> &'static str {
        "ethereum"
    }
}

impl EthereumAdapter {
    /// Creative: Generate a Solidity interface snippet for this proof system.
    pub fn solidity_interface(&self) -> &'static str {
        r#"
interface IPQAggregate {
    /**
     * @dev Verification hint structure for gas-efficient on-chain checks.
     */
    function verify(
        bytes32 proof_commitment,
        uint256 num_signatures,
        bytes32 pk_root,
        bytes32 msg_hash
    ) external view returns (bool);
    
    /**
     * @dev Full Nova SNARK verification.
     * @param proof The full compressed SNARK proof (approx 1.2KB)
     */
    function verifyFull(bytes calldata proof, bytes32 pk_root, bytes32 msg_hash) external view returns (bool);
}
"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_adapter_encoding() {
        let adapter = EthereumAdapter;
        let proof = ZKSNARKProof::new(vec![1, 2, 3], 10, [0xFF; 32]);
        
        let encoded = adapter.encode_proof(&proof);
        assert_eq!(u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]), 3);
    }

    #[test]
    fn test_ethereum_instruction_gen() {
        let adapter = EthereumAdapter;
        let proof = ZKSNARKProof::new(vec![0; 100], 5, [1; 32]);
        let contract = [0xEE; 20];
        let pk_root = [0xBB; 32];
        let msg_hash = [0xCC; 32];
        
        let ix = adapter.create_verify_instruction(
            &proof, &contract, &pk_root, &msg_hash
        ).expect("Create calldata failed");
        
        assert_eq!(ix.contract_address, contract);
        assert_eq!(ix.data.len(), 128); // 4 * 32 bytes (uint256 padded)
    }
}
