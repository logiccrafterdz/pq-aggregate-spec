//! Cosmos-specific blockchain adapter.
//!
//! Provides encoding for Cosmos SDK and IBC-enabled blockchains.

use alloc::vec::Vec;
use alloc::string::String;
use crate::types::ZKSNARKProof;
use crate::error::Result;
use crate::adapters::{BlockchainAdapter, VerificationHint};

/// Adapter for Cosmos SDK and IBC-compatible blockchains.
pub struct CosmosAdapter;

/// A simple representation of a Cosmos SDK Message or IBC Packet.
#[derive(Clone, Debug)]
pub struct CosmosMessage {
    pub msg_type: String,
    pub signer: String,
    pub data: Vec<u8>,
}

impl BlockchainAdapter for CosmosAdapter {
    type Instruction = CosmosMessage;
    type Address = String;
    
    fn encode_proof(&self, proof: &ZKSNARKProof) -> Vec<u8> {
        // Cosmos often uses Protobuf. Here we simulate a simple proto-like encoding.
        // [field_tag:1][length:1..5][data:N]
        let mut out = Vec::new();
        out.push(0x0a); // Field 1: proof_bytes (string/bytes)
        
        let bytes = proof.to_bytes();
        let len = bytes.len();
        
        // Simple varint for length
        let mut l = len;
        while l >= 0x80 {
            out.push((l as u8 & 0x7f) | 0x80);
            l >>= 7;
        }
        out.push(l as u8);
        
        out.extend_from_slice(&bytes);
        out
    }
    
    fn decode_proof(&self, bytes: &[u8]) -> Option<ZKSNARKProof> {
        if bytes.len() < 2 { return None; }
        if bytes[0] != 0x0a { return None; }
        
        // Skip varint length (simple skip for prototype)
        let mut pos = 1;
        while pos < bytes.len() && (bytes[pos] & 0x80) != 0 {
            pos += 1;
        }
        pos += 1;
        
        if pos >= bytes.len() { return None; }
        ZKSNARKProof::from_bytes(&bytes[pos..])
    }
    
    fn create_verify_instruction(
        &self,
        proof: &ZKSNARKProof,
        signer: &Self::Address,
        pk_root: &[u8; 32],
        msg_hash: &[u8; 32],
    ) -> Result<Self::Instruction> {
        let hint = VerificationHint::new(proof, *pk_root, *msg_hash);
        
        // Creative: Generate a JSON-like verify message for CosmWasm
        let data = hint.to_bytes();
        
        Ok(CosmosMessage {
            msg_type: "/pqagg.v1.MsgVerifyAggregate".into(),
            signer: signer.clone(),
            data,
        })
    }
    
    fn chain_id(&self) -> &'static str {
        "cosmos"
    }
}

impl CosmosAdapter {
    /// Creative: Add IBC packet wrapping logic.
    /// 
    /// Allows the proof to be sent between chains via IBC.
    pub fn wrap_for_ibc(
        &self,
        proof: &ZKSNARKProof,
        source_port: String,
        source_channel: String,
    ) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(source_port.as_bytes());
        packet.push(b':');
        packet.extend_from_slice(source_channel.as_bytes());
        packet.push(b'|');
        packet.extend_from_slice(&self.encode_proof(proof));
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosmos_adapter_encoding() {
        let adapter = CosmosAdapter;
        let proof = ZKSNARKProof::new(vec![1, 2, 3], 10, [0xFF; 32]);
        
        let encoded = adapter.encode_proof(&proof);
        assert_eq!(encoded[0], 0x0a); // Proto tag
    }

    #[test]
    fn test_cosmos_instruction_gen() {
        let adapter = CosmosAdapter;
        let proof = ZKSNARKProof::new(vec![0; 50], 5, [1; 32]);
        let signer = "cosmos1signer".to_string();
        let pk_root = [0xBB; 32];
        let msg_hash = [0xCC; 32];
        
        let msg = adapter.create_verify_instruction(
            &proof, &signer, &pk_root, &msg_hash
        ).expect("Create msg failed");
        
        assert_eq!(msg.msg_type, "/pqagg.v1.MsgVerifyAggregate");
        assert_eq!(msg.signer, signer);
    }

    #[test]
    fn test_ibc_wrapping() {
        let adapter = CosmosAdapter;
        let proof = ZKSNARKProof::new(vec![1], 1, [0; 32]);
        let packet = adapter.wrap_for_ibc(&proof, "transfer".into(), "channel-0".into());
        
        assert!(packet.starts_with(b"transfer:channel-0|"));
    }
}
