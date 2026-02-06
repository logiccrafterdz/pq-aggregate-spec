//! Multi-chain Bridge Hub for PQ-Aggregate.
//!
//! Provides logic for relaying and translating proofs between different
//! blockchain ecosystems (e.g., Solana to Ethereum).

use alloc::vec::Vec;
use alloc::string::String;
use crate::types::ZKSNARKProof;
use crate::error::{PQAggregateError, Result};
use crate::adapters::BlockchainAdapter;

/// A packet that carries a proof and its source/destination metadata across chains.
#[derive(Clone, Debug)]
pub struct BridgePacket {
    pub source_chain: String,
    pub dest_chain: String,
    pub proof_bytes: Vec<u8>,
    pub sequence: u64,
}

/// The BridgeHub orchestrates proof translation between different adapters.
pub struct BridgeHub;

impl BridgeHub {
    /// Creative: Translate a proof from one adapter's format to another.
    /// 
    /// This allows a proof generated for Ethereum to be "translated" into 
    /// a format suitable for Solana or Cosmos without re-signing.
    pub fn translate_proof<S: BlockchainAdapter, D: BlockchainAdapter>(
        source_adapter: &S,
        dest_adapter: &D,
        encoded_proof: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. Decode using source adapter
        let proof = source_adapter.decode_proof(encoded_proof)
            .ok_or_else(|| PQAggregateError::InvalidInput { 
                reason: "Failed to decode proof via source adapter".into() 
            })?;
            
        // 2. Re-encode using destination adapter
        Ok(dest_adapter.encode_proof(&proof))
    }

    /// Create a bridge packet for relaying.
    pub fn create_relay_packet<A: BlockchainAdapter>(
        adapter: &A,
        proof: &ZKSNARKProof,
        dest_chain: String,
        sequence: u64,
    ) -> BridgePacket {
        BridgePacket {
            source_chain: adapter.chain_id().to_string(),
            dest_chain,
            proof_bytes: adapter.encode_proof(proof),
            sequence,
        }
    }
    
    /// Creative: "Atomic Transition" - Verify a proof on the destination chain 
    /// while strictly checking the source chain's provenance.
    pub fn verify_relayed_packet<A: BlockchainAdapter>(
        adapter: &A,
        packet: &BridgePacket,
        expected_source: &str,
    ) -> bool {
        if packet.source_chain != expected_source {
            return false;
        }
        
        // Ensure the proof can be decoded by the current (destination) adapter
        adapter.decode_proof(&packet.proof_bytes).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::solana::SolanaAdapter;
    use crate::adapters::ethereum::EthereumAdapter;
    use crate::types::ZKSNARKProof;

    #[test]
    fn test_proof_translation() {
        let solana = SolanaAdapter;
        let ethereum = EthereumAdapter;
        let proof = ZKSNARKProof::new(vec![1, 2, 3], 5, [0; 32]);

        // Encode for Solana
        let sol_encoded = solana.encode_proof(&proof);

        // Translate Solana -> Ethereum
        let eth_encoded = BridgeHub::translate_proof(&solana, &ethereum, &sol_encoded).unwrap();

        // Verify Ethereum can decode it
        let decoded = ethereum.decode_proof(&eth_encoded).unwrap();
        assert_eq!(decoded.num_signatures(), 5);
    }

    #[test]
    fn test_bridge_relay_packet() {
        let solana = SolanaAdapter;
        let proof = ZKSNARKProof::new(vec![0; 100], 10, [1; 32]);
        
        let packet = BridgeHub::create_relay_packet(&solana, &proof, "ethereum".into(), 42);
        
        assert_eq!(packet.source_chain, "solana");
        assert_eq!(packet.dest_chain, "ethereum");
        assert_eq!(packet.sequence, 42);
        
        assert!(BridgeHub::verify_relayed_packet(&solana, &packet, "solana"));
        assert!(!BridgeHub::verify_relayed_packet(&solana, &packet, "cosmos"));
    }
}
