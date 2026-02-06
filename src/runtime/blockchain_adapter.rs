use crate::runtime::api::ActionId;
use crate::nova::unified_prover::{UnifiedProof};

#[derive(Debug)]
pub enum AdapterError {
    SubmissionFailed(String),
}

pub struct BlockchainAdapter {
    // Mock adapter
}

impl BlockchainAdapter {
    pub fn new() -> Self {
        Self {}
    }

    pub fn submit_unified_proof(
        &self,
        _action_id: &ActionId,
        _proof: &UnifiedProof,
        _target_chain: u16,
    ) -> Result<String, AdapterError> {
        // Mock submission
        Ok("tx_hash_12345".to_string())
    }
}
