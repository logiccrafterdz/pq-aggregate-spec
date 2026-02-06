use crate::runtime::api::{ActionId, ActionStatus};
use crate::policy::{RiskTier};
#[cfg(feature = "nova")]
use crate::nova::unified_prover::{UnifiedProof};

#[derive(Debug, Clone)]
pub enum ActionState {
    Logged { nonce: u64, timestamp: u64 },
    PolicyEvaluated { compliant: bool, risk_tier: RiskTier },
    SignaturesRequested { threshold: u8, validator_set: Vec<u16> },
    #[cfg(feature = "nova")]
    ProofGenerated { proof: UnifiedProof, tx_hash: [u8; 32] },
    #[cfg(not(feature = "nova"))]
    ProofGenerated { tx_hash: [u8; 32] },
    Submitted { chain_tx_id: String },
    Finalized { block_height: u64 },
}

pub struct CausalGuardOrchestrator {
    // Internal state tracking for more granular transitions
    states: std::collections::HashMap<ActionId, ActionState>,
}

impl CausalGuardOrchestrator {
    pub fn new() -> Self {
        Self {
            states: std::collections::HashMap::new(),
        }
    }

    pub fn record_state(&mut self, id: ActionId, state: ActionState) {
        self.states.insert(id, state);
    }

    pub fn get_state(&self, id: &ActionId) -> Option<&ActionState> {
        self.states.get(id)
    }
}
