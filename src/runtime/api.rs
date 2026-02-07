use crate::causal::CausalEventLogger;
use crate::policy::PolicyEngine;
use sha3::{Sha3_256, Digest};
use std::collections::HashMap;

/// Unique identifier for an agent action.
pub type ActionId = [u8; 32];

#[derive(Debug, Clone, PartialEq)]
pub enum ActionStatus {
    Pending,      // Logged, awaiting policy evaluation
    Compliant,    // Policy passed, awaiting signatures
    Rejected,     // Policy violation detected
    Signed,       // Signatures collected, proof generated
    Submitted,    // Transaction submitted to chain
    Confirmed,    // Transaction confirmed on-chain
    Failed(String), // Error with description
}

#[derive(Debug, Clone, PartialEq)]
pub struct RiskContext {
    pub estimated_value_usd: Option<u64>,
    pub destination_chain: Option<u16>,
    pub is_cross_chain: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionProposal {
    pub agent_id: [u8; 32],
    pub action_type: u8,          // 0x01=TRANSFER, 0x02=SWAP, etc.
    pub payload: Vec<u8>,         // Raw transaction data (max 4KB)
    pub risk_context: RiskContext,// Optional metadata for policy engine
}

use crate::runtime::orchestrator::{CausalGuardOrchestrator, ActionState};
use crate::runtime::signature_orchestrator::{SignatureOrchestrator, ValidatorRegistry, SignatureError};
use crate::runtime::blockchain_adapter::{BlockchainAdapter, AdapterError};
#[cfg(feature = "nova")]
use crate::nova::unified_prover::UnifiedProof;
use crate::causal::LoggerError;
use crate::runtime::wallet_manager::WalletManager;

pub struct CausalGuardRuntime {
    logger: CausalEventLogger,
    policy_engine: PolicyEngine,
    orchestrator: CausalGuardOrchestrator,
    signature_orchestrator: SignatureOrchestrator,
    blockchain_adapter: BlockchainAdapter,
    _wallet: WalletManager,
    // Using a simple map for now to track status at the API level.
    action_states: HashMap<ActionId, ActionStatus>,
    rate_limits: HashMap<[u8; 32], u64>,
    // Idempotency: Map (agent_id, payload_hash) -> ActionId
    idempotency_cache: HashMap<([u8; 32], [u8; 32]), ActionId>,
}

#[derive(Debug)]
pub enum RuntimeError {
    PayloadTooLarge,
    InvalidActionType,
    AgentRateLimited,
    InternalError(String),
}

impl CausalGuardRuntime {
    pub fn new(logger: CausalEventLogger, policy_engine: PolicyEngine) -> Self {
        let wallet = WalletManager::new();
        Self {
            logger,
            policy_engine,
            orchestrator: CausalGuardOrchestrator::new(),
            signature_orchestrator: SignatureOrchestrator::new(ValidatorRegistry::new()),
            blockchain_adapter: BlockchainAdapter::new(wallet.clone()),
            _wallet: wallet,
            action_states: HashMap::new(),
            rate_limits: HashMap::new(),
            idempotency_cache: HashMap::new(),
        }
    }

    /// Primary agent entry point: propose an action for evaluation
    pub fn propose_action(
        &mut self,
        proposal: ActionProposal,
        current_time_ms: u64,
    ) -> Result<ActionId, RuntimeError> {
        // 0. Idempotency Check
        let mut payload_hasher = Sha3_256::new();
        payload_hasher.update(&proposal.payload);
        let payload_hash: [u8; 32] = payload_hasher.finalize().into();

        if let Some(existing_id) = self.idempotency_cache.get(&(proposal.agent_id, payload_hash)) {
            return Ok(*existing_id);
        }

        // 1. Validation
        if proposal.payload.len() > 4096 {
            return Err(RuntimeError::PayloadTooLarge);
        }
        if proposal.action_type == 0 || proposal.action_type > 0x05 {
            return Err(RuntimeError::InvalidActionType);
        }

        // 2. Rate Limiting (Simple check: 1 proposal per 6 seconds avg for 10/min)
        if let Some(last_time) = self.rate_limits.get(&proposal.agent_id) {
            if current_time_ms < *last_time + 6000 {
                return Err(RuntimeError::AgentRateLimited);
            }
        }
        self.rate_limits.insert(proposal.agent_id, current_time_ms);

        // 3. Mandatory Causal Logging
        let event = self.logger.log_event(
            &proposal.agent_id,
            proposal.action_type,
            &proposal.payload,
            current_time_ms / 1000 // Convert to seconds for logger
        ).map_err(|e| RuntimeError::InternalError(e.to_string()))?;

        // 4. ActionId Generation: SHA3-256(nonce || timestamp || agent_id)
        let mut hasher = Sha3_256::new();
        hasher.update(&event.nonce.to_be_bytes());
        hasher.update(&event.timestamp.to_be_bytes());
        hasher.update(&proposal.agent_id);
        let action_id: ActionId = hasher.finalize().into();

        // 5. Initialize State
        self.action_states.insert(action_id, ActionStatus::Pending);
        self.orchestrator.record_state(action_id, ActionState::Logged { 
            nonce: event.nonce, 
            timestamp: event.timestamp 
        });
        
        // 6. Cache for Idempotency
        self.idempotency_cache.insert((proposal.agent_id, payload_hash), action_id);

        Ok(action_id)
    }

    pub fn get_action_status(&self, action_id: &ActionId) -> ActionStatus {
        if let Some(status) = self.action_states.get(action_id) {
            status.clone()
        } else {
            ActionStatus::Failed("Action Not Found".to_string())
        }
    }

    /// Internal method to transition state (simulating async task results)
    pub fn update_action_status(&mut self, action_id: ActionId, status: ActionStatus) {
        self.action_states.insert(action_id, status);
    }

    /// Orchestration: Progress an action through its lifecycle
    pub fn process_action_lifecycle(&mut self, action_id: ActionId) -> Result<(), RuntimeError> {
        let current_status = self.get_action_status(&action_id);

        match current_status {
            ActionStatus::Pending => {
                // 1. Policy Evaluation
                // In a real system, we'd fetch the events from the logger
                let events = self.logger.get_events_range(0, 100)
                    .map_err(|e: LoggerError| RuntimeError::InternalError(e.to_string()))?;
                
                let root = self.logger.get_current_root();
                let evaluation = self.policy_engine.evaluate_chain(&events, &root)
                    .map_err(|e| RuntimeError::InternalError(e.to_string()))?;

                if evaluation.compliant {
                    self.orchestrator.record_state(action_id, ActionState::PolicyEvaluated { 
                        compliant: true, 
                        risk_tier: evaluation.risk_tier 
                    });
                    self.update_action_status(action_id, ActionStatus::Compliant);
                } else {
                    self.update_action_status(action_id, ActionStatus::Rejected);
                }
            },
            ActionStatus::Compliant => {
                // 2. Signature Collection
                let risk_tier_opt = if let Some(ActionState::PolicyEvaluated { risk_tier, .. }) = self.orchestrator.get_state(&action_id) {
                    Some(*risk_tier)
                } else {
                    None
                };

                if let Some(risk_tier) = risk_tier_opt {
                    let threshold = risk_tier.to_threshold() as u8;
                    
                    self.orchestrator.record_state(action_id, ActionState::SignaturesRequested { 
                        threshold, 
                        validator_set: vec![1, 2, 3] 
                    });

                    let (_sigs, _proofs) = self.signature_orchestrator.collect_signatures(
                        &[0u8; 32], 
                        threshold, 
                        risk_tier
                    ).map_err(|e: SignatureError| RuntimeError::InternalError(format!("{:?}", e)))?;

                    // 3. Proof Generation (Simulated for prototype)
                    #[cfg(feature = "nova")]
                    let proof = UnifiedProof {
                        proof: vec![0xDE, 0xAD, 0xBE, 0xEF],
                        root_hash: [0u8; 32],
                    };

                    #[cfg(feature = "nova")]
                    self.orchestrator.record_state(action_id, ActionState::ProofGenerated { 
                        proof: proof.clone(), 
                        tx_hash: [0u8; 32] 
                    });

                    #[cfg(not(feature = "nova"))]
                    self.orchestrator.record_state(action_id, ActionState::ProofGenerated { 
                        tx_hash: [0u8; 32] 
                    });

                    self.update_action_status(action_id, ActionStatus::Signed);
                }
            },
            ActionStatus::Signed => {
                // 4. Blockchain Submission
                #[cfg(feature = "nova")]
                let tx_hash = {
                    let proof_opt = if let Some(state) = self.orchestrator.get_state(&action_id) {
                        match state {
                            ActionState::ProofGenerated { proof, .. } => Some(proof.clone()),
                            _ => None,
                        }
                    } else {
                        None
                    };

                    if let Some(proof) = proof_opt {
                        self.blockchain_adapter.submit_unified_proof(&action_id, &proof, 1)
                            .map_err(|e: AdapterError| RuntimeError::InternalError(format!("{:?}", e)))?
                    } else {
                        self.blockchain_adapter.submit_unified_proof(&action_id, &UnifiedProof { proof: vec![], root_hash: [0u8; 32] }, 1)
                            .map_err(|e: AdapterError| RuntimeError::InternalError(format!("{:?}", e)))?
                    }
                };

                #[cfg(not(feature = "nova"))]
                let tx_hash = {
                    self.blockchain_adapter.submit_unified_proof(&action_id, &[0u8; 32], 1)
                        .map_err(|e: AdapterError| RuntimeError::InternalError(format!("{:?}", e)))?
                };
                
                self.orchestrator.record_state(action_id, ActionState::Submitted { 
                    chain_tx_id: tx_hash 
                });
                self.update_action_status(action_id, ActionStatus::Submitted);
            },
            ActionStatus::Submitted => {
                // 5. Finalization (Confirmation)
                self.orchestrator.record_state(action_id, ActionState::Finalized { 
                    block_height: 1000 
                });
                self.update_action_status(action_id, ActionStatus::Confirmed);
            },
            _ => {}
        }

        Ok(())
    }
}
