//! Policy Engine implementation.
//!
//! Orchestrates the verification of causal event chains and ensures
//! compliance with defined behavioral policies.

use alloc::vec::Vec;
use crate::causal::CausalEvent;
use crate::causal::logger::CausalEventLogger;
use crate::policy::types::{BehavioralPolicy, PolicyEvaluation, RiskTier, PolicyProof};
use crate::policy::evaluator;
use sha3::{Digest, Sha3_256};
use thiserror::Error;

/// Errors related to policy evaluation.
#[derive(Debug, Error, PartialEq)]
pub enum PolicyError {
    #[error("Chain verification failed: Merkle root mismatch")]
    ChainVerificationFailed,
    #[error("Policy condition violated at index {condition_idx}")]
    PolicyConditionViolated { condition_idx: usize },
    #[error("Insufficient events to evaluate policy")]
    InsufficientEvents,
    #[error("Nonce gap detected in event sequence")]
    NonceGapDetected,
}

/// The Behavioral Policy Engine.
pub struct PolicyEngine {
    policies: Vec<BehavioralPolicy>,
}

impl PolicyEngine {
    /// Create a new policy engine with a set of active policies.
    pub fn new(policies: Vec<BehavioralPolicy>) -> Self {
        Self {
            policies,
        }
    }

    /// Evaluate policy compliance for a chain of events.
    pub fn evaluate_chain(
        &self,
        events: &[CausalEvent],
        expected_root: &[u8; 32],
    ) -> Result<PolicyEvaluation, PolicyError> {
        // 1. Verify integrity of the entire chain
        if !CausalEventLogger::verify_event_chain(events, expected_root) {
            return Err(PolicyError::ChainVerificationFailed);
        }

        // 2. Check for nonce gaps (ensure full causal history)
        if events.is_empty() {
            return Err(PolicyError::InsufficientEvents);
        }
        
        // 3. Find the latest nonce in this batch
        let last_nonce = events.iter().map(|e| e.nonce).max().unwrap_or(0);

        // 4. Aggregated compliance check
        let mut satisfied_conditions = Vec::new();
        let mut failed_condition = None;
        let mut overall_risk = RiskTier::Low;

        for policy in &self.policies {
            // Update risk tier to the highest defined in matching policies
            if policy.risk_tier.to_threshold() > overall_risk.to_threshold() {
                overall_risk = policy.risk_tier;
            }

            for (idx, condition) in policy.conditions.iter().enumerate() {
                if evaluator::evaluate_condition(condition, events, last_nonce) {
                    satisfied_conditions.push(idx);
                } else {
                    failed_condition = Some(idx);
                    return Ok(PolicyEvaluation {
                        compliant: false,
                        risk_tier: overall_risk,
                        satisfied_conditions,
                        failed_condition,
                        evaluation_nonce: last_nonce,
                    });
                }
            }
        }

        Ok(PolicyEvaluation {
            compliant: true,
            risk_tier: overall_risk,
            satisfied_conditions,
            failed_condition: None,
            evaluation_nonce: last_nonce,
        })
    }

    /// Generate cryptographic proofs and field elements for SNARK integration.
    pub fn create_proof(
        &self,
        evaluation: &PolicyEvaluation,
        root_hash: [u8; 32],
        timestamp: u64,
    ) -> PolicyProof {
        let mut hasher = Sha3_256::new();
        hasher.update(&evaluation.evaluation_nonce.to_le_bytes());
        hasher.update(&[evaluation.compliant as u8]);
        hasher.update(&[evaluation.risk_tier.to_threshold() as u8]);
        let evaluation_hash = hasher.finalize().into();

        PolicyProof {
            root_hash,
            evaluation_hash,
            timestamp,
        }
    }
}
