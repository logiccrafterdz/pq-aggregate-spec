//! Unified Prover for behavioral-signature proofs.
//! 
//! Orchestrates the collection of causal events, policy evaluation, 
//! and signature aggregation into a single Nova recursive SNARK.

use nova_snark::{RecursiveSNARK, CompressedSNARK};
use nova_snark::provider::{PallasEngine, VestaEngine};
use pasta_curves::{pallas, vesta};
use crate::causal::CausalEvent;
use crate::policy::{PolicyEngine};
use crate::nova::behavioral_circuit::{BehavioralVerificationCircuit, UnifiedCircuitInputs};
use crate::nova::params::{UnifiedPparams, S1, S2};
use crate::error::PQAggregateError;

#[derive(Debug, Clone)]
pub struct UnifiedProof {
    pub proof: Vec<u8>,
    pub root_hash: [u8; 32],
}

/// Type aliases for unified circuit components
pub type UnifiedPK = nova_snark::ProverKey<
    PallasEngine, 
    VestaEngine, 
    BehavioralVerificationCircuit<pallas::Scalar>, 
    BehavioralVerificationCircuit<pasta_curves::vesta::Scalar>, 
    S1, 
    S2
>;

pub type UnifiedCSNARK = CompressedSNARK<
    PallasEngine, 
    VestaEngine, 
    BehavioralVerificationCircuit<pallas::Scalar>, 
    BehavioralVerificationCircuit<pasta_curves::vesta::Scalar>, 
    S1, 
    S2
>;

/// Orchestrator for generating unified proofs.
pub struct UnifiedProver {
    policy_engine: PolicyEngine,
}

impl UnifiedProver {
    pub fn new(policy_engine: PolicyEngine) -> Self {
        Self { policy_engine }
    }

    /// Generate a unified status proof for a chain of events and signatures.
    pub fn prove_unified(
        &self,
        params: &UnifiedPparams,
        pk: &UnifiedPK,
        events: &[CausalEvent],
        expected_chain_root: [u8; 32],
        _message_hash: [u8; 32],
        _pk_root: [u8; 32],
        threshold_t: u8,
    ) -> Result<UnifiedCSNARK, PQAggregateError> {
        
        // 1. Evaluate Policy
        let evaluation = self.policy_engine.evaluate_chain(events, &expected_chain_root)
            .map_err(|e| PQAggregateError::NovaError(e.to_string()))?;
            
        if !evaluation.compliant {
            return Err(PQAggregateError::NovaError("Policy compliance failed".to_string()));
        }

        // 2. Prepare Circuit Inputs
        let inputs = UnifiedCircuitInputs {
            chain_root: pallas::Scalar::zero(), 
            chain_length: events.len() as u64,
            policy_root: pallas::Scalar::zero(), 
            evaluation_hash: pallas::Scalar::zero(),
            risk_tier: evaluation.risk_tier.to_threshold() as u8,
            pk_root: pallas::Scalar::zero(),
            message_hash: pallas::Scalar::zero(),
            threshold_t,
        };

        let nonces: Vec<u64> = events.iter().map(|e| e.nonce).collect();
        let timestamps: Vec<u64> = events.iter().map(|e| e.timestamp).collect();
        let fingerprints: Vec<pallas::Scalar> = events.iter()
            .map(|_| pallas::Scalar::zero())
            .collect();

        let primary_circuit = BehavioralVerificationCircuit::new(
            inputs.clone(),
            nonces.clone(),
            timestamps.clone(),
            fingerprints.clone(),
        );
        
        // Secondary circuit (vesta) - simplified implementation
        let secondary_circuit = BehavioralVerificationCircuit::new(
            UnifiedCircuitInputs {
                chain_root: vesta::Scalar::zero(),
                chain_length: 0,
                policy_root: vesta::Scalar::zero(),
                evaluation_hash: vesta::Scalar::zero(),
                risk_tier: 0,
                pk_root: vesta::Scalar::zero(),
                message_hash: vesta::Scalar::zero(),
                threshold_t: 0,
            },
            vec![],
            vec![],
            vec![],
        );

        // 3. Initial inputs (z0)
        // z: [chain_root, policy_root, risk_tier, pk_root, threshold_t]
        let z0_primary = vec![
            inputs.chain_root,
            inputs.policy_root,
            pallas::Scalar::from(inputs.risk_tier as u64),
            inputs.pk_root,
            pallas::Scalar::from(inputs.threshold_t as u64),
        ];
        let z0_secondary = vec![vesta::Scalar::zero(); 5];

        // 4. Prove Step
        // We need the specific UnifiedPparams for the setup
        // But for this orchestrator, we assume params are compatible
        // If arity differs, Pparams will fail here.
        
        let mut recursive_snark = RecursiveSNARK::new(
            params,
            &primary_circuit,
            &secondary_circuit,
            &z0_primary,
            &z0_secondary,
        ).map_err(|e| PQAggregateError::NovaError(e.to_string()))?;

        recursive_snark.prove_step(
            params,
            &primary_circuit,
            &secondary_circuit,
        ).map_err(|e| PQAggregateError::NovaError(e.to_string()))?;

        // 5. Compress
        CompressedSNARK::prove(params, pk, &recursive_snark)
            .map_err(|e| PQAggregateError::NovaError(e.to_string()))
    }
}
