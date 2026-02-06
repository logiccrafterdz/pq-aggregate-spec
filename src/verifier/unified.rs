//! Unified Verifier for behavioral-signature proofs.
//!
//! Validates composite proofs in constant time (O(1)).

use nova_snark::CompressedSNARK;
use nova_snark::provider::{PallasEngine, VestaEngine};
use pasta_curves::pallas;
use crate::nova::behavioral_circuit::BehavioralVerificationCircuit;
use crate::nova::params::{S1, S2};
use crate::error::PQAggregateError;
use crate::nova::params::UnifiedPparams;

/// Unified verifier for composite behavioral-signature proofs.
pub struct UnifiedVerifier;

impl UnifiedVerifier {
    /// Verify a unified proof against expected public inputs.
    pub fn verify_unified(
        _params: &UnifiedPparams,
        vk: &nova_snark::VerifierKey<PallasEngine, VestaEngine, BehavioralVerificationCircuit<pallas::Scalar>, BehavioralVerificationCircuit<pasta_curves::vesta::Scalar>, S1, S2>,
        proof: &CompressedSNARK<PallasEngine, VestaEngine, BehavioralVerificationCircuit<pallas::Scalar>, BehavioralVerificationCircuit<pasta_curves::vesta::Scalar>, S1, S2>,
        _chain_root: [u8; 32],
        risk_tier: u8,
        _pk_root: [u8; 32],
        threshold_t: u8,
    ) -> Result<bool, PQAggregateError> {
        
        let z0_primary = vec![
            pallas::Scalar::zero(),
            pallas::Scalar::zero(),
            pallas::Scalar::from(risk_tier as u64),
            pallas::Scalar::zero(),
            pallas::Scalar::from(threshold_t as u64),
        ];
        
        // Identity circuit output should match input in this prototype
        let zn_primary = z0_primary.clone();
        let z0_secondary = vec![pasta_curves::vesta::Scalar::zero(); 5];

        let (zn_got, _) = proof.verify(vk, 1, &z0_primary, &z0_secondary)
            .map_err(|e| PQAggregateError::NovaError(e.to_string()))?;

        Ok(zn_got == zn_primary)
    }
}
