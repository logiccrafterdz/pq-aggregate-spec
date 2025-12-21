//! Nova prover implementation.
//! 
//! Handles creation of RecursiveSNARKs and transformation of aggregate signatures
//! into Nova folding steps.

use nova_snark::{RecursiveSNARK, CompressedSNARK, VerifierKey};
use nova_snark::traits::circuit::TrivialCircuit;
use nova_snark::provider::{PallasEngine, VestaEngine};
use pasta_curves::pallas;

use crate::nova::params::{Pparams, S1, S2};
use crate::nova::circuit::MerkleStepCircuit;
use crate::error::PQAggregateError;

/// Type alias for the CompressedSNARK used in this crate
pub type MerkleCompressedSNARK = CompressedSNARK<
    PallasEngine, 
    VestaEngine, 
    MerkleStepCircuit<pallas::Scalar>, 
    MerkleStepCircuit<pasta_curves::vesta::Scalar>,
    S1,
    S2
>;

/// Type alias for the VerifierKey
pub type MerkleVerifierKey = VerifierKey<
    PallasEngine, 
    VestaEngine, 
    MerkleStepCircuit<pallas::Scalar>, 
    MerkleStepCircuit<pasta_curves::vesta::Scalar>,
    S1,
    S2
>;

/// Generates a CompressedSNARK by folding `steps` number of circuit executions.
pub fn prove_batch(
    params: &Pparams,
    steps: usize,
    pk: &nova_snark::ProverKey<PallasEngine, VestaEngine, MerkleStepCircuit<pallas::Scalar>, MerkleStepCircuit<pasta_curves::vesta::Scalar>, S1, S2>,
) -> Result<MerkleCompressedSNARK, crate::error::PQAggregateError> {
    
    // Primary circuit: Merkle Verification (arity 2)
    let primary_circuit = MerkleStepCircuit::new();
    let secondary_circuit = MerkleStepCircuit::new(); 
    
    // Initial inputs (z0)
    let z0_primary = vec![pallas::Scalar::zero(); 2]; 
    let z0_secondary = vec![pasta_curves::vesta::Scalar::zero(); 2]; 
    
    // Initialize RecursiveSNARK
    let mut recursive_snark = RecursiveSNARK::new(
        params,
        &primary_circuit,
        &secondary_circuit,
        &z0_primary,
        &z0_secondary,
    ).map_err(|e| PQAggregateError::NovaError(e.to_string()))?; 
    
    // Fold steps
    for _ in 0..steps {
        recursive_snark.prove_step(
            params,
            &primary_circuit,
            &secondary_circuit,
        ).map_err(|e| PQAggregateError::NovaError(e.to_string()))?;
    }
    
    // Compress (using provided pk)
    CompressedSNARK::prove(params, pk, &recursive_snark)
        .map_err(|e| PQAggregateError::NovaError(e.to_string()))
}

/// Setup keys for CompressedSNARK.
pub fn setup_keys(params: &Pparams) -> Result<(
    nova_snark::ProverKey<PallasEngine, VestaEngine, MerkleStepCircuit<pallas::Scalar>, MerkleStepCircuit<pasta_curves::vesta::Scalar>, S1, S2>,
    MerkleVerifierKey
), PQAggregateError> {
    CompressedSNARK::setup(params).map_err(|e| PQAggregateError::NovaError(e.to_string()))
}

/// Verifies a compressed SNARK proof (O(1) verification).
pub fn verify_proof(
    vk: &MerkleVerifierKey,
    proof: &MerkleCompressedSNARK,
    num_steps: usize,
    z0_primary: &[pallas::Scalar],
    zn_primary: &[pallas::Scalar],
) -> Result<bool, crate::error::PQAggregateError> {
    
    // Secondary inputs (always zero for this configuration)
    let z0_secondary = vec![pasta_curves::vesta::Scalar::zero(); 2];
    
    // Verify returns the output state (zn_primary, zn_secondary)
    let (zn_primary_got, _) = proof.verify(vk, num_steps, z0_primary, &z0_secondary)
        .map_err(|e| PQAggregateError::NovaError(e.to_string()))?;
        
    // Check if output matches expected
    if zn_primary_got != zn_primary {
        return Ok(false);
    }
        
    Ok(true)
}
