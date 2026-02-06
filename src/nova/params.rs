use nova_snark::{
    provider::{PallasEngine, VestaEngine, ipa_pc::EvaluationEngine},
    PublicParams, CompressedSNARK,
    spartan::snark::RelaxedR1CSSNARK,
    traits::snark::RelaxedR1CSSNARKTrait
};
use pasta_curves::{pallas, vesta};

use crate::nova::circuit::MerkleStepCircuit;

use crate::nova::behavioral_circuit::BehavioralVerificationCircuit;

pub type EE1 = EvaluationEngine<PallasEngine>;
pub type EE2 = EvaluationEngine<VestaEngine>;

pub type S1 = RelaxedR1CSSNARK<PallasEngine, EE1>;
pub type S2 = RelaxedR1CSSNARK<VestaEngine, EE2>;

/// Type alias for simpler usage
pub type Pparams = PublicParams<
    PallasEngine,
    VestaEngine,
    MerkleStepCircuit<pallas::Scalar>,
    MerkleStepCircuit<vesta::Scalar>,
>;

pub type UnifiedPparams = PublicParams<
    PallasEngine,
    VestaEngine,
    BehavioralVerificationCircuit<pallas::Scalar>,
    BehavioralVerificationCircuit<vesta::Scalar>,
>;

/// Generate public parameters for the Merkle Identity Circuit.
pub fn gen_params() -> Pparams {
    let circuit_primary = MerkleStepCircuit::new();
    let circuit_secondary = MerkleStepCircuit::new();
    
    let ck_primary = S1::ck_floor();
    let ck_secondary = S2::ck_floor();
    
    PublicParams::setup(
        &circuit_primary, 
        &circuit_secondary, 
        &*ck_primary, 
        &*ck_secondary
    ).expect("Failed to setup Nova parameters")
}

/// Generate public parameters for the Unified Behavioral Circuit.
pub fn gen_unified_params() -> UnifiedPparams {
    // Generate empty circuit for setup
    let circuit_primary = BehavioralVerificationCircuit::new(
        super::behavioral_circuit::UnifiedCircuitInputs {
            chain_root: pallas::Scalar::zero(),
            chain_length: 0,
            policy_root: pallas::Scalar::zero(),
            evaluation_hash: pallas::Scalar::zero(),
            risk_tier: 0,
            pk_root: pallas::Scalar::zero(),
            message_hash: pallas::Scalar::zero(),
            threshold_t: 0,
        },
        vec![],
        vec![],
        vec![],
    );
    let circuit_secondary = BehavioralVerificationCircuit::new(
        super::behavioral_circuit::UnifiedCircuitInputs {
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
    
    let ck_primary = S1::ck_floor();
    let ck_secondary = S2::ck_floor();
    
    PublicParams::setup(
        &circuit_primary, 
        &circuit_secondary, 
        &*ck_primary, 
        &*ck_secondary
    ).expect("Failed to setup Unified parameters")
}

/// Setup keys for Unified CompressedSNARK.
pub fn setup_unified_keys(params: &UnifiedPparams) -> Result<(
    nova_snark::ProverKey<PallasEngine, VestaEngine, BehavioralVerificationCircuit<pallas::Scalar>, BehavioralVerificationCircuit<pasta_curves::vesta::Scalar>, S1, S2>,
    nova_snark::VerifierKey<PallasEngine, VestaEngine, BehavioralVerificationCircuit<pallas::Scalar>, BehavioralVerificationCircuit<pasta_curves::vesta::Scalar>, S1, S2>
), crate::error::PQAggregateError> {
    CompressedSNARK::setup(params).map_err(|e: nova_snark::errors::NovaError| crate::error::PQAggregateError::NovaError(e.to_string()))
}
