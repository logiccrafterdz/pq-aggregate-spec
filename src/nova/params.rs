use nova_snark::{
    provider::{PallasEngine, VestaEngine, ipa_pc::EvaluationEngine},
    PublicParams, 
    spartan::snark::RelaxedR1CSSNARK,
    traits::{evaluation::EvaluationEngineTrait, snark::RelaxedR1CSSNARKTrait}
};
use pasta_curves::{pallas, vesta};

use crate::nova::circuit::MerkleStepCircuit;

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

/// Generate public parameters for the Merkle Identity Circuit.
pub fn gen_params() -> Pparams {
    let circuit_primary = MerkleStepCircuit::new();
    let circuit_secondary = MerkleStepCircuit::new();
    
    // Use commitment keys (floor) from SNARK type (RelaxedR1CSSNARK)
    // Search results suggest S1::ck_floor() might be the way
    let ck_primary = S1::ck_floor();
    let ck_secondary = S2::ck_floor();
    
    // Explicitly specify S1, S2 for setup? 
    // PublicParams::setup signature might be generic over S1, S2 or not.
    // If setup returns Pparams (4 args), then S1/S2 are not part of Pparams?
    // Wait, earlier error said Pparams (PublicParams) takes 4.
    // CompressedSNARK takes 6.
    
    PublicParams::setup(
        &circuit_primary, 
        &circuit_secondary, 
        &*ck_primary, 
        &*ck_secondary
    ).expect("Failed to setup Nova parameters")
}
