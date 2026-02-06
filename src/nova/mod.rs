//! Nova integration for PQ-Aggregate.
//!
//! # Feature: `nova`
//! This module is only available when the `nova` feature is enabled.
//!
//! Implements recursive SNARK verification using the Nova proving system.

#[cfg(feature = "nova")]
pub mod circuit;

#[cfg(feature = "nova")]
pub mod params;

#[cfg(feature = "nova")]
pub mod prover;

#[cfg(test)]
#[cfg(feature = "nova")]
mod tests {
    use crate::nova::params::gen_params;
    use crate::nova::prover::{prove_batch, verify_proof, setup_keys};
    use pasta_curves::pallas;
    use std::time::Instant;

    #[test]
    fn test_nova_basic_flow_t3_benchmark() {
        println!("Generating parameters...");
        let start = Instant::now();
        let params = gen_params();
        println!("Params generation: {:?}", start.elapsed());

        println!("Generating compressed SNARK keys...");
        let (pk, vk) = setup_keys(&params).expect("Key setup failed");
        
        println!("Proving 3 steps...");
        let start_prove = Instant::now();
        let proof = prove_batch(&params, 3, &pk).expect("Proving failed");
        println!("Proving time: {:?}", start_prove.elapsed());

        println!("Verifying...");
        let z0 = vec![pallas::Scalar::zero(); 2];
        let zn = z0.clone(); // Identity circuit preservation
        
        let start_verify = Instant::now();
        // verify_proof(vk, proof, num_steps, z0, zn)
        let valid = verify_proof(&vk, &proof, 3, &z0, &zn).expect("Verification failed");
        let duration = start_verify.elapsed();
        println!("Verification time: {:?}", duration);
        
        assert!(valid, "Proof should be valid");
    }
}
