//! Hardware Security Module (HSM) integration.
//!
//! Provides a unified interface for key management across:
//! - Software HSM (Encrypted keystore + BIP-39)
//! - Cloud HSM (AWS Nitro / Azure Confidential) - *Future*
//! - Physical HSM (Ledger / YubiHSM) - *Future*

pub mod software_hsm;

pub use software_hsm::SoftwareHSM;

use crate::error::Result;
// use zeroize::Zeroizing;
// use std::path::PathBuf;

/// Unified Key Storage backend.
pub enum KeyStorage {
    /// Layer 1: Software HSM (immediate production use)
    SoftwareHSM(SoftwareHSM),
    
    /// Layer 2: Cloud HSM (future migration path)
    AwsNitro { enclave_id: String },
    
    /// Layer 3: Physical HSM (enterprise path)
    Ledger { device_path: String },
}

impl KeyStorage {
    /// Sign a message using the stored key.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            KeyStorage::SoftwareHSM(hsm) => hsm.sign(msg),
            _ => unimplemented!("Hardware/Cloud HSM not yet implemented"),
        }
    }
}
