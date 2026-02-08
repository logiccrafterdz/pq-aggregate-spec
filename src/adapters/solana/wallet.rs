//! Secure wallet management for Solana Devnet.
//!
//! Uses mock types for the spec. Production integration should use
//! actual solana-sdk in a separate workspace member.

#![cfg(feature = "solana-devnet")]

use zeroize::Zeroize;
use std::env;

use crate::error::{PQAggregateError, Result};

/// Environment variable for fee payer private key (base58 encoded)
pub const ENV_FEE_PAYER_KEY: &str = "SOLANA_FEE_PAYER_KEY";

/// Environment variable for signer private key (base58 encoded, optional)  
pub const ENV_SIGNER_KEY: &str = "SOLANA_SIGNER_KEY";

/// Mock public key (32 bytes)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    
    pub fn from_str(s: &str) -> Result<Self> {
        let bytes = bs58::decode(s).into_vec().map_err(|e| {
            PQAggregateError::InvalidInput {
                reason: format!("Invalid pubkey: {}", e),
            }
        })?;
        
        if bytes.len() != 32 {
            return Err(PQAggregateError::InvalidInput {
                reason: "Pubkey must be 32 bytes".to_string(),
            });
        }
        
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl core::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

impl From<[u8; 32]> for Pubkey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Mock keypair for signing
#[derive(Clone)]
pub struct Keypair {
    secret: [u8; 64],
    pubkey: Pubkey,
}

impl Keypair {
    pub fn new() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut secret);
        
        // Derive pubkey from first 32 bytes (simplified)
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(&secret[32..64]);
        
        Self {
            secret,
            pubkey: Pubkey(pubkey_bytes),
        }
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(PQAggregateError::InvalidInput {
                reason: "Keypair must be 64 bytes".to_string(),
            });
        }
        
        let mut secret = [0u8; 64];
        secret.copy_from_slice(bytes);
        
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(&bytes[32..64]);
        
        Ok(Self {
            secret,
            pubkey: Pubkey(pubkey_bytes),
        })
    }
    
    pub fn pubkey(&self) -> Pubkey {
        self.pubkey
    }
    
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.secret);
        hasher.update(message);
        let hash = hasher.finalize();
        
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&hash);
        sig
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Default for Keypair {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock signature
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

/// Secure wallet manager with zeroization on drop.
pub struct WalletManager {
    fee_payer: Keypair,
    signer: Option<Keypair>,
}

impl WalletManager {
    /// Create a new wallet manager from environment variables.
    pub fn from_env() -> Result<Self> {
        let fee_payer_key = env::var(ENV_FEE_PAYER_KEY).map_err(|_| {
            PQAggregateError::InvalidInput {
                reason: format!("Missing environment variable: {}", ENV_FEE_PAYER_KEY),
            }
        })?;

        let fee_payer = Self::keypair_from_base58(&fee_payer_key)?;

        let signer = env::var(ENV_SIGNER_KEY)
            .ok()
            .and_then(|k| Self::keypair_from_base58(&k).ok());

        Ok(Self { fee_payer, signer })
    }

    /// Create wallet manager with explicit keypairs (for testing).
    pub fn new(fee_payer: Keypair, signer: Option<Keypair>) -> Self {
        Self { fee_payer, signer }
    }

    /// Get the fee payer public key.
    pub fn fee_payer_pubkey(&self) -> Pubkey {
        self.fee_payer.pubkey()
    }

    /// Get the signer public key (or fee payer if no separate signer).
    pub fn signer_pubkey(&self) -> Pubkey {
        self.signer
            .as_ref()
            .map(|k| k.pubkey())
            .unwrap_or_else(|| self.fee_payer.pubkey())
    }

    /// Get reference to fee payer keypair.
    pub fn fee_payer(&self) -> &Keypair {
        &self.fee_payer
    }

    /// Get reference to signer keypair (or fee payer if no separate signer).
    pub fn signer(&self) -> &Keypair {
        self.signer.as_ref().unwrap_or(&self.fee_payer)
    }

    /// Parse a base58-encoded private key into a Keypair.
    fn keypair_from_base58(key: &str) -> Result<Keypair> {
        let bytes = bs58::decode(key).into_vec().map_err(|e| {
            PQAggregateError::InvalidInput {
                reason: format!("Invalid base58 key: {}", e),
            }
        })?;

        Keypair::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_from_keypair() {
        let kp = Keypair::new();
        let pubkey = kp.pubkey();
        
        let wallet = WalletManager::new(kp, None);
        
        assert_eq!(wallet.fee_payer_pubkey(), pubkey);
        assert_eq!(wallet.signer_pubkey(), pubkey);
    }

    #[test]
    fn test_wallet_separate_signer() {
        let fee_payer = Keypair::new();
        let signer = Keypair::new();
        let fee_pubkey = fee_payer.pubkey();
        let signer_pubkey = signer.pubkey();
        
        let wallet = WalletManager::new(fee_payer, Some(signer));
        
        assert_eq!(wallet.fee_payer_pubkey(), fee_pubkey);
        assert_eq!(wallet.signer_pubkey(), signer_pubkey);
        assert_ne!(wallet.fee_payer_pubkey(), wallet.signer_pubkey());
    }
    
    #[test]
    fn test_pubkey_display() {
        let pk = Pubkey::new([0xAA; 32]);
        let s = pk.to_string();
        assert!(!s.is_empty());
    }
}
