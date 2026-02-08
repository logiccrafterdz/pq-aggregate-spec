//! Structured Metadata for Risk-Adaptive Policy Enforcement.
//!
//! Provides cryptographically bound metadata without exposing raw payloads.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Risk flags bitmask constants.
pub mod risk_flags {
    /// Cross-chain transfer.
    pub const CROSS_CHAIN: u8 = 0x01;
    /// High-value transaction.
    pub const HIGH_VALUE: u8 = 0x02;
    /// Unknown or unverified recipient.
    pub const UNKNOWN_RECIPIENT: u8 = 0x04;
}

/// Structured metadata for risk-adaptive policies.
///
/// This struct captures essential transaction context without storing
/// raw payloads. Total size: 8 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct StructuredMetadata {
    /// Transaction amount in USD cents (0 = unknown/zero-value action).
    pub amount_usd_cents: u32,
    /// Destination chain ID (0 = same-chain).
    pub destination_chain: u16,
    /// Risk flags bitmask (see `risk_flags` module).
    pub risk_flags: u8,
    /// Reserved for alignment (must be 0).
    pub reserved: u8,
}

impl Default for StructuredMetadata {
    fn default() -> Self {
        Self {
            amount_usd_cents: 0,
            destination_chain: 0,
            risk_flags: 0,
            reserved: 0,
        }
    }
}

impl StructuredMetadata {
    /// Create new metadata with the given values.
    pub fn new(amount_usd_cents: u32, destination_chain: u16, risk_flags: u8) -> Self {
        Self {
            amount_usd_cents,
            destination_chain,
            risk_flags,
            reserved: 0,
        }
    }

    /// Check if this is a cross-chain transfer.
    pub fn is_cross_chain(&self) -> bool {
        self.destination_chain != 0 || (self.risk_flags & risk_flags::CROSS_CHAIN) != 0
    }

    /// Check if this is a high-value transaction.
    pub fn is_high_value(&self) -> bool {
        (self.risk_flags & risk_flags::HIGH_VALUE) != 0
    }

    /// Get amount in USD (not cents).
    pub fn amount_usd(&self) -> u64 {
        self.amount_usd_cents as u64 / 100
    }

    /// Serialize to bytes (little-endian).
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&self.amount_usd_cents.to_le_bytes());
        out[4..6].copy_from_slice(&self.destination_chain.to_le_bytes());
        out[6] = self.risk_flags;
        out[7] = self.reserved;
        out
    }
}

/// Compute the cryptographic commitment for metadata.
///
/// The commitment binds metadata to the payload via:
/// ```text
/// commitment = SHA3-256(nonce || payload_hash || metadata_bytes)
/// ```
///
/// This prevents an attacker from substituting metadata for a given payload_hash.
pub fn compute_metadata_commitment(
    nonce: u64,
    payload_hash: &[u8; 32],
    metadata: &StructuredMetadata,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(&nonce.to_le_bytes());
    hasher.update(payload_hash);
    hasher.update(&metadata.to_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_default() {
        let m = StructuredMetadata::default();
        assert_eq!(m.amount_usd_cents, 0);
        assert_eq!(m.destination_chain, 0);
        assert_eq!(m.risk_flags, 0);
        assert!(!m.is_cross_chain());
        assert!(!m.is_high_value());
    }

    #[test]
    fn test_metadata_cross_chain() {
        let m = StructuredMetadata::new(1500_00, 137, 0); // 1500 USD, Polygon chain
        assert!(m.is_cross_chain());
        assert_eq!(m.amount_usd(), 1500);
    }

    #[test]
    fn test_metadata_commitment_deterministic() {
        let nonce = 42u64;
        let payload_hash = [0xABu8; 32];
        let metadata = StructuredMetadata::new(5000, 1, risk_flags::HIGH_VALUE);

        let c1 = compute_metadata_commitment(nonce, &payload_hash, &metadata);
        let c2 = compute_metadata_commitment(nonce, &payload_hash, &metadata);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_metadata_commitment_changes_with_amount() {
        let nonce = 1u64;
        let payload_hash = [0x00u8; 32];
        
        let m1 = StructuredMetadata::new(100, 0, 0);
        let m2 = StructuredMetadata::new(200, 0, 0);

        let c1 = compute_metadata_commitment(nonce, &payload_hash, &m1);
        let c2 = compute_metadata_commitment(nonce, &payload_hash, &m2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_metadata_size() {
        assert_eq!(core::mem::size_of::<StructuredMetadata>(), 8);
    }
}
