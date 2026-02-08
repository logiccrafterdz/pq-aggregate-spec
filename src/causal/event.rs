//! Causal Event structure for agent behavior logging.
//!
//! Provides the data structures for capturing agent actions as verifiable
//! causal events tied to a monotonically increasing nonce.
//!
//! ## Event Versions
//! - **v0.01 (legacy)**: Original format without metadata commitment.
//! - **v0.02 (metadata-aware)**: Includes cryptographic metadata commitment for risk-adaptive policies.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::causal::metadata::{StructuredMetadata, compute_metadata_commitment};

/// Event format versions.
pub const EVENT_VERSION_LEGACY: u8 = 0x01;
pub const EVENT_VERSION_METADATA: u8 = 0x02;

/// Types of actions that can be logged.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ActionType {
    SignatureRequest = 0x01,
    AddressVerification = 0x02,
    BalanceCheck = 0x03,
    WaitInterval = 0x04,
    PolicyQuery = 0x05,
}

impl From<u8> for ActionType {
    fn from(val: u8) -> Self {
        match val {
            0x01 => ActionType::SignatureRequest,
            0x02 => ActionType::AddressVerification,
            0x03 => ActionType::BalanceCheck,
            0x04 => ActionType::WaitInterval,
            0x05 => ActionType::PolicyQuery,
            _ => ActionType::WaitInterval, // Default/Unknown
        }
    }
}

/// A cryptographically robust, nonce-ordered event.
///
/// Supports two versions:
/// - **v0.01 (legacy)**: `metadata_commitment` is `[0u8; 32]`, fingerprint excludes metadata.
/// - **v0.02 (metadata-aware)**: `metadata_commitment` is bound to payload, fingerprint includes metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CausalEvent {
    /// Event format version (0x01 = legacy, 0x02 = metadata-aware).
    pub version: u8,
    /// Strictly monotonically increasing counter.
    pub nonce: u64,
    /// Unix epoch in milliseconds.
    pub timestamp: u64,
    /// SHA3-256 hash of agent identifier.
    pub agent_id: [u8; 32],
    /// Enum-encoded action.
    pub action_type: u8,
    /// SHA3-256 of action-specific data.
    pub payload_hash: [u8; 32],
    /// Cryptographic commitment to structured metadata (v0.02+).
    /// For v0.01 events, this is `[0u8; 32]`.
    pub metadata_commitment: [u8; 32],
    /// SHA3-256 of (nonce || timestamp || action_type || payload_hash [|| metadata_commitment]).
    pub behavioral_fingerprint: [u8; 32],
}

impl CausalEvent {
    /// Create a new legacy (v0.01) causal event without metadata.
    ///
    /// Maintains backward compatibility with existing code.
    pub fn new(
        nonce: u64,
        timestamp: u64,
        agent_id: [u8; 32],
        action_type: u8,
        payload: &[u8],
    ) -> Self {
        let payload_hash = Self::hash_data(payload);
        let metadata_commitment = [0u8; 32]; // Legacy: no metadata
        let behavioral_fingerprint = Self::compute_fingerprint_v1(
            nonce,
            timestamp,
            action_type,
            &payload_hash,
        );

        Self {
            version: EVENT_VERSION_LEGACY,
            nonce,
            timestamp,
            agent_id,
            action_type,
            payload_hash,
            metadata_commitment,
            behavioral_fingerprint,
        }
    }

    /// Create a new metadata-aware (v0.02) causal event.
    ///
    /// The metadata is cryptographically bound to the payload hash.
    pub fn new_with_metadata(
        nonce: u64,
        timestamp: u64,
        agent_id: [u8; 32],
        action_type: u8,
        payload: &[u8],
        metadata: &StructuredMetadata,
    ) -> Self {
        let payload_hash = Self::hash_data(payload);
        let metadata_commitment = compute_metadata_commitment(nonce, &payload_hash, metadata);
        let behavioral_fingerprint = Self::compute_fingerprint_v2(
            nonce,
            timestamp,
            action_type,
            &payload_hash,
            &metadata_commitment,
        );

        Self {
            version: EVENT_VERSION_METADATA,
            nonce,
            timestamp,
            agent_id,
            action_type,
            payload_hash,
            metadata_commitment,
            behavioral_fingerprint,
        }
    }

    /// Verify and recompute the behavioral fingerprint based on event version.
    ///
    /// Returns `true` if the stored fingerprint matches the computed one.
    pub fn verify_fingerprint(&self) -> bool {
        let computed = match self.version {
            EVENT_VERSION_LEGACY => Self::compute_fingerprint_v1(
                self.nonce,
                self.timestamp,
                self.action_type,
                &self.payload_hash,
            ),
            EVENT_VERSION_METADATA => Self::compute_fingerprint_v2(
                self.nonce,
                self.timestamp,
                self.action_type,
                &self.payload_hash,
                &self.metadata_commitment,
            ),
            _ => return false, // Unknown version
        };
        computed == self.behavioral_fingerprint
    }

    /// Compute leaf hash for Merkle integration: leaf = SHA3-256(nonce || behavioral_fingerprint).
    pub fn to_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.behavioral_fingerprint);
        hasher.finalize().into()
    }

    /// Helper to hash payload data.
    pub fn hash_data(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compute the legacy (v0.01) behavioral fingerprint.
    ///
    /// `SHA3-256(nonce || timestamp || action_type || payload_hash)`
    fn compute_fingerprint_v1(
        nonce: u64,
        timestamp: u64,
        action_type: u8,
        payload_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&[action_type]);
        hasher.update(payload_hash);
        hasher.finalize().into()
    }

    /// Compute the metadata-aware (v0.02) behavioral fingerprint.
    ///
    /// `SHA3-256(nonce || timestamp || action_type || payload_hash || metadata_commitment)`
    fn compute_fingerprint_v2(
        nonce: u64,
        timestamp: u64,
        action_type: u8,
        payload_hash: &[u8; 32],
        metadata_commitment: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&[action_type]);
        hasher.update(payload_hash);
        hasher.update(metadata_commitment);
        hasher.finalize().into()
    }

    /// Serialize to compact binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        // version(1) + nonce(8) + timestamp(8) + agent_id(32) + action_type(1) 
        // + payload_hash(32) + metadata_commitment(32) + behavioral_fingerprint(32)
        let mut out = Vec::with_capacity(1 + 8 + 8 + 32 + 1 + 32 + 32 + 32);
        out.push(self.version);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.agent_id);
        out.push(self.action_type);
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&self.metadata_commitment);
        out.extend_from_slice(&self.behavioral_fingerprint);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_event_creation() {
        let event = CausalEvent::new(
            1,
            1000,
            [0xAAu8; 32],
            0x01,
            b"test payload",
        );
        assert_eq!(event.version, EVENT_VERSION_LEGACY);
        assert_eq!(event.metadata_commitment, [0u8; 32]);
        assert!(event.verify_fingerprint());
    }

    #[test]
    fn test_metadata_event_creation() {
        let metadata = StructuredMetadata::new(1500_00, 137, 0);
        let event = CausalEvent::new_with_metadata(
            1,
            1000,
            [0xAAu8; 32],
            0x01,
            b"test payload",
            &metadata,
        );
        assert_eq!(event.version, EVENT_VERSION_METADATA);
        assert_ne!(event.metadata_commitment, [0u8; 32]);
        assert!(event.verify_fingerprint());
    }

    #[test]
    fn test_fingerprint_tamper_detection() {
        let metadata = StructuredMetadata::new(100_00, 0, 0);
        let mut event = CausalEvent::new_with_metadata(
            1,
            1000,
            [0xBBu8; 32],
            0x02,
            b"payload",
            &metadata,
        );
        
        // Tamper with metadata_commitment
        event.metadata_commitment[0] ^= 0xFF;
        assert!(!event.verify_fingerprint());
    }

    #[test]
    fn test_legacy_backward_compatibility() {
        // Simulate a v0.01 event and verify it still works
        let event = CausalEvent::new(5, 2000, [0xCCu8; 32], 0x03, b"legacy data");
        assert!(event.verify_fingerprint());
        
        // Leaf computation should work
        let leaf = event.to_leaf();
        assert_ne!(leaf, [0u8; 32]);
    }
}
