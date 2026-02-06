//! Causal Event structure for agent behavior logging.
//!
//! Provides the data structures for capturing agent actions as verifiable
//! causal events tied to a monotonically increasing nonce.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CausalEvent {
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
    /// SHA3-256 of (nonce || timestamp || action_type || payload_hash).
    pub behavioral_fingerprint: [u8; 32],
}

impl CausalEvent {
    /// Create a new causal event and compute its behavioral fingerprint.
    pub fn new(
        nonce: u64,
        timestamp: u64,
        agent_id: [u8; 32],
        action_type: u8,
        payload: &[u8],
    ) -> Self {
        let payload_hash = Self::hash_data(payload);
        let behavioral_fingerprint = Self::compute_fingerprint(
            nonce,
            timestamp,
            action_type,
            &payload_hash,
        );

        Self {
            nonce,
            timestamp,
            agent_id,
            action_type,
            payload_hash,
            behavioral_fingerprint,
        }
    }

    /// Compute leaf hash for Merkle integration: leaf = SHA3-256(nonce || behavioral_fingerprint).
    pub fn to_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.behavioral_fingerprint);
        hasher.finalize().into()
    }

    /// Helper to hash payload data.
    fn hash_data(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compute the behavioral fingerprint: SHA3-256(nonce || timestamp || action_type || payload_hash).
    fn compute_fingerprint(
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

    /// Serialize to compact binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple manual serialization for compact representation
        let mut out = Vec::with_capacity(32 + 32 + 32 + 8 + 8 + 1);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.agent_id);
        out.push(self.action_type);
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&self.behavioral_fingerprint);
        out
    }
}
