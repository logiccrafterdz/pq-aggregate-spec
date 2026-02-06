//! Causal Event Logger implementation.
//!
//! Enforces strict nonce ordering and temporal causal integrity.

use alloc::vec::Vec;
use crate::causal::event::CausalEvent;
use crate::causal::merkle::IncrementalMerkleTree;
use core::result::Result;
use sha3::{Digest, Sha3_256};
use thiserror::Error;

/// Errors specific to the Causal Event Logger.
#[derive(Debug, Error, PartialEq)]
pub enum LoggerError {
    #[error("Nonce regression: Attempted to log event with nonce {0} <= last {1}")]
    NonceRegression(u64, u64),
    #[error("Timestamp regression: Timestamp {0} violates causal ordering (skew limit exceeded)")]
    TimestampRegression(u64),
    #[error("Invalid agent identifier")]
    InvalidAgentId,
    #[error("Payload too large: {0} bytes (max 4096)")]
    PayloadTooLarge(usize),
}

/// The Causal Event Logger.
pub struct CausalEventLogger {
    last_nonce: u64,
    last_timestamp: u64,
    merkle_tree: IncrementalMerkleTree,
    /// Store leaves to support generate_proof. 
    /// Note: In a production small-memory system, these would be in flash.
    leaves: Vec<[u8; 32]>,
}

impl CausalEventLogger {
    /// Create a new logger with an initial root.
    pub fn new(_initial_root: [u8; 32]) -> Self {
        Self {
            last_nonce: 0,
            last_timestamp: 0,
            merkle_tree: IncrementalMerkleTree::new(),
            leaves: Vec::new(),
        }
    }

    /// Log a new event after verifying causal constraints.
    pub fn log_event(
        &mut self,
        agent_id: &[u8; 32],
        action_type: u8,
        payload: &[u8],
        current_time_ms: u64,
    ) -> Result<CausalEvent, LoggerError> {
        // 1. Validate payload size
        if payload.len() > 4096 {
            return Err(LoggerError::PayloadTooLarge(payload.len()));
        }

        // 2. Validate nonce monotonicity
        // Note: For simplicity, we auto-increment if nonce isn't provided, 
        // but here the spec implies we should handle it. Since the API doesn't 
        // take a nonce, we use internal counter.
        let new_nonce = self.last_nonce + 1;

        // 3. Validate timestamp regression (±500ms skew tolerance)
        if self.last_timestamp > 0 && current_time_ms + 500 < self.last_timestamp {
            return Err(LoggerError::TimestampRegression(current_time_ms));
        }

        // 4. Create the event
        let event = CausalEvent::new(
            new_nonce,
            current_time_ms,
            *agent_id,
            action_type,
            payload,
        );

        // 5. Update state
        self.last_nonce = new_nonce;
        self.last_timestamp = if current_time_ms > self.last_timestamp {
            current_time_ms
        } else {
            self.last_timestamp
        };

        // 6. Update Merkle Tree
        let leaf = event.to_leaf();
        self.merkle_tree.insert(leaf);
        self.leaves.push(leaf);

        Ok(event)
    }

    /// Get the current Merkle root.
    pub fn get_current_root(&self) -> [u8; 32] {
        self.merkle_tree.current_root
    }

    /// Generate a Merkle proof for a specific nonce.
    /// Since we use IncrementalMerkleTree with stored leaves, we can 
    /// provide the proof.
    pub fn generate_proof(&self, nonce: u64) -> Option<Vec<[u8; 32]>> {
        if nonce == 0 || nonce > self.leaves.len() as u64 {
            return None;
        }
        
        // In a real sparse/incremental tree, generating a past proof 
        // requires the full tree or specific path history. 
        // For this implementation, we simulate it using the leaves.
        let tree = crate::utils::MerkleTree::from_leaves(&self.leaves);
        tree.prove((nonce - 1) as usize).map(|p| p.siblings)
    }

    /// Verify the integrity of an event chain against a root.
    pub fn verify_event_chain(
        events: &[CausalEvent],
        expected_root: &[u8; 32],
    ) -> bool {
        if events.is_empty() {
            return expected_root == &[0u8; 32];
        }

        // 1. Re-derive leaves from raw event data (don't trust stored fingerprints)
        let mut leaves = Vec::with_capacity(events.len());
        for (i, event) in events.iter().enumerate() {
            // Recompute fingerprint from components
            // We use the same logic as CausalEvent::new but without the struct overhead
            let mut hasher = Sha3_256::new();
            hasher.update(&event.nonce.to_le_bytes());
            hasher.update(&event.timestamp.to_le_bytes());
            hasher.update(&[event.action_type]);
            hasher.update(&event.payload_hash);
            let derived_fingerprint: [u8; 32] = hasher.finalize().into();

            if derived_fingerprint != event.behavioral_fingerprint {
                return false; // Tampered!
            }

            // Recompute leaf from nonce and fingerprint
            let mut leaf_hasher = Sha3_256::new();
            leaf_hasher.update(&event.nonce.to_le_bytes());
            leaf_hasher.update(&derived_fingerprint);
            leaves.push(leaf_hasher.finalize().into());

            // 2. Strict ordering check
            if i > 0 {
                if events[i].nonce <= events[i-1].nonce {
                    return false;
                }
                if events[i].timestamp + 500 < events[i-1].timestamp {
                    return false;
                }
            }
        }

        let tree = crate::utils::MerkleTree::from_leaves(&leaves);
        tree.root() == *expected_root
    }
}
