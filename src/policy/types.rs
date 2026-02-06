//! Policy types for behavioral verification.
//!
//! Provides the definitions for policy conditions, risk tiers, and
//! composite behavioral policies.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Currency types for valuation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Currency {
    USD,
    ETH,
    SOL,
}

/// Risk tiers for adaptive security.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskTier {
    /// t = 2 (e.g., <$100 transfers)
    Low,
    /// t = 3 (e.g., $100–$1,000)
    Medium,
    /// t = 5 (e.g., >$1,000 or cross-chain)
    High,
}

impl RiskTier {
    /// Map risk tier to a threshold value.
    pub fn to_threshold(&self) -> usize {
        match self {
            RiskTier::Low => 2,
            RiskTier::Medium => 3,
            RiskTier::High => 5,
        }
    }
}

/// Deterministic conditions for a behavioral policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyCondition {
    /// Maximum cumulative outflow within a window (e.g., 24h).
    MaxDailyOutflow { max_amount: u64, currency: Currency },
    /// Minimum number of specific verification actions required for high-value requests.
    MinVerificationCount { threshold: u8, for_amount_gte: u64 },
    /// Minimum temporal separation between specific action types.
    MinTimeBetweenActions { action_type: u8, min_seconds: u64 },
    /// Reject if multiple requests occur within a specific window.
    NoConcurrentRequests { window_seconds: u64 },
    /// Restricted destination address prefixes.
    AddressWhitelist { allowed_prefixes: Vec<[u8; 20]> },
}

/// A composite behavioral policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BehavioralPolicy {
    pub name: &'static str,
    pub conditions: Vec<PolicyCondition>,
    pub risk_tier: RiskTier,
}

/// Outcome of a policy evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub compliant: bool,
    pub risk_tier: RiskTier,
    pub satisfied_conditions: Vec<usize>, // indices of passed conditions
    pub failed_condition: Option<usize>,  // first failing condition index
    pub evaluation_nonce: u64,            // nonce at which decision was made
}

/// Cryptographic proof of policy satisfaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyProof {
    /// Merkle root of the verified event chain (from Step 1).
    pub root_hash: [u8; 32],
    /// SHA3-256 hash of PolicyEvaluation (for Nova circuit input).
    pub evaluation_hash: [u8; 32],
    /// Unix timestamp in ms of the evaluation.
    pub timestamp: u64,
}
