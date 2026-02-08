//! Deterministic evaluators for policy conditions.
//!
//! Supports both legacy (v0.01) and metadata-aware (v0.02) events
//! with conservative fallback behavior for legacy events.

use crate::causal::{CausalEvent, StructuredMetadata, EVENT_VERSION_METADATA};
use crate::causal::metadata::compute_metadata_commitment;
use crate::policy::types::PolicyCondition;

/// Extracted metadata from a v0.02 event, or None for legacy events.
#[derive(Debug, Clone, Copy)]
pub struct ExtractedMetadata {
    pub amount_usd_cents: u32,
    pub destination_chain: u16,
    pub risk_flags: u8,
}

impl From<&StructuredMetadata> for ExtractedMetadata {
    fn from(m: &StructuredMetadata) -> Self {
        Self {
            amount_usd_cents: m.amount_usd_cents,
            destination_chain: m.destination_chain,
            risk_flags: m.risk_flags,
        }
    }
}

/// Attempt to extract metadata from an event.
///
/// For v0.02 events, this returns the structured metadata if available.
/// For v0.01 (legacy) events, returns None (conservative fallback).
///
/// **Security Note**: We cannot directly extract metadata from the commitment
/// since it's a one-way hash. The caller must provide the original metadata
/// for verification. This function is primarily for policy evaluation where
/// the runtime has access to the original proposal.
pub fn extract_metadata_from_proposal(
    event: &CausalEvent,
    proposed_metadata: Option<&StructuredMetadata>,
) -> Option<ExtractedMetadata> {
    if event.version != EVENT_VERSION_METADATA {
        return None; // Legacy event, no metadata
    }

    // Verify the proposed metadata matches the commitment
    if let Some(metadata) = proposed_metadata {
        let expected_commitment = compute_metadata_commitment(
            event.nonce,
            &event.payload_hash,
            metadata,
        );
        if expected_commitment == event.metadata_commitment {
            return Some(ExtractedMetadata::from(metadata));
        }
    }

    None // Commitment mismatch or no metadata provided
}

/// Evaluates a single policy condition against an event chain.
pub fn evaluate_condition(
    condition: &PolicyCondition,
    events: &[CausalEvent],
    target_nonce: u64,
) -> bool {
    evaluate_condition_with_metadata(condition, events, target_nonce, None)
}

/// Evaluates a policy condition with optional metadata for the target event.
pub fn evaluate_condition_with_metadata(
    condition: &PolicyCondition,
    events: &[CausalEvent],
    target_nonce: u64,
    target_metadata: Option<&StructuredMetadata>,
) -> bool {
    match condition {
        PolicyCondition::MaxDailyOutflow { max_amount, currency: _ } => {
            evaluate_max_outflow(*max_amount, events, target_nonce)
        }
        PolicyCondition::MinVerificationCount { threshold, min_amount_usd, cross_chain_only } => {
            evaluate_verification_count_with_metadata(
                *threshold,
                *min_amount_usd,
                *cross_chain_only,
                events,
                target_nonce,
                target_metadata,
            )
        }
        PolicyCondition::MinTimeBetweenActions { action_type, min_seconds } => {
            evaluate_time_between(*action_type, *min_seconds, events, target_nonce)
        }
        PolicyCondition::NoConcurrentRequests { window_seconds } => {
            evaluate_concurrency(*window_seconds, events, target_nonce)
        }
        PolicyCondition::AddressWhitelist { allowed_prefixes } => {
            evaluate_whitelist(allowed_prefixes, events, target_nonce)
        }
    }
}

fn evaluate_max_outflow(max_amount: u64, events: &[CausalEvent], target_nonce: u64) -> bool {
    let day_ms = 24 * 60 * 60 * 1000;
    let target_event = events.iter().find(|e| e.nonce == target_nonce);
    if let Some(target) = target_event {
        let start_ts = target.timestamp.saturating_sub(day_ms);
        let mut total = 0u64;
        
        for event in events.iter().filter(|e| e.nonce <= target_nonce && e.timestamp >= start_ts) {
            // In a real system, we'd parse the payload for 'amount'.
            // For the spec, we simulate 'outflow' by using a fixed value for SignatureRequests
            if event.action_type == 0x01 { // SIGNATURE_REQUEST
                total = total.saturating_add(1000); // Simulated $1000 per request
            }
        }
        total <= max_amount
    } else {
        true
    }
}

/// Risk-adaptive verification count evaluation.
///
/// **Behavior**:
/// - If `target_metadata` is provided (v0.02 event):
///   - Skip enforcement if `amount < min_amount_usd`
///   - Skip enforcement if `cross_chain_only && destination_chain == 0`
/// - If `target_metadata` is None (v0.01 legacy event):
///   - **Conservative fallback**: Always enforce the verification requirement
fn evaluate_verification_count_with_metadata(
    threshold: u8,
    min_amount_usd: Option<u64>,
    cross_chain_only: bool,
    events: &[CausalEvent],
    target_nonce: u64,
    target_metadata: Option<&StructuredMetadata>,
) -> bool {
    // 1. Check if we should skip enforcement based on metadata
    if let Some(metadata) = target_metadata {
        // Skip if amount is below threshold
        if let Some(min_amount) = min_amount_usd {
            let amount_usd = metadata.amount_usd_cents as u64 / 100;
            if amount_usd < min_amount {
                return true; // Low-value action, skip verification requirement
            }
        }

        // Skip if cross_chain_only is set but this is a same-chain action
        if cross_chain_only && metadata.destination_chain == 0 {
            return true; // Same-chain action, skip verification requirement
        }
    }
    // If metadata is None (legacy event), we fall through to enforce verification

    // 2. Count verification events before the target
    let count = events.iter()
        .filter(|e| e.nonce < target_nonce && e.action_type == 0x02) // ADDRESS_VERIFICATION
        .count();
    
    count >= threshold as usize
}

fn evaluate_time_between(action_type: u8, min_seconds: u64, events: &[CausalEvent], target_nonce: u64) -> bool {
    let target_event = events.iter().find(|e| e.nonce == target_nonce);
    if let Some(target) = target_event {
        if target.action_type != action_type {
            return true;
        }

        let last_same_action = events.iter()
            .filter(|e| e.nonce < target_nonce && e.action_type == action_type)
            .last();

        if let Some(last) = last_same_action {
            let diff_ms = target.timestamp.saturating_sub(last.timestamp);
            diff_ms >= min_seconds * 1000
        } else {
            true
        }
    } else {
        true
    }
}

fn evaluate_concurrency(window_seconds: u64, events: &[CausalEvent], target_nonce: u64) -> bool {
    let target_event = events.iter().find(|e| e.nonce == target_nonce);
    if let Some(target) = target_event {
        let window_ms = window_seconds * 1000;
        
        let concurrent = events.iter()
            .filter(|e| e.nonce < target_nonce && e.nonce > 0)
            .any(|e| target.timestamp.saturating_sub(e.timestamp) < window_ms);
            
        !concurrent
    } else {
        true
    }
}

fn evaluate_whitelist(prefixes: &[[u8; 20]], events: &[CausalEvent], target_nonce: u64) -> bool {
    // Simulating address check from payload
    // In a real system, we'd extract the destination from payload_hash or separate log data
    let destination = [0u8; 20]; // Simulated
    
    // If target is address verification or signature request, check.
    let target_event = events.iter().find(|e| e.nonce == target_nonce);
    if let Some(target) = target_event {
        if target.action_type == 0x01 || target.action_type == 0x02 {
            return prefixes.iter().any(|p| p == &destination);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::causal::metadata::StructuredMetadata;

    #[test]
    fn test_low_value_skips_verification() {
        let events = vec![
            CausalEvent::new(1, 1000, [0u8; 32], 0x01, b"request"),
        ];
        
        // $50 transfer with min_amount_usd=1000 should skip verification
        let metadata = StructuredMetadata::new(50_00, 0, 0); // $50
        let condition = PolicyCondition::MinVerificationCount {
            threshold: 3,
            min_amount_usd: Some(1000),
            cross_chain_only: false,
        };
        
        assert!(evaluate_condition_with_metadata(&condition, &events, 1, Some(&metadata)));
    }

    #[test]
    fn test_high_value_enforces_verification() {
        let events = vec![
            CausalEvent::new(1, 1000, [0u8; 32], 0x01, b"request"),
        ];
        
        // $1,500 transfer with min_amount_usd=1000 should enforce verification
        let metadata = StructuredMetadata::new(1500_00, 0, 0); // $1,500
        let condition = PolicyCondition::MinVerificationCount {
            threshold: 3,
            min_amount_usd: Some(1000),
            cross_chain_only: false,
        };
        
        // No verifications yet, should fail
        assert!(!evaluate_condition_with_metadata(&condition, &events, 1, Some(&metadata)));
    }

    #[test]
    fn test_cross_chain_only_same_chain_skips() {
        let events = vec![
            CausalEvent::new(1, 1000, [0u8; 32], 0x01, b"request"),
        ];
        
        // Same-chain transfer with cross_chain_only=true should skip
        let metadata = StructuredMetadata::new(5000_00, 0, 0); // Same chain (destination_chain=0)
        let condition = PolicyCondition::MinVerificationCount {
            threshold: 3,
            min_amount_usd: None,
            cross_chain_only: true,
        };
        
        assert!(evaluate_condition_with_metadata(&condition, &events, 1, Some(&metadata)));
    }

    #[test]
    fn test_cross_chain_enforces_verification() {
        let events = vec![
            CausalEvent::new(1, 1000, [0u8; 32], 0x01, b"request"),
        ];
        
        // Cross-chain transfer with cross_chain_only=true should enforce
        let metadata = StructuredMetadata::new(5000_00, 137, 0); // Polygon chain
        let condition = PolicyCondition::MinVerificationCount {
            threshold: 3,
            min_amount_usd: None,
            cross_chain_only: true,
        };
        
        // No verifications yet, should fail
        assert!(!evaluate_condition_with_metadata(&condition, &events, 1, Some(&metadata)));
    }

    #[test]
    fn test_legacy_event_conservative_enforcement() {
        let events = vec![
            CausalEvent::new(1, 1000, [0u8; 32], 0x01, b"request"),
        ];
        
        // No metadata (legacy event) should always enforce verification
        let condition = PolicyCondition::MinVerificationCount {
            threshold: 3,
            min_amount_usd: Some(1000), // Would skip for low-value with metadata
            cross_chain_only: false,
        };
        
        // No metadata provided, should enforce (conservative) and fail
        assert!(!evaluate_condition_with_metadata(&condition, &events, 1, None));
    }
}
