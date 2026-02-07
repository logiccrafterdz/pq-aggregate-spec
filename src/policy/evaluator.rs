//! Deterministic evaluators for policy conditions.

use crate::causal::CausalEvent;
use crate::policy::types::PolicyCondition;

/// Evaluates a single policy condition against an event chain.
pub fn evaluate_condition(
    condition: &PolicyCondition,
    events: &[CausalEvent],
    target_nonce: u64,
) -> bool {
    match condition {
        PolicyCondition::MaxDailyOutflow { max_amount, currency: _ } => {
            evaluate_max_outflow(*max_amount, events, target_nonce)
        }
        PolicyCondition::MinVerificationCount { threshold, for_amount_gte } => {
            evaluate_verification_count(*threshold, *for_amount_gte, events, target_nonce)
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

fn evaluate_verification_count(threshold: u8, _min_amount: u64, events: &[CausalEvent], target_nonce: u64) -> bool {
    // NOTE(v0.1.0): CausalEvent stores only payload_hash, not the raw payload,
    // so we cannot extract the actual transaction amount. As a secure default,
    // we always enforce the verification count requirement regardless of amount.
    // A future version should carry structured metadata (amount, destination, etc.)
    // alongside the payload hash.

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
