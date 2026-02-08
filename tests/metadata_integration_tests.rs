//! Integration tests for Structured Metadata Extension.
//!
//! Covers all TC-1.x verification criteria for risk-adaptive policies.

use pq_aggregate::causal::{
    CausalEvent, CausalEventLogger, StructuredMetadata, 
    EVENT_VERSION_LEGACY, EVENT_VERSION_METADATA,
    risk_flags,
};
use pq_aggregate::causal::metadata::compute_metadata_commitment;
use pq_aggregate::policy::types::PolicyCondition;
use pq_aggregate::policy::evaluator::{evaluate_condition_with_metadata, extract_metadata_from_proposal};

// =============================================================================
// TC-1.1: New events (v0.02) with metadata pass chain verification
// =============================================================================

#[test]
fn tc_1_1_v02_events_with_metadata_pass_verification() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xAAu8; 32];
    
    // Log a metadata-aware event
    let metadata = StructuredMetadata::new(1500_00, 137, risk_flags::CROSS_CHAIN);
    let event = logger.log_event_with_metadata(
        &agent_id,
        0x01, // SignatureRequest
        b"transfer $1500 to Polygon",
        metadata,
        1000,
    ).unwrap();
    
    assert_eq!(event.version, EVENT_VERSION_METADATA);
    assert_ne!(event.metadata_commitment, [0u8; 32]);
    
    // Verify chain
    let root = logger.get_current_root();
    let events = logger.get_all_events();
    assert!(CausalEventLogger::verify_event_chain(events, &root));
}

// =============================================================================
// TC-1.2: Legacy events (v0.01) remain verifiable without modification
// =============================================================================

#[test]
fn tc_1_2_legacy_events_remain_verifiable() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xBBu8; 32];
    
    // Log legacy events using the original API
    logger.log_event(&agent_id, 0x01, b"legacy request 1", 1000).unwrap();
    logger.log_event(&agent_id, 0x02, b"legacy verification", 2000).unwrap();
    logger.log_event(&agent_id, 0x01, b"legacy request 2", 3000).unwrap();
    
    let root = logger.get_current_root();
    let events = logger.get_all_events();
    
    // All events should be v0.01
    for event in events {
        assert_eq!(event.version, EVENT_VERSION_LEGACY);
        assert_eq!(event.metadata_commitment, [0u8; 32]);
    }
    
    // Chain verification should pass
    assert!(CausalEventLogger::verify_event_chain(events, &root));
}

// =============================================================================
// TC-1.3: Tampering with metadata_commitment invalidates fingerprint
// =============================================================================

#[test]
fn tc_1_3_metadata_commitment_tampering_detected() {
    let metadata = StructuredMetadata::new(5000_00, 1, 0);
    let mut event = CausalEvent::new_with_metadata(
        1,
        1000,
        [0xCCu8; 32],
        0x01,
        b"test payload",
        &metadata,
    );
    
    // Verify original fingerprint
    assert!(event.verify_fingerprint());
    
    // Tamper with metadata_commitment
    event.metadata_commitment[0] ^= 0xFF;
    
    // Fingerprint should now be invalid
    assert!(!event.verify_fingerprint());
}

// =============================================================================
// TC-1.4: $50 transfer with min_amount_usd=1000 → skips verification
// =============================================================================

#[test]
fn tc_1_4_low_value_transfer_skips_verification() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xDDu8; 32];
    
    // Log a signature request (no verifications logged)
    let metadata = StructuredMetadata::new(50_00, 0, 0); // $50
    logger.log_event_with_metadata(&agent_id, 0x01, b"$50 transfer", metadata, 1000).unwrap();
    
    let events = logger.get_all_events();
    let condition = PolicyCondition::MinVerificationCount {
        threshold: 3,
        min_amount_usd: Some(1000),
        cross_chain_only: false,
    };
    
    // Should pass (skip verification for low-value)
    assert!(evaluate_condition_with_metadata(&condition, events, 1, Some(&metadata)));
}

// =============================================================================
// TC-1.5: $1,500 transfer with min_amount_usd=1000 → enforces 3 verifications
// =============================================================================

#[test]
fn tc_1_5_high_value_transfer_enforces_verification() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xEEu8; 32];
    
    let metadata = StructuredMetadata::new(1500_00, 0, 0); // $1,500
    let condition = PolicyCondition::MinVerificationCount {
        threshold: 3,
        min_amount_usd: Some(1000),
        cross_chain_only: false,
    };
    
    // Log signature request without prior verifications
    logger.log_event_with_metadata(&agent_id, 0x01, b"$1500 transfer", metadata, 1000).unwrap();
    
    let events = logger.get_all_events();
    
    // Should fail (high-value needs 3 verifications, has 0)
    assert!(!evaluate_condition_with_metadata(&condition, events, 1, Some(&metadata)));
    
    // Now add 3 address verifications
    let mut logger2 = CausalEventLogger::new([0u8; 32]);
    logger2.log_event(&agent_id, 0x02, b"verify addr 1", 1000).unwrap();
    logger2.log_event(&agent_id, 0x02, b"verify addr 2", 2000).unwrap();
    logger2.log_event(&agent_id, 0x02, b"verify addr 3", 3000).unwrap();
    logger2.log_event_with_metadata(&agent_id, 0x01, b"$1500 transfer", metadata, 4000).unwrap();
    
    let events2 = logger2.get_all_events();
    
    // Should pass now (has 3 verifications before the request)
    assert!(evaluate_condition_with_metadata(&condition, events2, 4, Some(&metadata)));
}

// =============================================================================
// TC-1.6: Cross-chain transfer with cross_chain_only=true → enforces verifications
// =============================================================================

#[test]
fn tc_1_6_cross_chain_transfer_enforces_verification() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xFFu8; 32];
    
    // Cross-chain transfer to Polygon
    let metadata = StructuredMetadata::new(500_00, 137, risk_flags::CROSS_CHAIN);
    let condition = PolicyCondition::MinVerificationCount {
        threshold: 3,
        min_amount_usd: None,
        cross_chain_only: true,
    };
    
    logger.log_event_with_metadata(&agent_id, 0x01, b"cross-chain transfer", metadata, 1000).unwrap();
    let events = logger.get_all_events();
    
    // Should fail (cross-chain needs verifications)
    assert!(!evaluate_condition_with_metadata(&condition, events, 1, Some(&metadata)));
}

// =============================================================================
// TC-1.7: Same-chain transfer with cross_chain_only=true → skips verifications
// =============================================================================

#[test]
fn tc_1_7_same_chain_transfer_skips_verification() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0x11u8; 32];
    
    // Same-chain transfer (destination_chain = 0)
    let metadata = StructuredMetadata::new(10000_00, 0, 0); // $10,000 but same-chain
    let condition = PolicyCondition::MinVerificationCount {
        threshold: 3,
        min_amount_usd: None,
        cross_chain_only: true,
    };
    
    logger.log_event_with_metadata(&agent_id, 0x01, b"same-chain transfer", metadata, 1000).unwrap();
    let events = logger.get_all_events();
    
    // Should pass (same-chain skips verification when cross_chain_only=true)
    assert!(evaluate_condition_with_metadata(&condition, events, 1, Some(&metadata)));
}

// =============================================================================
// TC-1.8: Attempt to substitute metadata for existing payload_hash fails
// =============================================================================

#[test]
fn tc_1_8_metadata_substitution_fails() {
    let original_metadata = StructuredMetadata::new(50_00, 0, 0); // $50
    let fake_metadata = StructuredMetadata::new(50000_00, 0, 0); // $50,000
    
    let event = CausalEvent::new_with_metadata(
        1,
        1000,
        [0x22u8; 32],
        0x01,
        b"transfer payload",
        &original_metadata,
    );
    
    // Try to extract metadata with the fake values
    let extracted = extract_metadata_from_proposal(&event, Some(&fake_metadata));
    
    // Should fail (commitment mismatch)
    assert!(extracted.is_none());
    
    // Correct metadata should succeed
    let extracted_correct = extract_metadata_from_proposal(&event, Some(&original_metadata));
    assert!(extracted_correct.is_some());
    assert_eq!(extracted_correct.unwrap().amount_usd_cents, 50_00);
}

// =============================================================================
// TC-1.9: Legacy events default to conservative enforcement
// =============================================================================

#[test]
fn tc_1_9_legacy_events_conservative_enforcement() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0x33u8; 32];
    
    // Log a legacy event (no metadata)
    logger.log_event(&agent_id, 0x01, b"legacy request", 1000).unwrap();
    
    let events = logger.get_all_events();
    let condition = PolicyCondition::MinVerificationCount {
        threshold: 3,
        min_amount_usd: Some(10000), // High threshold that would skip with metadata
        cross_chain_only: false,
    };
    
    // Should fail (conservative: always enforce for legacy events)
    assert!(!evaluate_condition_with_metadata(&condition, events, 1, None));
}

// =============================================================================
// Additional tests for edge cases
// =============================================================================

#[test]
fn test_mixed_v01_v02_events_verify() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0x44u8; 32];
    
    // Mix of legacy and metadata events
    logger.log_event(&agent_id, 0x02, b"legacy verify", 1000).unwrap();
    
    let metadata = StructuredMetadata::new(100_00, 0, 0);
    logger.log_event_with_metadata(&agent_id, 0x01, b"v02 request", metadata, 2000).unwrap();
    
    logger.log_event(&agent_id, 0x02, b"legacy verify 2", 3000).unwrap();
    
    let root = logger.get_current_root();
    let events = logger.get_all_events();
    
    // Chain verification should work with mixed versions
    assert!(CausalEventLogger::verify_event_chain(events, &root));
}

#[test]
fn test_metadata_commitment_deterministic() {
    let nonce = 42u64;
    let payload_hash = [0xABu8; 32];
    let metadata = StructuredMetadata::new(1000_00, 1, risk_flags::HIGH_VALUE);
    
    let c1 = compute_metadata_commitment(nonce, &payload_hash, &metadata);
    let c2 = compute_metadata_commitment(nonce, &payload_hash, &metadata);
    
    assert_eq!(c1, c2);
}

#[test]
fn test_metadata_commitment_changes_with_amount() {
    let nonce = 1u64;
    let payload_hash = [0x00u8; 32];
    
    let m1 = StructuredMetadata::new(100_00, 0, 0);
    let m2 = StructuredMetadata::new(200_00, 0, 0);
    
    let c1 = compute_metadata_commitment(nonce, &payload_hash, &m1);
    let c2 = compute_metadata_commitment(nonce, &payload_hash, &m2);
    
    assert_ne!(c1, c2);
}

#[test]
fn test_structured_metadata_size() {
    assert_eq!(core::mem::size_of::<StructuredMetadata>(), 8);
}

#[test]
fn test_risk_flags_helpers() {
    let m = StructuredMetadata::new(0, 0, risk_flags::CROSS_CHAIN | risk_flags::HIGH_VALUE);
    assert!((m.risk_flags & risk_flags::CROSS_CHAIN) != 0);
    assert!((m.risk_flags & risk_flags::HIGH_VALUE) != 0);
    assert!((m.risk_flags & risk_flags::UNKNOWN_RECIPIENT) == 0);
}
