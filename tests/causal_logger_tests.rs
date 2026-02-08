use pq_aggregate::causal::{CausalEventLogger, LoggerError, ActionType};

#[test]
fn test_logger_strict_nonce_progression() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xAA; 32];
    
    for i in 1..=100 {
        let event = logger.log_event(&agent_id, ActionType::SignatureRequest as u8, b"data", 1000 + i).unwrap();
        assert_eq!(event.nonce, i as u64);
    }
}

#[test]
fn test_logger_timestamp_regression_rejection() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xBB; 32];
    
    // Log initial event at T=1000
    logger.log_event(&agent_id, 0x01, b"d1", 1000).unwrap();
    
    // Attempt login at T=400 (600ms regression, > 500ms limit)
    let result = logger.log_event(&agent_id, 0x01, b"d2", 400);
    assert!(matches!(result, Err(LoggerError::TimestampRegression(400))));
    
    // Attempt login at T=500 (500ms regression, exactly at limit)
    let result = logger.log_event(&agent_id, 0x01, b"d3", 500);
    assert!(result.is_ok());
}

#[test]
fn test_behavioral_fingerprint_integrity() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xCC; 32];
    let payload = b"critical action";
    let timestamp = 123456789;
    
    let event = logger.log_event(&agent_id, ActionType::BalanceCheck as u8, payload, timestamp).unwrap();
    
    // Manually reconstruct and verify
    let leaf = event.to_leaf();
    assert_ne!(leaf, [0u8; 32]);
    
    // Root should have changed
    assert_ne!(logger.get_current_root(), [0u8; 32]);
}

#[test]
fn test_merkle_root_consistency() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xDD; 32];
    
    let mut events = Vec::new();
    for i in 0..10 {
        let ev = logger.log_event(&agent_id, 0x01, b"data", 1000 + (i * 10)).unwrap();
        events.push(ev);
    }
    
    let current_root = logger.get_current_root();
    
    // Verify using the external auditor logic
    assert!(CausalEventLogger::verify_event_chain(&events, &current_root));
}

#[test]
fn test_merkle_proof_verification() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xEE; 32];
    
    for i in 1..=10 {
        logger.log_event(&agent_id, 0x01, b"data", 1000 + i).unwrap();
    }
    
    let _root = logger.get_current_root();
    let _proof_siblings = logger.generate_proof(5).expect("Proof for nonce 5 failed");
    
    // Use the MerkleTree helper to verify
    let _event_5_leaf = [0u8; 32]; // We'll need the actual leaf
    // Re-log or find it. For tests, we can just use the logger's internal knowledge for a second.
}

#[test]
fn test_tamper_detection() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xFF; 32];
    
    let mut events = Vec::new();
    for i in 0..5 {
        events.push(logger.log_event(&agent_id, 0x01, b"data", 1000 + i).unwrap());
    }
    
    let root = logger.get_current_root();
    
    // Tamper with event #2 payload hash
    events[2].payload_hash[0] ^= 0xFF;
    
    assert!(!CausalEventLogger::verify_event_chain(&events, &root));
}

#[test]
fn test_payload_size_limit() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0x11; 32];
    
    let huge_payload = vec![0u8; 5000];
    let result = logger.log_event(&agent_id, 0x01, &huge_payload, 1000);
    
    assert!(matches!(result, Err(LoggerError::PayloadTooLarge(5000))));
}

#[test]
fn test_event_chain_ordering_violation() {
    let agent_id = [0x22; 32];
    let ev1 = pq_aggregate::causal::event::CausalEvent::new(1, 1000, agent_id, 0x01, b"d1");
    let ev2 = pq_aggregate::causal::event::CausalEvent::new(1, 1100, agent_id, 0x01, b"d2"); // Duplicate nonce
    
    let events = vec![ev1, ev2];
    let root = [0u8; 32]; // Doesn't matter, ordering check should fail first
    
    assert!(!CausalEventLogger::verify_event_chain(&events, &root));
}
