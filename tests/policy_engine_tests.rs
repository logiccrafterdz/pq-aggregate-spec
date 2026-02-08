use pq_aggregate::causal::{CausalEventLogger, CausalEvent};
use pq_aggregate::policy::{PolicyEngine, BehavioralPolicy, PolicyCondition, RiskTier, Currency};


fn setup_logger() -> CausalEventLogger {
    CausalEventLogger::new([0u8; 32])
}

#[test]
fn test_tc_2_1_min_verification_count() {
    let mut logger = setup_logger();
    let agent_id = [0xAA; 32];
    let mut events = Vec::new();
    
    let policy = BehavioralPolicy {
        name: "High Value Protection",
        conditions: vec![PolicyCondition::MinVerificationCount { 
            threshold: 3, 
            min_amount_usd: None,  // Always enforce regardless of amount
            cross_chain_only: false,
        }],
        risk_tier: RiskTier::High,
    };
    let engine = PolicyEngine::new(vec![policy]);

    // 1. Log 2 verifications and check compliance for a signature request
    events.push(logger.log_event(&agent_id, 0x02, b"v1", 1000).unwrap());
    events.push(logger.log_event(&agent_id, 0x02, b"v2", 1100).unwrap());
    
    // Log signature request at nonce 3
    events.push(logger.log_event(&agent_id, 0x01, b"sig1", 1200).unwrap());
    
    let res = engine.evaluate_chain(&events, &logger.get_current_root()).unwrap();
    assert!(!res.compliant);
    assert_eq!(res.failed_condition, Some(0));

    // 2. Clear and try with 3 verifications
    let mut logger2 = setup_logger();
    let mut events2 = Vec::new();
    events2.push(logger2.log_event(&agent_id, 0x02, b"v1", 1000).unwrap());
    events2.push(logger2.log_event(&agent_id, 0x02, b"v2", 1100).unwrap());
    events2.push(logger2.log_event(&agent_id, 0x02, b"v3", 1200).unwrap());
    events2.push(logger2.log_event(&agent_id, 0x01, b"sig2", 1300).unwrap()); // Signature at nonce 4
    
    let res = engine.evaluate_chain(&events2, &logger2.get_current_root()).unwrap();
    assert!(res.compliant);
}

#[test]
fn test_tc_2_2_min_time_between_actions() {
    let mut logger = setup_logger();
    let agent_id = [0xBB; 32];
    let mut events = Vec::new();
    let engine = PolicyEngine::new(vec![BehavioralPolicy {
        name: "Cooldown",
        conditions: vec![PolicyCondition::MinTimeBetweenActions { action_type: 0x01, min_seconds: 600 }],
        risk_tier: RiskTier::Medium,
    }]);

    events.push(logger.log_event(&agent_id, 0x01, b"r1", 1000_000).unwrap());
    events.push(logger.log_event(&agent_id, 0x01, b"r2", 1599_000).unwrap()); // 599s < 600s
    
    let res = engine.evaluate_chain(&events, &logger.get_current_root()).unwrap();
    assert!(!res.compliant);

    // Try with correct timing
    let mut logger2 = setup_logger();
    let mut events2 = Vec::new();
    events2.push(logger2.log_event(&agent_id, 0x01, b"r1", 1000_000).unwrap());
    events2.push(logger2.log_event(&agent_id, 0x01, b"r2", 1600_000).unwrap()); // 600s == 600s
    assert!(engine.evaluate_chain(&events2, &logger2.get_current_root()).unwrap().compliant);
}

#[test]
fn test_tc_2_3_max_daily_outflow() {
    let mut logger = setup_logger();
    let agent_id = [0xCC; 32];
    let mut events = Vec::new();
    let engine = PolicyEngine::new(vec![BehavioralPolicy {
        name: "Spending Limit",
        conditions: vec![PolicyCondition::MaxDailyOutflow { max_amount: 5000, currency: Currency::USD }],
        risk_tier: RiskTier::Medium,
    }]);

    // log_event simulation uses 1000 per signature request
    for i in 1..=5 {
        events.push(logger.log_event(&agent_id, 0x01, b"req", 1000 + i).unwrap());
    }
    
    // 5000 is allowed
    assert!(engine.evaluate_chain(&events, &logger.get_current_root()).unwrap().compliant);
    
    // 6th request (6000 total) fails
    events.push(logger.log_event(&agent_id, 0x01, b"req", 2000).unwrap());
    assert!(!engine.evaluate_chain(&events, &logger.get_current_root()).unwrap().compliant);
}

#[test]
fn test_tc_2_4_concurrency_protection() {
    let mut logger = setup_logger();
    let agent_id = [0xDD; 32];
    let mut events = Vec::new();
    let engine = PolicyEngine::new(vec![BehavioralPolicy {
        name: "Anti-Burst",
        conditions: vec![PolicyCondition::NoConcurrentRequests { window_seconds: 30 }],
        risk_tier: RiskTier::High,
    }]);

    events.push(logger.log_event(&agent_id, 0x01, b"op1", 100_000).unwrap());
    events.push(logger.log_event(&agent_id, 0x03, b"op2", 129_000).unwrap()); // 29s diff
    
    let res = engine.evaluate_chain(&events, &logger.get_current_root()).unwrap();
    assert!(!res.compliant);
}

#[test]
fn test_tc_2_5_composite_policy() {
    let mut logger = setup_logger();
    let agent_id = [0xEE; 32];
    let mut events = Vec::new();
    
    let policy = BehavioralPolicy {
        name: "Strict Combo",
        conditions: vec![
            PolicyCondition::MaxDailyOutflow { max_amount: 5000, currency: Currency::USD },
            PolicyCondition::NoConcurrentRequests { window_seconds: 30 }
        ],
        risk_tier: RiskTier::High,
    };
    let engine = PolicyEngine::new(vec![policy]);

    // Violate 1st condition (Amount)
    for i in 1..=6 {
        events.push(logger.log_event(&agent_id, 0x01, b"req", 1000 * i as u64).unwrap());
    }
    let res = engine.evaluate_chain(&events, &logger.get_current_root()).unwrap();
    assert!(!res.compliant);
    assert_eq!(res.failed_condition, Some(0)); // Max outflow is idx 0

    // Reset and violate 2nd condition (Time)
    let mut logger2 = setup_logger();
    let mut events2 = Vec::new();
    events2.push(logger2.log_event(&agent_id, 0x01, b"op1", 100_000).unwrap());
    events2.push(logger2.log_event(&agent_id, 0x03, b"op2", 120_000).unwrap());
    let res2 = engine.evaluate_chain(&events2, &logger2.get_current_root()).unwrap();
    assert!(!res2.compliant);
    assert_eq!(res2.failed_condition, Some(1)); // Concurrency is idx 1
}

#[test]
fn test_tc_2_8_risk_tier_mapping() {
    let mut logger = setup_logger();
    let agent_id = [0xDA; 32];
    let mut events = Vec::new();
    
    let engine_low = PolicyEngine::new(vec![BehavioralPolicy {
        name: "Low Risk",
        conditions: vec![],
        risk_tier: RiskTier::Low,
    }]);
    
    let engine_high = PolicyEngine::new(vec![BehavioralPolicy {
        name: "High Risk",
        conditions: vec![],
        risk_tier: RiskTier::High,
    }]);

    events.push(logger.log_event(&agent_id, 0x01, b"msg", 1000).unwrap());
    let root = logger.get_current_root();

    assert_eq!(engine_low.evaluate_chain(&events, &root).unwrap().risk_tier.to_threshold(), 2);
    assert_eq!(engine_high.evaluate_chain(&events, &root).unwrap().risk_tier.to_threshold(), 5);
}
