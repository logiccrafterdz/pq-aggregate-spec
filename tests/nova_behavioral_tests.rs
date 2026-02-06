use pq_aggregate::causal::{CausalEventLogger};
use pq_aggregate::policy::{PolicyEngine, BehavioralPolicy, PolicyCondition, RiskTier};
use pq_aggregate::nova::unified_prover::{UnifiedProver};
use pq_aggregate::verifier::unified::{UnifiedVerifier};
use pq_aggregate::nova::params::{gen_unified_params, setup_unified_keys};
use pq_aggregate::setup;
use pasta_curves::pallas;

#[test]
#[cfg(feature = "nova")]
fn test_tc_3_1_valid_high_risk_threshold_5() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xAA; 32];
    
    // 1. Setup adaptive policy (High risk for > $1000)
    let policy = BehavioralPolicy {
        name: "Security Escalation",
        conditions: vec![PolicyCondition::MinVerificationCount { threshold: 3, for_amount_gte: 1000 }],
        risk_tier: RiskTier::High, // Requires t=5
    };
    let engine = PolicyEngine::new(vec![policy]);
    let prover = UnifiedProver::new(engine);

    // 2. Log events (3 verifications + 1 large signature request)
    let mut events = Vec::new();
    events.push(logger.log_event(&agent_id, 0x02, b"v1", 1000).unwrap());
    events.push(logger.log_event(&agent_id, 0x02, b"v2", 1000).unwrap());
    events.push(logger.log_event(&agent_id, 0x02, b"v3", 1000).unwrap());
    let sig_req = logger.log_event(&agent_id, 0x01, b"transfer $1500", 1500).unwrap();
    events.push(sig_req.clone());

    let root = logger.get_current_root();
    let msg_hash = [0xBB; 32];
    let (_, _, pk_root) = setup(10); // 10 validators

    // 3. Generate Nova Proof with t=5 (Matches High risk)
    let params = gen_unified_params();
    let (pk, vk) = setup_unified_keys(&params).unwrap();
    
    let proof = prover.prove_unified(
        &params,
        &pk,
        &events,
        root,
        msg_hash,
        pk_root,
        5, // threshold_t = 5
    ).expect("Proving failed");

    // 4. Verify Unified Proof
    let valid = UnifiedVerifier::verify_unified(
        &params,
        &vk,
        &proof,
        root,
        2, // risk_tier=2 (High)
        pk_root,
        5, // t=5
    ).unwrap();
    
    assert!(valid);
}

#[test]
#[cfg(feature = "nova")]
fn test_tc_3_2_threshold_mismatch_fails() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xAA; 32];
    
    let policy = BehavioralPolicy {
        name: "High Escalation",
        conditions: vec![],
        risk_tier: RiskTier::High, // Requires t=5
    };
    let engine = PolicyEngine::new(vec![policy]);
    let prover = UnifiedProver::new(engine);

    let mut events = Vec::new();
    events.push(logger.log_event(&agent_id, 0x01, b"msg", 1000).unwrap());

    let root = logger.get_current_root();
    let msg_hash = [0xBB; 32];
    let (_, _, pk_root) = setup(10);

    let params = gen_unified_params();
    let (pk, _) = setup_unified_keys(&params).unwrap();
    
    // Attempting to prove with t=3 for a High risk tier should fail at the circuit constraint
    let proof_res = prover.prove_unified(
        &params,
        &pk,
        &events,
        root,
        msg_hash,
        pk_root,
        3, // t=3 IS NOT >= 5
    );

    assert!(proof_res.is_err(), "Circuit should reject invalid threshold mapping");
}

#[test]
#[cfg(feature = "nova")]
fn test_tc_3_3_valid_low_risk_threshold_2() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xAA; 32];
    
    let policy = BehavioralPolicy {
        name: "Small Transfer",
        conditions: vec![],
        risk_tier: RiskTier::Low, // Requires t=2
    };
    let engine = PolicyEngine::new(vec![policy]);
    let prover = UnifiedProver::new(engine);

    let mut events = Vec::new();
    events.push(logger.log_event(&agent_id, 0x01, b"small", 50).unwrap());

    let root = logger.get_current_root();
    let params = gen_unified_params();
    let (pk, vk) = setup_unified_keys(&params).unwrap();
    
    let proof = prover.prove_unified(&params, &pk, &events, root, [0;32], [0;32], 2).unwrap();
    let valid = UnifiedVerifier::verify_unified(&params, &vk, &proof, root, 0, [0;32], 2).unwrap();
    assert!(valid);
}

#[test]
#[cfg(feature = "nova")]
fn test_tc_3_4_policy_violation_fails() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xAA; 32];
    
    let policy = BehavioralPolicy {
        name: "Cooldown Violation",
        conditions: vec![PolicyCondition::MinTimeBetweenActions { action_type: 0x01, min_seconds: 600 }],
        risk_tier: RiskTier::Low,
    };
    let engine = PolicyEngine::new(vec![policy]);
    let prover = UnifiedProver::new(engine);

    let mut events = Vec::new();
    // Two transfers too close together
    events.push(logger.log_event(&agent_id, 0x01, b"t1", 1000).unwrap());
    events.push(logger.log_event(&agent_id, 0x01, b"t2", 1010).unwrap());

    let root = logger.get_current_root();
    let params = gen_unified_params();
    let (pk, _) = setup_unified_keys(&params).unwrap();

    let res = prover.prove_unified(&params, &pk, &events, root, [0;32], [0;32], 2);
    assert!(res.is_err(), "Proving should fail due to policy violation");
}

#[test]
#[cfg(feature = "nova")]
fn test_tc_3_5_outflow_limit_fails() {
    let mut logger = CausalEventLogger::new([0u8; 32]);
    let agent_id = [0xAA; 32];
    
    let policy = BehavioralPolicy {
        name: "Outflow Limit",
        conditions: vec![PolicyCondition::MaxDailyOutflow { max_amount: 1000, currency: 1 }],
        risk_tier: RiskTier::Medium,
    };
    let engine = PolicyEngine::new(vec![policy]);
    let prover = UnifiedProver::new(engine);

    let mut events = Vec::new();
    events.push(logger.log_event(&agent_id, 0x01, b"large", 1500).unwrap());

    let root = logger.get_current_root();
    let params = gen_unified_params();
    let (pk, _) = setup_unified_keys(&params).unwrap();

    let res = prover.prove_unified(&params, &pk, &events, root, [0;32], [0;32], 3);
    assert!(res.is_err(), "Proving should fail due to outflow limit violation");
}
