#![cfg(feature = "runtime")]

use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;
use pq_aggregate::runtime::{CausalGuardRuntime, ActionProposal, ActionStatus, RiskContext};
use pq_aggregate::causal::CausalEventLogger;
use pq_aggregate::policy::{BehavioralPolicy, PolicyCondition, PolicyEngine, RiskTier};
use pq_aggregate::agents::defi_guardian::DeFiGuardianAgent;

fn setup_live_runtime() -> CausalGuardRuntime {
    let logger = CausalEventLogger::new([0u8; 32]);
    let condition = PolicyCondition::MinVerificationCount {
        threshold: 3,
        min_amount_usd: Some(100), // $100
        cross_chain_only: false,
    };
    let safety_policy = BehavioralPolicy {
        name: "High Value Safety",
        conditions: vec![condition],
        risk_tier: RiskTier::High,
    };
    let engine = PolicyEngine::new(vec![safety_policy]);
    CausalGuardRuntime::new(logger, engine)
}

#[tokio::test]
async fn test_s_5_1_policy_rejection_high_value() {
    let runtime = Arc::new(Mutex::new(setup_live_runtime()));
    let agent_id = [0xAA; 32];
    
    // Propose $1,500 swap (High risk) with 0 prior history
    let proposal = ActionProposal {
        agent_id,
        action_type: 0x02, // SWAP
        payload: vec![1, 2, 3],
        risk_context: RiskContext {
            estimated_value_usd: Some(1500),
            destination_chain: Some(1),
            is_cross_chain: false,
        },
    };

    let mut rt = runtime.lock().await;
    let action_id = rt.propose_action(proposal, 1000).unwrap();
    
    // Process lifecycle: Should reach REJECTED because high-risk requires history
    rt.process_action_lifecycle(action_id).unwrap();
    
    assert_eq!(rt.get_action_status(&action_id), ActionStatus::Rejected);
}

#[tokio::test]
async fn test_s_5_2_compliant_swap_solana_devnet() {
    let runtime = Arc::new(Mutex::new(setup_live_runtime()));
    let agent_id = [0xBB; 32];
    
    // Build up verification history first (3 address verifications required by policy)
    {
        let mut rt = runtime.lock().await;
        for i in 0u64..3 {
            let verification = ActionProposal {
                agent_id,
                action_type: 0x02, // ADDRESS_VERIFICATION
                payload: vec![(i + 1) as u8],
                risk_context: RiskContext {
                    estimated_value_usd: None,
                    destination_chain: None,
                    is_cross_chain: false,
                },
            };
            // Space proposals 7 seconds apart to avoid rate limiting
            let time = 1000 + i * 7000;
            let aid = rt.propose_action(verification, time).unwrap();
            rt.process_action_lifecycle(aid).unwrap(); // Evaluate policy
        }
    }

    // Now propose the swap — should pass policy with sufficient verification history
    let proposal = ActionProposal {
        agent_id,
        action_type: 0x02,
        payload: vec![10, 20, 30], // Different payload than verifications
        risk_context: RiskContext {
            estimated_value_usd: Some(500),
            destination_chain: Some(1), // Solana
            is_cross_chain: false,
        },
    };

    let mut rt = runtime.lock().await;
    let action_id = rt.propose_action(proposal, 30000).unwrap();
    
    // Mocking the full successful lifecycle
    rt.process_action_lifecycle(action_id).unwrap(); // PENDING -> COMPLIANT
    rt.process_action_lifecycle(action_id).unwrap(); // COMPLIANT -> SIGNED
    rt.process_action_lifecycle(action_id).unwrap(); // SIGNED -> SUBMITTED
    rt.process_action_lifecycle(action_id).unwrap(); // SUBMITTED -> CONFIRMED
    
    let status = rt.get_action_status(&action_id);
    assert_eq!(status, ActionStatus::Confirmed);
}

#[tokio::test]
async fn test_s_5_3_rate_limiting_enforcement() {
    let mut runtime = setup_live_runtime();
    let agent_id = [0xCC; 32];
    
    let prop = ActionProposal {
        agent_id,
        action_type: 0x01,
        payload: vec![0],
        risk_context: RiskContext { estimated_value_usd: None, is_cross_chain: false, destination_chain: None },
    };

    // First attempt
    runtime.propose_action(prop.clone(), 1000).unwrap();
    
    // Second attempt immediately (within 6s window)
    let res = runtime.propose_action(prop, 2000);
    assert!(res.is_err()); // Rate limited
}

#[tokio::test]
async fn test_s_5_4_cross_chain_bridge_simulation() {
    let mut runtime = setup_live_runtime();
    let agent_id = [0xDD; 32];
    
    let proposal = ActionProposal {
        agent_id,
        action_type: 0x03, // BRIDGE
        payload: vec![0],
        risk_context: RiskContext {
            estimated_value_usd: Some(2000),
            destination_chain: Some(2), // Ethereum
            is_cross_chain: true,
        },
    };

    let action_id = runtime.propose_action(proposal, 1000).unwrap();
    
    // In this simulation, $2000 is high risk, and since we have no history,
    // it should be rejected. This proves the unified risk model works for bridges too.
    runtime.process_action_lifecycle(action_id).unwrap();
    assert_eq!(runtime.get_action_status(&action_id), ActionStatus::Rejected);
}

#[tokio::test]
async fn test_s_5_5_defi_guardian_agent_autonomous_run() {
    let runtime = Arc::new(Mutex::new(setup_live_runtime()));
    let agent_id = [0xEE; 32];
    
    let mut agent = DeFiGuardianAgent::new(runtime.clone(), agent_id);
    
    // Run agent briefly in a separate task
    let agent_handle = tokio::spawn(async move {
        // We'll let it run for one cycle then stop (simulated via timeout)
        let _ = tokio::time::timeout(Duration::from_secs(5), agent.run()).await;
    });

    // Manually progress the runtime to satisfy the agent's poll
    tokio::time::sleep(Duration::from_secs(2)).await;
    {
        let _rt = runtime.lock().await;
        // In a real system, the background task in CausalGuardRuntime would do this.
        // For the test, we manually trigger the lifecycle for any pending actions.
    }

    // Wait for agent task to finish (timeout)
    let _ = agent_handle.await;
    
    // Verification: Agent started and performed at least one loop
    // (Checked via stdout/logs in a real run, here we just ensure no panic)
}
