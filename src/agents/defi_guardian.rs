use std::time::Duration;
use std::sync::Arc;
use crate::runtime::{CausalGuardRuntime, ActionProposal, RiskContext, ActionStatus};
use tokio::sync::Mutex;

pub struct DeFiGuardianAgent {
    runtime: Arc<Mutex<CausalGuardRuntime>>,
    agent_id: [u8; 32],
    monitoring_interval: Duration,
}

impl DeFiGuardianAgent {
    pub fn new(runtime: Arc<Mutex<CausalGuardRuntime>>, agent_id: [u8; 32]) -> Self {
        Self {
            runtime,
            agent_id,
            monitoring_interval: Duration::from_secs(10),
        }
    }

    /// Main loop: monitor opportunities → propose actions → track status
    pub async fn run(&mut self) -> Result<(), String> {
        println!("🚀 DeFi Guardian Agent starting (Agent ID: {:?})", self.agent_id);
        
        loop {
            // 1. Monitor market conditions (simulated)
            let opportunity = self.monitor_dex_arbitrage().await;
            
            println!("🔍 Found opportunity: {} USD", opportunity.value_usd);

            // 2. Propose action THROUGH runtime (never direct signing)
            let proposal = ActionProposal {
                agent_id: self.agent_id,
                action_type: 0x02, // SWAP
                payload: vec![0xDE, 0xAD, 0xBE, 0xEF], // Mock payload
                risk_context: RiskContext {
                    estimated_value_usd: Some(opportunity.value_usd),
                    destination_chain: Some(1), // Solana
                    is_cross_chain: false,
                },
            };

            let mut runtime_guard: tokio::sync::MutexGuard<CausalGuardRuntime> = self.runtime.lock().await;
            let current_time_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;

            match runtime_guard.propose_action(proposal, current_time_ms) {
                Ok(action_id) => {
                    println!("✅ Proposed action: {:?}", action_id);
                    // 3. Track to completion
                    drop(runtime_guard); // Release lock while waiting/polling
                    self.track_to_completion(action_id).await;
                },
                Err(e) => {
                    println!("⚠️ Proposal failed: {:?}", e);
                }
            }

            tokio::time::sleep(self.monitoring_interval).await;
        }
    }

    async fn monitor_dex_arbitrage(&self) -> Opportunity {
        // Simulated monitoring
        Opportunity { value_usd: 500, is_cross_chain: false, destination_chain: Some(1) }
    }

    async fn track_to_completion(&self, action_id: [u8; 32]) {
        loop {
            let runtime_guard: tokio::sync::MutexGuard<CausalGuardRuntime> = self.runtime.lock().await;
            let status = runtime_guard.get_action_status(&action_id);
            println!("⏳ Action Status: {:?}", status);

            match status {
                ActionStatus::Confirmed | ActionStatus::Rejected | ActionStatus::Failed(_) => {
                    println!("🏁 Action reached terminal state: {:?}", status);
                    break;
                },
                _ => {
                    drop(runtime_guard);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
}

pub struct Opportunity {
    pub value_usd: u64,
    pub is_cross_chain: bool,
    pub destination_chain: Option<u16>,
}
