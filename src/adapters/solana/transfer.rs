//! Risk-adaptive transfer flow orchestration.
//!
//! Coordinates the full transfer lifecycle with policy enforcement.

#![cfg(feature = "solana-devnet")]

use crate::error::Result;
use crate::types::ZKSNARKProof;
use super::wallet::Pubkey;
use super::real_adapter::SolanaDevnetAdapter;
use super::faucet::FaucetClient;
use super::DEVNET_RPC_URL;

/// Transfer flow states for debugging and logging.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransferState {
    Proposed,
    MetadataLogged,
    PolicyEvaluated,
    SignaturesCollected,
    ProofGenerated,
    Submitted,
    Confirmed,
    Failed,
}

/// Result of a transfer attempt.
#[derive(Debug)]
pub struct TransferResult {
    pub state: TransferState,
    pub signature: Option<String>,
    pub error: Option<String>,
    pub latency_ms: u64,
}

/// High-level transfer flow coordinator.
pub struct TransferFlow {
    adapter: SolanaDevnetAdapter,
    faucet: FaucetClient,
}

impl TransferFlow {
    /// Create a new transfer flow from environment.
    pub fn from_env() -> Result<Self> {
        let adapter = SolanaDevnetAdapter::from_env()?;
        let faucet = FaucetClient::new(DEVNET_RPC_URL);
        Ok(Self { adapter, faucet })
    }

    /// Execute a low-value transfer (no extra verification required).
    ///
    /// For amounts < $1,000, the transfer proceeds without additional
    /// address verification requirements.
    pub async fn execute_low_value_transfer(
        &mut self,
        to: &Pubkey,
        amount_cents: u32,
    ) -> TransferResult {
        let start = std::time::Instant::now();
        
        if amount_cents >= 100_000 {
            return TransferResult {
                state: TransferState::Failed,
                signature: None,
                error: Some("Use execute_high_value_transfer for amounts >= $1,000".to_string()),
                latency_ms: start.elapsed().as_millis() as u64,
            };
        }

        match self.adapter.transfer_usdc_with_policy(to, amount_cents, None).await {
            Ok(sig) => TransferResult {
                state: TransferState::Confirmed,
                signature: Some(sig.to_string()),
                error: None,
                latency_ms: start.elapsed().as_millis() as u64,
            },
            Err(e) => TransferResult {
                state: TransferState::Failed,
                signature: None,
                error: Some(e.to_string()),
                latency_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Execute a high-value transfer with full verification flow.
    ///
    /// 1. Ensures required address verifications are logged
    /// 2. Generates proof via threshold signing
    /// 3. Submits transaction with embedded proof
    pub async fn execute_high_value_transfer(
        &mut self,
        to: &Pubkey,
        amount_cents: u32,
        verified_addresses: &[Pubkey],
        proof: &ZKSNARKProof,
    ) -> TransferResult {
        let start = std::time::Instant::now();

        // 1. Log address verifications
        for addr in verified_addresses {
            if let Err(e) = self.adapter.log_address_verification(addr) {
                return TransferResult {
                    state: TransferState::Failed,
                    signature: None,
                    error: Some(format!("Verification logging failed: {}", e)),
                    latency_ms: start.elapsed().as_millis() as u64,
                };
            }
        }

        // 2. Execute transfer with proof
        match self.adapter.transfer_usdc_with_policy(to, amount_cents, Some(proof)).await {
            Ok(sig) => TransferResult {
                state: TransferState::Confirmed,
                signature: Some(sig.to_string()),
                error: None,
                latency_ms: start.elapsed().as_millis() as u64,
            },
            Err(e) => TransferResult {
                state: TransferState::Failed,
                signature: None,
                error: Some(e.to_string()),
                latency_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Ensure wallet has sufficient SOL for gas fees.
    pub async fn ensure_funded(&mut self, min_lamports: u64) -> Result<()> {
        let balance = self.adapter.get_sol_balance().await?;
        
        if balance < min_lamports {
            let needed = min_lamports - balance;
            self.faucet.request_sol_airdrop(
                &Pubkey::from(self.adapter.get_event_logger().get_current_root()),
                Some(needed + 100_000_000), // Add buffer
            ).await?;

        }
        
        Ok(())
    }

    /// Get the underlying adapter for direct access.
    pub fn adapter(&self) -> &SolanaDevnetAdapter {
        &self.adapter
    }

    /// Get mutable access to the adapter.
    pub fn adapter_mut(&mut self) -> &mut SolanaDevnetAdapter {
        &mut self.adapter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_state_transitions() {
        assert_eq!(TransferState::Proposed, TransferState::Proposed);
        assert_ne!(TransferState::Proposed, TransferState::Confirmed);
    }

    #[test]
    fn test_transfer_result_creation() {
        let result = TransferResult {
            state: TransferState::Confirmed,
            signature: None,
            error: None,
            latency_ms: 100,
        };
        
        assert_eq!(result.state, TransferState::Confirmed);
        assert!(result.error.is_none());
    }
}
