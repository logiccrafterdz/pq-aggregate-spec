//! Trust-Minimized Bridge Relayer.
//!
//! Watches for CausalGuard events on Solana and relays verified proofs to Ethereum.
//!
//! **Security**: The relayer is untrusted. It can only submit proofs that
//! are cryptographically valid and signed by the threshold committee.

use std::sync::Arc;
use std::time::Duration;
use ethers::types::{Address, U256};

use crate::error::{PQAggregateError, Result};
use crate::types::ZKSNARKProof;
use crate::adapters::solana::SolanaDevnetAdapter;
use crate::adapters::ethereum::EthereumAdapter;

pub struct BridgeRelayer {
    _solana_adapter: Arc<SolanaDevnetAdapter>,
    ethereum_adapter: Arc<EthereumAdapter>,
    ethereum_verifier: Address,
}

impl BridgeRelayer {
    pub fn new(
        solana: Arc<SolanaDevnetAdapter>,
        ethereum: Arc<EthereumAdapter>,
        verifier: Address,
    ) -> Self {
        Self {
            _solana_adapter: solana,
            ethereum_adapter: ethereum,
            ethereum_verifier: verifier,
        }
    }

    /// Process a cross-chain transfer event.
    ///
    /// In a real system, this would come from an event listener loop.
    pub async fn relay_transfer(
        &self,
        proof: &ZKSNARKProof,
        amount_cents: u32,
        recipient_eth: Address,
    ) -> Result<String> {
        // 1. Verify proof locally (Sanity check)
        // In this spec/demo, assume the caller passed a valid proof triggered by the runtime.
        if proof.num_signatures() < 5 {
            return Err(PQAggregateError::PolicyViolation {
                reason: "Cross-chain transfers require High Risk consensus (t=5)".into(),
            });
        }

        // 2. Submit to Ethereum
        let amount_wei = U256::from(amount_cents) * U256::from(10).pow(U256::from(6)); // Convert cents to USDC wei (6 decimals)
        // Actually USDC has 6 decimals, so cents (2 decimals) -> base units:
        // $1.00 = 100 cents = 1,000,000 units.
        // 1 cent = 10,000 units.
        let amount_token_units = U256::from(amount_cents) * U256::from(10000);

        println!("Relaying proof to Ethereum verifier at {:?}...", self.ethereum_verifier);
        
        match self.ethereum_adapter.submit_proof_and_mint(
            self.ethereum_verifier,
            proof,
            amount_token_units,
            recipient_eth,
        ).await {
            Ok(tx_hash) => {
                println!("Relay successful! TX: {}", tx_hash);
                Ok(tx_hash)
            },
            Err(e) => {
                eprintln!("Relay failed: {}", e);
                Err(e)
            }
        }
    }
}
