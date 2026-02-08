//! Cross-Chain Bridge Integration Tests.
//!
//! Verifies the full flow: Solana (Lock) -> Relayer -> Ethereum (Mint).

#![cfg(all(feature = "solana-devnet", feature = "ethereum-sepolia"))]

use std::sync::Arc;
use std::str::FromStr;

use pq_aggregate::adapters::solana::{SolanaDevnetAdapter, WalletManager as SolWallet, Keypair as SolKeypair};
use pq_aggregate::adapters::ethereum::EthereumAdapter;
use pq_aggregate::adapters::bridge::BridgeRelayer;
use pq_aggregate::types::ZKSNARKProof;
use ethers::types::Address;

// Mock setup helper
async fn setup_bridge() -> BridgeRelayer {
    // Solana Setup
    let sol_kp = SolKeypair::new();
    let sol_wallet = SolWallet::new(sol_kp, None);
    let sol_adapter = Arc::new(SolanaDevnetAdapter::new(sol_wallet).unwrap());

    // Ethereum Setup (Mocking env vars for test if not present)
    if std::env::var("ETHEREUM_PRIVATE_KEY").is_err() {
        std::env::set_var("ETHEREUM_PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"); // Anvil/Hardhat default 0
        std::env::set_var("ETHEREUM_RPC_URL", "http://localhost:8545");
    }
    
    // Attempt real connection, fall back to mock or skip if offline
    let eth_adapter = match EthereumAdapter::from_env() {
        Ok(a) => Arc::new(a),
        Err(_) => panic!("Ethereum adapter init failed"),
    };

    let verifier_address = Address::from_str("0x0000000000000000000000000000000000000000").unwrap(); // Mock address

    BridgeRelayer::new(sol_adapter, eth_adapter, verifier_address)
}

#[tokio::test]
async fn test_tc_3_6_full_bridge_flow() {
    // Skip if actual RPC is not reachable (to avoid CI failure)
    if std::env::var("LIVE_CROSS_CHAIN_TEST").is_err() {
        println!("Skipping live cross-chain test (LIVE_CROSS_CHAIN_TEST not set)");
        return;
    }

    let relayer = setup_bridge().await;

    // 1. Simulate Solana "Lock" event (High Value $1,500)
    // In reality, we'd call solana_adapter.transfer_usdc_with_policy()
    // For this test, we construct the proof manually as if it came from the runtime.
    
    let proof = ZKSNARKProof::new(vec![0u8; 100], 5, [0u8; 32]); // t=5 compliant
    let amount_cents = 150000; // $1,500.00
    let recipient = Address::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();

    // 2. Relay to Ethereum
    let result = relayer.relay_transfer(&proof, amount_cents, recipient).await;
    
    assert!(result.is_ok(), "Bridge relay failed: {:?}", result.err());
}

#[tokio::test]
async fn test_tc_3_7_forgery_rejection() {
    let relayer = setup_bridge().await;
    
    // Create a proof with insufficient signatures (t=2) for a High Value transfer
    let weak_proof = ZKSNARKProof::new(vec![0u8; 100], 2, [0u8; 32]);
    let amount_cents = 150000;
    let recipient = Address::random();

    let result = relayer.relay_transfer(&weak_proof, amount_cents, recipient).await;
    
    // Relayer itself checks policy before submitting, so it should fail early
    assert!(result.is_err());
    
    match result {
        Err(e) => assert!(format!("{}", e).contains("High Risk consensus")),
        _ => panic!("Expected policy violation error"),
    }
}
