//! Live integration tests for Solana Devnet adapter.
//!
//! These tests require network access and a funded Devnet wallet.
//! They skip automatically if the required environment variables are missing.

#![cfg(feature = "solana-devnet")]

use pq_aggregate::adapters::solana::{
    TransferFlow, FaucetClient, Pubkey, WalletManager,
};

use pq_aggregate::core::keygen::setup;

use pq_aggregate::core::signing::aggregate_sign;
use pq_aggregate::core::aggregation::aggregate_proofs;
use std::env;

#[tokio::test]
async fn test_solana_devnet_integration_suite() {
    // 0. Check for environment variables
    if env::var("SOLANA_FEE_PAYER_KEY").is_err() {
        println!("Skipping live Devnet tests: SOLANA_FEE_PAYER_KEY not set.");
        return;
    }

    let mut flow = TransferFlow::from_env().expect("Failed to create transfer flow");
    let recipient = Pubkey::new([0xDE; 32]);
    
    // 1. Funding Check
    println!("Checking wallet funds...");
    flow.ensure_funded(100_000_000).await.expect("Funding failed");
    let balance = flow.adapter().get_sol_balance().await.expect("Failed to get balance");
    println!("Wallet balance: {} lamports", balance);

    // --- TC-2.1: Low-value transfer succeeds ---
    println!("Executing TC-2.1: Low-value transfer...");
    let result_low = flow.execute_low_value_transfer(&recipient, 50).await; // $0.50
    assert!(result_low.signature.is_some(), "Low-value transfer should succeed: {:?}", result_low.error);
    println!("TC-2.1 Success: sig={:?}", result_low.signature);

    // --- TC-2.2: High-value transfer rejected without verifications ---
    println!("Executing TC-2.2: High-value transfer (blocked)...");
    let result_high_blocked = flow.execute_low_value_transfer(&recipient, 150000).await; // $1,500
    assert!(result_high_blocked.signature.is_none(), "High-value transfer should be blocked by policy");
    assert!(result_high_blocked.error.as_ref().unwrap().contains("requires 3 address verifications"));
    println!("TC-2.2 Success: Transfer correctly blocked");

    // --- TC-2.3: High-value transfer succeeds after 3 verifications ---
    println!("Executing TC-2.3: High-value transfer (with proof)...");
    
    // a. Prepare threshold proof
    let (sks, pks, pk_root) = setup(10);
    let msg = b"transfer_proof_payload";
    let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 3);
    let zkp = aggregate_proofs(sigs, proofs, pk_root, msg, &pks).expect("Proof generation failed");

    // b. Execute flow with verifications and proof
    let verifications = vec![
        Pubkey::new([0x01; 32]),
        Pubkey::new([0x02; 32]),
        Pubkey::new([0x03; 32]),
    ];
    
    let result_high_success = flow.execute_high_value_transfer(
        &recipient, 
        150000, 
        &verifications, 
        &zkp
    ).await;
    
    assert!(result_high_success.signature.is_some(), "High-value transfer should succeed with proof: {:?}", result_high_success.error);
    println!("TC-2.3 Success: sig={:?}", result_high_success.signature);

    // --- TC-2.6: Network error and audit log persistence ---
    let audit_log = flow.adapter().get_audit_log();
    assert!(audit_log.len() >= 3, "Audit log should track all attempts");
    println!("Audit log entries: {}", audit_log.len());
}

#[tokio::test]
async fn test_faucet_airdrop_limit() {
    if env::var("SOLANA_FEE_PAYER_KEY").is_err() { return; }
    
    let faucet = FaucetClient::devnet();
    let wallet = WalletManager::from_env().unwrap();
    
    // Requesting a small amount should succeed
    let sig = faucet.request_sol_airdrop(&wallet.fee_payer_pubkey(), Some(100_000)).await;
    assert!(sig.is_ok(), "Small airdrop should succeed");
}
