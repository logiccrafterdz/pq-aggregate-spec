# CausalGuard Solana Devnet Integration Guide

This guide describes how to use the production-grade Solana adapter to execute USDC transfers with risk-adaptive policy enforcement.

## 1. Setup

### Environment Variables
Set the following variables in your environment:

```bash
# Fee payer (Base58 private key)
export SOLANA_FEE_PAYER_KEY="your_fee_payer_key"

# Signer (Optional, defaults to fee payer)
export SOLANA_SIGNER_KEY="your_signer_key"
```

### Funding
Fund your wallet via the Devnet faucet:
```bash
./scripts/fund_devnet_wallet.sh
```

## 2. Risk-Adaptive Policy Flow

CausalGuard enforces different security policies based on transaction value:

| Amount | Policy | Requirement |
|--------|--------|-------------|
| < $1,000 | Fast-path | Immediate execution |
| ≥ $1,000 | Secured-path | 3 address verifications + PQ-Proof |

### Example: Low-Value Transfer ($50 USDC)
```rust
let mut flow = TransferFlow::from_env()?;
let to = Pubkey::from_str("RecipientPubKey...")?;

let result = flow.execute_low_value_transfer(&to, 5000).await;
println!("Transfer Sig: {:?}", result.signature);
```

### Example: High-Value Transfer ($1,500 USDC)
```rust
let mut flow = TransferFlow::from_env()?;
let to = Pubkey::from_str("RecipientPubKey...")?;

// 1. Threshold signatures collected from 3/10 agents
let proof = generate_threshold_proof(amount, to)?;

// 2. Verified addresses (e.g. from MFA or Hardware Wallet)
let verifications = vec![addr1, addr2, addr3];

// 3. Execute with proof embedding
let result = flow.execute_high_value_transfer(&to, 150000, &verifications, &proof).await;
```

## 3. On-Chain Verification

The Anchor program is located in `programs/causalguard_verifier`.

### Deployment
```bash
anchor build
anchor deploy --provider.cluster devnet
```

### Verification Logic
The verifier checks:
1. Proof structure compliance.
2. Signatures meet the required threshold (t=3).
3. Merkle root matches the authorized `PKroot`.

## 4. Testing
Run the live integration suite:
```bash
cargo test --features solana-devnet --test solana_devnet_tests
```
