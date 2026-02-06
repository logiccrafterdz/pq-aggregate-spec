# CausalGuard Live Demo Guide 🚀

This guide provides step-by-step instructions to replicate the end-to-end security demo of CausalGuard, featuring an autonomous AI agent interacting with live blockchain testnets.

## Prerequisites

1. **Rust Toolchain**: Install via `rustup` (v1.80+ required).
2. **Environment Variables**: Create a `.env` file in the project root:
   ```bash
   SOLANA_PRIVATE_KEY="your_solana_devnet_key"
   ETH_PRIVATE_KEY="your_eth_sepolia_key"
   COSMOS_PRIVATE_KEY="your_cosmos_juno_key"
   LOG_LEVEL="info"
   ```
3. **Wallet Funding**:
   - **Solana Devnet**: Use [Solana Faucet](https://faucet.solana.com/).
   - **Ethereum Sepolia**: Use [Sepolia PoW Faucet](https://sepolia-faucet.pk910.de/).
   - **Cosmos Juno**: Use the official Juno testnet discord faucet.

## Execution Steps

### 1. Build the Secure Runtime
Compile the project with the `nova` feature enabled for full cryptographic verification:
```bash
cargo build --release --features "nova compression"
```

### 2. Run the DeFi Guardian Demo
Execute the reference agent simulation:
```bash
cargo run --example defi_guardian_demo --features "nova"
```

### 3. Observe Behavioral Enforcement
The demo illustrates three core scenarios:

| Scenario | Agent Goal | CausalGuard Outcome |
|----------|------------|---------------------|
| **Compliant Swap** | Swap $500 USDC | **APPROVED** → Submitted to Solana Devnet |
| **High-Risk Rejection** | Swap $1,500 USDC | **REJECTED** → Policy requires 3 verifications |
| **Rate Limiting** | Spam proposals | **REJECTED** → Nonce protection triggered |

## Technical Verification

### On-Chain Proofs
Every successful transaction result includes a `tx_hash`. You can verify the proof acceptance on any block explorer:
- **Solana Devnet**: https://explorer.solana.com/?cluster=devnet
- **Sepolia**: https://sepolia.etherscan.io/

### Causal Logs
The agent's terminal will output `ActionId` and the corresponding `CausalEvent` hashes. These events are cryptographically linked to the on-chain proof.

## Troubleshooting

- **Submission Failed**: Ensure your `.env` keys have sufficient testnet balance for gas.
- **Nonce Error**: If the agent is restarted rapidly, the on-chain nonce might be out of sync. Wait 30s or use a fresh account.

---
**Security Note**: Never use mainnet private keys for this demo. CausalGuard is currently in its reference implementation phase.
