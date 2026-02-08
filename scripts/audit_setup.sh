#!/bin/bash
set -e

echo "Starting Audit Setup Pipeline..."

# 1. Clean Build
echo "[1/5] Building from clean state..."
cargo clean
cargo build --release --features "runtime solana-devnet ethereum-sepolia"

# 2. Deterministic Wallet Generation
echo "[2/5] Generating deterministic audit wallets..."
# Using a fixed mnemonic for reproducibility (DO NOT USE IN PROD)
AUDIT_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
cargo run --bin wallet-gen -- --mnemonic "$AUDIT_MNEMONIC" --output "audit_keystore.enc"

# 3. Environment Setup (Mocking Funding)
echo "[3/5] Setting up environment..."
export ETHEREUM_RPC_URL="https://rpc.sepolia.org" # Default, can be overridden
export SOLANA_RPC_URL="https://api.devnet.solana.com"

# 4. Cross-Chain Verification
echo "[4/5] Running Cross-Chain Bridge Tests..."
# We use --nocapture to see output
cargo test --features "runtime solana-devnet ethereum-sepolia" --test cross_chain_bridge_tests -- --nocapture

# 5. Reporting
echo "[5/5] Pipeline Complete. System is ready for audit."
echo "Artifacts:"
echo "- Keystore: audit_keystore.enc"
echo "- Binaries: target/release/"
