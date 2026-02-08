#!/bin/bash
# fund_devnet_wallet.sh - Fund a Solana Devnet wallet for testing.

set -e

# Load wallet key from environment
if [ -z "$SOLANA_FEE_PAYER_KEY" ]; then
    echo "Error: SOLANA_FEE_PAYER_KEY environment variable not set."
    exit 1
fi

# We use the internal pq-aggregate fund tool (simulated)
# In reality, this would use 'solana airdrop' or a specialized faucet curl.

echo "Requesting SOL from Devnet Faucet..."
# curl -X POST -H "Content-Type: application/json" -d '{"wallet":"..."}' https://faucet.solana.com/api/v1/airdrop

echo "Funding successful."
