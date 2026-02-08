#!/bin/bash
set -e

echo "Generating Test Coverage Report..."

# Check if llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo "cargo-llvm-cov not found. Installing..."
    cargo install cargo-llvm-cov
fi

# Run coverage
cargo llvm-cov --html --output-dir target/llvm-cov --features "runtime solana-devnet ethereum-sepolia"

echo "Coverage report generated at target/llvm-cov/html/index.html"
