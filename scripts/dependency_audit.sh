#!/bin/bash
set -e

echo "Running Dependency Audit..."

# Check if cargo-audit is installed
if ! command -v cargo-audit &> /dev/null; then
    echo "cargo-audit not found. Installing..."
    cargo install cargo-audit
fi

# Run audit and output to CSV (simulated extraction from JSON if needed, but JSON is standard)
echo "Generating JSON report..."
cargo audit --json > artifacts/DEPENDENCY_AUDIT.json

# Simple CSV conversion
echo "Package,Version,ID,Description" > artifacts/DEPENDENCY_AUDIT.csv
# Uses jq to parse json if available, else just leaves json
if command -v jq &> /dev/null; then
    jq -r '.vulnerabilities[] | [.package.name, .package.version, .advisory.id, .advisory.description] | @csv' artifacts/DEPENDENCY_AUDIT.json >> artifacts/DEPENDENCY_AUDIT.csv
else
    echo "jq not found. CSV generation skipped (JSON available)."
fi

echo "Audit complete. Report at artifacts/DEPENDENCY_AUDIT.json"
