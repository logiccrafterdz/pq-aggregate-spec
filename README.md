# PQ-Aggregate

**Post-quantum threshold signatures via independent ML-DSA key aggregation.**
---

A `no_std`-compatible Rust implementation targeting Solana, Ethereum, and Cosmos via pluggable adapters. Aggregates `t`-of-`n` ML-DSA-65 signatures into compact proofs with Merkle-based public key aggregation.

## Features

- **Independent Keypairs**: No secret sharing required
- **Merkle Aggregation**: Compact public key representation
- **Nova IVC (v0.2.0)**: O(1) verification time via recursive folding
- **Blockchain Adapters**: Native support for **Solana**, **Ethereum/EVM**, and **Cosmos/IBC**
- **Proof Compression**: Optional DEFLATE compression for high-density storage
- **`no_std` Compatible**: Works in embedded and WASM environments

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
pq-aggregate = { git = "https://github.com/LogicCrafterDz/pq-aggregate-spec", features = ["nova", "compression"] }
```

## Blockchain Support

| Chain | Adapter | Features |
| :--- | :--- | :--- |
| **Solana** | `SolanaAdapter` | Instruction gen, PDA derivation |
| **Ethereum** | `EthereumAdapter` | ABI-compatible calldata, Solidity interface |
| **Cosmos** | `CosmosAdapter` | Protobuf encoding, IBC packet wrapping |
