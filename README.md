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

## Architectural Overview

PQ-Aggregate provides a multi-layered cryptographic security system designed for high-performance blockchain environments:

### Layered Proof System
1.  **Layer 0 (ML-DSA)**: Individual validators generate post-quantum signatures.
2.  **Layer 1 (NovaSNARK)**: Multiple signatures are folded into a single O(1) proof using recursive SNARKs.
3.  **Layer 2 (Super-Proofs)**: Multiple SNARK batches are squashed into "Super-Proofs" for massive throughput (e.g., L2 rollups).

###  Blockchain Interoperability
The **Bridge Hub** allows proofs to travel between chains:
- **Proof Translation**: Convert Ethereum proofs to Solana format without re-signing.
- **Provenance Verification**: Verify that a proof originated from a specific source chain.

### Security Gadgets
- **Adaptive Thresholds**: Dynamic $t$-of-$n$ logic enforced at the verifier/circuit boundary.
- **Validator Rotation**: Secure Merkle root transitions authorized by the outgoing committee.
