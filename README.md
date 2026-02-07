# PQ-Aggregate and CausalGuard

**High-performance post-quantum threshold signatures and cryptographic causal integrity for cross-chain environments.**

PQ-Aggregate is a post-quantum security framework that combines ML-DSA threshold signatures with recursive SNARK aggregation. It is designed to provide horizontal scalability for validator sets while maintaining constant-time verification on-chain.

CausalGuard, integrated into this framework, provides "Causal Integrity" for autonomous agents and cross-chain transactions by cryptographically linking events and enforcing policy compliance in zero-knowledge.

## Core Features

- **ML-DSA-65 Security**: Level 3 post-quantum security using independent key aggregation without the need for complex distributed key generation (DKG).
- **Nova Recursive Folding**: O(1) verification time via recursive IVC, allowing for massive scaling of signature batches.
- **Causal Integrity**: Sequential event linking using causal headers and Merkle-based event trails to prevent reordering and omission attacks.
- **Zero-Knowledge Policy Engine**: On-chain enforcement of complex behavioral rules without revealing sensitive transaction logic.
- **Blockchain Interoperability**: Pluggable adapters for Solana, Ethereum (EVM), and Cosmos (IBC).
- **`no_std` Compatibility**: Optimized for constrained environments, including blockchain runtimes and WASM.

## Architectural Components

### 1. PQ-Aggregate (Core Cryptography)
The core protocol implementation focuses on compact proof generation for large validator sets:
- **Independent Keypairs**: Each validator maintains an independent ML-DSA-65 keypair.
- **Merkle Roots as Aggregate PKs**: Public keys are aggregated into a Merkle root, allowing for O(log n) inclusion proofs and O(1) aggregate verification.
- **Layered Proof System**:
    - **Layer 0**: Individual ML-DSA signatures.
    - **Layer 1**: Nova folding of multiple signatures into a single proof.
    - **Layer 2 (Super-Proofs)**: Batching multiple SNARK proofs for high-throughput L2 environments.

### 2. CausalGuard (Integrity Layer)
CausalGuard ensures that actions taken by validators or AI agents follow a verifiable, non-repudiable sequence:
- **Causal Logger**: Maintains a cryptographically linked history of events. Each event includes a hash of the previous state, a timestamp, and a unique UUIDv7.
- **Behavioral Circuits**: ZK circuits that prove a specific sequence of actions complies with predefined architectural or security patterns.
- **Policy Engine**: A modular evaluator that checks event metadata against trust scores and threshold requirements.

### 3. Agent Runtime
The runtime environment provides an interface for AI agents (e.g., DeFi Guardian) to interact with the protocol:
- **Action Proposals**: Agents submit actions that are verified against the causal history.
- **Risk Context**: Every action is evaluated within a risk-aware context, determining the required threshold of signatures based on the transaction value or complexity.

## Getting Started

### Installation
Add the following to your `Cargo.toml`:

```toml
[dependencies]
pq-aggregate = { git = "https://github.com/LogicCrafterDz/pq-aggregate-spec", features = ["nova", "runtime"] }
```

### Basic Usage
```rust
use pq_aggregate::{setup, aggregate_sign, aggregate_proofs, verify};

// 1. Generate validator keys (n=10)
let (sks, pks, pk_root) = setup(10);

// 2. Collect threshold signatures (t=7)
let msg = b"cross-chain-transfer";
let (sigs, proofs) = aggregate_sign(&sks, &pks, msg, 7);

// 3. Generate the aggregate ZK proof
let proof = aggregate_proofs(sigs, proofs, pk_root, msg, &pks).unwrap();

// 4. Verify on-chain (O(1))
assert!(verify(pk_root, msg, &proof));
```

## Blockchain Support

| Adapter | Architecture | Feature Set |
| :--- | :--- | :--- |
| **Solana** | Anchor/eBPF | PDA-based verification, Instruction generation |
| **Ethereum** | EVM/Solidity | ABI encoding, SNARK verifier contracts |
| **Cosmos** | SDK/IBC | Protobuf support, Cross-chain packet integrity |

## Technical Specifications

- **Signature Scheme**: ML-DSA-65 (Crystals-Dilithium)
- **Aggregation Strategy**: Nova-based IVC (Incremental Verifiable Computation)
- **Latency**: Core aggregation ~0.28ms per signature (benchmarked on x86_64)
- **Proof Size**: ~1.2KB (constant size regardless of validator count)
- **Trust Model**: $t$-of-$n$ adaptive threshold with causal provenance

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
