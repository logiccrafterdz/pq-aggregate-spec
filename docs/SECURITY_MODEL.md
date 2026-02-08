# CausalGuard Security Model

## 1. System Overview
CausalGuard is a post-quantum threshold signature system designed to secure causal interactions in distributed systems. It aggregates signatures from multiple validators (t-of-n) into a single ZK-proof, enforcing strict causal ordering.

## 2. Threat Model (STRIDE)

### Spoofing
- **Threat**: Attacker impersonates a validator to forge signatures.
- **Mitigation**: 
  - ML-DSA-65 (Dilithium) signatures provide EUF-CMA security against quantum adversaries.
  - Keys stored in HSM (Software/Hardware) and zeroized after use.
  - Rate-limiting on RPC endpoints prevents brute-force attempts.

### Tampering
- **Threat**: Attacker modifies the `Lock` event on Solana or the Proof on Ethereum.
- **Mitigation**:
  - **Atomic Verifiability**: The proof $\pi$ committed on Solana is bitwise identical to the one verified on Ethereum.
  - **Merkle Roots**: Public keys are committed to a Merkle Root (`pkRoot`) stored immutably in the contract.
  - **ZK-SNARKs**: Nova proofs guarantee computational integrity of the aggregation process.

### Repudiation
- **Threat**: Validator denies signing a valid message.
- **Mitigation**:
  - **Non-Repudiation**: Digital signatures (ML-DSA) are non-repudiatable.
  - **On-Chain Audit Trail**: Every signature aggregation is logged on Solana (Data Availability) before bridging.

### Information Disclosure
- **Threat**: Attacker extracts private keys from memory or disk.
- **Mitigation**:
  - **Encryption at Rest**: Keystores are AES-256-GCM encrypted.
  - **Memory Hygiene**: `zeroize` crate ensures sensitive memory is overwritten immediately after use.
  - **No Custody**: Relayers are stateless and never see private keys.

### Denial of Service
- **Threat**: Attacker floods the Aggregator or Relayer.
- **Mitigation**:
  - **State-Free Relaying**: Relayers do not maintain session state; they process events atomically.
  - **Gas Limits**: Smart contracts enforce strict gas limits (< 85k verified).

### Elevation of Privilege
- **Threat**: Attacker alters the Policy to lower the threshold.
- **Mitigation**:
  - **Immutable Policy**: Critical policy parameters (t, n, pkRoot) are hardcoded or governance-locked in the verifier contract.

## 3. Trust Assumptions
1.  **Honest Aggregator (Temporary)**: We assume the aggregator correctly assembles valid signatures. Validated by end-to-end ZK proofs.
2.  **L1 Security**: We assume Solana and Ethereum consensus mechanisms remain secure.
3.  **Local Entropy**: We assume the validator's OS PRNG (via `rand`) is secure for key generation.
4.  **BIP-39 Implementation**: We rely on the correctness of the `bip39` crate for seed derivation.

## 4. Assets & Boundaries
- **High Value**: Validator Private Keys, Aggregator Secret State.
- **Medium Value**: Proof Metadata, Policy Configurations.
- **Low Value**: Public Keys, Relay Logs.
