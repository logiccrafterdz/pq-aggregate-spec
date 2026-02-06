# CausalGuard Runtime Security Model

## 1. Overview
The CausalGuard Runtime is a trusted execution environment that mediates interactions between untrusted AI agents and the high-performance cryptographic core of PQ-Aggregate. It enforces the **Principle of Least Authority**, ensuring agents never touch cryptographic secrets.

## 2. Trust Boundaries

### A. Non-Bypassable Logging (Layer 1)
- Every action proposed by an agent *must* be logged via `CausalEventLogger` before any other processing.
- The `ActionId` is cryptographically tied to the log entry: `SHA3-256(nonce || timestamp || agent_id)`.
- Replay protection is enforced via `idempotency_cache`.

### B. Deterministic Policy Gatekeeper (Layer 2)
- No action can reach the signing phase without a `COMPLIANT` result from the `PolicyEngine`.
- Policies are evaluated on the full causal history, preventing "history-less" or "nonce-skipping" attacks.
- High-value actions ($1,000+) automatically escalate to `RiskTier::High`, requiring 3 prior verifications.

### C. Signature Activation (Layer 3)
- ML-DSA secret keys are held in a separate memory space (simulated as the Validator network).
- The Runtime only requests signatures for `COMPLIANT` actions.
- Adaptive thresholds (t=2, 3, 5) are mapping-enforced: `RiskTier -> Threshold`.

## 3. Security Invariants
1. **Zero Secret Leakage**: No API call or error message exposes validator keys or agent private metadata.
2. **Immutable History**: Once an `ActionId` is returned, the corresponding event is committed to the Merkle tree.
3. **No Downgrade Attacks**: The mapping from `RiskTier` to `threshold` is hardcoded in the trusted `SignatureOrchestrator` logic.

## 4. Rate Limiting & DoS Protection
- **API Boundary**: Strict 10 proposals/minute policy per `agent_id`.
- **Payload Limits**: Max 4KB per proposal to prevent memory exhaustion.
- **Async Isolation**: Background tasks handle orchestration, preventing agent interactions from blocking system availability.
