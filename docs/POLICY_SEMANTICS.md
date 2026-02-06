# Behavioral Policy Semantics

This document specifies the deterministic evaluation rules for the PQ-Aggregate Behavioral Policy Engine.

## Evaluation Model

The Policy Engine treats behavioral verification as a pure function:
`f(EventChain, Policy) -> (Pass|Fail, RiskTier, Proof)`

### Rules of Engagement
1. **Nonce Monotonicity**: Every event in the chain must have a unique, strictly increasing nonce. Gaps are allowed between ranges, but sequence violation triggers immediate rejection.
2. **Temporal Causality**: Time must flow forward. Events with timestamps older than the previous event (minus 500ms skew tolerance) are rejected.
3. **Short-Circuit Evaluation**: Conditions are evaluated in the order they appear. The first failure halts evaluation.

## Condition Specifications

### 1. MaxDailyOutflow
Enforces a cap on cumulative value transferred within a rolling 24-hour window.
- **Window**: `[T_target - 86,400s, T_target]`
- **Valuation**: `SignatureRequest` events are weighted according to their payload value (mocked as 1000 USD in prototype).

### 2. MinTimeBetweenActions
Prevents rapid-fire execution of sensitive actions.
- **Logic**: For a target action of type `X`, the gap `T_target - T_last_X` must be ≥ `min_seconds`.

### 3. NoConcurrentRequests
Rejects burst behavior across different action types.
- **Logic**: No other events allowed within `window_seconds` prior to the target event.

### 4. MinVerificationCount
Escalates security requirements based on transaction value.
- **Logic**: If `amount >= threshold_amount`, then `count(ADDRESS_VERIFICATION)` in the history must be ≥ `required_count`.

## Security Mapping

Policy decisions map directly to `RiskTier` levels, which dictate the cryptographic threshold ($t$) required for signature aggregation:
- **Low Risk**: $t = 2$
- **Medium Risk**: $t = 3$
- **High Risk**: $t = 5$

This mapping ensures that behavioral non-compliance or high-risk behavior automatically triggers a requirement for more validator signatures.
