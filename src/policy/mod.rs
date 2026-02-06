//! Behavioral Policy Engine module.
//!
//! Provides deterministic verification of agent behavior before
//! cryptographic execution.

pub mod types;
pub mod evaluator;
pub mod engine;

pub use types::{BehavioralPolicy, PolicyCondition, RiskTier, PolicyEvaluation, PolicyProof, Currency};
pub use engine::{PolicyEngine, PolicyError};
