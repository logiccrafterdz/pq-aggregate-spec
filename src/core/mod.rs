//! Core module for PQ-Aggregate cryptographic operations.
//!
//! This module contains the primary cryptographic functionality:
//! - Key generation (`keygen`)
//! - Threshold signing (`signing`)
//! - Proof aggregation (`aggregation`)

pub mod keygen;
pub mod signing;
pub mod aggregation;

pub use keygen::setup;
pub use signing::aggregate_sign;
pub use aggregation::aggregate_proofs;
