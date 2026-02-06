//! Causal Event Logger module.
//!
//! Provides cryptographically robust, nonce-ordered behavioral logging
//! for agents.

pub mod event;
pub mod merkle;
pub mod logger;

pub use event::{CausalEvent, ActionType};
pub use merkle::IncrementalMerkleTree;
pub use logger::{CausalEventLogger, LoggerError};
