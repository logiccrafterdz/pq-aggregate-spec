//! Causal Event Logger module.
//!
//! Provides cryptographically robust, nonce-ordered behavioral logging
//! for agents with structured metadata support for risk-adaptive policies.

pub mod event;
pub mod merkle;
pub mod logger;
pub mod metadata;

pub use event::{CausalEvent, ActionType, EVENT_VERSION_LEGACY, EVENT_VERSION_METADATA};
pub use merkle::IncrementalMerkleTree;
pub use logger::{CausalEventLogger, LoggerError};
pub use metadata::{StructuredMetadata, compute_metadata_commitment, risk_flags};
