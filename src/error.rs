//! Error types for PQ-Aggregate operations.
//!
//! Provides strongly-typed errors for cryptographic operations using `thiserror`.

use alloc::string::String;

/// Errors that can occur during PQ-Aggregate operations.
#[derive(Debug)]
pub enum PQAggregateError {
    /// Invalid threshold value (must be 1 <= t <= n)
    InvalidThreshold {
        threshold: usize,
        num_participants: usize,
    },
    /// Merkle proof verification failed
    MerkleProofInvalid {
        index: usize,
        reason: String,
    },
    /// Signature verification failed
    SignatureInvalid {
        signer_index: usize,
    },
    /// Proof aggregation failed
    AggregationFailed {
        reason: String,
    },
    /// Key generation failed
    KeygenFailed {
        reason: String,
    },
    /// Invalid input parameters
    InvalidInput {
        reason: String,
    },
    /// Insufficient signatures for threshold
    InsufficientSignatures {
        required: usize,
        provided: usize,
    },
    /// Network/RPC error
    NetworkError {
        reason: String,
    },
    /// Policy violation (e.g., insufficient verifications)
    PolicyViolation {
        reason: String,
    },
    /// Rate limit exceeded
    RateLimitExceeded {
        reason: String,
    },
    /// Nova SNARK error
    #[cfg(feature = "nova")]
    NovaError(String),
    /// Cryptographic operation failed
    CryptoError {
        reason: String,
    },
    /// File I/O Error
    #[cfg(feature = "std")]
    IOError(std::io::Error),
}


impl core::fmt::Display for PQAggregateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidThreshold { threshold, num_participants } => {
                write!(f, "Invalid threshold: {} out of {} participants", threshold, num_participants)
            }
            Self::MerkleProofInvalid { index, reason } => {
                write!(f, "Merkle proof invalid for index {}: {}", index, reason)
            }
            Self::SignatureInvalid { signer_index } => {
                write!(f, "Invalid signature from signer {}", signer_index)
            }
            Self::AggregationFailed { reason } => {
                write!(f, "Proof aggregation failed: {}", reason)
            }
            Self::KeygenFailed { reason } => {
                write!(f, "Key generation failed: {}", reason)
            }
            Self::InvalidInput { reason } => {
                write!(f, "Invalid input: {}", reason)
            }
            Self::InsufficientSignatures { required, provided } => {
                write!(f, "Insufficient signatures: {} required, {} provided", required, provided)
            }
            Self::NetworkError { reason } => {
                write!(f, "Network error: {}", reason)
            }
            Self::PolicyViolation { reason } => {
                write!(f, "Policy violation: {}", reason)
            }
            Self::RateLimitExceeded { reason } => {
                write!(f, "Rate limit exceeded: {}", reason)
            }
            #[cfg(feature = "nova")]
            Self::NovaError(reason) => {
                write!(f, "Nova SNARK error: {}", reason)
            }
            Self::CryptoError { reason } => {
                write!(f, "Crypto error: {}", reason)
            }
            #[cfg(feature = "std")]
            Self::IOError(e) => {
                write!(f, "IO error: {}", e)
            }
        }
    }
}


#[cfg(feature = "std")]
impl std::error::Error for PQAggregateError {}

/// Result type alias for PQ-Aggregate operations.
pub type Result<T> = core::result::Result<T, PQAggregateError>;
