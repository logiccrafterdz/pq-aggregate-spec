//! Bridge Relayer Module.
//!
//! Exports the BridgeRelayer service.

#[cfg(all(feature = "solana-devnet", feature = "ethereum-sepolia"))]
mod relayer;

#[cfg(all(feature = "solana-devnet", feature = "ethereum-sepolia"))]
pub use relayer::BridgeRelayer;
