//! Ethereum Sepolia adapter module.
//!
//! Provides production-grade integration with Ethereum Sepolia for real USDC transfers
//! and cross-chain bridge verification.

#[cfg(feature = "ethereum-sepolia")]
mod real_adapter;

#[cfg(feature = "ethereum-sepolia")]
mod faucet;

#[cfg(feature = "ethereum-sepolia")]
pub use real_adapter::EthereumAdapter;

#[cfg(feature = "ethereum-sepolia")]
pub use faucet::FaucetClient;

/// Sepolia Chain ID
#[cfg(feature = "ethereum-sepolia")]
pub const SEPOLIA_CHAIN_ID: u64 = 11155111;

/// Sepolia USDC Contract Address (Testnet)
#[cfg(feature = "ethereum-sepolia")]
pub const SEPOLIA_USDC_ADDRESS: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
