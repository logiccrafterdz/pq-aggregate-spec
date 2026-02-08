//! Solana Devnet adapter module.
//!
//! Provides production-grade integration with Solana Devnet for real USDC transfers
//! with CausalGuard proof verification and risk-adaptive policy enforcement.

mod basic;
pub use basic::*;


#[cfg(feature = "solana-devnet")]
mod wallet;
#[cfg(feature = "solana-devnet")]
mod faucet;
#[cfg(feature = "solana-devnet")]
mod real_adapter;
#[cfg(feature = "solana-devnet")]
mod transfer;

#[cfg(feature = "solana-devnet")]
pub use wallet::{WalletManager, Pubkey, Keypair, Signature};
#[cfg(feature = "solana-devnet")]
pub use faucet::FaucetClient;
#[cfg(feature = "solana-devnet")]
pub use real_adapter::SolanaDevnetAdapter;
#[cfg(feature = "solana-devnet")]
pub use transfer::TransferFlow;


/// Devnet USDC mint address (Circle's test USDC on Solana Devnet)
#[cfg(feature = "solana-devnet")]
pub const DEVNET_USDC_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

/// Devnet RPC endpoint
#[cfg(feature = "solana-devnet")]
pub const DEVNET_RPC_URL: &str = "https://api.devnet.solana.com";

/// Maximum transactions per minute (rate limiting)
pub const MAX_TXS_PER_MINUTE: u32 = 10;

/// Transaction retry count on network errors
pub const MAX_RETRIES: u32 = 3;
