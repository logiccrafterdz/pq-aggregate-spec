//! Faucet automation for Solana Devnet.
//!
//! Provides automated SOL and USDC requests from Devnet faucets.
//! Uses HTTP requests to Devnet RPC and faucet APIs.

#![cfg(feature = "solana-devnet")]

use crate::error::{PQAggregateError, Result};
use super::wallet::{Pubkey, Signature};

/// Devnet RPC endpoint
const DEVNET_RPC_URL: &str = "https://api.devnet.solana.com";

/// Default airdrop amount in lamports (0.5 SOL)
const DEFAULT_AIRDROP_LAMPORTS: u64 = 500_000_000;

/// Faucet client for requesting test tokens.
pub struct FaucetClient {
    http_client: reqwest::Client,
    rpc_url: String,
}

impl FaucetClient {
    /// Create a new faucet client.
    pub fn new(rpc_url: &str) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            rpc_url: rpc_url.to_string(),
        }
    }

    /// Create a faucet client for Devnet.
    pub fn devnet() -> Self {
        Self::new(DEVNET_RPC_URL)
    }

    /// Request SOL airdrop from Devnet faucet via RPC.
    ///
    /// # Arguments
    /// * `wallet` - The public key to receive SOL
    /// * `lamports` - Amount in lamports (optional, defaults to 0.5 SOL)
    ///
    /// # Returns
    /// Transaction signature on success
    pub async fn request_sol_airdrop(
        &self,
        wallet: &Pubkey,
        lamports: Option<u64>,
    ) -> Result<Signature> {
        let amount = lamports.unwrap_or(DEFAULT_AIRDROP_LAMPORTS);
        
        // Create JSON-RPC request for airdrop
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "requestAirdrop",
            "params": [
                wallet.to_string(),
                amount
            ]
        });

        let response = self.http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| PQAggregateError::NetworkError {
                reason: format!("Airdrop request failed: {}", e),
            })?;

        let result: serde_json::Value = response.json().await.map_err(|e| {
            PQAggregateError::NetworkError {
                reason: format!("Failed to parse airdrop response: {}", e),
            }
        })?;

        // Extract signature from response
        if let Some(sig_str) = result.get("result").and_then(|v| v.as_str()) {
            let sig_bytes = bs58::decode(sig_str).into_vec().map_err(|e| {
                PQAggregateError::InvalidInput {
                    reason: format!("Invalid signature: {}", e),
                }
            })?;
            
            if sig_bytes.len() == 64 {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&sig_bytes);
                return Ok(Signature::new(arr));
            }
        }

        // Check for error
        if let Some(error) = result.get("error") {
            return Err(PQAggregateError::NetworkError {
                reason: format!("Airdrop error: {}", error),
            });
        }

        Err(PQAggregateError::NetworkError {
            reason: "Invalid airdrop response".to_string(),
        })
    }

    /// Confirm a transaction by polling for status.
    pub async fn confirm_transaction(&self, signature: &Signature) -> Result<bool> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignatureStatuses",
            "params": [[signature.to_string()]]
        });

        // Poll for up to 30 seconds
        for _ in 0..30 {
            let response = self.http_client
                .post(&self.rpc_url)
                .json(&request)
                .send()
                .await
                .map_err(|e| PQAggregateError::NetworkError {
                    reason: format!("Confirmation check failed: {}", e),
                })?;

            let result: serde_json::Value = response.json().await.map_err(|e| {
                PQAggregateError::NetworkError {
                    reason: format!("Failed to parse confirmation response: {}", e),
                }
            })?;

            if let Some(statuses) = result.get("result").and_then(|r| r.get("value")).and_then(|v| v.as_array()) {
                if let Some(status) = statuses.first().and_then(|s| s.as_object()) {
                    if status.get("confirmationStatus").and_then(|c| c.as_str()) == Some("confirmed") {
                        return Ok(true);
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(false)
    }

    /// Get current SOL balance for a wallet.
    pub async fn get_sol_balance(&self, wallet: &Pubkey) -> Result<u64> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [wallet.to_string()]
        });

        let response = self.http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| PQAggregateError::NetworkError {
                reason: format!("Balance request failed: {}", e),
            })?;

        let result: serde_json::Value = response.json().await.map_err(|e| {
            PQAggregateError::NetworkError {
                reason: format!("Failed to parse balance response: {}", e),
            }
        })?;

        result.get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| PQAggregateError::NetworkError {
                reason: "Invalid balance response".to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_faucet_client_creation() {
        let client = FaucetClient::new("https://api.devnet.solana.com");
        assert!(!client.rpc_url.is_empty());
    }

    #[test]
    fn test_faucet_client_devnet() {
        let client = FaucetClient::devnet();
        assert_eq!(client.rpc_url, DEVNET_RPC_URL);
    }
}
