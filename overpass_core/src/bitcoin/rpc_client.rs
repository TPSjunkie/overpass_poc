use bitcoincore_rpc::RpcApi;
use std::sync::Arc;
use thiserror::Error;
use serde::{Deserialize, Serialize};
use bitcoin::{Transaction, Txid, Amount, Network};


#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("JSON-RPC error: {0}")]
    JsonRpcError(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[cfg(not(target_arch = "wasm32"))]
    #[error("Bitcoin Core RPC error: {0}")]
    BitcoinCoreError(#[from] bitcoincore_rpc::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinRpcConfig {
    pub url: String,
    pub user: String,
    pub password: String,
    pub network: Network,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    30
}

impl Default for BitcoinRpcConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8332".to_string(),
            user: "".to_string(),
            password: "".to_string(),
            network: Network::Bitcoin,
            timeout_seconds: default_timeout(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
pub struct BitcoinRpcClient {
    pub config: BitcoinRpcConfig,
    pub request_id: std::sync::atomic::AtomicU64,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub struct BitcoinRpcClient {
    pub config: BitcoinRpcConfig,
    pub inner: Arc<bitcoincore_rpc::Client>,
}

impl BitcoinRpcClient {
    /// Creates a new instance of `BitcoinRpcClient`.
    pub fn new(config: BitcoinRpcConfig) -> Result<Self, RpcError> {
        #[cfg(target_arch = "wasm32")]
        {
            Ok(Self {
                config,
                request_id: std::sync::atomic::AtomicU64::new(1),
            })
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let client = bitcoincore_rpc::Client::new(
                &config.url,
                bitcoincore_rpc::Auth::UserPass(config.user.clone(), config.password.clone()),
            )
            .map_err(RpcError::BitcoinCoreError)?;
            Ok(Self { inner: Arc::new(client), config })
        }
    }

    /// Gets the current block count from the Bitcoin network.
    pub async fn get_block_count(&self) -> Result<u64, RpcError> {
        #[cfg(target_arch = "wasm32")]
        {
            self.make_request("getblockcount", vec![]).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(self.inner.get_block_count().map_err(RpcError::BitcoinCoreError)?)
        }
    }

    /// Retrieves a raw transaction by its TxID.
    pub async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, RpcError> {
        #[cfg(target_arch = "wasm32")]
        {
            self.make_request("getrawtransaction", vec![
                serde_json::Value::String(txid.to_string()),
                serde_json::Value::Bool(true),
            ])
            .await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner
                .get_raw_transaction(txid, None)
                .map_err(RpcError::BitcoinCoreError)
        }
    }

    /// Sends a raw transaction to the Bitcoin network.
    pub async fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, RpcError> {
        #[cfg(target_arch = "wasm32")]
        {
            let tx_hex = bitcoin::consensus::encode::serialize_hex(tx);
            self.make_request("sendrawtransaction", vec![serde_json::Value::String(tx_hex)]).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner.send_raw_transaction(tx).map_err(RpcError::BitcoinCoreError)
        }
    }

    /// Gets the current balance of the wallet.
    pub async fn get_balance(&self) -> Result<Amount, RpcError> {
        #[cfg(target_arch = "wasm32")]
        {
            let btc: f64 = self.make_request("getbalance", vec![]).await?;
            Amount::from_btc(btc).map_err(|e| RpcError::InvalidResponse(e.to_string()))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner.get_balance(None, None).map_err(RpcError::BitcoinCoreError)
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn make_request<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<T, RpcError> {
        use web_sys::{Request, RequestInit, RequestMode, Response};

        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: self
                .request_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            method: method.to_string(),
            params,
        };

        let mut opts = RequestInit::new();
        opts.method("POST")
            .mode(RequestMode::Cors)
            .body(Some(&JsValue::from_str(&serde_json::to_string(&request)?)));

        let req = Request::new_with_str_and_init(&self.config.url, &opts)?;
        req.headers()
            .set("Content-Type", "application/json")?;

        let window = web_sys::window().ok_or_else(|| RpcError::NetworkError("No window object available".to_string()))?;
        let resp_value = JsFuture::from(window.fetch_with_request(&req)).await?;
        let resp: Response = resp_value.dyn_into()?;

        let json = JsFuture::from(resp.json()?).await?;
        let rpc_response: RpcResponse<T> = serde_wasm_bindgen::from_value(json)?;

        match (rpc_response.result, rpc_response.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(RpcError::JsonRpcError(error.message)),
            _ => Err(RpcError::InvalidResponse("Invalid response structure".to_string())),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoincore_rpc::RpcApi;

    #[tokio::test]
    async fn test_get_block_count() {
        // Configure BitcoinRpcClient
        let config = BitcoinRpcConfig {
            url: "http://127.0.0.1:18443".to_string(), // Default regtest RPC port
            user: "user".to_string(),
            password: "password".to_string(),
            network: Network::Regtest,
            timeout_seconds: 30,
        };

        let client = BitcoinRpcClient::new(config).expect("Failed to create RPC client");

        // Test get_block_count
        let block_count = client.get_block_count().await.expect("Failed to get block count");
        assert!(block_count > 0, "Block count should be positive");
    }

    #[tokio::test]
    async fn test_get_balance() {
        // Configure BitcoinRpcClient
        let config = BitcoinRpcConfig {
            url: "http://127.0.0.1:18443".to_string(),
            user: "user".to_string(),
            password: "password".to_string(),
            network: Network::Regtest,
            timeout_seconds: 30,
        };

        let client = BitcoinRpcClient::new(config).expect("Failed to create RPC client");

        // Test get_balance
        let balance = client.get_balance().await.expect("Failed to get balance");
        assert!(balance.to_sat() > 0, "Wallet balance should be positive");
    }
    #[tokio::test]
    async fn test_send_raw_transaction() {
        // Configure BitcoinRpcClient
        let config = BitcoinRpcConfig {
            url: "http://127.0.0.1:18443".to_string(),
            user: "user".to_string(),
            password: "password".to_string(),
            network: Network::Regtest,
            timeout_seconds: 30,
        };

        let client = BitcoinRpcClient::new(config).expect("Failed to create RPC client");

        // Generate a new address for testing
        let new_address = client
            .inner
            .get_new_address(None, None)
            .expect("Failed to get new address");
        let txid = client
            .inner
            .send_to_address(&new_address.require_network(Network::Regtest).expect("Invalid network"), Amount::from_sat(1000), None, None, None, None, None, None)
            .expect("Failed to send transaction");

        let tx = client
            .get_raw_transaction(&txid)
            .await
            .expect("Failed to get raw transaction");
        assert_eq!(tx.txid(), txid, "Transaction ID mismatch");
    }}
