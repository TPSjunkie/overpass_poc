use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use bitcoin::hashes::Hash;

/// A conceptual Bitcoin transaction struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl BitcoinTransaction {
    /// Serializes the transaction to bytes (example, in reality you'd handle raw tx hex).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    /// Deserializes the transaction from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BitcoinClientError> {
        serde_json::from_slice(bytes).map_err(|e| BitcoinClientError::SerializationError(e.to_string()))
    }
}

#[derive(Error, Debug)]
pub enum BitcoinClientError {
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Transaction not found")]
    TransactionNotFound,
    #[error("Insufficient funds for the transaction")]
    InsufficientFunds,
}

/// A Bitcoin client connected to a local regtest node via RPC.
#[derive(Debug, Clone)]
pub struct BitcoinClient {
    state_cache: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
    rpc_client: Arc<Client>,
}

#[derive(Debug, Clone)]
pub struct HTLCParams {
    pub preimage: [u8; 32],
    pub hash: [u8; 32],
    pub timelock: u64,
}

impl BitcoinClient {
    /// Creates a new Bitcoin client connected to a local regtest node.
    pub fn new(rpc_url: &str, rpc_user: &str, rpc_pass: &str) -> Result<Self, BitcoinClientError> {
        let auth = Auth::UserPass(rpc_user.to_string(), rpc_pass.to_string());
        let rpc_client = Client::new(rpc_url, auth)
            .map_err(|e| BitcoinClientError::RpcError(format!("RPC connection failed: {}", e)))?;
        
        Ok(Self {
            state_cache: Arc::new(RwLock::new(HashMap::new())),
            rpc_client: rpc_client.into(),
        })
    }

    /// Returns the current block count.
    pub fn get_block_count(&self) -> Result<u64, BitcoinClientError> {
        self.rpc_client
            .get_block_count()
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to get block count: {}", e)))
    }

    /// Generates blocks in regtest mode.
    pub fn generate_blocks(&self, num_blocks: u64, address: &str) -> Result<Vec<bitcoin::BlockHash>, BitcoinClientError> {
        use std::str::FromStr;
        let bitcoin_address = bitcoin::Address::from_str(address)
            .map_err(|e| BitcoinClientError::SerializationError(e.to_string()))?;
        self.rpc_client
            .generate_to_address(num_blocks, &bitcoin_address.require_network(bitcoin::Network::Regtest).expect("Invalid network"))
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to generate blocks: {}", e)))
    }

    /// Gets a new address for receiving funds.
    pub fn get_new_address(&self) -> Result<bitcoin::Address<bitcoin::address::NetworkChecked>, BitcoinClientError> {
        self.rpc_client
            .get_new_address(None, None)
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to get new address: {}", e)))?
            .require_network(bitcoin::Network::Regtest)
            .map_err(|e| BitcoinClientError::SerializationError(e.to_string()))
    }

    /// Fetches the current balance in satoshis.
    pub fn get_balance(&self) -> Result<u64, BitcoinClientError> {
        let balance = self.rpc_client
            .get_balance(None, None)
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to fetch balance: {}", e)))?;
        Ok(balance.to_sat())
    }

    /// Sends a transaction to the Bitcoin network (Note: For demonstration, we use a dummy raw transaction).
    /// In reality, you'd craft a raw transaction (hex) and send it with `send_raw_transaction`.
    pub fn send_raw_transaction(&self, raw_tx_hex: &str) -> Result<bitcoin::Txid, BitcoinClientError> {
        let txid = self.rpc_client
            .send_raw_transaction(&hex::decode(raw_tx_hex)
                .map_err(|e| BitcoinClientError::SerializationError(e.to_string()))?)
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to send transaction: {}", e)))?;
        Ok(txid)
    }

    /// Adds a transaction to the local state cache.
    pub fn cache_transaction(&self, txid: [u8; 32], transaction_bytes: Vec<u8>) {
        let mut cache = self.state_cache.write().unwrap();
        cache.insert(txid, transaction_bytes);
    }

    /// Retrieves a transaction from the state cache.
    pub fn get_cached_transaction(&self, txid: &[u8; 32]) -> Option<Vec<u8>> {
        let cache = self.state_cache.read().unwrap();
        cache.get(txid).cloned()
    }

    /// Creates HTLC parameters for a transaction
    pub fn create_htlc_parameters(&self) -> Result<HTLCParams, BitcoinClientError> {
        // Generate a random 32-byte secret preimage
        let mut preimage = [0u8; 32];
        getrandom::getrandom(&mut preimage)
            .map_err(|e| BitcoinClientError::SerializationError(e.to_string()))?;
        
        // Create SHA256 hash of the preimage
        let hash = bitcoin::hashes::sha256::Hash::hash(&preimage);
        
        // Generate a locktime (e.g., 24 hours from now)
        let current_height = self.get_block_count()?;
        let timelock = current_height + 144; // roughly 24 hours worth of blocks
        
        // Create HTLC parameters
        let params = HTLCParams {
            preimage,
            hash: hash.to_byte_array(),
            timelock,
        };
        
        Ok(params)
    }

    /// Creates a new Bitcoin client with default regtest configuration
    pub fn default() -> Result<Self, BitcoinClientError> {
        Self::new(
            "http://127.0.0.1:18443",
            "bitcoinrpc",
            "testpassword"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// To run these tests, ensure a local regtest node is running:
    /// bitcoind -regtest -daemon -rpcuser=rpcuser -rpcpassword=rpcpassword
    /// 
    /// Then run:
    /// cargo test
    #[test]
    fn test_connection_to_regtest() {
        let client = BitcoinClient::new(
            "http://127.0.0.1:18443",
            "rpcuser",
            "rpcpassword"
        ).expect("Failed to create client");

        let block_count = client.get_block_count().expect("Failed to get block count");
        println!("Current block count: {}", block_count);
        assert!(block_count > 0);

        // Generate some blocks to ensure we have funds and see if RPC works:
        let address = client.get_new_address().expect("Failed to get new address");
        println!("New regtest address: {}", address);

        let _ = client.generate_blocks(101, &address.to_string())
            .expect("Failed to generate blocks");

        // Now we should have some balance in regtest
        let balance = client.get_balance().expect("Failed to get balance");
        println!("Current balance: {} sats", balance);
        assert!(balance > 0);
    }}