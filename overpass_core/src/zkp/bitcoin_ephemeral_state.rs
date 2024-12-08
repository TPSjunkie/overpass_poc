use bitcoin::hashes::HashEngine;
use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use crate::error::client_errors::{SystemError, SystemErrorType};
use crate::bitcoin::bitcoin_types::{StealthAddress, HTLCParameters};
use bitcoincore_rpc::{Auth, Client, RpcApi};

// Adjusted HTLCParameters to reflect preimage must be revealed before timeout.
impl HTLCParameters {
    pub fn verify_timelock(&self, current_height: u32) -> bool {
        // Preimage must be revealed at or before timeout_height.
        u64::from(current_height) <= self.timeout_height.into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinEphemeralState {
    pub lock_amount: u64,
    pub lock_script_hash: [u8; 32],
    pub lock_height: u64,
    pub pubkey_hash: [u8; 20],
    pub sequence: u32,
    pub nonce: u64,
    pub htlc_params: Option<HTLCParameters>,
    pub stealth_address: Option<StealthAddress>,
    #[serde(skip)]
    state_cache: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
}

impl BitcoinEphemeralState {
    pub fn new(
        lock_amount: u64,
        lock_script_hash: [u8; 32],
        lock_height: u64,
        pubkey_hash: [u8; 20],
        sequence: u32,
        nonce: u64,
        htlc_params: Option<HTLCParameters>,
        stealth_address: Option<StealthAddress>,
    ) -> Result<Self, SystemError> {
        if let Some(params) = &htlc_params {
            if lock_amount < params.amount {
                return Err(SystemError::new(
                    SystemErrorType::InvalidAmount,
                    "Lock amount is less than HTLC requirement".to_string(),
                ));
            }
        }

        Ok(Self {
            lock_amount,
            lock_script_hash,
            lock_height,
            pubkey_hash,
            sequence,
            nonce,
            htlc_params,
            stealth_address,
            state_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn verify_timelock(&self, current_height: u32) -> bool {
        u64::from(current_height) >= self.lock_height
    }

    pub fn verify_hashlock(&self, preimage: &[u8], current_height: u32) -> Result<bool, SystemError> {
        if let Some(params) = &self.htlc_params {
            if !self.verify_timelock(current_height) {
                return Ok(false);
            }
            let hash = sha256d::Hash::hash(preimage);
            Ok(hash.to_byte_array() == params.hash_lock)
        } else {
            Ok(false)
        }
    }

    fn compute_state_hash(&self) -> Result<[u8; 32], SystemError> {
        let mut engine = sha256d::Hash::engine();
        engine.input(&self.lock_amount.to_le_bytes());
        engine.input(&self.lock_script_hash);
        engine.input(&self.lock_height.to_le_bytes());
        engine.input(&self.pubkey_hash);
        engine.input(&self.sequence.to_le_bytes());
        engine.input(&self.nonce.to_le_bytes());

        if let Some(htlc) = &self.htlc_params {
            let htlc_bytes = serde_json::to_vec(htlc)
                .map_err(|e| SystemError::new(SystemErrorType::SerializationError, e.to_string()))?;
            engine.input(&htlc_bytes);
        }

        Ok(*sha256d::Hash::from_engine(engine).as_byte_array())
    }

    pub fn verify_state_transition(&self, next_state: &BitcoinEphemeralState, current_height: u32) -> Result<bool, SystemError> {
        // Height must increase
        if next_state.lock_height <= self.lock_height {
            return Ok(false);
        }

        // HTLC conditions
        if let Some(_htlc) = &self.htlc_params {
            if !self.verify_timelock(current_height) {
                return Ok(false);
            }
        }

        // Nonce must increment
        if next_state.nonce <= self.nonce {
            return Ok(false);
        }

        // Timelock verification if needed
        if !self.verify_timelock(current_height) {
            return Ok(false);
        }

        let current_hash = self.compute_state_hash()?;
        let next_hash = next_state.compute_state_hash()?;

        if current_hash == next_hash {
            return Ok(false);
        }

        let mut cache = self.state_cache.write().unwrap();
        cache.insert(
            next_hash,
            serde_json::to_vec(next_state)
                .map_err(|e| SystemError::new(SystemErrorType::SerializationError, e.to_string()))?,
        );

        Ok(true)
    }}
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl BitcoinTransaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BitcoinClientError> {
        serde_json::from_slice(bytes).map_err(|e| BitcoinClientError::SerializationError(e.to_string()))
    }
}

/// A Bitcoin client that connects to a local regtest node using `bitcoincore_rpc`.
#[derive(Debug, Clone)]
pub struct BitcoinClient {
    rpc_client: Arc<Client>,
}

impl BitcoinClient {
    pub fn new(rpc_url: &str, rpc_user: &str, rpc_pass: &str) -> Result<Self, BitcoinClientError> {
        let auth = Auth::UserPass(rpc_user.to_string(), rpc_pass.to_string());
        let rpc_client = Client::new(rpc_url, auth)
            .map_err(|e| BitcoinClientError::RpcError(format!("RPC connection failed: {}", e)))?;
        Ok(Self {
            rpc_client: Arc::new(rpc_client),
        })
    }

    pub fn get_block_count(&self) -> Result<u64, BitcoinClientError> {
        self.rpc_client
            .get_block_count()
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to get block count: {}", e)))
    }

    pub fn generate_blocks(&self, num_blocks: u64, address: &str) -> Result<Vec<bitcoin::BlockHash>, BitcoinClientError> {
        use std::str::FromStr;
        let addr = bitcoin::Address::from_str(address)
            .map_err(|e| BitcoinClientError::SerializationError(e.to_string()))?;
        self.rpc_client
            .generate_to_address(num_blocks, &addr.assume_checked())
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to generate blocks: {}", e)))
    }
    pub fn get_new_address(&self) -> Result<bitcoin::Address, BitcoinClientError> {
        self.rpc_client
            .get_new_address(None, None)
            .map(|addr| addr.assume_checked())
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to get new address: {}", e)))
    }

    pub fn get_balance(&self) -> Result<u64, BitcoinClientError> {
        let balance = self.rpc_client
            .get_balance(None, None)
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to fetch balance: {}", e)))?;
        Ok(balance.to_sat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Make sure bitcoind is running on regtest and a wallet is loaded:
    // bitcoind -regtest -daemon -rpcuser=bitcoinrpc -rpcpassword=testpassword
    // bitcoin-cli -regtest -rpcuser=bitcoinrpc -rpcpassword=testpassword createwallet "testwallet"
    #[test]
    fn test_state_transition() {
        let htlc_params = Some(HTLCParameters {
            amount: 1_000_000,
            receiver: [1u8; 20],
            hash_lock: [2u8; 32],
            timeout_height: 120,
        });

        let initial_state = BitcoinEphemeralState::new(
            1_000_000,
            [0u8; 32],
            100,
            [1u8; 20],
            0,
            0,
            htlc_params.clone(),
            None,
        ).unwrap();

        let next_state = BitcoinEphemeralState::new(
            1_000_000,
            [0u8; 32],
            150,
            [1u8; 20],
            0,
            1,
            htlc_params,
            None,
        ).unwrap();

        let valid = initial_state.verify_state_transition(&next_state, 150).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_hashlock() {
        let preimage = [3u8; 32];
        let hash = sha256d::Hash::hash(&preimage).to_byte_array();
        let htlc_params = Some(HTLCParameters {
            amount: 500_000,
            receiver: [4u8; 20],
            hash_lock: hash,
            timeout_height: 120, // Must reveal before or at 120
        });

        let state = BitcoinEphemeralState::new(
            500_000,
            [0u8; 32],
            100,
            [1u8; 20],
            0,
            0,
            htlc_params,
            None,
        ).unwrap();

        // Reveal preimage at current_height=110 (≤120)
        let valid = state.verify_hashlock(&preimage, 110).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_bitcoin_client_regtest() {
        let client = BitcoinClient::new(
            "http://127.0.0.1:18443",
            "rpcuser",
            "rpcpassword"
        ).expect("Failed to connect to regtest");

        let block_count = client.get_block_count().expect("Failed to get block count");
        println!("Block count: {}", block_count);
        assert!(block_count >= 0);

        let address = client.get_new_address().expect("Failed to get new address");
        println!("Got new address: {}", address);

        // Generate blocks to fund this address (coinbase rewards go to it).
        let _ = client.generate_blocks(101, &address.to_string())
            .expect("Failed to generate blocks");
        
        let balance = client.get_balance().expect("Failed to get balance");
        println!("Balance after generating blocks: {}", balance);
        assert!(balance > 0);
    }
}
