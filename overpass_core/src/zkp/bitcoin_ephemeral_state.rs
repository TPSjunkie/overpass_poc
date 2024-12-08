use bitcoin::hashes::HashEngine;
use std::sync::RwLock;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use thiserror::Error;

use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;
use crate::error::client_errors::{SystemError, SystemErrorType};
use crate::bitcoin::bitcoin_types::{StealthAddress, HTLCParameters};

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
            if !params.verify_timelock(current_height) {
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

    /// Verifies a state transition from `self` to `next_state`.
    /// Checks nonce increments, lock height increases, HTLC conditions, and distinctness.
    pub fn verify_state_transition(&self, next_state: &BitcoinEphemeralState, current_height: u32) -> Result<bool, SystemError> {
        // Height must increase
        if next_state.lock_height <= self.lock_height {
            return Ok(false);
        }

        // HTLC conditions (if any)
        if let Some(htlc) = &self.htlc_params {
            if !htlc.verify_timelock(next_state.lock_height as u32) {
                return Ok(false);
            }
        }

        // Nonce must increment
        if next_state.nonce <= self.nonce {
            return Ok(false);
        }

        // Timelock verification if needed
        if !next_state.verify_timelock(current_height) {
            return Ok(false);
        }

        let current_hash = self.compute_state_hash()?;
        let next_hash = next_state.compute_state_hash()?;

        // The new state must differ
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
    }
}

#[derive(Error, Debug)]
pub enum BitcoinClientError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Transaction not found")]
    TransactionNotFound,
    #[error("Insufficient funds for the transaction")]
    InsufficientFunds,
}

/// Represents a simple Bitcoin transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl BitcoinTransaction {
    /// Serializes the transaction to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    /// Deserializes the transaction from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BitcoinClientError> {
        serde_json::from_slice(bytes).map_err(|e| BitcoinClientError::SerializationError(e.to_string()))
    }
}

/// A conceptual BitcoinClient that simulates anchoring states on-chain.
/// In a real system, this client would interact with the Bitcoin network.
/// Here, it simply caches transactions to simulate sending and retrieval.
#[derive(Debug, Clone)]
pub struct BitcoinClient {
    state_cache: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
}

impl BitcoinClient {
    /// Creates a new Bitcoin client with an empty state cache.
    pub fn new() -> Self {
        Self {
            state_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Mock function to send a transaction (e.g. anchoring a channel state).
    pub fn send_transaction(
        &self,
        transaction: &BitcoinTransaction,
    ) -> Result<(), BitcoinClientError> {
        let tx_bytes = transaction.to_bytes();
        self.cache_transaction(transaction.txid, tx_bytes);
        // In a real scenario, you would broadcast to the network.
        Ok(())
    }

    /// Adds a transaction to the state cache.
    pub fn cache_transaction(&self, txid: [u8; 32], transaction_bytes: Vec<u8>) {
        let mut cache = self.state_cache.write().unwrap();
        cache.insert(txid, transaction_bytes);
    }

    /// Retrieves a transaction from the state cache.
    pub fn get_cached_transaction(&self, txid: &[u8; 32]) -> Option<Vec<u8>> {
        let cache = self.state_cache.read().unwrap();
        cache.get(txid).cloned()
    }
}

/// Utility functions and tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::bitcoin_types::HTLCParameters;
    use rand::Rng;

    #[test]
    fn test_state_transition() {
        let htlc_params = Some(HTLCParameters {
            amount: 1_000_000,
            receiver: [1u8; 20],
            hash_lock: [2u8; 32],
            timeout_height: 200,
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
            timeout_height: 120,
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

        let valid = state.verify_hashlock(&preimage, 110).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_bitcoin_client() {
        let client = BitcoinClient::new();
        let mut rng = rand::thread_rng();
        let mut txid = [0u8; 32];
        rng.fill(&mut txid);

        let transaction = BitcoinTransaction {
            txid,
            vout: 0,
            amount: 50_000,
            script_pubkey: vec![],
        };

        client.send_transaction(&transaction).unwrap();
        let cached = client.get_cached_transaction(&txid).unwrap();
        let loaded_tx = BitcoinTransaction::from_bytes(&cached).unwrap();
        assert_eq!(loaded_tx.txid, txid);
        assert_eq!(loaded_tx.amount, 50_000);
    }
}
