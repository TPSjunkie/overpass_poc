use crate::bitcoin::bitcoin_types::{HTLCParameters};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use bitcoin::{Address, Script};
use bitcoin::hashes::Hash;

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

    /// Creates HTLC parameters for locking channels.
    pub fn create_htlc_parameters(
        &self,
        amount: u64,
        receiver: [u8; 20],
        hash_lock: [u8; 32],
        timeout_height: u32,
    ) -> HTLCParameters {
        HTLCParameters {
            amount,
            receiver,
            hash_lock,
            timeout_height,
        }
    }

    /// Sends a transaction to the Bitcoin network.
    pub fn send_transaction(
        &self,
        transaction: &BitcoinTransaction,
    ) -> Result<(), BitcoinClientError> {
        let tx_bytes = transaction.to_bytes();
        self.cache_transaction(transaction.txid, tx_bytes.clone());

        let rpc_url = "http://localhost:18443"; // Regtest RPC URL
        let rpc_auth = Auth::UserPass("rpcuser".into(), "rpcpassword".into());
        let client = Client::new(rpc_url, rpc_auth)
            .map_err(|e| BitcoinClientError::RpcError(format!("RPC connection failed: {}", e)))?;

        client
            .send_raw_transaction(&tx_bytes)
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to send transaction: {}", e)))?;
        Ok(())
    }

    /// Fetches the current balance for a given address.
    pub fn get_balance(&self, address: &Address) -> Result<u64, BitcoinClientError> {
        let rpc_url = "http://localhost:18443";
        let rpc_auth = Auth::UserPass("rpcuser".into(), "rpcpassword".into());
        let client = Client::new(rpc_url, rpc_auth)
            .map_err(|e| BitcoinClientError::RpcError(format!("RPC connection failed: {}", e)))?;

        let unspent = client.list_unspent(None, None, Some(&[address]), None, None)
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to fetch UTXOs: {}", e)))?;
        let balance: u64 = unspent.iter().map(|utxo| utxo.amount.to_sat()).sum();

        Ok(balance)
    }

    /// Locks funds in an HTLC.
    pub fn create_htlc_lock(
        &self,
        amount: u64,
        receiver: [u8; 20],
        hash_lock: [u8; 32],
        timeout_height: u32,
    ) -> Result<BitcoinTransaction, BitcoinClientError> {
        let rpc_url = "http://localhost:18443";
        let rpc_auth = Auth::UserPass("rpcuser".into(), "rpcpassword".into());
        let client = Client::new(rpc_url, rpc_auth)
            .map_err(|e| BitcoinClientError::RpcError(format!("RPC connection failed: {}", e)))?;

        let script = Script::builder()
            .push_opcode(bitcoin::opcodes::all::OP_HASH256)
            .push_slice(&hash_lock)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_slice(&receiver)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();

        let unspent = client
            .list_unspent(None, None, None, None, None)
            .map_err(|e| BitcoinClientError::RpcError(format!("Failed to fetch UTXOs: {}", e)))?
            .into_iter()
            .find(|utxo| utxo.amount.to_sat() >= amount)
            .ok_or(BitcoinClientError::InsufficientFunds)?;

        let tx = BitcoinTransaction::new(
            *unspent.txid.as_byte_array(),
            unspent.vout,
            amount,
            script.into_bytes(),
        );

        self.cache_transaction(tx.txid, tx.to_bytes());
        Ok(tx)
    }

    /// Redeems an HTLC.
    pub fn redeem_htlc(
        &self,
        htlc_txid: [u8; 32],
        preimage: [u8; 32],
    ) -> Result<BitcoinTransaction, BitcoinClientError> {
        let htlc_tx_bytes = self.get_cached_transaction(&htlc_txid)
            .ok_or(BitcoinClientError::TransactionNotFound)?;
        let htlc_tx = BitcoinTransaction::from_bytes(&htlc_tx_bytes)?;

        let unlocking_script = Script::builder()
            .push_slice(&preimage)
            .into_script();

        let tx = BitcoinTransaction::new(
            htlc_txid,
            0,
            htlc_tx.amount.saturating_sub(1000),
            unlocking_script.into_bytes(),
        );

        self.cache_transaction(tx.txid, tx.to_bytes());
        Ok(tx)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl BitcoinTransaction {
    /// Creates a new Bitcoin transaction.
    pub fn new(txid: [u8; 32], vout: u32, amount: u64, script_pubkey: Vec<u8>) -> Self {
        Self {
            txid,
            vout,
            amount,
            script_pubkey,
        }
    }

    /// Serializes the transaction to bytes.
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