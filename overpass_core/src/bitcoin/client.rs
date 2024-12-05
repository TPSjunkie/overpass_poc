// src/bitcoin/client.rs

use crate::bitcoin::bitcoin_types::{
    BitcoinLockState, HTLCParameters, OpReturnMetadata, StealthAddress,
};
use bitcoin::{
    blockdata::script::ScriptBuf,
    locktime,
    opcodes::all::OP_RETURN,
    script::Builder,
    OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

/// Represents a Bitcoin client managing state and operations.
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

    /// Creates an OP_RETURN script with encoded metadata.
    pub fn create_op_return_script(
        &self,
        metadata: &OpReturnMetadata,
    ) -> Result<ScriptBuf, String> {
        let encoded = metadata
            .encode()
            .map_err(|e| format!("Failed to encode metadata: {}", e))?;

        // Create PushBytesBuf from encoded bytes
        let push_bytes = bitcoin::script::PushBytesBuf::try_from(encoded)
            .map_err(|e| format!("Failed to create PushBytesBuf: {}", e))?;

        Ok(Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(&push_bytes)
            .into_script())
    }

    /// Creates a new Bitcoin transaction.
    pub fn create_transaction(
        &self,
        prev_script: &ScriptBuf,
        value: u64,
        pubkey_hash: [u8; 20],
    ) -> Result<Transaction, String> {
        let tx_in = TxIn {
            previous_output: OutPoint::default(),
            script_sig: prev_script.clone(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let script_pubkey = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_DUP)
            .push_opcode(bitcoin::opcodes::all::OP_HASH160)
            .push_slice(&pubkey_hash)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();

        let tx_out = TxOut {
            value,
            script_pubkey,
        };

        let tx = Transaction {
            version: 2,
            lock_time: locktime::absolute::LockTime::ZERO,
            input: vec![tx_in],
            output: vec![tx_out],
        };

        Ok(tx)
    }

    /// Verifies HTLC parameters against a preimage.
    pub async fn verify_htlc(
        &self,
        state: &BitcoinLockState,
        preimage: &[u8],
    ) -> Result<bool, String> {
        match &state.htlc_params {
            Some(params) => params
                .verify_hashlock(preimage)
                .map_err(|e| format!("Failed to verify hashlock: {}", e)),
            None => Err("HTLC parameters not found".to_string()),
        }
    }

    /// Creates a new BitcoinLockState.
    pub fn create_lock_state(
        &self,
        lock_amount: u64,
        lock_script_hash: [u8; 32],
        lock_height: u64,
        pubkey_hash: [u8; 20],
        sequence: u32,
        nonce: u64,
        htlc_params: Option<HTLCParameters>,
        stealth_address: Option<StealthAddress>,
    ) -> Result<BitcoinLockState, String> {
        BitcoinLockState::new(
            lock_amount,
            lock_script_hash,
            lock_height,
            pubkey_hash,
            sequence,
            nonce,
            htlc_params,
            stealth_address,
        )
        .map_err(|e| format!("Failed to create lock state: {}", e))
    }

    /// Adds a state to the cache.
    pub async fn cache_state(
        &self,
        state_hash: [u8; 32],
        state_data: Vec<u8>,
    ) -> Result<(), String> {
        let mut cache = self.state_cache.write().await;
        cache.insert(state_hash, state_data);
        Ok(())
    }

    /// Retrieves a state from the cache.
    pub async fn get_cached_state(&self, state_hash: [u8; 32]) -> Option<Vec<u8>> {
        let cache = self.state_cache.read().await;
        cache.get(&state_hash).cloned()
    }
}