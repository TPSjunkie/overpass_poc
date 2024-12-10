// src/bitcoin/client.rs
// src/bitcoin/scripts.rs

use bitcoin::script::PushBytesBuf;
use bitcoin::script::Builder;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TxIn;
use bitcoin::Transaction;

use bitcoin::locktime;
use crate::bitcoin::bitcoin_types::{
    BitcoinLockState, HTLCParameters, StealthAddress, OpReturnMetadata,
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
/// Creates an OP_RETURN script with encoded metadata.


/// Creates an OP_RETURN script with encoded metadata.
pub fn create_op_return_script(
    &self,
    metadata: &OpReturnMetadata,
) -> Result<ScriptBuf, String> {
    let encoded = metadata
        .encode()
        .map_err(|e| format!("Failed to encode metadata: {}", e))?;

    let push_bytes = PushBytesBuf::try_from(encoded).map_err(|e| format!("Invalid metadata bytes: {}", e))?;

    Ok(Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&push_bytes)
        .into_script())
}    /// Creates a new Bitcoin transaction.
    /// This function creates a new Bitcoin transaction with the given parameters.
    /// It takes a previous script, a value, and a pubkey hash as input.
    /// It returns a `Transaction` object that represents the Bitcoin transaction.
    pub fn create_transaction(
        &self,
        _prev_script: &ScriptBuf,
        value: u64,
        _pubkey_hash: [u8; 20],
    ) -> Result<Transaction, String> {
        let mut tx = Transaction {
            version: 2,
            lock_time: locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        tx.input.push(TxIn {
            previous_output: OutPoint::default(),
            script_sig: ScriptBuf::default(),
            sequence: bitcoin::Sequence(0),
            witness: bitcoin::Witness::default(),
        });
        tx.output.push(bitcoin::TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        });        
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
#[cfg(test)]
mod tests {
    use crate::bitcoin::bitcoin_types::OpReturnMetadata;

    use super::*;
    use bitcoin::hashes::{sha256, Hash};

    #[test]
    fn test_create_htlc_parameters() {
        let client = BitcoinClient::new();
        let htlc = client.create_htlc_parameters(
            1_000_000,
            [1u8; 20],
            sha256::Hash::hash(&[0u8; 32]).to_byte_array(),
            144,
        );

        assert_eq!(htlc.amount, 1_000_000);
        assert_eq!(htlc.timeout_height, 144);
        assert_eq!(htlc.receiver, [1u8; 20]);
    }

    #[test]
    fn test_create_op_return_script() {
        let client = BitcoinClient::new();
        
        let metadata = OpReturnMetadata::new(
            [0u8; 32],
            1,
            sha256::Hash::hash(&[0u8; 32]).to_byte_array(),
            vec![1, 2, 3],
            None,
            1,
            [0u8; 32],
        );

        let script = client.create_op_return_script(&metadata);
        assert!(script.is_ok());
    }
    #[tokio::test]
    async fn test_verify_htlc() {
        let client = BitcoinClient::new();
        let preimage = [0u8; 32];
        let hash_lock = sha256::Hash::hash(&preimage).to_byte_array();

        let state = client
            .create_lock_state(
                1_000_000,
                [0u8; 32],
                100,
                [1u8; 20],
                0,
                0,
                Some(HTLCParameters {
                    amount: 1_000_000,
                    receiver: [1u8; 20],
                    hash_lock,
                    timeout_height: 144,
                }),
                None,
            )
            .unwrap();

        let valid = client.verify_htlc(&state, &preimage).await.unwrap();
        assert!(!valid);
    }
    #[tokio::test]
    async fn test_state_caching() {
        let client = BitcoinClient::new();
        let test_hash = [1u8; 32];
        let test_data = vec![1, 2, 3, 4];

        client
            .cache_state(test_hash, test_data.clone())
            .await
            .unwrap();
        let cached = client.get_cached_state(test_hash).await;

        assert_eq!(cached, Some(test_data));
    }
}