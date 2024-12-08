// src/bitcoin/bitcoin_types.rs

use bitcoin::hashes::{sha256d, Hash, HashEngine};
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;

/// Represents a stealth address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthAddress {
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
    view_tag: [u8; 32],
}

impl StealthAddress {
    pub fn new(scan_pubkey: PublicKey, spend_pubkey: PublicKey, view_tag: [u8; 32]) -> Self {
        Self {
            scan_pubkey,
            spend_pubkey,
            view_tag,
        }
    }

    pub fn get_scan_pubkey(&self) -> &PublicKey {
        &self.scan_pubkey
    }

    pub fn get_spend_pubkey(&self) -> &PublicKey {
        &self.spend_pubkey
    }

    pub fn get_view_tag(&self) -> u8 {
        self.view_tag[0]
    }
}

#[derive(Error, Debug)]
pub enum BitcoinStateError {
    #[error("Invalid lock amount: {0}")]
    InvalidLockAmount(String),
    #[error("Invalid HTLC parameters: {0}")]
    InvalidHTLC(String),
    #[error("Invalid preimage: {0}")]
    InvalidPreimage(String),
    #[error("Verification failed: {0}")]
    VerificationError(String),
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Crypto error: {0}")]
    CryptoError(String),
    #[error("State error: {0}")]
    StateError(String),
}

/// Core HTLC Parameters
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HTLCParameters {
    pub amount: u64,
    pub receiver: [u8; 20],
    pub hash_lock: [u8; 32],
    pub timeout_height: u32,
}

impl HTLCParameters {
    pub fn new(amount: u64, receiver: [u8; 20], hash_lock: [u8; 32], timeout_height: u32) -> Self {
        Self {
            amount,
            receiver,
            hash_lock,
            timeout_height,
        }
    }

    pub fn check_timelock(&self, current_height: u32) -> bool {
        current_height >= self.timeout_height
    }

    pub fn verify_hashlock(&self, preimage: &[u8]) -> Result<bool, BitcoinStateError> {
        let hash = sha256d::Hash::hash(preimage);
        Ok(hash.to_byte_array() == self.hash_lock)
    }
}

/// OpReturn Metadata for HTLCs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpReturnMetadata {
    pub channel_id: [u8; 32],
    pub rebalancing_flags: u8,
    pub hash_lock: [u8; 32],
    pub data: Vec<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stealth_address: Option<StealthAddress>,
    pub version: i32,
    pub nonce: [u8; 32],
}

impl OpReturnMetadata {
    pub fn new(
        channel_id: [u8; 32],
        rebalancing_flags: u8,
        hash_lock: [u8; 32],
        data: Vec<i32>,
        stealth_address: Option<StealthAddress>,
        version: i32,
        nonce: [u8; 32],
    ) -> Self {
        Self {
            channel_id,
            rebalancing_flags,
            hash_lock,
            data,
            stealth_address,
            version,
            nonce,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, BitcoinStateError> {
        serde_json::to_vec(self).map_err(|e| BitcoinStateError::EncodingError(e.to_string()))
    }

    pub fn decode(data: &[u8]) -> Result<Self, BitcoinStateError> {
        serde_json::from_slice(data).map_err(|e| BitcoinStateError::EncodingError(e.to_string()))
    }
}

/// Bitcoin Lock State for Channel Management
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinLockState {
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

impl BitcoinLockState {
    pub fn new(
        lock_amount: u64,
        lock_script_hash: [u8; 32],
        lock_height: u64,
        pubkey_hash: [u8; 20],
        sequence: u32,
        nonce: u64,
        htlc_params: Option<HTLCParameters>,
        stealth_address: Option<StealthAddress>,
    ) -> Result<Self, BitcoinStateError> {
        if let Some(params) = &htlc_params {
            if lock_amount < params.amount {
                return Err(BitcoinStateError::InvalidLockAmount(
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

    pub async fn compute_state_hash(&self) -> Result<[u8; 32], BitcoinStateError> {
        let mut engine = sha256d::Hash::engine();

        engine.input(&self.lock_amount.to_le_bytes());
        engine.input(&self.lock_script_hash);
        engine.input(&self.lock_height.to_le_bytes());
        engine.input(&self.pubkey_hash);
        engine.input(&self.sequence.to_le_bytes());
        engine.input(&self.nonce.to_le_bytes());

        if let Some(htlc) = &self.htlc_params {
            let htlc_bytes =
                serde_json::to_vec(htlc).map_err(|e| BitcoinStateError::EncodingError(e.to_string()))?;
            engine.input(&htlc_bytes);
        }

        Ok(sha256d::Hash::from_engine(engine).to_byte_array())
    }

    pub async fn verify_state_transition(
        &self,
        next_state: &BitcoinLockState,
    ) -> Result<bool, BitcoinStateError> {
        if next_state.lock_height <= self.lock_height {
            return Ok(false);
        }

        if let Some(htlc) = &self.htlc_params {
            if let Some(next_htlc) = &next_state.htlc_params {
                return Ok(false);
            }
        }

        if next_state.nonce <= self.nonce {
            return Ok(false);
        }

        let current_hash = self.compute_state_hash().await?;
        let next_hash = next_state.compute_state_hash().await?;

        if current_hash == next_hash {
            return Ok(false);
        }

        let mut cache = self.state_cache.write().await;
        cache.insert(
            next_hash,
            serde_json::to_vec(next_state)
                .map_err(|e| BitcoinStateError::EncodingError(e.to_string()))?,
        );

        Ok(true)
    }}