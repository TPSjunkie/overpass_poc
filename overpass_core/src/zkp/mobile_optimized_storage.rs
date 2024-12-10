// src/zkp/mobile_optimized_storage.rs
use std::num::NonZero;
use crate::zkp::channel::ChannelState;
/// Local Storage Layer (Level 3)
/// Hybrid hot/cold storage optimized for mobile devices.

use crate::zkp::compressed_transaction::CompressedTransaction;
use crate::zkp::helpers::{Bytes32, compute_merkle_root as other_compute_merkle_root};
use crate::zkp::state_proof::StateProof;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Represents errors in storage operations.
#[derive(Debug)]
pub enum StorageError {
    TransactionTooOld,
    StorageLimitExceeded,
    Other(String),
}

/// MobileOptimizedStorage handles hybrid hot/cold storage for mobile devices.
pub struct MobileOptimizedStorage {
    /// Hot storage (active data): channels and recent transactions.
    active_channels: LruCache<Bytes32, ChannelState>,
    recent_transactions: LruCache<Bytes32, Vec<CompressedTransaction>>,
    
    /// Cold storage (compressed historical data).
    transaction_history: HashMap<Bytes32, Vec<CompressedTransaction>>,
    channel_roots: HashMap<Bytes32, Bytes32>,
    
    /// Performance parameters.
    compression_threshold: usize, // Number of transactions before compression
    retention_period: u64,        // Retention period in seconds
}

impl MobileOptimizedStorage {
    /// Creates a new MobileOptimizedStorage instance.
    pub fn new(compression_threshold: usize, retention_period: u64) -> Self {
        Self {
            active_channels: LruCache::new(NonZero::new(5).unwrap()),
            recent_transactions: LruCache::new(NonZero::new(100).unwrap()),
            transaction_history: HashMap::new(),
            channel_roots: HashMap::new(),
            compression_threshold,
            retention_period,
        }
    }
    
    /// Stores a transaction, possibly compressing history.
    pub fn store_transaction(
        &mut self,
        channel_id: Bytes32,
        old_commitment: Bytes32,
        new_commitment: Bytes32,
        proof: StateProof,
        metadata: serde_json::Value,
    ) -> Result<(), StorageError> {
        let timestamp = proof.timestamp;
        let metadata_hash = sha256_hash(&serde_json::to_vec(&metadata).map_err(|e| StorageError::Other(e.to_string()))?);
        let merkle_root = compute_merkle_root(&self.transaction_history, &channel_id);
        
        let compressed_tx = CompressedTransaction {
            timestamp,
            old_commitment,
            new_commitment,
            metadata_hash,
            merkle_root,
        };
        
        // Add to recent transactions
        if let Some(txs) = self.recent_transactions.get_mut(&channel_id) {
            txs.push(compressed_tx.clone());
            if txs.len() >= self.compression_threshold {
                self.compress_transactions(channel_id)?;
            }
        } else {
            self.recent_transactions.put(channel_id, vec![compressed_tx.clone()]);
        }
        
        // Add to transaction history
        self.transaction_history
            .entry(channel_id)
            .or_insert_with(Vec::new)
            .push(compressed_tx);
        
        Ok(())
    }    
    /// Compresses transactions for a channel.
    fn compress_transactions(&mut self, channel_id: Bytes32) -> Result<(), StorageError> {
        if let Some(recent_txs) = self.recent_transactions.pop(&channel_id) {
            if recent_txs.is_empty() {
                return Ok(());
            }
            // Compress recent_txs into one
            let compressed = CompressedTransaction {
                timestamp: recent_txs.last().unwrap().timestamp,
                old_commitment: recent_txs.first().unwrap().old_commitment,
                new_commitment: recent_txs.last().unwrap().new_commitment,
                metadata_hash: sha256_hash(&serialize_metadata(&recent_txs)),
                merkle_root: compute_merkle_root(&self.transaction_history, &channel_id),
            };
            // Add to history
            self.transaction_history
                .entry(channel_id)
                .or_insert_with(Vec::new)
                .push(compressed);
        }
        Ok(())
    }
}

/// Computes SHA256 hash.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Serializes metadata for hashing.
fn serialize_metadata(txs: &[CompressedTransaction]) -> Vec<u8> {
    serde_json::to_vec(txs).unwrap_or_default()
}

/// Computes Merkle root from transaction history for a channel.
fn compute_merkle_root(transaction_history: &HashMap<Bytes32, Vec<CompressedTransaction>>, channel_id: &Bytes32) -> [u8; 32] {
    if let Some(txs) = transaction_history.get(channel_id) {
        let leaves: Vec<[u8; 32]> = txs.iter().map(|tx| tx.merkle_root).collect();
        compute_merkle_root_helper(leaves)
    } else {
        [0u8; 32]
    }
}

/// Computes the Merkle root from a list of leaves.
fn compute_merkle_root_helper(leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut current_level = leaves;
    while current_level.len() > 1 {
        if current_level.len() % 2 != 0 {
            current_level.push(*current_level.last().unwrap());
        }
        current_level = current_level
            .chunks(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
    }
    current_level[0]
}

/// Hashes two bytes32 together to form a parent node.
fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&left);
    hasher.update(&right);
    let result = hasher.finalize();
    let mut parent = [0u8; 32];
    parent.copy_from_slice(&result);
    parent
}