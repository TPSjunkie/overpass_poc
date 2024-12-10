// src/zkp/compressed_transaction.rs (continued)

use serde::{Serialize, Deserialize};

/// Type alias for bytes32.
pub type Bytes32 = [u8;32];

/// Efficient storage format for historical transactions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompressedTransaction {
    /// Transaction timestamp.
    pub timestamp: u64,
    /// Previous balance commitment.
    pub old_commitment: Bytes32,
    /// New balance commitment.
    pub new_commitment: Bytes32,
    /// Hash of transaction metadata.
    pub metadata_hash: Bytes32,
    /// Merkle root after this transaction.
    pub merkle_root: Bytes32,
}