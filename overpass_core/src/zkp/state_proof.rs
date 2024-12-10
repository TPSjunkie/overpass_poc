// src/zkp/state_proof.rs

use serde::{Serialize, Deserialize};

/// A 32-byte array, representing bytes32 in Python.
pub type Bytes32 = [u8; 32];

/// Zero-knowledge proof of state transition validity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    /// The proof itself.
    pub pi: Bytes32,
    /// Publicly verifiable inputs.
    pub public_inputs: Vec<Bytes32>,
    /// Proof generation timestamp.
    pub timestamp: u64,
}