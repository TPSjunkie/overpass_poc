// src/zkp/helpers.rs

use std::time::UNIX_EPOCH;
use std::time::SystemTime;

/// Helper functions and type definitions for Zero-Knowledge Proofs.

use sha2::{Sha256, Digest};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;

use serde::{Serialize, Deserialize};

// Import PedersenParameters from pedersen_parameters module
use crate::zkp::pedersen_parameters::PedersenParameters;

/// Type alias for bytes32.
pub type Bytes32 = [u8; 32];

/// Represents a Point on the elliptic curve.
pub type Point = RistrettoPoint;

/// Generates a random blinding factor.
pub fn generate_random_blinding() -> [u8; 32] {
    let mut rng = OsRng;
    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding);
    blinding
}

/// Computes Pedersen commitment.
pub fn pedersen_commit(value: u64, blinding: [u8; 32], hparams: &PedersenParameters) -> Bytes32 {
    let value_scalar = Scalar::from(value);
    let blinding_scalar = Scalar::from_bytes_mod_order(blinding);
    let commitment = hparams.g * value_scalar + hparams.h * blinding_scalar;
    hash_point(commitment)
}

/// Hashes a RistrettoPoint to bytes32 using SHA256.
pub fn hash_point(point: Point) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(point.compress().as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Computes the Merkle root from wallet roots.
pub fn compute_global_root(wallet_roots: &HashMap<Bytes32, Bytes32>) -> Bytes32 {
    let leaves: Vec<Bytes32> = wallet_roots.values().cloned().collect();
    compute_merkle_root(leaves)
}

/// Computes the Merkle root from channel state.
pub fn compute_channel_root(channel_id: Bytes32, commitment: Bytes32, nonce: u64) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(&channel_id);
    hasher.update(&commitment);
    hasher.update(&nonce.to_le_bytes());
    let result = hasher.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&result);
    root
}

/// Computes Merkle root from list of leaves.
pub fn compute_merkle_root(leaves: Vec<Bytes32>) -> Bytes32 {
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

/// Hashes two bytes32 together to form parent node.
pub fn hash_pair(left: Bytes32, right: Bytes32) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(&left);
    hasher.update(&right);
    let result = hasher.finalize();
    let mut parent = [0u8; 32];
    parent.copy_from_slice(&result);
    parent
}

/// Current Unix timestamp.
pub fn current_timestamp() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    now.as_secs()
}

/// Represents a state proof for wallet updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    pub pi: [u8; 32],
    pub public_inputs: Vec<Bytes32>,
    pub timestamp: u64,
    params: PedersenParameters,
}

/// Verify a wallet proof.
pub fn verify_wallet_proof(
    old_root: &Bytes32,
    new_root: &Bytes32,
    proof: &StateProof,
    params: &PedersenParameters,
) -> bool {
    // Verify timestamp is recent enough (within last hour)
    let current_time = current_timestamp();
    if current_time - proof.timestamp > 3600 {
        return false;
    }

    // Verify public inputs contain the old and new roots
    if proof.public_inputs.len() < 2 {
        return false;
    }
    if proof.public_inputs[0] != *old_root || proof.public_inputs[1] != *new_root {
        return false;
    }

    // Verify the proof using the Pedersen parameters
    let mut hasher = Sha256::new();
    hasher.update(&proof.pi);
    for input in &proof.public_inputs {
        hasher.update(input);
    }
    hasher.update(params.g.compress().as_bytes());
    hasher.update(params.h.compress().as_bytes());
    
    let result = hasher.finalize();
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&result);
    
    // Verify the proof matches the expected hash
    proof.pi == expected
}

/// Verifies a zero-knowledge proof using Pedersen commitments.
/// This is a basic implementation that should be replaced with a proper ZK proof system.
pub fn verify_zk_proof(
    proof: &[u8; 32],
    public_inputs: &[Bytes32],
    params: &PedersenParameters,
) -> bool {
    // Basic verification logic:
    // 1. Check proof length
    if proof.len() != 32 {
        return false;
    }

    // 2. Check public inputs are present
    if public_inputs.is_empty() {
        return false;
    }

    // 3. Verify proof against public inputs using Pedersen parameters
    // This is a simplified check - replace with actual cryptographic verification
    let mut hasher = Sha256::new();
    hasher.update(proof);
    for input in public_inputs {
        hasher.update(input);
    }
    hasher.update(params.g.compress().as_bytes());
    hasher.update(params.h.compress().as_bytes());
    
    let result = hasher.finalize();
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&result);
    
    // Compare proof against expected hash
    // In a real implementation, this would be replaced with actual ZK verification
    proof == &expected
}

/// Generates a zero-knowledge proof of state transition.
/// Replace with actual ZK proof generation logic using a library like Plonky2.
pub fn generate_state_proof(
    old_commitment: Bytes32,
    new_commitment: Bytes32,
    merkle_root: Bytes32,
    params: &PedersenParameters,
) -> StateProof {
    // Create a basic proof structure using SHA-256
    // Note: This is a simplified implementation and should be replaced with proper ZK proofs
    let mut hasher = Sha256::new();
    
    // Add all inputs to the hash
    hasher.update(&old_commitment);
    hasher.update(&new_commitment);
    hasher.update(&merkle_root);
    
    // Add current timestamp to the proof
    let timestamp = current_timestamp();
    hasher.update(&timestamp.to_le_bytes());

    // Generate the proof
    let result = hasher.finalize();
    let mut pi = [0u8; 32];
    pi.copy_from_slice(&result);
    
    // Create and return the state proof
    StateProof {
        pi,
        public_inputs: vec![old_commitment, new_commitment, merkle_root],
        timestamp,
        params: params.clone(),
    }
}