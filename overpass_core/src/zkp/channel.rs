// src/zkp/channel.rs

use plonky2_field::types::PrimeField64;
use plonky2_field::types::Field;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use crate::zkp::tree::{SparseMerkleError, SparseMerkleTree};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::Hasher;
use plonky2::hash::poseidon::PoseidonHash;

/// Represents the state of a channel.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChannelState {
    pub balances: Vec<u64>,
    pub nonce: u64,
    pub metadata: Vec<u8>,
    pub merkle_root: [u8; 32],
    pub(crate) proof: Option<Vec<u8>>,
}


impl ChannelState {
    /// Converts the ChannelState into a 32-byte hash using PoseidonHash.
    pub fn hash_state(&self) -> Result<[u8; 32]> {
        // Serialize the entire state using serde_json for consistency
        let serialized = serde_json::to_vec(self).context("Serialization failed")?;

        // Convert serialized bytes to field elements
        let mut inputs = Vec::new();
        for chunk in serialized.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            inputs.push(GoldilocksField::from_canonical_u64(u64::from_le_bytes(bytes)));
        }

        // Compute Poseidon hash
        let hash_out = PoseidonHash::hash_no_pad(&inputs);

        // Convert HashOut to bytes
        let mut bytes = [0u8; 32];
        for (i, &element) in hash_out.elements.iter().enumerate() {
            let elem_u64 = element.to_canonical_u64();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem_u64.to_le_bytes());
        }

        Ok(bytes)
    }

    /// Verifies that the transition from old_state to self is valid.
    pub fn verify_transition(&self, old_state: &ChannelState) -> bool {
        // Example verification: nonce should increment and balances should not be negative
        if self.nonce != old_state.nonce + 1 {
            return false;
        }
        if self.balances.len() != old_state.balances.len() {
            return false;
        }
        for (new_balance, old_balance) in self.balances.iter().zip(old_state.balances.iter()) {
            if *new_balance < *old_balance {
                return false;
            }
        }
        true
    }

    /// Updates the Sparse Merkle Tree with the new state.
    pub fn update_in_tree(
        &self,
        smt: &mut SparseMerkleTree,
        old_state: &ChannelState,
        _old_key: [u8; 32],
        new_key: [u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), SparseMerkleError> {
        if !self.verify_transition(old_state) {
            return Err(SparseMerkleError::InvalidInput);
        }

        let new_leaf = self.hash_state().map_err(|_| SparseMerkleError::InvalidInput)?;

        smt.update(new_key, new_leaf)?;

        let new_root = smt.root;

        Ok((new_leaf, new_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::tree::SparseMerkleTree;

    #[test]
    fn test_state_transition_with_smt() -> Result<(), SparseMerkleError> {
        let mut smt = SparseMerkleTree::new(32);

        let old_state = ChannelState {
            balances: vec![100, 50],
            nonce: 15,
            metadata: vec![1, 2, 3],
            merkle_root: [0u8; 32],
            proof: None,
        };
        let old_key = [1u8; 32];
        let old_leaf = old_state.hash_state().unwrap();

        smt.update(old_key, old_leaf).unwrap();

        let new_state = ChannelState {
            balances: vec![103, 53],
            nonce: 16,
            metadata: vec![1, 2, 3, 4],
            merkle_root: [0u8; 32],
            proof: None,
        };
        let new_key = [1u8; 32];

        let (new_leaf, new_root) = new_state.update_in_tree(&mut smt, &old_state, old_key, new_key).unwrap();

        let proof = smt.generate_proof(new_key, new_leaf).unwrap();
        let verified = SparseMerkleTree::verify_proof(smt.root, &proof, new_key).unwrap();
        assert!(verified, "Proof of new state should be valid");

        Ok(())
    }
}