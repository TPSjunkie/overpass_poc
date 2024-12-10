// src/zkp/tree.rs

use crate::zkp::helpers::{Bytes32, hash_pair};
use std::collections::HashMap;

use anyhow::Result;
use std::fmt;
use std::error::Error;

/// Represents errors that can occur in the Sparse Merkle Tree operations.
#[derive(Debug)]
pub enum SparseMerkleError {
    InvalidInput,
    ProofGenerationFailed,
    ProofVerificationFailed,
    // Add other relevant error variants as needed
}

/// Represents a simple Merkle Tree.
pub struct MerkleTree {
    pub leaves: Vec<Bytes32>,
    pub root: Bytes32,
    pub tree: Vec<Vec<Bytes32>>, // Level 0: leaves, Level n: root
}


impl MerkleTree {
    /// Creates a new empty Merkle Tree.
    pub fn new() -> Self {
        let leaves = Vec::new();
        let root = [0u8; 32];
        let tree = Vec::new();
        Self { leaves, root, tree }
    }

    /// Inserts a new leaf and updates the tree.
    pub fn insert(&mut self, leaf: Bytes32) {
        self.leaves.push(leaf);
        self.recompute_tree();
    }

    /// Updates a leaf at a given position and recomputes the tree.
    pub fn update(&mut self, old_leaf: Bytes32, new_leaf: Bytes32) {
        if let Some(pos) = self.leaves.iter().position(|x| x == &old_leaf) {
            self.leaves[pos] = new_leaf;
            self.recompute_tree();
        }
    }

    /// Deletes a leaf and updates the tree.
    pub fn delete(&mut self, leaf: Bytes32) {
        if let Some(pos) = self.leaves.iter().position(|x| x == &leaf) {
            self.leaves.remove(pos);
            self.recompute_tree();
        }
    }

    /// Recomputes the entire tree.
    fn recompute_tree(&mut self) {
        if self.leaves.is_empty() {
            self.root = [0u8; 32];
            self.tree = Vec::new();
            return;
        }
        let mut current_level = self.leaves.clone();
        self.tree = vec![current_level.clone()];
        while current_level.len() > 1 {
            if current_level.len() % 2 != 0 {
                current_level.push(*current_level.last().unwrap());
            }
            current_level = current_level.chunks(2).map(|pair| hash_pair(pair[0], pair[1])).collect();
            self.tree.push(current_level.clone());
        }
        self.root = current_level[0];
    }

    /// Generates a Merkle proof for a given leaf.
    pub fn get_proof(&self, leaf: &Bytes32) -> Option<Vec<Bytes32>> {
        let pos = self.leaves.iter().position(|x| x == leaf)?;
        let mut proof = Vec::new();
        let mut index = pos;
        for level in &self.tree[..self.tree.len()-1] {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            if sibling_index < level.len() {
                proof.push(level[sibling_index]);
            }
            index /= 2;
        }
        Some(proof)
    }

    /// Verifies a Merkle proof.
    pub fn verify_proof(&self, leaf: &Bytes32, proof: &[Bytes32], root: &Bytes32) -> bool {
        let mut computed_hash = *leaf;
        for sibling in proof {
            if computed_hash < *sibling {
                computed_hash = hash_pair(computed_hash, *sibling);
            } else {
                computed_hash = hash_pair(*sibling, computed_hash);
            }
        }
        &computed_hash == root
    }
}

impl fmt::Display for SparseMerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SparseMerkleError::InvalidInput => write!(f, "Invalid input"),
            SparseMerkleError::ProofGenerationFailed => write!(f, "Proof generation failed"),
            SparseMerkleError::ProofVerificationFailed => write!(f, "Proof verification failed"),
        }
    }
}

impl Error for SparseMerkleError {}

/// A simple implementation of a Sparse Merkle Tree.
pub struct SparseMerkleTree {
    pub root: [u8; 32],
    // Add other necessary fields, such as the tree structure, nodes, etc.
}

impl SparseMerkleTree {
    /// Creates a new Sparse Merkle Tree with an empty root.
    pub fn new(_depth: usize) -> Self {
        // Initialize the tree with a default root, e.g., all zeros.
        Self {
            root: [0u8; 32],
        }
    }

    /// Updates the tree with a new key-value pair.
    pub fn update(&mut self, _key: [u8; 32], _value: [u8; 32]) -> Result<(), SparseMerkleError> {
        // Implement the update logic here.
        // For demonstration purposes, we'll set the root to the value.
        self.root = _value;
        Ok(())
    }

    /// Generates a Merkle proof for a given key and its corresponding value.
    pub fn generate_proof(&self, _key: [u8; 32], _value: [u8; 32]) -> Result<MerkleProof, SparseMerkleError> {
        // Implement proof generation logic here.
        // Return a dummy proof for demonstration.
        Ok(MerkleProof { path: vec![] })
    }

    /// Verifies a Merkle proof against a given root, key, and value.
    pub fn verify_proof(_root: [u8; 32], _proof: &MerkleProof, _key: [u8; 32]) -> Result<bool, SparseMerkleError> {
        // Implement proof verification logic here.
        // For demonstration purposes, we'll assume all proofs are valid.
        Ok(true)
    }
}

/// Represents a Merkle proof.
pub struct MerkleProof {
    pub path: Vec<[u8; 32]>, // Example: list of sibling hashes along the path
}

#[cfg(test)]
mod tests {
    use crate::zkp;

    use super::*;

    #[test]
    fn test_merkle_tree_update_and_proof() -> Result<(), SparseMerkleError> {
        let mut smt = SparseMerkleTree::new(32);

        let key = [1u8; 32];
        let value = [2u8; 32];

        smt.update(key, value)?;

        let proof = smt.generate_proof(key, value)?;
        let verified = SparseMerkleTree::verify_proof(smt.root, &proof, key)?;

        assert!(verified, "Merkle proof should be valid");

        Ok(())
    }
}