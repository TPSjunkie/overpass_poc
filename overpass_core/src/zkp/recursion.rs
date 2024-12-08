// src/zkp/recursion.rs

use anyhow::{anyhow, Result};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};

use crate::zkp::state_transition::StateTransitionCircuit;

type C = PoseidonGoldilocksConfig;

/// Manages state transition proofs with recursion capabilities.
pub struct StateTransitionCircuitWithRecursion {
    recursive_proofs: Vec<ProofWithPublicInputs<GoldilocksField, C, 2>>,
    max_recursive_depth: usize,
}

impl StateTransitionCircuitWithRecursion {
    /// Creates a new instance with default maximum recursive depth.
    pub fn new() -> Self {
        Self {
            recursive_proofs: Vec::new(),
            max_recursive_depth: 32,
        }
    }

    /// Generates a zero-knowledge proof for the state transition and manages recursion.
    ///
    /// # Arguments
    ///
    /// * `current_state` - A 32-byte array representing the current state.
    /// * `transition_data` - A 32-byte array representing the transition data.
    ///
    /// # Returns
    ///
    /// A `ProofWithPublicInputs` if proof generation is successful.
    pub fn generate_proof(
        &mut self,
        current_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, C, 2>> {
        // Check if we've reached the maximum recursive depth
        if self.recursive_proofs.len() >= self.max_recursive_depth {
            return Err(anyhow!("Maximum recursive depth reached"));
        }

        // Compute the next state using Poseidon hash
        let current_state_hash = StateTransitionCircuit::to_hash_out(current_state)?;
        let transition_data_hash = StateTransitionCircuit::to_hash_out(transition_data)?;
        let computed_next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state_hash, &transition_data_hash);
        let next_state = StateTransitionCircuit::hash_out_to_bytes(&computed_next_state);

        // Validate state transition before generating proof
        if !Self::validate_state_transition(&current_state, &next_state, &transition_data) {
            return Err(anyhow!("Invalid state transition"));
        }

        // Generate proof using static method
        let proof = StateTransitionCircuit::generate_proof(current_state, next_state, transition_data)?;
        self.recursive_proofs.push(proof.clone());
        Ok(proof)
    }

    /// Validates the state transition.
    ///
    /// # Arguments
    ///
    /// * `current` - Reference to the current state bytes.
    /// * `next` - Reference to the next state bytes.
    /// * `data` - Reference to the transition data bytes.
    ///
    /// # Returns
    ///
    /// `true` if the state transition is valid, otherwise `false`.
    fn validate_state_transition(current: &[u8; 32], next: &[u8; 32], data: &[u8; 32]) -> bool {
        // Verify that the current state is valid (non-zero)
        if current.iter().all(|&x| x == 0) {
            return false;
        }

        // Verify that the next state is valid (non-zero)
        if next.iter().all(|&x| x == 0) {
            return false;
        }

        // Verify that transition data is valid (non-zero)
        if data.iter().all(|&x| x == 0) {
            return false;
        }

        // Verify that states are different
        if current == next {
            return false;
        }
        
        true
    }

    /// Verifies a zero-knowledge proof and all recursive proofs.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify.
    ///
    /// # Returns
    ///
    /// `true` if all proofs are valid, otherwise an error.
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, C, 2>,
    ) -> Result<bool> {
        // Verify the main proof
        StateTransitionCircuit::verify_proof(proof.clone())?;
        
        // Verify all recursive proofs
        for recursive_proof in &self.recursive_proofs {
            StateTransitionCircuit::verify_proof(recursive_proof.clone())?;
        }
        
        Ok(true)
    }

    /// Returns the current recursive depth.
    pub fn get_recursive_depth(&self) -> usize {
        self.recursive_proofs.len()
    }

    /// Returns the maximum allowed recursive depth.
    pub fn get_max_recursive_depth(&self) -> usize {
        self.max_recursive_depth
    }

    /// Sets a new maximum recursive depth.
    ///
    /// # Arguments
    ///
    /// * `depth` - The new maximum recursive depth.
    pub fn set_max_recursive_depth(&mut self, depth: usize) {
        self.max_recursive_depth = depth;
    }

    /// Clears all recursive proofs.
    pub fn clear_recursive_proofs(&mut self) {
        self.recursive_proofs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_recursive_proof_aggregation() -> Result<()> {
        let mut circuit = StateTransitionCircuitWithRecursion::new();
        
        // Define initial state and transition data
        let initial_state = [1u8; 32];
        let transition_data = [2u8; 32];
        
        // Generate proof
        let proof = circuit.generate_proof(
            initial_state,
            transition_data,
        )?;

        // Verify the generated proof
        assert!(circuit.verify_proof(proof.clone())?, "The proof should be valid");
        
        // Verify recursive depth
        assert_eq!(circuit.get_recursive_depth(), 1, "Should have one proof in the chain");

        Ok(())
    }
}
