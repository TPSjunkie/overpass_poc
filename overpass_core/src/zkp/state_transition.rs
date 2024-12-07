// src/zkp/state_transition.rs

use anyhow::{anyhow, ensure, Context, Result};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{Hasher, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use plonky2_field::types::Field;

type C = PoseidonGoldilocksConfig;

/// Represents a state transition circuit using Plonky2.
pub struct StateTransitionCircuit {
    circuit_data: CircuitData<GoldilocksField, C, 2>,
    // Public input targets
    current_state_inputs: [HashOutTarget; 1], // Using 1 HashOutTarget to group all elements
    next_state_inputs: [HashOutTarget; 1],
    // Private input target
    transition_data_target: HashOutTarget,
}

impl StateTransitionCircuit {
    /// Constructs a new state transition circuit.
    pub fn new() -> Self {
        // Define the circuit configuration
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Add public input targets for current_state and next_state
        let current_state_inputs = [builder.add_virtual_hash()];
        let next_state_inputs = [builder.add_virtual_hash()];

        // Register all public inputs
        builder.register_public_inputs(&current_state_inputs[0].elements);
        builder.register_public_inputs(&next_state_inputs[0].elements);

        // Add a virtual hash for transition data (private input)
        let transition_data_target = builder.add_virtual_hash();

        // Compute next_state as the Poseidon hash of current_state and transition_data
        let computed_next_state = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            vec![
                current_state_inputs[0].elements[0],
                transition_data_target.elements[0],
                current_state_inputs[0].elements[1],
                transition_data_target.elements[1],
                current_state_inputs[0].elements[2],
                transition_data_target.elements[2],
                current_state_inputs[0].elements[3],
                transition_data_target.elements[3],
            ],
        );

        // Enforce that the computed_next_state matches the provided next_state
        for i in 0..4 {
            builder.connect(computed_next_state.elements[i], next_state_inputs[0].elements[i]);
        }

        // Build the circuit data
        let circuit_data = builder.build::<C>();

        Self {
            circuit_data,
            current_state_inputs,
            next_state_inputs,
            transition_data_target,
        }
    }    /// Converts a `[u8; 32]` array to a `HashOut<GoldilocksField>`.
    fn to_hash_out(data: [u8; 32]) -> Result<HashOut<GoldilocksField>> {
        data.chunks(8)
            .map(|chunk| {
                let bytes = chunk
                    .try_into()
                    .context("Chunk size mismatch while converting to u64")?;
                Ok(GoldilocksField::from_canonical_u64(u64::from_le_bytes(bytes)))
            })
            .collect::<Result<Vec<_>>>()
            .map(|fields| HashOut::from_partial(&fields))
    }

    /// Generates a zero-knowledge proof for the state transition.
    ///
    /// # Arguments
    ///
    /// * `current_state` - A 32-byte array representing the current state.
    /// * `next_state` - A 32-byte array representing the next state.
    /// * `transition_data` - A 32-byte array representing the transition data.
    ///
    /// # Returns
    ///
    /// A `ProofWithPublicInputs` if proof generation is successful.
    pub fn generate_proof(
        &self,
        current_state: [u8; 32],
        next_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, C, 2>> {
        // Validate input lengths
        ensure!(
            current_state.len() == 32 && next_state.len() == 32 && transition_data.len() == 32,
            "All inputs must be exactly 32 bytes"
        );

        let mut pw = PartialWitness::<GoldilocksField>::new();

        // Assign the transition data (private input)
        pw.set_hash_target(self.transition_data_target, Self::to_hash_out(transition_data)?)?;

        // Assign the current_state public inputs
        let current_state_hash = Self::to_hash_out(current_state)
            .context("Failed to convert current_state bytes to HashOut")?;
        for (i, input) in current_state_hash.elements.iter().enumerate() {
            pw.set_target(self.current_state_inputs[0].elements[i], *input)?;
        }

        // Assign the next_state public inputs
        let next_state_hash = Self::to_hash_out(next_state)
            .context("Failed to convert next_state bytes to HashOut")?;
        for (i, input) in next_state_hash.elements.iter().enumerate() {
            pw.set_target(self.next_state_inputs[0].elements[i], *input)?;
        }

        // Attempt to generate the proof
        let proof = self
            .circuit_data
            .prove(pw)
            .map_err(|e| anyhow!("Proof generation failed: {:?}", e))?;

        Ok(proof)
    }

    /// Verifies a zero-knowledge proof for the state transition.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, otherwise an error.
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, C, 2>,
    ) -> Result<bool> {
        self.circuit_data
            .verify(proof)
            .context("Proof verification failed")?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::plonk::config::Hasher;
    use plonky2_field::types::PrimeField64;
    use super::*;
    use anyhow::Result;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::hash::hash_types::HashOut;
    use rand::Rng;

    impl StateTransitionCircuit {
        /// Computes the Poseidon hash for testing purposes.
        fn compute_poseidon_hash(
            current_state: &HashOut<GoldilocksField>,
            transition_data: &HashOut<GoldilocksField>,
        ) -> HashOut<GoldilocksField> {
            let mut input = Vec::new();
            input.push(current_state.elements[0]);
            input.push(transition_data.elements[0]);
            input.push(current_state.elements[1]);
            input.push(transition_data.elements[1]);
            input.push(current_state.elements[2]);
            input.push(transition_data.elements[2]);
            input.push(current_state.elements[3]);
            input.push(transition_data.elements[3]);
            PoseidonHash::hash_no_pad(&input)
        }

        /// Converts a `HashOut<GoldilocksField>` back to a `[u8; 32]` array.
        fn hash_out_to_bytes(hash: &HashOut<GoldilocksField>) -> [u8; 32] {
            let mut bytes = [0u8; 32];
            for (i, field_elem) in hash.elements.iter().enumerate() {
                bytes[i * 8..(i + 1) * 8]
                    .copy_from_slice(&field_elem.to_canonical_u64().to_le_bytes());
            }
            bytes
        }
    }

    #[test]
    fn test_state_transition_circuit() -> Result<()> {
        let circuit = StateTransitionCircuit::new();

        let mut rng = rand::thread_rng();
        let current_state_bytes: [u8; 32] = rng.gen();
        let transition_data_bytes: [u8; 32] = rng.gen();

        let current_state_hash = StateTransitionCircuit::to_hash_out(current_state_bytes)
            .context("Failed to convert current_state bytes to HashOut")?;
        let transition_data_hash = StateTransitionCircuit::to_hash_out(transition_data_bytes)
            .context("Failed to convert transition_data bytes to HashOut")?;
        let computed_next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state_hash, &transition_data_hash);
        let next_state_bytes = StateTransitionCircuit::hash_out_to_bytes(&computed_next_state);

        let proof = circuit
            .generate_proof(current_state_bytes, next_state_bytes, transition_data_bytes)
            .context("Proof generation failed")?;

        let is_valid = circuit
            .verify_proof(proof)
            .context("Proof verification failed")?;
        assert!(is_valid, "The proof should be valid");

        Ok(())
    }

    #[test]
    fn test_invalid_inputs() -> Result<()> {
        let circuit = StateTransitionCircuit::new();

        let current_state = [0u8; 32];
        let transition_data = [0u8; 32];

        let current_state_hash = StateTransitionCircuit::to_hash_out(current_state)?;
        let transition_data_hash = StateTransitionCircuit::to_hash_out(transition_data)?;
        let next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state_hash, &transition_data_hash);
        let next_state_bytes = StateTransitionCircuit::hash_out_to_bytes(&next_state);

        let result = circuit.generate_proof(current_state, next_state_bytes, transition_data);
        assert!(result.is_ok(), "Proof generation should succeed with valid inputs");

        Ok(())
    }

    #[test]
    fn test_edge_case_zeroed_states() -> Result<()> {
        let circuit = StateTransitionCircuit::new();

        let zero_state = [0u8; 32];
        let transition_data = [0u8; 32];

        let current_state_hash = StateTransitionCircuit::to_hash_out(zero_state)?;
        let transition_data_hash = StateTransitionCircuit::to_hash_out(transition_data)?;
        let next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state_hash, &transition_data_hash);
        let next_state_bytes = StateTransitionCircuit::hash_out_to_bytes(&next_state);

        let proof = circuit
            .generate_proof(zero_state, next_state_bytes, transition_data)
            .context("Proof generation failed for zeroed states")?;

        let is_valid = circuit
            .verify_proof(proof)
            .context("Proof verification failed for zeroed states")?;
        assert!(is_valid, "The proof for zeroed states should be valid");

        Ok(())
    }

    #[test]
    fn test_invalid_proof() -> Result<()> {
        let circuit = StateTransitionCircuit::new();

        let mut rng = rand::thread_rng();
        let current_state_bytes: [u8; 32] = rng.gen();
        let transition_data_bytes: [u8; 32] = rng.gen();

        let current_state_hash = StateTransitionCircuit::to_hash_out(current_state_bytes)?;
        let transition_data_hash = StateTransitionCircuit::to_hash_out(transition_data_bytes)?;
        let next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state_hash, &transition_data_hash);
        let next_state_bytes = StateTransitionCircuit::hash_out_to_bytes(&next_state);

        let proof = circuit
            .generate_proof(current_state_bytes, next_state_bytes, transition_data_bytes)
            .context("Proof generation failed")?;

        let mut invalid_proof = proof;
        for i in 0..4 {
            invalid_proof.public_inputs[i + 4] = GoldilocksField::ZERO;
        }

        let result = circuit.verify_proof(invalid_proof);
        assert!(result.is_err(), "Verification should fail for invalid proof");

        Ok(())
    }
}