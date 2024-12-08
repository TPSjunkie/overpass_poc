// src/zkp/state_transition.rs

use plonky2::iop::witness::WitnessWrite;
use plonky2_field::types::PrimeField64;
use plonky2::plonk::config::Hasher;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2_field::types::Field;
use anyhow::{anyhow, Context, Result};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::HashOut,
        poseidon::PoseidonHash,
    },
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};

type C = PoseidonGoldilocksConfig;

/// Represents a state transition circuit using Plonky2.
pub struct StateTransitionCircuit;

impl StateTransitionCircuit {
    /// Constructs a new state transition circuit and returns the CircuitData along with input targets.
    fn build_circuit() -> (
        CircuitData<GoldilocksField, C, 2>,
        [HashOutTarget; 1],
        [HashOutTarget; 1],
        HashOutTarget,
    ) {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let current_state_inputs = [builder.add_virtual_hash()];
        let next_state_inputs = [builder.add_virtual_hash()];

        builder.register_public_inputs(&current_state_inputs[0].elements);
        builder.register_public_inputs(&next_state_inputs[0].elements);

        let transition_data_target = builder.add_virtual_hash();

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

        for i in 0..4 {
            builder.connect(computed_next_state.elements[i], next_state_inputs[0].elements[i]);
        }

        let circuit_data = builder.build::<C>();

        (circuit_data, current_state_inputs, next_state_inputs, transition_data_target)
    }

    /// Converts a `[u8; 32]` array to a `HashOut<GoldilocksField>`.
    pub fn to_hash_out(data: [u8; 32]) -> Result<HashOut<GoldilocksField>> {
        data.chunks(8)
            .map(|chunk| {
                let bytes = chunk
                    .try_into()
                    .with_context(|| "Chunk size mismatch while converting to u64")?;
                Ok(GoldilocksField::from_canonical_u64(u64::from_le_bytes(bytes)))
            })
            .collect::<Result<Vec<_>>>()
            .map(|fields| HashOut::from_partial(&fields))
    }

    /// Computes the Poseidon hash.
    pub fn compute_poseidon_hash(
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
    pub fn hash_out_to_bytes(hash: &HashOut<GoldilocksField>) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, field_elem) in hash.elements.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8]
                .copy_from_slice(&field_elem.to_canonical_u64().to_le_bytes());
        }
        bytes
    }

    /// Generates a zero-knowledge proof for the state transition.
    pub fn generate_proof(
        current_state: [u8; 32],
        next_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, C, 2>> {
        // Build a fresh circuit for each proof
        let (circuit_data, current_state_inputs, next_state_inputs, transition_data_target) = Self::build_circuit();

        let mut pw = PartialWitness::<GoldilocksField>::new();

        // Assign the transition data (private input)
        pw.set_hash_target(transition_data_target, Self::to_hash_out(transition_data)?)?;

        // Assign the current_state public inputs
        let current_state_hash = Self::to_hash_out(current_state)
            .context("Failed to convert current_state bytes to HashOut")?;
        for (i, input) in current_state_hash.elements.iter().enumerate() {
            pw.set_target(current_state_inputs[0].elements[i], *input)?;
        }

        // Assign the next_state public inputs
        let next_state_hash = Self::to_hash_out(next_state)
            .context("Failed to convert next_state bytes to HashOut")?;
        for (i, input) in next_state_hash.elements.iter().enumerate() {
            pw.set_target(next_state_inputs[0].elements[i], *input)?;
        }

        // Generate the proof using the fresh circuit_data
        let proof = circuit_data.prove(pw).map_err(|e| anyhow!("Proof generation failed: {:?}", e))?;
        Ok(proof)
    }

    /// Verifies a zero-knowledge proof for the state transition.
    pub fn verify_proof(
        proof: ProofWithPublicInputs<GoldilocksField, C, 2>,
    ) -> Result<bool> {
        // Build a fresh circuit for verification
        let (circuit_data, _, _, _) = Self::build_circuit();

        // Verify the proof
        circuit_data.verify(proof)
            .with_context(|| "Proof verification failed")?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_state_transition_circuit() -> Result<()> {
        // Initialize random number generator
        let mut rng = rand::thread_rng();

        // Generate random current state and transition data
        let current_state_bytes: [u8; 32] = rng.gen();
        let transition_data_bytes: [u8; 32] = rng.gen();

        // Compute next state using Poseidon hash
        let current_state_hash = StateTransitionCircuit::to_hash_out(current_state_bytes)?;
        let transition_data_hash = StateTransitionCircuit::to_hash_out(transition_data_bytes)?;
        let computed_next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state_hash, &transition_data_hash);
        let next_state_bytes = StateTransitionCircuit::hash_out_to_bytes(&computed_next_state);

        // Generate proof
        let proof = StateTransitionCircuit::generate_proof(current_state_bytes, next_state_bytes, transition_data_bytes)
            .context("Proof generation failed")?;

        // Verify proof
        let is_valid = StateTransitionCircuit::verify_proof(proof)
            .context("Proof verification failed")?;
        assert!(is_valid, "The proof should be valid");

        Ok(())
    }

    #[test]
    fn test_invalid_proof() -> Result<()> {
        // Initialize random number generator
        let mut rng = rand::thread_rng();

        // Generate random current state and transition data
        let current_state_bytes: [u8; 32] = rng.gen();
        let transition_data_bytes: [u8; 32] = rng.gen();

        // Compute next state using Poseidon hash
        let current_state_hash = StateTransitionCircuit::to_hash_out(current_state_bytes)?;
        let transition_data_hash = StateTransitionCircuit::to_hash_out(transition_data_bytes)?;
        let computed_next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state_hash, &transition_data_hash);
        let next_state_bytes = StateTransitionCircuit::hash_out_to_bytes(&computed_next_state);

        // Generate proof
        let proof = StateTransitionCircuit::generate_proof(current_state_bytes, next_state_bytes, transition_data_bytes)
            .context("Proof generation failed")?;

        // Tamper with the public inputs to invalidate the proof
        let mut tampered_proof = proof.clone();
        for input in tampered_proof.public_inputs.iter_mut() {
            *input = GoldilocksField::ZERO;
        }

        // Attempt to verify tampered proof
        let result = StateTransitionCircuit::verify_proof(tampered_proof);
        assert!(result.is_err(), "Verification should fail for tampered proof");

        Ok(())
    }
}
