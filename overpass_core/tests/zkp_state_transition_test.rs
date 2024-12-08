// tests/zkp_state_transition_test.rs

use overpass_core::zkp::state_transition::StateTransitionCircuit;
use anyhow::Result;
use rand::Rng;

#[test]
fn test_state_transition_proof_generation_and_verification() -> Result<()> {
    // Initialize random number generator
    let mut rng = rand::thread_rng();

    // Generate random current state and transition data
    let current_state: [u8; 32] = rng.gen();
    let transition_data: [u8; 32] = rng.gen();

    // Compute next state using Poseidon hash
    let current_state_hash = StateTransitionCircuit::to_hash_out(current_state)?;
    let transition_data_hash = StateTransitionCircuit::to_hash_out(transition_data)?;
    let computed_next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state_hash, &transition_data_hash);
    let next_state = StateTransitionCircuit::hash_out_to_bytes(&computed_next_state);

    // Generate proof
    let proof = StateTransitionCircuit::generate_proof(current_state, next_state, transition_data)?;

    // Verify proof
    let is_valid = StateTransitionCircuit::verify_proof(proof)?;
    assert!(is_valid, "Proof verification failed");

    Ok(())
}

#[test]
fn test_invalid_state_transition() -> Result<()> {
    // Initialize random number generator
    let mut rng = rand::thread_rng();

    // Generate random current state and transition data
    let current_state: [u8; 32] = rng.gen();
    let transition_data: [u8; 32] = rng.gen();

    // Tamper with next state to create an invalid transition
    let mut invalid_next_state = [0u8; 32];
    rng.fill(&mut invalid_next_state);

    // Attempt to generate proof with invalid next state
    let result = StateTransitionCircuit::generate_proof(current_state, invalid_next_state, transition_data);

    // Ensure proof generation fails
    assert!(result.is_err(), "Proof generation should fail for an invalid transition");

    Ok(())
}
