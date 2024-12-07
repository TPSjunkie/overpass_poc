// File: overpass_core/tests/zkp_state_transition_test.rs

use overpass_core::zkp::state_transition::StateTransitionCircuit;
use rand::Rng;

#[test]
fn test_state_transition_proof() {
    let circuit = StateTransitionCircuit::new();

    let current_state: [u8; 32] = [1; 32];
    let next_state: [u8; 32] = [2; 32];
    let transition_data: [u8; 32] = [3; 32];

    let proof = circuit
        .generate_proof(current_state, next_state, transition_data)
        .expect("Proof generation should succeed");

    let is_valid = circuit
        .verify_proof(proof)
        .expect("Proof verification should succeed");

    assert!(is_valid);
}