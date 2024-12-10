use plonky2_field::goldilocks_field::GoldilocksField;
use anyhow::{anyhow, Result};
use bitcoin::{
    absolute::LockTime,
    consensus::encode,
    blockdata::{
        opcodes::all::OP_RETURN,
        script::{Builder, ScriptBuf},
        transaction::{Transaction, TxIn, TxOut},
    },
    Sequence, Witness,
};

use overpass_core::zkp::{
    bitcoin_ephemeral_state::BitcoinClient,
    state_transition::StateTransitionCircuit,
    tree::SparseMerkleTree,
    channel::ChannelState,
};

use plonky2_field::types::Field;
use plonky2::plonk::config::Hasher;
use plonky2_field::types::PrimeField64;

/// Converts a ChannelState into a 32-byte hash using PoseidonHash.
fn hash_state(state: &ChannelState) -> Result<[u8; 32]> {
    use plonky2::hash::poseidon::PoseidonHash;

    // Convert ChannelState fields to field elements
    let mut inputs = Vec::new();

    // Serialize balances (assuming u32 for each balance)
    for &balance in &state.balances {
        inputs.push(GoldilocksField::from_canonical_u32(balance as u32));
    }

    // Serialize nonce (assuming u64)
    inputs.push(GoldilocksField::from_canonical_u64(state.nonce));

    // Serialize metadata (assuming Vec<u8>)
    for &byte in &state.metadata {
        inputs.push(GoldilocksField::from_canonical_u8(byte));
    }

    // Compute Poseidon hash of thash_pad
    let hash_out = PoseidonHash::hash_pad(&inputs);

    // Convert HashOut to bytes
    let mut bytes = [0u8; 32];
    for (i, &element) in hash_out.elements.iter().enumerate() {
        let elem_u64 = element.to_canonical_u64();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem_u64.to_le_bytes());
    }

    Ok(bytes)
}

/// Builds an OP_RETURN transaction embedding the provided data.
fn build_op_return_transaction(client: &BitcoinClient, data: [u8; 32]) -> Result<String> {
    let amount = 100_000;
    let (outpoint, script_pubkey) = client.get_spendable_utxo(amount)?;

    // Build OP_RETURN script
    let op_return_script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&data)
        .into_script();

    // Create inputs and outputs
    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence(0xffffffff),
        witness: Witness::default(),
    };
    let tx_out_opreturn = TxOut {
        value: 0,
        script_pubkey: op_return_script,
    };
    let tx_out_change = TxOut {
        value: amount - 1_000, // Deduct fee
        script_pubkey: script_pubkey.into(),
    };

    // Build transaction
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out_opreturn, tx_out_change],
    };

    // Serialize and encode transaction in hex
    let raw_tx_hex = hex::encode(encode::serialize(&tx));

    // Sign the transaction
    let signed_tx_hex = client
        .sign_raw_transaction(&raw_tx_hex)
        .map_err(|e| anyhow!("Transaction signing failed: {}", e))?;

    Ok(signed_tx_hex)
}

/// Attempts to convert a byte array into a specified type.
fn try_into_array<T>(bytes: [u8; 32]) -> Result<T, anyhow::Error>
where
    T: TryFrom<[u8; 32]>,
{
    bytes.try_into().map_err(|_| anyhow!("Conversion failed for bytes array"))
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Converts a ChannelState into a 32-byte hash using PoseidonHash.
    fn hash_state(state: &ChannelState) -> Result<[u8; 32]> {
        use plonky2::hash::poseidon::PoseidonHash;

        // Convert ChannelState fields to field elements
        let mut inputs = Vec::new();

        // Serialize balances (assuming u32 for each balance)
        for &balance in &state.balances {
            inputs.push(GoldilocksField::from_canonical_u32(balance.try_into().unwrap()));
        }

        // Serialize nonce (assuming u64)
        inputs.push(GoldilocksField::from_canonical_u64(state.nonce));

        // Serialize metadata (assuming Vec<u8>)
        for &byte in &state.metadata {
            inputs.push(GoldilocksField::from_canonical_u8(byte));
        }

        // Compute Poseidon hash of the inputs
        let hash_out = PoseidonHash::hash_no_pad(&inputs);

        // Convert HashOut to bytes
        let mut bytes = [0u8; 32];
        for (i, &element) in hash_out.elements.iter().enumerate() {
            let elem_u64 = element.to_canonical_u64();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem_u64.to_le_bytes());
        }

        Ok(bytes)
    }

    #[test]
    fn test_e2e_integration() -> Result<()> {
        // Initialize Bitcoin client
        let client = BitcoinClient::new("http://127.0.0.1:18443", "rpcuser", "rpcpassword", None)?;

        // Fund the wallet and ensure a nonzero balance
        let addr = client.get_new_address()?;
        client.generate_blocks(101, &addr.to_string())?;
        let balance = client.get_balance()?;
        assert!(balance > 0, "Wallet balance should be greater than zero");

        // Define initial and next channel states
        let initial_state = ChannelState::new(vec![100, 50], 0, vec![], [0u8; 32], vec![]);
        let next_state = ChannelState::new(vec![97, 53], 1, vec![], [0u8; 32], vec![]);

        // Compute hashes for states using PoseidonHash
        let initial_state_bytes = hash_state(&initial_state)?;
        let next_state_bytes = hash_state(&next_state)?;

        // Log state hashes
        println!("Initial state bytes: {:?}", initial_state_bytes);
        println!("Next state bytes: {:?}", next_state_bytes);

        // Generate transition data
        // Here, transition_data encodes:
        // - delta_balance_0: -3
        // - delta_balance_1: +3
        // - delta_nonce: +1
        let mut transition_data = [0u8; 32];
        transition_data[0..4].copy_from_slice(&(-3i32).to_le_bytes()); // delta_balance_0 = -3
        transition_data[4..8].copy_from_slice(&3i32.to_le_bytes());   // delta_balance_1 = +3
        transition_data[8..12].copy_from_slice(&1i32.to_le_bytes());  // delta_nonce = +1
        // The rest of the bytes remain zero
        println!("Transition data: {:?}", transition_data);

        // Initialize the state transition circuit
        let circuit = StateTransitionCircuit::new();

        // Compute the expected next state using the circuit's public method
        let computed_next_state = circuit.compute_next_state(&initial_state_bytes, &transition_data)?;
        println!("Computed next state: {:?}", computed_next_state);

        // Assert that the computed next state matches the expected next state
        assert_eq!(
            next_state_bytes, computed_next_state,
            "Computed next state does not match expected"
        );

        // Generate and verify the proof
        let proof = circuit.generate_proof(&initial_state, &transition_data)?;
        assert!(
            circuit.verify_proof(&proof)?,
            "Proof verification failed"
        );

        // Update Merkle tree
        let channel_key = [9u8; 32];
        let mut smt = SparseMerkleTree::new(32);
        smt.update(&channel_key, &initial_state_bytes)?;
        smt.update(&channel_key, &next_state_bytes)?;

        // Generate and verify Merkle proof
        let merkle_proof = smt.generate_proof(&channel_key, &next_state_bytes)?;
        assert!(
            overpass_core::zkp::tree::SparseMerkleTree::verify_proof(&channel_key, &merkle_proof, &next_state_bytes)?,
            "Merkle proof verification failed"
        );

        // Submit SMT root to Bitcoin blockchain
        let raw_tx_hex = build_op_return_transaction(&client, smt.root())?;
        let txid = client.send_raw_transaction_hex(&raw_tx_hex)?;
        client.generate_blocks(1, &client.get_new_address()?.to_string())?;
        println!("Anchored SMT root in TX {}", txid);

        Ok(())
    }}