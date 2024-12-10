// src/zkp/wallet_contract.rs

use crate::zkp::pedersen_parameters::PedersenParameters;
use crate::zkp::state_proof::StateProof;
use crate::zkp::global_root_contract::GlobalRootContract;
use std::collections::HashMap;
use crate::zkp::channel::ChannelState;
use crate::zkp::helpers::{
    compute_channel_root,
    generate_random_blinding,
    pedersen_commit,
    generate_state_proof,
};
use crate::zkp::mobile_optimized_storage::MobileOptimizedStorage;

/// Type alias for bytes32.
pub type Bytes32 = [u8; 32];

/// Local Verification Layer (Level 2)
/// Manages channels and generates network proofs.
pub struct WalletContract {
    pub wallet_id: Bytes32,
    pub params: PedersenParameters,
    pub channels: HashMap<Bytes32, ChannelState>,
    pub merkle_root: Bytes32,
    pub storage: MobileOptimizedStorage,
    pub global_contract: GlobalRootContract,
}

impl WalletContract {
    /// Creates a new WalletContract.
    pub fn new(
        wallet_id: Bytes32,
        params: PedersenParameters,
        global_contract: GlobalRootContract,
    ) -> Self {
        let merkle_root = compute_channel_root([0u8; 32], [0u8; 32], 0);
        Self {
            wallet_id,
            params,
            channels: HashMap::new(),
            merkle_root,
            storage: MobileOptimizedStorage::new(100, 30 * 24 * 3600),
            global_contract,
        }
    }
    
    /// Registers a new channel.
    /// Returns true if successful, otherwise false.
    pub fn register_channel(
        &mut self,
        channel_id: Bytes32,
        initial_balance: u64,
        _counterparty: Bytes32,
        metadata: Vec<u8>,
    ) -> bool {
        if self.channels.contains_key(&channel_id) {
            return false; // Channel already exists
        }

        // Call as an associated function
        let sanitized_metadata = Self::sanitize_metadata(metadata).unwrap_or_else(|| vec![]);
        let channel = ChannelState {
            balances: vec![initial_balance],
            nonce: 0,
            metadata: sanitized_metadata,
            merkle_root: [0u8; 32],
            proof: None,
        };

        self.channels.insert(channel_id, channel);

        // Update the Merkle root to reflect the new channel
        self.update_merkle_root();

        // Register wallet in global root contract
        match self.global_contract.register_wallet(self.merkle_root) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("Failed to register wallet in global contract: {:?}", e);
                false
            }
        }
    }

    /// Helper to sanitize metadata, ensuring it's valid.
    fn sanitize_metadata(metadata: Vec<u8>) -> Option<Vec<u8>> {
        if metadata.is_empty() {
            None
        } else {
            Some(metadata)
        }
    }

    /// Updates the Merkle root for the wallet, based on channel states.
    fn update_merkle_root(&mut self) {
        self.merkle_root = compute_channel_root([0u8; 32], [0u8; 32], self.channels.len() as u64);
    }

    /// Updates a channel's state and generates a proof.
    pub fn update_channel(
        &mut self,
        channel_id: Bytes32,
        new_balance: u64,
        metadata: Vec<u8>,
    ) -> bool {
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            // Generate new Pedersen commitment
            let blinding = generate_random_blinding();
            let new_commitment = pedersen_commit(new_balance, blinding, &self.params);
            
            // Generate state transition proof
            let proof = generate_state_proof(
                [0u8; 32], // Placeholder for old commitment
                new_commitment,
                self.merkle_root,
                &self.params,
            );
            
            // Update channel state
            channel.balances = vec![new_balance];
            channel.nonce += 1;
            channel.metadata = metadata;
            
            // Update merkle root for the wallet
            self.merkle_root = compute_channel_root([0u8; 32], [0u8; 32], 0);
            
            // Store transaction
            self.storage.store_transaction(
                channel_id,
                [0u8; 32], // Placeholder for old commitment
                new_commitment,
                StateProof::from(proof.clone()), // Corrected from helpers::StateProof::from(...)
                serde_json::Value::Null, // Replace with actual metadata if needed
            ).expect("Failed to store transaction");
            
            // Update global root contract
            self.global_contract
                .update_wallet(self.merkle_root, proof) // Removed self.wallet_id argument
                .expect("Failed to update wallet in global contract");
            
            true
        } else {
            false
        }
    }
}