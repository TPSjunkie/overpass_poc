/*// ./src/services/overpass.rs
use serde::Deserialize;
use serde::Serialize;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use crate::services::overpass_db::OverpassDB;
use anyhow::{anyhow, Result};
use bitcoin::Network;
use crate::logging::config::Config;

#[derive(Serialize, Deserialize, Debug)]
pub struct OverpassTransactionResponse {
    pub result: OverpassTransaction,
    pub hash: String,
    pub confirmations: i32,
    pub size: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OverpassTransaction {
    // Add fields for OverpassTransaction here
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OverpassVerifyResponse {
    pub result: bool,
    pub confirmations: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OverpassStateResponse {
    pub result: OverpassState,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OverpassProofResponse {
    pub result: OverpassProof,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OverpassConfigResponse {
    pub result: OverpassConfig,
}

pub struct OverpassService {
    pub(crate) config: OverpassConfig,
    db: OverpassDB,
    client: Client,
    network: Network,
    debug_mode: bool,
}

impl Default for OverpassService {
    fn default() -> Self {
        Self::new(
            Config::default(),
            OverpassDB::new("overpass.db").unwrap(),
            Client::new("http://localhost:8332", Auth::None).expect("Failed to create Bitcoin Core client"),
            Network::Bitcoin,
            false,
        )
    }
}

impl OverpassService {
    /// Creates a new `OverpassService` instance.
    pub fn new(config: OverpassConfig, db: OverpassDB, client: Client, network: Network, debug_mode: bool) -> Self {
        Self {
            config,
            db,
            client,
            network,
            debug_mode,
        }
    }

    /// Processes a transaction request, updates the state, and returns a response.
    pub fn process_transaction(
        &self,
        request: OverpassTransaction,
    ) -> Result<OverpassTransactionResponse> {
        // Load current state
        let current_state_bytes = self.db.get(b"state")?.ok_or_else(|| anyhow!("State not found"))?;
        let current_state: OverpassState = bincode::deserialize(¤t_state_bytes)?;

        // Validate transaction
        if request.amount > current_state.balance {
            return Err(anyhow!("Insufficient balance"));
        }

        // Update state
        let new_balance = current_state.balance - request.amount;
        let new_state = OverpassState {
            nonce: current_state.nonce + 1,
            balance: new_balance,
            merkle_root: vec![], // Placeholder for the updated root.
            size: current_state.size,
        };

        // Generate proof
        let proof = self.generate_proof(¤t_state, &new_state)?;
        let state_hash = hex::encode(&proof.state);
        let transaction_hash = hex::encode(&request.data);
        let transaction_data = request.data.clone();

        // Save state and transaction
        let new_state_bytes = bincode::serialize(&new_state)?;
        let transaction_bytes = bincode::serialize(&request)?;
        let proof_bytes = bincode::serialize(&proof)?;

        self.db.put(b"state", &new_state_bytes)?;
        self.db.put(format!("tx_{}", transaction_hash).as_bytes(), &transaction_bytes)?;
        self.db.put(format!("proof_{}", state_hash).as_bytes(), &proof_bytes)?;
        self.db.put(format!("data_{}", transaction_hash).as_bytes(), &transaction_data)?;

        Ok(OverpassTransactionResponse {
            result: request,
            hash: transaction_hash,
            confirmations: 0,
            size: request.data.len() as u32,
        })
    }

    /// Generates a proof for a state transition.
    fn generate_proof(
        &self,
        _old_state: &OverpassState,
        _new_state: &OverpassState,
    ) -> Result<OverpassProof> {
        // Generate Sparse Merkle Tree proof (placeholder)
        let proof = vec![0; 32]; // Example proof data
        let state = vec![0; 32]; // Example state data

        Ok(OverpassProof { state, proof })
    }

    /// Verifies a transaction's proof against the current state.
    pub fn verify_proof(&self, proof: OverpassProof) -> Result<OverpassVerifyResponse> {
        // Validate proof (placeholder)
        let is_valid = proof.proof.len() == 32 && proof.state.len() == 32;

        if !is_valid {
            return Err(anyhow!("Invalid proof"));
        }

        Ok(OverpassVerifyResponse {
            result: true,
            confirmations: 1,
        })
    }

    /// Retrieves the current state.
    pub fn get_state(&self) -> Result<OverpassStateResponse> {
        let state_bytes = self.db.get(b"state")?.ok_or_else(|| anyhow!("State not found"))?;
        let state: OverpassState = bincode::deserialize(&state_bytes)?;
        Ok(OverpassStateResponse { result: state })
    }

    /// Initializes the service with default or provided values.
    pub fn initialize(&self) -> Result<()> {
        let initial_state = OverpassState {
            nonce: 0,
            balance: self.config.initial_balance,
            merkle_root: vec![0; 32], // Example root
            size: 0,
        };

        let state_bytes = bincode::serialize(&initial_state)?;
        self.db.put(b"state", &state_bytes)?;
        Ok(())
    }
}*/