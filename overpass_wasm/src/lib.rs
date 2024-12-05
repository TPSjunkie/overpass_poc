pub mod channel;
pub mod error;
pub mod storage;
pub mod types;
use crate::types::cell_builder::{Cell, CellBuilder};
use crate::types::dag_boc::DAGBOC;
use crate::types::ops::{ChannelOpCode, OpCode, WalletOpCode};
use crate::types::state_boc::StateBOC;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// Remove the unused import
// use types::cell_builder;

// Rest of WASM implementation...
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
pub struct Channel {
    state_boc: StateBOC,
    dag_boc: DAGBOC,
    nonce: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ChannelConfig {
    pub initial_balance: u64,
    pub security_bits: usize,
    pub version: u32,
}

#[derive(Serialize, Deserialize)]
pub struct StateUpdate {
    pub nonce: u64,
    pub balance: u64,
    pub merkle_root: [u8; 32],
    pub cell_hash: [u8; 32],
}

#[wasm_bindgen]
impl Channel {
    #[wasm_bindgen(constructor)]
    pub fn new(config_str: &str) -> Result<Channel, JsValue> {
        console_error_panic_hook::set_once();

        let config: ChannelConfig = serde_json_wasm::from_str(config_str)
            .map_err(|e| JsValue::from_str(&format!("Config parse error: {}", e)))?;

        let state_boc = StateBOC::new();
        let dag_boc = DAGBOC::new();
        let mut cell_builder = CellBuilder::new();

        let initial_cell = Cell {
            cell_type: crate::types::cell_builder::CellType::Ordinary,
            data: Vec::new(),
            references: Vec::new(),
            slice: None,
            nonce: 0,
            balance: config.initial_balance,
        };

        cell_builder
            .add_cell(initial_cell)
            .map_err(|e| JsValue::from_str(&format!("Cell initialization error: {}", e)))?;

        let channel = Channel {
            state_boc,
            dag_boc,
            nonce: 0,
        };

        Ok(channel)
    }
    #[wasm_bindgen]
    pub fn create_wallet(&mut self, entropy: &[u8]) -> Result<JsValue, JsValue> {
        console_log!("Creating new wallet BOC structure");

        let op = OpCode::Wallet(WalletOpCode::CreateChannel);
        let cell = crate::types::state_boc::Cell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data: entropy.to_vec(),
            references: Vec::new(),
            slice: None,
            nonce: 0,
            balance: 0,
        };

        self.state_boc.add_cell(cell);

        self.dag_boc
            .process_op_code(op)
            .map_err(|e| JsValue::from_str(&format!("OpCode processing error: {}", e)))?;

        self.nonce += 1;

        self.serialize_state()
    }
    #[wasm_bindgen]
    pub fn update_state(&mut self, amount: u64, data: &[u8]) -> Result<JsValue, JsValue> {
        console_log!("Updating state with amount: {}", amount);

        let op = OpCode::Channel(ChannelOpCode::UpdateState);
        let cell = crate::types::state_boc::Cell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data: data.to_vec(),
            references: Vec::new(),
            slice: None,
            nonce: self.nonce,
            balance: 0,
        };

        self.state_boc.add_cell(cell);

        self.dag_boc
            .process_op_code(op)
            .map_err(|e| JsValue::from_str(&format!("OpCode processing error: {}", e)))?;

        self.nonce += 1;

        self.serialize_state()
    }
    #[wasm_bindgen]
    pub fn process_transaction(&mut self, tx_data: &[u8]) -> Result<JsValue, JsValue> {
        console_log!("Processing transaction");

        let op = OpCode::Wallet(WalletOpCode::ProcessTransaction);
        let cell = crate::types::state_boc::Cell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data: tx_data.to_vec(),
            references: Vec::new(),
            slice: None,
            nonce: self.nonce,
            balance: 0,
        };

        self.state_boc.add_cell(cell);

        self.dag_boc
            .process_op_code(op)
            .map_err(|e| JsValue::from_str(&format!("OpCode processing error: {}", e)))?;

        self.nonce += 1;

        self.serialize_state()
    }
    #[wasm_bindgen]
    pub fn finalize_state(&mut self) -> Result<JsValue, JsValue> {
        console_log!("Finalizing state");

        let op = OpCode::Channel(ChannelOpCode::FinalizeState);
        self.dag_boc
            .process_op_code(op)
            .map_err(|e| JsValue::from_str(&format!("OpCode processing error: {}", e)))?;

        let final_hash = self.state_boc.compute_hash();

        Ok(serde_wasm_bindgen::to_value(&final_hash)
            .map_err(|e| JsValue::from_str(&format!("State serialization error: {}", e)))?)
    }

    #[wasm_bindgen]
    pub fn get_current_state(&self) -> Result<JsValue, JsValue> {
        self.serialize_state()
    }

    #[wasm_bindgen]
    pub fn verify_state(&mut self, state_bytes: &[u8]) -> Result<bool, JsValue> {
        let mut submitted_state = StateBOC::deserialize(state_bytes)
            .map_err(|e| JsValue::from_str(&format!("State deserialization error: {}", e)))?;

        Ok(self.state_boc.compute_hash() == submitted_state.compute_hash())
    }

    fn serialize_state(&self) -> Result<JsValue, JsValue> {
        let state_boc_bytes = self
            .state_boc
            .serialize()
            .map_err(|e| JsValue::from_str(&format!("BOC serialization error: {}", e)))?;
        Ok(serde_wasm_bindgen::to_value(&state_boc_bytes)
            .map_err(|e| JsValue::from_str(&format!("State serialization error: {}", e)))?)
    }
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    console_log!("Overpass WASM module initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use wasm_bindgen_test::*;
    use crate::types::state_boc::StateBOC;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    #[allow(dead_code)]
    fn test_channel_creation() {
        let channel = Channel::new("test_channel").unwrap();
        let state = channel.get_current_state().unwrap();
        let state: Vec<u8> = serde_wasm_bindgen::from_value(state).unwrap();
        let mut state_boc = StateBOC::deserialize(&state).unwrap();
        assert_eq!(state_boc.compute_hash(), [0; 32]); // Assuming a default hash for a new channel
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)]
    async fn test_transaction_processing() {
        let mut channel = Channel::new("test_channel").unwrap();
        let amount: u64 = 100;

        let promise = channel.process_transaction(&amount.to_le_bytes()).unwrap();
        let promise = promise.dyn_into::<js_sys::Promise>().unwrap();
        let result = JsFuture::from(promise).await.unwrap();

        let update: StateUpdate = serde_wasm_bindgen::from_value(result).unwrap();
        assert_eq!(update.balance, amount);
        assert_eq!(update.nonce, 1);
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)]
    async fn test_multiple_transactions() {
        let mut channel = Channel::new("test_channel").unwrap();

        for i in 1..=3 {
            let amount = 100 * i as u64;
            let promise = channel.process_transaction(&amount.to_le_bytes()).unwrap();
            let promise = promise.dyn_into::<js_sys::Promise>().unwrap();
            let result = JsFuture::from(promise).await.unwrap();

            let update: StateUpdate = serde_wasm_bindgen::from_value(result).unwrap();
            assert_eq!(update.nonce, i as u64);
        }
    }
}
