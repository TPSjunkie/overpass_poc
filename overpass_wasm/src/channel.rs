// src/channel.rs

use wasm_bindgen::prelude::*;
use sha2::{Digest, Sha256};
use crate::types::dag_boc::{StateUpdate, StateUpdateWrapper};

#[derive(Clone, Debug)]
pub struct Channel {
    state_updates: Vec<StateUpdate>,
}

impl Channel {
    pub fn new() -> Self {
        Channel {
            state_updates: Vec::new(),
        }
    }

    pub fn state_updates(&self) -> &[StateUpdate] {
        &self.state_updates
    }

    pub fn get_current_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for update in &self.state_updates {
            hasher.update(update.hash());
        }
        hasher.finalize().to_vec()
    }

    pub fn has_update(&self, update: &StateUpdate) -> bool {
        self.state_updates.iter().any(|u| u == update)
    }

    pub fn verify_all_updates(&self) -> bool {
        self.state_updates.iter().all(|update| update.verify())
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct ChannelWrapper(Channel);

#[wasm_bindgen]
impl ChannelWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        ChannelWrapper(Channel::new())
    }

    #[wasm_bindgen]
    pub fn update_state(&mut self, update: &StateUpdateWrapper) -> Result<(), JsValue> {
        if !update.verify() {
            return Err(JsValue::from_str("Invalid state update: verification failed"));
        }

        let state_update = update.get_inner().clone();
        
        if self.0.has_update(&state_update) {
            return Err(JsValue::from_str("State update already exists"));
        }

        self.0.state_updates.push(state_update);
        Ok(())
    }

    #[wasm_bindgen(getter)]
    pub fn hash(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.0.get_current_hash()[..])
    }

    #[wasm_bindgen(getter)]
    pub fn state_count(&self) -> usize {
        self.0.state_updates.len()
    }

    #[wasm_bindgen]
    pub fn verify(&self) -> bool {
        self.0.verify_all_updates()
    }
}

#[wasm_bindgen]
pub fn create_channel() -> ChannelWrapper {
    ChannelWrapper::new()
}

#[wasm_bindgen]
pub fn verify_state_update(update: &StateUpdateWrapper) -> bool {
    update.verify()
}