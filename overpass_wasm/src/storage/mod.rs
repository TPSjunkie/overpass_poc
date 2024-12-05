// File: overpass_wasm/src/storage/mod.rs

use wasm_bindgen::prelude::*;
use web_sys::{Storage, Window};

#[wasm_bindgen]
pub struct ClientStorage {
    // Use browser's localStorage for testing
    storage: Storage,
}

#[wasm_bindgen]
impl ClientStorage {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<ClientStorage, JsValue> {
        // Get window.localStorage
        let window: Window =
            web_sys::window().ok_or_else(|| JsValue::from_str("No window found"))?;
        let storage = window
            .local_storage()?
            .ok_or_else(|| JsValue::from_str("No localStorage found"))?;

        Ok(Self { storage })
    }

    #[wasm_bindgen(js_name = saveState)]
    pub fn save_state(&self, channel_id: &str, state: &JsValue) -> Result<(), JsValue> {
        // Store in localStorage
        self.storage
            .set_item(channel_id, &state.as_string().unwrap_or_default())
            .map_err(|e| JsValue::from(format!("{:?}", e)))?;

        Ok(())
    }

    #[wasm_bindgen(js_name = loadState)]
    pub fn load_state(&self, channel_id: &str) -> Result<JsValue, JsValue> {
        // Get from localStorage
        let state_string = match self.storage.get_item(channel_id)? {
            Some(s) => s,
            None => return Ok(JsValue::NULL),
        };

        Ok(JsValue::from_str(&state_string))
    }

    #[wasm_bindgen(js_name = listChannels)]
    pub fn list_channels(&self) -> Result<Vec<String>, JsValue> {
        let mut channels = Vec::new();

        // Iterate localStorage keys
        for i in 0..self.storage.length()? {
            if let Some(key) = self.storage.key(i)? {
                if key.starts_with("channel-") {
                    channels.push(key);
                }
            }
        }

        Ok(channels)
    }
}
