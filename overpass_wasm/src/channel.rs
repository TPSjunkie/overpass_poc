use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

/// A simplified serializable transaction structure for WebAssembly.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[wasm_bindgen]
pub struct Transaction {
    pub amount: u64,
    #[wasm_bindgen(skip)]
    pub data: Vec<u8>,
    pub nonce: u64,
    pub timestamp: u64,
    #[wasm_bindgen(skip)]
    pub signature: Vec<u8>,
}

#[wasm_bindgen]
impl Transaction {
    /// Creates a new transaction with placeholder signature and current timestamp.
    #[wasm_bindgen(constructor)]
    pub fn new(amount: u64, data: Vec<u8>, nonce: u64) -> Self {
        let timestamp = js_sys::Date::now() as u64;
        let signature = Vec::new(); // Placeholder for actual signature.
        Self {
            amount,
            data,
            nonce,
            timestamp,
            signature,
        }
    }

    /// Serializes the transaction to a `Vec<u8>`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Converts the transaction to a `JsValue`.
    #[wasm_bindgen(js_name = toJsValue)]
    pub fn to_js_value(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Creates a transaction from a `JsValue`.
    #[wasm_bindgen(js_name = fromJsValue)]
    pub fn from_js_value(value: JsValue) -> Result<Transaction, JsValue> {
        serde_wasm_bindgen::from_value(value).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

/// Handle conversion of `Option<T>` to `JsValue`.
pub fn option_to_js_value<T: Serialize>(option: Option<T>) -> Result<JsValue, JsValue> {
    option
        .map_or(Ok(JsValue::NULL), |value| serde_wasm_bindgen::to_value(&value).map_err(|e| JsValue::from_str(&e.to_string())))
}

/// Handle conversion of `JsValue` to `Option<T>`.
pub fn js_value_to_option<T: for<'de> Deserialize<'de>>(value: JsValue) -> Result<Option<T>, JsValue> {
    if value.is_null() || value.is_undefined() {
        Ok(None)
    } else {
        serde_wasm_bindgen::from_value(value).map(Some).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}