use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::*;
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StateUpdate {
    dag_cells: Vec<u8>,
    references: Vec<u32>,
    roots: Vec<u32>,
    hash: Vec<u8>,
    state_mapping: Vec<(u32, u32)>,
    nonce: u64,
}

impl StateUpdate {
    /// Constructs a new `StateUpdate` with provided data and calculates its hash.
    pub fn new(
        dag_cells: Vec<u8>,
        references: Vec<u32>,
        roots: Vec<u32>,
        state_mapping: Vec<u32>,
        nonce: u64,
    ) -> Self {
        assert!(
            state_mapping.len() % 2 == 0,
            "State mapping must contain an even number of elements"
        );

        // Map state_mapping to pairs of (u32, u32)
        let state_mapping = state_mapping
            .chunks(2)
            .map(|chunk| (chunk[0], chunk[1]))
            .collect();

        // Initialize the StateUpdate
        let mut update = StateUpdate {
            dag_cells,
            references,
            roots,
            hash: Vec::new(),
            state_mapping,
            nonce,
        };

        // Compute the hash
        let mut hasher = Sha256::new();
        hasher.update(&update.dag_cells);
        update.roots.iter().for_each(|x| hasher.update(x.to_le_bytes()));
        update.hash = hasher.finalize().to_vec();

        update
    }

    pub fn dag_cells(&self) -> &[u8] {
        &self.dag_cells
    }

    pub fn references(&self) -> &[u32] {
        &self.references
    }

    pub fn roots(&self) -> &[u32] {
        &self.roots
    }

    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    pub fn state_mapping(&self) -> &[(u32, u32)] {
        &self.state_mapping
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Verifies the integrity of the StateUpdate by recalculating its hash.
    pub fn verify(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.dag_cells);
        self.roots.iter().for_each(|x| hasher.update(x.to_le_bytes()));
        hasher.finalize().as_slice() == self.hash
    }
}

#[wasm_bindgen]
pub struct StateUpdateWrapper {
    inner: StateUpdate,
}

#[wasm_bindgen]
impl StateUpdateWrapper {
    /// Constructs a new `StateUpdateWrapper` and validates the input data.
    #[wasm_bindgen(constructor)]
    pub fn new(
        dag_cells: js_sys::Uint8Array,
        references: js_sys::Uint32Array,
        roots: js_sys::Uint32Array,
        state_mapping: js_sys::Uint32Array,
        nonce: u64,
    ) -> Result<StateUpdateWrapper, JsValue> {
        if roots.length() == 0 {
            return Err(JsValue::from_str("Roots array cannot be empty"));
        }

        if state_mapping.length() % 2 != 0 {
            return Err(JsValue::from_str("State mapping must contain pairs of values"));
        }

        // Convert JS arrays to Rust vectors
        let dag_cells = dag_cells.to_vec();
        let references = references.to_vec();
        let roots = roots.to_vec();
        let state_mapping = state_mapping.to_vec();

        // Construct and return the wrapper
        Ok(StateUpdateWrapper {
            inner: StateUpdate::new(dag_cells, references, roots, state_mapping, nonce),
        })
    }

    #[wasm_bindgen(getter)]
    pub fn dag_cells(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.inner.dag_cells[..])
    }

    #[wasm_bindgen(getter)]
    pub fn references(&self) -> js_sys::Uint32Array {
        js_sys::Uint32Array::from(&self.inner.references[..])
    }

    #[wasm_bindgen(getter)]
    pub fn roots(&self) -> js_sys::Uint32Array {
        js_sys::Uint32Array::from(&self.inner.roots[..])
    }

    #[wasm_bindgen(getter)]
    pub fn hash(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.inner.hash[..])
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> u64 {
        self.inner.nonce
    }

    #[wasm_bindgen(getter)]
    pub fn state_mapping(&self) -> js_sys::Array {
        self.inner
            .state_mapping
            .iter()
            .map(|(a, b)| {
                let pair = js_sys::Array::new();
                pair.push(&(*a).into());
                pair.push(&(*b).into());
                pair
            })
            .collect()
    }

    #[wasm_bindgen]
    pub fn verify(&self) -> bool {
        self.inner.verify()
    }

    pub(crate) fn get_inner(&self) -> &StateUpdate {
        &self.inner
    }

    pub(crate) fn into_inner(self) -> StateUpdate {
        self.inner
    }
}