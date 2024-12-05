// src/common/types/dag_boc.rs

use crate::error::client_errors::{SystemError, SystemErrorType};
use crate::types::ops::OpCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// DAG Cell
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DagCell {
    pub balance: u64,
    pub nonce: u64,
}

/// DAG BOC representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DAGBOC {
    pub dag_cells: Vec<Vec<u8>>,
    pub references: Vec<(u32, u32)>,
    pub roots: Vec<Vec<u8>>,
    pub hash: Option<[u8; 32]>,
    pub state_mapping: HashMap<Vec<u8>, u32>,
}

impl DAGBOC {
    /// Creates a new `DAGBOC`.
    pub fn new() -> Self {
        DAGBOC {
            dag_cells: Vec::new(),
            references: Vec::new(),
            roots: Vec::new(),
            hash: None,
            state_mapping: HashMap::new(),
        }
    }
    /// Get State
    pub fn get_state_cells(&self) -> Vec<Vec<u8>> {
        self.dag_cells.clone()
    }
    /// Adds a cell to the DAG BOC.
    pub fn add_cell(&mut self, cell_data: Vec<u8>) -> Result<u32, SystemError> {
        let id = self.dag_cells.len() as u32;
        self.dag_cells.push(cell_data);
        Ok(id)
    }

    /// Updates the state mapping.
    pub fn update_state_mapping(&mut self, key: Vec<u8>, value: u32) -> Result<(), SystemError> {
        self.state_mapping.insert(key, value);
        Ok(())
    }

    /// Processes an opcode to modify the DAG BOC.
    pub fn process_op_code(&mut self, op_code: OpCode) -> Result<(), SystemError> {
        match op_code {
            OpCode::Add { cell } => {
                self.add_cell(cell)?;
            }
            OpCode::SetCode {
                code,
                new_code,
                new_data: _,
                new_libraries: _,
                new_version: _,
            } => {
                if let Some(index) = self.dag_cells.iter().position(|c| c == &code) {
                    self.dag_cells[index] = new_code;
                } else {
                    return Err(SystemError::new(
                        SystemErrorType::InvalidInput,
                        "Code not found".to_string(),
                    ));
                }
            }
            OpCode::SetData { cell, new_data } => {
                if let Some(index) = self.dag_cells.iter().position(|c| c == &cell) {
                    self.dag_cells[index] = new_data;
                } else {
                    return Err(SystemError::new(
                        SystemErrorType::InvalidInput,
                        "Cell not found".to_string(),
                    ));
                }
            }
            OpCode::AddReference { from, to } => {
                self.references.push((from, to));
            }
            OpCode::SetRoot { index } => {
                if let Some(cell) = self.dag_cells.get(index as usize) {
                    self.roots.push(cell.clone());
                } else {
                    return Err(SystemError::new(
                        SystemErrorType::InvalidInput,
                        "Index out of bounds".to_string(),
                    ));
                }
            }
            OpCode::Remove { cell } => {
                if let Some(index) = self.dag_cells.iter().position(|c| c == &cell) {
                    self.dag_cells.remove(index);
                } else {
                    return Err(SystemError::new(
                        SystemErrorType::InvalidInput,
                        "Cell not found".to_string(),
                    ));
                }
            }
            OpCode::RemoveReference { from, to } => {
                if let Some(index) = self
                    .references
                    .iter()
                    .position(|&(f, t)| f == from && t == to)
                {
                    self.references.remove(index);
                } else {
                    return Err(SystemError::new(
                        SystemErrorType::InvalidInput,
                        "Reference not found".to_string(),
                    ));
                }
            }
            _ => {
                return Err(SystemError::new(
                    SystemErrorType::InvalidInput,
                    "Unsupported operation".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Serializes the DAG BOC to a byte vector.
    pub fn serialize(&self) -> Result<Vec<u8>, SystemError> {
        serde_json::to_vec(self)
            .map_err(|e| SystemError::new(SystemErrorType::SerializationFailed, e.to_string()))
    }

    /// Deserializes the DAG BOC from a byte slice.
    pub fn deserialize(data: &[u8]) -> Result<Self, SystemError> {
        serde_json::from_slice(data)
            .map_err(|e| SystemError::new(SystemErrorType::DeserializationFailed, e.to_string()))
    }

    /// Computes the hash of the DAG BOC.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        for cell in &self.dag_cells {
            hasher.update(cell);
        }

        for &(from, to) in &self.references {
            hasher.update(&from.to_le_bytes());
            hasher.update(&to.to_le_bytes());
        }

        for root in &self.roots {
            hasher.update(root);
        }

        hasher.finalize().into()
    }

    /// Sets the DAG cells.
    pub fn with_dag_cells(mut self, dag_cells: Vec<Vec<u8>>) -> Self {
        self.dag_cells = dag_cells;
        self
    }

    /// Sets the references.
    pub fn with_references(mut self, references: Vec<(u32, u32)>) -> Self {
        self.references = references;
        self
    }

    /// Sets the roots.
    pub fn with_roots(mut self, roots: Vec<Vec<u8>>) -> Self {
        self.roots = roots;
        self
    }
}

// crate::types::dag_boc.rs

pub struct DagBOC {
    // Fields representing the DAG
}

impl DagBOC {
    pub fn new() -> Self {
        Self {
            // Initialize DAG
        }
    }

    pub fn process_op_code(&mut self, _op_code: OpCode) -> Result<(), anyhow::Error> {
        // Process operation code
        Ok(())
    }

    pub fn get_state_cells(&self) -> Vec<u8> {
        // Retrieve state cells
        vec![] // Placeholder
    }
}
