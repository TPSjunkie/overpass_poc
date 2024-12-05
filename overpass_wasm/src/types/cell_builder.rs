// src/types/cell_builder.rs

use crate::error::client_errors::{SystemError, SystemErrorType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Represents a state initialization object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateInit {
    /// The code of the contract.
    pub code: Option<Vec<u8>>,
    /// The data of the contract.
    pub data: Option<Vec<u8>>,
    /// The library of the contract.
    pub library: Option<Vec<u8>>,
}

/// Slice of a cell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Slice {
    pub start: u64,
    pub end: u64,
}

/// Cell type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CellType {
    Ordinary,
    MerkleProof,
}

/// Cell structure with necessary fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cell {
    pub nonce: u64,
    pub balance: u64,
    pub cell_type: CellType,
    pub data: Vec<u8>,
    pub references: Vec<u64>,
    pub slice: Option<Slice>,
}

#[derive(Clone, Debug)]
pub struct CellBuilder {
    pub cells: HashMap<u64, Arc<RwLock<Cell>>>,
    pub size: u64,
}

impl CellBuilder {
    /// Creates a new `CellBuilder`.
    pub fn new() -> Self {
        Self {
            cells: HashMap::new(),
            size: 0,
        }
    }

    /// Adds a cell to the builder.
    pub fn add_cell(&mut self, cell: Cell) -> Result<(), SystemError> {
        let cell_id = cell.nonce;
        if self.cells.contains_key(&cell_id) {
            return Err(SystemError::new(
                SystemErrorType::InvalidInput,
                "Cell already exists".to_string(),
            ));
        }
        self.size += cell.balance;
        self.cells.insert(cell_id, Arc::new(RwLock::new(cell)));
        Ok(())
    }
    /// Adds multiple cells to the builder.
    pub fn add_cells(&mut self, cells: Vec<Cell>) -> Result<(), SystemError> {
        for cell in cells {
            self.add_cell(cell)?;
        }
        Ok(())
    }

    /// Builds the cells from the builder.
    pub fn build_cells(&self) -> Result<Vec<Cell>, SystemError> {
        let mut cells = Vec::new();
        for (id, cell_lock) in &self.cells {
            let mut cell = cell_lock.read().unwrap().clone();
            cell.nonce = *id;
            cells.push(cell);
        }
        Ok(cells)
    }
}
