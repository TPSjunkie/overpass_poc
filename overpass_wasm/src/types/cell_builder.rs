// src/types/cell_builder.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CellBuilderError {
    #[error("Cell already exists")]
    CellExists,
    #[error("Invalid cell: {0}")]
    InvalidCell(String),
    #[error("Lock error: {0}")]
    LockError(String),
}

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

impl Cell {
    pub fn new(nonce: u64, data: Vec<u8>) -> Self {
        Self {
            nonce,
            balance: 0,
            cell_type: CellType::Ordinary,
            data,
            references: Vec::new(),
            slice: None,
        }
    }

    pub fn with_balance(mut self, balance: u64) -> Self {
        self.balance = balance;
        self
    }

    pub fn with_references(mut self, references: Vec<u64>) -> Self {
        self.references = references;
        self
    }

    pub fn with_slice(mut self, start: u64, end: u64) -> Self {
        self.slice = Some(Slice { start, end });
        self
    }
}

#[derive(Clone, Debug)]
pub struct CellBuilder {
    cells: HashMap<u64, Arc<RwLock<Cell>>>,
    size: u64,
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
    pub fn add_cell(&mut self, cell: Cell) -> Result<(), CellBuilderError> {
        let cell_id = cell.nonce;
        if self.cells.contains_key(&cell_id) {
            return Err(CellBuilderError::CellExists);
        }
        self.size += cell.balance;
        self.cells.insert(cell_id, Arc::new(RwLock::new(cell)));
        Ok(())
    }

    /// Adds multiple cells to the builder.
    pub fn add_cells(&mut self, cells: Vec<Cell>) -> Result<(), CellBuilderError> {
        for cell in cells {
            self.add_cell(cell)?;
        }
        Ok(())
    }

    /// Gets a reference to a cell if it exists.
    pub fn get_cell(&self, id: u64) -> Option<Arc<RwLock<Cell>>> {
        self.cells.get(&id).cloned()
    }

    /// Builds the cells from the builder.
    pub fn build_cells(&self) -> Result<Vec<Cell>, CellBuilderError> {
        let mut cells = Vec::new();
        for (id, cell_lock) in &self.cells {
            let cell = cell_lock.read()
                .map_err(|e| CellBuilderError::LockError(e.to_string()))?
                .clone();
            cells.push(cell);
        }
        Ok(cells)
    }

    /// Returns the total size of all cells.
    pub fn total_size(&self) -> u64 {
        self.size
    }

    /// Returns the number of cells.
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// Clears all cells.
    pub fn clear(&mut self) {
        self.cells.clear();
        self.size = 0;
    }
}

impl Default for CellBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_builder() {
        let mut builder = CellBuilder::new();
        
        let cell1 = Cell::new(1, vec![1, 2, 3])
            .with_balance(100)
            .with_references(vec![2, 3]);
            
        let cell2 = Cell::new(2, vec![4, 5, 6])
            .with_balance(200);
            
        assert!(builder.add_cell(cell1.clone()).is_ok());
        assert!(builder.add_cell(cell2.clone()).is_ok());
        
        assert_eq!(builder.cell_count(), 2);
        assert_eq!(builder.total_size(), 300);
        
        let cells = builder.build_cells().unwrap();
        assert_eq!(cells.len(), 2);
        assert!(cells.contains(&cell1));
        assert!(cells.contains(&cell2));
    }

    #[test]
    fn test_duplicate_cell() {
        let mut builder = CellBuilder::new();
        let cell = Cell::new(1, vec![1, 2, 3]);
        
        assert!(builder.add_cell(cell.clone()).is_ok());
        assert!(matches!(builder.add_cell(cell), Err(CellBuilderError::CellExists)));
    }
}