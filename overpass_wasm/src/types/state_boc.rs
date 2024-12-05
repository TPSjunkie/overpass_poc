use anyhow::Result;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256}; // For hash computation

/// Represents a state init object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateInit {
    /// The code of the contract.
    pub code: Option<Vec<u8>>,
    /// The data of the contract.
    pub data: Option<Vec<u8>>,
    /// The library of the contract.
    pub library: Option<Vec<u8>>,
}

/// Slice of a cell
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Slice {
    pub start: u64,
    pub end: u64,
}

/// Cell type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CellType {
    Ordinary,
    MerkleProof,
}

/// Cell
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cell {
    pub cell_type: CellType,
    pub data: Vec<u8>,
    pub references: Vec<u64>,
    pub slice: Option<Slice>,
    pub(crate) nonce: u64,
    pub(crate) balance: i32,
}

/// State BOC (Bag of Cells)
#[derive(Debug, Clone, PartialEq)]
pub struct StateBOC {
    pub state_cells: Vec<Cell>,
    pub references: Vec<Vec<u8>>,
    pub roots: Vec<Vec<u8>>,
    pub hash: Option<[u8; 32]>,
}

impl StateBOC {
    /// Creates a new StateBOC
    pub fn new() -> Self {
        StateBOC {
            state_cells: Vec::new(),
            references: Vec::new(),
            roots: Vec::new(),
            hash: None,
        }
    }

    /// Adds a cell to the state
    pub fn add_cell(&mut self, cell: Cell) {
        self.state_cells.push(cell);
    }

    /// Serializes the StateBOC
    pub fn serialize(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| anyhow::anyhow!("Serialization error: {}", e))
    }

    /// Deserializes a StateBOC from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| anyhow::anyhow!("Deserialization error: {}", e))
    }

    /// Computes the SHA256 hash of the current state
    pub fn compute_hash(&mut self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        for cell in &self.state_cells {
            hasher.update(&cell.data);
            hasher.update(cell.balance.to_le_bytes());
            hasher.update(cell.nonce.to_le_bytes());
        }

        for reference in &self.references {
            hasher.update(reference);
        }

        for root in &self.roots {
            hasher.update(root);
        }

        let hash = hasher.finalize();
        let hash_bytes: [u8; 32] = hash.into();
        self.hash = Some(hash_bytes);
        hash_bytes
    }

    /// Updates the balance of all cells
    pub fn update_balance(&mut self, balance: i32) {
        for cell in &mut self.state_cells {
            cell.balance += balance;
        }
    }

    /// Updates balances for multiple participants
    pub fn update_balances(&mut self, balances: &[i32]) {
        for (i, cell) in self.state_cells.iter_mut().enumerate() {
            if let Some(balance) = balances.get(i) {
                cell.balance += balance;
            }
        }
    }

    /// Sets the state cells directly
    pub fn set_state_cells(&mut self, cells: Vec<Cell>) {
        self.state_cells = cells;
    }
}

impl Default for StateBOC {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for StateBOC {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("StateBOC", 4)?;
        state.serialize_field("state_cells", &self.state_cells)?;
        state.serialize_field("references", &self.references)?;
        state.serialize_field("roots", &self.roots)?;
        state.serialize_field("hash", &self.hash)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for StateBOC {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StateBocHelper {
            state_cells: Vec<Cell>,
            references: Vec<Vec<u8>>,
            roots: Vec<Vec<u8>>,
            hash: Option<[u8; 32]>,
        }

        let helper = StateBocHelper::deserialize(deserializer)?;
        Ok(StateBOC {
            state_cells: helper.state_cells,
            references: helper.references,
            roots: helper.roots,
            hash: helper.hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_boc_new() {
        let state_boc = StateBOC::new();
        assert!(state_boc.state_cells.is_empty());
        assert!(state_boc.references.is_empty());
        assert!(state_boc.roots.is_empty());
        assert!(state_boc.hash.is_none());
    }

    #[test]
    fn test_state_boc_builder() {
        let state_cells = vec![Cell {
            cell_type: CellType::Ordinary,
            data: vec![1, 2, 3],
            references: vec![],
            slice: None,
            nonce: 0,
            balance: 100,
        }];
        let references = vec![vec![4, 5, 6]];
        let roots = vec![vec![7, 8, 9]];
        let hash = [0u8; 32];

        let state_boc = StateBOC {
            state_cells: state_cells.clone(),
            references: references.clone(),
            roots: roots.clone(),
            hash: Some(hash),
        };

        assert_eq!(state_boc.state_cells, state_cells);
        assert_eq!(state_boc.references, references);
        assert_eq!(state_boc.roots, roots);
        assert_eq!(state_boc.hash, Some(hash));
    }

    #[test]
    fn test_state_boc_hash_computation() {
        let mut state_boc = StateBOC::new();
        state_boc.add_cell(Cell {
            cell_type: CellType::Ordinary,
            data: vec![1, 2, 3],
            references: vec![0],
            slice: None,
            nonce: 1,
            balance: 100,
        });

        let hash = state_boc.compute_hash();
        assert!(state_boc.hash.is_some());
        assert_eq!(state_boc.hash.unwrap(), hash);
    }
}
