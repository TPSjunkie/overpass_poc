// ./src/services/overpass_db.rs
use sled::{self, Db};
use anyhow::{Result, Context};

/// Wrapper around the sled database for managing Overpass states and transactions.
pub struct OverpassDB {
    db: Db,
}

impl OverpassDB {
    /// Creates a new instance of the OverpassDB.
    /// 
    /// # Arguments
    /// 
    /// * `path` - Path to the database directory.
    /// 
    /// # Returns
    /// 
    /// Result containing the OverpassDB instance or an error if the database cannot be opened.
    pub fn new(path: &str) -> Result<Self> {
        let db = sled::open(path).context("Failed to open database")?;
        Ok(Self { db })
    }

    /// Retrieves a value from the database by key.
    /// 
    /// # Arguments
    /// 
    /// * `key` - The key to look up.
    /// 
    /// # Returns
    /// 
    /// * `Some(Vec<u8>)` if the key exists.
    /// * `None` if the key does not exist or an error occurs.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .get(key)
            .context("Database get operation failed")
            .map(|opt| opt.map(|ivec| ivec.to_vec()))
    }

    /// Inserts a key-value pair into the database.
    /// 
    /// # Arguments
    /// 
    /// * `key` - The key to insert.
    /// * `value` - The value to associate with the key.
    /// 
    /// # Returns
    /// 
    /// * `Some(Vec<u8>)` if the key previously existed, containing the old value.
    /// * `None` if the key is new.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .insert(key, value)
            .context("Database put operation failed")
            .map(|opt| opt.map(|ivec| ivec.to_vec()))
    }

    /// Deletes a key from the database.
    /// 
    /// # Arguments
    /// 
    /// * `key` - The key to delete.
    /// 
    /// # Returns
    /// 
    /// * `Some(Vec<u8>)` if the key existed, containing the old value.
    /// * `None` if the key did not exist.
    pub fn delete(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .remove(key)
            .context("Database delete operation failed")
            .map(|opt| opt.map(|ivec| ivec.to_vec()))
    }

    /// Retrieves a range of keys and their associated values.
    /// 
    /// # Arguments
    /// 
    /// * `start` - The starting key (inclusive).
    /// * `end` - The ending key (exclusive).
    /// 
    /// # Returns
    /// 
    /// An iterator over the keys and values within the range.
    pub fn scan(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut result = Vec::new();
        for item in self.db.range(start..end) {
            let (key, value) = item.context("Database range scan failed")?;
            result.push((key.to_vec(), value.to_vec()));
        }
        Ok(result)
    }

    /// Flushes all changes to disk.
    /// 
    /// Ensures that all changes made to the database are durable.
    pub fn flush(&self) -> Result<()> {
        self.db.flush().context("Database flush failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    const TEST_DB_PATH: &str = "./test_db";

    fn setup_db() -> Result<OverpassDB> {
        // Ensure a clean state for tests
        if Path::new(TEST_DB_PATH).exists() {
            fs::remove_dir_all(TEST_DB_PATH).expect("Failed to clean up test database directory");
        }
        OverpassDB::new(TEST_DB_PATH)
    }

    fn teardown_db() {
        if Path::new(TEST_DB_PATH).exists() {
            fs::remove_dir_all(TEST_DB_PATH).expect("Failed to clean up test database directory");
        }
    }

    #[test]
    fn test_put_get_delete() -> Result<()> {
        let db = setup_db()?;

        // Test put operation with error handling
        db.put(b"key1", b"value1")?;
        db.put(b"key2", b"value2")?;

        // Test get operation with error handling and value verification
        let get_result1 = db.get(b"key1")?;
        let get_result2 = db.get(b"key2")?;
        let get_result3 = db.get(b"key3")?;

        assert_eq!(get_result1, Some(b"value1".to_vec()), "Incorrect value for key1");
        assert_eq!(get_result2, Some(b"value2".to_vec()), "Incorrect value for key2");
        assert_eq!(get_result3, None, "Non-existent key should return None");

        // Test delete operation with error handling and value verification
        let delete_result = db.delete(b"key1")?;
        assert_eq!(delete_result, Some(b"value1".to_vec()), "Incorrect deleted value");

        // Verify deletion
        let get_after_delete = db.get(b"key1")?;
        assert_eq!(get_after_delete, None, "Key should not exist after deletion");

        // Test overwriting existing key
        db.put(b"key2", b"new_value2")?;
        let updated_value = db.get(b"key2")?;
        assert_eq!(updated_value, Some(b"new_value2".to_vec()), "Value not updated correctly");

        teardown_db();
        Ok(())
    }

    #[test]
    fn test_scan() -> Result<()> {
        let db = setup_db()?;

        // Insert test data
        db.put(b"key1", b"value1")?;
        db.put(b"key2", b"value2")?;
        db.put(b"key3", b"value3")?;

        // Test scanning range
        let scanned = db.scan(b"key1", b"key3")?;
        assert_eq!(scanned.len(), 2);
        assert_eq!(scanned[0], (b"key1".to_vec(), b"value1".to_vec()));
        assert_eq!(scanned[1], (b"key2".to_vec(), b"value2".to_vec()));

        teardown_db();
        Ok(())
    }

    #[test]
    fn test_flush() -> Result<()> {
        let db = setup_db()?;
        
        // Insert some data
        db.put(b"key", b"value")?;
        
        // Flush changes to disk
        db.flush()?;
        
        // Verify data persists
        let value = db.get(b"key")?;
        assert_eq!(value, Some(b"value".to_vec()));

        teardown_db();
        Ok(())
    }
}