// ./src/bitcoin/mod.rs

pub mod client;
pub mod scripts;
pub mod bitcoin_transaction;
pub mod wallet;
pub mod rpc_client;
pub mod bitcoin_types;
pub mod zkp_handler;
pub mod stealth_addresses;

pub use client::BitcoinClient;
pub use wallet::{StealthKeyPair, Wallet};
pub use bitcoin_types::{HTLCParameters, StealthAddress};
pub use zkp_handler::BitcoinHtlcProof;
pub use stealth_addresses::{StealthAddressGenerator, StealthAddressManager};
pub use rpc_client::{BitcoinRpcClient, BitcoinRpcConfig};
pub use bitcoin_transaction::BitcoinTransaction;
pub use bitcoin_types::BitcoinLockState;