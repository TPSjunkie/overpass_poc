// src/zkp/bitcoin_ephemeral_state.rs

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::{
    blockdata::transaction::{Transaction, TxIn, TxOut}, consensus::encode, Address, Network, OutPoint, ScriptBuf
    
};
use bitcoin::PublicKey;
use bitcoin::blockdata::script::Builder;
use bitcoin::secp256k1::{Secp256k1, SecretKey, All};
use std::collections::HashMap;
use std::str::FromStr;
/// Represents a simple Bitcoin client for testing purposes.
pub struct BitcoinClient {
    rpc: Client,
    utxos: HashMap<String, (TxOut, bitcoin::OutPoint)>, // Keyed by txid
    secp: Secp256k1<All>,
    network: Network,
}

impl BitcoinClient {
    /// Creates a new Bitcoin client.
    pub fn new(rpc_url: &str, rpc_user: &str, rpc_password: &str, network: Network) -> Result<Self> {
        // Initialize the RPC client with credentials.
        let auth = Auth::UserPass(rpc_user.to_string(), rpc_password.to_string());
        let rpc = Client::new(rpc_url, auth)
            .context("Failed to create RPC client. Check RPC URL and credentials.")?;
        
        Ok(Self {
            rpc,
            utxos: HashMap::new(),
            secp: Secp256k1::new(),
            network,
        })
    }

    /// Retrieves a new Bitcoin address.
    pub fn get_new_address(&self) -> Result<Address> {
        let address = self.rpc.get_new_address(None, None)
            .context("Failed to get new address")?;
        Ok(address.assume_checked())
    }

    /// Generates a specified number of blocks to the given address (Regtest only).
    pub fn generate_blocks(&self, count: u32, address: &str) -> Result<()> {
        let addr = Address::from_str(address)
            .context("Invalid Bitcoin address")?
            .assume_checked();
        self.rpc.generate_to_address(count.into(), &addr)
            .context("Failed to generate blocks")?;
        Ok(())
    }

    /// Retrieves the balance of the wallet.
    pub fn get_balance(&self) -> Result<u64> {
        let balance = self.rpc.get_balance(None, None)
            .context("Failed to get balance")?;
        Ok(balance.to_sat())
    }

    /// Retrieves a spendable UTXO with the specified amount.
    pub fn get_spendable_utxo(&mut self, amount: u64) -> Result<(bitcoin::OutPoint, TxOut)> {
        // Refresh UTXO set
        self.refresh_utxos()?;

        // Find a UTXO with sufficient amount
        for (_, (tx_out, outpoint)) in &self.utxos {
            if tx_out.value >= amount {
                return Ok((*outpoint, tx_out.clone()));
            }
        }

        Err(anyhow!("No spendable UTXO found with the specified amount"))
    }

    /// Refreshes the UTXO set by fetching from the RPC.
    fn refresh_utxos(&mut self) -> Result<()> {
        self.utxos.clear();
        let utxos = self.rpc.list_unspent(None, None, None, None, None)
            .context("Failed to list unspent transactions")?;
        for utxo in utxos {
            let txid = utxo.txid.to_string();
            let tx_out = TxOut {
                value: utxo.amount.to_sat(),
                script_pubkey: utxo.script_pub_key,
            };
            let outpoint = OutPoint {
                txid: utxo.txid,
                vout: utxo.vout,
            };
            self.utxos.insert(txid, (tx_out, outpoint));
        }
        Ok(())
    }

    /// Signs a raw transaction hex.
    pub fn sign_raw_transaction(&self, raw_tx_hex: &str) -> Result<String> {
        let tx_bytes = hex::decode(raw_tx_hex)
            .context("Failed to decode raw transaction hex")?;
        let tx: Transaction = encode::deserialize(&tx_bytes)
            .context("Failed to deserialize transaction")?;
        
        let signed_tx = self.rpc.sign_raw_transaction_with_wallet(&tx, None, None)
            .context("Failed to sign transaction")?;

        let signed_tx_hex = hex::encode(signed_tx.hex);
        Ok(signed_tx_hex)
    }

    /// Sends a raw transaction given its hex representation.
    pub fn send_raw_transaction_hex(&self, raw_tx_hex: &str) -> Result<String> {
        let tx = self.rpc.send_raw_transaction(raw_tx_hex)
            .context("Failed to send raw transaction")?;
        Ok(tx.to_string())
    }

    /// Creates a P2PKH script for demonstration purposes.
    pub fn create_p2pkh_script(&self, public_key: &PublicKey) -> ScriptBuf {
        Builder::new()
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_DUP)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_HASH160)
            .push_slice(&bitcoin::PublicKey::from(*public_key).pubkey_hash())
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
            .into_script()
    }
    /// Generates a key pair for signing transactions.
    pub fn generate_keypair(&self, secret_key: &SecretKey) -> PublicKey {
        PublicKey::from_private_key(&self.secp, &bitcoin::PrivateKey::from_slice(&secret_key[..], self.network).unwrap())
    }}

/// Builds an OP_RETURN transaction embedding the provided data.
pub fn build_op_return_transaction(client: &mut BitcoinClient, data: &[u8], private_key: &SecretKey) -> Result<String> {
    // Generate key pair
    let public_key = client.generate_keypair(private_key);
    let script_pubkey = client.create_p2pkh_script(&public_key);

    // Amount to send to OP_RETURN
    let op_return_amount = 0;
    let fee = 1_000;
    let total_amount = op_return_amount + fee;

    // Get a spendable UTXO
    let (outpoint, tx_out) = client.get_spendable_utxo(total_amount)?;

    // Build OP_RETURN script
    let op_return_script = Builder::new()
        .push_opcode(bitcoin::blockdata::opcodes::all::OP_RETURN) .into_script();      

    // Create inputs and outputs
    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence(0xffffffff),
        witness: bitcoin::Witness::new(),
    };
    let tx_out_opreturn = TxOut {
        value: op_return_amount,
        script_pubkey: op_return_script,
    };
    let tx_out_change = TxOut {
        value: tx_out.value - total_amount,
        script_pubkey,
    };

    // Build unsigned transaction
    let tx = Transaction {
        version: 2,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out_opreturn, tx_out_change],
    };

    // Sign the transaction
    let signed_tx_hex = client.sign_raw_transaction(&hex::encode(encode::serialize(&tx)))?;

    // Send the transaction
    let txid = client.send_raw_transaction_hex(&signed_tx_hex)?;

    Ok(txid)
}