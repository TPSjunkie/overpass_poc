// ./src/types/generate_keypair.rs

use wasm_bindgen::prelude::*;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;

/// Generates an Ed25519 keypair and returns it as a tuple of public and private keys in Uint8Array format.
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    // Generate 32 random bytes for the private key
    let mut private_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut private_key_bytes);

    // Create the signing key from the private key bytes
    let signing_key = SigningKey::from_bytes(&private_key_bytes);

    // Extract the public key from the signing key
    let public_key = signing_key.verifying_key().to_bytes(); // 32 bytes public key

    // Serialize the keys into a JavaScript-compatible format
    serde_wasm_bindgen::to_value(&(public_key.to_vec(), private_key_bytes.to_vec()))
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair().unwrap();
        let keypair: (Vec<u8>, Vec<u8>) = serde_wasm_bindgen::from_value(keypair).unwrap();
        let (public_key, private_key) = keypair;

        // Check key lengths
        assert_eq!(public_key.len(), 32, "Public key must be 32 bytes");
        assert_eq!(private_key.len(), 32, "Private key must be 32 bytes");

        // Ensure keys are different
        assert_ne!(public_key, private_key, "Public and private keys must not be identical");
    }
}