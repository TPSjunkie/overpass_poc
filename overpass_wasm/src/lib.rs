// src/lib.rs

mod channel;
mod error;

mod storage;

pub mod types; // Ensure this is declared

pub use types::dag_boc::StateUpdateWrapper; // Re-export `StateUpdateWrapper`
pub use channel::{Channel, ChannelWrapper, create_channel, verify_state_update};
pub use types::generate_keypair; // Re-export `generate_keypair`
use wasm_bindgen::prelude::*;

// Initialize console error panic hook for better error messages
#[wasm_bindgen(start)]
pub fn init_panic_hook() -> Result<(), JsValue> {
    #[cfg(feature = "console_error_panic_hook")]
    {
        console_error_panic_hook::set_once();
    }
    Ok(())
}