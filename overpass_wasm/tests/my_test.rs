use wasm_bindgen_test::*;
use overpass_wasm::{ChannelWrapper, StateUpdateWrapper};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_channel_creation() {
    let channel = ChannelWrapper::new();
    assert_eq!(channel.state_count(), 0, "Initial state count should be 0");
}

#[wasm_bindgen_test]
async fn test_state_update() {
    let mut channel = ChannelWrapper::new();

    // Generate test data
    let dag_cells = js_sys::Uint8Array::new_with_length(32);
    let references = js_sys::Uint32Array::from(&[1, 2, 3][..]);
    let roots = js_sys::Uint32Array::from(&[1][..]);
    let state_mapping = js_sys::Uint32Array::from(&[1, 2, 3, 4][..]);
    let nonce = 1u64;

    // Create state update
    let update = overpass_wasm::StateUpdateWrapper::new(
        dag_cells,
        references,
        roots,
        state_mapping,
        nonce,
    )
    .expect("Failed to create state update");

    // Update state
    channel
        .update_state(&update)
        .expect("State update should not fail");

    // Verify state
    assert_eq!(channel.state_count(), 1, "State count should be 1 after update");
    assert!(
        channel.verify(),
        "Channel verification should succeed after valid state update"
    );
}

#[wasm_bindgen_test]
fn test_invalid_state_update() {
    let mut channel = ChannelWrapper::new();

    // Generate test data with empty roots (invalid)
    let dag_cells = js_sys::Uint8Array::new_with_length(32);
    let references = js_sys::Uint32Array::from(&[1, 2, 3][..]);
    let roots = js_sys::Uint32Array::new_with_length(0); // Empty roots
    let state_mapping = js_sys::Uint32Array::from(&[1, 2, 3, 4][..]);
    let nonce = 1u64;

    // Attempt to create an invalid state update and verify it fails
    let update_result = overpass_wasm::StateUpdateWrapper::new(
        dag_cells,
        references,
        roots,
        state_mapping,
        nonce,
    );

    assert!(
        update_result.is_err(),
        "Creating a state update with empty roots should return an error"
    );
}

#[wasm_bindgen_test]
fn test_multiple_updates() {
    let mut channel = ChannelWrapper::new();
    let mut last_hash: Option<js_sys::Uint8Array> = None;

    // Create multiple state updates
    for i in 0..3 {
        let dag_cells = js_sys::Uint8Array::new_with_length(32);
        let references = js_sys::Uint32Array::from(&[1, 2, 3][..]);
        let roots = js_sys::Uint32Array::from(&[i as u32][..]);
        let state_mapping = js_sys::Uint32Array::from(&[1, 2, 3, 4][..]);
        let nonce = i as u64;

        let update = overpass_wasm::StateUpdateWrapper::new(
            dag_cells,
            references,
            roots,
            state_mapping,
            nonce,
        )
        .expect(&format!("Failed to create state update for nonce {i}"));

        channel
            .update_state(&update)
            .expect("State update should not fail");

        let current_hash = channel.hash();

        if let Some(prev_hash) = last_hash {
            assert_ne!(
                prev_hash.to_vec(),
                current_hash.to_vec(),
                "Hash should change with each update"
            );
        }
        last_hash = Some(current_hash);
    }

    assert_eq!(
        channel.state_count(),
        3,
        "State count should reflect the number of updates"
    );
    assert!(
        channel.verify(),
        "Channel verification should succeed after multiple updates"
    );
}
#[wasm_bindgen_test]
fn test_hash_consistency() {
    let channel = ChannelWrapper::new();
    let hash = channel.hash();

    // Hash should be 32 bytes (SHA-256)
    assert_eq!(
        hash.length(),
        32,
        "Hash length should be 32 bytes for SHA-256"
    );

    let channel2 = ChannelWrapper::new();
    // Empty channels should have the same hash
    assert_eq!(
        channel2.hash().to_vec(),
        hash.to_vec(),
        "Empty channels should have identical hashes"
    );
}