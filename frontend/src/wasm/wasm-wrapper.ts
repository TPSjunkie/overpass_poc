// ./src/wasm/wasm-wrapper.ts
// # Wrapper for the WASM module

import * as wasm from './overpass_wasm_bg.wasm';

export class WasmWrapper {
  static async init() {
    await wasm.init();
  }

  static generateProof(
    currentState: Uint8Array,
    nextState: Uint8Array,
    transitionData: Uint8Array
  ): Uint8Array {
    return wasm.generate_proof(currentState, nextState, transitionData);
  }

  static verifyProof(proof: Uint8Array, currentState: Uint8Array, nextState: Uint8Array): boolean {
    return wasm.verify_proof(proof);
  }
}