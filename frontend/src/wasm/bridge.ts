// src/wasm/bridge.ts
import type { WasmModule } from './types';

let wasmInstance: WasmModule | null = null;

export async function initWasm(): Promise<WasmModule> {
  if (!wasmInstance) {
    try {
      const wasm = await import('@/pkg/overpass_wasm');
      if (typeof wasm.init === 'function') {
        await wasm.init();
      }
      wasmInstance = wasm as unknown as WasmModule;
      return wasmInstance;
    } catch (err) {
      console.error('Failed to initialize WASM:', err);
      throw err;
    }
  }
  return wasmInstance;
}

export function getWasmInstance(): WasmModule {
  if (!wasmInstance) {
    throw new Error('WASM not initialized. Call initWasm() first');
  }
  return wasmInstance;
}