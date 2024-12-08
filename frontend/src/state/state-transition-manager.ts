import { WasmWrapper } from '../wasm/wasm-wrapper';
import { Poseidon } from '@iden3/js-crypto'; // Using @iden3/js-crypto for Poseidon hash

export class StateTransitionManager { // TODO: Fix type
    private currentState: Uint8Array;       // TODO: Fix type       

  constructor(initialState: Uint8Array) {
    this.currentState = initialState;
  }

  async generateTransition(transitionData: Uint8Array): Promise<{ proof: Uint8Array; nextState: Uint8Array }> {
    const nextState = this.computeNextState(this.currentState, transitionData);
    const proof = WasmWrapper.generateProof(this.currentState, nextState, transitionData);

    this.currentState = nextState;

    return { proof, nextState };
  }

  verifyTransition(proof: Uint8Array, nextState: Uint8Array): boolean {
    return WasmWrapper.verifyProof(proof, this.currentState, nextState);
  }

  // Compute the next state using Poseidon hash
  private computeNextState(currentState: Uint8Array, transitionData: Uint8Array): Uint8Array {
    // Compute the next state locally
    const input = [...currentState, ...transitionData].map(BigInt);
    const hash = Poseidon.hash(input);
    return new Uint8Array([Number(hash % BigInt(256))]); // Convert bigint to Uint8Array  }}
  }
}