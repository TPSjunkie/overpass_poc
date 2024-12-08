// # Local wallet data management

export class Wallet {
    private states: Map<string, Uint8Array>;
    private proofs: Map<string, Uint8Array>;
  
    constructor() {
      this.states = new Map();
      this.proofs = new Map();
    }
  
    saveState(channelId: string, state: Uint8Array): void {
      this.states.set(channelId, state);
    }
  
    loadState(channelId: string): Uint8Array | undefined {
      return this.states.get(channelId);
    }
  
    saveProof(channelId: string, proof: Uint8Array): void {
      this.proofs.set(channelId, proof);
    }
  
    loadProof(channelId: string): Uint8Array | undefined {
      return this.proofs.get(channelId);
    }
  }