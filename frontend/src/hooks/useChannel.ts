// src// File: frontend/src/hooks/useChannel.ts

import { useState, useCallback } from 'react';
import { init } from '../wasm/overpass_wasm';
import Channel, { InitInput } from '../wasm/overpass_wasm';

interface ChannelConfig {
    network: 'mainnet' | 'testnet' | 'regtest';
    initial_balance: bigint;
    security_bits: number;
    version: string;
}

interface StateUpdate {
  nonce: bigint;
  balance: bigint;
  merkle_root: Uint8Array;
  size: number;
}

interface TransactionResult {
  hash: string;
  confirmations: number;
  size: number;
}

export class ChannelManager {
  private channel: any | null = null;
  private initialized = false;

  async initialize(params: { network: string; initial_balance: number; security_bits: number; }) {
    if (!this.initialized) {
      await init();
      const config: ChannelConfig = {
          network: params.network as 'mainnet' | 'testnet' | 'regtest',
          initial_balance: BigInt(params.initial_balance),
          security_bits: params.security_bits,
          version: '0.1.0'
      };
    
      const configString = JSON.stringify(config, (_, value) =>
          typeof value === 'bigint' ? value.toString() : value
      );
    
      this.channel = new (Channel as any)(configString);
      this.initialized = true;
      return { size: await this.getStateSize() };
    }
    return null;
  }

  private async getStateSize(): Promise<number> {
    const state = await this.getCurrentState();
    return new Blob([state]).size;
  }

  async getCurrentState(): Promise<Uint8Array> {
    if (!this.channel) throw new Error('Channel not initialized');
    return await this.channel.get_current_state();
  }

  async updateState(amount: bigint, data: Uint8Array): Promise<StateUpdate> {
    if (!this.channel) throw new Error('Channel not initialized');
    
    const result = await this.channel.update_state(amount, data);
    const stateSize = await this.getStateSize();
    
    return {
      nonce: amount,
      balance: amount,
      merkle_root: result,
      size: stateSize
    };
  }

  async generateProof(): Promise<Uint8Array> {
    if (!this.channel) throw new Error('Channel not initialized');
    return await this.channel.finalize_state();
  }
  
  async verifyProof(state: Uint8Array): Promise<boolean> {
    if (!this.channel) throw new Error('Channel not initialized');
    return await this.channel.verify_state(state);
  }
  
  async processTransaction(amount: bigint, data: Uint8Array): Promise<TransactionResult> {
    if (!this.channel) throw new Error('Channel not initialized');
    
    const state = await this.updateState(amount, data);
    const proof = await this.generateProof();
    const verified = await this.verifyProof(state.merkle_root);
    
    if (!verified) {
      throw new Error('Transaction verification failed');
    }

    return {
      hash: Array.from(proof)
        .map((b: number) => b.toString(16).padStart(2, '0'))
        .join(''),
      confirmations: verified ? 1 : 0,
      size: state.size
    };
  }

  async verifyFinalState(): Promise<{ confirmations: number }> {
    if (!this.channel) throw new Error('Channel not initialized');
    const state = await this.getCurrentState();
    const isValid = await this.channel.verify_state(state);
    return { confirmations: isValid ? 1 : 0 };
  }

  destroy() {
    if (this.channel) {
      this.channel.free();
      this.channel = null;
      this.initialized = false;
    }
  }
}

export function useChannel() {
  const [channelManager] = useState(() => new ChannelManager());

  const initialize = useCallback(async (params: { network: string; initial_balance: number; security_bits: number; }) => {
    return await channelManager.initialize(params);
  }, [channelManager]);

  return {
    channelManager,
    initialize
  };
}