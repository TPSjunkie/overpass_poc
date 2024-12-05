import type { ChannelConfig, ChannelState, WalletState } from './types';

export class OverpassChannel {
  resolveHTLC(_id: any, _preimage: Uint8Array, receiver: string, htlcAmount: number) {
      throw new Error("Method not implemented.");
  }
  createHTLCWithParams(_arg0: { amount: number; hashLock: string; timeoutBlocks: number; }) {
      throw new Error("Method not implemented.");
  }
  private channel: any | null = null;
  private config: ChannelConfig;
  private wallet: WalletState | null = null;

  constructor(config: ChannelConfig) {
    this.config = config;
  }

  /// HTLC
  async createHTLC(sender: string, receiver: string, amount: number, timeout: number): Promise<any> {
    if (!this.channel) throw new Error('Channel not initialized');

    const encoder = new TextEncoder();
    const senderBytes = encoder.encode(sender);
    const receiverBytes = encoder.encode(receiver);

    const htlc = await this.channel.createHTLC(senderBytes, receiverBytes, amount, timeout);
    return htlc;
  }
  async redeemHTLC(sender: string, receiver: string, amount: number, timeout: number, secret: string): Promise<any> {
    if (!this.channel) throw new Error('Channel not initialized');

    const encoder = new TextEncoder();
    const senderBytes = encoder.encode(sender);
    const receiverBytes = encoder.encode(receiver);
    const secretBytes = encoder.encode(secret);

    const htlc = await this.channel.redeemHTLC(senderBytes, receiverBytes, amount, timeout, secretBytes);
    return htlc;
  } 

  async refundHTLC(sender: string, receiver: string, amount: number, timeout: number, secret: string): Promise<any> {
    if (!this.channel) throw new Error('Channel not initialized');

    const encoder = new TextEncoder();
    const senderBytes = encoder.encode(sender);
    const receiverBytes = encoder.encode(receiver);
    const secretBytes = encoder.encode(secret);

    const htlc = await this.channel.refundHTLC(senderBytes, receiverBytes, amount, timeout, secretBytes);
    return htlc;
  }

  async claimHTLC(sender: string, receiver: string, amount: number, timeout: number, secret: string): Promise<any> {
    if (!this.channel) throw new Error('Channel not initialized');

    const encoder = new TextEncoder();
    const senderBytes = encoder.encode(sender);
    const receiverBytes = encoder.encode(receiver);
    const secretBytes = encoder.encode(secret);

    const htlc = await this.channel.claimHTLC(senderBytes, receiverBytes, amount, timeout, secretBytes);
    return htlc;
  }
  async initialize(): Promise<void> {
    init();
    this.channel = await createChannel(JSON.stringify(this.config));
  }

  async createWallet(passphrase: string): Promise<WalletState> {
    if (!this.channel) throw new Error('Channel not initialized');
    
    const encoder = new TextEncoder();
    const passphraseBytes = encoder.encode(passphrase);
    
    const wallet = await this.channel.createWallet(passphraseBytes);
    this.wallet = wallet as WalletState;
    return wallet;
  }

  async transfer(amount: number): Promise<ChannelState> {
    if (!this.channel || !this.wallet) {
      throw new Error('Channel or wallet not initialized');
    }

    const walletBytes = new TextEncoder().encode(JSON.stringify(this.wallet));
    const newState = await this.channel.updateState(BigInt(amount), walletBytes);
    return JSON.parse(newState) as ChannelState;
  }
}

function init() {
  throw new Error('Function not implemented.');
}

async function createChannel(_config: string): Promise<any> {
  throw new Error('Function not implemented.');
}
export type HTLC = {
  id: string;
  amount: number;
  hashLock: string;
  timeoutBlocks: number;
};

export default OverpassChannel;
