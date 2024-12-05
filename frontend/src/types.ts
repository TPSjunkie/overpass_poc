export interface ChannelConfig {
    network: 'mainnet' | 'testnet' | 'regtest';
    initial_balance: number;
    security_bits: number;
  }
  
  export interface ChannelState extends ChannelConfig {
    balances: number[];
    nonce: number;
  }
export interface WalletState {
  encrypted: boolean;
  network: string;
  stealth_keys?: {
    scan_key: string;
    spend_key: string;
  };
}

export interface LogMessage {
  timestamp: string;
  message: string;
}

export interface Transaction {
  id: number;
  sender: string;
  recipient: string;
  amount: number;
  timestamp: string;
}

export interface StateUpdate {
  transaction: Transaction;
  new_state: ChannelState;
}

export interface ChannelManager {
  initialize: () => Promise<void>;
  process_transaction: (
    amount: bigint,
    data: Uint8Array,
  ) => Promise<StateUpdate>;
  get_state: () => Promise<ChannelState>;
  get_logs: () => Promise<LogMessage[]>;
  get_transactions: () => Promise<Transaction[]>;
  get_wallet_state: () => Promise<WalletState>;
}


  export interface ChannelState {
    balances: number[];
    nonce: number;
  }
  
  export interface WalletState {
    encrypted: boolean;
    network: string;
    stealth_keys?: {
      scan_key: string;
      spend_key: string;
    };
  }
  
  export interface LogMessage {
    timestamp: string;
    message: string;
  }

export interface User {
    id: number;
    username: string;
    email: string;
    password: string;
}
