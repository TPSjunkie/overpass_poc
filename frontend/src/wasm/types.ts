import { SystemError, SystemErrorType } from "@/error/client_errors";

import { Result } from "postcss";
 // Define the interface for the WASM module
export interface WasmModule {
    memory: WebAssembly.Memory;
    Channel: any;
  }
  
export interface ChannelConfig {
    network: 'mainnet' | 'testnet' | 'regtest';
    initial_balance: number;
    security_bits: number;
  }
  
  export interface StateUpdate {
    nonce: number;
    balance: bigint;
    merkle_root: Uint8Array;
    cell_hash: Uint8Array;
  }
  
  // Expose the WASM module interface
  export interface WasmChannel {
    new(config_str: string): WasmChannel;
    create_wallet(entropy: Uint8Array): Promise<Uint8Array>;
    update_state(amount: bigint, data: Uint8Array): Promise<StateUpdate>;
    process_transaction(tx_data: Uint8Array): Promise<Uint8Array>;
    finalize_state(): Promise<Uint8Array>;
    get_current_state(): Promise<Uint8Array>;
    verify_state(state_bytes: Uint8Array): Promise<boolean>;
    free(): void;
  }
  
  // Main WASM module interface
  export interface WasmModule {
    Channel: any;
    start(): void;
    memory: WebAssembly.Memory;
  }  
  // Type-safe initialization function
  export type WasmInit = () => Promise<WasmModule>;
  
  // Bridge between TypeScript and WASM
  export class Channel {
    static new(): Channel | null {
        throw new Error("Method not implemented.");
    }
    private wasmChannel: WasmChannel;
  
    constructor(config: ChannelConfig) {
      this.wasmChannel = new (getWasmModule().Channel)(JSON.stringify(config));
    }
  
    async createWallet(entropy: Uint8Array): Promise<Uint8Array> {
      return await this.wasmChannel.create_wallet(entropy);
    }
  
    async updateState(amount: bigint, data: Uint8Array): Promise<StateUpdate> {
      return await this.wasmChannel.update_state(amount, data);
    }
  
    async processTransaction(txData: Uint8Array): Promise<Uint8Array> {
      return await this.wasmChannel.process_transaction(txData);
    }
  
    async finalizeState(): Promise<Uint8Array> {
      return await this.wasmChannel.finalize_state();
    }
  
    async getCurrentState(): Promise<Uint8Array> {
      return await this.wasmChannel.get_current_state();
    }
  
    async verifyState(stateBytes: Uint8Array): Promise<boolean> {
      return await this.wasmChannel.verify_state(stateBytes);
    }
  
    destroy(): void {
      this.wasmChannel.free();
    }
  }
  
  // Module loading and caching
  let wasmModule: WasmModule | null = null;
export async function initWasm(): Promise<void> {
  if (!wasmModule) {
    const wasm = await import('./overpass_wasm.js');
    await wasm.default();
    wasmModule = {
      ...wasm,
      Channel: wasm.ChannelWrapper,
      start: () => {},
      memory: new WebAssembly.Memory({ initial: 256, maximum: 256 })
    };
    wasmModule.start();
  }
}
  
  export function getWasmModule(): WasmModule {
    if (!wasmModule) {
      throw new Error('WASM module not initialized. Call initWasm() first.');
    }
    return wasmModule;
  }
/// This file contains the types for the WASM module.
/// Represents a state init object.
// Slice of a cell
export interface Slice {
    start: number;
    end: number;
}

// Cell type
export enum CellType {
    Ordinary,
    MerkleProof,
}

// Cell structure with necessary fields.
export interface Cell {
    nonce: any;
    balance: number;
    cellType: CellType;
    data: Uint8Array;
    references: number[];
    slice?: Slice;
}

export class CellBuilder {
    private cells: Map<number, Cell>;
    private size: number;

    constructor() {
        this.cells = new Map();
        this.size = 0;
    }
    // Adds a cell to the builder.
    public addCell(cell: Cell): Result {
        const cellId = cell.nonce;
        if (this.cells.has(cellId)) {
            return new SystemError(
                SystemErrorType.InvalidTransaction,
                "Cell already exists"
            ) as unknown as Result;
        }
        this.size += cell.balance;
        this.cells.set(cellId, cell);
        return {} as Result;
    }

    // Adds multiple cells to the builder.
    public addCells(cells: Cell[]): Result {
        for (const cell of cells) {
            const result = this.addCell(cell);
            if (result instanceof SystemError) {
                return result;
            }
        }
        return {} as Result;
    }

    // Builds the cells from the builder.
    public buildCells(): Result {
        const cells: Cell[] = [];
        for (const [id, cell] of this.cells) {
            const newCell = { ...cell, nonce: id };
            cells.push(newCell);
        }
        return cells as unknown as Result;
    }
}       


export class STATEBOC {
    [x: string]: any;
    private stateCells: Uint8Array[];
    private references: Uint8Array[];
    private roots: Uint8Array[];
    private hashValue?: Uint8Array;

    constructor() {
        this.stateCells = [];
        this.references = [];
        this.roots = [];
        this.hashValue = undefined;
    }

    addCell(cell: Uint8Array): void {
        this.stateCells.push(cell);
    }
    addRoot(index: number): void {
        this.roots.push(this.stateCells[index]);
    }

    withHash(hash: Uint8Array): STATEBOC {
        this.hashValue = hash;
        return this;
    }

    withStateCells(stateCells: Uint8Array[]): STATEBOC {
        this.stateCells = stateCells;
        return this;
    }

    withReferences(references: Uint8Array[]): STATEBOC {
        this.references = references;
        return this;
    }

    withRoots(roots: Uint8Array[]): STATEBOC {
        this.roots = roots;
        return this;
    }

    getHash(): Uint8Array {
        return this.hashValue || new Uint8Array(32);
    }

    getStateCells(): Uint8Array[] {
        return this.stateCells;
    }

    getReferences(): Uint8Array[] {
        return this.references;
    }

    getRoots(): Uint8Array[] {
        return this.roots;
    }

    setHash(hash: Uint8Array): void {
        this.hashValue = hash;
    }

    setStateCells(stateCells: Uint8Array[]): void {
        this.stateCells = stateCells;
    }

    setReferences(references: Uint8Array[]): void {
        this.references = references;
    }

    setRoots(roots: Uint8Array[]): void {
        this.roots = roots;
    }

    serializeToVec(): Promise<Uint8Array> {
        return new Promise((resolve, reject) => {
            try {
                const data = {
                    stateCells: this.stateCells,
                    references: this.references,
                    roots: this.roots,
                    hash: this.hashValue
                };
                const jsonString = JSON.stringify(data);
                const encoder = new TextEncoder();
                resolve(encoder.encode(jsonString));
            } catch (e: unknown) {
                reject(new SystemError(SystemErrorType.SerializationError, (e as Error).message));
            }
        });
    }

    static deserialize(data: Uint8Array): Promise<STATEBOC> {
        return new Promise((resolve, reject) => {
            try {
                const decoder = new TextDecoder();
                const jsonString = decoder.decode(data);
                const parsed = JSON.parse(jsonString);
                const stateBoc = new STATEBOC()
                    .withStateCells(parsed.stateCells)
                    .withReferences(parsed.references)
                    .withRoots(parsed.roots);
                if (parsed.hash) {
                    stateBoc.withHash(parsed.hash);
                }
                resolve(stateBoc);
            } catch (e: unknown) {
                reject(new SystemError(SystemErrorType.SerializationError, (e as Error).message));
            }
        });
    }

    async computeHash(): Promise<Uint8Array> {
        const data = new Uint8Array([
            ...this.stateCells.reduce((acc: number[], curr) => [...acc, ...Array.from(curr)], []),
            ...this.references.reduce((acc: number[], curr) => [...acc, ...Array.from(curr)], []),
            ...this.roots.reduce((acc: number[], curr) => [...acc, ...Array.from(curr)], [])
        ]);
        
        // Web Crypto API for SHA-256
        const buffer = await crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(buffer);
    }
}

export class DAGBOC {
    dagCells: never[];
    references: never[];
    roots: never[];
    hashValue: undefined;
    stateMapping: any;
    hash: any;
    constructor() {
        this.dagCells = [];
        this.references = [];
        this.roots = [];
        this.hashValue = undefined;
    }

    getStateCells(): Uint8Array[] {
        return [...this.dagCells];
    }
    addCell(cellData: Uint8Array): number {
        const id = this.dagCells.length;
        (this.dagCells as Uint8Array[]).push(cellData);
        return id;
    }

    updateStateMapping(key: Uint8Array, value: number): void {
        this.stateMapping.set(key, value);
    }

    processOpCode(opCode: any): void {
        switch (opCode.type) {
            case 'Add':
                this.addCell(opCode.cell);
                break;
            case 'SetCode':
                const codeIndex = this.dagCells.findIndex((c: Uint8Array) => arrayEquals(c, opCode.code));
                if (codeIndex !== -1) {
                    (this.dagCells as Uint8Array[])[codeIndex] = opCode.newCode;
                } else {
                    throw new Error('Code not found');
                }
                break;
            case 'SetData':
                const cellIndex = this.dagCells.findIndex((c: Uint8Array) => arrayEquals(c, opCode.cell));
                if (cellIndex !== -1) {
                    (this.dagCells as Uint8Array[])[cellIndex] = opCode.newData;
                } else {
                    throw new Error('Cell not found');
                }
                break;
            case 'AddReference':
                (this.references as [number, number][]).push([opCode.from, opCode.to]);
                break;
            case 'SetRoot':
                if (this.dagCells[opCode.index]) {
                    (this.roots as Uint8Array[]).push(this.dagCells[opCode.index] as Uint8Array);
                } else {
                    throw new Error('Index out of bounds');
                }
                break;
            case 'Remove':
                const removeIndex = this.dagCells.findIndex((c: Uint8Array) => arrayEquals(c, opCode.cell));
                if (removeIndex !== -1) {
                    (this.dagCells as Uint8Array[]).splice(removeIndex, 1);
                } else {
                    throw new Error('Cell not found');
                }
                break;
            case 'RemoveReference':
                const refIndex = (this.references as [number, number][]).findIndex(([f, t]) => f === opCode.from && t === opCode.to);
                if (refIndex !== -1) {
                    (this.references as [number, number][]).splice(refIndex, 1);
                } else {
                    throw new Error('Reference not found');
                }
                break;
            default:
                throw new Error('Unsupported operation');
        }
    }
    serialize(): Uint8Array {
        return new TextEncoder().encode(JSON.stringify(this));
    }

    static deserialize(data: Uint8Array): DAGBOC {
        const text = new TextDecoder().decode(data);
        const obj = JSON.parse(text);
        const dagBoc = new DAGBOC();
        dagBoc.dagCells = obj.dagCells;
        dagBoc.references = obj.references;
        dagBoc.roots = obj.roots;
        dagBoc.hash = obj.hash;
        obj.stateMapping.forEach((value: number, key: Uint8Array) => {
            dagBoc.stateMapping.set(key, value);
        });
        return dagBoc;
    }

    async computeHash(): Promise<Uint8Array> {
        const data = new Uint8Array([
            ...(this.dagCells as Uint8Array[]).flatMap((cell: Uint8Array) => Array.from(cell)),
            ...(this.references as [number, number][]).flatMap(([from, to]) => Array.from(new Uint32Array([from, to]))),
            ...(this.roots as Uint8Array[]).flatMap((root: Uint8Array) => Array.from(root))
        ]);

        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(hashBuffer);
    }

    withDagCells(dagCells: Uint8Array[]): DAGBOC {
        this.dagCells = dagCells as never[];
        return this;
    }
    withReferences(references: [number, number][]): DAGBOC {
        this.references = references as never[];
        return this;
    }
    withRoots(roots: Uint8Array[]): DAGBOC {
        this.roots = roots as never[];
        return this;
    }}

function arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((val, index) => val === b[index]);
}   

export class WalletWrapper {
    private contract: any;

    constructor(contract: any) {
        this.contract = contract;
    }

    async createWallet(config: any): Promise<any> {
        const state = await this.contract.create_wallet(config);
        return state;
    }
    async updateState(config: any): Promise<any> {
        const state = await this.contract.update_state(config);
        return state;
    }
    async transfer(config: any): Promise<any> {
        const state = await this.contract.transfer(config);
        return state;
    }
    async getState(): Promise<any> {
        const state = await this.contract.get_state();
        return state;
    }
    async verifyState(config: any): Promise<boolean> {
        const state = await this.contract.verify_state(config);
        return state;
    }
}       

export class PaymentChannelContract {
    private contract: any;

    constructor(contract: any) {
        this.contract = contract;
    }

    async createChannel(config: any): Promise<any> {
        const state = await this.contract.create_channel(config);
        return state;
    }
    async updateState(config: any): Promise<any> {
        const state = await this.contract.update_state(config);
        return state;
    }
    async finalizeState(config: any): Promise<any> {
        const state = await this.contract.finalize_state(config);
        return state;
    }
    async disputeState(config: any): Promise<any> {
        const state = await this.contract.dispute_state(config);
        return state;
    }
    async initChannel(config: any): Promise<void> {
        await this.contract.init_channel(config);
    }
}

export class HTLCWrapper {
    private contract: any;

    constructor(contract: any) {
        this.contract = contract;
    }

    async createHTLC(config: any): Promise<any> {
        const state = await this.contract.create_htlc_state(config);
        return state;
    }

    async updateHTLC(config: any): Promise<any> {
        const state = await this.contract.update_state(config);
        return state;
    }

    async finalizeHTLC(config: any): Promise<any> {
        const state = await this.contract.finalize_state(config);
        return state;
    }

    async disputeHTLC(config: any): Promise<any> {
        const state = await this.contract.dispute_state(config);
        return state;
    }

    async initChannel(config: any): Promise<void> {
        await this.contract.init_channel(config);
    }
}