/* tslint:disable */
/* eslint-disable */
export function init_panic_hook(): void;
/**
 * Generates an Ed25519 keypair and returns it as a tuple of public and private keys in Uint8Array format.
 */
export function generate_keypair(): any;
export function create_channel(): ChannelWrapper;
export function verify_state_update(update: StateUpdateWrapper): boolean;
export enum ContractOpCode {
  CreatePayment = 160,
  UpdateState = 161,
  FinalizeState = 162,
  DisputeState = 163,
  InitChannel = 164,
}
export class ChannelWrapper {
  free(): void;
  constructor();
  update_state(update: StateUpdateWrapper): void;
  verify(): boolean;
  readonly hash: Uint8Array;
  readonly state_count: number;
}
export class ClientStorage {
  free(): void;
  constructor();
  saveState(channel_id: string, state: any): void;
  loadState(channel_id: string): any;
  listChannels(): (string)[];
}
export class StateUpdateWrapper {
  free(): void;
  /**
   * Constructs a new `StateUpdateWrapper` and validates the input data.
   */
  constructor(dag_cells: Uint8Array, references: Uint32Array, roots: Uint32Array, state_mapping: Uint32Array, nonce: bigint);
  verify(): boolean;
  readonly dag_cells: Uint8Array;
  readonly references: Uint32Array;
  readonly roots: Uint32Array;
  readonly hash: Uint8Array;
  readonly nonce: bigint;
  readonly state_mapping: Array<any>;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_clientstorage_free: (a: number, b: number) => void;
  readonly clientstorage_new: () => [number, number, number];
  readonly clientstorage_saveState: (a: number, b: number, c: number, d: any) => [number, number];
  readonly clientstorage_loadState: (a: number, b: number, c: number) => [number, number, number];
  readonly clientstorage_listChannels: (a: number) => [number, number, number, number];
  readonly init_panic_hook: () => void;
  readonly __wbg_stateupdatewrapper_free: (a: number, b: number) => void;
  readonly stateupdatewrapper_new: (a: any, b: any, c: any, d: any, e: bigint) => [number, number, number];
  readonly stateupdatewrapper_dag_cells: (a: number) => any;
  readonly stateupdatewrapper_references: (a: number) => any;
  readonly stateupdatewrapper_roots: (a: number) => any;
  readonly stateupdatewrapper_hash: (a: number) => any;
  readonly stateupdatewrapper_nonce: (a: number) => bigint;
  readonly stateupdatewrapper_state_mapping: (a: number) => any;
  readonly stateupdatewrapper_verify: (a: number) => number;
  readonly generate_keypair: () => [number, number, number];
  readonly __wbg_channelwrapper_free: (a: number, b: number) => void;
  readonly channelwrapper_new: () => number;
  readonly channelwrapper_update_state: (a: number, b: number) => [number, number];
  readonly channelwrapper_hash: (a: number) => any;
  readonly channelwrapper_state_count: (a: number) => number;
  readonly channelwrapper_verify: (a: number) => number;
  readonly verify_state_update: (a: number) => number;
  readonly create_channel: () => number;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_4: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __externref_drop_slice: (a: number, b: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

export function init() {
  throw new Error('Function not implemented.');
}
