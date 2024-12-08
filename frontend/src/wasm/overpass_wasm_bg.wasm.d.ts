/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const __wbg_clientstorage_free: (a: number, b: number) => void;
export const clientstorage_new: () => [number, number, number];
export const clientstorage_saveState: (a: number, b: number, c: number, d: any) => [number, number];
export const clientstorage_loadState: (a: number, b: number, c: number) => [number, number, number];
export const clientstorage_listChannels: (a: number) => [number, number, number, number];
export const init_panic_hook: () => void;
export const __wbg_stateupdatewrapper_free: (a: number, b: number) => void;
export const stateupdatewrapper_new: (a: any, b: any, c: any, d: any, e: bigint) => [number, number, number];
export const stateupdatewrapper_dag_cells: (a: number) => any;
export const stateupdatewrapper_references: (a: number) => any;
export const stateupdatewrapper_roots: (a: number) => any;
export const stateupdatewrapper_hash: (a: number) => any;
export const stateupdatewrapper_nonce: (a: number) => bigint;
export const stateupdatewrapper_state_mapping: (a: number) => any;
export const stateupdatewrapper_verify: (a: number) => number;
export const generate_keypair: () => [number, number, number];
export const __wbg_channelwrapper_free: (a: number, b: number) => void;
export const channelwrapper_new: () => number;
export const channelwrapper_update_state: (a: number, b: number) => [number, number];
export const channelwrapper_hash: (a: number) => any;
export const channelwrapper_state_count: (a: number) => number;
export const channelwrapper_verify: (a: number) => number;
export const verify_state_update: (a: number) => number;
export const create_channel: () => number;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_export_4: WebAssembly.Table;
export const __externref_table_dealloc: (a: number) => void;
export const __externref_drop_slice: (a: number, b: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
export default function() {
    throw new Error('Function not implemented.');
}


export function generate_proof(currentState: Uint8Array, nextState: Uint8Array, transitionData: Uint8Array): Uint8Array {
    throw new Error('Function not implemented.');
}

export function verify_proof(proof: Uint8Array): boolean {
    throw new Error('Function not implemented.');
}

export function generate_keypair(): [number, number, number] {
    throw new Error("Function not implemented.");
}

export function create_channel(): number {
    throw new Error("Function not implemented.");
}
export function channelwrapper_new(): number {
    throw new Error("Function not implemented.");
}
export function channelwrapper_update_state(channel: number, stateUpdate: number): [number, number] {
    throw new Error("Function not implemented.");
}
export function channelwrapper_hash(channel: number): Uint8Array {
    throw new Error("Function not implemented.");
}
export function channelwrapper_state_count(channel: number): number {
    throw new Error("Function not implemented.");
}
export function channelwrapper_verify(channel: number): number { {
    throw new Error("Function not implemented.");
}
}
export function verify_state_update(stateUpdate: number): number {
    throw new Error("Function not implemented.");
}
export function stateupdatewrapper_new(dagCells: Uint8Array, references: Uint8Array, roots: Uint8Array, hash: Uint8Array, nonce: bigint): [number, number, number] {
    throw new Error('Function not implemented.');
}
export function stateupdatewrapper_dag_cells(stateUpdate: number): Uint8Array {
    throw new Error("Function not implemented.");
}   
export function stateupdatewrapper_references(stateUpdate: number): Uint8Array {
    throw new Error("Function not implemented.");
}
export function stateupdatewrapper_roots(stateUpdate: number): Uint8Array {
    throw new Error("Function not implemented.");
}
export function stateupdatewrapper_hash(stateUpdate: number): Uint8Array {
    throw new Error("Function not implemented.");
}
    export function clientstorage_new(): [number, number, number] {
    throw new Error("Function not implemented.");
}
        export function clientstorage_saveState(clientStorage: number, channelId: number, state: Uint8Array): [number, number] {
    throw new Error ("Function not implemented.");
}
            export function clientstorage_loadState(clientStorage: number, channelId: number): Uint8Array {
    throw new Error ("Function not implemented.");
}
                export function clientstorage_listChannels(clientStorage: number): Uint8Array {
    throw new Error ("Function not implemented.");
}   
export function stateupdatewrapper_nonce(stateUpdate: number): bigint {
    throw new Error("Function not implemented.");
}
export function stateupdatewrapper_state_mapping(stateUpdate: number): Uint8Array {
    throw new Error("Function not implemented.");
}
export function stateupdatewrapper_verify(stateUpdate: number): number {
    throw new Error("Function not implemented.");
}   

export function init() {
    throw new Error('Function not implemented.');
}

