// ./src/utils/hash-utils.ts
// # Utility functions for hashing
import { Poseidon } from '@iden3/js-crypto'; // Using @iden3/js-crypto for Poseidon hash

export class HashUtils {
  static computePoseidonHash(inputs: Uint8Array[]): Uint8Array {
    // Convert Uint8Array inputs to bigint[]
    const bigintInputs = inputs.map(input => BigInt('0x' + Buffer.from(input).toString('hex')));
    // Compute the Poseidon hash
    const hashResult = Poseidon.hash(bigintInputs);
    // Convert bigint to Uint8Array
    return new Uint8Array(hashResult.toString(16).match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
  }}