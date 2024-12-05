// ./wrappers/htlc.ts

import { ChannelConfig } from "../types";

interface HTLCState {
    hashLock: Uint8Array;
    timeLock: number;
    amount: number;
    sender: Uint8Array;
    recipient: Uint8Array;
    claimed: boolean;
    refunded: boolean;
}

export class HTLCWrapper {
    private contract: any;
    private htlcState: HTLCState;

    constructor(hashLock: Uint8Array, timeLock: number, amount: number, sender: Uint8Array, recipient: Uint8Array) {
        this.htlcState = {
            hashLock,
            timeLock,
            amount,
            sender,
            recipient,
            claimed: false,
            refunded: false
        };
    }

    claim(preimage: Uint8Array): void {
        // Verify the hash of the preimage matches the hashLock
        const verifyHash = async () => {
            const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', preimage));
            return hash.every((value, index) => value === this.htlcState.hashLock[index]);
        };

        if (!verifyHash()) {
            throw new Error("Invalid preimage");
        }

        if (this.htlcState.claimed || this.htlcState.refunded) {
            throw new Error("HTLC already claimed or refunded");
        }

        this.htlcState.claimed = true;
    }

    refund(currentTime: number): void {
        if (currentTime <= this.htlcState.timeLock) {
            throw new Error("Time lock not expired");
        }

        if (this.htlcState.claimed || this.htlcState.refunded) {
            throw new Error("HTLC already claimed or refunded");
        }

        this.htlcState.refunded = true;
    }

    getState(): HTLCState {
        return { ...this.htlcState };
    }

    async initChannel(config: ChannelConfig): Promise<void> {
        await this.contract?.init_channel(config);
    }
}