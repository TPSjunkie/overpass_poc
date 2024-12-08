import { init} from '../wasm/overpass_wasm';
import { HTLCWrapper } from '../wrappers/htlc';

async function demoHTLC() {
    await init();

    // Hash lock (32 bytes) and preimage
    const preimage = new Uint8Array([1, 2, 3, ...Array(29).fill(0)]);
    const hashLock = new Uint8Array(await crypto.subtle.digest('SHA-256', preimage));

    // Create HTLC contract
    const htlc = new HTLCWrapper(
        hashLock,
        Math.floor(Date.now() / 1000) + 3600, // Time lock: 1 hour from now
        1000, // Amount
        new Uint8Array([0x01, 0x02]), // Sender
        new Uint8Array([0x03, 0x04])  // Recipient
    );

    console.log('HTLC created:', htlc);

    // Claim the HTLC
    try {
        htlc.claim(preimage);
        console.log('HTLC claimed. New state:', htlc.getState());
    } catch (err) {
        console.error('Failed to claim HTLC:', err);
    }

    // Try to refund before time lock expires
    try {
        htlc.refund(Math.floor(Date.now() / 1000));
    } catch (err) {
        console.error('Failed to refund HTLC:', err);
    }
}

demoHTLC();