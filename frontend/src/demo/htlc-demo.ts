import { OverpassChannel, HTLC } from "@/OverpassChannel";

// Instead of importing from 'crypto', use the browser's crypto API
const getRandomBytes = (length: number): Uint8Array => {
    return crypto.getRandomValues(new Uint8Array(length));
};

const createHash = async (message: Uint8Array): Promise<string> => {
    const hashBuffer = await crypto.subtle.digest('SHA-256', message);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

export async function demonstrateHTLC(channel: OverpassChannel): Promise<void> {
    try {
        console.log("\n🔒 Demonstrating Hash Time-Locked Contract (HTLC)");

        // Generate a random preimage and compute its hash
        const preimage = getRandomBytes(32); // Generates a 32-byte preimage
        const hash = await createHash(preimage);

        console.log("\nSetting up HTLC...");
        console.log("Hash:", hash);

        // Create HTLC with specified amount and timeout
        const htlcAmount = BigInt(25000); // Amount in satoshis or your channel's unit
        const timeoutBlocks = 144; // 24 hours in Bitcoin blocks
        const receiver = "receiverAddress"; // Add a receiver address

        const htlc: HTLC = await channel.createHTLC(htlcAmount.toString(), hash, timeoutBlocks, Number(receiver));        console.log("\nHTLC created:", htlc);

        // Demonstrate HTLC resolution
        console.log("\nResolving HTLC with preimage...");
        const resolution = await channel.resolveHTLC(htlc.id, preimage, receiver, Number(htlc.hashLock));
        console.log("HTLC resolution:", resolution);
    } catch (error) {
        console.error("\n❌ Error during HTLC demonstration:", error);
    }
}