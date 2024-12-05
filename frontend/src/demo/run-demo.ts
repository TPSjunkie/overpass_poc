import { demonstrateWallet } from './wallet-demo';
import { demonstratePaymentChannel } from './payment-channel-demo';
import { demonstrateHTLC } from './htlc-demo';
import * as process from '../wasm/index';



async function runFullDemo() {
    console.log("🚀 Starting Overpass Demo");
    
    try {
        // Initialize wallets and channel
        const { channel } = await demonstrateWallet();
        
        // Demonstrate payment channel operations
        await demonstratePaymentChannel(channel);
        
        // Demonstrate HTLC
        await demonstrateHTLC(channel);
        
        console.log("\n✨ Demo completed successfully!");
    } catch (error) {
        console.error("\n❌ Demo failed:", error);
        process.exit(1);
    }
}

runFullDemo();