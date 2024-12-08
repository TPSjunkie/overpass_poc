// ./src/network/network-client.ts
// # Handles API communicationexport class NetworkClient {
export class NetworkClient {
    private baseUrl: string;
    
    constructor(baseUrl: string) {
        this.baseUrl = baseUrl;
    }
    
    async submitProof(channelId: string, proof: Uint8Array, nextState: Uint8Array): Promise<boolean> {
        const response = await fetch(`${this.baseUrl}/submit-proof`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            channelId,
            proof: Array.from(proof),
            nextState: Array.from(nextState),
        }),
        });
        const data = await response.json();
        return data.success;
    }
    
    async fetchState(channelId: string): Promise<Uint8Array> {
        const response = await fetch(`${this.baseUrl}/state/${channelId}`);
        const data = await response.json();
        return new Uint8Array(data.state);
    }
    }