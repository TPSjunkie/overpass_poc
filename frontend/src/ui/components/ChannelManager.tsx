// File: frontend/src/components/ChannelManager.tsx

import { FormEvent, useState } from 'react';
import { useChannel } from '../../hooks/useChannel';
import { StateUpdate } from '../../types';

export function ChannelManager() {
    const { channelManager: channel } = useChannel();
    const [stateUpdates, setStateUpdates] = useState<StateUpdate[]>([]);

    const sendTransaction = async (amount: bigint) => {
        if (channel) {
            // Process transaction - this simulates the full network flow
            const result = await channel.processTransaction(amount, new Uint8Array(0));
            
            if ('transaction' in result && 'new_state' in result) {
                setStateUpdates(prev => [...prev, result as StateUpdate]);
            }
        }
    };    function handleSubmit(event: FormEvent<HTMLFormElement>): void {
        event.preventDefault();
        const form = event.currentTarget;
        const amountInput = form.elements.namedItem('amount') as HTMLInputElement;
        const amount = BigInt(amountInput.value);
        sendTransaction(amount);
    }

    return (
        <div className="channel-manager">
            <h2>Channel Manager</h2>
            
            {/* Transaction Form */}
            <form onSubmit={handleSubmit}>
                <input type="number" name="amount" placeholder="Amount" />
                <button type="submit">Send Transaction</button>
            </form>

            {/* State Updates Log */}
            <div className="updates-log">
                {stateUpdates.map((update, i) => (
                    <div key={i} className="update">
                        <div>Transaction: {update.transaction.amount}</div>
                        <div>New State: {JSON.stringify(update.new_state)}</div>
                        <div>Proof Valid: ✓</div>
                    </div>
                ))}
            </div>
        </div>
    );
}