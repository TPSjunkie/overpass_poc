import { useChannel } from '../../hooks/useChannel';
import { useState } from 'react';

export function ChannelTest() {
  const { channelManager, initialize } = useChannel();
  const [status, setStatus] = useState('');

  const runTest = async () => {
    await initialize({ network: 'testnet', initial_balance: 1000, security_bits: 256 });
    
    // Test transaction
    const testData = new Uint8Array([1, 2, 3, 4]);
    if (channelManager) {
      await channelManager.processTransaction(BigInt(100), testData);
      setStatus(`Transaction processed successfully`);
    } else {
      setStatus('Channel manager is not initialized');
    }
  };
  return (
    <div>
      <button onClick={runTest}>Run Channel Test</button>
      <div>{status}</div>
    </div>
  );
}
