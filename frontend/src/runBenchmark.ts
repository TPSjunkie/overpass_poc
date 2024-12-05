import { Buffer } from 'buffer';
import { ChannelManager } from './hooks/useChannel'; // Path to your ChannelManager

interface CustomPerformanceEntry extends PerformanceEntry {
  operation: string;
  duration: number;
  memoryUsage: number;
  networkLatency: number;
  transactionHash: string;
  blockConfirmations: number;
  stateSize: number;
  proofSize: number;
}

async function runBenchmark() {
  const channelManager = new ChannelManager();

  console.log('Initializing the channel...');
  await channelManager.initialize({
    network: 'regtest',
    initial_balance: 1000,
    security_bits: 256,
  });

  console.log('Channel initialized.');

  const batchSizes = [10, 50, 100, 500, 1000]; // Simulating different loads
  const metrics: CustomPerformanceEntry[] = [];

  for (const batchSize of batchSizes) {
    console.log(`Processing batch size: ${batchSize}`);
    const startTime = performance.now();
    for (let i = 0; i < batchSize; i++) {
      const data = new Uint8Array(Buffer.from(`Transaction ${i}`));
      try {
        await channelManager.processTransaction(BigInt(i), data);
      } catch (error) {
        console.error(`Error processing transaction ${i}:`, error);
      }
    }
    const endTime = performance.now();

    metrics.push({
        name: `Batch ${batchSize}`,
        entryType: 'measure',
        startTime,
        duration: endTime - startTime,
        operation: `Batch ${batchSize}`,
        memoryUsage: (performance as any).memory?.usedJSHeapSize || 0,
        networkLatency: 0, // Placeholder: Adjust if network latency is simulated
        transactionHash: '',
        blockConfirmations: 0,
        stateSize: 0,
        proofSize: 0,
        toJSON: function () {
            throw new Error('Function not implemented.');
        }
    });

    console.log(`Batch size ${batchSize} completed in ${(endTime - startTime).toFixed(2)} ms`);
  }

  // Log Results
  console.log('Benchmark completed. Results:');
  console.table(
    metrics.map((metric) => ({
      Batch: metric.operation,
      DurationMs: metric.duration.toFixed(2),
      MemoryMB: (metric.memoryUsage / (1024 * 1024)).toFixed(2),
    })),
  );

  return metrics;
}

// Execute Benchmark
runBenchmark()
  .then((results) => console.log('Results saved:', results))
  .catch((error) => console.error('Benchmark failed:', error));