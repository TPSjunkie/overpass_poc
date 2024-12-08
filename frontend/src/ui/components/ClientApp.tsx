// ./src/ui/components/ClientApp.tsx
// # Main application component
// # React UI for the client application

import { useState } from 'react';
import { StateTransitionManager } from '../../state/state-transition-manager';

const ClientApp = () => {
  const [transitionData, setTransitionData] = useState('');
  const [proof, setProof] = useState<Uint8Array | null>(null);
  const [nextState, setNextState] = useState<Uint8Array | null>(null);

  const handleGenerateProof = async () => {
    const transitionManager = new StateTransitionManager(new Uint8Array(32)); // Placeholder initial state
    const { proof, nextState } = await transitionManager.generateTransition(
      new TextEncoder().encode(transitionData)
    );
    setProof(proof);
    setNextState(nextState);
  };

  return (
    <div>
      <h1>Overpass Client</h1>
      <input
        type="text"
        value={transitionData}
        onChange={(e) => setTransitionData(e.target.value)}
        placeholder="Enter transition data"
      />
      <button onClick={handleGenerateProof}>Generate Proof</button>
      {proof && nextState && (
        <div>
          <p>Proof: {Array.from(proof).join(', ')}</p>
          <p>Next State: {Array.from(nextState).join(', ')}</p>
        </div>
      )}
    </div>
  );
};

export default ClientApp;