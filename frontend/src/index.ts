// ./src/index.ts
// # Entry point for the client application
import ReactDOM from 'react-dom/client';
import { WasmWrapper } from './wasm/wasm-wrapper';
import ClientApp from './ui/components/ClientApp'; // Import ClientApp component
import React from 'react';

const main = async () => {
  await WasmWrapper.init(); // Initialize WASM
  const rootElement = document.getElementById('root');
  if (rootElement) {
    const root = ReactDOM.createRoot(rootElement);
    root.render(React.createElement(ClientApp));
  }
};

main().catch(console.error);