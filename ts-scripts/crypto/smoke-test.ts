import { initializeWasm } from '@docknetwork/crypto-wasm-ts';

async function main() {
  console.log('Loading WASM module...');
  await initializeWasm();
  console.log('WASM loaded successfully.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});