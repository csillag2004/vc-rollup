import { ethers } from "ethers";
import { EthrDID } from "ethr-did";
import { Resolver } from "did-resolver";
import { getResolver } from "ethr-did-resolver";
import * as dotenv from "dotenv";

dotenv.config();

const RPC_URL = "https://sepolia-rpc.scroll.io";
const CHAIN_ID = 534351;
const CHAIN_ID_HEX = "0x" + CHAIN_ID.toString(16);  // "0x8274f"
const REGISTRY = process.env.REGISTRY_ADDRESS!;
const PRIVATE_KEY = process.env.PRIVATE_KEY!;

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const issuerWallet = new ethers.Wallet(PRIVATE_KEY, provider);

  console.log("Issuer address:", issuerWallet.address);
  console.log("Chain ID hex:", CHAIN_ID_HEX);

  // --- 1. Resolver setup ---
  const ethrResolver = getResolver({
    networks: [
      {
        name: CHAIN_ID_HEX,
        provider,
        registry: REGISTRY,
        chainId: CHAIN_ID,
      },
    ],
  });
  const resolver = new Resolver(ethrResolver);

  // --- 2. DID creation ---
  const issuerDid = new EthrDID({
    identifier: issuerWallet.address,
    provider,
    chainNameOrId: CHAIN_ID,
    registry: REGISTRY,
    txSigner: issuerWallet,
  });

  const did = issuerDid.did;
  console.log("\nCreated DID:", did);

  // --- 3. First resolution ---
  console.log("\n--- First resolution ---");
  const doc1 = await resolver.resolve(did);
  console.log(JSON.stringify(doc1.didDocument, null, 2));

  // --- 4. Key rotation (setAttribute) ---
  console.log("\n--- Adding delegate key ---");
  const newWallet = ethers.Wallet.createRandom();
  console.log("New delegate address:", newWallet.address);

  const tx = await issuerDid.setAttribute(
    "did/pub/Secp256k1/veriMethod/hex",
    newWallet.address,
    86400
  );
  console.log("TX hash:", tx);

  // Wait for confirmation
  const txHash = typeof tx === "string" ? tx : (tx as any).hash;
  await provider.waitForTransaction(txHash);
  console.log("TX confirmed!");

  // --- 5. Second resolution ---
  console.log("\n--- Second resolution (after key rotation) ---");
  const doc2 = await resolver.resolve(did);
  console.log(JSON.stringify(doc2.didDocument, null, 2));

  // --- 6. Verify change ---
  const vms1 = doc1.didDocument?.verificationMethod?.length ?? 0;
  const vms2 = doc2.didDocument?.verificationMethod?.length ?? 0;
  console.log(`\nVerification methods: ${vms1} -> ${vms2}`);

  if (vms2 > vms1) {
    console.log("SUCCESS: Key rotation confirmed!");
  } else {
    console.log("WARNING: Key rotation not reflected yet.");
  }
}

main().catch(console.error);