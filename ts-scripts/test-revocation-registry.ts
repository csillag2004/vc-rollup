import 'dotenv/config';
import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { InMemoryState } from '../ts-scripts/in-memory-persistence';
import {
  initializeWasm,
  PositiveAccumulator,
  Accumulator,
  //  InMemoryState
  
} from '@docknetwork/crypto-wasm-ts';

function bytesToHex(bytes: Uint8Array): string {
    return '0x' + Buffer.from(bytes).toString('hex');
}

let myMap = new Map<string, number>(); //it a number lesz a random y, most még nem random, csak tesztelés miatt 1-et adok neki
myMap.set('cred1', 1001);
myMap.set('cred2', 2002);
myMap.set('cred3', 3003);

async function main() {
    const RPC_URL = 'https://sepolia-rpc.scroll.io';
    const CHAIN_ID = 534351;
    const REGISTRY = process.env.REGISTRY_ADDRESS!;
    const PRIVATE_KEY = process.env.PRIVATE_KEY!;
    const CREDDEF_REGISTRY = process.env.CREDDEF_REGISTRY_ADDR!;
    const REVOCATION_REGISTRY = process.env.REVOCATION_REGISTRY_ADDR!;
    const SCHEMA_REGISTRY = process.env.SCHEMA_REGISTRY_ADDR!;


    //solidity json fájl beolvasása
    const artifactPath = path.resolve(
        __dirname, '..','out',  'RevocationRegistry.sol', 'RevocationRegistry.json'
    );
    const artifact_revocation = JSON.parse(fs.readFileSync(artifactPath, 'utf-8'));

    const artifactPath2 = path.resolve(
        __dirname, '..', 'out', 'SchemaRegistry.sol', 'SchemaRegistry.json'
    );
    const artifact_schema = JSON.parse(fs.readFileSync(artifactPath2, 'utf-8'));

    const artifactPath3 = path.resolve(
        __dirname, '..', 'out', 'CredDefRegistry.sol', 'CredDefRegistry.json'
    );
    const artifact_creddef = JSON.parse(fs.readFileSync(artifactPath3, 'utf-8'));

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
    const schemaRegistryContract = new ethers.Contract(SCHEMA_REGISTRY, artifact_schema.abi, wallet);
    const credDefRegistryContract = new ethers.Contract(CREDDEF_REGISTRY, artifact_creddef.abi, wallet);
    const revocationRegistryContract = new ethers.Contract(REVOCATION_REGISTRY, artifact_revocation.abi, wallet);

    //1. create accumulator

    function stringToBytes(message: string): Uint8Array {
        return Uint8Array.from(Buffer.from(message, 'utf-8'));
    }

    await initializeWasm();
    const params = PositiveAccumulator.generateParams(stringToBytes('vc-rollup-thesis-accumulator-params-v1'));
    const keypair = PositiveAccumulator.generateKeypair(params);
    const state = new InMemoryState();
    const accumulator = PositiveAccumulator.initialize(params);

    console.log("Initial accumulator:", bytesToHex(accumulator.accumulated));

    //2. schemaIdk létrehozása
    const attributes = ['studentName', 'university', 'degree', 'graduationYear'];
    const random = Math.floor(Math.random() * 100000);
    const version = "1.0-" + random; //minden futtatásnál új verzió, hogy ne ütközzön a már regisztrált sémákkal
    const schemaTx = await schemaRegistryContract.registerSchema!("UniversityDegree", version, attributes);
    const schemaReceipt = await schemaTx.wait();
    // Az event-ből nyerjük ki a schemaId-t
    const schemaEvent = schemaRegistryContract.interface.parseLog(schemaReceipt?.logs[0]!);
    const schemaId = schemaEvent?.args[0]; // schemaId az első argument

    //3. credDef létrehozása
    const credDefTx = await credDefRegistryContract.registerCredDef!(schemaId, "default", PRIVATE_KEY);
    const credDefReceipt = await credDefTx.wait();
    const credDefEvent = credDefRegistryContract.interface.parseLog(credDefReceipt?.logs[0]!);
    const credDefId = credDefEvent?.args[0]; // credDefId az első argument

    //4. revocation registry létrehozása
    const revTx = await revocationRegistryContract.createRegistry!(credDefId, bytesToHex(accumulator.accumulated));
    const revReceipt = await revTx.wait();

    const revEvent = revocationRegistryContract.interface.parseLog(revReceipt?.logs[0]!);
    const registryId = revEvent?.args[0]; // registryId az első argument
    const acc = revEvent?.args[3]; // newAccumulator az 4. argument
    console.log("Created registry with accumulator: ", acc);


    //5. add credentials
    const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(myMap.get('cred1')!);
    const m2 = Accumulator.encodePositiveNumberAsAccumulatorMember(myMap.get('cred2')!);
    const m3 = Accumulator.encodePositiveNumberAsAccumulatorMember(myMap.get('cred3')!);

    //m1
    await accumulator.addBatch([m1], keypair.secretKey, state);
    console.log("Accumulator after adding cred1: ", bytesToHex(accumulator.accumulated));

    const revup1Tx=await revocationRegistryContract.updateRegistry!(registryId, bytesToHex(accumulator.accumulated), [myMap.get('cred1')!], []);
    const revup1Receipt = await revup1Tx.wait();
    const revup1Event = revocationRegistryContract.interface.parseLog(revup1Receipt?.logs[0]!);
    const new1Acc = revup1Event?.args[2];
    console.log("Updated registry with new accumulator: ", new1Acc);

    //m2
    await accumulator.addBatch([m2], keypair.secretKey, state);
    console.log("Accumulator after adding cred2: ", bytesToHex(accumulator.accumulated));

    const revup2Tx=await revocationRegistryContract.updateRegistry!(registryId, bytesToHex(accumulator.accumulated), [myMap.get('cred1')!], []);
    const revup2Receipt = await revup2Tx.wait();
    const revup2Event = revocationRegistryContract.interface.parseLog(revup2Receipt?.logs[0]!);
    const new2Acc = revup2Event?.args[2];
    console.log("Updated registry with new accumulator: ", new2Acc);

    //m3
    await accumulator.addBatch([m3], keypair.secretKey, state);
    console.log("Accumulator after adding cred3: ", bytesToHex(accumulator.accumulated));

    const revup3Tx=await revocationRegistryContract.updateRegistry!(registryId, bytesToHex(accumulator.accumulated), [myMap.get('cred1')!], []);
    const revup3Receipt = await revup3Tx.wait();
    const revup3Event = revocationRegistryContract.interface.parseLog(revup3Receipt?.logs[0]!);
    const new3Acc = revup3Event?.args[2];
    console.log("Updated registry with new accumulator: ", new3Acc);

    //6. revoke credential (cred2)
    await accumulator.removeBatch([m2], keypair.secretKey, state);
    console.log("Accumulator after revoking cred2: ", bytesToHex(accumulator.accumulated));

    const revRevokeTx=await revocationRegistryContract.updateRegistry!(registryId, bytesToHex(accumulator.accumulated), [], [myMap.get('cred2')!]);
    const revRevokeReceipt = await revRevokeTx.wait();
    const revRevokeEvent = revocationRegistryContract.interface.parseLog(revRevokeReceipt?.logs[0]!);
    const revokedAcc = revRevokeEvent?.args[2];
    console.log("Updated registry with new accumulator after revocation cred2: ", revokedAcc);


    //7. witness
    try {
        const witness1 = await accumulator.membershipWitness(m1, keypair.secretKey, state);
        console.log("Membership witness for cred1: ", witness1);
    } catch (e) {
        console.log("cred1 is revoked, cannot generate witness");
    }
    
    try {        
        const witness2 = await accumulator.membershipWitness(m2, keypair.secretKey, state);
        console.log("Membership witness for cred2: ", witness2);
    } catch (e) {
        console.log("cred2 is revoked, cannot generate witness");
    }

    
    try {
        const witness3 = await accumulator.membershipWitness(m3, keypair.secretKey, state);
        console.log("Membership witness for cred3: ", witness3);
    } catch (e) {
        console.log("cred3 is revoked, cannot generate witness");

    }
}


main().catch(console.error);

