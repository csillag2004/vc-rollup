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
  CompositeProof,
  Witness,
  Witnesses,
  ProofSpec, 
  MetaStatements,
  Statement,
  Statements,
  WitnessEqualityMetaStatement,
  MetaStatement,
  BBSPlusKeypairG2,
  BBSPlusSignatureParamsG1,
  BBSPlusSignatureG1,
} from '@docknetwork/crypto-wasm-ts';


const RPC_URL = 'https://sepolia-rpc.scroll.io';
const CHAIN_ID = 534351;
const REGISTRY = process.env.REGISTRY_ADDRESS!;
const PRIVATE_KEY = process.env.PRIVATE_KEY!;
const CREDDEF_REGISTRY = process.env.CREDDEF_REGISTRY_ADDR!;
const REVOCATION_REGISTRY = process.env.REVOCATION_REGISTRY_ADDR!;
const SCHEMA_REGISTRY = process.env.SCHEMA_REGISTRY_ADDR!;

let myMap = new Map<string, number>(); //it a number lesz a random y, most még nem random, csak tesztelés miatt 1-et adok neki

let schemaRegistryContract: ethers.Contract;
let credDefRegistryContract: ethers.Contract;
let revocationRegistryContract: ethers.Contract;

export class Issuer {
    //private registryId?: string;

    constructor() {
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
        schemaRegistryContract = new ethers.Contract(SCHEMA_REGISTRY, artifact_schema.abi, wallet);
        credDefRegistryContract = new ethers.Contract(CREDDEF_REGISTRY, artifact_creddef.abi, wallet);
        revocationRegistryContract = new ethers.Contract(REVOCATION_REGISTRY, artifact_revocation.abi, wallet);

        myMap.set('cred1', 1001);
        myMap.set('cred2', 2002);
        myMap.set('cred3', 3003);

    }

    private stringToBytes(message: string): Uint8Array {
        return Uint8Array.from(Buffer.from(message, 'utf-8'));
    }

    private bytesToHex(bytes: Uint8Array): string {
        return '0x' + Buffer.from(bytes).toString('hex');
    }

    async createAccumulator() {
        await initializeWasm();
        const params = PositiveAccumulator.generateParams(this.stringToBytes('vc-rollup-thesis-accumulator-params-v1'));
        const keypair = PositiveAccumulator.generateKeypair(params);
        const state = new InMemoryState();
        const accumulator = PositiveAccumulator.initialize(params);
        console.log("Initial accumulator:", this.bytesToHex(accumulator.accumulated));
        return accumulator;
    }

    async schemaId() {
        const attributes = ['studentName', 'university', 'degree', 'graduationYear', 'revocationId'];
        const random = Math.floor(Math.random() * 100000);
        const version = "1.0-" + random; //minden futtatásnál új verzió, hogy ne ütközzön a már regisztrált sémákkal
        const schemaTx = await schemaRegistryContract.registerSchema!("UniversityDegree", version, attributes);
        const schemaReceipt = await schemaTx.wait();
        // Az event-ből nyerjük ki a schemaId-t
        const schemaEvent = schemaRegistryContract.interface.parseLog(schemaReceipt?.logs[0]!);
        const schemaId = schemaEvent?.args[0]; // schemaId az első argument
        return schemaId;
    }

    async credDefId(schemaId: string) {
        const credDefTx = await credDefRegistryContract.registerCredDef!(schemaId, "default", PRIVATE_KEY);
        const credDefReceipt = await credDefTx.wait();
        const credDefEvent = credDefRegistryContract.interface.parseLog(credDefReceipt?.logs[0]!);
        const credDefId = credDefEvent?.args[0]; // credDefId az első argument
        return credDefId;
    }

    async revocationRegistry(accumulator: PositiveAccumulator, credDefId: string) {
        const revTx = await revocationRegistryContract.createRegistry!(credDefId, this.bytesToHex(accumulator.accumulated));
        const revReceipt = await revTx.wait();

        const revEvent = revocationRegistryContract.interface.parseLog(revReceipt?.logs[0]!);
        const registryId = revEvent?.args[0]; // registryId az első argument
        const acc = revEvent?.args[3]; // newAccumulator az 4. argument
        console.log("Created registry with accumulator: ", acc);
        return registryId;
    }

    async addCredentials(credId: string, accumulator: PositiveAccumulator, keypair: ReturnType<typeof PositiveAccumulator.generateKeypair>, state: InMemoryState, cred: string, registryId: string) {
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(myMap.get(cred)!);
        await accumulator.addBatch([m1], keypair.secretKey, state);
        console.log("Accumulator after adding " + cred + ": ", this.bytesToHex(accumulator.accumulated));

        const revup1Tx = await revocationRegistryContract.updateRegistry!(registryId, this.bytesToHex(accumulator.accumulated), [myMap.get(cred)!], []);
        const revup1Receipt = await revup1Tx.wait();
        const revup1Event = revocationRegistryContract.interface.parseLog(revup1Receipt?.logs[0]!);
        const new1Acc = revup1Event?.args[2];
        console.log("Updated registry with new accumulator: ", new1Acc);
        return new1Acc;
    }

    async revokeCredentials(credId: string, accumulator: PositiveAccumulator, keypair: ReturnType<typeof PositiveAccumulator.generateKeypair>, state: InMemoryState, registryId: string) {
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(myMap.get(credId)!);

        await accumulator.removeBatch([m1], keypair.secretKey, state);
        console.log("Accumulator after revoking " + credId + ": ", this.bytesToHex(accumulator.accumulated));

        const revRevokeTx = await revocationRegistryContract.updateRegistry!(registryId, this.bytesToHex(accumulator.accumulated), [], [myMap.get(credId)!]);
        const revRevokeReceipt = await revRevokeTx.wait();
        const revRevokeEvent = revocationRegistryContract.interface.parseLog(revRevokeReceipt?.logs[0]!);
        const revokedAcc = revRevokeEvent?.args[2];
        console.log("Updated registry with new accumulator after revocation " + credId + ": ", revokedAcc);
        return revokedAcc;
    }

    async createWitness(credId: string, accumulator: PositiveAccumulator, keypair: ReturnType<typeof PositiveAccumulator.generateKeypair>, state: InMemoryState, cred: string) {
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(myMap.get(cred)!);
        try {
            const witness = await accumulator.membershipWitness(m1, keypair.secretKey, state);
            const w1 = Witness.vbAccumulatorMembership(m1, witness);
            console.log("Membership witness for " + cred + ": ", witness);
            return { witness, w1 };
        } catch (e) {
            console.log(cred + " is revoked, cannot generate witness");
            return null;
        }
    }

    signCredential(credId: string, keypair: BBSPlusKeypairG2, signatureParams: BBSPlusSignatureParamsG1, messages: Uint8Array[], witness: Witness | null, w: Witness | null, message_count: number) {
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(myMap.get(credId)!);
        
        const sigParams = BBSPlusSignatureParamsG1.generate(
            message_count,
            this.stringToBytes('issuer-sig-params-v1'),
        );
        const issuerKp = BBSPlusKeypairG2.generate(sigParams);
        const issuerSk = issuerKp.secretKey;
        const issuerPk = issuerKp.publicKey;

        const encB = (s: string) => Accumulator.encodeBytesAsAccumulatorMember(this.stringToBytes(s));
        const cred1Messages: Uint8Array[] = [
            encB('Alice'),       // 0: studentName
            encB('Budapest U'),  // 1: university
            encB('BSc'),         // 2: degree
            encB('2026'),        // 3: graduationYear
            m1,                  // 4: revocationId  ← K_HANDLE (same bytes as acc member)
        ];
        const sig1 = BBSPlusSignatureG1.generate(cred1Messages, issuerSk, sigParams, false);

        if (!w || !witness) {
            throw new Error('cred1 membership witness is not available — cannot build proof');
        }

        return { sig1, cred1Messages, issuerPk, sigParams };
    }
}
