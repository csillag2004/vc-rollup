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
  AccumulatorParams,
  VBMembershipWitness,
} from '@docknetwork/crypto-wasm-ts';




export class Issuer {
    private readonly RPC_URL = 'https://sepolia-rpc.scroll.io';
    private readonly CHAIN_ID = 534351;
    private readonly REGISTRY = process.env.REGISTRY_ADDRESS!;
    private readonly PRIVATE_KEY = process.env.PRIVATE_KEY!;
    private readonly CREDDEF_REGISTRY = process.env.CREDDEF_REGISTRY_ADDR!;
    private readonly REVOCATION_REGISTRY = process.env.REVOCATION_REGISTRY_ADDR!;
    private readonly SCHEMA_REGISTRY = process.env.SCHEMA_REGISTRY_ADDR!;

    private myMap = new Map<string, number>(); //it a number lesz a random y, most még nem random, csak tesztelés miatt 1-et adok neki

    private schemaRegistryContract!: ethers.Contract;
    private credDefRegistryContract!: ethers.Contract;
    private revocationRegistryContract!: ethers.Contract;

    // FIXME accumulatort nem kéne tárolni az issuerben!!! - solkidityn fel
    private accumulator!: PositiveAccumulator;
    private keypair!: ReturnType<typeof PositiveAccumulator.generateKeypair>;
    private state!: InMemoryState;
    private params!: AccumulatorParams;

    // FIXME ezekből elég 1???? fa-map json
    private schemaid?: string;
    private creddefId?: string;
    private registryId?: string;

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

        const provider = new ethers.JsonRpcProvider(this.RPC_URL);
        const wallet = new ethers.Wallet(this.PRIVATE_KEY, provider);
        this.schemaRegistryContract = new ethers.Contract(this.SCHEMA_REGISTRY, artifact_schema.abi, wallet);
        this.credDefRegistryContract = new ethers.Contract(this.CREDDEF_REGISTRY, artifact_creddef.abi, wallet);
        this.revocationRegistryContract = new ethers.Contract(this.REVOCATION_REGISTRY, artifact_revocation.abi, wallet);

        this.myMap.set('cred1', 1001);
        this.myMap.set('cred2', 2002);
        this.myMap.set('cred3', 3003);

    }

    private stringToBytes(message: string): Uint8Array {
        return Uint8Array.from(Buffer.from(message, 'utf-8'));
    }

    private bytesToHex(bytes: Uint8Array): string {
        return '0x' + Buffer.from(bytes).toString('hex');
    }

    async createAccumulator() {
        await initializeWasm();
        this.params = PositiveAccumulator.generateParams(this.stringToBytes('vc-rollup-thesis-accumulator-params-v1'));
        this.keypair = PositiveAccumulator.generateKeypair(this.params);
        this.state = new InMemoryState();
        this.accumulator = PositiveAccumulator.initialize(this.params);
        console.log("Initial accumulator:", this.bytesToHex(this.accumulator.accumulated));
        return this.accumulator;
    }

    async schemaId(name: string, version: string, attributes: string[]) {
        //const attributes = ['studentName', 'university', 'degree', 'graduationYear', 'revocationId'];
        //const random = Math.floor(Math.random() * 100000);
        //const version = "1.0-" + random; //minden futtatásnál új verzió, hogy ne ütközzön a már regisztrált sémákkal
        const schemaTx = await this.schemaRegistryContract.registerSchema!(name, version, attributes);
        const schemaReceipt = await schemaTx.wait();
        // Az event-ből nyerjük ki a schemaId-t
        const schemaEvent = this.schemaRegistryContract.interface.parseLog(schemaReceipt?.logs[0]!);
        this.schemaid = schemaEvent?.args[0]; // schemaId az első argument
        //return this.schemaId;
    }

    async credDefId(schemaId: string) {
        const credDefTx = await this.credDefRegistryContract.registerCredDef!(schemaId, "default", this.PRIVATE_KEY);
        const credDefReceipt = await credDefTx.wait();
        const credDefEvent = this.credDefRegistryContract.interface.parseLog(credDefReceipt?.logs[0]!);
        this.creddefId = credDefEvent?.args[0]; // credDefId az első argument
        return this.creddefId;
    }

    async revocationRegistry(accumulator: PositiveAccumulator, credDefId: string) {
        const revTx = await this.revocationRegistryContract.createRegistry!(credDefId, this.bytesToHex(accumulator.accumulated));
        const revReceipt = await revTx.wait();

        const revEvent = this.revocationRegistryContract.interface.parseLog(revReceipt?.logs[0]!);
        this.registryId = revEvent?.args[0]; // registryId az első argument
        const acc = revEvent?.args[3]; // newAccumulator az 4. argument
        console.log("Created registry with accumulator: ", acc);
        return this.registryId;
    }

    async addCredentials(credId: string, registryId: string) {
        const m = Accumulator.encodePositiveNumberAsAccumulatorMember(this.myMap.get(credId)!);
        await this.accumulator.addBatch([m], this.keypair.secretKey, this.state);
        console.log("Accumulator after adding " + credId + ": ", this.bytesToHex(this.accumulator.accumulated));

        const revup1Tx = await this.revocationRegistryContract.updateRegistry!(registryId, this.bytesToHex(this.accumulator.accumulated), [this.myMap.get(credId)!], []);
        const revup1Receipt = await revup1Tx.wait();
        const revup1Event = this.revocationRegistryContract.interface.parseLog(revup1Receipt?.logs[0]!);
        const new1Acc = revup1Event?.args[2];
        console.log("Updated registry with new accumulator: ", new1Acc);
        return this.accumulator; //!!!ide inkább az kéne, hogy meghívjon egy updateAccumulator függvényt
    }

    async revokeCredentials(credId: string, registryId: string) {
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(this.myMap.get(credId)!);

        await this.accumulator.removeBatch([m1], this.keypair.secretKey, this.state);
        console.log("Accumulator after revoking " + credId + ": ", this.bytesToHex(this.accumulator.accumulated));

        const revRevokeTx = await this.revocationRegistryContract.updateRegistry!(registryId, this.bytesToHex(this.accumulator.accumulated), [], [this.myMap.get(credId)!]);
        const revRevokeReceipt = await revRevokeTx.wait();
        const revRevokeEvent = this.revocationRegistryContract.interface.parseLog(revRevokeReceipt?.logs[0]!);
        const revokedAcc = revRevokeEvent?.args[2];
        console.log("Updated registry with new accumulator after revocation " + credId + ": ", revokedAcc);
        
        this.myMap.delete(credId);
        return this.accumulator;
    }

    async createWitness(credId: string) {
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(this.myMap.get(credId)!);
        try {
            const witness = await this.accumulator.membershipWitness(m1, this.keypair.secretKey, this.state);
            const w1 = Witness.vbAccumulatorMembership(m1, witness);
            console.log("Membership witness for " + credId + ": ", witness);
            return { witness, w1 };
        } catch (e) {
            console.log(credId + " is revoked, cannot generate witness");
            return null;
        }
    }

    signCredential(credId: string,  messages: string[], witness1: {witness: VBMembershipWitness; w1: Uint8Array<ArrayBufferLike>;} | null,  message_count: number) {
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(this.myMap.get(credId)!);
        
        const sigParams = BBSPlusSignatureParamsG1.generate(
            message_count,
            this.stringToBytes('issuer-sig-params-v1'),
        );
        const issuerKp = BBSPlusKeypairG2.generate(sigParams);
        const issuerSk = issuerKp.secretKey;
        const issuerPk = issuerKp.publicKey;

        const encB = (s: string) => Accumulator.encodeBytesAsAccumulatorMember(this.stringToBytes(s));
        const cred1Messages: Uint8Array[] = [
            encB(messages[0]!),       // 0: studentName
            encB(messages[1]!),  // 1: university
            encB(messages[2]!),         // 2: degree
            encB(messages[3]!),        // 3: graduationYear
            m1,                  // 4: revocationId  ← K_HANDLE (same bytes as acc member)
        ];
        const sig1 = BBSPlusSignatureG1.generate(cred1Messages, issuerSk, sigParams, false);

        if (!witness1) {
            throw new Error('cred1 membership witness is not available — cannot build proof');
        }

        const k_handler = cred1Messages.length - 1; //revocationId index, ami a K_HANDLE lesz a proofban

        return { sig1, cred1Messages, issuerPk, sigParams, k_handler, message_count};
    }

    getPublicKey() {
        return this.keypair.publicKey;
    }

    getParams() {
        return this.params;
    }

    getAccumulator() {
        return this.accumulator;
    }

    getSchemaId() {
        return this.schemaid;
    }

    getCredDefId() {
        return this.creddefId;
    }

    getRegistryId() {
        return this.registryId;
    }

    getCredentialById(credId: string) {
        if (this.myMap.has(credId)) {
            return this.myMap.get(credId);
        }
        throw new Error(`Credential with ID ${credId} not found`);
    }

    //Claude
    async stateHas(credId: string): Promise<boolean> {
        const m = Accumulator.encodePositiveNumberAsAccumulatorMember(this.myMap.get(credId)!);
        return this.state.has(m);
    }

    async stateHas_y(y: number): Promise<boolean> {
        const m = Accumulator.encodePositiveNumberAsAccumulatorMember(y);
        return this.state.has(m);
    }
}
