import 'dotenv/config';
import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
//import { InMemoryState } from '../ts-scripts/in-memory-persistence';
import { InMemoryState } from './in-memory-persistence';

import {Holder} from './holder';
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
  BBSPlusPublicKeyG2,
  BBSPlusSignatureParamsG1,
  BBSPlusSignatureG1,
  AccumulatorParams,
  AccumulatorPublicKey,
  VBMembershipWitness,
  AccumulatorSecretKey,
  VBWitnessUpdateInfo
} from '@docknetwork/crypto-wasm-ts';
import { on } from 'events';
import { findPackageJSON } from 'module';
import { stat } from 'fs/promises';
import { WitnessUpdateInfo } from '@docknetwork/crypto-wasm-ts/lib/accumulator/witness-update-info';




type SignCredentialResult = {
    sig1: BBSPlusSignatureG1;
    cred1Messages: Uint8Array[];
    k_handler: number;
    message_count: number;  
};

export class Issuer {
    private readonly ADDRESS: string;//=process.env.ADDRESS_ISSUER!;
    private readonly RPC_URL = 'https://sepolia-rpc.scroll.io';
    private readonly CHAIN_ID = 534351;
    private readonly REGISTRY = process.env.REGISTRY_ADDRESS!;
    private readonly PRIVATE_KEY = process.env.PRIVATE_KEY_ISSUER!;
    private readonly CREDDEF_REGISTRY = process.env.CREDDEF_REGISTRY_ADDR!;
    private readonly REVOCATION_REGISTRY = process.env.REVOCATION_REGISTRY_ADDR!;
    private readonly SCHEMA_REGISTRY = process.env.SCHEMA_REGISTRY_ADDR!;
    private readonly ACCUMULATOR_ADDR = process.env.ACCUMULATOR_ADDR!;

    //private myMap = new Map<string, number>(); //it a number lesz a random y, most még nem random, csak tesztelés miatt 1-et adok neki

    private schemaRegistryContract!: ethers.Contract;
    private credDefRegistryContract!: ethers.Contract;
    private revocationRegistryContract!: ethers.Contract;
    private accumulatorContract!: ethers.Contract;
    private didContract!: ethers.Contract;

    // FIXME accumulatort nem kéne tárolni az issuerben!!! - solkidityn fel
    //private accumulator!: PositiveAccumulator;
    //private keypair!: ReturnType<typeof PositiveAccumulator.generateKeypair>;
    private state!: InMemoryState;
    //private params!: AccumulatorParams;
    private accu_private_key!: AccumulatorSecretKey;
    private issuer_kp!: BBSPlusKeypairG2;
    private signParams!: BBSPlusSignatureParamsG1;


    // FIXME ezekből elég 1???? fa-map json
    //private schemaid?: string;
    //private creddefId?: string;
    //private registryId?: string;

    // schemaId → (credDefId → (registryId → (credId → number)))
    private schemaTree: Map<string, Map<string, Map<string, Map<string, number>>>> = new Map();
    // credId -> current witness (recreate whenever the accumulator changes)
    private witnesses: Map<string, { witness: VBMembershipWitness; w1: Uint8Array<ArrayBufferLike> }> = new Map();
    // credId -> sign result (set once at signCredential time, permanent)
    private signResults: Map<string, SignCredentialResult> = new Map();
    private credentialHolders: Map<string, Holder> = new Map();
    private starterBlock: Map<string, number> = new Map(); 


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

        const artifactPath4 = path.resolve(
            __dirname, '..', 'out', 'Accumulator.sol', 'Accumulator.json'
        );
        const artifact_accumulator = JSON.parse(fs.readFileSync(artifactPath4, 'utf-8'));

        const didRegistryAbi = [
            "function setAttribute(address identity, bytes32 name, bytes value, uint256 validity)"
        ];

        const provider = new ethers.JsonRpcProvider(this.RPC_URL);
        const wallet = new ethers.Wallet(this.PRIVATE_KEY, provider);
        this.ADDRESS = wallet.address;
        this.schemaRegistryContract = new ethers.Contract(this.SCHEMA_REGISTRY, artifact_schema.abi, wallet);
        this.credDefRegistryContract = new ethers.Contract(this.CREDDEF_REGISTRY, artifact_creddef.abi, wallet);
        this.revocationRegistryContract = new ethers.Contract(this.REVOCATION_REGISTRY, artifact_revocation.abi, wallet);
        this.accumulatorContract = new ethers.Contract(this.ACCUMULATOR_ADDR, artifact_accumulator.abi, wallet);  //le kell nullázni az akkumlátort!!!
        this.didContract = new ethers.Contract(this.REGISTRY, didRegistryAbi, wallet);
        

        //this.myMap.set('cred1', 1001);
        //this.myMap.set('cred2', 2002);
        //this.myMap.set('cred3', 3003);

        this.state=new InMemoryState();

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
        const accumulator = PositiveAccumulator.initialize(params);

        this.accu_private_key = keypair.secretKey;

        const witnessUpdateInfo = VBWitnessUpdateInfo.new(accumulator.accumulated, [], [], this.accu_private_key)

        const accTx = await this.accumulatorContract.setAccumulator!(this.bytesToHex(accumulator.accumulated), [], [], this.bytesToHex(witnessUpdateInfo.value));
        await accTx.wait();
        const accTx2 = await this.accumulatorContract.setParams!(this.bytesToHex(params.bytes));
        await accTx2.wait();
        const accTx3 = await this.accumulatorContract.setPublicKey!(this.bytesToHex(keypair.publicKey.bytes));
        await accTx3.wait();
    }

    async getOnChainAccumulator(){
        const onChainAccumulator: string = await this.accumulatorContract.getAccumulator!();
            if (!onChainAccumulator || onChainAccumulator === '0x' || onChainAccumulator.length <= 2) {
            return null;
        }
        return PositiveAccumulator.fromAccumulated(Uint8Array.from(Buffer.from(onChainAccumulator.slice(2), 'hex')));
    }

    async getPublicKey(): Promise<AccumulatorPublicKey | null> {
        const onChainPublicKey: string = await this.accumulatorContract.getPublicKey!();
        if (!onChainPublicKey || onChainPublicKey === '0x' || onChainPublicKey.length <= 2) {
            return null;
        }
        const bytes = Uint8Array.from(Buffer.from(onChainPublicKey.slice(2), 'hex'));
        return new AccumulatorPublicKey(bytes);
    }

    async getParams(): Promise<AccumulatorParams | null> {
        const onChainParams: string = await this.accumulatorContract.getParams!();
        if (!onChainParams || onChainParams === '0x' || onChainParams.length <= 2) {
            return null;
        }
        const bytes = Uint8Array.from(Buffer.from(onChainParams.slice(2), 'hex'));
        return new AccumulatorParams(bytes);
    }

    async getAccumulatorAddress(): Promise<string> {
        return await this.accumulatorContract.getAddress();
    }

    async schemaId(name: string, version: string, attributes: string[]) {
        //const attributes = ['studentName', 'university', 'degree', 'graduationYear', 'revocationId'];
        //const random = Math.floor(Math.random() * 100000);
        //const version = "1.0-" + random; //minden futtatásnál új verzió, hogy ne ütközzön a már regisztrált sémákkal
        const schemaTx = await this.schemaRegistryContract.registerSchema!(name, version, attributes);
        const schemaReceipt = await schemaTx.wait();
        // Az event-ből nyerjük ki a schemaId-t
        const schemaEvent = this.schemaRegistryContract.interface.parseLog(schemaReceipt?.logs[0]!);
        const schemaid = schemaEvent?.args[0]; // schemaId az első argument
        this.addSchemaToTree(schemaid!);
        //return this.schemaId;
    }

    private addSchemaToTree(schemaId: string): void {
        if (!this.schemaTree.has(schemaId)) {
            this.schemaTree.set(schemaId, new Map());
        }
    }

    private addCredDefToTree(schemaId: string, credDefId: string): void {
        this.addSchemaToTree(schemaId);
        const credDefs = this.schemaTree.get(schemaId)!;
        if (!credDefs.has(credDefId)) {
            credDefs.set(credDefId, new Map());
        }
    }

    private addRegistryToTree(schemaId: string, credDefId: string, registryId: string): void {
        this.addCredDefToTree(schemaId, credDefId);
        const registries = this.schemaTree.get(schemaId)!.get(credDefId)!;
        if (!registries.has(registryId)) {
            registries.set(registryId, new Map());
        }
    }

    getSchemaIds(): string[] {
        return Array.from(this.schemaTree.keys());
    }

    getCredDefIdsForSchema(schemaId: string): string[] {
        return Array.from(this.schemaTree.get(schemaId)?.keys() ?? []);
    }

    getRegistryIdsForCredDef(schemaId: string, credDefId: string): string[] {
        return Array.from(this.schemaTree.get(schemaId)?.get(credDefId)?.keys() ?? []);
    }

    hasSchema(schemaId: string): boolean {
        return this.schemaTree.has(schemaId);
    }

    hasCredDef(schemaId: string, credDefId: string): boolean {
        return this.schemaTree.get(schemaId)?.has(credDefId) ?? false;
    }

    hasRegistry(schemaId: string, credDefId: string, registryId: string): boolean {
        return this.schemaTree.get(schemaId)?.get(credDefId)?.has(registryId) ?? false;
    }

    private addCredToTree(schemaId: string, credDefId: string, registryId: string, credId: string, y: number): void {
        this.addRegistryToTree(schemaId, credDefId, registryId);
        this.schemaTree.get(schemaId)!.get(credDefId)!.get(registryId)!.set(credId, y);
    }

    getCredIdsForRegistry(schemaId: string, credDefId: string, registryId: string): string[] {
        return Array.from(this.schemaTree.get(schemaId)?.get(credDefId)?.get(registryId)?.keys() ?? []);
    }

    hasCred(schemaId: string, credDefId: string, registryId: string, credId: string): boolean {
        return this.schemaTree.get(schemaId)?.get(credDefId)?.get(registryId)?.has(credId) ?? false;
    }

    getYForCred(schemaId: string, credDefId: string, registryId: string, credId: string): number | undefined {
        return this.schemaTree.get(schemaId)?.get(credDefId)?.get(registryId)?.get(credId);
    }

    findSchemaIdByCredDef(credDefId: string): string | null {
        for (const [schemaId, credDefs] of this.schemaTree.entries()) {
            if (credDefs.has(credDefId)) {
                return schemaId;
            }
        }
        return null;
    }

    findCredDefIdByRegistry(registryId: string): string | null {
        for (const credDefs of this.schemaTree.values()) {
            for (const [credDefId, registries] of credDefs.entries()) {
                if (registries.has(registryId)) {
                    return credDefId;
                }
            }
        }
        return null;
    }

    async findYByCredId(credId: string) {
        for (const credDefs of this.schemaTree.values()) {
            for (const registries of credDefs.values()) {
                for (const creds of registries.values()) {
                    if (creds.has(credId)) {
                        return creds.get(credId)!;
                    }
                }
            }
        }
        return null;
    }

    async findRegistryIdByCredId(credId: string): Promise<string | null> {
        for (const credDefs of this.schemaTree.values()) {
            for (const registries of credDefs.values()) {
                for (const [registryId, creds] of registries.entries()) {
                    if (creds.has(credId)) {
                        return registryId;
                    }
                }
            }
        }
        return null;
    }

    async credDefId(schemaId: string) {
        //BBSPlus
        const sigParams = BBSPlusSignatureParamsG1.generate(
            (await this.getSchemaAttributes(schemaId)).length + 1, // +1 for the trailing revocationId (K_HANDLE)
            this.stringToBytes(schemaId), //az aláírás paramétere a schemaID
        );
        this.signParams = sigParams;
        const issuerKp = BBSPlusKeypairG2.generate(sigParams);
        this.issuer_kp=issuerKp;
        const issuerSk = issuerKp.secretKey;
        const issuerPk = issuerKp.publicKey;

        //update DID
        const attrName = ethers.encodeBytes32String("did/pub/Bls12381G2/veriKey/hex");
        const validity = 5 * 60 * 60 * 24 * 365; // 5 év, másodpercben
        const tx = await this.didContract.setAttribute!(
            this.ADDRESS,            // identity = a saját DID-je (did:ethr:...:issuerAddress)
            attrName,
            this.bytesToHex(issuerPk.bytes),  // value = nyers pubkey bytes
            validity
        );
        await tx.wait();

        //CredDef
        const keyId = ethers.keccak256(this.bytesToHex(issuerPk.bytes));
        const credDefTx = await this.credDefRegistryContract.registerCredDef!(schemaId, "default", keyId);
        const credDefReceipt = await credDefTx.wait();
        const credDefEvent = this.credDefRegistryContract.interface.parseLog(credDefReceipt?.logs[0]!);
        const creddefId = credDefEvent?.args[0]; // credDefId az első argument
        this.addCredDefToTree(schemaId, creddefId!);
        //return this.creddefId;
    }

    async getSchemaAttributes(schemaId: string): Promise<string[]> {
        const schema = await this.schemaRegistryContract.getSchema!(schemaId);
        return schema.attributeNames;
    }

    async revocationRegistry(credDefId: string) {
        const revTx = await this.revocationRegistryContract.createRegistry!(credDefId, await this.getAccumulatorAddress());
        const revReceipt = await revTx.wait();

        const revEvent = this.revocationRegistryContract.interface.parseLog(revReceipt?.logs[0]!);
        const registryId = revEvent?.args[0]; // registryId az első argument
        const acc = revEvent?.args[3]; // newAccumulator az 4. argument
        //console.log("Created registry with accumulator: ", acc);
        this.addRegistryToTree(this.findSchemaIdByCredDef(credDefId)!, credDefId, registryId!);
        //return this.registryId;
    }

    async addCredentials(credId: string, registryId: string, holder: Holder) {
        // reuse existing y if this credId was already issued, otherwise generate a new one
        const y = (await this.findYByCredId(credId)) ?? (Math.floor(Math.random() * (Number.MAX_SAFE_INTEGER - 1)) + 1);
        const credDefId = this.findCredDefIdByRegistry(registryId)!;
        const schemaId = this.findSchemaIdByCredDef(credDefId)!;
        this.addCredToTree(schemaId, credDefId, registryId, credId, y);
        this.credentialHolders.set(credId, holder); //EZ ÍGY JÓ???

        const m = Accumulator.encodePositiveNumberAsAccumulatorMember(y);
        const accumulator = await this.getOnChainAccumulator();
        if (!accumulator) throw new Error("Accumulator not initialized on-chain");
        const witnessUpdateInfo = VBWitnessUpdateInfo.new(accumulator.accumulated, [m], [], this.accu_private_key)
        await accumulator.addBatch([m], this.accu_private_key, this.state); //off-chain update
        //console.log("y:" + y);

        // updateRegistry first — its event reads the on-chain accumulator, which is still the
        // pre-add value. That's what `updatePostAdd` expects as accumulatorValueBeforeAddition.
        const revup1Tx = await this.revocationRegistryContract.updateRegistry!(registryId, [y], []);
        const revup1Receipt = await revup1Tx.wait();
        this.starterBlock.set(credId, revup1Receipt.blockNumber);

        // Now push the post-add bytes on-chain
        const accTx = await this.accumulatorContract.setAccumulator!(this.bytesToHex(accumulator.accumulated), [y], [], this.bytesToHex(witnessUpdateInfo.value));
        await accTx.wait();
    }

    //Claude
    async stateHas(credId: string): Promise<boolean> {
        const y = await this.findYByCredId(credId);
        const m = Accumulator.encodePositiveNumberAsAccumulatorMember(y!);
        return this.state.has(m);
    }

    async revokeCredentials(credId: string, registryId: string) {
        const y = await this.findYByCredId(credId);
        if (y === null) {
            throw new Error(`Credential does not exist, cannot revoke`);
        }
        if (!(await this.stateHas(credId))) {
            throw new Error(`Credential is not in the state, cannot revoke`);
        }
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(y);

        const accumulator = await this.getOnChainAccumulator();
        const witnessUpdateInfo = VBWitnessUpdateInfo.new(accumulator!.accumulated, [], [m1], this.accu_private_key)
        await accumulator!.removeBatch([m1], this.accu_private_key, this.state);
        //console.log("Accumulator after revoking " + credId + ": ", this.bytesToHex(this.accumulator.accumulated));

        const accTx = await this.accumulatorContract.setAccumulator!(this.bytesToHex(accumulator!.accumulated), [], [y], this.bytesToHex(witnessUpdateInfo.value));
        await accTx.wait(); //on-chain update

        const revRevokeTx = await this.revocationRegistryContract.updateRegistry!(registryId, [], [y]);
        await revRevokeTx.wait();
    }

    async createWitness(credId: string) {
        const y = await this.findYByCredId(credId);
        if (y === null) {
            throw new Error(`Credential does not exist, cannot create witness`);
        }
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(y!);
        try {
            const accumulator = await this.getOnChainAccumulator();
            const witness = await accumulator!.membershipWitness(m1, this.accu_private_key, this.state); //holder oldalon legyen egy accumulator proving key
            const private_witness = Witness.vbAccumulatorMembership(m1, witness); 
            console.log("Membership witness for " + credId + ": ", witness);
            this.witnesses.set(credId, { witness, w1: private_witness });
            return { witness, w1: private_witness };
        } catch (e) {
            throw new Error("credential is revoked, cannot generate witness");
            return null;
        }
    }

    getWitness(credId: string): { witness: VBMembershipWitness; w1: Uint8Array<ArrayBufferLike> } | null {
        return this.witnesses.get(credId) ?? null;
    }

    getSignResult(credId: string): SignCredentialResult | null {
        return this.signResults.get(credId) ?? null;
    }

    async verifyWitness(credId: string, witness: VBMembershipWitness): Promise<boolean> {
        const y = await this.findYByCredId(credId);
        if (y === null) {
            throw new Error(`Credential does not exist, cannot verify witness`);
        }
        const accumulator = await this.getOnChainAccumulator();
        if (!accumulator) {
            throw new Error("Accumulator not initialized on-chain");
        }
        const pk = await this.getPublicKey();
        const params = await this.getParams();
        if (!pk || !params) {
            throw new Error("Accumulator publicKey/params not initialized on-chain");
        }
        const storedWitness = this.getWitness(credId);
        if (!storedWitness) {
            throw new Error(`No witness stored for ${credId}`);
        }
        return accumulator.verifyMembershipWitness(
            Accumulator.encodePositiveNumberAsAccumulatorMember(y),
            storedWitness.witness, //ide ez kell vagy a sima w?
            pk,
            params
        );
    }


    async signCredential(credId: string,  messages: string[], witness1: {witness: VBMembershipWitness; w1: Uint8Array<ArrayBufferLike>;} | null,  message_count: number) {
        const y = await this.findYByCredId(credId);
        const registryId = await this.findRegistryIdByCredId(credId);
        const credDefId = this.findCredDefIdByRegistry(registryId!);
        const schemaId = this.findSchemaIdByCredDef(credDefId!);
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(y!);
        
        /*const sigParams = BBSPlusSignatureParamsG1.generate(
            message_count,
            this.stringToBytes('issuer-sig-params-v1'),
        );
        const issuerKp = BBSPlusKeypairG2.generate(sigParams);
        const issuerSk = issuerKp.secretKey;
        const issuerPk = issuerKp.publicKey;*/
        const sigParams = this.signParams;
        const issuerPk = this.issuer_kp.publicKey;

        const encB = (s: string) => Accumulator.encodeBytesAsAccumulatorMember(this.stringToBytes(s));
        // encode every caller-supplied message, then append the revocationId as the final element (the K_HANDLE)
        const cred1Messages: Uint8Array[] = [
            ...messages.map(m => encB(m)),
            m1,
        ];
        const sig1 = BBSPlusSignatureG1.generate(cred1Messages, this.issuer_kp.secretKey, sigParams!, false);

        if (!witness1) {
            throw new Error('cred1 membership witness is not available');
        }

        const k_handler = cred1Messages.length - 1; //revocationId index, ami a K_HANDLE lesz a proofban
        this.signResults.set(credId, { sig1, cred1Messages, k_handler, message_count });

        this.credentialHolders.get(credId)?.setCredential(credId, schemaId!, credDefId!, registryId!, y!, sig1, cred1Messages, k_handler, message_count, witness1.witness, witness1.w1, this.starterBlock.get(credId)!);
        console.log("\nw1: ", witness1.w1, "\n");
        //return { sig1, cred1Messages, issuerPk, sigParams, k_handler, message_count};
    }

    async verifySignature(credId: string, messages: string[]): Promise<boolean> { //ez csak teszteléshez létezik?
        const signResult = this.getSignResult(credId);
        if (!signResult) {
            throw new Error(`No signature result found for ${credId}`);
        }

        const signature = signResult.sig1;

        const y = await this.findYByCredId(credId);
        const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(y!);
        const encB = (s: string) => Accumulator.encodeBytesAsAccumulatorMember(this.stringToBytes(s));
        const credMessages: Uint8Array[] = [
            ...messages.map(m => encB(m)),
            m1,
        ];

        try{
            const isValid = signature.verify(credMessages, this.issuer_kp.publicKey, this.signParams, false).verified;
            return isValid;
        }
        catch(e){
            return false;
        }
    }

    /*getPublicKey() {
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

    //Claude
    async stateHas(credId: string): Promise<boolean> {
        const m = Accumulator.encodePositiveNumberAsAccumulatorMember(this.myMap.get(credId)!);
        return this.state.has(m);
    }

    async stateHas_y(y: number): Promise<boolean> {
        const m = Accumulator.encodePositiveNumberAsAccumulatorMember(y);
        return this.state.has(m);
    }*/
}
