import 'dotenv/config';
import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { InMemoryState } from '../ts-scripts/in-memory-persistence';
import {Verifier} from './verifier';
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
  AccumulatorPublicKey,
  MembershipProvingKey,
  BBSPlusPublicKeyG2,
  VBMembershipWitness,
  AccumulatorParams,
} from '@docknetwork/crypto-wasm-ts';
import { VBWitnessUpdateInfo, WitnessUpdateInfo } from '@docknetwork/crypto-wasm-ts/lib/accumulator/witness-update-info';

//const MESSAGE_COUNT = 5;
//const K_HANDLE = 4;

//type CredentialRecord
type Credential = { //cso ,m
    credId: string
    schemaId: string,
    credDefId: string;
    registryId: string;
    signature: BBSPlusSignatureG1;
    messages: Uint8Array[];
}

type CredentialHelper = {
    k_handle: number;
    message_count: number;
    epoch: number;
    lastSyncedBlock: number;
}

type MyWitness = {
    publicWitness: VBMembershipWitness;
    privateWitness: Uint8Array<ArrayBufferLike>;
}

type CredentialRecord = {
    credential: Credential,
    y: number,
    witness: MyWitness,
    helper: CredentialHelper

}

export class Holder {
    private readonly ACCUMULATOR_ADDR = process.env.ACCUMULATOR_ADDR!;
    private readonly PRIVATE_KEY = process.env.PRIVATE_KEY_HOLDER!;
    private readonly SCHEMA_REGISTRY = process.env.SCHEMA_REGISTRY_ADDR!;
    private readonly REVOCATION_REGISTRY = process.env.REVOCATION_REGISTRY_ADDR!;
    private readonly RPC_URL = 'https://sepolia-rpc.scroll.io';

    private schemaRegistryContract!: ethers.Contract;
    private revocationRegistryContract!: ethers.Contract;
    private accumulatorContract!: ethers.Contract;

    private provingKey!: MembershipProvingKey;
    private nonce = this.stringToBytes('nonce1');

    //az issuer által aláírt credential + witness tárolása a holderben
    credentialMap: Map<string, CredentialRecord> = new Map(); //credId -> Credential
    //private credential: any;
    //private signature: any;
    //private y: any;
    //private witness: any;

    constructor() {
        const artifactPath = path.resolve(
            __dirname, '..','out',  'RevocationRegistry.sol', 'RevocationRegistry.json'
        );
        const artifact_revocation = JSON.parse(fs.readFileSync(artifactPath, 'utf-8'));

        const artifactPath2 = path.resolve(
            __dirname, '..', 'out', 'SchemaRegistry.sol', 'SchemaRegistry.json'
        );
        const artifact_schema = JSON.parse(fs.readFileSync(artifactPath2, 'utf-8'));

        const artifactPath4 = path.resolve(
            __dirname, '..', 'out', 'Accumulator.sol', 'Accumulator.json'
        );
        const artifact_accumulator = JSON.parse(fs.readFileSync(artifactPath4, 'utf-8'));

        const provider = new ethers.JsonRpcProvider(this.RPC_URL);
        const wallet = new ethers.Wallet(this.PRIVATE_KEY, provider);
        this.schemaRegistryContract = new ethers.Contract(this.SCHEMA_REGISTRY, artifact_schema.abi, wallet);
        this.revocationRegistryContract = new ethers.Contract(this.REVOCATION_REGISTRY, artifact_revocation.abi, wallet);
        this.accumulatorContract = new ethers.Contract(this.ACCUMULATOR_ADDR, artifact_accumulator.abi, wallet);  //le kell nullázni az akkumlátort!!!

    }

    private stringToBytes(message: string): Uint8Array {
        return Uint8Array.from(Buffer.from(message, 'utf-8'));
    }

    private bytesToHex(bytes: Uint8Array): string {
        return '0x' + Buffer.from(bytes).toString('hex');
    }

    /*updateWitness(credId: string): Witness | null {
        const credential = this.credentialMap.get(credId);
    }*/

    getCredential(credId: string): CredentialRecord | null {
        return this.credentialMap.get(credId) || null;
    }

    async compositeProofForCredential(credId: string, reveals: number[], verifier: Verifier): Promise<CompositeProof | null> {
        const credential = this.credentialMap.get(credId);
        if (!credential) {
            console.error(`Credential with ID ${credId} not found.`);
            return null;
        }

        //const REVEAL = new Set<number>([2, 3]); // reveal degree + graduationYear
        const REVEAL = new Set<number>(reveals);
        const revealedMsgs = new Map<number, Uint8Array>();
        const unrevealedMsgs = new Map<number, Uint8Array>();
        credential.credential.messages.forEach((m, i) =>
            REVEAL.has(i) ? revealedMsgs.set(i, m) : unrevealedMsgs.set(i, m),
        );

        this.provingKey = Accumulator.generateMembershipProvingKey(this.stringToBytes('Our proving key'));

        const proverStmts = new Statements();
        const sBBS = proverStmts.add(
            Statement.bbsPlusSignatureProverConstantTime((await this.getIssuerParams(credential.credential.schemaId))!, revealedMsgs, false),
        );
        const sAcc = proverStmts.add(
            Statement.vbAccumulatorMembership(
                (await this.getParams())!, (await this.getPublicKey())!, this.provingKey, (await this.getOnChainAccumulator())!.accumulated
            ),
        );

        const eq = new WitnessEqualityMetaStatement();
        eq.addWitnessRef(sBBS, credential.helper.k_handle);
        eq.addWitnessRef(sAcc, 0);
        const metaStatements = new MetaStatements();
        metaStatements.add(MetaStatement.witnessEquality(eq));

        const witnesses = new Witnesses();
        witnesses.add(Witness.bbsPlusSignatureConstantTime(credential.credential.signature, unrevealedMsgs, false));
        witnesses.add(Witness.vbAccumulatorMembership(credential.credential.messages[credential.helper.k_handle]! ,credential.witness.publicWitness));

        const proofSpec = new ProofSpec(proverStmts, metaStatements);
        //const nonce = this.stringToBytes('nonce1');
        const proof = CompositeProof.generate(proofSpec, witnesses, this.nonce);
        console.log("Generated proof for cred1.");
        await verifier.setProofInfo(credId, proof, revealedMsgs, credential.credential.schemaId, credential.credential.credDefId, credential.credential.registryId, this.nonce, this.provingKey);
        return proof;
    }

    async getOnChainAccumulator(){
        const onChainAccumulator: string = await this.accumulatorContract.getAccumulator!();
            if (!onChainAccumulator || onChainAccumulator === '0x' || onChainAccumulator.length <= 2) {
            return null;
        }
        return PositiveAccumulator.fromAccumulated(Uint8Array.from(Buffer.from(onChainAccumulator.slice(2), 'hex')));
    }

    async getParams(): Promise<AccumulatorParams | null> {
        const onChainParams: string = await this.accumulatorContract.getParams!();
        if (!onChainParams || onChainParams === '0x' || onChainParams.length <= 2) {
            return null;
        }
        const bytes = Uint8Array.from(Buffer.from(onChainParams.slice(2), 'hex'));
        return new AccumulatorParams(bytes);
    }

    async getPublicKey(): Promise<AccumulatorPublicKey | null> {
        const onChainPublicKey: string = await this.accumulatorContract.getPublicKey!();
        if (!onChainPublicKey || onChainPublicKey === '0x' || onChainPublicKey.length <= 2) {
            return null;
        }
        const bytes = Uint8Array.from(Buffer.from(onChainPublicKey.slice(2), 'hex'));
        return new AccumulatorPublicKey(bytes);
    }

    async getIssuerParams(schemaId: string): Promise<BBSPlusSignatureParamsG1 | null> {
        const sigParams = BBSPlusSignatureParamsG1.generate(
            (await this.getSchemaAttributes(schemaId)).length + 1, // +1 for the trailing revocationId (K_HANDLE)
            this.stringToBytes(schemaId), //az aláírás paramétere a schemaID
        );
        return sigParams;
    }

    async getSchemaAttributes(schemaId: string): Promise<string[]> {
        const schema = await this.schemaRegistryContract.getSchema!(schemaId);
        return schema.attributeNames;
    }

    async verifyWitness(credId: string, credential?: CredentialRecord): Promise<boolean> {
        if (!credential){
            credential = this.credentialMap.get(credId);
        }
        if (!credential) {
            console.error(`Credential with ID ${credId} not found.`);
            return false;
        }
        const y = credential.y;
        const witness = credential.witness.publicWitness;
        const accumulator = await this.getOnChainAccumulator();
        const publicKey = await this.getPublicKey();
        const params = await this.getParams();
        if (!accumulator || !publicKey || !params) {
            console.error('Failed to retrieve accumulator, public key, or parameters from the contract.');
            return false;
        }
        return accumulator.verifyMembershipWitness(Accumulator.encodePositiveNumberAsAccumulatorMember(y), witness, publicKey, params);
    }

    getWitness(credId: string): VBMembershipWitness | null {
        const credential = this.credentialMap.get(credId);
        if (!credential) {
            console.error(`Credential with ID ${credId} not found.`);
            return null;
        }
        return credential.witness.publicWitness;
    }

    async getEpoch(credId: string) {
        const epoch = await this.revocationRegistryContract.getRegistry!(this.credentialMap.get(credId)!.credential.registryId);
        return epoch;
    }

    async updateWitness(credId: string){
        try{
            const credential = this.credentialMap.get(credId);
            const epoch = await this.getEpoch(credId);
            if (!credential) {
                console.error(`Credential with ID ${credId} not found.`);
                return;
            }
            if(credential.helper.epoch === undefined || credential.helper.epoch >= epoch){
                console.log(`Credential with ID ${credId} is already up to date.`);
                return;
            }
            const fromBlock = credential.helper.lastSyncedBlock + 1;
            const filter = this.accumulatorContract.filters.AccumulatorUpdated!();
            const events = await this.accumulatorContract.queryFilter(filter, fromBlock, 'latest');
            if (events.length === 0) {
                return;
            }
            let witness1 = credential.witness.publicWitness;
            const y = credential.y;
            const m = Accumulator.encodePositiveNumberAsAccumulatorMember(y);
            for (const event of events) {
                if (!('args' in event)) {
                    continue;
                }
                const {
                    value,
                    additions,
                    removals,
                    witnessUpdateInfo,
                    epoch
                } = event.args;
                console.log("accumulator:", value);
                const accBytes = ethers.getBytes(value);
                const updateInfo = new VBWitnessUpdateInfo(ethers.getBytes(witnessUpdateInfo));
                const addedMembers = (additions as bigint[]).map(y =>
                    Accumulator.encodePositiveNumberAsAccumulatorMember(Number(y))
                );
                const removedMembers = (removals as bigint[]).map(y =>
                    Accumulator.encodePositiveNumberAsAccumulatorMember(Number(y))
                );
                witness1.updateUsingPublicInfoPostBatchUpdate(m, addedMembers, removedMembers, updateInfo)
                /*for (const yAdded of addedScalars as bigint[]) {
                    const addedM = Accumulator.encodePositiveNumberAsAccumulatorMember(Number(yAdded));
                    witness.updatePostAdd(addedM, m, accBytes);
                }
                for (const yRemoved of revokedScalars as bigint[]) {
                    const removedM = Accumulator.encodePositiveNumberAsAccumulatorMember(Number(yRemoved));
                    witness.updatePostRemove(removedM, m, accBytes);
                }*/
                credential.helper.epoch=Number(epoch);
                credential.helper.lastSyncedBlock = event.blockNumber;
            }
            credential.witness.publicWitness = witness1;
            credential.witness.privateWitness = Witness.vbAccumulatorMembership(m, witness1);
        }
        catch(CannotBeZero)
        {
            throw new Error("credential is revoked, cannot update witness");
        }
    }


    /*getProvingKey() {
        return this.provingKey;
    }

    getNonce() {
        return this.nonce;
    }*/

    async setCredential(credId: string, 
        schemaId: string,
        credDefId: string,
        registryId: string,
        y: number,
        signature: BBSPlusSignatureG1,
        messages: Uint8Array[],
        k_handle: number,
        message_count: number,
        witness: VBMembershipWitness,
        w: Uint8Array<ArrayBufferLike>,
        lastSyncedBlock: number) {

        const credential: Credential = {
            credId,
            schemaId,
            credDefId,
            registryId,
            signature,
            messages,
        };

        const helper: CredentialHelper = {
            k_handle: k_handle,
            message_count: message_count,
            epoch: 0,
            lastSyncedBlock: lastSyncedBlock
        };

        const mywitness: MyWitness = {
            publicWitness: witness,
            privateWitness: w
        };
        //if(!(await this.verifyWitness(credId, credential))) return;
    
        const credRekord: CredentialRecord = {
            credential: credential,
            y: y,
            witness: mywitness,
            helper: helper
        }

        this.credentialMap.set(credId, credRekord);
        
    }

    

}