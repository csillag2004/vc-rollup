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
  AccumulatorPublicKey,
  MembershipProvingKey,
  BBSPlusPublicKeyG2,
  VBMembershipWitness,
  AccumulatorParams,
} from '@docknetwork/crypto-wasm-ts';

//const MESSAGE_COUNT = 5;
//const K_HANDLE = 4;

type Credential = {
    schemaId: string;
    credDefId: string;
    registryId: string;
    y: number;
    signature: BBSPlusSignatureG1;
    messages: Uint8Array[];
    issuerPk: BBSPlusPublicKeyG2;
    sigParams: BBSPlusSignatureParamsG1;
    k_handle: number;
    message_count: number;
    witness: VBMembershipWitness;
    w: Uint8Array<ArrayBufferLike>;
}

export class Holder {
    private readonly ACCUMULATOR_ADDR = process.env.ACCUMULATOR_ADDR!;
    private readonly PRIVATE_KEY = process.env.PRIVATE_KEY!;
     private readonly RPC_URL = 'https://sepolia-rpc.scroll.io';
    private accumulatorContract!: ethers.Contract;

    private provingKey!: MembershipProvingKey;
    private nonce = this.stringToBytes('nonce1');

    //az issuer által aláírt credential + witness tárolása a holderben
    credentialMap: Map<string, Credential> = new Map(); //credId -> Credential
    //private credential: any;
    //private signature: any;
    //private y: any;
    //private witness: any;

    constructor() {
        const artifactPath4 = path.resolve(
            __dirname, '..', 'out', 'Accumulator.sol', 'Accumulator.json'
        );
        const artifact_accumulator = JSON.parse(fs.readFileSync(artifactPath4, 'utf-8'));

        const provider = new ethers.JsonRpcProvider(this.RPC_URL);
        const wallet = new ethers.Wallet(this.PRIVATE_KEY, provider);
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

    getCredential(credId: string): Credential | null {
        return this.credentialMap.get(credId) || null;
    }

    async compositeProofForCredential(credId: string): Promise<CompositeProof | null> {
        const credential = this.credentialMap.get(credId);
        if (!credential) {
            console.error(`Credential with ID ${credId} not found.`);
            return null;
        }

        const REVEAL = new Set<number>([2, 3]); // reveal degree + graduationYear
        const revealedMsgs = new Map<number, Uint8Array>();
        const unrevealedMsgs = new Map<number, Uint8Array>();
        credential.messages.forEach((m, i) =>
            REVEAL.has(i) ? revealedMsgs.set(i, m) : unrevealedMsgs.set(i, m),
        );

        this.provingKey = Accumulator.generateMembershipProvingKey(this.stringToBytes('Our proving key'));

        const proverStmts = new Statements();
        const sBBS = proverStmts.add(
            Statement.bbsPlusSignatureProverConstantTime(credential.sigParams, revealedMsgs, false),
        );
        const sAcc = proverStmts.add(
            Statement.vbAccumulatorMembership(
                (await this.getParams())!, (await this.getPublicKey())!, this.provingKey, (await this.getOnChainAccumulator())!.accumulated
            ),
        );

        const eq = new WitnessEqualityMetaStatement();
        eq.addWitnessRef(sBBS, credential.k_handle);
        eq.addWitnessRef(sAcc, 0);
        const metaStatements = new MetaStatements();
        metaStatements.add(MetaStatement.witnessEquality(eq));

        const witnesses = new Witnesses();
        witnesses.add(Witness.bbsPlusSignatureConstantTime(credential.signature, unrevealedMsgs, false));
        witnesses.add(Witness.vbAccumulatorMembership(credential.messages[credential.k_handle]! ,credential.witness));

        const proofSpec = new ProofSpec(proverStmts, metaStatements);
        //const nonce = this.stringToBytes('nonce1');
        const proof = CompositeProof.generate(proofSpec, witnesses, this.nonce);
        console.log("Generated proof for cred1.");

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


    /*getProvingKey() {
        return this.provingKey;
    }

    getNonce() {
        return this.nonce;
    }*/

    setCredential(credId: string, 
        schemaId: string,
        credDefId: string,
        registryId: string,
        y: number,
        signature: BBSPlusSignatureG1,
        messages: Uint8Array[],
        issuerPk: BBSPlusPublicKeyG2,
        sigParams: BBSPlusSignatureParamsG1,
        k_handle: number,
        message_count: number,
        witness: VBMembershipWitness,
        w: Uint8Array<ArrayBufferLike>) {
        const credential: Credential = {
            schemaId,
            credDefId,
            registryId,
            y,
            signature,
            messages,
            issuerPk,
            sigParams,
            k_handle,
            message_count,
            witness,
            w
        };
        this.credentialMap.set(credId, credential);
    }

    

}