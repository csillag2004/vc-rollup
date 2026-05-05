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
} from '@docknetwork/crypto-wasm-ts';

const MESSAGE_COUNT = 5;
const K_HANDLE = 4;

export class Holder {
    private provingKey!: MembershipProvingKey;
    private nonce = this.stringToBytes('nonce1');

    //az issuer által aláírt credential + witness tárolása a holderben
    credentialMap: Map<string, {cred: any, signature: any, y: any, witness: any}> = new Map(); //credId -> {credential, signature, y, witness}
    private credential: any;
    private signature: any;
    private y: any;
    private witness: any;

    private stringToBytes(message: string): Uint8Array {
        return Uint8Array.from(Buffer.from(message, 'utf-8'));
    }

    private bytesToHex(bytes: Uint8Array): string {
        return '0x' + Buffer.from(bytes).toString('hex');
    }

    compositeProofForCredential(sig1: BBSPlusSignatureG1, cred1Messages: Uint8Array[], issuerPk: BBSPlusKeypairG2['publicKey'], sigParams: BBSPlusSignatureParamsG1, witness: Witness, w: Uint8Array<ArrayBufferLike>, params: any, publickey: AccumulatorPublicKey, accumulator: { accumulated: any }) {
        const REVEAL = new Set<number>([2, 3]); // reveal degree + graduationYear
        const revealedMsgs = new Map<number, Uint8Array>();
        const unrevealedMsgs = new Map<number, Uint8Array>();
        cred1Messages.forEach((m, i) =>
            REVEAL.has(i) ? revealedMsgs.set(i, m) : unrevealedMsgs.set(i, m),
        );

        this.provingKey = Accumulator.generateMembershipProvingKey(this.stringToBytes('Our proving key'));

        const proverStmts = new Statements();
        const sBBS = proverStmts.add(
            Statement.bbsPlusSignatureProverConstantTime(sigParams, revealedMsgs, false),
        );
        const sAcc = proverStmts.add(
            Statement.vbAccumulatorMembership(
                params, publickey, this.provingKey, accumulator.accumulated,
            ),
        );

        const eq = new WitnessEqualityMetaStatement();
        eq.addWitnessRef(sBBS, K_HANDLE);
        eq.addWitnessRef(sAcc, 0);
        const metaStatements = new MetaStatements();
        metaStatements.add(MetaStatement.witnessEquality(eq));

        const witnesses = new Witnesses();
        witnesses.add(Witness.bbsPlusSignatureConstantTime(sig1, unrevealedMsgs, false));
        witnesses.add(w);

        const proofSpec = new ProofSpec(proverStmts, metaStatements);
        //const nonce = this.stringToBytes('nonce1');
        const proof = CompositeProof.generate(proofSpec, witnesses, this.nonce);
        console.log("Generated proof for cred1.");

        return proof;
    }

    getProvingKey() {
        return this.provingKey;
    }

    getNonce() {
        return this.nonce;
    }

    setCredential(cred: any, signature: any, y: any, witness: any) {
        this.credential = cred;
        this.signature = signature;
        this.y = y;
        this.witness = witness;
    }

}