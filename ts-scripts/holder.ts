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

const MESSAGE_COUNT = 5;
const K_HANDLE = 4;

function stringToBytes(message: string): Uint8Array {
        return Uint8Array.from(Buffer.from(message, 'utf-8'));
}

function bytesToHex(bytes: Uint8Array): string {
    return '0x' + Buffer.from(bytes).toString('hex');
}



function compositeProofForCredential(sig1: BBSPlusSignatureG1, cred1Messages: Uint8Array[], issuerPk: BBSPlusKeypairG2['publicKey'], sigParams: BBSPlusSignatureParamsG1, witness: Witness, w: Uint8Array<ArrayBufferLike>, params: any, keypair: { publicKey: any }, accumulator: { accumulated: any }) {
    const REVEAL = new Set<number>([2, 3]); // reveal degree + graduationYear
    const revealedMsgs = new Map<number, Uint8Array>();
    const unrevealedMsgs = new Map<number, Uint8Array>();
    cred1Messages.forEach((m, i) =>
        REVEAL.has(i) ? revealedMsgs.set(i, m) : unrevealedMsgs.set(i, m),
    );

    const provingKey = Accumulator.generateMembershipProvingKey(stringToBytes('Our proving key'));

    const proverStmts = new Statements();
    const sBBS = proverStmts.add(
        Statement.bbsPlusSignatureProverConstantTime(sigParams, revealedMsgs, false),
    );
    const sAcc = proverStmts.add(
        Statement.vbAccumulatorMembership(
            params, keypair.publicKey, provingKey, accumulator.accumulated,
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
    const nonce = stringToBytes('nonce1');
    const proof = CompositeProof.generate(proofSpec, witnesses, nonce);
    console.log("Generated proof for cred1.");

    return proof;
}