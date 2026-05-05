import 'dotenv/config';
import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { InMemoryState } from '../ts-scripts/in-memory-persistence';
import {
  initializeWasm,
  PositiveAccumulator,
  Accumulator,
  AccumulatorParams,
  AccumulatorKeypair,
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
  MembershipProvingKey,
  IntegerType,
} from '@docknetwork/crypto-wasm-ts';


export class Verifier {

    async buildCompositeProof(sigParams: BBSPlusSignatureParamsG1, issuerPk: BBSPlusKeypairG2['publicKey'], revealedMsgs: Map<number, Uint8Array<ArrayBufferLike>>, keypair: AccumulatorKeypair["publicKey"], provingKey: MembershipProvingKey, accumulator: PositiveAccumulator, proof: CompositeProof, nonce: Uint8Array, params: AccumulatorParams, k_handle: number) {

        //10. Verifier rebuilds statements + metastatements (no witnesses, no signature)
        const verStmts = new Statements();
        verStmts.add(
            Statement.bbsPlusSignatureVerifierConstantTime(sigParams, issuerPk, revealedMsgs, false),
        );
        verStmts.add(
            Statement.vbAccumulatorMembership(
                params, keypair, provingKey, accumulator.accumulated,
            ),
        );
        const eqV = new WitnessEqualityMetaStatement();
        eqV.addWitnessRef(0, k_handle);
        eqV.addWitnessRef(1, 0);
        const metaStmtsV = new MetaStatements();
        metaStmtsV.add(MetaStatement.witnessEquality(eqV));
        const verifierSpec = new ProofSpec(verStmts, metaStmtsV);

        const isValid = proof.verify(verifierSpec, nonce);
        console.log("Proof verification result for cred1: ", isValid);
    }
}

