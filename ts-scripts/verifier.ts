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
  BBSPlusPublicKeyG2,
} from '@docknetwork/crypto-wasm-ts';

type ProofInfo ={
    proof: CompositeProof;
    revealedMessages: Map<number, Uint8Array>;
    schemaId: string;
    credDefId: string;
    registryId: string;
    nonce: Uint8Array<ArrayBufferLike>
}

export class Verifier {

    proofinfo: Map<string, ProofInfo> = new Map();

    async setProofInfo(
        credId: string,
        proof: CompositeProof,
        revealedMessages: Map<number, Uint8Array>, 
        schemaId: string, 
        credDefId: string,
        registryId: string,
        nonce: Uint8Array<ArrayBufferLike>){
        const proofinfo: ProofInfo = {
            proof, revealedMessages, schemaId,credDefId, registryId, nonce
        };
        this.proofinfo.set(credId, proofinfo)
    }

    getProof(credId: string){
        return this.proofinfo.get(credId);
    }

    /*async buildCompositeProof(credId: string){//sigParams: BBSPlusSignatureParamsG1, issuerPk: BBSPlusKeypairG2['publicKey'], revealedMsgs: Map<number, Uint8Array<ArrayBufferLike>>, keypair: AccumulatorKeypair["publicKey"], provingKey: MembershipProvingKey, accumulator: PositiveAccumulator, proof: CompositeProof, nonce: Uint8Array, params: AccumulatorParams, k_handle: number) {
        const proof = this.proofinfo.get(credId);


        //10. Verifier rebuilds statements + metastatements (no witnesses, no signature)
        const verStmts = new Statements();
        verStmts.add(
            Statement.bbsPlusSignatureVerifierConstantTime(sigParams, issuerPk, proof?.revealedMessages!, false),
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

        const isValid = proof?.proof.verify(verifierSpec, proof.nonce);
        console.log("Proof verification result for cred1: ", isValid);
        return isValid;
    }

    async getOnChainAccumulator(){
        const onChainAccumulator: string = await this.accumulatorContract.getAccumulator!();
            if (!onChainAccumulator || onChainAccumulator === '0x' || onChainAccumulator.length <= 2) {
            return null;
        }
        return PositiveAccumulator.fromAccumulated(Uint8Array.from(Buffer.from(onChainAccumulator.slice(2), 'hex')));
    }*/
}

