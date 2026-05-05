import 'dotenv/config';
import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { InMemoryState } from './in-memory-persistence';
import {Issuer} from './issuer';
import {Verifier} from './verifier';
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
  BBSPlusSignatureParamsG1,
  BBSPlusSignatureG1,
} from '@docknetwork/crypto-wasm-ts';
import { sign } from 'crypto';

async function main() {
    const issuer = new Issuer();
    const holder = new Holder();
    const verifier = new Verifier();

    //1. create accumulator
    const accumulator = await issuer.createAccumulator();

    //2. schemaIdk létrehozása
    const schemaId = await issuer.schemaId(); //kapott attribútumokat

    //3. credDefId létrehozása
    const credDefId = await issuer.credDefId(schemaId);

    //4. revocation registry létrehozása
    const registryId = await issuer.revocationRegistry(accumulator, credDefId);

    //5. add credential
    const newAccumulator = await issuer.addCredentials("cred1", registryId);
    const newAccumulator2 = await issuer.addCredentials("cred2", registryId);
    const newAccumulator3 = await issuer.addCredentials("cred3", registryId);

    //6. revoke credential (cred2)
    const revokedAccumulator = await issuer.revokeCredentials("cred2",  registryId);

    //7. witness
    const witness1 = await issuer.createWitness("cred1");
    const witness2 = await issuer.createWitness("cred2");
    const witness3 = await issuer.createWitness("cred3");

    //8. BBS+ setup + sign cred1
    const sign = issuer.signCredential("cred1", ["Alice", "Smith", "2020", "Computer Science", "Bachelor"], witness1, 5); 
    console.log("Credential signature created: ", sign);

    //9. composite proof
    const proof = holder.compositeProofForCredential(sign.sig1, sign.cred1Messages, sign.issuerPk, sign.sigParams, witness1!.witness, witness1!.w1, accumulator.params, issuer.getPublicKey(), accumulator);
    console.log("Composite proof created: ", proof);

    //10. verify proof
    await verifier.buildCompositeProof(sign.sigParams,
                                        sign.issuerPk,
                                        new Map<number, Uint8Array>([[2, sign.cred1Messages[2]!], [3, sign.cred1Messages[3]!]]),
                                        issuer.getPublicKey(),
                                        holder.getProvingKey(),
                                        issuer.getAccumulator(),
                                        proof,
                                        holder.getNonce(),
                                        issuer.getAccumulator().params!,
                                        sign.k_handler);
}

main().catch(console.error);


