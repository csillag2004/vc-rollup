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

async function main() {
    const issuer = new Issuer();
    const holder = new Holder();
    const verifier = new Verifier();

    //1. create accumulator
    const accumulator = await issuer.createAccumulator();

    //2. schemaIdk létrehozása
    const schemaId = await issuer.schemaId();

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



}

main().catch(console.error);

