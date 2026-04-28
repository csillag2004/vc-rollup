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

function bytesToHex(bytes: Uint8Array): string {
    return '0x' + Buffer.from(bytes).toString('hex');
}

let myMap = new Map<string, number>(); //it a number lesz a random y, most még nem random, csak tesztelés miatt 1-et adok neki
myMap.set('cred1', 1001);
myMap.set('cred2', 2002);
myMap.set('cred3', 3003);

async function main() {
    const RPC_URL = 'https://sepolia-rpc.scroll.io';
    const CHAIN_ID = 534351;
    const REGISTRY = process.env.REGISTRY_ADDRESS!;
    const PRIVATE_KEY = process.env.PRIVATE_KEY!;
    const CREDDEF_REGISTRY = process.env.CREDDEF_REGISTRY_ADDR!;
    const REVOCATION_REGISTRY = process.env.REVOCATION_REGISTRY_ADDR!;
    const SCHEMA_REGISTRY = process.env.SCHEMA_REGISTRY_ADDR!;


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

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
    const schemaRegistryContract = new ethers.Contract(SCHEMA_REGISTRY, artifact_schema.abi, wallet);
    const credDefRegistryContract = new ethers.Contract(CREDDEF_REGISTRY, artifact_creddef.abi, wallet);
    const revocationRegistryContract = new ethers.Contract(REVOCATION_REGISTRY, artifact_revocation.abi, wallet);

    //1. create accumulator

    function stringToBytes(message: string): Uint8Array {
        return Uint8Array.from(Buffer.from(message, 'utf-8'));
    }

    await initializeWasm();
    const params = PositiveAccumulator.generateParams(stringToBytes('vc-rollup-thesis-accumulator-params-v1'));
    const keypair = PositiveAccumulator.generateKeypair(params);
    const state = new InMemoryState();
    const accumulator = PositiveAccumulator.initialize(params);

    console.log("Initial accumulator:", bytesToHex(accumulator.accumulated));

    //2. schemaIdk létrehozása
    const attributes = ['studentName', 'university', 'degree', 'graduationYear', 'revocationId'];
    const random = Math.floor(Math.random() * 100000);
    const version = "1.0-" + random; //minden futtatásnál új verzió, hogy ne ütközzön a már regisztrált sémákkal
    const schemaTx = await schemaRegistryContract.registerSchema!("UniversityDegree", version, attributes);
    const schemaReceipt = await schemaTx.wait();
    // Az event-ből nyerjük ki a schemaId-t
    const schemaEvent = schemaRegistryContract.interface.parseLog(schemaReceipt?.logs[0]!);
    const schemaId = schemaEvent?.args[0]; // schemaId az első argument

    //3. credDef létrehozása
    const credDefTx = await credDefRegistryContract.registerCredDef!(schemaId, "default", PRIVATE_KEY);
    const credDefReceipt = await credDefTx.wait();
    const credDefEvent = credDefRegistryContract.interface.parseLog(credDefReceipt?.logs[0]!);
    const credDefId = credDefEvent?.args[0]; // credDefId az első argument

    //4. revocation registry létrehozása
    const revTx = await revocationRegistryContract.createRegistry!(credDefId, bytesToHex(accumulator.accumulated));
    const revReceipt = await revTx.wait();

    const revEvent = revocationRegistryContract.interface.parseLog(revReceipt?.logs[0]!);
    const registryId = revEvent?.args[0]; // registryId az első argument
    const acc = revEvent?.args[3]; // newAccumulator az 4. argument
    console.log("Created registry with accumulator: ", acc);


    //5. add credentials
    const m1 = Accumulator.encodePositiveNumberAsAccumulatorMember(myMap.get('cred1')!);
    const m2 = Accumulator.encodePositiveNumberAsAccumulatorMember(myMap.get('cred2')!);
    const m3 = Accumulator.encodePositiveNumberAsAccumulatorMember(myMap.get('cred3')!);

    //m1
    await accumulator.addBatch([m1], keypair.secretKey, state);
    console.log("Accumulator after adding cred1: ", bytesToHex(accumulator.accumulated));

    const revup1Tx=await revocationRegistryContract.updateRegistry!(registryId, bytesToHex(accumulator.accumulated), [myMap.get('cred1')!], []);
    const revup1Receipt = await revup1Tx.wait();
    const revup1Event = revocationRegistryContract.interface.parseLog(revup1Receipt?.logs[0]!);
    const new1Acc = revup1Event?.args[2];
    console.log("Updated registry with new accumulator: ", new1Acc);

    //m2
    await accumulator.addBatch([m2], keypair.secretKey, state);
    console.log("Accumulator after adding cred2: ", bytesToHex(accumulator.accumulated));

    const revup2Tx=await revocationRegistryContract.updateRegistry!(registryId, bytesToHex(accumulator.accumulated), [myMap.get('cred2')!], []);
    const revup2Receipt = await revup2Tx.wait();
    const revup2Event = revocationRegistryContract.interface.parseLog(revup2Receipt?.logs[0]!);
    const new2Acc = revup2Event?.args[2];
    console.log("Updated registry with new accumulator: ", new2Acc);

    //m3
    await accumulator.addBatch([m3], keypair.secretKey, state);
    console.log("Accumulator after adding cred3: ", bytesToHex(accumulator.accumulated));

    const revup3Tx=await revocationRegistryContract.updateRegistry!(registryId, bytesToHex(accumulator.accumulated), [myMap.get('cred3')!], []);
    const revup3Receipt = await revup3Tx.wait();
    const revup3Event = revocationRegistryContract.interface.parseLog(revup3Receipt?.logs[0]!);
    const new3Acc = revup3Event?.args[2];
    console.log("Updated registry with new accumulator: ", new3Acc);

    //6. revoke credential (cred2)
    await accumulator.removeBatch([m2], keypair.secretKey, state);
    console.log("Accumulator after revoking cred2: ", bytesToHex(accumulator.accumulated));

    const revRevokeTx=await revocationRegistryContract.updateRegistry!(registryId, bytesToHex(accumulator.accumulated), [], [myMap.get('cred2')!]);
    const revRevokeReceipt = await revRevokeTx.wait();
    const revRevokeEvent = revocationRegistryContract.interface.parseLog(revRevokeReceipt?.logs[0]!);
    const revokedAcc = revRevokeEvent?.args[2];
    console.log("Updated registry with new accumulator after revocation cred2: ", revokedAcc);


    //7. witness
    let witness1; //legyen igazi type
    let witness2;
    let witness3; 
    let w1;
    let w2;
    let w3;
    try {
        witness1 = await accumulator.membershipWitness(m1, keypair.secretKey, state);
        w1 = Witness.vbAccumulatorMembership(m1, witness1);
        console.log("Membership witness for cred1: ", witness1);
    } catch (e) {
        console.log("cred1 is revoked, cannot generate witness");
    }
    
    try {        
        witness2 = await accumulator.membershipWitness(m2, keypair.secretKey, state);
        w2 = Witness.vbAccumulatorMembership(m2, witness2);
        console.log("Membership witness for cred2: ", witness2);
    } catch (e) {
        console.log("cred2 is revoked, cannot generate witness");
    }

    
    try {
        witness3 = await accumulator.membershipWitness(m3, keypair.secretKey, state);
        w3 = Witness.vbAccumulatorMembership(m3, witness3);
        console.log("Membership witness for cred3: ", witness3);
    } catch (e) {
        console.log("cred3 is revoked, cannot generate witness");

    }

    //MAJD WITNESS UPDATE KELL


    //8. BBS+ setup + sign cred1
    //    The BBS+ message at slot K_HANDLE must be the SAME field element
    //    as the accumulator member m1 — that's what the witness-equality
    //    MetaStatement binds together. We pre-encode all messages and pass
    //    `false` to BBS+ so it doesn't re-encode them.
    const MESSAGE_COUNT = 5;
    const K_HANDLE = 4;

    const sigParams = BBSPlusSignatureParamsG1.generate(
        MESSAGE_COUNT,
        stringToBytes('issuer-sig-params-v1'),
    );
    const issuerKp = BBSPlusKeypairG2.generate(sigParams);
    const issuerSk = issuerKp.secretKey;
    const issuerPk = issuerKp.publicKey;

    const encB = (s: string) => Accumulator.encodeBytesAsAccumulatorMember(stringToBytes(s));
    const cred1Messages: Uint8Array[] = [
        encB('Alice'),       // 0: studentName
        encB('Budapest U'),  // 1: university
        encB('BSc'),         // 2: degree
        encB('2026'),        // 3: graduationYear
        m1,                  // 4: revocationId  ← K_HANDLE (same bytes as acc member)
    ];
    const sig1 = BBSPlusSignatureG1.generate(cred1Messages, issuerSk, sigParams, false);

    if (!w1 || !witness1) {
        throw new Error('cred1 membership witness is not available — cannot build proof');
    }

    //9. Build composite proof for cred1
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
    witnesses.add(w1);

    const proofSpec = new ProofSpec(proverStmts, metaStatements);
    const nonce = stringToBytes('nonce1');
    const proof = CompositeProof.generate(proofSpec, witnesses, nonce);
    console.log("Generated proof for cred1.");

    //10. Verifier rebuilds statements + metastatements (no witnesses, no signature)
    const verStmts = new Statements();
    verStmts.add(
        Statement.bbsPlusSignatureVerifierConstantTime(sigParams, issuerPk, revealedMsgs, false),
    );
    verStmts.add(
        Statement.vbAccumulatorMembership(
            params, keypair.publicKey, provingKey, accumulator.accumulated,
        ),
    );
    const eqV = new WitnessEqualityMetaStatement();
    eqV.addWitnessRef(0, K_HANDLE);
    eqV.addWitnessRef(1, 0);
    const metaStmtsV = new MetaStatements();
    metaStmtsV.add(MetaStatement.witnessEquality(eqV));
    const verifierSpec = new ProofSpec(verStmts, metaStmtsV);

    const isValid = proof.verify(verifierSpec, nonce);
    console.log("Proof verification result for cred1: ", isValid);
}


main().catch(console.error);

