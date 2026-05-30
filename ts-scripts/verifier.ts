import 'dotenv/config';
import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { Resolver } from 'did-resolver';
import { getResolver as getEthrDidResolver } from 'ethr-did-resolver';
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
  AccumulatorPublicKey,
} from '@docknetwork/crypto-wasm-ts';

type ProofInfo ={
    proof: CompositeProof;
    revealedMessages: Map<number, Uint8Array>;
    schemaId: string;
    credDefId: string;
    registryId: string;
    nonce: Uint8Array<ArrayBufferLike>;
    provingKey: MembershipProvingKey;
}

export class Verifier {
    private readonly ACCUMULATOR_ADDR = process.env.ACCUMULATOR_ADDR!;
    private readonly PRIVATE_KEY = process.env.PRIVATE_KEY_VERIFIER!;
    private readonly SCHEMA_REGISTRY = process.env.SCHEMA_REGISTRY_ADDR!;
    private readonly CREDDEF_REGISTRY = process.env.CREDDEF_REGISTRY_ADDR!;
    //private readonly REVOCATION_REGISTRY = process.env.REVOCATION_REGISTRY_ADDR!;
    private readonly REGISTRY = process.env.REGISTRY_ADDRESS!;   // EthereumDIDRegistry
    private readonly RPC_URL = 'https://sepolia-rpc.scroll.io';
    private readonly CHAIN_ID = 534351;                         // Scroll Sepolia
    private readonly DID_NETWORK = 'scrollSepolia';

    private schemaRegistryContract!: ethers.Contract;
    private credDefRegistryContract!: ethers.Contract;
    private revocationRegistryContract!: ethers.Contract;
    private accumulatorContract!: ethers.Contract;

    constructor() {
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

        const provider = new ethers.JsonRpcProvider(this.RPC_URL);
        const wallet = new ethers.Wallet(this.PRIVATE_KEY, provider);
        this.schemaRegistryContract = new ethers.Contract(this.SCHEMA_REGISTRY, artifact_schema.abi, wallet);
        this.credDefRegistryContract = new ethers.Contract(this.CREDDEF_REGISTRY, artifact_creddef.abi, wallet);
        //this.revocationRegistryContract = new ethers.Contract(this.REVOCATION_REGISTRY, artifact_revocation.abi, wallet);
        this.accumulatorContract = new ethers.Contract(this.ACCUMULATOR_ADDR, artifact_accumulator.abi, wallet);  //le kell nullázni az akkumlátort!!!
    }

    proofinfo: Map<string, ProofInfo> = new Map();

    async setProofInfo(
        credId: string,
        proof: CompositeProof,
        revealedMessages: Map<number, Uint8Array>, 
        schemaId: string, 
        credDefId: string,
        registryId: string,
        nonce: Uint8Array<ArrayBufferLike>,
        prove: MembershipProvingKey){
        const proofinfo: ProofInfo = {
            proof, revealedMessages, schemaId, credDefId, registryId, nonce, provingKey: prove
        };
        this.proofinfo.set(credId, proofinfo)
    }

    getProof(credId: string){
        return this.proofinfo.get(credId);
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

    async getIssuerPublicKey(credDefId: string): Promise<BBSPlusPublicKeyG2 | null> {
        // 1. Look up the CredDef on-chain -> issuer address + keyId (= keccak256 of the BBS+ pubkey)
        const credDef = await this.credDefRegistryContract.getCredDef!(credDefId);
        const issuer: string = credDef.issuer;
        const keyId: string = credDef.keyId; // bytes32, 0x-prefixed

        // 2. Resolve the issuer's did:ethr document via ethr-did-resolver
        const did = `did:ethr:${this.DID_NETWORK}:${issuer}`;
        const resolver = new Resolver(
            getEthrDidResolver({
                networks: [
                    { name: this.DID_NETWORK, chainId: this.CHAIN_ID, rpcUrl: this.RPC_URL, registry: this.REGISTRY },
                ],
            }),
        );
        const { didDocument } = await resolver.resolve(did);
        const verificationMethods = didDocument?.verificationMethod ?? [];

        // 3. Pick the verification method whose published key matches the on-chain keyId.
        //    This binds the DID-published BBS+ key to the CredDef the issuer registered.
        for (const vm of verificationMethods) {
            const hex = this.publicKeyHexFromVerificationMethod(vm);
            if (!hex) continue;
            if (ethers.keccak256(hex).toLowerCase() === keyId.toLowerCase()) {
                return new BBSPlusPublicKeyG2(Uint8Array.from(Buffer.from(hex.slice(2), 'hex')));
            }
        }
        return null;
    }

    /** Extracts the raw public-key bytes (as a 0x-prefixed hex string) from a DID verification method.
     *  The issuer publishes the BBS+ key with `hex` encoding (did/pub/Bls12381G2/veriKey/hex). */
    private publicKeyHexFromVerificationMethod(vm: { publicKeyHex?: string }): string | null {
        if (!vm.publicKeyHex) return null;
        return vm.publicKeyHex.startsWith('0x') ? vm.publicKeyHex : '0x' + vm.publicKeyHex;
    }

    async getIssuerParams(schemaId: string): Promise<BBSPlusSignatureParamsG1 | null> {
        const sigParams = BBSPlusSignatureParamsG1.generate(
            (await this.getSchemaAttributes(schemaId)).length + 1, // +1 for the trailing revocationId (K_HANDLE)
            this.stringToBytes(schemaId), //az aláírás paramétere a schemaID
        );
        return sigParams;
    }

    private stringToBytes(message: string): Uint8Array {
        return Uint8Array.from(Buffer.from(message, 'utf-8'));
    }

    async getSchemaAttributes(schemaId: string): Promise<string[]> {
        const schema = await this.schemaRegistryContract.getSchema!(schemaId);
        return schema.attributeNames;
    }

    async buildCompositeProof(credId: string){//sigParams: BBSPlusSignatureParamsG1, issuerPk: BBSPlusKeypairG2['publicKey'], revealedMsgs: Map<number, Uint8Array<ArrayBufferLike>>, keypair: AccumulatorKeypair["publicKey"], provingKey: MembershipProvingKey, accumulator: PositiveAccumulator, proof: CompositeProof, nonce: Uint8Array, params: AccumulatorParams, k_handle: number) {
        const proof = this.proofinfo.get(credId);


        //10. Verifier rebuilds statements + metastatements (no witnesses, no signature)
        const verStmts = new Statements();
        verStmts.add(
            Statement.bbsPlusSignatureVerifierConstantTime((await this.getIssuerParams(proof!.schemaId!))!, (await this.getIssuerPublicKey(proof!.credDefId!))!, proof!.revealedMessages!, false),
        );
        const accumulator = this.getOnChainAccumulator()
        verStmts.add(
            Statement.vbAccumulatorMembership( //átadod
                (await this.getParams())! /*DID-ba*/, (await this.getPublicKey())!/*DID*/, (proof?.provingKey)!/*holder adja*/, (await this.getOnChainAccumulator())!.accumulated,
            )
        );
        const eqV = new WitnessEqualityMetaStatement();
        eqV.addWitnessRef(0, (await this.getSchemaAttributes(proof!.schemaId!)).length); //kell egy új függvény, ami visszaadja, hogy hány attribútuma van a schemának
        eqV.addWitnessRef(1, 0);
        const metaStmtsV = new MetaStatements();
        metaStmtsV.add(MetaStatement.witnessEquality(eqV));
        const verifierSpec = new ProofSpec(verStmts, metaStmtsV);

        const isValid = proof?.proof.verify(verifierSpec, proof.nonce);
        console.log("Proof verification result for cred1: ", isValid);
        return isValid;
    }
}

