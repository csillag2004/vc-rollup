// Chain access with ethers: deployment from forge artifacts, contract calls, the RegistryHistory
// that anyone can rebuild from events, and the guard proofs guarded updates leave on the ledger.
import { ethers } from 'ethers';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  g1ToEip, g2ToEip, g1FromEip, g2FromEip, type G1Point, scalarToHex32, g1, g2,
} from '../crypto/bls.ts';
import type { PublicKeys, RegistryValues, Srs } from '../crypto/accumulator.ts';
import type { RegistryHistory } from '../registry/history.ts';
import type { Presentation } from '../ql/compile.ts';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

export function artifact(name: string, file = `${name}.sol`): { abi: ethers.InterfaceAbi; bytecode: string } {
  const j = JSON.parse(fs.readFileSync(path.join(ROOT, 'out', file, `${name}.json`), 'utf8'));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

export interface Deployment {
  did: ethers.Contract;
  schemas: ethers.Contract;
  credDefs: ethers.Contract;
  policies: ethers.Contract;
  state: ethers.Contract;
  /** first block worth reading events from (the deployment block on a public chain; 0 on anvil) */
  fromBlock?: number;
}

export type ContractName = Exclude<keyof Deployment, 'fromBlock'>;

/** public RPCs cap eth_getLogs at a block range, so events are read in windows of this size */
const LOG_WINDOW = 9_000;

async function events(d: Deployment, c: ethers.Contract, filter: ethers.DeferredTopicFilter): Promise<(ethers.EventLog | ethers.Log)[]> {
  if (!d.fromBlock) return c.queryFilter(filter, 0, 'latest');
  const latest = await c.runner!.provider!.getBlockNumber();
  const out: (ethers.EventLog | ethers.Log)[] = [];
  for (let from = d.fromBlock; from <= latest; from += LOG_WINDOW) {
    out.push(...await c.queryFilter(filter, from, Math.min(from + LOG_WINDOW - 1, latest)));
  }
  return out;
}

async function deployOne(signer: ethers.Signer, name: string, args: unknown[], file?: string): Promise<ethers.Contract> {
  const a = artifact(name, file);
  const c = await new ethers.ContractFactory(a.abi, a.bytecode, signer).deploy(...args);
  await c.waitForDeployment();
  return c as unknown as ethers.Contract;
}

export async function deployAll(signer: ethers.Signer, didAddress?: string): Promise<Deployment> {
  const did = didAddress
    ? new ethers.Contract(didAddress, artifact('EthereumDIDRegistry').abi, signer)
    : await deployOne(signer, 'EthereumDIDRegistry', []);
  const schemas = await deployOne(signer, 'SchemaRegistry', []);
  const credDefs = await deployOne(signer, 'CredDefRegistry', [await did.getAddress(), await schemas.getAddress()]);
  const policies = await deployOne(signer, 'PolicyRegistry', [await credDefs.getAddress()]);
  const state = await deployOne(signer, 'StateRegistry', [await credDefs.getAddress(), await policies.getAddress()]);
  return { did, schemas, credDefs, policies, state };
}

export function attach(addresses: Record<ContractName, string>, runner: ethers.ContractRunner, fromBlock?: number): Deployment {
  return {
    ...(fromBlock !== undefined ? { fromBlock } : {}),
    did: new ethers.Contract(addresses.did, artifact('EthereumDIDRegistry').abi, runner),
    schemas: new ethers.Contract(addresses.schemas, artifact('SchemaRegistry').abi, runner),
    credDefs: new ethers.Contract(addresses.credDefs, artifact('CredDefRegistry').abi, runner),
    policies: new ethers.Contract(addresses.policies, artifact('PolicyRegistry').abi, runner),
    state: new ethers.Contract(addresses.state, artifact('StateRegistry').abi, runner),
  };
}

/** the custom error a reverted call carries, decoded against every contract of the deployment */
export function revertName(d: Deployment, e: unknown): string {
  const x = e as { data?: string; info?: { error?: { data?: string } }; error?: { data?: string }; message?: string };
  const data = x?.data ?? x?.info?.error?.data ?? x?.error?.data;
  if (data) {
    for (const c of [d.state, d.policies, d.credDefs, d.schemas, d.did]) {
      try {
        const parsed = c.interface.parseError(data);
        if (parsed) return parsed.name;
      } catch { /* not this contract's error */ }
    }
  }
  return (x?.message ?? String(e)).slice(0, 120);
}

/** the attribute under which an issuer publishes its BBS key in its ethr-DID document */
export const BBS_KEY_ATTRIBUTE = ethers.encodeBytes32String('did/pub/Bls12381G2/veriKey/hex');

export async function publishBbsKey(d: Deployment, issuer: ethers.Signer, pk: Uint8Array): Promise<ethers.TransactionReceipt> {
  const addr = await issuer.getAddress();
  const tx = await (d.did.connect(issuer) as ethers.Contract).setAttribute!(addr, BBS_KEY_ATTRIBUTE, pk, 365n * 24n * 3600n);
  return tx.wait();
}

/** the latest BBS key the DID's controller published (read from DIDAttributeChanged events) */
export async function resolveBbsKey(d: Deployment, issuer: string): Promise<Uint8Array> {
  const evs = await events(d, d.did, d.did.filters.DIDAttributeChanged!(issuer));
  const mine = evs.filter((e) => 'args' in e && e.args.name === BBS_KEY_ATTRIBUTE);
  const last = mine[mine.length - 1];
  if (!last || !('args' in last)) throw new Error(`no BBS key in the DID document of ${issuer}`);
  return ethers.getBytes(last.args.value);
}

export const pubToEip = (p: PublicKeys) => ({ V0: g1ToEip(p.V0), Qtilde: g2ToEip(p.Qtilde), Q: g1ToEip(p.Q) });
export const srsToEip = (s: Srs) => ({ g1: s.g1Powers.map(g1ToEip), g2: s.g2Powers.map(g2ToEip) });

/** rebuild the registry history from the contract's events */
export async function readHistory(d: Deployment, registryId: string): Promise<RegistryHistory> {
  const st = d.state;
  const created = (await events(d, st, st.filters.RegistryCreated!(registryId)))[0] as ethers.EventLog | undefined;
  if (!created) throw new Error(`unknown registry ${registryId}`);
  const pub: PublicKeys = { V0: g1FromEip(created.args.V0), Qtilde: g2FromEip(created.args.Qtilde), Q: g1FromEip(created.args.Q) };
  const credDefId: string = created.args.credDefId;
  const srsEv = (await events(d, st, st.filters.SrsPublished!(registryId)))[0] as ethers.EventLog | undefined;
  const srs: Srs | undefined = srsEv
    ? { g1Powers: srsEv.args.g1Powers.map((h: string) => g1FromEip(h)), g2Powers: srsEv.args.g2Powers.map((h: string) => g2FromEip(h)) }
    : undefined;

  // issuance and revocation both reveal y
  type Step = { version: number; y: bigint; into: Map<bigint, number>; apply: (v: RegistryValues) => RegistryValues };
  const issuedAt = new Map<bigint, number>();
  const revokedAt = new Map<bigint, number>();
  const steps: Step[] = [];
  for (const e of (await events(d, st, st.filters.Issued!(registryId))) as ethers.EventLog[]) {
    const I = g1FromEip(e.args.newI), WIR = g1FromEip(e.args.newWIR);
    steps.push({ version: Number(e.args.version), y: BigInt(e.args.y), into: issuedAt, apply: (v) => ({ ...v, I, WIR }) });
  }
  for (const e of (await events(d, st, st.filters.Revoked!(registryId))) as ethers.EventLog[]) {
    const A = g1FromEip(e.args.newA), Rtilde = g2FromEip(e.args.newRtilde), WIR = g1FromEip(e.args.newWIR);
    steps.push({ version: Number(e.args.version), y: BigInt(e.args.y), into: revokedAt, apply: (v) => ({ ...v, A, Rtilde, WIR }) });
  }
  steps.sort((a, b) => a.version - b.version);
  const values: RegistryValues[] = [{ A: pub.V0, Rtilde: g2, I: g1, WIR: g1 }];
  for (const s of steps) {
    if (s.version !== values.length) throw new Error(`gap in history at version ${s.version}`);
    values.push(s.apply(values[values.length - 1]!));
    s.into.set(s.y, s.version);
  }
  const issuer: string = await d.credDefs.issuerOf!(credDefId);
  const issuerPk = await resolveBbsKey(d, issuer);
  return { registryId, credDefId, pub, ...(srs ? { srs } : {}), values, issuedAt, revokedAt, issuerPk };
}

/** the guard proof is the presentation as UTF-8 JSON: deterministic for a given presentation, and readable back */
export const encodeGuardProof = (p: Presentation): Uint8Array => ethers.toUtf8Bytes(JSON.stringify(p));
export const decodeGuardProof = (proof: ethers.BytesLike): Presentation => JSON.parse(ethers.toUtf8String(proof));

export interface GuardProofRecord { registryId: string; version: number; policyId: string; presentation: Presentation }

/** the proof of the guarded update that created `version` of the registry (GuardProof event) */
export async function readGuardProof(d: Deployment, registryId: string, version: number): Promise<GuardProofRecord> {
  const e = (await events(d, d.state, d.state.filters.GuardProof!(registryId, version)))[0] as ethers.EventLog | undefined;
  if (!e) throw new Error(`no guarded update created version ${version} of ${registryId}`);
  return { registryId, version, policyId: e.args.policyId, presentation: decodeGuardProof(e.args.proof) };
}

export const yHex = (y: bigint): string => scalarToHex32(y);
export const g1Eip = (p: G1Point): string => g1ToEip(p);
