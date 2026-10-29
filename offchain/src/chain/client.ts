// Chain access with ethers: deployment from forge artifacts, contract calls, and the
// RegistryHistory that anyone can rebuild from events.
import { ethers } from 'ethers';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  g1ToEip, g2ToEip, g1FromEip, g2FromEip, type G1Point, scalarToHex32, g1, g2,
} from '../crypto/bls.ts';
import type { PublicKeys, RegistryValues, Srs } from '../crypto/accumulator.ts';
import type { RegistryHistory } from '../registry/history.ts';

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

  type Step = { version: number; apply: (v: RegistryValues) => RegistryValues; y?: bigint };
  const steps: Step[] = [];
  for (const e of (await events(d, st, st.filters.Issued!(registryId))) as ethers.EventLog[]) {
    const I = g1FromEip(e.args.newI), WIR = g1FromEip(e.args.newWIR);
    steps.push({ version: Number(e.args.version), apply: (v) => ({ ...v, I, WIR }) });
  }
  for (const e of (await events(d, st, st.filters.Revoked!(registryId))) as ethers.EventLog[]) {
    const A = g1FromEip(e.args.newA), Rtilde = g2FromEip(e.args.newRtilde), WIR = g1FromEip(e.args.newWIR);
    steps.push({ version: Number(e.args.version), y: BigInt(e.args.y), apply: (v) => ({ ...v, A, Rtilde, WIR }) });
  }
  steps.sort((a, b) => a.version - b.version);
  const values: RegistryValues[] = [{ A: pub.V0, Rtilde: g2, I: g1, WIR: g1 }];
  const revokedAt = new Map<bigint, number>();
  for (const s of steps) {
    if (s.version !== values.length) throw new Error(`gap in history at version ${s.version}`);
    values.push(s.apply(values[values.length - 1]!));
    if (s.y !== undefined) revokedAt.set(s.y, s.version);
  }
  const issuer: string = await d.credDefs.issuerOf!(credDefId);
  const issuerPk = await resolveBbsKey(d, issuer);
  return { registryId, credDefId, pub, ...(srs ? { srs } : {}), values, revokedAt, issuerPk };
}

export const yHex = (y: bigint): string => scalarToHex32(y);
export const g1Eip = (p: G1Point): string => g1ToEip(p);
