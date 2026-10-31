// The three off-chain roles on top of the chain client: the issuer (holds the BBS key and α, is the
// only updater), the holder (wallet, presentations) and the verifier (anyone; reads the ledger).
import { ethers } from 'ethers';
import * as acc from '../crypto/accumulator.ts';
import * as bbs from '../crypto/bbs.ts';
import { g1ToEip, g2ToEip, mod, randomScalar, utf8ToBytes, scalarToHex32, type G1Point } from '../crypto/bls.ts';
import { type Deployment, type ContractName, publishBbsKey, readHistory, pubToEip, srsToEip } from '../chain/client.ts';
import { parse } from '../ql/parser.ts';
import {
  present, verifyPresentation, analyse, type PublicContext, type WalletCredential, type Presentation, type Binding,
} from '../ql/compile.ts';
import { checkFreshness } from '../ql/freshness.ts';
import { groupVersionAt, type RegistryHistory } from '../registry/history.ts';

const CLASS_ID = { 'state-independent': 0, stable: 1, 'co-stable': 2, volatile: 3 } as const;
const CAS_ID = { none: 0, group: 1, global: 2 } as const;
const KIND_ID = { group: 0, registry: 1, creddef: 2 } as const;
export const ACTION = { issue: 0, revoke: 1, present: 2 } as const;

export interface PolicyRef { policyId: string; query: string; bindings: [string, Binding][] }

/** Validate the proof before the trusted updater supplies its hash and CAS versions. */
export function validateGuardPresentation(policy: PolicyRef, p: Presentation, ctx: PublicContext) {
  if (p.query !== policy.query) throw new Error('guard proof rejected: it presents another query');
  const verified = verifyPresentation(parse(policy.query), p, ctx);
  if (!verified.ok) throw new Error(`guard proof rejected: ${verified.reason}`);
  if (verified.cas === 'global') {
    // CredDef bindings are skipped by the contract. Every registry used by this proof must
    // also have a registry or group binding so that the transaction checks its version.
    const covered = new Set([...ctx.bindings.values()].flatMap((b) => b.kind === 'creddef' ? [] : [b.registryId]));
    for (const id of Object.keys(p.versions)) {
      if (!covered.has(id)) throw new Error(`guard proof rejected: registry ${id} has no CAS binding`);
    }
  }
  return verified;
}

/** public context for a query: histories of every registry it may touch, read from the ledger */
export async function loadContext(d: Deployment, bindings: [string, Binding][], extraRegistries: string[] = []): Promise<PublicContext> {
  const ids = new Set(extraRegistries);
  for (const [, b] of bindings) if (b.kind !== 'creddef') ids.add(b.registryId);
  const registries = new Map<string, RegistryHistory>();
  for (const id of ids) registries.set(id, await readHistory(d, id));
  return { registries, bindings: new Map(bindings) };
}

export async function readGroup(d: Deployment, groupId: string): Promise<Binding> {
  const [registryId, , , members] = await d.state.getGroup!(groupId);
  return { kind: 'group', groupId, registryId, members: (members as string[]).map((m) => BigInt(m)) };
}

export class Issuer {
  readonly signer: ethers.Signer;
  readonly d: Deployment;
  kp!: bbs.BbsKeyPair;
  credDefId = '';
  /** registryId -> accumulator secret */
  readonly secrets = new Map<string, acc.AccumulatorSecret>();
  /** registryId -> pub keys and SRS kept locally */
  readonly local = new Map<string, { pub: acc.PublicKeys; srs: acc.Srs }>();

  constructor(signer: ethers.Signer, d: Deployment) { this.signer = signer; this.d = d; }

  private c(name: ContractName): ethers.Contract { return this.d[name].connect(this.signer) as ethers.Contract; }

  async setUp(schemaName: string, attributes: string[]): Promise<void> {
    await this.publishKey();
    await this.registerCredDef(await this.registerSchema(schemaName, '1.0', attributes));
  }

  /** a fresh BBS key in the issuer's DID document */
  async publishKey(): Promise<void> {
    this.kp = await bbs.generateKeyPair();
    await publishBbsKey(this.d, this.signer, this.kp.publicKey);
  }

  async registerSchema(name: string, version: string, attributes: string[]): Promise<string> {
    const schemas = this.c('schemas');
    const schemaId: string = await schemas.registerSchema!.staticCall(name, version, true, attributes);
    await (await schemas.registerSchema!(name, version, true, attributes)).wait();
    return schemaId;
  }

  async registerCredDef(schemaId: string): Promise<string> {
    const me = await this.signer.getAddress();
    const credDefs = this.c('credDefs');
    this.credDefId = await credDefs.registerCredDef!.staticCall(me, schemaId, 'default', ethers.id('bbs-key-1'));
    await (await credDefs.registerCredDef!(me, schemaId, 'default', ethers.id('bbs-key-1'))).wait();
    return this.credDefId;
  }

  async createRegistry(label: string, srsDegree: number): Promise<string> {
    const { secret, pub } = acc.generateAccumulatorKeys();
    const srs = acc.makeSrs(secret.alpha, srsDegree);
    const st = this.c('state');
    const e = pubToEip(pub);
    const lbl = ethers.id(label);
    const registryId: string = await st.createRegistry!.staticCall(this.credDefId, lbl, e.V0, e.Qtilde, e.Q);
    await (await st.createRegistry!(this.credDefId, lbl, e.V0, e.Qtilde, e.Q)).wait();
    const s = srsToEip(srs);
    await (await st.publishSrs!(registryId, s.g1, s.g2)).wait();
    this.secrets.set(registryId, secret);
    this.local.set(registryId, { pub, srs });
    return registryId;
  }

  /** the holder sends its link secret; the issuer picks a fresh revocation ID and signs */
  async issue(registryId: string, attributes: string[], linkSecret: bigint, guard?: { policy: PolicyRef; presentation: Presentation }):
    Promise<WalletCredential> {
    const h = await readHistory(this.d, registryId);
    const values = h.values[h.values.length - 1]!;
    const yMsg = crypto.getRandomValues(new Uint8Array(32));
    const msgs = [yMsg, ...attributes.map(utf8ToBytes), utf8ToBytes(linkSecret.toString(16))];
    const scalars = msgs.map(bbs.messageToScalar);
    const y = scalars[0]!;
    const header = utf8ToBytes(this.credDefId);
    const sig = await bbs.sign(this.kp, header, msgs);
    const st = this.c('state');
    const step = acc.issueStep(this.secrets.get(registryId)!, values, y, () => 0n);
    // the Schnorr challenge is the contract's; recompute the response with it
    const k = randomScalar();
    const Rc = mulG1(values.I, k);
    const c = BigInt(await st.issueChallenge!(registryId, g1ToEip(step.newI), g1ToEip(step.T), g1ToEip(Rc)));
    const call = { newI: g1ToEip(step.newI), newWIR: g1ToEip(step.newWIR), T: g1ToEip(step.T), R: g1ToEip(Rc), z: mod(k + c * y) };
    if (guard) {
      const g = await this.guardFor(guard.policy, guard.presentation);
      await (await st.guardedIssueUpdate!(registryId, call, g)).wait();
    } else {
      await (await st.issueUpdate!(registryId, call)).wait();
    }
    const version = h.values.length; // the version this issuance created
    return {
      credDefId: this.credDefId, registryId, header, scalars, sig, yIndex: 0, lsIndex: msgs.length - 1,
      disclose: [], receiptA: step.receiptA, receiptVersion: version,
    };
  }

  revokeArgs(registryId: string, h: RegistryHistory, y: bigint) {
    const st = acc.revokeStep(this.secrets.get(registryId)!, h.values[h.values.length - 1]!, y);
    return [registryId, scalarToHex32(y), g1ToEip(st.newA), g2ToEip(st.newRtilde), g1ToEip(st.newWIR)] as const;
  }

  async revoke(registryId: string, y: bigint): Promise<ethers.TransactionReceipt> {
    const h = await readHistory(this.d, registryId);
    return (await this.c('state').revoke!(...this.revokeArgs(registryId, h, y))).wait();
  }

  async createGroup(registryId: string, label: string, members: bigint[]): Promise<string> {
    const sorted = [...members].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const h = await readHistory(this.d, registryId);
    const I = h.values[h.values.length - 1]!.I;
    const W = acc.groupSubsetWitness(this.secrets.get(registryId)!, I, sorted);
    const srs = srsToEip(this.local.get(registryId)!.srs);
    const st = this.c('state');
    const args = [registryId, ethers.id(label), sorted.map(scalarToHex32), g1ToEip(W), srs.g2] as const;
    const groupId: string = await st.createGroup!.staticCall(...args);
    await (await st.createGroup!(...args)).wait();
    return groupId;
  }

  async registerPolicy(query: string, bindings: [string, Binding][], bindTo?: keyof typeof ACTION): Promise<PolicyRef> {
    const an = analyse(parse(query));
    const b = bindings.map(([name, x]) => ({
      name: ethers.encodeBytes32String(name), kind: KIND_ID[x.kind],
      target: x.kind === 'group' ? x.groupId : x.kind === 'registry' ? x.registryId : x.credDefId,
    }));
    const pol = this.c('policies');
    const args = [query, CLASS_ID[an.class], CAS_ID[an.cas], b] as const;
    const policyId: string = await pol.registerPolicy!.staticCall(...args);
    await (await pol.registerPolicy!(...args)).wait();
    if (bindTo) await (await pol.bindPolicy!(this.credDefId, ACTION[bindTo], policyId)).wait();
    return { policyId, query, bindings };
  }

  /** expected versions in binding order: group versions (group CAS) or registry versions at the bound state */
  async guardFor(policy: PolicyRef, p: Presentation) {
    const registered = await this.c('policies').getPolicy!(policy.policyId);
    const an = analyse(parse(policy.query));
    if (registered.query !== policy.query || Number(registered.class) !== CLASS_ID[an.class]
      || Number(registered.casMode) !== CAS_ID[an.cas] || registered.bindings.length !== policy.bindings.length) {
      throw new Error('guard policy does not match the registered policy');
    }
    for (const [i, [name, b]] of policy.bindings.entries()) {
      const stored = registered.bindings[i];
      const target = b.kind === 'group' ? b.groupId : b.kind === 'registry' ? b.registryId : b.credDefId;
      if (stored.name !== ethers.encodeBytes32String(name) || Number(stored.kind) !== KIND_ID[b.kind] || stored.target !== target) {
        throw new Error('guard bindings do not match the registered policy');
      }
      if (b.kind === 'group') {
        const actual = await readGroup(this.d, b.groupId);
        if (actual.kind !== 'group' || actual.registryId !== b.registryId
          || actual.members.length !== b.members.length || actual.members.some((y, j) => y !== b.members[j])) {
          throw new Error('guard group does not match the ledger');
        }
      }
    }
    const ctx = await loadContext(this.d, policy.bindings, Object.keys(p.versions));
    validateGuardPresentation(policy, p, ctx);
    const expected = policy.bindings.map(([, b]) => {
      if (b.kind === 'creddef') return 0n;
      const h = ctx.registries.get(b.registryId)!;
      const v = p.versions[b.registryId] ?? h.values.length - 1;
      if (b.kind === 'group' && an.cas === 'group') return BigInt(groupVersionAt(h, b.members, v));
      return BigInt(v);
    });
    return { policyId: policy.policyId, expectedVersions: expected, proofHash: ethers.id(JSON.stringify(p)) };
  }

  /**
   * A guarded revocation on request: the requester sends its revocation ID and a presentation of the
   * policy's query. The issuer verifies it off-chain (verify on read for the guard) and submits the
   * update with the versions the proof was bound to; the contract does the compare-and-swap.
   */
  async guardedRevoke(registryId: string, y: bigint, policy: PolicyRef, p: Presentation): Promise<ethers.TransactionReceipt> {
    const g = await this.guardFor(policy, p);
    const h = await readHistory(this.d, registryId);
    return (await this.c('state').guardedRevoke!(...this.revokeArgs(registryId, h, y), g)).wait();
  }

  aggregate(registryId: string, A: G1Point, members: bigint[]): G1Point {
    return acc.aggregateReceiptWithTrapdoor(this.secrets.get(registryId)!, A, members);
  }
}

const mulG1 = (p: G1Point, k: bigint): G1Point => p.multiply(mod(k));

export class Holder {
  readonly wallet: WalletCredential[] = [];
  readonly linkSecret = randomScalar();
  readonly d: Deployment;
  constructor(d: Deployment) { this.d = d; }

  async present(query: string, bindings: [string, Binding][], nonce: string, opts: Parameters<typeof present>[5] = {}): Promise<Presentation> {
    const ctx = await loadContext(this.d, bindings, this.wallet.map((w) => w.registryId));
    return present(parse(query), query, ctx, this.wallet, nonce, opts);
  }
}

export class Verifier {
  readonly d: Deployment;
  constructor(d: Deployment) { this.d = d; }

  /** cryptographic check plus freshness against the current ledger */
  async verify(query: string, bindings: [string, Binding][], p: Presentation) {
    const ctx = await loadContext(this.d, bindings, Object.keys(p.versions));
    const v = verifyPresentation(parse(query), p, ctx);
    const fresh = checkFreshness(p, v.class, v.cas, ctx);
    return { ...v, fresh: fresh.fresh, freshReason: fresh.reason };
  }
}
