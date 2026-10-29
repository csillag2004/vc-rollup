// The three off-chain roles on top of the chain client: the issuer (holds the BBS key and α, is the
// only updater), the holder (wallet, presentations) and the verifier (anyone; reads the ledger).
import { ethers } from 'ethers';
import * as acc from '../crypto/accumulator.ts';
import * as bbs from '../crypto/bbs.ts';
import { g1ToEip, g2ToEip, randomScalar, utf8ToBytes, scalarToHex32, type G1Point } from '../crypto/bls.ts';
import {
  type Deployment, type ContractName, publishBbsKey, readHistory, readGuardProof, pubToEip, srsToEip, encodeGuardProof,
} from '../chain/client.ts';
import { parse } from '../ql/parser.ts';
import {
  present, verifyPresentation, type PublicContext, type WalletCredential, type Presentation, type Binding,
} from '../ql/compile.ts';
import {
  compileGuard, chainBindings, presentedNeedsVersions, presentedBindings, BINDING_KIND, type GuardPrograms, type Op,
} from '../ql/programs.ts';
import { checkFreshness } from '../ql/freshness.ts';
import type { RegistryHistory } from '../registry/history.ts';

export const ACTION = { issue: 0, revoke: 1, present: 2 } as const;

/** a registered policy: the query text, its bindings and the two programs compiled from them */
export interface PolicyRef { policyId: string; query: string; bindings: [string, Binding][]; programs: GuardPrograms }

/** StateRegistry.Guard */
export interface Guard { policyId: string; expectedVersions: bigint[]; proof: Uint8Array }

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

const OP_FIELDS = ['kind', 'quant', 'k', 'domain', 'binding', 'body'] as const;
const sameOps = (a: Op[], b: ethers.Result[]): boolean =>
  a.length === b.length && a.every((op, i) => OP_FIELDS.every((f) => BigInt(op[f]) === BigInt(b[i]![f])));

/**
 * A policy as the ledger has it. The contract evaluates the registered programs, a reader verifies the
 * query text, so the programs must be the compilation of the text and the bindings.
 */
export async function readPolicy(d: Deployment, policyId: string): Promise<PolicyRef> {
  const p = await d.policies.getPolicy!(policyId);
  const bindings: [string, Binding][] = [];
  for (const b of p.bindings as ethers.Result[]) {
    const kind = Number(b.kind);
    bindings.push([ethers.decodeBytes32String(b.name),
      kind === BINDING_KIND.group ? await readGroup(d, b.target)
        : kind === BINDING_KIND.registry ? { kind: 'registry', registryId: b.target } : { kind: 'creddef', credDefId: b.target }]);
  }
  const programs = compileGuard(parse(p.query), bindings);
  if (!sameOps(programs.presented, p.presentedOps) || !sameOps(programs.public, p.publicOps)) {
    throw new Error(`policy ${policyId}: the registered programs are not the compilation of its query`);
  }
  return { policyId, query: p.query, bindings, programs };
}

export class Issuer {
  readonly signer: ethers.Signer;
  readonly d: Deployment;
  kp!: bbs.BbsKeyPair;
  credDefId = '';
  /** registryId -> accumulator secret */
  readonly secrets = new Map<string, acc.AccumulatorSecret>();

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
    return registryId;
  }

  /** the holder sends its link secret; the issuer picks a fresh revocation ID, signs, and issues it in the clear */
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
    const step = acc.issueStep(this.secrets.get(registryId)!, values, y);
    const args = [registryId, scalarToHex32(y), g1ToEip(step.newI), g1ToEip(step.newWIR)] as const;
    if (guard) {
      await (await st.guardedIssueUpdate!(...args, this.guardFor(guard.policy, guard.presentation))).wait();
    } else {
      await (await st.issueUpdate!(...args)).wait();
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

  /** members must be issued (the contract checks each one in storage); anyone may create a group */
  async createGroup(registryId: string, label: string, members: bigint[]): Promise<string> {
    const sorted = [...members].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const st = this.c('state');
    const args = [registryId, ethers.id(label), sorted.map(scalarToHex32)] as const;
    const groupId: string = await st.createGroup!.staticCall(...args);
    await (await st.createGroup!(...args)).wait();
    return groupId;
  }

  /** compiles the query into the presented and public programs; the contract classifies them */
  async registerPolicy(query: string, bindings: [string, Binding][], bindTo?: keyof typeof ACTION): Promise<PolicyRef> {
    const programs = compileGuard(parse(query), bindings);
    const pol = this.c('policies');
    const args = [query, chainBindings(bindings), programs.presented, programs.public] as const;
    const policyId: string = await pol.registerPolicy!.staticCall(...args);
    await (await pol.registerPolicy!(...args)).wait();
    if (bindTo) await (await pol.bindPolicy!(this.credDefId, ACTION[bindTo], policyId)).wait();
    return { policyId, query, bindings, programs };
  }

  /**
   * The guard for a presentation of the policy's query: the proof bytes, and in binding order the
   * expected versions. The contract compares only the registries the presented clauses refer to, and
   * only for a co-stable or volatile presented part; every other entry is 0.
   */
  guardFor(policy: PolicyRef, p: Presentation): Guard {
    const compared = presentedNeedsVersions(policy.programs) ? presentedBindings(policy.programs) : new Set<number>();
    const expectedVersions = policy.bindings.map(([name, b], i) => {
      if (!compared.has(i) || b.kind !== 'registry') return 0n;
      const v = p.versions[b.registryId];
      if (v === undefined) throw new Error(`the presentation is not bound to a version of ${name}`);
      return BigInt(v);
    });
    return { policyId: policy.policyId, expectedVersions, proof: encodeGuardProof(p) };
  }

  /**
   * A guarded revocation on request: the requester sends its revocation ID and a presentation of the
   * policy's query. The issuer verifies it off-chain (verify on read for the guard) and submits the
   * update with the proof; the contract evaluates the public part and compares versions for the
   * presented part, and the proof lands on the ledger.
   */
  async guardedRevoke(registryId: string, y: bigint, policy: PolicyRef, p: Presentation): Promise<ethers.TransactionReceipt> {
    if (p.query !== policy.query) throw new Error('guard proof rejected: it presents another query');
    const ctx = await loadContext(this.d, policy.bindings, Object.keys(p.versions));
    const v = verifyPresentation(parse(policy.query), p, ctx);
    if (!v.ok) throw new Error(`guard proof rejected: ${v.reason}`);
    const h = await readHistory(this.d, registryId);
    return (await this.c('state').guardedRevoke!(...this.revokeArgs(registryId, h, y), this.guardFor(policy, p))).wait();
  }

  aggregate(registryId: string, A: G1Point, members: bigint[]): G1Point {
    return acc.aggregateReceiptWithTrapdoor(this.secrets.get(registryId)!, A, members);
  }
}

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

  /**
   * The proof of the guarded update that created `version` of the registry, read back from the ledger
   * and checked against the policy it names, at the versions it was bound to.
   */
  async verifyGuardProof(registryId: string, version: number): Promise<{ ok: boolean; reason?: string; policyId?: string }> {
    try {
      const g = await readGuardProof(this.d, registryId, version);
      const policy = await readPolicy(this.d, g.policyId);
      if (g.presentation.query !== policy.query) return { ok: false, policyId: g.policyId, reason: 'the proof presents another query' };
      const ctx = await loadContext(this.d, policy.bindings, Object.keys(g.presentation.versions));
      const v = verifyPresentation(parse(policy.query), g.presentation, ctx);
      return { ok: v.ok, policyId: g.policyId, ...(v.reason ? { reason: v.reason } : {}) };
    } catch (e) {
      return { ok: false, reason: (e as Error).message };
    }
  }
}
