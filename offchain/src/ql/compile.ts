// Compiler from a closed query to a sigma tree, run identically by the prover and the verifier.
//
// Materialisation (dashboard 1.5, 2.7):
//  - a quantifier over Presented, or over a group / Issued with a credential atom (Sig, SameHolder)
//    on its variable, is *holder-bound*: the holder presents credentials for it and proves the body
//    in zero knowledge (only ∃ and at least k; ∀ and at most k over holder-chosen sets are rejected);
//  - every other quantifier is about public registry data and is evaluated publicly against the
//    bound registry version (groups: the public member list and revocation log; Issued: the
//    whole-registry checks on A, R̃, I, or the issued and revoked counts), optionally with an
//    aggregate receipt as evidence.
// Constants are folded, AND becomes one challenge, OR becomes a CDS threshold of 1.
import type { Formula, Domain } from './ast.ts';
import { pretty } from './ast.ts';
import { normalise, wellFormed, classify, casMode, type FormulaClass, type CasMode } from './logic.ts';
import { holds, type Env } from './semantics.ts';
import * as S from '../crypto/sigma.ts';
import * as L from '../crypto/leaves.ts';
import * as acc from '../crypto/accumulator.ts';
import type * as bbs from '../crypto/bbs.ts';
import { g1FromHex, g1ToHex, type G1Point, mod } from '../crypto/bls.ts';
import {
  type RegistryHistory, revokedUpTo, issuedCountAt, refreshAto, revokedReceiptAt, valuesHashAt,
} from '../registry/history.ts';

// ---------------------------------------------------------------- public context

export type Binding =
  | { kind: 'group'; groupId: string; registryId: string; members: bigint[] }
  | { kind: 'registry'; registryId: string }
  | { kind: 'creddef'; credDefId: string };

export interface PublicContext {
  registries: Map<string, RegistryHistory>;
  bindings: Map<string, Binding>;
}

export interface WalletCredential {
  credDefId: string;
  registryId: string;
  header: Uint8Array;
  scalars: bigint[];
  sig: bbs.BbsSignature;
  yIndex: number;
  lsIndex?: number;
  disclose: number[];
  /** receipt against A, valid at version receiptVersion */
  receiptA: G1Point;
  receiptVersion: number;
}

export interface PresentedCredential {
  credDefId: string;
  registryId: string;
  header: string;
  yIndex: number;
  lsIndex?: number;
  bbs: L.BbsLeafPublic;
}

export interface Presentation {
  query: string;
  nonce: string;
  /** registryId -> bound version */
  versions: Record<string, number>;
  credentials: PresentedCredential[];
  /** quantifier path -> indices into credentials */
  instances: Record<string, number[]>;
  /** public values of the ZK leaves, in compile order */
  leaves: (L.AccLeafPublic | L.RevLeafPublic)[];
  /** aggregate receipts for ∀x∈S.NotRevoked(x) over public groups, by group name */
  evidence: Record<string, string>;
  proof: S.NodeProof | null;
}

export interface Analysis {
  normalised: Formula;
  class: FormulaClass;
  cas: CasMode;
}

export class CompileError extends Error {}

export function analyse(query: Formula): Analysis {
  const errs = wellFormed(query);
  if (errs.length) throw new CompileError(errs.join('; '));
  return { normalised: normalise(query), class: classify(query), cas: casMode(query) };
}

// ---------------------------------------------------------------- shared traversal

type Built = S.Node | boolean;

interface Scope {
  /** variable -> credential index */
  creds: Map<string, number>;
}

interface Mode {
  prover: boolean;
  ctx: PublicContext;
  versions: Record<string, number>;
  credentials: PresentedCredential[];
  instances: Record<string, number[]>;
  leaves: (L.AccLeafPublic | L.RevLeafPublic)[];
  leafCursor: number;
  evidence: Record<string, string>;
  // prover only
  wallet?: WalletCredential[];
  walletIndexOf?: Map<number, number>;  // presented index -> wallet index
  openings?: Map<number, { y: L.Opening; ls?: L.Opening }>;
  witnesses?: S.Witnesses;
  aggregates?: Record<string, G1Point>;
  topLeaves: S.Node[];
}

const isHolderBound = (f: Extract<Formula, { t: 'quant' }>): boolean =>
  f.dom.kind === 'presented' || mentionsCredAtom(f.body, f.v);

function mentionsCredAtom(f: Formula, v: string): boolean {
  switch (f.t) {
    case 'atom': return (f.name === 'Sig' || f.name === 'SameHolder') && f.args.includes(v);
    case 'not': return mentionsCredAtom(f.f, v);
    case 'and': case 'or': return f.fs.some((g) => mentionsCredAtom(g, v));
    case 'quant': return mentionsCredAtom(f.body, v);
    default: return false;
  }
}

function freeCredVars(f: Formula, scope: Scope): boolean {
  switch (f.t) {
    case 'atom': return f.args.some((a) => scope.creds.has(a));
    case 'not': return freeCredVars(f.f, scope);
    case 'and': case 'or': return f.fs.some((g) => freeCredVars(g, scope));
    case 'quant': return freeCredVars(f.body, scope);
    default: return false;
  }
}

function andOf(parts: Built[]): Built {
  if (parts.some((p) => p === false)) return false;
  const nodes = parts.filter((p): p is S.Node => p !== true);
  return nodes.length === 0 ? true : nodes.length === 1 ? nodes[0]! : { kind: 'and', children: nodes };
}

function orOf(parts: Built[]): Built {
  if (parts.some((p) => p === true)) return true;
  const nodes = parts.filter((p): p is S.Node => p !== false);
  return nodes.length === 0 ? false : nodes.length === 1 ? nodes[0]! : { kind: 'thr', k: 1, children: nodes };
}

function registryOf(m: Mode, id: string): RegistryHistory {
  const h = m.ctx.registries.get(id);
  if (!h) throw new CompileError(`unknown registry ${id}`);
  if (m.versions[id] === undefined) {
    if (!m.prover) throw new CompileError(`no bound version for registry ${id}`);
    m.versions[id] = h.values.length - 1;
  }
  return h;
}

const versionOf = (m: Mode, id: string): number => m.versions[id]!;

function binding(m: Mode, name: string): Binding {
  const b = m.ctx.bindings.get(name);
  if (!b) throw new CompileError(`unbound name ${name}`);
  return b;
}

// ---- public evaluation of closed registry subformulas

function publicEval(f: Formula, m: Mode): boolean {
  const env: Env = {
    state: { iss: new Set(), rev: new Set() },
    states: new Map(), groups: new Map(), presented: [],
  };
  // group domains: the members are issued; the revocation set is the one at the bound version
  const evalNode = (g: Formula, asg: Map<string, bigint>, reg?: RegistryHistory): boolean => {
    switch (g.t) {
      case 'const': return g.v;
      case 'not': return !evalNode(g.f, asg, reg);
      case 'and': return g.fs.every((h) => evalNode(h, asg, reg));
      case 'or': return g.fs.some((h) => evalNode(h, asg, reg));
      case 'atom': {
        const y = asg.get(g.args[0]!)!;
        const r = regOfVar.get(g.args[0]!)!;
        const rev = revokedUpTo(r, versionOf(m, r.registryId));
        if (g.name === 'Revoked') return rev.has(y);
        if (g.name === 'NotRevoked') return !rev.has(y);
        throw new CompileError(`${g.name} needs a holder-bound variable`);
      }
      case 'quant': {
        if (g.dom.kind === 'issued') return issuedCheck(g, m);
        if (g.dom.kind !== 'group') throw new CompileError('Presented inside a public subformula');
        const b = binding(m, g.dom.name);
        if (b.kind !== 'group') throw new CompileError(`${g.dom.name} is not a group`);
        const h = registryOf(m, b.registryId);
        regOfVar.set(g.v, h);
        const count = b.members.filter((y) => evalNode(g.body, new Map([...asg, [g.v, y]]), h)).length;
        const n = b.members.length;
        switch (g.q) {
          case 'forall': return count === n;
          case 'exists': return count >= 1;
          case 'atleast': return count >= g.k;
          case 'atmost': return count <= g.k;
        }
      }
      default: throw new CompileError(`cannot evaluate ${g.t}`);
    }
  };
  const regOfVar = new Map<string, RegistryHistory>();
  void env; void holds;
  return evalNode(f, new Map());
}

/** whole-registry checks: quantifiers over Issued with a single registry atom as body */
function issuedCheck(g: Extract<Formula, { t: 'quant' }>, m: Mode): boolean {
  const b = binding(m, (g.dom as Extract<Domain, { kind: 'issued' }>).name);
  if (b.kind !== 'registry') throw new CompileError('Issued must be bound to a registry');
  const h = registryOf(m, b.registryId);
  const v = h.values[versionOf(m, b.registryId)]!;
  // issuance reveals y, so the counts are public (the contract counts the same way)
  const nIss = issuedCountAt(h, versionOf(m, b.registryId));
  const nRev = revokedUpTo(h, versionOf(m, b.registryId)).size;
  const body = g.body;
  if (body.t !== 'atom' || body.args[0] !== g.v) throw new CompileError(`unsupported shape over Issued: ${pretty(g)}`);
  const allRevoked = acc.allIssuedRevoked(v);
  const noneRevoked = acc.noneRevoked(v, h.pub);
  switch (`${g.q}/${body.name}`) {
    case 'forall/Revoked': return allRevoked;
    case 'exists/NotRevoked': return !allRevoked;
    case 'exists/Revoked': return !noneRevoked;
    case 'forall/NotRevoked': return noneRevoked;
    case 'atleast/Revoked': return nRev >= g.k;
    case 'atmost/Revoked': return nRev <= g.k;
    case 'atleast/NotRevoked': return nIss - nRev >= g.k;
    case 'atmost/NotRevoked': return nIss - nRev <= g.k;
    default: throw new CompileError(`unsupported shape over Issued: ${pretty(g)}`);
  }
}

// ---- evidence: aggregate receipt for ∀x∈S. NotRevoked(x)

function attachEvidence(f: Formula, m: Mode, truth: boolean): boolean {
  if (f.t !== 'quant' || f.q !== 'forall' || f.dom.kind !== 'group') return truth;
  if (f.body.t !== 'atom' || f.body.name !== 'NotRevoked') return truth;
  const name = f.dom.name;
  const b = binding(m, name);
  if (b.kind !== 'group') return truth;
  const h = registryOf(m, b.registryId);
  const A = h.values[versionOf(m, b.registryId)]!.A;
  if (m.prover) {
    const W = m.aggregates?.[name];
    if (W && truth) m.evidence[name] = g1ToHex(W);
    return truth;
  }
  const Wh = m.evidence[name];
  if (Wh === undefined || !h.srs) return truth;
  // the evidence must agree with the public evaluation
  return acc.verifyAggregate(A, g1FromHex(Wh), b.members, h.srs) && truth;
}

// ---- the traversal

function build(f: Formula, m: Mode, scope: Scope, path: string): Built {
  switch (f.t) {
    case 'const': return f.v;
    case 'and': return andOf(f.fs.map((g, i) => build(g, m, scope, `${path}.${i}`)));
    case 'or': {
      const parts = f.fs.map((g, i) => {
        if (containsHolderBound(g)) throw new CompileError('a holder-bound quantifier under a disjunction is not supported');
        return build(g, m, scope, `${path}.${i}`);
      });
      return orOf(parts);
    }
    case 'not': return !atomConst(f.f, m, scope);
    case 'atom': return atomNode(f, m, scope);
    case 'implies': throw new CompileError('normalise first');
    case 'quant': {
      if (!isHolderBound(f)) {
        if (freeCredVars(f.body, scope)) throw new CompileError(`public quantifier over ${f.v} refers to a presented credential`);
        return attachEvidence(f, m, publicEval(f, m));
      }
      return holderBound(f, m, scope, path);
    }
  }
}

function containsHolderBound(f: Formula): boolean {
  switch (f.t) {
    case 'quant': return isHolderBound(f) || containsHolderBound(f.body);
    case 'not': return containsHolderBound(f.f);
    case 'and': case 'or': return f.fs.some(containsHolderBound);
    default: return false;
  }
}

/** Sig and the negations the NNF leaves (¬Sig) are public facts about a presented credential */
function atomConst(f: Formula, m: Mode, scope: Scope): boolean {
  if (f.t !== 'atom' || f.name !== 'Sig') throw new CompileError(`cannot negate ${pretty(f)}`);
  const c = m.credentials[scope.creds.get(f.args[0]!)!]!;
  const b = binding(m, f.args[1]!);
  if (b.kind === 'creddef') return c.credDefId === b.credDefId;
  if (b.kind === 'registry') return c.registryId === b.registryId;
  throw new CompileError(`${f.args[1]} is not a CredDef or registry`);
}

function nextLeaf<T>(m: Mode): T {
  const x = m.leaves[m.leafCursor++];
  if (x === undefined) throw new CompileError('presentation has too few leaves');
  return x as T;
}

function atomNode(f: Extract<Formula, { t: 'atom' }>, m: Mode, scope: Scope): Built {
  const ci = scope.creds.get(f.args[0]!);
  if (ci === undefined) throw new CompileError(`${f.args[0]} is not bound to a presented credential`);
  const cred = m.credentials[ci]!;
  switch (f.name) {
    case 'Sig': return atomConst(f, m, scope);
    case 'SameHolder': return sameHolderNode(f, m, scope);
    case 'NotRevoked': case 'Revoked': {
      const h = registryOf(m, cred.registryId);
      const v = versionOf(m, cred.registryId);
      const vals = h.values[v]!;
      const K = g1FromHex(cred.bbs.K);
      if (f.name === 'NotRevoked') {
        let pub: L.AccLeafPublic;
        if (m.prover) {
          const w = m.wallet![m.walletIndexOf!.get(ci)!]!;
          const o = m.openings!.get(ci)!.y;
          const revoked = revokedUpTo(h, v).has(o.value);
          if (!revoked) {
            const C = refreshAto(h, o.value, w.receiptA, w.receiptVersion, v);
            const r = L.accLeafProver('R-ATOM-NOTREVOKED', vals.A, h.pub.Qtilde, K, o, C);
            m.leaves.push(r.pub); m.witnesses!.set(r.leaf, r.wit);
            return r.leaf;
          }
          pub = L.fakeAccLeafPublic(h.pub.Q);
          m.leaves.push(pub);
        } else pub = nextLeaf(m);
        return L.accLeafVerifier('R-ATOM-NOTREVOKED', vals.A, h.pub.Qtilde, K, pub);
      }
      let pub: L.RevLeafPublic;
      if (m.prover) {
        const o = m.openings!.get(ci)!.y;
        const Ct = revokedReceiptAt(h, o.value, v);
        if (Ct) {
          const r = L.revLeafProver(vals.Rtilde, h.pub.Q, K, o, Ct);
          m.leaves.push(r.pub); m.witnesses!.set(r.leaf, r.wit);
          return r.leaf;
        }
        pub = L.fakeRevLeafPublic(h.pub.Qtilde);
        m.leaves.push(pub);
      } else pub = nextLeaf(m);
      return L.revLeafVerifier(vals.Rtilde, h.pub.Q, K, pub);
    }
    default: throw new CompileError(`unexpected atom ${f.name}`);
  }
}

function sameHolderNode(f: Extract<Formula, { t: 'atom' }>, m: Mode, scope: Scope): Built {
  const [a, b] = [scope.creds.get(f.args[0]!)!, scope.creds.get(f.args[1]!)!];
  const ca = m.credentials[a]!, cb = m.credentials[b]!;
  if (!ca.bbs.Kls || !cb.bbs.Kls) throw new CompileError('SameHolder needs holder-bound credentials (link secret)');
  const Ka = g1FromHex(ca.bbs.Kls), Kb = g1FromHex(cb.bbs.Kls);
  if (m.prover) {
    const oa = m.openings!.get(a)!.ls!, ob = m.openings!.get(b)!.ls!;
    if (mod(oa.value - ob.value) === 0n) {
      const r = L.sameHolderLeafProver(Ka, Kb, oa, ob);
      m.witnesses!.set(r.leaf, r.wit);
      return r.leaf;
    }
  }
  return L.sameHolderLeafVerifier(Ka, Kb);
}

function holderBound(f: Extract<Formula, { t: 'quant' }>, m: Mode, scope: Scope, path: string): Built {
  if (f.q === 'forall' || f.q === 'atmost') {
    throw new CompileError(`${f.q} over holder-chosen credentials is not meaningful (${pretty(f)})`);
  }
  const n = f.q === 'exists' ? 1 : f.k;
  if (n === 0) return true;
  const key = path;
  let picks: number[];
  if (m.prover) {
    picks = chooseCredentials(f, m, scope, n);
    m.instances[key] = picks;
  } else {
    picks = m.instances[key] ?? [];
    if (picks.length !== n) throw new CompileError(`quantifier ${key} needs ${n} credential(s)`);
  }
  const parts: Built[] = [];
  // pairwise distinct revocation IDs
  for (let i = 0; i < picks.length; i++) {
    for (let j = i + 1; j < picks.length; j++) parts.push(distinctNode(picks[i]!, picks[j]!, m));
  }
  // distinct from enclosing holder-bound variables over the same kind of domain
  for (const [, ci] of scope.creds) for (const p of picks) if (ci !== p) parts.push(distinctNode(ci, p, m)); else return false;
  for (const p of picks) {
    parts.push(domainMembership(f.dom, p, m));
    const inner: Scope = { creds: new Map([...scope.creds, [f.v, p]]) };
    parts.push(build(f.body, m, inner, `${path}/${f.v}`));
  }
  return andOf(parts);
}

function distinctNode(i: number, j: number, m: Mode): Built {
  const Ki = g1FromHex(m.credentials[i]!.bbs.K), Kj = g1FromHex(m.credentials[j]!.bbs.K);
  if (m.prover) {
    const oi = m.openings!.get(i)!.y, oj = m.openings!.get(j)!.y;
    const r = L.neqLeafProver(Ki, Kj, oi, oj);
    m.witnesses!.set(r.leaf, r.wit);
    return r.leaf;
  }
  return L.neqLeafVerifier(Ki, Kj);
}

/** a presented credential must belong to the quantifier's domain */
function domainMembership(d: Domain, ci: number, m: Mode): Built {
  const cred = m.credentials[ci]!;
  if (d.kind === 'presented') return true;
  if (d.kind === 'issued') {
    const b = binding(m, d.name);
    if (b.kind !== 'registry' || b.registryId !== cred.registryId) return false;
    return true; // signed by the issuer of this registry's CredDef, hence issued
  }
  const b = binding(m, d.name);
  if (b.kind !== 'group' || b.registryId !== cred.registryId) return false;
  const h = registryOf(m, b.registryId);
  if (!h.srs) throw new CompileError('group membership proofs need the SRS');
  const accS = acc.groupAccumulator(b.members, h.srs);
  const K = g1FromHex(cred.bbs.K);
  let pub: L.AccLeafPublic;
  if (m.prover) {
    const o = m.openings!.get(ci)!.y;
    if (b.members.some((s) => mod(s - o.value) === 0n)) {
      const D = acc.groupMemberReceipt(b.members, o.value, h.srs);
      const r = L.accLeafProver('R-EXISTS-MEMBER', accS, h.pub.Qtilde, K, o, D);
      m.leaves.push(r.pub); m.witnesses!.set(r.leaf, r.wit);
      return r.leaf;
    }
    pub = L.fakeAccLeafPublic(h.pub.Q);
    m.leaves.push(pub);
  } else pub = nextLeaf(m);
  return L.accLeafVerifier('R-EXISTS-MEMBER', accS, h.pub.Qtilde, K, pub);
}

// ---- the holder's witness search (the "constraint solver" in front of the compiler)

function chooseCredentials(f: Extract<Formula, { t: 'quant' }>, m: Mode, scope: Scope, n: number): number[] {
  const wallet = m.wallet!;
  const chosen: number[] = [];
  for (let wi = 0; wi < wallet.length && chosen.length < n; wi++) {
    if ([...scope.creds.values()].some((ci) => m.walletIndexOf!.get(ci) === wi)) continue;
    if ([...chosen].some((ci) => m.walletIndexOf!.get(ci) === wi)) continue;
    // try the candidate under a provisional index; only a chosen credential is presented
    const w = wallet[wi]!;
    const stub = m.credentials.length;
    m.credentials.push({ credDefId: w.credDefId, registryId: w.registryId, header: '', yIndex: w.yIndex, bbs: {} as L.BbsLeafPublic });
    m.walletIndexOf!.set(stub, wi);
    let ok = false;
    try { ok = holderTruth(f, m, scope, stub); } finally { m.credentials.pop(); m.walletIndexOf!.delete(stub); }
    if (ok) chosen.push(presentCredential(m, wi));
  }
  if (chosen.length < n) throw new CompileError(`the wallet has fewer than ${n} credential(s) satisfying ${pretty(f)}`);
  return chosen;
}

function presentCredential(m: Mode, wi: number): number {
  for (const [ci, w] of m.walletIndexOf!) if (w === wi) return ci;
  const w = m.wallet![wi]!;
  const h = registryOf(m, w.credDefId === '' ? w.registryId : w.registryId);
  const spec = { pk: h.issuerPk, header: w.header, yIndex: w.yIndex, ...(w.lsIndex !== undefined ? { lsIndex: w.lsIndex } : {}) };
  const yOpen = L.newOpening(w.scalars[w.yIndex]!);
  const lsOpen = w.lsIndex !== undefined ? L.newOpening(w.scalars[w.lsIndex]!) : undefined;
  const r = L.bbsLeafProver(spec, w.sig, w.scalars, w.disclose, yOpen, lsOpen);
  const ci = m.credentials.length;
  m.credentials.push({
    credDefId: w.credDefId, registryId: w.registryId, header: Buffer.from(w.header).toString('hex'),
    yIndex: w.yIndex, ...(w.lsIndex !== undefined ? { lsIndex: w.lsIndex } : {}), bbs: r.pub,
  });
  m.walletIndexOf!.set(ci, wi);
  m.openings!.set(ci, { y: yOpen, ...(lsOpen ? { ls: lsOpen } : {}) });
  m.witnesses!.set(r.leaf, r.wit);
  m.topLeaves.push(r.leaf);
  return ci;
}

/** does the body hold for this candidate? (the holder knows its own IDs) */
function holderTruth(f: Extract<Formula, { t: 'quant' }>, m: Mode, scope: Scope, ci: number): boolean {
  const w = m.wallet![m.walletIndexOf!.get(ci)!]!;
  const h = registryOf(m, w.registryId);
  const y = w.scalars[w.yIndex]!;
  if (f.dom.kind === 'group') {
    const b = binding(m, f.dom.name);
    if (b.kind !== 'group' || b.registryId !== w.registryId || !b.members.includes(y)) return false;
  }
  if (f.dom.kind === 'issued') {
    const b = binding(m, f.dom.name);
    if (b.kind !== 'registry' || b.registryId !== w.registryId) return false;
  }
  const inner: Scope = { creds: new Map([...scope.creds, [f.v, ci]]) };
  const rev = revokedUpTo(h, versionOf(m, w.registryId));
  const truth = (g: Formula): boolean => {
    switch (g.t) {
      case 'const': return g.v;
      case 'not': return !atomConst(g.f, m, inner);
      case 'and': return g.fs.every(truth);
      case 'or': return g.fs.some(truth);
      case 'atom': {
        const c = inner.creds.get(g.args[0]!);
        if (c === undefined) return false;
        const wc = m.wallet![m.walletIndexOf!.get(c)!]!;
        const yc = wc.scalars[wc.yIndex]!;
        const revc = c === ci ? rev : revokedUpTo(registryOf(m, wc.registryId), versionOf(m, wc.registryId));
        switch (g.name) {
          case 'Revoked': return revc.has(yc);
          case 'NotRevoked': return !revc.has(yc);
          case 'Sig': return atomConst(g, m, inner);
          case 'SameHolder': {
            const d = inner.creds.get(g.args[1]!);
            if (d === undefined) return true; // decided when the other variable is chosen
            const wd = m.wallet![m.walletIndexOf!.get(d)!]!;
            return wc.lsIndex !== undefined && wd.lsIndex !== undefined && wc.scalars[wc.lsIndex] === wd.scalars[wd.lsIndex];
          }
        }
        return false;
      }
      case 'quant':
        // nested holder-bound quantifiers are searched when they are compiled; public ones are evaluated
        return isHolderBound(g) ? true : publicEval(g, m);
      default: return false;
    }
  };
  return truth(f.body);
}

// ---------------------------------------------------------------- entry points

function context(query: string, m: Pick<Mode, 'versions' | 'credentials' | 'instances' | 'leaves' | 'evidence' | 'ctx'>, nonce: string): string {
  const vh: Record<string, string> = {};
  for (const [id, v] of Object.entries(m.versions)) vh[id] = valuesHashAt(m.ctx.registries.get(id)!, v);
  const bindings = [...m.ctx.bindings].map(([n, b]) => [n, b.kind, 'groupId' in b ? b.groupId : 'registryId' in b ? b.registryId : b.credDefId]);
  return JSON.stringify({ query, nonce, bindings, versions: m.versions, vh, credentials: m.credentials, instances: m.instances, leaves: m.leaves, evidence: m.evidence });
}

export interface ProveOptions {
  /** registryId -> version to bind to (default: the latest) */
  versions?: Record<string, number>;
  aggregates?: Record<string, G1Point>;
}

export function present(query: Formula, queryText: string, ctx: PublicContext, wallet: WalletCredential[], nonce: string, opts: ProveOptions = {})
  : Presentation {
  const an = analyse(query);
  const m: Mode = {
    prover: true, ctx, versions: { ...(opts.versions ?? {}) }, credentials: [], instances: {}, leaves: [], leafCursor: 0,
    evidence: {}, wallet, walletIndexOf: new Map(), openings: new Map(), witnesses: new Map(),
    ...(opts.aggregates ? { aggregates: opts.aggregates } : {}), topLeaves: [],
  };
  // bind the registries the query names up front
  for (const b of ctx.bindings.values()) if (b.kind !== 'creddef') registryOf(m, b.registryId);
  const body = build(an.normalised, m, { creds: new Map() }, 'q');
  if (body === false) throw new CompileError('the query is false for this wallet and registry state');
  const root = andOf([...m.topLeaves, body]);
  const ctxStr = context(queryText, m, nonce);
  const proof = root === true ? null : S.prove(root as S.Node, m.witnesses!, ctxStr);
  return { query: queryText, nonce, versions: m.versions, credentials: m.credentials, instances: m.instances, leaves: m.leaves, evidence: m.evidence, proof };
}

export interface VerifyResult { ok: boolean; reason?: string; class: FormulaClass; cas: CasMode }

/** cryptographic and logical check of a presentation; freshness against the ledger is checked separately */
export function verifyPresentation(query: Formula, p: Presentation, ctx: PublicContext): VerifyResult {
  const an = analyse(query);
  const res = (ok: boolean, reason?: string): VerifyResult => ({ ok, class: an.class, cas: an.cas, ...(reason ? { reason } : {}) });
  try {
    const m: Mode = {
      prover: false, ctx, versions: p.versions, credentials: p.credentials, instances: p.instances, leaves: p.leaves, leafCursor: 0,
      evidence: p.evidence, topLeaves: [],
    };
    for (const b of ctx.bindings.values()) if (b.kind !== 'creddef') registryOf(m, b.registryId);
    const credLeaves = p.credentials.map((c) => {
      const h = registryOf(m, c.registryId);
      if (h.credDefId !== c.credDefId) throw new CompileError('credential registry does not belong to its CredDef');
      const spec = { pk: h.issuerPk, header: Buffer.from(c.header, 'hex'), yIndex: c.yIndex, ...(c.lsIndex !== undefined ? { lsIndex: c.lsIndex } : {}) };
      return L.bbsLeafVerifier(spec, c.bbs);
    });
    const body = build(an.normalised, m, { creds: new Map() }, 'q');
    if (m.leafCursor !== p.leaves.length) return res(false, 'unused leaves');
    if (body === false) return res(false, 'the query is false');
    const root = andOf([...credLeaves, body]);
    if (root === true) return res(true);
    if (!p.proof) return res(false, 'missing proof');
    const ok = S.verify(root as S.Node, p.proof, context(p.query, m, p.nonce));
    return res(ok, ok ? undefined : 'sigma proof does not verify');
  } catch (e) {
    return res(false, (e as Error).message);
  }
}

export { mod };
