// A small sigma-protocol framework: linear relations over G1/G2, composed by AND and by threshold
// (CDS; OR is threshold 1), made non-interactive with one Fiat–Shamir challenge for the whole tree.
//
// Leaf: a set of relations lhs = Σ v_j · base_j over named secret variables (shared inside the leaf),
// plus extra public checks (pairings, non-identity) that are not part of the sigma protocol.
// Leaves never share variables: credentials are linked through public Pedersen commitments, so any
// leaf can be simulated on its own and placed under OR / threshold.
import { type Point, type G1Point, type G2Point, G1, G2, mod, mul, randomScalar, inv, pointToHex, isG1, R } from './bls.ts';
import { keccak256, toUtf8Bytes } from 'ethers';

export interface Term { base: Point; v: string }
export interface Relation { lhs: Point; terms: Term[] }

export interface Leaf {
  kind: 'leaf';
  label: string;
  rels: Relation[];
  /** public points that must be bound in the transcript besides lhs (e.g. blinded receipts) */
  publics: Point[];
  /** extra checks on public data, run by the verifier */
  check: () => boolean;
}
export interface And { kind: 'and'; children: Node[] }
export interface Thr { kind: 'thr'; k: number; children: Node[] }
export type Node = Leaf | And | Thr;

export type Witness = Map<string, bigint>;
/** prover-side: which leaves are true and their witnesses */
export type Witnesses = Map<Leaf, Witness>;

export interface LeafProof { T: string[]; z: Record<string, string> }
export interface NodeProof { c: string; leaf?: LeafProof; children?: NodeProof[] }

const vars = (leaf: Leaf): string[] => [...new Set(leaf.rels.flatMap((r) => r.terms.map((t) => t.v)))];

function evalRel(rel: Relation, z: Map<string, bigint>): Point {
  let acc: Point = isG1(rel.lhs) ? G1.ZERO : G2.ZERO;
  for (const t of rel.terms) acc = (acc as any).add(mul(t.base as any, z.get(t.v)!));
  return acc;
}

// ---- truth (which subtrees the prover can prove for real) ----
export function canProve(node: Node, w: Witnesses): boolean {
  switch (node.kind) {
    case 'leaf': return w.has(node);
    case 'and': return node.children.every((c) => canProve(c, w));
    case 'thr': return node.children.filter((c) => canProve(c, w)).length >= node.k;
  }
}

// ---- prover ----
interface PState {
  node: Node;
  simulated: boolean;
  c?: bigint;                 // fixed early for simulated nodes
  k?: Map<string, bigint>;    // blinders (real leaves)
  z?: Map<string, bigint>;    // responses (simulated leaves)
  T?: Point[];
  children?: PState[];
}

function simulate(node: Node, c: bigint): PState {
  if (node.kind === 'leaf') {
    const z = new Map(vars(node).map((v) => [v, randomScalar()] as const));
    const T = node.rels.map((rel) => (evalRel(rel, z) as any).subtract(mul(rel.lhs as any, c)));
    return { node, simulated: true, c, z, T };
  }
  if (node.kind === 'and') return { node, simulated: true, c, children: node.children.map((ch) => simulate(ch, c)) };
  const cs = thresholdShares(c, node.children.length, node.k, new Map());
  return { node, simulated: true, c, children: node.children.map((ch, i) => simulate(ch, cs[i]!)) };
}

function commit(node: Node, w: Witnesses): PState {
  if (node.kind === 'leaf') {
    const k = new Map(vars(node).map((v) => [v, randomScalar()] as const));
    return { node, simulated: false, k, T: node.rels.map((rel) => evalRel(rel, k)) };
  }
  if (node.kind === 'and') return { node, simulated: false, children: node.children.map((ch) => commit(ch, w)) };
  // threshold: pick k provable children (the first ones), simulate the others with random challenges
  const real = new Set<number>();
  node.children.forEach((ch, i) => { if (real.size < node.k && canProve(ch, w)) real.add(i); });
  if (real.size < node.k) throw new Error('threshold not satisfiable with the given witnesses');
  return {
    node, simulated: false,
    children: node.children.map((ch, i) => (real.has(i) ? commit(ch, w) : simulate(ch, randomScalar()))),
  };
}

function respond(st: PState, c: bigint, w: Witnesses): NodeProof {
  const node = st.node;
  if (st.simulated) return finishSimulated(st);
  if (node.kind === 'leaf') {
    const wit = w.get(node)!;
    const z: Record<string, string> = {};
    for (const [v, k] of st.k!) {
      const x = wit.get(v);
      if (x === undefined) throw new Error(`missing witness ${v} in ${node.label}`);
      z[v] = mod(k + c * x).toString(16);
    }
    return { c: c.toString(16), leaf: { T: st.T!.map(pointToHex), z } };
  }
  if (node.kind === 'and') return { c: c.toString(16), children: st.children!.map((ch) => respond(ch, c, w)) };
  // threshold: challenges of simulated children are fixed; interpolate the real ones
  const fixed = new Map<number, bigint>();
  st.children!.forEach((ch, i) => { if (ch.simulated) fixed.set(i, ch.c!); });
  const cs = thresholdShares(c, node.children.length, node.k, fixed);
  return { c: c.toString(16), children: st.children!.map((ch, i) => respond(ch, cs[i]!, w)) };
}

function finishSimulated(st: PState): NodeProof {
  const c = st.c!;
  if (st.node.kind === 'leaf') {
    const z: Record<string, string> = {};
    for (const [v, x] of st.z!) z[v] = x.toString(16);
    return { c: c.toString(16), leaf: { T: st.T!.map(pointToHex), z } };
  }
  return { c: c.toString(16), children: st.children!.map(finishSimulated) };
}

function collectCommitments(st: PState, out: Point[]): void {
  if (st.T) out.push(...st.T);
  st.children?.forEach((ch) => collectCommitments(ch, out));
}

function collectPublics(node: Node, out: Point[]): void {
  if (node.kind === 'leaf') {
    for (const r of node.rels) out.push(r.lhs);
    out.push(...node.publics);
  } else node.children.forEach((ch) => collectPublics(ch, out));
}

/** c = H(context ‖ every public point ‖ every commitment) mod r */
export function challenge(context: string, publics: Point[], commitments: (Point | string)[]): bigint {
  const parts = [context, ...publics.map(pointToHex), ...commitments.map((p) => (typeof p === 'string' ? p : pointToHex(p)))];
  return mod(BigInt(keccak256(toUtf8Bytes(parts.join('|')))));
}

export function prove(root: Node, w: Witnesses, context: string): NodeProof {
  if (!canProve(root, w)) throw new Error('statement not provable with the given witnesses');
  const st = commit(root, w);
  const publics: Point[] = [];
  collectPublics(root, publics);
  const Ts: Point[] = [];
  collectCommitments(st, Ts);
  const c = challenge(context, publics, Ts);
  return respond(st, c, w);
}

// ---- verifier ----
function verifyNode(node: Node, p: NodeProof, c: bigint, Ts: string[]): boolean {
  if (BigInt('0x' + p.c) !== c) return false;
  if (node.kind === 'leaf') {
    if (!p.leaf || p.leaf.T.length !== node.rels.length) return false;
    if (!node.check()) return false;
    const z = new Map<string, bigint>();
    for (const v of vars(node)) {
      const s = p.leaf.z[v];
      if (s === undefined) return false;
      z.set(v, mod(BigInt('0x' + s)));
    }
    return node.rels.every((rel, i) => {
      const Thex = p.leaf!.T[i]!;
      Ts.push(Thex);
      const T = isG1(rel.lhs) ? G1.fromHex(Thex) : G2.fromHex(Thex);
      return (evalRel(rel, z) as any).equals((T as any).add(mul(rel.lhs as any, c)));
    });
  }
  if (!p.children || p.children.length !== node.children.length) return false;
  if (node.kind === 'and') return node.children.every((ch, i) => verifyNode(ch, p.children![i]!, c, Ts));
  const cs = p.children.map((ch) => mod(BigInt('0x' + ch.c)));
  if (!sharesConsistent(c, cs, node.k)) return false;
  return node.children.every((ch, i) => verifyNode(ch, p.children![i]!, cs[i]!, Ts));
}

export function verify(root: Node, proof: NodeProof, context: string): boolean {
  const Ts: string[] = [];
  const c = mod(BigInt('0x' + proof.c));
  if (!verifyNode(root, proof, c, Ts)) return false;
  const publics: Point[] = [];
  collectPublics(root, publics);
  return challenge(context, publics, Ts) === c;
}

export function proofSize(p: NodeProof): number {
  let n = 32; // challenge
  if (p.leaf) n += p.leaf.T.reduce((a, t) => a + t.length / 2, 0) + Object.keys(p.leaf.z).length * 32;
  p.children?.forEach((ch) => { n += proofSize(ch); });
  return n;
}

// ---- threshold challenge shares (CDS) ----
// Children i = 1..n get challenges f(i) for a polynomial f of degree n−k with f(0) = c.
// The prover fixes the n−k simulated challenges first; f is then determined.

function lagrangeAt(xs: bigint[], ys: bigint[], x: bigint): bigint {
  let acc = 0n;
  for (let i = 0; i < xs.length; i++) {
    let num = 1n, den = 1n;
    for (let j = 0; j < xs.length; j++) {
      if (j === i) continue;
      num = mod(num * (x - xs[j]!));
      den = mod(den * (xs[i]! - xs[j]!));
    }
    acc = mod(acc + ys[i]! * num * inv(den));
  }
  return acc;
}

function thresholdShares(c: bigint, n: number, k: number, fixed: Map<number, bigint>): bigint[] {
  const deg = n - k;
  const xs = [0n];
  const ys = [c];
  for (const [i, ci] of fixed) { xs.push(BigInt(i + 1)); ys.push(ci); }
  // pad with random points if fewer than deg are fixed (used when simulating a whole threshold node)
  for (let i = 0; xs.length < deg + 1 && i < n; i++) {
    if (!fixed.has(i)) { xs.push(BigInt(i + 1)); ys.push(randomScalar()); }
  }
  if (xs.length !== deg + 1) throw new Error(`threshold shares: ${xs.length - 1} fixed, need ${deg}`);
  return Array.from({ length: n }, (_, i) => lagrangeAt(xs, ys, BigInt(i + 1)));
}

function sharesConsistent(c: bigint, cs: bigint[], k: number): boolean {
  const n = cs.length;
  const deg = n - k;
  const xs = [0n, ...Array.from({ length: deg }, (_, i) => BigInt(i + 1))];
  const ys = [c, ...cs.slice(0, deg)];
  return cs.every((ci, i) => lagrangeAt(xs, ys, BigInt(i + 1)) === ci);
}

export { R };
export type { G1Point, G2Point };
