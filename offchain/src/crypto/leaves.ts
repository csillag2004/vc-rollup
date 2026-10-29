// The sigma leaves the compiler uses. Each leaf has a prover side (makes the public values and
// the witness) and a verifier side (rebuilds the relations from the public values only).
// Credential variables are linked through Pedersen commitments K = g^y · h^t to the revocation ID y.
import {
  G1, G2, type G1Point, type G2Point, g1, g2, mul, inv, mod, randomScalar, hashToG1, pairingEq,
  g1ToHex, g2ToHex, g1FromHex, g2FromHex, utf8ToBytes,
} from './bls.ts';
import type { Leaf, Witness } from './sigma.ts';
import * as bbs from './bbs.ts';

/** second Pedersen generator, nothing-up-my-sleeve */
export const H = hashToG1(utf8ToBytes('revoq/pedersen/h'), 'revoq/pedersen');

export interface Opening { value: bigint; blind: bigint }
export const commit = (o: Opening): G1Point => mul(g1, o.value).add(mul(H, o.blind));
export const newOpening = (value: bigint): Opening => ({ value, blind: randomScalar() });

// ---------------------------------------------------------------- BBS credential

export interface BbsLeafPublic {
  Abar: string; Bbar: string; D: string;
  disclosed: Record<number, string>; // index -> scalar hex
  L: number;
  K: string;          // commitment to the revocation ID message
  Kls?: string;       // commitment to the link secret message
}

export interface BbsLeafSpec {
  pk: Uint8Array; header: Uint8Array;
  yIndex: number; lsIndex?: number;
}

/** Prove knowledge of a BBS signature whose message yIndex is the y inside K (and lsIndex inside Kls). */
export function bbsLeafProver(
  spec: BbsLeafSpec, sig: bbs.BbsSignature, scalars: bigint[], disclosedIdx: number[],
  yOpen: Opening, lsOpen?: Opening,
): { pub: BbsLeafPublic; leaf: Leaf; wit: Witness } {
  const r = randomScalar();
  const B = bbs.computeB(spec.pk, spec.header, scalars);
  const { Abar, D, Bbar } = bbs.randomise(sig, B, r);
  const disclosed: Record<number, string> = {};
  for (const i of disclosedIdx) disclosed[i] = scalars[i]!.toString(16);
  const pub: BbsLeafPublic = {
    Abar: g1ToHex(Abar), Bbar: g1ToHex(Bbar), D: g1ToHex(D), disclosed, L: scalars.length,
    K: g1ToHex(commit(yOpen)), ...(lsOpen ? { Kls: g1ToHex(commit(lsOpen)) } : {}),
  };
  const wit: Witness = new Map([['e', sig.e], ['rinv', inv(r)], ['ty', yOpen.blind]]);
  scalars.forEach((m, i) => { if (!disclosedIdx.includes(i)) wit.set(`m${i}`, m); });
  if (lsOpen) wit.set('tls', lsOpen.blind);
  return { pub, leaf: bbsLeafVerifier(spec, pub), wit };
}

export function bbsLeafVerifier(spec: BbsLeafSpec, pub: BbsLeafPublic): Leaf {
  const Abar = g1FromHex(pub.Abar), Bbar = g1FromHex(pub.Bbar), D = g1FromHex(pub.D);
  const disclosed = new Map(Object.entries(pub.disclosed).map(([i, m]) => [Number(i), BigInt('0x' + m)] as const));
  const Bpub = bbs.publicB(spec.pk, spec.header, pub.L, disclosed);
  const hidden = [...Array(pub.L).keys()].filter((i) => !disclosed.has(i));
  if (!hidden.includes(spec.yIndex)) throw new Error('the revocation ID must stay hidden');
  const W = bbs.publicKeyPoint(spec.pk);
  const rels = [
    // D − B̄ = e·Ā
    { lhs: D.subtract(Bbar), terms: [{ base: Abar, v: 'e' }] },
    // P1 + Q1·dom + Σ_disclosed H_i m_i = r⁻¹·D − Σ_hidden m_i·H_i
    { lhs: Bpub, terms: [{ base: D, v: 'rinv' }, ...hidden.map((i) => ({ base: bbs.messageGenerator(pub.L, i).negate(), v: `m${i}` }))] },
    // K = g^y · h^t with the same y as message yIndex
    { lhs: g1FromHex(pub.K), terms: [{ base: g1, v: `m${spec.yIndex}` }, { base: H, v: 'ty' }] },
  ];
  if (pub.Kls !== undefined && spec.lsIndex !== undefined) {
    rels.push({ lhs: g1FromHex(pub.Kls), terms: [{ base: g1, v: `m${spec.lsIndex}` }, { base: H, v: 'tls' }] });
  }
  return {
    kind: 'leaf', label: 'R-CRED-SIG', rels, publics: [Abar, Bbar],
    check: () => !Abar.equals(G1.ZERO) && pairingEq(Abar, W, Bbar, g2),
  };
}

// ---------------------------------------------------------------- membership in a G1 accumulator
// A (NotRevoked), I (Issued) or [P_S]_1 (member of a group). Receipt C with e(C, g̃^y·Q̃) = e(acc, g̃).
// Blinded: C' = C^ρ, D = acc^ρ · C'^(−y) = C'^α; check e(C', Q̃) = e(D, g̃).

export interface AccLeafPublic { Cp: string; Dp: string }

export function accLeafProver(label: string, acc: G1Point, Qtilde: G2Point, K: G1Point, yOpen: Opening, C: G1Point)
  : { pub: AccLeafPublic; leaf: Leaf; wit: Witness } {
  const rho = randomScalar();
  const Cp = mul(C, rho);
  const Dp = mul(acc, rho).subtract(mul(Cp, yOpen.value));
  const pub = { Cp: g1ToHex(Cp), Dp: g1ToHex(Dp) };
  const wit: Witness = new Map([['rho', rho], ['y', yOpen.value], ['t', yOpen.blind]]);
  return { pub, leaf: accLeafVerifier(label, acc, Qtilde, K, pub), wit };
}

export function accLeafVerifier(label: string, acc: G1Point, Qtilde: G2Point, K: G1Point, pub: AccLeafPublic): Leaf {
  const Cp = g1FromHex(pub.Cp), Dp = g1FromHex(pub.Dp);
  return {
    kind: 'leaf', label,
    rels: [
      { lhs: Dp, terms: [{ base: acc, v: 'rho' }, { base: Cp.negate(), v: 'y' }] },
      { lhs: K, terms: [{ base: g1, v: 'y' }, { base: H, v: 't' }] },
    ],
    publics: [acc, Cp],
    check: () => !Cp.equals(G1.ZERO) && pairingEq(Cp, Qtilde, Dp, g2),
  };
}

// ---------------------------------------------------------------- membership in R̃ (G2)
// Receipt C̃ with e(g^y·Q, C̃) = e(g, R̃). Blinded: C̃' = C̃^ρ, D̃ = R̃^ρ · C̃'^(−y) = C̃'^α;
// check e(Q, C̃') = e(g, D̃).

export interface RevLeafPublic { Cp: string; Dp: string }

export function revLeafProver(Rtilde: G2Point, Q: G1Point, K: G1Point, yOpen: Opening, Ct: G2Point)
  : { pub: RevLeafPublic; leaf: Leaf; wit: Witness } {
  const rho = randomScalar();
  const Cp = mul(Ct, rho);
  const Dp = mul(Rtilde, rho).subtract(mul(Cp, yOpen.value));
  const pub = { Cp: g2ToHex(Cp), Dp: g2ToHex(Dp) };
  const wit: Witness = new Map([['rho', rho], ['y', yOpen.value], ['t', yOpen.blind]]);
  return { pub, leaf: revLeafVerifier(Rtilde, Q, K, pub), wit };
}

export function revLeafVerifier(Rtilde: G2Point, Q: G1Point, K: G1Point, pub: RevLeafPublic): Leaf {
  const Cp = g2FromHex(pub.Cp), Dp = g2FromHex(pub.Dp);
  return {
    kind: 'leaf', label: 'R-ATOM-REVOKED',
    rels: [
      { lhs: Dp, terms: [{ base: Rtilde, v: 'rho' }, { base: Cp.negate(), v: 'y' }] },
      { lhs: K, terms: [{ base: g1, v: 'y' }, { base: H, v: 't' }] },
    ],
    publics: [Rtilde, Cp],
    check: () => !Cp.equals(G2.ZERO) && pairingEq(Q, Cp, g1, Dp),
  };
}

// ---------------------------------------------------------------- simulatable fakes for false branches
// A false branch has no receipt. Its public values are chosen so the pairing check holds
// (C' = g^a, D = Q^a, i.e. C'^α without knowing α); the sigma part is then simulated.

export function fakeAccLeafPublic(Q: G1Point): AccLeafPublic {
  const a = randomScalar();
  return { Cp: g1ToHex(mul(g1, a)), Dp: g1ToHex(mul(Q, a)) };
}

export function fakeRevLeafPublic(Qtilde: G2Point): RevLeafPublic {
  const a = randomScalar();
  return { Cp: g2ToHex(mul(g2, a)), Dp: g2ToHex(mul(Qtilde, a)) };
}

// ---------------------------------------------------------------- distinctness and same holder

/** y_i ≠ y_j: Δ = K_i − K_j = g^δ h^ρ, prove u, s with g = Δ^u · h^s (u = 1/δ, s = −ρ/δ). */
export function neqLeafProver(Ki: G1Point, Kj: G1Point, oi: Opening, oj: Opening): { leaf: Leaf; wit: Witness } {
  const delta = mod(oi.value - oj.value);
  if (delta === 0n) throw new Error('same revocation ID twice');
  const rho = mod(oi.blind - oj.blind);
  const u = inv(delta);
  return { leaf: neqLeafVerifier(Ki, Kj), wit: new Map([['u', u], ['s', mod(-rho * u)]]) };
}

export function neqLeafVerifier(Ki: G1Point, Kj: G1Point): Leaf {
  const Delta = Ki.subtract(Kj);
  return {
    kind: 'leaf', label: 'R-DISTINCT',
    rels: [{ lhs: g1, terms: [{ base: Delta, v: 'u' }, { base: H, v: 's' }] }],
    publics: [Ki, Kj],
    check: () => !Delta.equals(G1.ZERO),
  };
}

/** same link secret: K_x − K_y = h^s */
export function sameHolderLeafProver(Kx: G1Point, Ky: G1Point, ox: Opening, oy: Opening): { leaf: Leaf; wit: Witness } {
  if (mod(ox.value - oy.value) !== 0n) throw new Error('different link secrets');
  return { leaf: sameHolderLeafVerifier(Kx, Ky), wit: new Map([['s', mod(ox.blind - oy.blind)]]) };
}

export function sameHolderLeafVerifier(Kx: G1Point, Ky: G1Point): Leaf {
  return {
    kind: 'leaf', label: 'R-CRED-EQ',
    rels: [{ lhs: Kx.subtract(Ky), terms: [{ base: H, v: 's' }] }],
    publics: [Kx, Ky],
    check: () => true,
  };
}
