// The three-accumulator registry: A (active side, static add), R̃ (revoked set, G2), I (issued set),
// W_IR (revoked ⊆ issued), the issuer's trapdoor α and the SRS.
import {
  G1, G2, type G1Point, type G2Point, g1, g2, mul, inv, mod, randomScalar, msm,
  pairingEq, hashToG1, setPolyCoeffs, setPolyAt, commitPoly, R, scalarToBytes32,
} from './bls.ts';
import { keccak256, AbiCoder } from 'ethers';

export interface PublicKeys {
  V0: G1Point;
  Qtilde: G2Point; // g̃^α
  Q: G1Point;      // g^α
}

export interface RegistryValues {
  A: G1Point;
  Rtilde: G2Point;
  I: G1Point;
  WIR: G1Point;
}

export interface Srs {
  g1Powers: G1Point[]; // g^(α^i), i = 0..n
  g2Powers: G2Point[];
}

export interface AccumulatorSecret {
  alpha: bigint;
}

export function generateAccumulatorKeys(): { secret: AccumulatorSecret; pub: PublicKeys } {
  const alpha = randomScalar();
  const V0 = hashToG1(crypto.getRandomValues(new Uint8Array(32)), 'revoq/V0');
  return { secret: { alpha }, pub: { V0, Qtilde: mul(g2, alpha), Q: mul(g1, alpha) } };
}

export function initialValues(pub: PublicKeys): RegistryValues {
  return { A: pub.V0, Rtilde: g2, I: g1, WIR: g1 };
}

export function makeSrs(alpha: bigint, degree: number): Srs {
  const g1Powers: G1Point[] = [];
  const g2Powers: G2Point[] = [];
  let a = 1n;
  for (let i = 0; i <= degree; i++) {
    g1Powers.push(mul(g1, a));
    g2Powers.push(mul(g2, a));
    a = mod(a * alpha);
  }
  return { g1Powers, g2Powers };
}

// ---- issuer side (needs α) ----

export interface IssueStepValues {
  newI: G1Point;
  newWIR: G1Point;
  T: G1Point;      // I^y
  Rcommit: G1Point; // Schnorr commitment I^k
  z: bigint;       // k + c·y
  receiptA: G1Point; // C = A^(1/(y+α))
  receiptI: G1Point; // the old I: receipt for y against newI
}

/**
 * Issuance: I' = I^(y+α), W_IR' = W_IR^(y+α), receipt C = A^(1/(y+α)) (static add: A unchanged).
 * The Schnorr proof of knowledge of y for T = I^y uses the challenge the contract computes.
 */
export function issueStep(
  secret: AccumulatorSecret, values: RegistryValues, y: bigint,
  challenge: (newI: G1Point, T: G1Point, Rc: G1Point) => bigint,
): IssueStepValues {
  const { alpha } = secret;
  const newI = mul(values.I, y + alpha);
  const newWIR = mul(values.WIR, y + alpha);
  const T = mul(values.I, y);
  const k = randomScalar();
  const Rcommit = mul(values.I, k);
  const c = challenge(newI, T, Rcommit);
  const z = mod(k + c * y);
  return { newI, newWIR, T, Rcommit, z, receiptA: mul(values.A, inv(y + alpha)), receiptI: values.I };
}

export interface RevokeStepValues {
  newA: G1Point;
  newRtilde: G2Point;
  newWIR: G1Point;
}

/** Revocation: A' = A^(1/(y+α)), R̃' = R̃^(y+α), W_IR' = W_IR^(1/(y+α)). */
export function revokeStep(secret: AccumulatorSecret, values: RegistryValues, y: bigint): RevokeStepValues {
  const f = mod(y + secret.alpha);
  return { newA: mul(values.A, inv(f)), newRtilde: mul(values.Rtilde, f), newWIR: mul(values.WIR, inv(f)) };
}

/** Group anchoring witness: W_S = I^(1/P_S(α)) = [P_Iss / P_S]_1. */
export function groupSubsetWitness(secret: AccumulatorSecret, I: G1Point, members: bigint[]): G1Point {
  return mul(I, inv(setPolyAt(members, secret.alpha)));
}

/** Aggregate receipt for ∀x∈S. NotRevoked(x), with α: W = A^(1/P_S(α)). */
export function aggregateReceiptWithTrapdoor(secret: AccumulatorSecret, A: G1Point, members: bigint[]): G1Point {
  return mul(A, inv(setPolyAt(members, secret.alpha)));
}

// ---- public side (no α) ----

/** Membership in A (or any G1 accumulator with key Q̃): e(C, g̃^y·Q̃) = e(acc, g̃). */
export function verifyReceiptG1(acc: G1Point, y: bigint, C: G1Point, Qtilde: G2Point): boolean {
  return pairingEq(C, mul(g2, y).add(Qtilde), acc, g2);
}

/** Membership in R̃: e(g^y·Q, C̃) = e(g, R̃). */
export function verifyReceiptRtilde(Rtilde: G2Point, y: bigint, Ct: G2Point, Q: G1Point): boolean {
  return pairingEq(mul(g1, y).add(Q), Ct, g1, Rtilde);
}

/** Holder refresh against A after revocation of y' ≠ y: C' = (C / A')^(1/(y'−y)). */
export function refreshReceiptA(C: G1Point, newA: G1Point, y: bigint, yRevoked: bigint): G1Point {
  if (mod(y - yRevoked) === 0n) throw new Error('own credential revoked: receipt cannot be refreshed');
  return mul(C.subtract(newA), inv(yRevoked - y));
}

/** Refresh of a revoked-set receipt after a later revocation of y': C̃' = R̃_before · C̃^(y'−y). */
export function refreshReceiptRtilde(Ct: G2Point, RtildeBefore: G2Point, y: bigint, yRevoked: bigint): G2Point {
  return RtildeBefore.add(mul(Ct, yRevoked - y));
}

/**
 * Aggregate receipt from individual receipts, without α:
 * W = ∏ C_i^(λ_i), λ_i = ∏_{j≠i} 1/(y_j − y_i). All C_i must be against the same A.
 */
export function aggregateReceipt(members: bigint[], receipts: G1Point[]): G1Point {
  const lambdas = members.map((yi, i) =>
    members.reduce((acc, yj, j) => (j === i ? acc : mod(acc * inv(yj - yi))), 1n));
  return msm(receipts, lambdas);
}

/** e(W, [P_S]_2) = e(acc, g̃) */
export function verifyAggregate(acc: G1Point, W: G1Point, members: bigint[], srs: Srs): boolean {
  return pairingEq(W, commitPoly(setPolyCoeffs(members), srs.g2Powers), acc, g2);
}

/** [P_S]_1, the accumulator of a public group */
export function groupAccumulator(members: bigint[], srs: Srs): G1Point {
  return commitPoly(setPolyCoeffs(members), srs.g1Powers);
}

/** Receipt for y ∈ S against [P_S]_1, from the SRS only: D = [P_{S∖{y}}]_1. */
export function groupMemberReceipt(members: bigint[], y: bigint, srs: Srs): G1Point {
  const rest = members.filter((s) => mod(s - y) !== 0n);
  if (rest.length !== members.length - 1) throw new Error('not a member');
  return commitPoly(setPolyCoeffs(rest), srs.g1Powers);
}

// ---- whole-registry checks (public, no proof) ----

export const noneRevoked = (v: RegistryValues, pub: PublicKeys): boolean => v.A.equals(pub.V0);
export const allIssuedRevoked = (v: RegistryValues): boolean => pairingEq(v.I, g2, g1, v.Rtilde);
export const stepCheck = (A: G1Point, newA: G1Point, y: bigint, Qtilde: G2Point): boolean =>
  pairingEq(newA, mul(g2, y).add(Qtilde), A, g2);
export const consistencyCheck = (v: RegistryValues, pub: PublicKeys): boolean => pairingEq(v.A, v.Rtilde, pub.V0, g2);
export const subsetCheck = (v: RegistryValues): boolean => pairingEq(v.WIR, v.Rtilde, v.I, g2);

/** The hash the contract stores per version: keccak256(abi.encode(A, Rtilde, I)) over EIP-2537 bytes. */
export function valuesHash(v: { A: string; Rtilde: string; I: string }): string {
  return keccak256(AbiCoder.defaultAbiCoder().encode(['bytes', 'bytes', 'bytes'], [v.A, v.Rtilde, v.I]));
}

export const yToBytes32 = (y: bigint): string => '0x' + Buffer.from(scalarToBytes32(y)).toString('hex');
export { R };
