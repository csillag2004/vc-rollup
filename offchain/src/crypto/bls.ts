// BLS12-381 helpers on @noble/curves: scalar field, points, pairings, encodings.
// Notation in comments is multiplicative (g^a); the code is additive (G.multiply(a)).
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

export { bytesToHex, hexToBytes, concatBytes, utf8ToBytes };

export const G1 = bls12_381.G1.ProjectivePoint;
export const G2 = bls12_381.G2.ProjectivePoint;
export type G1Point = InstanceType<typeof G1>;
export type G2Point = InstanceType<typeof G2>;
export type Point = G1Point | G2Point;
export const Fr = bls12_381.fields.Fr;
export const Fp12 = bls12_381.fields.Fp12;
export const R = Fr.ORDER;

export const g1 = G1.BASE;
export const g2 = G2.BASE;

export const mod = (a: bigint): bigint => ((a % R) + R) % R;
export const inv = (a: bigint): bigint => Fr.inv(mod(a));

export function randomScalar(): bigint {
  // 48 random bytes reduced mod r: negligible bias
  const b = crypto.getRandomValues(new Uint8Array(48));
  const s = mod(BigInt('0x' + bytesToHex(b)));
  return s === 0n ? randomScalar() : s;
}

export function scalarFromBytes(b: Uint8Array): bigint {
  return mod(BigInt('0x' + bytesToHex(b)));
}

export function scalarToBytes32(s: bigint): Uint8Array {
  return hexToBytes(mod(s).toString(16).padStart(64, '0'));
}

export const scalarToHex32 = (s: bigint): string => '0x' + bytesToHex(scalarToBytes32(s));

/** p^s that accepts s = 0 (noble's multiply rejects 0). */
export function mul<P extends Point>(p: P, s: bigint): P {
  const k = mod(s);
  return (k === 0n ? (p as any).multiplyUnsafe(0n) : (p as any).multiply(k)) as P;
}

export function isG1(p: Point): p is G1Point {
  return p instanceof G1;
}

/** Σ s_i·P_i in one group. */
export function msm<P extends Point>(points: P[], scalars: bigint[]): P {
  if (points.length === 0) throw new Error('msm of nothing');
  let acc = mul(points[0]!, scalars[0]!);
  for (let i = 1; i < points.length; i++) acc = acc.add(mul(points[i]!, scalars[i]!) as any) as P;
  return acc;
}

/** ∏ e(a_i, b_i) == 1 */
export function pairingProductIsOne(pairs: [G1Point, G2Point][]): boolean {
  const live = pairs.filter(([a, b]) => !a.equals(G1.ZERO) && !b.equals(G2.ZERO));
  if (live.length === 0) return true;
  const r = bls12_381.pairingBatch(live.map(([g1, g2]) => ({ g1, g2 })));
  return Fp12.eql(r, Fp12.ONE);
}

/** e(a, b) == e(c, d) */
export function pairingEq(a: G1Point, b: G2Point, c: G1Point, d: G2Point): boolean {
  return pairingProductIsOne([[a, b], [c.negate(), d]]);
}

export function hashToG1(msg: Uint8Array, dst: string): G1Point {
  return G1.fromAffine((bls12_381.G1.hashToCurve(msg, { DST: dst }) as any).toAffine());
}

// ---- encodings ----

export const g1ToHex = (p: G1Point): string => bytesToHex(p.toRawBytes(true));
export const g2ToHex = (p: G2Point): string => bytesToHex(p.toRawBytes(true));
export const g1FromHex = (h: string): G1Point => G1.fromHex(h.replace(/^0x/, ''));
export const g2FromHex = (h: string): G2Point => G2.fromHex(h.replace(/^0x/, ''));
export const pointToHex = (p: Point): string => (isG1(p) ? g1ToHex(p) : g2ToHex(p as G2Point));

const fpTo64 = (x: bigint): string => x.toString(16).padStart(128, '0');
const fpFrom64 = (h: string): bigint => BigInt('0x' + h);

/** EIP-2537 encoding: G1 = x‖y, 64 bytes each (16 zero bytes + 48). */
export function g1ToEip(p: G1Point): string {
  if (p.equals(G1.ZERO)) return '0x' + '0'.repeat(256);
  const { x, y } = p.toAffine();
  return '0x' + fpTo64(x) + fpTo64(y);
}

/** EIP-2537 encoding: G2 = x.c0‖x.c1‖y.c0‖y.c1, 64 bytes each. */
export function g2ToEip(p: G2Point): string {
  if (p.equals(G2.ZERO)) return '0x' + '0'.repeat(512);
  const { x, y } = p.toAffine();
  return '0x' + fpTo64(x.c0) + fpTo64(x.c1) + fpTo64(y.c0) + fpTo64(y.c1);
}

export function g1FromEip(hex: string): G1Point {
  const h = hex.replace(/^0x/, '');
  if (/^0+$/.test(h)) return G1.ZERO;
  return G1.fromAffine({ x: fpFrom64(h.slice(0, 128)), y: fpFrom64(h.slice(128, 256)) });
}

export function g2FromEip(hex: string): G2Point {
  const h = hex.replace(/^0x/, '');
  if (/^0+$/.test(h)) return G2.ZERO;
  const Fp2 = bls12_381.fields.Fp2;
  const x = Fp2.create({ c0: fpFrom64(h.slice(0, 128)), c1: fpFrom64(h.slice(128, 256)) });
  const y = Fp2.create({ c0: fpFrom64(h.slice(256, 384)), c1: fpFrom64(h.slice(384, 512)) });
  return G2.fromAffine({ x, y });
}

export function sha256Hex(...parts: Uint8Array[]): string {
  return bytesToHex(sha256(concatBytes(...parts)));
}

// ---- polynomials over Fr ----

/** coefficients (constant term first) of P_S(x) = ∏ (x + s) */
export function setPolyCoeffs(set: bigint[]): bigint[] {
  let c = [1n];
  for (const s of set) {
    const next = new Array<bigint>(c.length + 1).fill(0n);
    for (let j = 0; j < c.length; j++) {
      next[j] = mod(next[j]! + c[j]! * s);
      next[j + 1] = mod(next[j + 1]! + c[j]!);
    }
    c = next;
  }
  return c;
}

/** P_S(α) for a known α */
export function setPolyAt(set: bigint[], alpha: bigint): bigint {
  return set.reduce((acc, s) => mod(acc * (alpha + s)), 1n);
}

/** [P]_1 or [P]_2 from SRS powers */
export function commitPoly<P extends Point>(coeffs: bigint[], powers: P[]): P {
  if (coeffs.length > powers.length) throw new Error(`SRS too short: need ${coeffs.length}, have ${powers.length}`);
  return msm(powers.slice(0, coeffs.length), coeffs);
}
