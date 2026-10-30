// BBS signatures, IETF draft-irtf-cfrg-bbs-signatures, ciphersuite BLS12-381-SHA-256.
// Keys and signatures come from @digitalbazaar/bbs-signatures; the generators, the message-to-scalar
// map and B are re-derived here (on noble v1) so the holder can prove knowledge of a signature
// inside our own composable sigma protocol. Tests check that both sides agree.
import * as bbs from '@digitalbazaar/bbs-signatures';
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  G1, G2, type G1Point, type G2Point, g2, mod, mul, inv, pairingEq, concatBytes, utf8ToBytes, bytesToHex,
} from './bls.ts';

const CIPHERSUITE_ID = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';
const API_ID = utf8ToBytes(CIPHERSUITE_ID + 'H2G_HM2S_');
const EXPAND_LEN = 48;
const P1 = G1.fromHex('a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9');

const i2osp = (v: bigint | number, len: number): Uint8Array => {
  let x = BigInt(v);
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
};
const os2ip = (b: Uint8Array): bigint => BigInt('0x' + (bytesToHex(b) || '0'));
const expand = (msg: Uint8Array, dst: Uint8Array): Uint8Array => expand_message_xmd(msg, dst, EXPAND_LEN, sha256);

export function hashToScalar(msg: Uint8Array, dst: Uint8Array): bigint {
  return mod(os2ip(expand(msg, dst)));
}

/** IETF messages_to_scalars: msg_i ↦ hash_to_scalar(msg_i, api_id ‖ "MAP_MSG_TO_SCALAR_AS_HASH_") */
export function messageToScalar(msg: Uint8Array): bigint {
  return hashToScalar(msg, concatBytes(API_ID, utf8ToBytes('MAP_MSG_TO_SCALAR_AS_HASH_')));
}

const generatorCache: G1Point[] = [];
/** IETF create_generators: (Q_1, H_1, ..., H_L) */
export function generators(count: number): G1Point[] {
  if (generatorCache.length < count) {
    const seedDst = concatBytes(API_ID, utf8ToBytes('SIG_GENERATOR_SEED_'));
    const genDst = concatBytes(API_ID, utf8ToBytes('SIG_GENERATOR_DST_'));
    let v = expand(concatBytes(API_ID, utf8ToBytes('MESSAGE_GENERATOR_SEED')), seedDst);
    generatorCache.length = 0;
    for (let i = 1; i <= count; i++) {
      v = expand(concatBytes(v, i2osp(i, 8)), seedDst);
      const h = bls12_381.G1.hashToCurve(v, { DST: genDst }) as any;
      generatorCache.push(G1.fromAffine(h.toAffine()));
    }
  }
  return generatorCache.slice(0, count);
}

/** IETF calculate_domain */
export function domain(pk: Uint8Array, gens: G1Point[], header: Uint8Array): bigint {
  const [Q1, ...H] = gens;
  const domArray = concatBytes(i2osp(H.length, 8), Q1!.toRawBytes(true), ...H.map((h) => h.toRawBytes(true)));
  const domInput = concatBytes(pk, domArray, API_ID, i2osp(header.length, 8), header);
  return hashToScalar(domInput, concatBytes(API_ID, utf8ToBytes('H2S_')));
}

export interface BbsKeyPair { secretKey: Uint8Array; publicKey: Uint8Array }
export interface BbsSignature { A: G1Point; e: bigint; bytes: Uint8Array }

export async function generateKeyPair(): Promise<BbsKeyPair> {
  return bbs.generateKeyPair({ ciphersuite: bbs.CIPHERSUITES.BLS12381_SHA256 });
}

export async function sign(kp: BbsKeyPair, header: Uint8Array, messages: Uint8Array[]): Promise<BbsSignature> {
  const bytes: Uint8Array = await bbs.sign({
    secretKey: kp.secretKey, publicKey: kp.publicKey, header, messages, ciphersuite: bbs.CIPHERSUITES.BLS12381_SHA256,
  });
  return parseSignature(bytes);
}

export async function verifyWithLibrary(pk: Uint8Array, sig: BbsSignature, header: Uint8Array, messages: Uint8Array[]): Promise<boolean> {
  return bbs.verifySignature({ publicKey: pk, signature: sig.bytes, header, messages, ciphersuite: bbs.CIPHERSUITES.BLS12381_SHA256 });
}

export function parseSignature(bytes: Uint8Array): BbsSignature {
  return { A: G1.fromHex(bytes.slice(0, 48)), e: os2ip(bytes.slice(48, 80)), bytes };
}

export const publicKeyPoint = (pk: Uint8Array): G2Point => G2.fromHex(pk);

/** B = P1 + Q_1·domain + Σ H_i·m_i (messages as scalars) */
export function computeB(pk: Uint8Array, header: Uint8Array, scalars: bigint[]): G1Point {
  const gens = generators(scalars.length + 1);
  let B = P1.add(mul(gens[0]!, domain(pk, gens, header)));
  scalars.forEach((m, i) => { B = B.add(mul(gens[i + 1]!, m)); });
  return B;
}

/** Our own check of a library signature: e(A, W + g̃^e) = e(B, g̃). */
export function verifyOwn(pk: Uint8Array, sig: BbsSignature, header: Uint8Array, scalars: bigint[]): boolean {
  const B = computeB(pk, header, scalars);
  return pairingEq(sig.A, publicKeyPoint(pk).add(mul(g2, sig.e)), B, g2);
}

/** Public part of B: P1 + Q_1·domain + Σ_{disclosed} H_i·m_i */
export function publicB(pk: Uint8Array, header: Uint8Array, L: number, disclosed: Map<number, bigint>): G1Point {
  const gens = generators(L + 1);
  let B = P1.add(mul(gens[0]!, domain(pk, gens, header)));
  for (const [i, m] of disclosed) B = B.add(mul(gens[i + 1]!, m));
  return B;
}

export const messageGenerator = (L: number, i: number): G1Point => generators(L + 1)[i + 1]!;

/**
 * Randomised signature for a proof of knowledge (Tessaro–Zhu form):
 * Ā = A·r, D = B·r, B̄ = D − e·Ā; the verifier checks e(Ā, W) = e(B̄, g̃).
 */
export function randomise(sig: BbsSignature, B: G1Point, r: bigint): { Abar: G1Point; D: G1Point; Bbar: G1Point } {
  const Abar = mul(sig.A, r);
  const D = mul(B, r);
  return { Abar, D, Bbar: D.subtract(mul(Abar, sig.e)) };
}

export const rInverse = (r: bigint): bigint => inv(r);
