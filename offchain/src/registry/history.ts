// What anyone can know about a registry from the ledger: its values at every version,
// the issued and revoked IDs with their versions, the keys, the SRS and the issuer's BBS key (from the DID document).
import type { PublicKeys, RegistryValues, Srs } from '../crypto/accumulator.ts';
import { refreshReceiptA, refreshReceiptRtilde, valuesHash } from '../crypto/accumulator.ts';
import { g1ToEip, g2ToEip, type G1Point, type G2Point } from '../crypto/bls.ts';

export interface RegistryHistory {
  registryId: string;
  credDefId: string;
  pub: PublicKeys;
  srs?: Srs;
  /** values[v] = registry values at version v */
  values: RegistryValues[];
  /** revocation ID -> version at which it was issued (issuance reveals y) */
  issuedAt: Map<bigint, number>;
  /** revocation ID -> version at which it was revoked */
  revokedAt: Map<bigint, number>;
  /** BBS public key of the CredDef's issuer */
  issuerPk: Uint8Array;
}

export const currentVersion = (h: RegistryHistory): number => h.values.length - 1;

export function revokedUpTo(h: RegistryHistory, v: number): Set<bigint> {
  return new Set([...h.revokedAt].filter(([, at]) => at <= v).map(([y]) => y));
}

/** the number of IDs issued up to v (the contract's issuedCount at v) */
export const issuedCountAt = (h: RegistryHistory, v: number): number => [...h.issuedAt.values()].filter((at) => at <= v).length;

/** revocations in (from, to], in order */
export function revocationsBetween(h: RegistryHistory, from: number, to: number): [bigint, number][] {
  return [...h.revokedAt].filter(([, at]) => at > from && at <= to).sort((a, b) => a[1] - b[1]);
}

/** group version at v: the number of members revoked up to v (members are issued, so only revocation touches them) */
export function groupVersionAt(h: RegistryHistory, members: bigint[], v: number): number {
  const rev = revokedUpTo(h, v);
  return members.filter((y) => rev.has(y)).length;
}

export function valuesHashAt(h: RegistryHistory, v: number): string {
  const x = h.values[v]!;
  return valuesHash({ A: g1ToEip(x.A), Rtilde: g2ToEip(x.Rtilde), I: g1ToEip(x.I) });
}

/** bring a receipt against A from version `from` to version `to` using the public log */
export function refreshAto(h: RegistryHistory, y: bigint, C: G1Point, from: number, to: number): G1Point {
  let c = C;
  for (const [yr, at] of revocationsBetween(h, from, to)) c = refreshReceiptA(c, h.values[at]!.A, y, yr);
  return c;
}

/** the free receipt for a revoked y (the R̃ just before its revocation), refreshed to version `to` */
export function revokedReceiptAt(h: RegistryHistory, y: bigint, to: number): G2Point | undefined {
  const at = h.revokedAt.get(y);
  if (at === undefined || at > to) return undefined;
  let c = h.values[at - 1]!.Rtilde;
  for (const [yr, u] of revocationsBetween(h, at, to)) c = refreshReceiptRtilde(c, h.values[u - 1]!.Rtilde, y, yr);
  return c;
}
