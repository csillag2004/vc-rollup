// An in-memory registry that follows the contract's rules (used by tests and the evaluation;
// the chain client produces the same RegistryHistory from events).
import * as acc from '../crypto/accumulator.ts';
import type { G1Point } from '../crypto/bls.ts';
import { mod } from '../crypto/bls.ts';
import type { RegistryHistory } from './history.ts';

export class MemoryRegistry {
  readonly h: RegistryHistory;
  readonly secret: acc.AccumulatorSecret;
  readonly issued = new Set<bigint>();

  constructor(registryId: string, credDefId: string, issuerPk: Uint8Array, srsDegree = 16) {
    const { secret, pub } = acc.generateAccumulatorKeys();
    this.secret = secret;
    this.h = {
      registryId, credDefId, pub, srs: acc.makeSrs(secret.alpha, srsDegree),
      values: [acc.initialValues(pub)], revokedAt: new Map(), issuerPk,
    };
  }

  get version(): number { return this.h.values.length - 1; }
  get values(): acc.RegistryValues { return this.h.values[this.version]!; }

  issue(y: bigint): { receiptA: G1Point; version: number } {
    if (this.issued.has(y)) throw new Error('ID reused');
    const st = acc.issueStep(this.secret, this.values, y, () => mod(y + 1n));
    this.h.values.push({ ...this.values, I: st.newI, WIR: st.newWIR });
    this.issued.add(y);
    return { receiptA: st.receiptA, version: this.version };
  }

  revoke(y: bigint): void {
    if (!this.issued.has(y)) throw new Error('not issued');
    if (this.h.revokedAt.has(y)) throw new Error('already revoked');
    const v = this.values;
    const st = acc.revokeStep(this.secret, v, y);
    if (!acc.stepCheck(v.A, st.newA, y, this.h.pub.Qtilde)) throw new Error('step check');
    this.h.values.push({ ...v, A: st.newA, Rtilde: st.newRtilde, WIR: st.newWIR });
    this.h.revokedAt.set(y, this.version);
  }

  aggregate(members: bigint[]): G1Point {
    return acc.aggregateReceiptWithTrapdoor(this.secret, this.values.A, members);
  }
}
