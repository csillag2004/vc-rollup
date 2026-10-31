// Off-chain cost of the compiled proofs: prover time, verifier time and proof size per rule,
// on an in-memory registry that follows the contract's rules.
import { parse } from '../src/ql/parser.ts';
import { present, verifyPresentation, type PublicContext, type WalletCredential, type Presentation } from '../src/ql/compile.ts';
import { MemoryRegistry } from '../src/registry/memory.ts';
import * as bbs from '../src/crypto/bbs.ts';
import { utf8ToBytes, randomScalar } from '../src/crypto/bls.ts';
import { proofSize } from '../src/crypto/sigma.ts';

export interface BenchRow { case: string; rule: string; proveMs: number; verifyMs: number; bytes: number; proveSamplesMs: number[]; verifySamplesMs: number[]; proofSamplesBytes: number[] }

function presentationBytes(p: Presentation): number {
  // points are compressed hex in the JSON; count bytes of points and scalars, not JSON syntax
  let n = p.proof ? proofSize(p.proof) : 0;
  for (const c of p.credentials) n += 48 * 3 + 48 + (c.bbs.Kls ? 48 : 0) + Object.keys(c.bbs.disclosed).length * 32;
  for (const l of p.leaves) n += (l.Cp.length + l.Dp.length) / 2;
  for (const w of Object.values(p.evidence)) n += w.length / 2;
  return n;
}

async function setup(groupSize: number) {
  const kp = await bbs.generateKeyPair();
  const reg = new MemoryRegistry('0xreg', '0xcd', kp.publicKey, Math.max(groupSize, 8));
  const header = utf8ToBytes('0xcd');
  const ls = randomScalar();
  const wallet: WalletCredential[] = [];
  const ys: bigint[] = [];
  for (let i = 0; i < groupSize; i++) {
    const msgs = [crypto.getRandomValues(new Uint8Array(32)), utf8ToBytes(`member-${i}`), utf8ToBytes(ls.toString())];
    const scalars = msgs.map(bbs.messageToScalar);
    const { receiptA, version } = reg.issue(scalars[0]!);
    ys.push(scalars[0]!);
    if (i < 6) {
      const sig = await bbs.sign(kp, header, msgs);
      wallet.push({ credDefId: '0xcd', registryId: '0xreg', header, scalars, sig, yIndex: 0, lsIndex: 2, disclose: [], receiptA, receiptVersion: version });
    }
  }
  // one revoked credential in the wallet and in the group, plus a later revocation outside it
  reg.revoke(ys[groupSize - 1]!);
  const outside = randomScalar();
  reg.issue(outside);
  reg.revoke(outside);
  const ctx: PublicContext = {
    registries: new Map([['0xreg', reg.h]]),
    bindings: new Map<string, any>([
      ['S', { kind: 'group', groupId: '0xg', registryId: '0xreg', members: [...ys].sort((a, b) => (a < b ? -1 : 1)) }],
      ['Landlord', { kind: 'creddef', credDefId: '0xcd' }],
      ['Issued', { kind: 'registry', registryId: '0xreg' }],
    ]),
  };
  return { reg, ctx, wallet, ys };
}

async function measure(caseName: string, rule: string, q: string, ctx: PublicContext, wallet: WalletCredential[], opts = {}, reps = 3): Promise<BenchRow> {
  const f = parse(q);
  let p!: Presentation;
  // Warm up the same proof shape before collecting independent wall-clock samples.
  p = present(f, q, ctx, wallet, 'warmup', opts);
  const warmup = verifyPresentation(f, p, ctx);
  if (!warmup.ok) throw new Error(`${caseName}: ${warmup.reason}`);
  const proveSamplesMs: number[] = [], verifySamplesMs: number[] = [];
  const presentations: Presentation[] = [];
  for (let i = 0; i < reps; i++) {
    const start = performance.now();
    p = present(f, q, ctx, wallet, `n${i}`, opts);
    proveSamplesMs.push(performance.now() - start);
    presentations.push(p);
  }
  for (let i = 0; i < reps; i++) {
    const start = performance.now();
    const v = verifyPresentation(f, presentations[i]!, ctx);
    verifySamplesMs.push(performance.now() - start);
    if (!v.ok) throw new Error(`${caseName}: ${v.reason}`);
  }
  const proveMs = proveSamplesMs.reduce((a, b) => a + b, 0) / reps;
  const verifyMs = verifySamplesMs.reduce((a, b) => a + b, 0) / reps;
  const proofSamplesBytes = presentations.map(presentationBytes);
  const bytes = proofSamplesBytes.reduce((a, b) => a + b, 0) / reps;
  return { case: caseName, rule, proveMs, verifyMs, bytes, proveSamplesMs, verifySamplesMs, proofSamplesBytes };
}

export async function runBench(smoke = false): Promise<BenchRow[]> {
  const rows: BenchRow[] = [];
  const small = await setup(6);
  // the revoked wallet credential is the last of the six
  const active = small.wallet.slice(0, 5);
  const revoked = [small.wallet[5]!];
  rows.push(await measure('one active credential', 'R-CRED-SIG + R-ATOM-NOTREVOKED', 'exists x in Presented. Sig(x, "Landlord") & Active(x)', small.ctx, active));
  rows.push(await measure('one revoked credential', 'R-CRED-SIG + R-ATOM-REVOKED (G2)', 'exists x in Presented. Sig(x, "Landlord") & Revoked(x)', small.ctx, revoked));
  rows.push(await measure('OR with a simulated branch', 'R-OR (CDS)', 'exists x in Presented. Sig(x, "Landlord") & (Revoked(x) | NotRevoked(x))', small.ctx, active));
  for (const k of (smoke ? [1, 2] : [1, 2, 3, 4])) {
    rows.push(await measure(`at least ${k} active`, 'R-ATLEAST (k credentials + distinctness)', `atleast ${k} x in Presented. Sig(x, "Landlord") & Active(x)`, small.ctx, active));
  }
  rows.push(await measure('same holder, two credentials', 'R-CRED-EQ', 'exists x in Presented. exists y in Presented. Sig(x, "Landlord") & Sig(y, "Landlord") & SameHolder(x, y)', small.ctx, active));
  for (const n of (smoke ? [4] : [4, 16, 64])) {
    const s = await setup(n);
    const members = (s.ctx.bindings.get('S') as any).members as bigint[];
    const activeMembers = members.filter((y) => !s.reg.h.revokedAt.has(y));
    const groupQ = `exists x in S. Sig(x, "Landlord") & Active(x)`;
    rows.push(await measure(`hidden member of S, |S| = ${n}`, 'R-EXISTS (acc_S) + R-ATOM-NOTREVOKED', groupQ, s.ctx, s.wallet.slice(0, 1)));
    // guard over the active members only (the group of the flat reservation before any booking)
    s.ctx.bindings.set('T', { kind: 'group', groupId: '0xt', registryId: '0xreg', members: activeMembers });
    rows.push(await measure(`∀x∈T. NotRevoked, |T| = ${activeMembers.length}`, 'public evaluation + aggregate receipt', 'forall x in T. NotRevoked(x)', s.ctx, [], { aggregates: { T: s.reg.aggregate(activeMembers) } }));
    rows.push(await measure(`∃x∈S. Revoked, |S| = ${n}`, 'public evaluation (loser\'s proof)', 'exists x in S. Revoked(x)', s.ctx, []));
  }
  return rows;
}

export function benchTable(rows: BenchRow[]): string {
  const lines = ['| Case | Rule | Prove (ms) | Verify (ms) | Mean size (bytes) |', '|---|---|---:|---:|---:|'];
  for (const r of rows) lines.push(`| ${r.case} | ${r.rule} | ${r.proveMs.toFixed(1)} | ${r.verifyMs.toFixed(1)} | ${r.bytes} |`);
  return lines.join('\n');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runBench().then((rows) => console.log(benchTable(rows))).catch((e) => { console.error(e); process.exit(1); });
}
