// Gas per registry operation on a local Prague chain (anvil), verify on write (EIP-2537).
import { ethers } from 'ethers';
import { deployAll } from '../src/chain/client.ts';
import { Issuer, Holder, readGroup, type PolicyRef } from '../src/actors/actors.ts';
import type { Binding } from '../src/ql/compile.ts';

const RPC = process.argv[2] ?? 'http://127.0.0.1:8545';
const KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // anvil default account

export interface GasRow { operation: string; detail: string; gas: bigint[] }

export async function runGas(rpc = RPC): Promise<GasRow[]> {
  const provider = new ethers.JsonRpcProvider(rpc, undefined, { pollingInterval: 50, cacheTimeout: -1 });
  const signer = new ethers.Wallet(KEY, provider);
  const rows: GasRow[] = [];
  /** run fn and collect the gas of every transaction it sent (anvil mines one block per transaction) */
  const record = async <T>(operation: string, detail: string, fn: () => Promise<T>): Promise<T> => {
    const from = await provider.getBlockNumber();
    const out = await fn();
    const to = await provider.getBlockNumber();
    const gas: bigint[] = [];
    for (let b = from + 1; b <= to; b++) {
      const block = await provider.getBlock(b);
      for (const h of block?.transactions ?? []) gas.push((await provider.getTransactionReceipt(h))!.gasUsed);
    }
    rows.push({ operation, detail, gas });
    return out;
  };

  const d = await deployAll(signer);
  const issuer = new Issuer(signer, d);
  await record('setup', 'BBS key in DID document, schema, CredDef', () => issuer.setUp('Interest', ['flat', 'name']));
  for (const deg of [4, 8, 16]) {
    await record('createRegistry + publishSrs', `SRS degree ${deg}`, () => issuer.createRegistry(`gas-${deg}`, deg));
  }
  const reg = await issuer.createRegistry('gas-main', 16);
  const holders = Array.from({ length: 16 }, () => new Holder(d));
  for (const [i, h] of holders.entries()) {
    h.wallet.push(await record('issueUpdate', 'y in the clear: G2 MSM + 2 pairing checks + storage', () => issuer.issue(reg, ['flat', `h${i}`], h.linkSecret)));
  }
  const ys = holders.map((h) => h.wallet[0]!.scalars[0]!);
  for (const n of [2, 4, 8, 16]) {
    await record('createGroup', `|S| = ${n} (every member checked in storage)`, () => issuer.createGroup(reg, `g${n}`, ys.slice(0, n)));
  }
  await record('revoke', 'step + consistency + subset (3 pairing checks)', () => issuer.revoke(reg, ys[15]!));

  // guarded revocations, each under its own policy: two public guards over a group of 4, one presented part
  const g = await readGroup(d, await issuer.createGroup(reg, 'guard-group', ys.slice(4, 8)));
  const gs = await readGroup(d, await issuer.createGroup(reg, 'guard-stable', ys.slice(8, 12)));
  const R: Binding = { kind: 'registry', registryId: reg };
  const pGroup = await record('registerPolicy', 'public part: forall x in S. NotRevoked(x)', () => issuer.registerPolicy('forall x in S. NotRevoked(x)', [['S', g]]));
  const pStable = await issuer.registerPolicy('exists x in S. Revoked(x)', [['S', gs]]);
  const pPresented = await record('registerPolicy', 'presented part: exists x in Presented. Sig(x, "R") & NotRevoked(x)',
    () => issuer.registerPolicy('exists x in Presented. Sig(x, "R") & NotRevoked(x)', [['R', R]]));
  await issuer.revoke(reg, ys[8]!); // makes the stable guard true

  const guarded = async (detail: string, policy: PolicyRef, holder: Holder, y: bigint) => {
    const p = await holder.present(policy.query, policy.bindings, detail);
    const bytes = issuer.guardFor(policy, p).proof.length;
    await record('guardedRevoke', `${detail}; proof ${bytes} B on the ledger`, () => issuer.guardedRevoke(reg, y, policy, p));
  };
  await guarded('public group guard forall x in S. NotRevoked(x), |S| = 4 (counted on chain)', pGroup, holders[4]!, ys[4]!);
  await guarded('public stable group guard exists x in S. Revoked(x), |S| = 4', pStable, holders[9]!, ys[9]!);
  await guarded('presented part, co-stable: one credential, one version comparison', pPresented, holders[0]!, ys[13]!);
  return rows;
}

export function gasTable(rows: GasRow[]): string {
  const merged = new Map<string, { operation: string; detail: string; gas: bigint[] }>();
  for (const r of rows) {
    const k = `${r.operation}|${r.detail}`;
    const m = merged.get(k) ?? { operation: r.operation, detail: r.detail, gas: [] };
    m.gas.push(r.gas.reduce((a, b) => a + b, 0n));
    merged.set(k, m);
  }
  const lines = ['| Operation | Detail | Gas (median of runs) | Runs |', '|---|---|---:|---:|'];
  for (const m of merged.values()) {
    const sorted = [...m.gas].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    lines.push(`| ${m.operation} | ${m.detail.replaceAll('|', '\\|')} | ${sorted[Math.floor(sorted.length / 2)]} | ${sorted.length} |`);
  }
  return lines.join('\n');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runGas().then((r) => console.log(gasTable(r))).catch((e) => { console.error(e); process.exit(1); });
}
