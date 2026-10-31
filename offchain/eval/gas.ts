// Gas per registry operation on a local Prague chain (anvil), verify on write (EIP-2537).
import { ethers } from 'ethers';
import { deployAll } from '../src/chain/client.ts';
import { Issuer, Holder, readGroup } from '../src/actors/actors.ts';

const RPC = process.env.RPC ?? 'http://127.0.0.1:8545';
const KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // anvil default account

export interface GasRow { operation: string; detail: string; gas: bigint[]; calldataBytes: number[] }

export async function runGas(rpc = RPC, smoke = false): Promise<GasRow[]> {
  const provider = new ethers.JsonRpcProvider(rpc, undefined, { pollingInterval: 50, cacheTimeout: -1 });
  const signer = new ethers.Wallet(KEY, provider);
  const rows: GasRow[] = [];
  /** run fn and collect the gas of every transaction it sent (anvil mines one block per transaction) */
  const record = async <T>(operation: string, detail: string, fn: () => Promise<T>): Promise<T> => {
    const from = await provider.getBlockNumber();
    const out = await fn();
    const to = await provider.getBlockNumber();
    const gas: bigint[] = [];
    const calldataBytes: number[] = [];
    for (let b = from + 1; b <= to; b++) {
      const block = await provider.getBlock(b);
      for (const h of block?.transactions ?? []) {
        gas.push((await provider.getTransactionReceipt(h))!.gasUsed);
        calldataBytes.push(ethers.getBytes((await provider.getTransaction(h))!.data).length);
      }
    }
    rows.push({ operation, detail, gas, calldataBytes });
    return out;
  };

  const d = await deployAll(signer);
  const issuer = new Issuer(signer, d);
  await record('setup', 'BBS key in DID document, schema, CredDef', () => issuer.setUp('Interest', ['flat', 'name']));
  for (const deg of (smoke ? [4] : [4, 8, 16])) {
    await record('createRegistry + publishSrs', `SRS degree ${deg}`, () => issuer.createRegistry(`gas-${deg}`, deg));
  }
  const reg = await issuer.createRegistry('gas-main', 16);
  const holders = Array.from({ length: 16 }, () => new Holder(d));
  for (const [i, h] of holders.entries()) {
    const w = await record('issueUpdate', i === 0 ? 'Schnorr + 2 pairing checks' : 'repeated', () => issuer.issue(reg, ['flat', `h${i}`], h.linkSecret));
    h.wallet.push(w);
  }
  const ys = holders.map((h) => h.wallet[0]!.scalars[0]!);
  for (const n of [2, 4, 8, 16]) {
    await record('createGroup', `|S| = ${n} (on-chain [P_S]_2 + subset check)`, () => issuer.createGroup(reg, `g${n}`, ys.slice(0, n)));
  }
  await record('revoke', 'step + consistency + subset (3 pairing checks)', () => issuer.revoke(reg, ys[15]!));

  // guarded revocations: one per CAS mode, each on its own group
  const g = await readGroup(d, await issuer.createGroup(reg, 'guard-group', ys.slice(4, 8)));
  const gs = await readGroup(d, await issuer.createGroup(reg, 'guard-stable', ys.slice(8, 12)));
  const pGroup = await record('registerPolicy', 'co-stable, group CAS', () => issuer.registerPolicy('forall x in S. NotRevoked(x)', [['S', g]]));
  const globalGroup = await readGroup(d, await issuer.createGroup(reg, 'guard-global', ys.slice(2, 4)));
  const pGlobal = await issuer.registerPolicy('(forall x in S. NotRevoked(x)) & (exists y in Issued. Revoked(y))', [['S', globalGroup], ['Issued', { kind: 'registry', registryId: reg }]]);
  await issuer.revoke(reg, ys[14]!);
  const pStable = await issuer.registerPolicy('exists x in S. Revoked(x)', [['S', gs]]);
  await issuer.revoke(reg, ys[8]!);

  const globalProof = await holders[2]!.present(pGlobal.query, pGlobal.bindings, 'global');
  await record('guardedRevoke', 'global CAS (policy lookup + registry versions)', () => issuer.guardedRevoke(reg, ys[2]!, pGlobal, globalProof));
  const h4 = holders[4]!;
  const pres = await h4.present(pGroup.query, pGroup.bindings, 'g');
  await record('guardedRevoke', 'group CAS (policy lookup + group version)', () => issuer.guardedRevoke(reg, ys[4]!, pGroup, pres));
  const presS = await holders[9]!.present(pStable.query, pStable.bindings, 's');
  await record('guardedRevoke', 'stable guard, no comparison', () => issuer.guardedRevoke(reg, ys[9]!, pStable, presS));
  // Issuance guarded by a still-true co-stable group predicate.
  const issueGroup = await readGroup(d, await issuer.createGroup(reg, 'issue-guard', ys.slice(0, 2)));
  const issuePolicy = await issuer.registerPolicy('forall x in S. NotRevoked(x)', [['S', issueGroup]]);
  const issueProof = await holders[0]!.present(issuePolicy.query, issuePolicy.bindings, 'guarded-issue');
  await record('guardedIssueUpdate', 'group CAS + Schnorr + 2 pairing checks', () =>
    issuer.issue(reg, ['flat', 'guarded-holder'], holders[0]!.linkSecret, { policy: issuePolicy, presentation: issueProof }));
  return rows;
}

export function gasTable(rows: GasRow[]): string {
  const merged = new Map<string, { operation: string; detail: string; gas: bigint[] }>();
  for (const r of rows) {
    const k = `${r.operation}|${r.detail === 'repeated' ? 'Schnorr + 2 pairing checks' : r.detail}`;
    const m = merged.get(k) ?? { operation: r.operation, detail: r.detail === 'repeated' ? 'Schnorr + 2 pairing checks' : r.detail, gas: [] };
    m.gas.push(r.gas.reduce((a, b) => a + b, 0n));
    merged.set(k, m);
  }
  const lines = ['| Operation | Detail | Gas (median of runs) | Runs |', '|---|---|---:|---:|'];
  for (const m of merged.values()) {
    const sorted = [...m.gas].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    lines.push(`| ${m.operation} | ${m.detail} | ${sorted[Math.floor(sorted.length / 2)]} | ${sorted.length} |`);
  }
  return lines.join('\n');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runGas().then((r) => console.log(gasTable(r))).catch((e) => { console.error(e); process.exit(1); });
}
