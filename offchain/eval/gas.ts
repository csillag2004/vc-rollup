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
    const w = await record('issueUpdate', i === 0 ? 'public ID + 2 pairing checks' : 'repeated', () => issuer.issue(reg, ['flat', `h${i}`], h.linkSecret));
    h.wallet.push(w);
  }
  const ys = holders.map((h) => h.wallet[0]!.scalars[0]!);
  for (const n of [2, 4, 8, 16]) {
    await record('createGroup', `|S| = ${n} (issued-ID storage checks)`, () => issuer.createGroup(reg, `g${n}`, ys.slice(0, n)));
  }
  // All control variants start from the identical state, with all policies already registered.
  // The action is unbound here so its bare path is callable. The later bound-policy row is separate.
  const g = await readGroup(d, await issuer.createGroup(reg, 'control-group', ys.slice(0, 4)));
  const pGroup = await record('registerPolicy', 'public group predicate', () =>
    issuer.registerPolicy('forall x in S. NotRevoked(x)', [['S', g]]));
  const pRegistry = await issuer.registerPolicy('forall x in Issued. NotRevoked(x)',
    [['Issued', { kind: 'registry', registryId: reg }]]);
  const groupProof = await holders[0]!.present(pGroup.query, pGroup.bindings, 'control-group');
  const registryProof = await holders[0]!.present(pRegistry.query, pRegistry.bindings, 'control-registry');
  const isolated = async (fn: () => Promise<unknown>) => {
    const snapshot: string = await provider.send('evm_snapshot', []);
    try { await fn(); } finally {
      if (!await provider.send('evm_revert', [snapshot])) throw new Error('failed to restore gas control state');
    }
  };
  await isolated(() => record('revoke', 'control: bare update, identical pre-state', () => issuer.revoke(reg, ys[0]!)));
  await isolated(() => record('guardedRevoke', 'control: public group guard, identical pre-state', () =>
    issuer.guardedRevoke(reg, ys[0]!, pGroup, groupProof)));
  await isolated(() => record('guardedRevoke', 'control: public registry guard, identical pre-state', () =>
    issuer.guardedRevoke(reg, ys[0]!, pRegistry, registryProof)));

  await (await d.policies.bindPolicy!(issuer.credDefId, 1, pGroup.policyId)).wait();
  await record('guardedRevoke', 'permanently bound public group guard', () =>
    issuer.guardedRevoke(reg, ys[0]!, pGroup, groupProof));
  const issueGroup = await readGroup(d, await issuer.createGroup(reg, 'issue-guard', ys.slice(8, 12)));
  const issuePolicy = await issuer.registerPolicy('forall x in S. NotRevoked(x)', [['S', issueGroup]], 'issue');
  const issueProof = await holders[8]!.present(issuePolicy.query, issuePolicy.bindings, 'guarded-issue');
  await record('guardedIssueUpdate', 'permanently bound public group guard + public ID', () =>
    issuer.issue(reg, ['flat', 'guarded-holder'], holders[8]!.linkSecret, { policy: issuePolicy, presentation: issueProof }));
  return rows;
}

export function gasTable(rows: GasRow[]): string {
  const merged = new Map<string, { operation: string; detail: string; gas: bigint[] }>();
  for (const r of rows) {
    const k = `${r.operation}|${r.detail === 'repeated' ? 'public ID + 2 pairing checks' : r.detail}`;
    const m = merged.get(k) ?? { operation: r.operation, detail: r.detail === 'repeated' ? 'public ID + 2 pairing checks' : r.detail, gas: [] };
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
