// Exhaustive semantic check of the classification: random closed formulas, every pair Σ ⊑ Σ'
// of states over a universe of 4 IDs, in the system model and in the thesis' general model.
// Then the same system-model formulas against the contract (anvil, Prague): each one that compiles
// to the two programs must be accepted by registerPolicy, and PolicyRegistry.classify must return
// the front end's class for both programs. The same holds for every clause shape the contract accepts
// and every pair of them, which the random formulas cover only thinly. Any mismatch fails the run.
import { ethers } from 'ethers';
import { runExhaustive, enumerateFormulas, type ExhaustiveRow } from '../src/ql/exhaustive.ts';
import { pretty, type Formula, type Domain, type QuantKind } from '../src/ql/ast.ts';
import type { Binding } from '../src/ql/compile.ts';
import { compileGuard, chainBindings, ChainCompileError, CLASSES, type GuardPrograms } from '../src/ql/programs.ts';
import { deployAll, revertName, type Deployment } from '../src/chain/client.ts';
import type { FormulaClass } from '../src/ql/logic.ts';

const RPC = process.argv[2] ?? 'http://127.0.0.1:8545';
const KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // anvil default account

const base = {
  universe: [1n, 2n, 3n, 4n],
  groups: new Map([['S', [1n, 2n, 3n]], ['T', [2n, 4n]]]),
  presented: [1n, 4n],
  formulas: 3000, maxDepth: 4, seed: 2026,
};

export function runClassification(formulas = base.formulas): { model: string; rows: ExhaustiveRow[] }[] {
  return [
    { model: 'system model (domains hold issued IDs)', rows: runExhaustive({ ...base, formulas, domainsIssued: true }) },
    { model: 'general model (groups of arbitrary IDs)', rows: runExhaustive({ ...base, formulas, domainsIssued: false }) },
  ];
}

export function classificationTable(res: ReturnType<typeof runClassification>): string {
  const lines = ['| Model | Verdict | Formulas | Violations | Volatile but semantically (co-)stable |', '|---|---|---:|---:|---:|'];
  for (const { model, rows } of res) for (const r of rows) lines.push(`| ${model} | ${r.verdict} | ${r.formulas} | ${r.violations} | ${r.verdict === 'volatile' ? r.gap : '–'} |`);
  return lines.join('\n');
}

export interface ChainCheck {
  label: string;
  formulas: number;
  compiled: number;
  /** compiled to two empty programs: the formula folds to true */
  trivial: number;
  /** compiled formulas by presented class, then public class */
  byClass: Record<FormulaClass, Record<FormulaClass, number>>;
  mismatches: string[];
}

/** the bindings the enumerated formulas use; registerPolicy does not look at the targets */
const BINDINGS: [string, Binding][] = [
  ['S', { kind: 'group', groupId: ethers.id('S'), registryId: ethers.id('R'), members: base.groups.get('S')! }],
  ['T', { kind: 'group', groupId: ethers.id('T'), registryId: ethers.id('R'), members: base.groups.get('T')! }],
  ['Issued', { kind: 'registry', registryId: ethers.id('R') }],
  ['R', { kind: 'registry', registryId: ethers.id('R') }],
];

/** every clause the contract accepts over S, Issued and Presented (k ≤ 2), alone and in pairs: ∧ always, ∨ within a part */
export function clauseShapes(): Formula[] {
  const atom = (name: 'Revoked' | 'NotRevoked' | 'Sig', v: string): Formula => ({ t: 'atom', name, args: name === 'Sig' ? [v, 'R'] : [v] });
  const quant = (q: QuantKind, k: number, dom: Domain, v: string, body: Formula): Formula => ({ t: 'quant', q, k, v, dom, body });
  const counted: [QuantKind, number][] = [['forall', 0], ['exists', 0], ['atleast', 0], ['atleast', 1], ['atleast', 2], ['atmost', 0], ['atmost', 1], ['atmost', 2]];
  const publics = (v: string): Formula[] => counted.flatMap(([q, k]) =>
    ([{ kind: 'group', name: 'S' }, { kind: 'issued', name: 'Issued' }] as Domain[]).flatMap((dom) =>
      (['Revoked', 'NotRevoked'] as const).map((b) => quant(q, k, dom, v, atom(b, v)))));
  // over Presented: exists and at least k, with a neutral, up, down and mixed body
  const presentedBodies = (v: string): Formula[] => [
    atom('Sig', v),
    { t: 'and', fs: [atom('Sig', v), atom('Revoked', v)] },
    { t: 'and', fs: [atom('Sig', v), atom('NotRevoked', v)] },
    { t: 'and', fs: [atom('Sig', v), { t: 'or', fs: [atom('Revoked', v), atom('NotRevoked', v)] }] },
  ];
  const presentedQuants: [QuantKind, number][] = [['exists', 0], ['atleast', 0], ['atleast', 1], ['atleast', 2]];
  const presenteds = (v: string): Formula[] => presentedQuants.flatMap(([q, k]) =>
    presentedBodies(v).map((body) => quant(q, k, { kind: 'presented' }, v, body)));
  const all = (v: string) => [...publics(v), ...presenteds(v)];
  const out: Formula[] = all('x');
  for (const a of all('x')) for (const b of all('y')) out.push({ t: 'and', fs: [a, b] });
  for (const part of [publics, presenteds]) for (const a of part('x')) for (const b of part('y')) out.push({ t: 'or', fs: [a, b] });
  return out;
}

export async function runChainClassification(rpc = RPC, formulas = base.formulas): Promise<ChainCheck[]> {
  const provider = new ethers.JsonRpcProvider(rpc, undefined, { pollingInterval: 50, cacheTimeout: -1 });
  const d = await deployAll(new ethers.Wallet(KEY, provider));
  return [
    await checkOnChain(d, 'the enumerated system-model formulas', enumerateFormulas({ ...base, formulas })),
    await checkOnChain(d, 'every clause shape, alone and in pairs', clauseShapes()),
  ];
}

async function checkOnChain(d: Deployment, label: string, fs: Formula[]): Promise<ChainCheck> {
  const policies = d.policies;
  const compiled: [string, GuardPrograms][] = [];
  for (const f of fs) {
    try {
      compiled.push([pretty(f), compileGuard(f, BINDINGS)]);
    } catch (e) {
      if (!(e instanceof ChainCompileError)) throw e;
    }
  }
  const empty = (): Record<FormulaClass, number> => ({ 'state-independent': 0, stable: 0, 'co-stable': 0, volatile: 0 });
  const byClass = { 'state-independent': empty(), stable: empty(), 'co-stable': empty(), volatile: empty() };
  const mismatches: string[] = [];
  const bindings = chainBindings(BINDINGS);
  const check = async ([query, g]: [string, GuardPrograms]): Promise<void> => {
    try {
      await policies.registerPolicy!.staticCall(query, bindings, g.presented, g.public);
      const [pc, uc] = await Promise.all([policies.classify!(g.presented), policies.classify!(g.public)]);
      const [presented, pub] = [CLASSES[Number(pc)]!, CLASSES[Number(uc)]!];
      if (presented !== g.presentedClass || pub !== g.publicClass) {
        mismatches.push(`${query}: front end ${g.presentedClass} / ${g.publicClass}, contract ${presented} / ${pub}`);
      }
      byClass[g.presentedClass][g.publicClass]++;
    } catch (e) {
      mismatches.push(`${query}: registerPolicy rejected the programs: ${revertName(d, e)}`);
    }
  };
  for (let i = 0; i < compiled.length; i += 64) await Promise.all(compiled.slice(i, i + 64).map(check));
  const trivial = compiled.filter(([, g]) => g.presented.length === 0 && g.public.length === 0).length;
  return { label, formulas: fs.length, compiled: compiled.length, trivial, byClass, mismatches };
}

export function chainTable(c: ChainCheck): string {
  const lines = [`| presented \\ public | ${CLASSES.join(' | ')} |`, `|---|${CLASSES.map(() => '---:').join('|')}|`];
  for (const p of CLASSES) lines.push(`| ${p} | ${CLASSES.map((u) => c.byClass[p][u]).join(' | ')} |`);
  return lines.join('\n');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(classificationTable(runClassification()));
  const checks = await runChainClassification();
  for (const c of checks) {
    console.log(`\nagainst the contract, ${c.label}: ${c.formulas} formulas, ${c.compiled} compile to the two programs, ${c.mismatches.length} mismatches\n`);
    console.log(chainTable(c));
    for (const m of c.mismatches.slice(0, 20)) console.error(m);
  }
  if (checks.some((c) => c.mismatches.length)) process.exit(1);
}
