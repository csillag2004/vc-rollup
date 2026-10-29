// Exhaustive semantic check of the syntactic classification on a small universe:
// every reachable pair of states Σ ⊑ Σ' is enumerated, and each verdict is checked against the
// semantic definitions (stable: true stays true; co-stable: false stays false).
import type { Formula, Domain, QuantKind } from './ast.ts';
import { classify, type FormulaClass } from './logic.ts';
import { holds, type State, type Env } from './semantics.ts';

export interface ExhaustiveConfig {
  universe: bigint[];
  groups: Map<string, bigint[]>;
  presented: bigint[];
  /** the system model: groups and presented credentials hold issued IDs only
   *  (only states with every group and the presented set ⊆ Iss are considered); false = the thesis' general model */
  domainsIssued: boolean;
  formulas: number;
  maxDepth: number;
  seed: number;
}

export interface ExhaustiveRow {
  verdict: FormulaClass;
  formulas: number;
  violations: number;
  /** semantically stable or co-stable although the verdict is volatile (the conservative gap) */
  gap: number;
  example?: string;
}

function states(universe: bigint[]): State[] {
  // each ID is unissued (0), active (1) or revoked (2)
  const out: State[] = [];
  const n = universe.length;
  for (let code = 0; code < 3 ** n; code++) {
    const iss = new Set<bigint>(), rev = new Set<bigint>();
    let c = code;
    for (const y of universe) {
      const s = c % 3; c = Math.floor(c / 3);
      if (s >= 1) iss.add(y);
      if (s === 2) rev.add(y);
    }
    out.push({ iss, rev });
  }
  return out;
}

const leq = (a: State, b: State): boolean => [...a.iss].every((y) => b.iss.has(y)) && [...a.rev].every((y) => b.rev.has(y));

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; };
}

export function randomFormula(r: () => number, depth: number, vars: string[], domains: Domain[]): Formula {
  const pick = <T>(xs: T[]): T => xs[Math.floor(r() * xs.length)]!;
  const atom = (): Formula => (vars.length === 0
    ? { t: 'const', v: r() < 0.5 }
    : { t: 'atom', name: pick(['Revoked', 'NotRevoked', 'Issued', 'NotIssued', 'Active'] as const), args: [pick(vars)] });
  if (depth === 0) return atom();
  const choice = r();
  if (vars.length > 0 && choice < 0.2) return atom();
  if (choice < 0.3) return { t: 'not', f: randomFormula(r, depth - 1, vars, domains) };
  if (choice < 0.45) return { t: 'and', fs: [randomFormula(r, depth - 1, vars, domains), randomFormula(r, depth - 1, vars, domains)] };
  if (choice < 0.6) return { t: 'or', fs: [randomFormula(r, depth - 1, vars, domains), randomFormula(r, depth - 1, vars, domains)] };
  if (choice < 0.65) return { t: 'implies', a: randomFormula(r, depth - 1, vars, domains), b: randomFormula(r, depth - 1, vars, domains) };
  const v = `x${vars.length}`;
  const q = pick<QuantKind>(['forall', 'exists', 'atleast', 'atmost']);
  return { t: 'quant', q, k: q === 'atleast' || q === 'atmost' ? Math.floor(r() * 3) : 0, v, dom: pick(domains), body: randomFormula(r, depth - 1, [...vars, v], domains) };
}

export function runExhaustive(cfg: ExhaustiveConfig): ExhaustiveRow[] {
  const all = states(cfg.universe).filter((s) => !cfg.domainsIssued
    || [...cfg.groups.values(), cfg.presented].every((g) => g.every((y) => s.iss.has(y))));
  const model = { domainsIssued: cfg.domainsIssued };
  const pairs: [State, State][] = [];
  for (const a of all) for (const b of all) if (leq(a, b)) pairs.push([a, b]);
  const domains: Domain[] = [...[...cfg.groups.keys()].map((name) => ({ kind: 'group', name }) as Domain), { kind: 'presented' }, { kind: 'issued', name: 'Issued' }];
  const r = rng(cfg.seed);
  const rows = new Map<FormulaClass, ExhaustiveRow>();
  for (const verdict of ['state-independent', 'stable', 'co-stable', 'volatile'] as FormulaClass[]) {
    rows.set(verdict, { verdict, formulas: 0, violations: 0, gap: 0 });
  }
  const env = (s: State): Env => ({ state: s, states: new Map([['Issued', s]]), groups: cfg.groups, presented: cfg.presented });

  for (let i = 0; i < cfg.formulas; i++) {
    const f = randomFormula(r, 1 + Math.floor(r() * cfg.maxDepth), [], domains);
    const verdict = classify(f, model);
    const row = rows.get(verdict)!;
    row.formulas++;
    let stable = true, coStable = true;
    for (const [a, b] of pairs) {
      const ta = holds(f, env(a)), tb = holds(f, env(b));
      if (ta && !tb) stable = false;
      if (!ta && tb) coStable = false;
      if (!stable && !coStable) break;
    }
    const ok = verdict === 'stable' ? stable : verdict === 'co-stable' ? coStable : verdict === 'state-independent' ? stable && coStable : true;
    if (!ok) {
      row.violations++;
      row.example ??= JSON.stringify(f);
    }
    if (verdict === 'volatile' && (stable || coStable)) row.gap++;
  }
  return [...rows.values()];
}
