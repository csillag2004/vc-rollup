// Desugaring, negation normal form, classification (thesis Lemmas atom-classes and closure,
// extended with the polarity rules for the Issued domain) and the CAS mode a guard needs.
import { type Formula, type Domain, DUAL, isRegAtom, domainsOf, freeVars } from './ast.ts';

/**
 * The system model: every domain holds issued credentials only (groups are anchored over issued IDs,
 * a presented credential carries the issuer's signature, and Issued is the issued set). Then
 * Issued(x) is constantly true for a bound x. The thesis' general model (groups of arbitrary IDs)
 * is kept as an option for the exhaustive check.
 */
export interface Model { domainsIssued: boolean }
export const SYSTEM_MODEL: Model = { domainsIssued: true };

/** Active(x) = Issued(x) ∧ NotRevoked(x); in the system model this is NotRevoked(x). */
export function desugar(f: Formula, m: Model = SYSTEM_MODEL): Formula {
  switch (f.t) {
    case 'atom':
      if (f.name !== 'Active') return f;
      return m.domainsIssued ? { t: 'atom', name: 'NotRevoked', args: f.args }
        : { t: 'and', fs: [{ t: 'atom', name: 'Issued', args: f.args }, { t: 'atom', name: 'NotRevoked', args: f.args }] };
    case 'not': return { t: 'not', f: desugar(f.f, m) };
    case 'and': case 'or': return { t: f.t, fs: f.fs.map((g) => desugar(g, m)) };
    case 'implies': return { t: 'or', fs: [{ t: 'not', f: desugar(f.a, m) }, desugar(f.b, m)] };
    case 'quant': return { ...f, body: desugar(f.body, m) };
    default: return f;
  }
}

/** push negations to the atoms; dual registry atoms replace negated ones; ¬Sig stays as a negated literal */
export function nnf(f: Formula, neg = false): Formula {
  switch (f.t) {
    case 'const': return { t: 'const', v: f.v !== neg };
    case 'atom':
      if (!neg) return f;
      if (isRegAtom(f.name)) return { t: 'atom', name: DUAL[f.name], args: f.args };
      return { t: 'not', f };
    case 'not': return nnf(f.f, !neg);
    case 'and': return { t: neg ? 'or' : 'and', fs: f.fs.map((g) => nnf(g, neg)) };
    case 'or': return { t: neg ? 'and' : 'or', fs: f.fs.map((g) => nnf(g, neg)) };
    case 'implies': return nnf({ t: 'or', fs: [{ t: 'not', f: f.a }, f.b] }, neg);
    case 'quant': {
      if (!neg) return { ...f, body: nnf(f.body, false) };
      const body = nnf(f.body, true);
      switch (f.q) {
        case 'forall': return { ...f, q: 'exists', k: 0, body };
        case 'exists': return { ...f, q: 'forall', k: 0, body };
        // ¬ atleast k φ = atmost k−1 φ;  ¬ atmost k φ = atleast k+1 φ
        case 'atleast': return f.k === 0 ? { t: 'const', v: false } : { ...f, q: 'atmost', k: f.k - 1, body: nnf(f.body) };
        case 'atmost': return { ...f, q: 'atleast', k: f.k + 1, body: nnf(f.body) };
      }
    }
  }
}

export function normalise(f: Formula, m: Model = SYSTEM_MODEL): Formula {
  return nnf(desugar(f, m));
}

// ---- classification ----

export type Pol = 'neutral' | 'up' | 'down' | 'mixed';
export type FormulaClass = 'state-independent' | 'stable' | 'co-stable' | 'volatile';

const join = (a: Pol, b: Pol): Pol => (a === 'neutral' ? b : b === 'neutral' ? a : a === b ? a : 'mixed');
const flip = (a: Pol): Pol => (a === 'up' ? 'down' : a === 'down' ? 'up' : a);

/** polarity: ↑ true stays true along ⊑ (stable), ↓ false stays false (co-stable) */
export function polarity(f: Formula, m: Model = SYSTEM_MODEL): Pol {
  switch (f.t) {
    case 'const': return 'neutral';
    case 'atom':
      // in the system model Issued(x) / NotIssued(x) of a bound x are constants
      if ((f.name === 'Issued' || f.name === 'NotIssued') && m.domainsIssued) return 'neutral';
      if (f.name === 'Revoked' || f.name === 'Issued') return 'up';
      if (f.name === 'NotRevoked' || f.name === 'NotIssued') return 'down';
      if (f.name === 'Active') return 'mixed';
      return 'neutral';
    case 'not': return flip(polarity(f.f, m));
    case 'and': case 'or': return f.fs.map((g) => polarity(g, m)).reduce(join, 'neutral');
    case 'implies': return join(flip(polarity(f.a, m)), polarity(f.b, m));
    case 'quant': {
      const b = polarity(f.body, m);
      if (f.dom.kind !== 'issued') return f.q === 'atmost' ? flip(b) : b;
      // the Issued domain grows: a hidden NotIssued under ∀, a hidden Issued under ∃ / at least
      if (f.q === 'forall') return join('down', b);
      if (f.q === 'atmost') return join('down', flip(b));
      return join('up', b);
    }
  }
}

export function classify(f: Formula, m: Model = SYSTEM_MODEL): FormulaClass {
  const p = polarity(normalise(f, m), m);
  return p === 'neutral' ? 'state-independent' : p === 'up' ? 'stable' : p === 'down' ? 'co-stable' : 'volatile';
}

export type CasMode = 'none' | 'group' | 'global';

/**
 * Which comparison a guard needs (thesis Def. fresh guard):
 * stable / state-independent: none; all domains are groups: group versions; otherwise global versions.
 */
export function casMode(f: Formula, m: Model = SYSTEM_MODEL): CasMode {
  const c = classify(f, m);
  if (c === 'stable' || c === 'state-independent') return 'none';
  return domainsOf(f).every((d) => d.kind === 'group') ? 'group' : 'global';
}

export function wellFormed(f: Formula): string[] {
  const errs: string[] = [];
  const fv = freeVars(f);
  if (fv.size) errs.push(`free variables: ${[...fv].join(', ')}`);
  const walk = (g: Formula, bound: string[]): void => {
    if (g.t === 'quant') {
      if (bound.includes(g.v)) errs.push(`variable ${g.v} shadows an outer one`);
      walk(g.body, [...bound, g.v]);
    } else if (g.t === 'not') walk(g.f, bound);
    else if (g.t === 'and' || g.t === 'or') g.fs.forEach((h) => walk(h, bound));
    else if (g.t === 'implies') { walk(g.a, bound); walk(g.b, bound); }
  };
  walk(f, []);
  return errs;
}

export const domainsAreGroups = (ds: Domain[]): boolean => ds.every((d) => d.kind === 'group');
