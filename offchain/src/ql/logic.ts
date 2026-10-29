// Desugaring, negation normal form, constant folding, classification (thesis Lemmas atom-classes and
// closure, extended with the polarity rules for the Issued domain) and the freshness check a reader needs.
import { type Formula, type Domain, DUAL, isRegAtom, domainsOf, freeVars } from './ast.ts';

/**
 * The system model: every domain holds issued credentials only (createGroup checks every member in
 * storage, a presented credential carries the issuer's signature, and Issued is the issued set). Then
 * Issued(x) is constantly true for a bound x. The thesis' general model (groups of arbitrary IDs)
 * is kept as an option for the exhaustive check.
 */
export interface Model { domainsIssued: boolean }
export const SYSTEM_MODEL: Model = { domainsIssued: true };

/**
 * The system model has one status atom, Revoked(x), with NotRevoked(x) its negation (design/GUARDS.md):
 * every domain holds issued IDs only, so Issued(x) is true, NotIssued(x) false and Active(x) = NotRevoked(x)
 * for a bound x. The general model keeps Active(x) = Issued(x) ∧ NotRevoked(x) and both Issued atoms.
 */
export function desugar(f: Formula, m: Model = SYSTEM_MODEL): Formula {
  switch (f.t) {
    case 'atom':
      if (m.domainsIssued) {
        if (f.name === 'Active') return { t: 'atom', name: 'NotRevoked', args: f.args };
        if (f.name === 'Issued' || f.name === 'NotIssued') return { t: 'const', v: f.name === 'Issued' };
        return f;
      }
      if (f.name !== 'Active') return f;
      return { t: 'and', fs: [{ t: 'atom', name: 'Issued', args: f.args }, { t: 'atom', name: 'NotRevoked', args: f.args }] };
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

/** constant folding; a quantifier folds only where its value does not depend on the domain */
export function fold(f: Formula): Formula {
  switch (f.t) {
    case 'and': case 'or': {
      // true is the unit of ∧ and absorbs ∨; false the other way round
      const unit = f.t === 'and';
      const fs: Formula[] = [];
      for (const g of f.fs.map(fold)) {
        if (g.t !== 'const') fs.push(g);
        else if (g.v !== unit) return g;
      }
      return fs.length === 0 ? { t: 'const', v: unit } : fs.length === 1 ? fs[0]! : { t: f.t, fs };
    }
    case 'quant': {
      const body = fold(f.body);
      if (body.t === 'const' && body.v && f.q === 'forall') return body;
      if (body.t === 'const' && !body.v && f.q !== 'forall') return { t: 'const', v: f.q === 'atmost' || (f.q === 'atleast' && f.k === 0) };
      return { ...f, body };
    }
    case 'not': return { t: 'not', f: fold(f.f) };
    default: return f;
  }
}

export function normalise(f: Formula, m: Model = SYSTEM_MODEL): Formula {
  return fold(nnf(desugar(f, m)));
}

// ---- classification ----

export type Pol = 'neutral' | 'up' | 'down' | 'mixed';
export type FormulaClass = 'state-independent' | 'stable' | 'co-stable' | 'volatile';

const join = (a: Pol, b: Pol): Pol => (a === 'neutral' ? b : b === 'neutral' ? a : a === b ? a : 'mixed');
const flip = (a: Pol): Pol => (a === 'up' ? 'down' : a === 'down' ? 'up' : a);

/** polarity: ↑ true stays true along ⊑ (stable), ↓ false stays false (co-stable) */
export function polarity(f: Formula): Pol {
  switch (f.t) {
    case 'const': return 'neutral';
    case 'atom':
      // Issued and NotIssued survive normalisation in the general model only
      if (f.name === 'Revoked' || f.name === 'Issued') return 'up';
      if (f.name === 'NotRevoked' || f.name === 'NotIssued') return 'down';
      if (f.name === 'Active') return 'mixed';
      return 'neutral';
    case 'not': return flip(polarity(f.f));
    case 'and': case 'or': return f.fs.map((g) => polarity(g)).reduce(join, 'neutral');
    case 'implies': return join(flip(polarity(f.a)), polarity(f.b));
    case 'quant': {
      const b = polarity(f.body);
      if (f.dom.kind !== 'issued') return f.q === 'atmost' ? flip(b) : b;
      // the Issued domain grows: a hidden NotIssued under ∀, a hidden Issued under ∃ / at least
      if (f.q === 'forall') return join('down', b);
      if (f.q === 'atmost') return join('down', flip(b));
      return join('up', b);
    }
  }
}

export const classOf = (p: Pol): FormulaClass =>
  (p === 'neutral' ? 'state-independent' : p === 'up' ? 'stable' : p === 'down' ? 'co-stable' : 'volatile');

export function classify(f: Formula, m: Model = SYSTEM_MODEL): FormulaClass {
  return classOf(polarity(normalise(f, m)));
}

export type CasMode = 'none' | 'group' | 'global';

/**
 * How a reader checks that an off-chain presentation is still fresh (thesis Def. fresh guard):
 * stable / state-independent: no comparison; all domains are groups: group versions; otherwise global
 * versions. The contract does not use it: it evaluates the public part of a guard itself and compares
 * registry versions for a co-stable or volatile presented part only (design/GUARDS.md).
 */
export function casMode(f: Formula, m: Model = SYSTEM_MODEL): CasMode {
  const c = classify(f, m);
  if (c === 'stable' || c === 'state-independent') return 'none';
  return domainsOf(normalise(f, m)).every((d) => d.kind === 'group') ? 'group' : 'global';
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
