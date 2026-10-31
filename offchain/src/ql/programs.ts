// The two postfix programs a policy is registered with (design/GUARDS.md, layer 2). The guard is
// `presented ∧ public`:
//  - the presented program has clauses over Presented; the holder proves them off-chain, the contract
//    classifies them for presentation use; any nonempty presented program is rejected for updates;
//  - the public program has clauses over groups and Issued whose body is exactly Revoked(x) or
//    NotRevoked(x); the contract evaluates them with counters when the update executes.
// Both are compiled from the normalised AST the prover proves from. A query that does not split
// this way cannot be bound to an on-chain action, but it can still be proved and verified off-chain.
import { encodeBytes32String } from 'ethers';
import type { Formula } from './ast.ts';
import { pretty } from './ast.ts';
import { analyse, CompileError, type Binding } from './compile.ts';
import { polarity, classOf, type FormulaClass, type Pol } from './logic.ts';

// the contract's enums, in declaration order (src/PolicyRegistry.sol)
export const OP_KIND = { clause: 0, and: 1, or: 2 } as const;
export const QUANT = { forall: 0, exists: 1, atleast: 2, atmost: 3 } as const;
export const DOMAIN = { group: 0, issued: 1, presented: 2 } as const;
export const POLARITY: Record<Pol, number> = { neutral: 0, up: 1, down: 2, mixed: 3 };
export const BINDING_KIND = { group: 0, registry: 1, creddef: 2 } as const;
export const CLASSES: FormulaClass[] = ['state-independent', 'stable', 'co-stable', 'volatile'];
export const MAX_OPS = 32;

/** PolicyRegistry.Op, field for field */
export interface Op { kind: number; quant: number; k: number; domain: number; binding: number; body: number }

export interface GuardPrograms {
  presented: Op[];
  public: Op[];
  presentedClass: FormulaClass;
  publicClass: FormulaClass;
}

/** the query is fine off-chain but cannot be bound to an on-chain action */
export class ChainCompileError extends CompileError {}

/** PolicyRegistry.Binding for each [name, binding]; names are short strings stored as bytes32 */
export function chainBindings(bindings: [string, Binding][]): { name: string; kind: number; target: string }[] {
  return bindings.map(([name, b]) => ({
    name: encodeBytes32String(name), kind: BINDING_KIND[b.kind],
    target: b.kind === 'group' ? b.groupId : b.kind === 'registry' ? b.registryId : b.credDefId,
  }));
}

const clauseOp = (quant: number, k: number, domain: number, binding: number, body: number): Op =>
  ({ kind: OP_KIND.clause, quant, k, domain, binding, body });
const connective = (kind: 'and' | 'or'): Op => ({ kind: OP_KIND[kind], quant: 0, k: 0, domain: 0, binding: 0, body: 0 });

type Quant = Extract<Formula, { t: 'quant' }>;

/** the conjuncts of a formula: nested conjunctions flattened */
function conjuncts(f: Formula): Formula[] {
  return f.t === 'and' ? f.fs.flatMap(conjuncts) : [f];
}

/** the clauses (top-level quantifiers) under the and / or tree of a conjunct */
function clauses(f: Formula): Quant[] {
  if (f.t === 'and' || f.t === 'or') return f.fs.flatMap(clauses);
  if (f.t === 'quant') return [f];
  throw new ChainCompileError(`${pretty(f)} is not a quantified clause`);
}

const isPresented = (q: Quant): boolean => q.dom.kind === 'presented';

export function compileGuard(query: Formula, bindings: [string, Binding][]): GuardPrograms {
  const index = new Map<string, number>();
  bindings.forEach(([name], i) => {
    if (index.has(name)) throw new CompileError(`duplicate binding name ${name}`);
    index.set(name, i);
  });
  const f = analyse(query).normalised;
  if (f.t === 'const' && !f.v) throw new ChainCompileError('the query is false in every state');
  const parts: { presented: Formula[]; public: Formula[] } = { presented: [], public: [] };
  if (f.t !== 'const') {
    for (const c of conjuncts(f)) {
      const cs = clauses(c);
      const presented = cs.filter(isPresented).length;
      if (presented !== 0 && presented !== cs.length) {
        throw new ChainCompileError(`${pretty(c)} mixes presented and public clauses under a disjunction, so the query does not split as presented ∧ public`);
      }
      parts[presented ? 'presented' : 'public'].push(c);
    }
  }

  const bindingOf = (name: string, kinds: Binding['kind'][], what: string): number => {
    const i = index.get(name);
    if (i === undefined) throw new CompileError(`unbound name ${name}`);
    if (!kinds.includes(bindings[i]![1].kind)) throw new ChainCompileError(`${what}: ${name} must be bound to a ${kinds.join(' or ')}`);
    return i;
  };

  const publicClause = (q: Quant): Op => {
    const b = q.body;
    if (b.t !== 'atom' || (b.name !== 'Revoked' && b.name !== 'NotRevoked') || b.args[0] !== q.v) {
      throw new ChainCompileError(`${pretty(q)}: a clause over a group or Issued must have the body Revoked(${q.v}) or NotRevoked(${q.v})`);
    }
    const name = (q.dom as { name: string }).name;
    const binding = q.dom.kind === 'group' ? bindingOf(name, ['group'], pretty(q)) : bindingOf(name, ['registry'], pretty(q));
    return clauseOp(QUANT[q.q], q.k, DOMAIN[q.dom.kind as 'group' | 'issued'], binding, POLARITY[b.name === 'Revoked' ? 'up' : 'down']);
  };

  const presentedClause = (q: Quant): Op => {
    if (q.q === 'forall' || q.q === 'atmost') throw new ChainCompileError(`${pretty(q)}: over Presented only exists and at least k mean anything`);
    const body = polarity(q.body);
    const sigs = (g: Formula, direct: boolean): string[] => {
      if (g.t === 'atom') return g.name === 'Sig' && g.args[0] === q.v ? [g.args[1]!] : [];
      if (g.t === 'and') return g.fs.flatMap((h) => sigs(h, direct));
      if (direct) return [];
      if (g.t === 'or') return g.fs.flatMap((h) => sigs(h, direct));
      if (g.t === 'quant') return sigs(g.body, direct);
      return [];
    };
    let binding: number;
    if (body === 'neutral') {
      // only credential atoms: the binding names the CredDef or registry and is never compared
      const name = sigs(q.body, false).find((n) => index.has(n));
      if (name === undefined) throw new ChainCompileError(`${pretty(q)}: name the CredDef or registry of ${q.v} with Sig(${q.v}, …)`);
      binding = bindingOf(name, ['registry', 'creddef'], pretty(q));
    } else {
      // the contract compares the version of this registry, so every state-dependent atom must be about
      // a credential of it: a direct conjunct Sig(x, R), and no state-dependent nested quantifier
      const nested = (g: Formula): Quant[] =>
        g.t === 'quant' ? [g] : g.t === 'and' || g.t === 'or' ? g.fs.flatMap(nested) : g.t === 'not' ? nested(g.f) : [];
      const dependent = nested(q.body).find((g) => polarity(g) !== 'neutral');
      if (dependent) throw new ChainCompileError(`${pretty(q)}: the nested ${pretty(dependent)} depends on the state; make it a clause of its own`);
      const name = sigs(q.body, true).find((n) => bindings[index.get(n) ?? -1]?.[1].kind === 'registry');
      if (name === undefined) throw new ChainCompileError(`${pretty(q)}: name the registry of ${q.v} with a conjunct Sig(${q.v}, R), R bound to a registry`);
      binding = index.get(name)!;
    }
    return clauseOp(QUANT[q.q], q.q === 'atleast' ? q.k : 0, DOMAIN.presented, binding, POLARITY[body]);
  };

  /** postfix: operands first, then the connective */
  const emit = (g: Formula, ops: Op[]): void => {
    if (g.t === 'and' || g.t === 'or') {
      g.fs.forEach((h, i) => { emit(h, ops); if (i > 0) ops.push(connective(g.t as 'and' | 'or')); });
      return;
    }
    const q = g as Quant;
    ops.push(isPresented(q) ? presentedClause(q) : publicClause(q));
  };
  const program = (fs: Formula[]): Op[] => {
    const ops: Op[] = [];
    fs.forEach((c, i) => { emit(c, ops); if (i > 0) ops.push(connective('and')); });
    if (ops.length > MAX_OPS) throw new ChainCompileError(`a program of ${ops.length} operations is longer than ${MAX_OPS}`);
    return ops;
  };

  return {
    presented: program(parts.presented),
    public: program(parts.public),
    presentedClass: classOf(polarity({ t: 'and', fs: parts.presented })),
    publicClass: classOf(polarity({ t: 'and', fs: parts.public })),
  };
}

