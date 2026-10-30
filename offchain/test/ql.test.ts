import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse } from '../src/ql/parser.ts';
import { pretty } from '../src/ql/ast.ts';
import { normalise, classify, casMode } from '../src/ql/logic.ts';
import { runExhaustive } from '../src/ql/exhaustive.ts';
import { compileGuard, ChainCompileError, type Op } from '../src/ql/programs.ts';
import type { Binding } from '../src/ql/compile.ts';

const cases: [string, string, string, string][] = [
  // query, NNF, class, CAS mode
  ['forall x in S. NotRevoked(x)', 'forall x in S. NotRevoked(x)', 'co-stable', 'group'],
  ['forall x in S. Active(x)', 'forall x in S. NotRevoked(x)', 'co-stable', 'group'],
  ['!(exists x in S. Active(x))', 'forall x in S. Revoked(x)', 'stable', 'none'],
  // one status atom: Issued(x) and NotIssued(x) are constants on every domain
  ['exists x in S. Revoked(x) & NotIssued(x)', 'false', 'state-independent', 'none'],
  ['(forall x in S. Issued(x)) & exists y in T. Revoked(y)', 'exists y in T. Revoked(y)', 'stable', 'none'],
  ['!(forall x in S. NotRevoked(x))', 'exists x in S. Revoked(x)', 'stable', 'none'],
  ['exists x in S. Revoked(x)', 'exists x in S. Revoked(x)', 'stable', 'none'],
  ['forall x in Issued. Revoked(x)', 'forall x in Issued. Revoked(x)', 'volatile', 'global'],
  ['(exists x in M. Revoked(x)) & (forall y in P. NotRevoked(y))', '(exists x in M. Revoked(x)) & (forall y in P. NotRevoked(y))', 'volatile', 'group'],
  ['atmost 1 x in S. Revoked(x)', 'atmost 1 x in S. Revoked(x)', 'co-stable', 'group'],
  ['!(atmost 1 x in S. Revoked(x))', 'atleast 2 x in S. Revoked(x)', 'stable', 'none'],
  ['atmost 2 x in Issued. NotRevoked(x)', 'atmost 2 x in Issued. NotRevoked(x)', 'volatile', 'global'],
  ['exists x in Presented. Sig(x, "Landlord") & Active(x)', 'exists x in Presented. Sig(x, "Landlord") & NotRevoked(x)', 'co-stable', 'global'],
  ['∃x ∈ Presented. ∃y ∈ Presented. Sig(x, "Uni") ∧ Sig(y, "Emp") ∧ SameHolder(x, y)', 'exists x in Presented. exists y in Presented. Sig(x, "Uni") & Sig(y, "Emp") & SameHolder(x, y)', 'state-independent', 'none'],
  ['(exists x in S. Revoked(x)) -> forall y in T. NotRevoked(y)', '(forall x in S. NotRevoked(x)) | (forall y in T. NotRevoked(y))', 'co-stable', 'group'],
  ['exists x in S. Revoked(x) -> forall y in T. NotRevoked(y)', 'exists x in S. NotRevoked(x) | (forall y in T. NotRevoked(y))', 'co-stable', 'group'],
];

test('parse, normalise, classify, CAS mode', () => {
  for (const [q, n, c, m] of cases) {
    const f = parse(q);
    assert.equal(pretty(normalise(f)), n, q);
    assert.equal(classify(f), c, q);
    assert.equal(casMode(f), m, q);
  }
});

test('parse errors', () => {
  assert.throws(() => parse('forall x in S NotRevoked(x)'));
  assert.throws(() => parse('Revoked(x, y)'));
  assert.throws(() => parse('Foo(x)'));
});

test('classification is sound on every pair of states (|U| = 3)', () => {
  for (const domainsIssued of [false, true]) {
    const rows = runExhaustive({
      universe: [1n, 2n, 3n], groups: new Map([['S', [1n, 2n]], ['T', [2n, 3n]]]), presented: [1n, 3n],
      domainsIssued, formulas: 400, maxDepth: 3, seed: 7,
    });
    for (const r of rows) assert.equal(r.violations, 0, `${r.verdict}: ${r.example}`);
  }
});

const bindings: [string, Binding][] = [
  ['S', { kind: 'group', groupId: '0x01', registryId: '0x0a', members: [1n, 2n] }],
  ['T', { kind: 'group', groupId: '0x02', registryId: '0x0a', members: [2n, 3n] }],
  ['Landlord', { kind: 'creddef', credDefId: '0x0c' }],
  ['Interest', { kind: 'registry', registryId: '0x0a' }],
  ['Issued', { kind: 'registry', registryId: '0x0a' }],
];
const [S, T, Landlord, Interest, Issued] = [0, 1, 2, 3, 4];
const Q = { all: 0, exists: 1, atleast: 2, atmost: 3 }, D = { group: 0, issued: 1, presented: 2 }, P = { neutral: 0, up: 1, down: 2 };
const clause = (quant: number, k: number, domain: number, binding: number, body: number): Op => ({ kind: 0, quant, k, domain, binding, body });
const AND: Op = { kind: 1, quant: 0, k: 0, domain: 0, binding: 0, body: 0 };
const OR: Op = { kind: 2, quant: 0, k: 0, domain: 0, binding: 0, body: 0 };

test('compile the example guards into presented and public programs (GUARDS.md)', () => {
  const cases: [string, Op[], Op[], string, string][] = [
    ['forall x in S. NotRevoked(x)', [], [clause(Q.all, 0, D.group, S, P.down)], 'state-independent', 'co-stable'],
    ['exists x in Presented. Sig(x, "Interest") & Revoked(x)', [clause(Q.exists, 0, D.presented, Interest, P.up)], [], 'stable', 'state-independent'],
    ['(exists x in Presented. Sig(x, "Interest") & Active(x)) & atmost 1 y in Issued. NotRevoked(y)',
      [clause(Q.exists, 0, D.presented, Interest, P.down)], [clause(Q.atmost, 1, D.issued, Issued, P.down)], 'co-stable', 'volatile'],
    ['!(forall x in S. NotRevoked(x))', [], [clause(Q.exists, 0, D.group, S, P.up)], 'state-independent', 'stable'],
    // postfix, and the conjuncts of each part in the order they appear
    ['((forall x in S. NotRevoked(x)) | exists y in T. Revoked(y)) & (atleast 2 z in Presented. Sig(z, "Landlord")) & atmost 0 w in T. Revoked(w)',
      [clause(Q.atleast, 2, D.presented, Landlord, P.neutral)],
      [clause(Q.all, 0, D.group, S, P.down), clause(Q.exists, 0, D.group, T, P.up), OR, clause(Q.atmost, 0, D.group, T, P.up), AND],
      'state-independent', 'volatile'],
    ['forall x in S. Issued(x)', [], [], 'state-independent', 'state-independent'],
  ];
  for (const [q, presented, pub, pc, uc] of cases) {
    const g = compileGuard(parse(q), bindings);
    assert.deepEqual(g.presented, presented, q);
    assert.deepEqual(g.public, pub, q);
    assert.equal(g.presentedClass, pc, q);
    assert.equal(g.publicClass, uc, q);
  }
});

test('a query that does not split as presented ∧ public stays off-chain', () => {
  for (const q of [
    'exists x in S. Sig(x, "Landlord") & Revoked(x)',                                  // holder-bound over a group
    '(exists x in Presented. Sig(x, "Interest") & Revoked(x)) | forall y in S. NotRevoked(y)', // mixed under ∨
    'exists x in Presented. NotRevoked(x)',                                             // registry not named
    'exists x in Presented. Sig(x, "Landlord") & NotRevoked(x)',                        // a CredDef has many registries
    'exists x in Presented. Sig(x, "Interest") & forall y in S. NotRevoked(y)',         // state-dependent nested clause
    'forall x in Presented. Sig(x, "Interest")',
    'forall x in S. exists y in T. Revoked(y)',
    'exists x in S. NotIssued(x)',
  ]) assert.throws(() => compileGuard(parse(q), bindings), ChainCompileError, q);
});
