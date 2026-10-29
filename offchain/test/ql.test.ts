import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse } from '../src/ql/parser.ts';
import { pretty } from '../src/ql/ast.ts';
import { normalise, classify, casMode } from '../src/ql/logic.ts';
import { runExhaustive } from '../src/ql/exhaustive.ts';

const cases: [string, string, string, string][] = [
  // query, NNF, class, CAS mode
  ['forall x in S. NotRevoked(x)', 'forall x in S. NotRevoked(x)', 'co-stable', 'group'],
  ['forall x in S. Active(x)', 'forall x in S. Issued(x) & NotRevoked(x)', 'co-stable', 'group'],
  ['!(exists x in S. Active(x))', 'forall x in S. NotIssued(x) | Revoked(x)', 'stable', 'none'],
  ['!(forall x in S. NotRevoked(x))', 'exists x in S. Revoked(x)', 'stable', 'none'],
  ['exists x in S. Revoked(x)', 'exists x in S. Revoked(x)', 'stable', 'none'],
  ['forall x in Issued. Revoked(x)', 'forall x in Issued. Revoked(x)', 'volatile', 'global'],
  ['(exists x in M. Revoked(x)) & (forall y in P. NotRevoked(y))', '(exists x in M. Revoked(x)) & (forall y in P. NotRevoked(y))', 'volatile', 'group'],
  ['atmost 1 x in S. Revoked(x)', 'atmost 1 x in S. Revoked(x)', 'co-stable', 'group'],
  ['!(atmost 1 x in S. Revoked(x))', 'atleast 2 x in S. Revoked(x)', 'stable', 'none'],
  ['atmost 2 x in Issued. NotRevoked(x)', 'atmost 2 x in Issued. NotRevoked(x)', 'volatile', 'global'],
  ['exists x in Presented. Sig(x, "Landlord") & Active(x)', 'exists x in Presented. Sig(x, "Landlord") & (Issued(x) & NotRevoked(x))', 'co-stable', 'global'],
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
