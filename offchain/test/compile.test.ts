import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse } from '../src/ql/parser.ts';
import { present, verifyPresentation, type PublicContext, type WalletCredential } from '../src/ql/compile.ts';
import { MemoryRegistry } from '../src/registry/memory.ts';
import * as bbs from '../src/crypto/bbs.ts';
import { utf8ToBytes, randomScalar } from '../src/crypto/bls.ts';

async function world() {
  const kp = await bbs.generateKeyPair();
  const reg = new MemoryRegistry('0xreg', '0xcd', kp.publicKey);
  const header = utf8ToBytes('0xcd');
  const mk = async (name: string, ls: bigint): Promise<WalletCredential> => {
    const msgs = [crypto.getRandomValues(new Uint8Array(32)), utf8ToBytes(name), utf8ToBytes(ls.toString())];
    const scalars = msgs.map(bbs.messageToScalar);
    const sig = await bbs.sign(kp, header, msgs);
    const { receiptA, version } = reg.issue(scalars[0]!);
    return { credDefId: '0xcd', registryId: '0xreg', header, scalars, sig, yIndex: 0, lsIndex: 2, disclose: [], receiptA, receiptVersion: version };
  };
  const ls = randomScalar();
  const alice = await mk('Alice', ls), bob = await mk('Bob', randomScalar()), carol = await mk('Carol', randomScalar());
  const alice2 = await mk('Alice-2', ls);
  const members = [alice, bob, carol].map((c) => c.scalars[0]!).sort((a, b) => (a < b ? -1 : 1));
  const ctx: PublicContext = {
    registries: new Map([['0xreg', reg.h]]),
    bindings: new Map<string, any>([
      ['S', { kind: 'group', groupId: '0xg', registryId: '0xreg', members }],
      ['Landlord', { kind: 'creddef', credDefId: '0xcd' }],
      ['Other', { kind: 'creddef', credDefId: '0xother' }],
      ['Issued', { kind: 'registry', registryId: '0xreg' }],
    ]),
  };
  return { reg, ctx, alice, bob, carol, alice2, members };
}

const run = (q: string, ctx: PublicContext, wallet: WalletCredential[], opts = {}) => {
  const f = parse(q);
  const p = present(f, q, ctx, wallet, 'nonce-1', opts);
  const roundTrip = JSON.parse(JSON.stringify(p));
  return { p, v: verifyPresentation(f, roundTrip, ctx) };
};

test('flat reservation guard, public group, with aggregate evidence', async () => {
  const { reg, ctx, alice, members } = await world();
  const q = 'forall x in S. NotRevoked(x)';
  const { p, v } = run(q, ctx, [alice], { aggregates: { S: reg.aggregate(members) } });
  assert.equal(v.ok, true, v.reason);
  assert.equal(v.class, 'co-stable');
  assert.equal(v.cas, 'group');
  assert.ok(p.evidence.S);
  reg.revoke(members[1]!);
  assert.throws(() => run(q, ctx, [alice]));
  // the loser's permanent proof
  const loser = run('!(forall x in S. NotRevoked(x))', ctx, [alice]);
  assert.equal(loser.v.ok, true);
  assert.equal(loser.v.class, 'stable');
});

test('holder proves an active credential of the Landlord in S, hiding which member', async () => {
  const { ctx, alice } = await world();
  const { p, v } = run('exists x in S. Sig(x, "Landlord") & Active(x)', ctx, [alice]);
  assert.equal(v.ok, true, v.reason);
  assert.equal(p.credentials.length, 1);
  // tampering with a leaf breaks it
  const bad = JSON.parse(JSON.stringify(p));
  bad.leaves[0].Dp = bad.leaves[1]?.Dp ?? bad.leaves[0].Cp;
  assert.equal(verifyPresentation(parse('exists x in S. Sig(x, "Landlord") & Active(x)'), bad, ctx).ok, false);
});

test('revoked credential: Revoked proves, NotRevoked cannot', async () => {
  const { reg, ctx, alice, bob } = await world();
  reg.revoke(alice.scalars[0]!);
  reg.revoke(bob.scalars[0]!); // a later revocation: the free receipt is refreshed publicly
  assert.equal(run('exists x in Presented. Sig(x, "Landlord") & Revoked(x)', ctx, [alice]).v.ok, true);
  assert.throws(() => run('exists x in Presented. Sig(x, "Landlord") & NotRevoked(x)', ctx, [alice]));
});

test('OR with a simulated branch, at least k with distinctness, SameHolder', async () => {
  const { reg, ctx, alice, bob, carol, alice2 } = await world();
  reg.revoke(bob.scalars[0]!);
  const or = run('exists x in Presented. Sig(x, "Landlord") & (Revoked(x) | NotRevoked(x))', ctx, [alice]);
  assert.equal(or.v.ok, true, or.v.reason);
  const k2 = run('atleast 2 x in Presented. Sig(x, "Landlord") & Active(x)', ctx, [alice, bob, carol]);
  assert.equal(k2.v.ok, true, k2.v.reason);
  assert.equal(k2.p.credentials.length, 2); // bob's revoked credential is not presented
  assert.throws(() => run('atleast 3 x in Presented. Sig(x, "Landlord") & Active(x)', ctx, [alice, bob, carol]));
  const same = run('exists x in Presented. exists y in Presented. Sig(x, "Landlord") & Sig(y, "Landlord") & SameHolder(x, y)', ctx, [alice, alice2]);
  assert.equal(same.v.ok, true, same.v.reason);
  assert.throws(() => run('exists x in Presented. Sig(x, "Other")', ctx, [alice]));
  assert.throws(() => run('forall x in Presented. Active(x)', ctx, [alice]));
});

test('public counting and whole-registry checks', async () => {
  const { reg, ctx, alice, bob } = await world();
  assert.equal(run('atmost 0 x in S. Revoked(x)', ctx, [alice]).v.ok, true);
  assert.equal(run('forall x in Issued. NotRevoked(x)', ctx, []).v.ok, true);
  reg.revoke(alice.scalars[0]!);
  reg.revoke(bob.scalars[0]!);
  assert.equal(run('atleast 2 x in S. Revoked(x)', ctx, []).v.ok, true);
  assert.equal(run('exists x in Issued. NotRevoked(x)', ctx, []).v.ok, true);
  assert.throws(() => run('atmost 1 x in S. Revoked(x)', ctx, []));
});

import { checkFreshness } from '../src/ql/freshness.ts';

test('freshness: co-stable guard goes stale on a member revocation, stable proof never', async () => {
  const { reg, ctx, alice, members } = await world();
  const g = run('forall x in S. NotRevoked(x)', ctx, [alice]);
  assert.equal(checkFreshness(g.p, g.v.class, g.v.cas, ctx).fresh, true);
  // an issuance outside the group does not invalidate a group-CAS guard
  reg.issue(randomScalar());
  assert.equal(checkFreshness(g.p, g.v.class, g.v.cas, ctx).fresh, true);
  reg.revoke(members[0]!);
  assert.equal(checkFreshness(g.p, g.v.class, g.v.cas, ctx).fresh, false);
  const loser = run('exists x in S. Revoked(x)', ctx, []);
  reg.revoke(members[1]!);
  assert.equal(checkFreshness(loser.p, loser.v.class, loser.v.cas, ctx).fresh, true);
  assert.equal(verifyPresentation(parse('exists x in S. Revoked(x)'), loser.p, ctx).ok, true);
});

import { validateGuardPresentation, type PolicyRef } from '../src/actors/actors.ts';

test('trusted updater rejects invalid and uncovered proofs while preserving CAS versions', async () => {
  const { reg, ctx, alice, members } = await world();
  const policy = (query: string, context = ctx): PolicyRef => ({ policyId: 'test-policy', query, bindings: [...context.bindings] });
  const q = 'forall x in S. NotRevoked(x)';
  const { p } = run(q, ctx, []);
  assert.doesNotThrow(() => validateGuardPresentation(policy(q), p, ctx));
  assert.throws(() => validateGuardPresentation(policy('exists x in S. Revoked(x)'), p, ctx), /another query/);
  const falseProof = { ...p, query: 'exists x in S. Revoked(x)' };
  assert.throws(() => validateGuardPresentation(policy(falseProof.query), falseProof, ctx), /query is false/);
  const active = 'exists x in Presented. Sig(x, "Landlord") & NotRevoked(x)';
  const onlyCredDef: PublicContext = { ...ctx, bindings: new Map([['Landlord', ctx.bindings.get('Landlord')!]]) };
  const uncovered = run(active, onlyCredDef, [alice]).p;
  assert.throws(() => validateGuardPresentation(policy(active, onlyCredDef), uncovered, onlyCredDef), /no CAS binding/);
  const covered = run(active, ctx, [alice]).p;
  assert.doesNotThrow(() => validateGuardPresentation(policy(active), covered, ctx));
  const tampered = structuredClone(covered);
  tampered.proof = null;
  assert.throws(() => validateGuardPresentation(policy(active), tampered, ctx), /missing proof/);
  const neutral = 'exists x in Presented. Sig(x, "Landlord")';
  const independent = run(neutral, onlyCredDef, [alice]).p;
  assert.doesNotThrow(() => validateGuardPresentation(policy(neutral, onlyCredDef), independent, onlyCredDef));
  reg.issue(randomScalar());
  assert.doesNotThrow(() => validateGuardPresentation(policy(q), p, ctx));
  assert.doesNotThrow(() => validateGuardPresentation(policy(active), covered, ctx));
  assert.notEqual(covered.versions['0xreg'], reg.h.values.length - 1);
  reg.revoke(members[0]!);
  assert.doesNotThrow(() => validateGuardPresentation(policy(q), p, ctx));
  assert.equal(checkFreshness(p, 'co-stable', 'group', ctx).fresh, false);
  const stableQuery = 'exists x in S. Revoked(x)';
  const stable = run(stableQuery, ctx, []).p;
  reg.revoke(members[1]!);
  assert.doesNotThrow(() => validateGuardPresentation(policy(stableQuery), stable, ctx));
  assert.doesNotThrow(() => validateGuardPresentation(policy(neutral, onlyCredDef), independent, onlyCredDef));
});


test('public proofs authenticate every claimed history version', async () => {
  const { reg, ctx, members } = await world();
  reg.revoke(members[0]!);
  const query = 'exists x in S. Revoked(x)';
  const p = run(query, ctx, []).p;
  const policy: PolicyRef = { policyId: 'test-policy', query, bindings: [...ctx.bindings] };
  for (const v of [reg.h.values.length, -1, 0.5, Number.NaN]) {
    const bad = { ...p, versions: { ...p.versions, '0xreg': v } };
    assert.equal(verifyPresentation(parse(query), bad, ctx).ok, false);
    assert.throws(() => validateGuardPresentation(policy, bad, ctx), /invalid bound version/);
  }
  const unknown = { ...p, versions: { ...p.versions, unknown: 0 } };
  assert.equal(verifyPresentation(parse(query), unknown, ctx).ok, false);
  reg.issue(randomScalar());
  assert.doesNotThrow(() => validateGuardPresentation(policy, p, ctx));
});
