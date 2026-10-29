// The guard policy, the race between Alice and Bob, and the proofs the holders present afterwards.
import assert from 'node:assert/strict';
import { Given, When, Then } from '@cucumber/cucumber';
import { ethers } from 'ethers';
import { scalarToHex32 } from '../../src/crypto/bls.ts';
import { ACTION } from '../../src/actors/actors.ts';
import { analyse } from '../../src/ql/compile.ts';
import { parse } from '../../src/ql/parser.ts';
import type { ReservationWorld } from '../support/world.ts';

/** the verifier's challenge; it travels in the presentation, so it must not name the holder */
const nonce = (): string => ethers.hexlify(ethers.randomBytes(16));

async function boundToRevoke(w: ReservationWorld): Promise<string> {
  return w.d.policies.boundPolicy!(w.landlord.credDefId, ACTION.revoke);
}

async function bindToRevoke(w: ReservationWorld): Promise<void> {
  if ((await boundToRevoke(w)) === w.policy!.policyId) return;
  const pol = w.d.policies.connect(w.landlord.signer) as ethers.Contract;
  await (await pol.bindPolicy!(w.landlord.credDefId, ACTION.revoke, w.policy!.policyId)).wait();
}

/** the holder proves the guard query against the current state; the verifier must find it valid and fresh */
async function proveGuard(w: ReservationWorld, name: string): Promise<void> {
  const p = await w.holder(name).present(w.policy!.query, w.policy!.bindings, nonce());
  const v = await w.verifier.verify(w.policy!.query, w.policy!.bindings, p);
  assert.ok(v.ok && v.fresh, `${name}'s guard proof: ${v.reason ?? v.freshReason}`);
  w.guards.set(name, p);
}

async function guardedRevoke(w: ReservationWorld, name: string) {
  const p = w.guards.get(name);
  assert.ok(p, `${name} has not proved the guard`);
  return w.attempt(`guardedRevoke ${name}`, () => w.landlord.guardedRevoke(w.registryId, w.y(name), w.policy!, p));
}

const groupVersion = async (w: ReservationWorld, group: string): Promise<number> =>
  Number(await w.d.state.groupVersion!(w.group(group).groupId));

// ---------------------------------------------------------------- policy

Given('the guard policy {string} is registered', async function (this: ReservationWorld, query: string) {
  this.policy = await this.landlord.registerPolicy(query, [['S', this.group('S')]]);
});

Given('the guard policy is not bound to Revoke', async function (this: ReservationWorld) {
  assert.equal(await boundToRevoke(this), ethers.ZeroHash);
});

Given('the guard policy is bound to Revoke for the CredDef', async function (this: ReservationWorld) {
  await bindToRevoke(this);
  assert.equal(await boundToRevoke(this), this.policy!.policyId);
});

// ---------------------------------------------------------------- the race

Given(/^(\w+) and (\w+) both prove the guard against group version (\d+)$/,
  async function (this: ReservationWorld, a: string, b: string, version: string) {
    assert.equal(await groupVersion(this, 'S'), Number(version));
    await proveGuard(this, a);
    await proveGuard(this, b);
  });

When(/^the landlord revokes (\w+)'s credential(?: without a guard)?$/, async function (this: ReservationWorld, name: string) {
  await this.attempt(`revoke ${name}`, () => this.landlord.revoke(this.registryId, this.y(name)));
});

When(/^the landlord revokes (\w+)'s credential with (?:her|his|their) guard$/, async function (this: ReservationWorld, name: string) {
  await guardedRevoke(this, name);
});

Given(/^(\w+)'s guarded revocation has been accepted$/, async function (this: ReservationWorld, name: string) {
  await bindToRevoke(this);
  // every member proves the guard first, against the same state
  for (const [member, h] of this.holders) {
    if (this.group('S').members.includes(h.wallet[0]!.scalars[0]!) && !this.guards.has(member)) await proveGuard(this, member);
  }
  const o = await guardedRevoke(this, name);
  assert.ok(o.ok, `${name}'s guarded revocation was rejected: ${o.error}`);
});

Then('both revocations are accepted', function (this: ReservationWorld) {
  const two = this.outcomes.slice(-2);
  assert.equal(two.length, 2);
  for (const o of two) assert.ok(o.ok, `${o.what} was rejected: ${o.error}`);
});

Then('the revocation is accepted', function (this: ReservationWorld) {
  const o = this.last();
  assert.ok(o.ok, `${o.what} was rejected: ${o.error}`);
});

Then(/^the version of (\w+) is (\d+)$/, async function (this: ReservationWorld, group: string, version: string) {
  assert.equal(await groupVersion(this, group), Number(version));
});

// ---------------------------------------------------------------- proofs after the race

When(/^a verifier checks (\w+)'s guard proof$/, async function (this: ReservationWorld, name: string) {
  this.lastVerify = await this.verifier.verify(this.policy!.query, this.policy!.bindings, this.guards.get(name)!);
});

Then('the proof is cryptographically valid', function (this: ReservationWorld) {
  assert.ok(this.lastVerify!.ok, this.lastVerify!.reason);
});

Then(/^it is not fresh because (\w+) moved from version (\d+) to (\d+)$/,
  function (this: ReservationWorld, group: string, from: string, to: string) {
    assert.equal(this.lastVerify!.fresh, false);
    assert.equal(this.lastVerify!.freshReason, `group ${group} moved from version ${from} to ${to}`);
  });

When('{word} proves {string}', async function (this: ReservationWorld, name: string, query: string) {
  const bindings = this.bindings();
  const p = await this.holder(name).present(query, bindings, nonce());
  this.lastProof = { who: name, query, bindings, p };
  this.lastVerify = await this.verifier.verify(query, bindings, p);
});

Then('the proof is valid and its class is {string}', function (this: ReservationWorld, cls: string) {
  assert.ok(this.lastVerify!.ok && this.lastVerify!.fresh, this.lastVerify!.reason ?? this.lastVerify!.freshReason);
  assert.equal(this.lastVerify!.class, cls);
});

Then(/^(\w+)'s proof is still valid and fresh$/, async function (this: ReservationWorld, name: string) {
  const proof = this.lastProof!;
  assert.equal(proof.who, name);
  const v = await this.verifier.verify(proof.query, proof.bindings, proof.p);
  assert.ok(v.ok, v.reason);
  assert.ok(v.fresh, v.freshReason);
});

Then('the verifier accepts the proof', function (this: ReservationWorld) {
  assert.ok(this.lastVerify!.ok && this.lastVerify!.fresh, this.lastVerify!.reason ?? this.lastVerify!.freshReason);
});

Then(/^the proof does not reveal which member of (\w+) (?:she|he|they) (?:is|are)$/, function (this: ReservationWorld, group: string) {
  // what travels to the verifier: no member's revocation ID (in any encoding) and no holder's name
  const sent = JSON.stringify(this.lastProof!.p, (_, v) => (typeof v === 'bigint' ? v.toString() : v)).toLowerCase();
  for (const y of this.group(group).members) {
    assert.ok(!sent.includes(scalarToHex32(y).slice(2).toLowerCase()), 'a revocation ID (hex) is in the presentation');
    assert.ok(!sent.includes(y.toString()), 'a revocation ID (decimal) is in the presentation');
  }
  for (const name of this.holders.keys()) assert.ok(!sent.includes(name.toLowerCase()), `${name} is in the presentation`);
});

// ---------------------------------------------------------------- classification

When('the policy {string} is classified', function (this: ReservationWorld, query: string) {
  this.analysis = analyse(parse(query));
});

Then('its class is {string} and its CAS mode is {string}', function (this: ReservationWorld, cls: string, cas: string) {
  assert.equal(this.analysis!.class, cls);
  assert.equal(this.analysis!.cas, cas);
});
