// Setting up the issuer, the registry and the groups, and the writes the contract must refuse.
import assert from 'node:assert/strict';
import { Given, When, Then } from '@cucumber/cucumber';
import { ethers } from 'ethers';
import { g1, g1ToEip, mul, randomScalar, scalarToHex32 } from '../../src/crypto/bls.ts';
import { readHistory } from '../../src/chain/client.ts';
import { Holder, readGroup } from '../../src/actors/actors.ts';
import type { ReservationWorld } from '../support/world.ts';

/** "Alice, Bob and Carol" -> ["Alice", "Bob", "Carol"] */
const names = (list: string): string[] => list.split(/\s*,\s*|\s+and\s+/).map((s) => s.trim()).filter(Boolean);

Given('a landlord with a BBS key published in its DID document', async function (this: ReservationWorld) {
  await this.landlord.publishKey();
});

Given('a schema {string} version {string} with attributes {string} and {string}',
  async function (this: ReservationWorld, name: string, version: string, a: string, b: string) {
    // the scenario's own schema: on a shared chain the same name from the same sender would collide
    this.schemas.set(name, await this.landlord.registerSchema(`${name}-${this.label}`, version, [a, b]));
  });

Given('the landlord registers a CredDef for the schema {string}', async function (this: ReservationWorld, name: string) {
  const schemaId = this.schemas.get(name);
  assert.ok(schemaId, `schema ${name} was not registered in this scenario`);
  await this.landlord.registerCredDef(schemaId);
});

When('the landlord registers a CredDef for an unknown schema', async function (this: ReservationWorld) {
  await this.attempt('registerCredDef', () => this.landlord.registerCredDef(ethers.hexlify(ethers.randomBytes(32))));
});

Given('a revocation registry for the CredDef with a published SRS', async function (this: ReservationWorld) {
  this.registryId = await this.landlord.createRegistry(`${this.label}-registry`, 8);
});

Given(/^the landlord has issued interest credentials to (.+)$/, async function (this: ReservationWorld, list: string) {
  for (const name of names(list)) {
    const h = new Holder(this.d);
    h.wallet.push(await this.landlord.issue(this.registryId, ['flat-1', name], h.linkSecret));
    this.holders.set(name, h);
  }
});

When(/^the landlord issues a new credential to (\w+)$/, async function (this: ReservationWorld, name: string) {
  const h = new Holder(this.d);
  h.wallet.push(await this.landlord.issue(this.registryId, ['flat-1', name], h.linkSecret));
  this.holders.set(name, h);
});

Given(/^the group (\w+) = \{(.+)\} is anchored on chain$/, async function (this: ReservationWorld, group: string, list: string) {
  const ys = names(list).map((n) => this.y(n));
  const groupId = await this.landlord.createGroup(this.registryId, `${this.label}-${group}`, ys);
  this.groups.set(group, await readGroup(this.d, groupId));
});

When(/^the landlord anchors a group of (\w+) and an ID that was never issued$/, async function (this: ReservationWorld, name: string) {
  // the issuer knows α, but the contract checks membership in its issued set, not with a pairing
  await this.attempt('createGroup', () =>
    this.landlord.createGroup(this.registryId, `${this.label}-unissued`, [this.y(name), randomScalar()]));
});

When(/^the landlord submits a revocation of (\w+) with a wrong new A$/, async function (this: ReservationWorld, name: string) {
  const h = await readHistory(this.d, this.registryId);
  const args = [...this.landlord.revokeArgs(this.registryId, h, this.y(name))];
  args[2] = g1ToEip(mul(g1, randomScalar()));
  const st = this.d.state.connect(this.landlord.signer) as ethers.Contract;
  await this.attempt(`revoke ${name}`, async () => (await st.revoke!(...args)).wait());
});

Then(/^the (?:registration|revocation|group creation) is rejected with "(\w+)"$/, function (this: ReservationWorld, error: string) {
  const o = this.last();
  assert.equal(o.ok, false, `${o.what} was accepted`);
  assert.equal(o.error, error);
});

Then(/^(\w+)'s credential is not revoked$/, async function (this: ReservationWorld, name: string) {
  const h = await readHistory(this.d, this.registryId);
  assert.equal(h.revokedAt.has(this.y(name)), false);
  assert.equal(await this.d.state.revokedAt!(this.registryId, scalarToHex32(this.y(name))), 0n);
});
