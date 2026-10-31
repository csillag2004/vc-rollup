// Run after forge build against local Anvil: ANVIL_RPC=http://127.0.0.1:8545 node --test test/guards.integration.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { deployAll, revertName } from '../src/chain/client.ts';
import { Issuer, Holder, readGroup } from '../src/actors/actors.ts';
import type { Binding } from '../src/ql/compile.ts';

test('issuer validates guard proofs and contract atomically rejects stale group/global versions', async () => {
  const provider = new ethers.JsonRpcProvider(process.env.ANVIL_RPC ?? 'http://127.0.0.1:8545', undefined,
    { pollingInterval: 20, cacheTimeout: -1 });
  try {
    const signer = await provider.getSigner(0);
    const d = await deployAll(signer);
    const issuer = new Issuer(signer, d);
    await issuer.setUp('guard-regression', ['name']);
    const registry = await issuer.createRegistry('guard-regression', 4);
    const alice = new Holder(d), bob = new Holder(d);
    alice.wallet.push(await issuer.issue(registry, ['Alice'], alice.linkSecret));
    bob.wallet.push(await issuer.issue(registry, ['Bob'], bob.linkSecret));
    const group = await issuer.createGroup(registry, 'S', [alice.wallet[0]!.scalars[0]!, bob.wallet[0]!.scalars[0]!]);
    const groupBindings: [string, Binding][] = [['S', await readGroup(d, group)]];
    const groupPolicy = await issuer.registerPolicy('forall x in S. NotRevoked(x)', groupBindings);
    const groupProof = await alice.present(groupPolicy.query, groupBindings, 'group');
    const falsePolicy = await issuer.registerPolicy('exists x in S. Revoked(x)', groupBindings);
    const before = (await d.state.getValues!(registry)).version;
    await assert.rejects(issuer.issue(registry, ['Rejected'], alice.linkSecret,
      { policy: falsePolicy, presentation: { ...groupProof, query: falsePolicy.query } }), /query is false/);
    assert.equal((await d.state.getValues!(registry)).version, before);

    // A successful guarded issue commits to exactly the proof bytes supplied off-chain.
    const accepted = await issuer.issue(registry, ['Accepted'], alice.linkSecret, { policy: groupPolicy, presentation: groupProof });
    const events = await d.state.queryFilter(d.state.filters.Issued!(registry));
    const event = events.at(-1) as ethers.EventLog;
    const expectedDigest = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'bytes32'],
      [groupPolicy.policyId, ethers.id(JSON.stringify(groupProof))]));
    assert.equal(event.args.guardDigest, expectedDigest);
    assert.notEqual(expectedDigest, ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'bytes32'],
      [groupPolicy.policyId, ethers.id(JSON.stringify({ ...groupProof, nonce: 'changed' }))])));

    const active = 'exists x in Presented. Sig(x, "Issuer") & NotRevoked(x)';
    const registryBindings: [string, Binding][] = [['Issuer', { kind: 'registry', registryId: registry }]];
    const activePolicy = await issuer.registerPolicy(active, registryBindings);
    const activeProof = await alice.present(active, registryBindings, 'active');
    await assert.rejects(issuer.issue(registry, ['Corrupt'], alice.linkSecret,
      { policy: activePolicy, presentation: { ...activeProof, proof: null } }), /missing proof/);
    await assert.rejects(issuer.guardedRevoke(registry, accepted.scalars[0]!, activePolicy,
      { ...activeProof, query: groupPolicy.query }), /another query/);
    const credBindings: [string, Binding][] = [['Issuer', { kind: 'creddef', credDefId: issuer.credDefId }]];
    const uncoveredPolicy = await issuer.registerPolicy(active, credBindings);
    const uncovered = await alice.present(active, credBindings, 'uncovered');
    await assert.rejects(issuer.guardedRevoke(registry, accepted.scalars[0]!, uncoveredPolicy, uncovered), /no CAS binding/);
    await assert.rejects(issuer.guardFor({ ...groupPolicy, query: falsePolicy.query }, groupProof), /registered policy/);

    await issuer.revoke(registry, alice.wallet[0]!.scalars[0]!);
    await assert.rejects(issuer.issue(registry, ['Stale'], alice.linkSecret,
      { policy: groupPolicy, presentation: groupProof }), (e) => revertName(d, e) === 'StaleGroupVersion');
    await assert.rejects(issuer.guardedRevoke(registry, bob.wallet[0]!.scalars[0]!, activePolicy, activeProof),
      (e) => revertName(d, e) === 'StaleVersion');
    assert.equal(await d.state.isRevoked!(registry, ethers.toBeHex(bob.wallet[0]!.scalars[0]!, 32)), false);
  } finally {
    provider.destroy();
  }
});
