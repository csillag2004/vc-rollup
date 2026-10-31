// Integration against the isolated local chain owned by scripts/run.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { deployAll, revertName, readHistory } from '../src/chain/client.ts';
import { Issuer, Holder, Verifier, readGroup, ACTION } from '../src/actors/actors.ts';
import type { Binding } from '../src/ql/compile.ts';

test('ledger enforces public truth, permanent policies and the private-guard boundary', async () => {
  const provider = new ethers.JsonRpcProvider(process.env.ANVIL_RPC ?? 'http://127.0.0.1:8545', undefined,
    { pollingInterval: 20, cacheTimeout: -1 });
  try {
    const signer = await provider.getSigner(0);
    const d = await deployAll(signer);
    const issuer = new Issuer(signer, d);
    await issuer.setUp('guard-regression', ['name']);
    const registry = await issuer.createRegistry('guard-regression', 8);
    const alice = new Holder(d), bob = new Holder(d);
    alice.wallet.push(await issuer.issue(registry, ['Alice'], alice.linkSecret));
    bob.wallet.push(await issuer.issue(registry, ['Bob'], bob.linkSecret));
    const group = await issuer.createGroup(registry, 'S', [alice.wallet[0]!.scalars[0]!, bob.wallet[0]!.scalars[0]!]);
    const bindings: [string, Binding][] = [['S', await readGroup(d, group)]];
    const policy = await issuer.registerPolicy('forall x in S. NotRevoked(x)', bindings, 'revoke');
    const proof = await alice.present(policy.query, bindings, 'group');
    const falsePolicy = await issuer.registerPolicy('exists x in S. Revoked(x)', bindings);
    await assert.rejects(issuer.issue(registry, ['Rejected'], alice.linkSecret,
      { policy: falsePolicy, presentation: { ...proof, query: falsePolicy.query } }), /query is false/);
    await assert.rejects(issuer.guardFor({ ...policy, query: falsePolicy.query }, proof), /registered policy/);
    await assert.rejects(d.policies.bindPolicy!(issuer.credDefId, ACTION.revoke, ethers.ZeroHash),
      e => revertName(d, e) === 'PolicyLocked');
    await assert.rejects(d.policies.bindPolicy!(issuer.credDefId, ACTION.revoke, falsePolicy.policyId),
      e => revertName(d, e) === 'PolicyLocked');

    const privateBindings: [string, Binding][] = [['R', { kind: 'registry', registryId: registry }]];
    const privatePolicy = await issuer.registerPolicy('exists x in Presented. Sig(x, "R") & NotRevoked(x)', privateBindings);
    await assert.rejects(d.policies.bindPolicy!(issuer.credDefId, ACTION.issue, privatePolicy.policyId),
      e => revertName(d, e) === 'UnsupportedPrivateGuard');
    const privateProof = await alice.present(privatePolicy.query, privateBindings, 'private');
    await assert.rejects(issuer.issue(registry, ['Private'], alice.linkSecret,
      { policy: privatePolicy, presentation: privateProof }), /private update guards are unsupported/);

    const receipt = await issuer.guardedRevoke(registry, alice.wallet[0]!.scalars[0]!, policy, proof);
    const event = receipt.logs.map(l => { try { return d.state.interface.parseLog(l); } catch { return null; } })
      .find(e => e?.name === 'Revoked')!;
    const version = Number(event.args.version);
    const verifier = new Verifier(d);
    assert.equal((await verifier.verifyGuardProof(registry, version)).ok, true);
    const expected = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'bytes32'],
      [policy.policyId, ethers.id(JSON.stringify(proof))]));
    assert.equal(event.args.guardDigest, expected);

    // Direct contract call: valid accumulator transition, current versions, arbitrary proof bytes.
    // No client proof verifier runs. The false public predicate must still reject the update.
    const h = await readHistory(d, registry);
    await assert.rejects(d.state.guardedRevoke!(...issuer.revokeArgs(registry, h, bob.wallet[0]!.scalars[0]!),
      { policyId: policy.policyId, expectedVersions: [BigInt(version)], proof: '0x1234' }),
      e => revertName(d, e) === 'GuardFalse');
    await assert.rejects(issuer.revoke(registry, bob.wallet[0]!.scalars[0]!), e => revertName(d, e) === 'PolicyRequired');
    assert.equal(await d.state.isRevoked!(registry, ethers.toBeHex(bob.wallet[0]!.scalars[0]!, 32)), false);
    assert.equal((await d.state.getValues!(registry)).version, BigInt(version));
  } finally {
    provider.destroy();
  }
});
