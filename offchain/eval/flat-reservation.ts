// End-to-end flat reservation on a local chain (anvil, Prague hardfork), the running example of the thesis.
//
//  1. The landlord issues an "interest" credential to Alice, Bob and Carol and anchors the group S.
//  2. Naive profile (no policy bound): Alice and Bob both prove ∀x∈S. NotRevoked(x) against the same
//     state; the landlord checks both proofs and revokes both credentials: the flat is booked twice.
//  3. Guarded profile (policy bound to Revoke): the same race; the contract evaluates the guard when each
//     guarded revocation executes, so the second one is rejected with GuardFalse. Alice's guard proof is
//     on the ledger and anyone can check it.
//  4. Bob's permanent proof that the flat is taken: ∃x∈S. Revoked(x) (stable), valid against any later state.
//  5. A holder presentation: "I hold an interest credential of the landlord in S, and it is revoked"
//     (Alice proves she holds the reservation without saying which member she is).
//
// Usage: anvil --hardfork prague &   then   node eval/flat-reservation.ts [rpc]
// On a public chain: eval/op-sepolia.ts (existing contracts, a funded key, labels made unique per run).
import { ethers } from 'ethers';
import { deployAll, revertName, yHex, type Deployment } from '../src/chain/client.ts';
import { Issuer, Holder, Verifier, readGroup, type PolicyRef } from '../src/actors/actors.ts';
import type { Binding } from '../src/ql/compile.ts';

const RPC = process.env.RPC ?? 'http://127.0.0.1:8545';
// anvil's first default account (a public test key)
const KEYS = ['0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'];

export interface FlatResult {
  naiveDoubleBooking: boolean;
  guardRejected: string | null;
  guardProofFromLedger: boolean;
  loserProofValid: boolean;
  loserProofStillValidLater: boolean;
  stableProofAfterSameRegistryUpdates: boolean;
  holderReservationProof: boolean;
  gas: Record<string, bigint>;
  log: string[];
}

export interface FlatOptions {
  /** the landlord's signer; default: anvil's first account on `rpc` */
  signer?: ethers.Signer;
  /** contracts already on chain; default: deploy a fresh set */
  deployment?: Deployment;
  /** appended to schema, registry and group labels, so a run on a shared chain does not collide */
  tag?: string;
}

export async function runFlatReservation(rpc = RPC, opts: FlatOptions = {}): Promise<FlatResult> {
  // every transaction is awaited, so the provider's nonce is always current
  const signer = opts.signer
    ?? new ethers.Wallet(KEYS[0]!, new ethers.JsonRpcProvider(rpc, undefined, { pollingInterval: 50, cacheTimeout: -1 }));
  const tag = opts.tag ?? '';
  const log: string[] = [];
  const gas: Record<string, bigint> = {};
  const say = (s: string) => { log.push(s); console.log(s); };

  const d = opts.deployment ?? await deployAll(signer);
  say(`${opts.deployment ? 'using' : 'deployed'} StateRegistry at ${await d.state.getAddress()}`);
  const landlord = new Issuer(signer, d);
  await landlord.setUp(`Interest${tag}`, ['flat', 'name']);

  const scenario = async (label: string, bound: boolean) => {
    const reg = await landlord.createRegistry(`flat-${label}${tag}`, 8);
    const alice = new Holder(d), bob = new Holder(d), carol = new Holder(d);
    for (const [h, n] of [[alice, 'Alice'], [bob, 'Bob'], [carol, 'Carol']] as const) {
      h.wallet.push(await landlord.issue(reg, [`flat-${label}`, n], h.linkSecret));
    }
    const ys = [alice, bob, carol].map((h) => h.wallet[0]!.scalars[0]!);
    const groupId = await landlord.createGroup(reg, `interested-${label}${tag}`, ys);
    const S = await readGroup(d, groupId);
    const bindings: [string, Binding][] = [['S', S], ['Landlord', { kind: 'creddef', credDefId: landlord.credDefId }]];
    const guardQuery = 'forall x in S. NotRevoked(x)';
    const policy: PolicyRef = await landlord.registerPolicy(guardQuery, [['S', S]], bound ? 'revoke' : undefined);
    return { reg, alice, bob, carol, ys, S, bindings, policy, guardQuery };
  };

  // ---- naive: no policy bound, the landlord checks the guard off-chain and revokes
  const n = await scenario('naive', false);
  const verifier = new Verifier(d);
  const pa = await n.alice.present(n.guardQuery, [['S', n.S]], 'alice-1');
  const pb = await n.bob.present(n.guardQuery, [['S', n.S]], 'bob-1');
  const okA = await verifier.verify(n.guardQuery, [['S', n.S]], pa);
  const okB = await verifier.verify(n.guardQuery, [['S', n.S]], pb);
  say(`naive: both guards hold at the same state: ${okA.ok && okA.fresh} / ${okB.ok && okB.fresh}`);
  await landlord.revoke(n.reg, n.ys[0]!);
  await landlord.revoke(n.reg, n.ys[1]!); // the check happened before the first revocation
  const revokedNaive = Number(await d.state.groupVersion!(n.S.kind === 'group' ? n.S.groupId : ''));
  say(`naive: revoked members of S after the race: ${revokedNaive} (the flat is booked twice)`);

  // A separate stable-proof fixture uses the still-unbound naive registry before policy binding.
  // Both later transitions really happen in the same registry as this proof.
  const stableQuery = 'exists x in S. Revoked(x)';
  const stableBindings: [string, Binding][] = [['S', n.S]];
  const stableProof = await n.bob.present(stableQuery, stableBindings, 'stable-before-updates');
  const later = await landlord.issue(n.reg, ['flat-naive', 'Later'], n.carol.linkSecret);
  await landlord.revoke(n.reg, later.scalars[0]!);
  const stableAfter = await verifier.verify(stableQuery, stableBindings, stableProof);
  say(`separate stable fixture: proof survives actual later issuance and revocation in its registry: ${stableAfter.ok && stableAfter.fresh}`);

  // ---- guarded: the policy is bound to Revoke, the contract evaluates the guard when the revocation executes
  const c = await scenario('guarded', true);
  const qa = await c.alice.present(c.guardQuery, c.policy.bindings, 'alice-2');
  const qb = await c.bob.present(c.guardQuery, c.policy.bindings, 'bob-2');
  const ra = await landlord.guardedRevoke(c.reg, c.ys[0]!, c.policy, qa);
  gas.guardedRevokeGroup = ra.gasUsed;
  say(`guarded: Alice's guarded revocation accepted (gas ${ra.gasUsed})`);
  const aliceVersion = Number(await d.state.revokedAt!(c.reg, yHex(c.ys[0]!)));
  const fromLedger = await verifier.verifyGuardProof(c.reg, aliceVersion);
  say(`guarded: Alice's guard proof read back from the GuardProof event of version ${aliceVersion}: valid ${fromLedger.ok}${fromLedger.reason ? ` (${fromLedger.reason})` : ''}`);
  let guardRejected: string | null = null;
  try {
    await landlord.guardedRevoke(c.reg, c.ys[1]!, c.policy, qb);
  } catch (e) {
    const name = revertName(d, e);
    guardRejected = name;
    say(`guarded: Bob's guarded revocation rejected: ${name}`);
  }
  const fresh = await verifier.verify(c.guardQuery, c.policy.bindings, qb);
  say(`guarded: Bob's guard proof is cryptographically valid (${fresh.ok}) but no longer fresh (${fresh.freshReason})`);

  // ---- the loser's permanent proof
  const loserQ = '!(forall x in S. NotRevoked(x))';
  const lp = await c.bob.present(loserQ, c.policy.bindings, 'bob-3');
  const lv = await verifier.verify(loserQ, c.policy.bindings, lp);
  say(`loser's proof ∃x∈S.Revoked(x): valid ${lv.ok}, class ${lv.class}`);
  const extra = await landlord.issue(c.reg, ['flat-guarded', 'Dave'], c.carol.linkSecret);
  void extra;
  const lv2 = await verifier.verify(loserQ, c.policy.bindings, lp);
  say(`loser's proof after later updates: valid ${lv2.ok && lv2.fresh}`);

  // ---- Alice proves she holds the reservation, hiding which member she is
  const hq = 'exists x in S. Sig(x, "Landlord") & Revoked(x)';
  const hp = await c.alice.present(hq, c.bindings, 'alice-3');
  const hv = await verifier.verify(hq, c.bindings, hp);
  say(`Alice: "one of S, signed by the landlord, revoked": ${hv.ok} (class ${hv.class})`);

  return {
    naiveDoubleBooking: revokedNaive === 2,
    guardRejected,
    guardProofFromLedger: fromLedger.ok,
    loserProofValid: lv.ok,
    loserProofStillValidLater: lv2.ok && lv2.fresh,
    stableProofAfterSameRegistryUpdates: stableAfter.ok && stableAfter.fresh,
    holderReservationProof: hv.ok,
    gas,
    log,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runFlatReservation().then((r) => { console.log(JSON.stringify({ ...r, log: undefined }, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2)); })
    .catch((e) => { console.error(e); process.exit(1); });
}
