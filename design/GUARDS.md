# Issuer-bound updates and contract-checked guards: frozen contract

Frozen 2026-10-29, before any implementation. The branch is `tdk/guards-0-contract`, on top of `tdk/full-implementation` at 4d3c3f4. Decisions come from Martin's grilling of the TDK spine on 2026-10-29 and are tagged [USER]. Encoding choices made while writing this contract are tagged [AGENT]. `design/GUARDS.sha256` seals this file. Later layers implement it and do not edit it; a change needs a new freeze.

## Why

[USER] The adversary includes the issuer, who holds the trapdoor α. The issuer is trusted to decide which of its credentials to issue and revoke, and when. It must not be able to make an invalid state update: that is the point of the design.

On `tdk/full-implementation`, three things let an issuer that knows α make an invalid update:

1. **Revoked ⊆ issued rests on the subset check `e(W_IR', R̃') = e(I, g̃)`.** Knowing α, the issuer can compute `W_IR = g^{P_Iss(α)/P_Rev(α)}` for any two sets. The check then passes after it revokes an ID that was never issued. Because issuance hides `y`, uniqueness of `y` also rests on the issuer.
2. **The group subset check `e(W_S, [P_S]_2) = e(I, g̃)` has the same flaw.** The issuer can compute `W_S` for any set.
3. **The guard is not evaluated.** `PolicyRegistry` stores the query text with an author-declared class and compare-and-swap mode. A guarded update needs only matching versions and a proof hash. `test_guardedIssueAcrossRegistries` shows the effect: it accepts a guarded issuance under `exists x in M. Revoked(x)` while no member of `M` is revoked.

What stays bound: the step, issuance and consistency checks. Given the stored values and `y`, each fixes the new value uniquely, because the pairing is non-degenerate. α does not help the issuer choose another value that passes.

## Layer 1: public issuance and structural set checks

- [USER] **Issuance reveals `y`.** The signature becomes `issueUpdate(registryId, y, newI, newWIR)`, with `guardedIssueUpdate(registryId, y, newI, newWIR, guard)` alongside. The Schnorr step, `IssueStep` and `issueChallenge` are removed.
- [USER] **Issuance checks.**
  - `y ≠ 0` and `y < r`.
  - `y` is not issued yet, checked in storage: `AlreadyIssued(y)`.
  - `newI` is not the point at infinity: `InvalidPoint()`. This rejects `y = −α`. Since `I` starts at `g` and is never the identity, `I^{α+y}` is the identity exactly when `α + y = 0`.
  - The step check `e(I', g̃) = e(I, g̃^y·Q̃)`: `StepCheckFailed()`.
  - The subset check `e(W_IR', R̃) = e(I', g̃)`, kept: `SubsetCheckFailed()`.
- [USER] **Revocation also checks in storage that `y` is issued:** `NotIssued(y)`. The checks run in this order: `EmptyRevocationId`, `RevocationIdOutOfField`, `NotIssued`, `AlreadyRevoked`, then step, consistency and subset.
  - [AGENT] No point-at-infinity check is needed at revocation. An issued `y` has `α + y ≠ 0`, so `A'` and `R̃'` cannot be the identity.
- [USER] **The pairing checks stay** (Q30): step, consistency and subset (`W_IR`) on revocation; step and subset on issuance. Against parties without α they mean what the paper says. Against the issuer, the storage checks carry the set relations.
- [AGENT] **Storage.** `issuedAtVersion[registryId][y]` (0 means not issued) and an append-only `issuedLog[registryId]`. Views: `isIssued`, `issuedAt`, `issuedCount`, `getIssuedLog(start, count)`.
- [AGENT] **Events.** `Issued(registryId, version, y, newI, newWIR, guardDigest)`, with `y` indexed.
- [USER] **Groups contain issued IDs only, checked structurally** (Q33). The signature becomes `createGroup(registryId, label, members)`.
  - Every member must be issued: `MemberNotIssued(y)`.
  - `W_S`, the G2 powers argument and the group pairing check are removed.
  - Anyone may create a group, as before.
  - [AGENT] The size limit `|S| ≤ srsDegree` stays: off-chain aggregate receipts over `S` need `[P_S]_2` from the SRS.
  - [AGENT] `BLS.setPolyCoeffs` stays in the library, with its test. Only the contract stops using it.

Tests (layer 1): `test_issue`, `test_issueRevealsY`, `test_issueTwiceReverts`, `test_issueZeroIdReverts`, `test_issueOutOfFieldReverts`, `test_issueMinusAlphaReverts`, `test_issueWrongStepReverts`, `test_issueWrongWIRReverts`, `test_issueOnlyIssuer`, `test_revokeNotIssuedReverts`, `test_issuerWithAlphaCannotRevokeUnissued`, `test_createGroupOfIssued`, `test_createGroupMemberNotIssuedReverts`, `test_createGroupByAnyone`, `test_createGroupUnsortedReverts`, `test_createGroupTooLargeReverts`, and the existing revocation tests, adapted.

`test_issuerWithAlphaCannotRevokeUnissued` is the core test. It computes, from α, revocation values for an ID that was never issued, including a `W_IR` that passes the subset check. It expects `NotIssued`. `test_issueMinusAlphaReverts` issues `y = r − α` and expects `InvalidPoint`.

## Layer 2: the contract checks guards

[USER] The contract evaluates the public part of a guard and computes the class of the rest (Q29, Q34). Nobody declares a class.

### The query language with one atom

[USER] The language has one status atom, `Revoked(x)`. `NotRevoked(x)` is its negation (Q20). Every domain contains only issued IDs:
- `Issued`, by definition;
- `Presented`, by the signature;
- groups, by layer 1.

So `Active`, `Issued(x)` and `NotIssued(x)` add nothing on any domain, and the front end desugars them away.

### The policy encoding

[AGENT] A policy is the query text plus two postfix programs over clauses. The guard is their conjunction: `presented ∧ public`.

- **The `presented` program** has clauses over `Presented` only. Holders prove it off-chain, and readers check that proof (it is the guard proof of layer 3). The contract classifies it.
- **The `public` program** has clauses over groups and `Issued` only. The contract evaluates it when the update executes.

Every example guard of the paper has this shape:

| guard | `presented` | `public` |
|---|---|---|
| the reservation | empty | `∀x∈S. NotRevoked(x)` |
| the lease | `∃x∈Presented. Revoked(x)` | empty |
| "all except the presented one" | `∃x∈Presented. NotRevoked(x)` | `∃^{≤1} x∈Issued. NotRevoked(x)` |
| "the flat is taken" | empty | `∃x∈S. Revoked(x)` |

A query that does not split this way cannot be bound to an on-chain action. The off-chain front end reports it as uncompilable for the chain.

```solidity
enum Quant { All, Exists, AtLeast, AtMost }
enum Domain { Group, Issued, Presented }
enum Polarity { Neutral, Up, Down, Mixed }   // Up: Revoked, Down: NotRevoked
enum OpKind { Clause, And, Or }
struct Op { OpKind kind; Quant quant; uint32 k; Domain domain; uint8 binding; Polarity body; }
```

- **No negation operator.** Programs are in negation normal form; the front end pushes negation into the atom and dualises quantifiers.
- **A clause** is `quant x ∈ domain(binding). body`.
  - In the `public` program, `body` is `Up` (the body is `Revoked(x)`) or `Down` (`NotRevoked(x)`).
  - In the `presented` program, `body` is the polarity of the clause body. That body may contain credential atoms (`Sig`, `SameHolder`), which are neutral.

### Registration

`registerPolicy(query, bindings, presented, public_)` replaces the declared class and compare-and-swap mode. `policyId = keccak256(abi.encode(author, query, bindings, presented, public_))`. Registration rejects:

| case | error |
|---|---|
| empty query text | `EmptyQuery()` |
| duplicate binding name | `DuplicateBindingName(i)` |
| more than 32 operations in a program | `ProgramTooLong(n)` |
| malformed postfix: an operator with fewer than two operands, or more or fewer than one value left | `MalformedProgram()` |
| a clause binding index out of range | `BadBinding(i)` |
| a clause whose domain does not fit its binding kind | `DomainBindingMismatch(i)` |
| a `presented` clause that is not over `Presented`, or whose quantifier is `All` or `AtMost` (scope guard 4: over `Presented` only `∃` and `∃^{≥k}` mean anything) | `BadPresentedClause(i)` |
| a `public` clause over `Presented`, or with a body other than `Up` or `Down` | `BadPublicClause(i)` |
| a nonzero `k` with `All` or `Exists` | `BadPresentedClause(i)` or `BadPublicClause(i)` |

An empty program means `true`.

Domain and binding kind must match like this:
- `Group` takes a `Group` binding;
- `Issued` takes a `Registry` binding;
- `Presented` takes a `Registry` binding, or a `CredDef` binding when `body` is `Neutral`.

### Classification

[USER] The polarity rules are the paper's lem:closure, as completed in `THESIS-CHANGES.md` item 11. Both programs are classified at registration and stored. `presentedClass(policyId)` and `publicClass(policyId)` are views.

- **flip** swaps `Up` and `Down`, and leaves `Neutral` and `Mixed` as they are.
- **join** has `Neutral` as its identity, is idempotent, and gives `Mixed` for any two different non-neutral values.
- **The polarity of a clause:**
  - over a group or `Presented`: `body` for `All`, `Exists` and `AtLeast`; `flip(body)` for `AtMost`;
  - over `Issued`: `join(Down, body)` for `All`; `join(Up, body)` for `Exists` and `AtLeast`; `join(Down, flip(body))` for `AtMost`.
- **`And` and `Or`** join their operands.
- **The class** follows from the polarity: `Neutral` gives `StateIndependent`, `Up` gives `Stable`, `Down` gives `CoStable`, `Mixed` gives `Volatile`.

### Checking a guard

`Guard = { policyId, expectedVersions, proof }`, where `expectedVersions` lines up with the policy's bindings. `_checkGuard`:

1. **The policy.** If a policy is bound to the action, `guard.policyId` must be it: `WrongPolicy`. The policy must exist: `UnknownPolicy`. The versions must line up: `GuardLengthMismatch`.
2. **Compare-and-swap, for the `presented` program only.** Skip this step if the class is `StateIndependent` or `Stable`. Otherwise, for every `Registry` binding a `presented` clause refers to, the registry's global version must equal the expected version: `StaleVersion(i, expected, current)`.
3. **Evaluate the `public` program** at the current state, before the update is applied. A clause with body `Up` counts `m = r` matching IDs, and one with body `Down` counts `m = n − r`. Here `n` and `r` are:
   - for a group, `n = |S|` and `r` = `groupVersion(S)`, the number of revoked members;
   - for `Issued`, `n = issuedCount` and `r = revokedCount` of the bound registry.

   The quantifier then decides the clause: `All` needs `m = n`, `Exists` `m ≥ 1`, `AtLeast k` `m ≥ k`, and `AtMost k` `m ≤ k`. A false program reverts with `GuardFalse(policyId)`. An unknown group or registry reverts with `UnknownGroup` or `UnknownRegistry`.

[AGENT] **Group versions leave the guard check.** Group clauses are evaluated at execution, so they are always fresh, and the group compare-and-swap mode is removed. `groupVersion` stays as a view: readers and off-chain verifiers of `Present` proofs still use it.

Tests (layer 2):
- **registration:** `test_registerPolicyComputesClass` (the four classes, including every row of the table above), `test_registerPolicyRejectsMalformed` (one case per error), `test_policyIdCoversPrograms`;
- **the guard check:**
  - `test_publicGuardEvaluatedOnChain`, which is `test_guardedIssueAcrossRegistries` with the guard false: `GuardFalse`;
  - `test_flatReservationRaceDecidedOnChain`: Bob's guarded revoke fails with `GuardFalse`, not with a version mismatch;
  - `test_issuerCannotReserveTwice`;
  - `test_allButPresentedUsesCounters`;
  - `test_presentedCoStableNeedsVersion`;
  - `test_presentedStableNeedsNoVersion` (the lease);
  - `test_groupGuardIgnoresOutsideRevocation`;
  - `test_wrongPolicyReverts`;
  - `test_unguardedUpdateRejectedWhenBound`;
- **the evaluator:** `testFuzz_publicClauseMatchesCount`, which checks every quantifier and polarity against a reference count.

## Layer 3: the guard proof on the ledger

- [USER] **`Guard.proof` is the proof's bytes** and replaces `proofHash` (Q35).
- **After a guarded update,** the contract emits `GuardProof(registryId, version, policyId, proof)`, where `version` is the new version. Anyone can check the proof afterwards.
- **`guardDigest`** is `keccak256(abi.encode(policyId, keccak256(proof)))`, unchanged in meaning. It stays in `Issued` and `Revoked`.

Tests (layer 3): `test_guardProofEmitted`, `test_guardDigestBindsProof`.

## Layer 4: off-chain code and evaluation

- **Off-chain code.** `offchain/` follows the new ABIs:
  - issuance with `y`;
  - `createGroup` without `W_S`;
  - policies compiled into the two programs by the TypeScript front end, from the same AST it proves from;
  - the guard proof sent as bytes.
- **The front end desugars** `Active`, `Issued` and `NotIssued` over the one atom.
- **Classification.** Its result must equal the contract's on every query the exhaustive check enumerates.
- **Runs.** The BDD scenarios, the flat reservation run and the gas report run again on anvil with the Prague hardfork, and `design/EVALUATION.md` is regenerated.
- [USER] **No OP Sepolia redeploy** without Martin's explicit go.

## Out of scope

- The paper text. `THESIS-CHANGES.md` gets the new items, but the paper is not edited.
- The Lean model. It is frozen and proved, and its checks are ideal set relations, which these storage checks implement.
- `qlc`.
- Holder-submitted updates and a threshold trapdoor: these are the next paper.
