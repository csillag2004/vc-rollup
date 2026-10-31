# TDK reference implementation: historical plan

The submission scope selected on 2026-10-31 is defined by [ENFORCED-GUARDS.md](ENFORCED-GUARDS.md). This plan records the original interview; its branch instructions, time budget, planned file layout and absence of formal modeling are historical. Current commands are in the [README](../README.md).

Branch: `tdk/full-implementation`, forked from `origin/consultation-10-06` (`925a6d2 guardissuance`).
Time budget: one day. Thesis text is not edited here; the required thesis changes are in
[`THESIS-CHANGES.md`](THESIS-CHANGES.md).

## Decisions (from the design interview, 2026-10-28/29)

| # | Decision |
|---|---|
| Q1 | Work on `tdk/full-implementation`, no push without asking. |
| Q2 | Önlab leftovers are deleted on this branch (they stay on `main`). |
| Q3/Q15/Q23 | Off-chain in TypeScript on `@noble/curves` (BLS12-381). Signatures are **BBS** (IETF draft, ciphersuite BLS12-381-SHA-256), not BBS+; keys and signatures are made and checked with `@digitalbazaar/bbs-signatures`. The presentation proof is our own composable sigma proof of knowledge of that signature, so it can be put under AND / OR / threshold with the accumulator proofs under one Fiat–Shamir challenge. An IETF verifier cannot check our presentation; it can check our signatures. |
| Q4/Q16/Q22 | A new `PolicyRegistry`: a policy is a query plus bindings of its domain names to on-chain objects (groups, registries, CredDefs). The CredDef issuer binds policies to actions (`issue`, `revoke`, `present`). The `StateRegistry` refuses unguarded updates when a policy is bound, and enforces the CAS mode the policy needs. `present` is stored only; verifiers enforce it. |
| Q5 | No GUI, no formal model (TLA+/Lean). |
| Q6 | One day. |
| Q7 | Thesis vs dashboard deviations were escalated (E1–E11) before planning; accepted. |
| Q8 | English identifiers, Hungarian comments in contracts (as before); `node:test` for TS, forge for Solidity. |
| Q10/E2 | A group holds already issued IDs only, so the group version grows on revocation only. |
| Q11 | Rules with proofs: NotRevoked (A), Revoked (R̃, G2), Issued (I), AND, OR (CDS), ∀-NotRevoked aggregate receipt, ∃ over a group (hidden member, `acc_S`), at least k, at most k, registry-level checks, Sig, SameHolder. |
| Q12 | Demo: flat reservation, naive vs CAS, loser's permanent proof. |
| Q13 | Optimistic chain: OP Sepolia; locally `anvil --hardfork prague`. |
| Q14 | Verify on write: the contract checks step, consistency and subset on every revocation with EIP-2537. |
| Q17 | Formula classes: stable / co-stable / volatile; atoms: monotone / antitone. |
| Q18 | Several quantifiers / `atleast k` over `Presented` get pairwise distinctness proofs (`y_i ≠ y_j`). |
| Q19 | Scope = contracts, crypto, language, protocol, flat reservation e2e, evaluation; plus an OP Sepolia deploy script (run only after explicit go). |
| Q20 | `createGroup` is verified on chain: `e(W_S, [P_S]_2) = e(I, g̃)`, `[P_S]_2` computed by the contract from the members and the G2 SRS. |
| Q21 | Issuance step check without revealing y: issuer sends `T = I^y` and a Schnorr proof; contract checks `e(I', g̃) = e(T, g̃)·e(I, Q̃)`. |

## Layout

```
src/                     Solidity (0.8.30, evm prague)
  lib/BLS.sol            EIP-2537 wrappers: add, MSM, pairing check, negation, Fr arithmetic
  SchemaRegistry.sol     (kept)
  CredDefRegistry.sol    (kept)
  StateRegistry.sol      A, R̃, I, W_IR, SRS, versions, groups, on-chain checks, guarded updates
  PolicyRegistry.sol     policies, bindings, CredDef action rules
test/                    forge tests (valid points produced with the precompiles and a test α)
script/Deploy.s.sol      local and OP Sepolia deployment
offchain/
  src/crypto/            bls.ts (encodings, EIP-2537 format), fr.ts, accumulator.ts, bbs.ts, sigma.ts, transcript.ts
  src/ql/                lexer.ts, parser.ts, ast.ts, nnf.ts, classify.ts, semantics.ts, compile.ts, prove.ts, verify.ts
  src/chain/             contracts.ts (ABIs from forge out/), history.ts (registry values by version from events)
  src/actors/            issuer.ts, holder.ts, verifier.ts
  test/                  node:test suites
  eval/                  flat-reservation.ts, toctou.ts, classify-exhaustive.ts, bench.ts
design/                  this plan, thesis changes, evaluation results
```

## Cryptographic core (multiplicative notation, tilde = G2)

- Registry values: `A = V0^{1/P_Rev(α)}` (static add), `R̃ = g̃^{P_Rev(α)}`, `I = g^{P_Iss(α)}`, `W_IR = g^{P_Iss/P_Rev(α)}`, keys `Q̃ = g̃^α`, `Q = g^α`, SRS `g^{α^i}`, `g̃^{α^i}`.
- Issue y: `I' = I^{y+α}`, `W_IR' = W_IR^{y+α}`, receipts `C_A = A^{1/(y+α)}` and `C_I = I` (old value).
- Revoke y: `A' = A^{1/(y+α)}`, `R̃' = R̃^{y+α}`, `W_IR' = W_IR^{1/(y+α)}`; free receipt `C̃ = R̃` (old value).
- Refresh after revocation of y': `C_A' = (C_A/A')^{1/(y'−y)}`, `C̃' = R̃_before · C̃^{y'−y}`.
  An I-receipt cannot be refreshed publicly (issuance hides y); Issued is monotone, so it is proved against the historical I the receipt belongs to (limitation: reveals the issuance version).
- Hidden-y membership proofs, prover without pairings (blind the receipt, publish the "α-image"):
  - in A (or I, or `acc_S`): `C' = C^ρ`, `D = A^ρ·C'^{−y}`; verifier checks `e(C', Q̃) = e(D, g̃)`, `C' ≠ 1`; sigma proof of `(ρ, y)` for `D = A^ρ C'^{−y}` in G1.
  - in R̃: `C̃' = C̃^ρ`, `D̃ = R̃^ρ·C̃'^{−y}`; verifier checks `e(Q, C̃') = e(g, D̃)`; sigma proof in G2.
  - y is linked to the credential through a Pedersen commitment `K_x = g^y h^r` that the BBS proof opens to the same hidden message; every leaf proves its own opening of `K_x`, so leaves can sit under OR and threshold (CDS) without shared responses.
- BBS proof (Tessaro–Zhu form, as in credx): `Ā = A·r`, `D = B·r`, `B̄ = D − e·Ā`; verifier checks `e(Ā, W) = e(B̄, g̃)`; sigma relations `D − B̄ = e·Ā` and `P1 + Q1·dom + Σ_rev H_i m_i = r⁻¹·D − Σ_hid m_i H_i`.
- Aggregate receipt for `∀x∈S. NotRevoked(x)`: `W = A^{1/P_S(α)}`, from α or as `∏ C_i^{λ_i}`, `λ_i = ∏_{j≠i} 1/(y_j − y_i)`; check `e(W, [P_S]_2) = e(A, g̃)`.
- Distinctness: `Δ = K_i/K_j`, prove knowledge of `(u, t)` with `g = Δ^u h^t`.
- Composition: AND = one challenge; OR / at least k = CDS with a degree `n−k` polynomial over the branch challenges; at most k over a domain of size n = at least `n−k` of the dual body.

## Query language

Concrete syntax = the thesis table plus `->`, `Sig(x, "Name")`, `SameHolder(x, y)`, `Active(x)`.
Pipeline: parse → desugar (`Active` → `NotRevoked` on our domains) → NNF (flip dual atoms) → classify
(polarity) → CAS mode → compile → prove / verify.

- Classification: Revoked/Issued ↑, NotRevoked/NotIssued ↓, credential atoms neutral; ∧/∨ join; ¬ flips;
  quantifier over group or Presented = body (`atmost` flips); `∀x∈Issued` = ↓ ⊔ body; `∃/atleast x∈Issued` = ↑ ⊔ body;
  `atmost x∈Issued` = ↓ ⊔ flip(body). ↑ = stable, ↓ = co-stable, mixed = volatile, neutral = state-independent.
- CAS mode: stable/state-independent → none; otherwise all domains groups → group versions; else global versions.
- Materialisation: subformulas without credential atoms over public groups / Issued are evaluated
  publicly against the bound registry state (constant folding by prover and verifier); for
  `∀x∈S.NotRevoked` the aggregate receipt is attached as evidence. Variables with `Sig` (holder-bound)
  over Presented, a group or Issued are proved in zero knowledge. `∀`/`atmost` over holder-bound
  variables are rejected. Unsupported shapes are reported as uncompilable.
- The proof binds (Fiat–Shamir) the query text, the bindings, and every referenced registry's
  `(registryId, version, values hash)`.

## Contract API (new parts)

- `StateRegistry.issueUpdate(registryId, IssueStep step)` with `step = {newI, newWIR, T, R, z}` (Schnorr), and
  `guardedIssueUpdate(registryId, step, Guard g)`.
- `revoke(registryId, y, newA, newRtilde, newWIR)` and `guardedRevoke(registryId, y, newA, newRtilde, newWIR, Guard g)`.
- `Guard = {policyId, uint64[] expectedVersions, bytes32 proofHash}`; expected versions in binding order;
  the policy's CAS mode decides whether a binding is compared by group version or by its registry's
  global version; `guardDigest = keccak256(policyId, proofHash)`.
- Value freshness is enforced by the on-chain step checks themselves (new values must step from the current ones).
- `createGroup(registryId, label, members, W_S, g2Srs)` with the on-chain subset check.
- `publishSrs` checks the SRS structure with two batched pairing checks.
- Points are stored in EIP-2537 uncompressed encoding (G1 128 B, G2 256 B).

## Steps (one commit each, roughly)

1. Clean branch (remove önlab contracts, scripts, ts-scripts, gui, cucumber), plan docs.
2. `BLS.sol` + tests against precompiles.
3. `StateRegistry` verify-on-write (revoke checks, issuance Schnorr, SRS check, group subset check) + tests.
4. `PolicyRegistry` + guarded updates through policies + tests.
5. Off-chain crypto: field/curve helpers, EIP-2537 encoding, accumulators, BBS (cross-checked with the library), sigma/CDS + tests.
6. Query language front end + classification + exhaustive semantic check.
7. Compiler, prover, verifier + tests per rule.
8. Chain client, actors, flat reservation e2e on anvil.
9. Evaluation: TOCTOU pair, exhaustive classification table, benchmarks (proof time/size, gas) → `design/EVALUATION.md`.
10. OP Sepolia deploy script (run only with a funded key and an explicit go).
