# Changes the thesis text needs (not applied here)

Reference: `TDK26-Kocsis-Kamilla/content/proposed-approach.tex`, `background.tex`, `detaild_trust_model.tex`.

## Background
1. Replace the "BBS+ signatures" subsection with BBS (IETF `draft-irtf-cfrg-bbs-signatures`, signature `(A, e)`, Tessaro–Zhu); keep BBS+ at most as history.
2. Layer 2: describe an optimistic rollup (OP Stack, OP Sepolia) instead of Scroll zkEVM, and the EIP-2537 BLS12-381 precompiles (pairing check, MSM). Maintainability already says "optimistic".
3. Add compare-and-swap (existing todo) and the pairing notation `e`, `g̃`, `Q̃ = g̃^α`, `Q = g^α`.

## 3.1 System model, 3.4 VDR
4. `def:representation`, `def:accumulator-updates`: `A = V0^{1/P_Rev(α)}` (static add); issuing changes only I (and `W_IR`). Fix `lem:representation` accordingly.
5. Groups (def:domains, first item): a finite set of **already issued** credential IDs, fixed by a party other than the prover, anchored in the VDR with an on-chain subset check `e(W_S, [P_S]_2) = e(I, g̃)`. Scope: `W_S = I^{1/P_S(α)}` can be computed for *any* set by whoever knows α, so the check binds an honest issuer only (like every check that compares values at α); without α, `W_S` needs the whole issued set, so in practice only the issuer anchors groups.
6. `def:group-version`: say explicitly that, by 5., the only update that can touch a member is revocation.
7. VDR components: add the PolicyRegistry and CredDef-level rules (policy bound to issue / revoke / present). Consider a new claim in the S1–S10 table ("policy-enforced lifecycle").

## 3.2 Trust model
8. Verify on write is now true: the contract checks step, consistency and subset on every revocation; issuance is step-checked in zero knowledge (`T = I^y` + Schnorr, y stays hidden). Uniqueness of a fresh y is not checkable and rests on the honest issuer.
9. Guard proofs are checked off-chain by the updater; the chain stores a guard digest. Say so in the scope.

## 3.3 Atomic guarded update
10. Formula classes: use stable / co-stable / volatile everywhere; line ~402 says "non-stable"; cite Chandy–Lamport precisely.
11. `lem:closure` (d) is incomplete (e.g. `atmost k x∈Issued. NotRevoked(x)` is volatile); add the polarity rules (↑/↓/mixed, `∀x∈Issued` = ↓ ⊔ body, `∃/atleast x∈Issued` = ↑ ⊔ body, `atmost` flips).
12. `def:fresh-guard` (b) stays (group CAS also for volatile group-only formulas).
13. Guards may span several registries (e.g. "issue X only if Y is revoked"); the update then carries the expected version of every bound registry or group. Generalise the fresh-guard definition to a set of versions.
14. Value freshness is enforced by the on-chain step checks (new values must step from the current ones), so a separate expected global version is not needed for it.

## 3.5 Query language
15. Move the concrete syntax table out of the comment; add `->`, `Sig(x, "Name")`, `SameHolder(x, y)`, `Active(x)`.
16. Replace the "domains must not overlap" todo: several quantifiers or `atleast k` over `Presented` get pairwise distinctness proofs (`y_i ≠ y_j`).
17. Over `Presented` (and over holder-bound variables) only ∃ and at least k are meaningful (already in 3.1); fix the typo "∃x ∀S" (line ~45) to "∀x ∈ S".

## Evaluation (empty chapter)
18. TOCTOU pair (naive vs CAS), exhaustive classification check, benchmark table: numbers in `design/EVALUATION.md` once produced.
