# Paper coverage

This historical mapping is not the current implementation coverage table. Use [CLAIM-EVIDENCE.md](../../design/CLAIM-EVIDENCE.md) and [ENFORCED-GUARDS.md](../../design/ENFORCED-GUARDS.md) for the restored public-guard implementation, its permanent policy bindings and unsupported private update guards. The sealed model remains unchanged.

What the Lean model says about each lemma and design-level claim of the historical paper source `content/03-proposed-approach.tex`, revision `e53e4837cfaf28f11ea9cf69b7e9c7b3e206d22e` (private source, not included in this artifact). Theorem locations and axioms are in `THEOREMS.md`; the encoding and its assumptions are in `CONTRACT.md`.

The findings for the author are in `paper-todos.json`. Its `todos` are ready-to-paste `\atodo[inline]{…}` notes, each backed by the theorems it names and placed by a LaTeX label of the chapter. Its `judgment` items are observations that no theorem backs; they need a supervisor's call before they become to-dos. To preview or insert the notes:

```sh
python3 -I scripts/apply-paper-todos.py <paper>/content/03-proposed-approach.tex          # diff only
python3 -I scripts/apply-paper-todos.py <paper>/content/03-proposed-approach.tex --write  # insert
```

The script places notes by text, so it applies on top of other review layers that keep the anchors, and skips notes already present. On e53e483 all 14 notes apply, and the paper builds with them without errors or undefined references.

## Lemmas

| Paper | Theorem | Disposition | To-do |
|---|---|---|---|
| lem:state-order | `state_order` | Proved as stated. Part (d) needs only the larger state to be valid. | `lean-proof-state-order` |
| lem:atom-classes | `atom_classes` | Proved as stated. | `lean-proof-atom-classes` |
| lem:closure | `closure` | Proved as stated. It covers quantifiers over conditions only (judgment `closure-gap`). | `lean-proof-closure` |
| lem:narrowing | `narrowing` | Proved as stated. | `lean-proof-narrowing` |
| lem:global-version | `global_version` | Proved, with versions as positions in the log. | `lean-proof-global-version` |
| lem:group-version | `group_version` | Proved, between two versions of the history. | `lean-proof-group-version` |
| lem:fresh-guard | `fresh_guard_sound` | Proved against the current state of every reachable VDR. | `lean-proof-fresh-guard` |
| lem:representation | `representation` | Proved, reading `A` under static add as the to-do at def:representation says: its value encodes `Rev`. | `lean-proof-representation` |
| lem:fresh-values (commented out) | none | Dropped with def:fresh-values (decision of 2026-10-29): the checks reject stale values (`stale_values`). | `lean-fresh-values` |
| missing | `checks_exact` | The checks of sec:plain-comparison, with an issuance check, accept exactly the honest values of an enabled update. | `lean-checks-lemma` |
| missing | `honest_update` | The issuer's enabled update with honest values is always accepted. | `lean-acceptance` |

## Design-level claims

| Claim | Theorem | Disposition | To-do |
|---|---|---|---|
| S1 Single writer | `s1_single_writer` | Proved; holds by the sender check (`sender_check_needed`). Availability and the trapdoor are outside the model. | |
| S2 Lifecycle discipline | `s2_lifecycle` | Proved, including unique issuance and revocation of active credentials only. Without the revoked-⊆-issued check it fails (`subset_check_needed`). | `lean-checks-lemma` |
| S3 Monotone growth | `s3_monotone` | Proved. Without the issuance check `I` can shrink (`issue_check_needed`); without the step check `R̃` can (`step_check_needed`). | `lean-fresh-values` |
| S4 Public state and revocation log | `s4_revocation_log` | Proved for the log's structure. "Public" is availability. Conflicts with S9 (judgment `s4-s9`). | |
| S5 Log-bound updates | `s5_log_bound` | Proved. | `lean-acceptance` |
| S6 Two-sided, exclusive status | `s6_exclusive` | Proved; carried by the consistency check (`consistency_check_needed`). Unforgeability of proofs is assumed (I2, I3). | |
| S7 Freshness by monotonicity | `s7_freshness` | Proved on the VDR. "Must be proved against the current state" is false for case (b) (`stale_volatile_guard`). | `lean-s7-wording` |
| S8 Atomic guarded updates | `s8_guarded_update` | Proved in the reading the design supports. The literal wording is false (`stale_stable_guard`, `stale_volatile_guard`); the example is confirmed (`alice_bob`), the bound is reached (`one_reservation`) and not exact (`both_rejected`), the policy is needed (`unguarded_race`), and so is the guard check (`guard_check_needed`). | `lean-s8-wording` |
| S9 Hidden identifier | none | Not expressible: confidentiality needs an adversary and knowledge, which a set model lacks. | judgment `s4-s9` |
| S10 Independent partitions | `s10_partitions` | Proved; holds by construction. Per-registry secrets are cryptography. | |
| S11 Authenticated history (proposed) | `s11_history` | Proved. | `lean-s11-history` |

## Claims the model cannot express

- S9 entirely; the availability, trapdoor and privacy parts of S1, S4 and S10; the unforgeability part of S6. `CONTRACT.md` gives the reason for each.
- The inherited claims I1–I7 are assumptions of the model, not targets.

## Caveat: the issuer holds α

`CONTRACT.md` says that check (5) rejects a double revocation "because the issuer cannot compute the quotient `W_IR`". That is true only of parties without α. The issuer holds α, so it can compute `W_IR = g^{P_Iss(α)/P_Rev(α)}` for any two sets, and check (5) then passes after it revokes an ID that was never issued or that is already revoked.

The proofs are unaffected. The model assumes that each check decides its set relation exactly, and the theorems rest on that assumption, not on the pairing. What changes is the mechanism that makes the assumption true against the issuer. In the contract of [vc-rollup#4](https://github.com/csillag2004/vc-rollup/pull/4), storage records which IDs are issued and which are revoked and checks both relations directly (`AlreadyIssued`, `NotIssued`, `AlreadyRevoked`). `test_issuerWithAlphaCannotRevokeUnissued` builds the forged `W_IR` from α and expects `NotIssued`. The same storage check settles the `repeated-issuance` judgment below.

The same contract fixes a group's members at creation and accepts only issued IDs. `both_rejected` issues into a group, so it describes a run the contract no longer allows.

`CONTRACT.md` is sealed, so its sentence stays as it is and this caveat stands beside it.

## Findings without a theorem

These are the `judgment` items of `paper-todos.json`:

- `s4-s9`: S4 publishes revoked identifiers, S9 says only issuer and holder know them; S9 holds as unlinkability.
- `closure-gap`: lem:closure does not cover quantifiers over formulas.
- `repeated-issuance`: no pairing check rejects issuing the same identifier twice; uniqueness rests on random identifiers.
- `structural-stability`: an implementation decides case (a) by structure; the claims should carry over, unproved.
- `contention-cost`: on a public chain a rejected update costs the issuer gas.
