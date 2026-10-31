# Credential lifecycle model: frozen contract

First frozen 2026-10-28, re-frozen 2026-10-29 after Martin's review of the first freeze and before any proof. `Model.lean` holds the exact definitions and the named `*Spec` propositions; this file says what they mean, what they leave out, and what the proving phase must deliver. `frozen/spec.sha256` seals both files. Proof files import `Model` and never edit it.

Tags: [USER] marks a requirement or decision from Martin (brief of 2026-10-28, review of 2026-10-29). [AGENT] marks an encoding or policy decision made while writing the model.

## Source

- The paper's `content/03-proposed-approach.tex` at e53e483 (private source, not included in this artifact), SHA-256 `9cb08241ad58f4a385d8f9a9435a1db4bff0dd38674c6295270492042b7639d0`. The first freeze used `content/proposed-approach.tex` at 967fe4d; the formal sections differ from it only in `\gls` and `\cref` macros.
- [USER] Sections in scope: `sec:credential-lifecycle`, the design-level claims table `tab:design-claims`, `sec:atomic-guarded-update` including Compare-and-swap, "Three accumulators: A, R̃, I" with the checks of `sec:plain-comparison`, and "Versioned state and authenticated history". The query language sections and the Solidity code are out of scope.
- [USER] The abstract is frozen (submitted to the TDK portal). Findings are clarified in the body; none proposes an abstract edit.

## Scope

- [USER] Model the state at the level of sets. Accumulators and pairing checks are ideal sets. The cryptography is assumed, not proved.
- [USER] One `*Spec` per design-level claim the model can express, and a list of the claims it cannot express, with reasons.
- [USER] The model, not the Solidity contracts. No proof search that takes days. The build must run on a clean Ubuntu VM within 16 GB of memory (32 GB at most).
- [USER] Lean 4 with `Std` only, pinned toolchain, targets frozen before proof search and sealed by hash, CI that runs `lake build`.
- [USER] Decisions of 2026-10-29:
  - A transaction carries the new accumulator values, and the VDR accepts them only if they pass the on-chain checks (option C2). The model adds an issuance check the paper lacks, and drops def:fresh-values: against arbitrary values a version check on the values protects nothing, and the step and issuance checks already compare the values with the stored ones. The global version serves guard freshness and the authenticated history (holders refreshing witnesses, proofs against past states).
  - S8 is frozen in the reading the design supports; its wording in the paper is sloppy, not a different design. S7 is stated on the VDR. S1 and S10 stay as targets that hold by construction.
  - The witnesses are sealed targets. The paper-lemma tier stays, with two additions. A new claim S11 (authenticated history) is added; no claim about the detectability of rejections.
  - Every check gets a necessity target: switching it off makes a named claim false. The idea is from Sinka Tibor's `argos-formal` mutations, implemented differently and with no code copied.
  - No human review between this freeze and the proofs.
- [AGENT] Toolchain `leanprover/lean4:v4.23.0`, the same release archive (SHA-256 `ecd028d6…22ba`) as Sinka Tibor's Lean work. `scripts/setup-toolchain.sh` installs it without elan.

## What "ideal" means

These assumptions replace the cryptography. None of them is proved here.

- [USER] Each stored accumulator value is the set its group element encodes: `I` encodes `Iss`, `R̃` encodes `Rev`. With static add, `A`'s value does not change on issuance and encodes `Rev` (`Accs.Arev`); a holder proves `y ∈ A` with a witness the issuer gave at issuance, so the set of IDs provably in `A` is `I \ Arev` (`Accs.A`). This settles the to-do at def:representation: both readings give `Iss \ Rev`.
- [AGENT] The issuer gives a holder a witness exactly when it issues the holder's ID. Witness issuance and refresh are not modelled.
- [AGENT] A proof of a formula against a state exists exactly when the formula holds there. This stands in for the soundness and completeness of BBS presentations, sigma protocols and accumulator witnesses (I1–I3).
- [AGENT] Each on-chain pairing check decides its set relation exactly. Pairing checks act on multisets (a repeated factor `(y+α)` is visible); the set model folds multiplicity into two checks:
  - the step check requires that `y` is not yet revoked. At group level, check (5) rejects a double revocation, because the issuer cannot compute the quotient `W_IR`;
  - the issuance check requires that `y` is not yet issued. At group level no check rejects a repeated issuance; uniqueness rests on choosing IDs at random.
- [AGENT] Versions identify states (anchored hashes, I4) and `Tx.sender` is the true sender (I6).

## Encoding

Registry layer (sec:atomic-guarded-update):

- [AGENT] Credential IDs are `Nat`. A set of IDs is a predicate `Nat → Prop`. `RegState` is a pair `(iss, rev)` without built-in invariants; `RegState.Valid` is def:registry-state (both sets finite, `rev ⊆ iss`). A set is finite when it has the members of some list.
- [AGENT] `Update`, `Enabled`, `apply`, `Step` and `Reach` follow def:updates and not:steps. `Reach` is the reflexive-transitive closure of `Step`.

Formula layer:

- [AGENT] Variables are `Nat`. Conditions and formulas follow def:conditions and def:formulas, with named variables and an assignment `Env`. `Formula.Closed` means every variable is bound. `Models σ Φ` evaluates under a fixed default assignment, which is irrelevant for closed formulas.
- [AGENT] A group and a presented set are lists of IDs; only membership matters. `Domain.presented` carries its set `P`, so a formula may mention more than one presented set. That generalizes the paper harmlessly.
- [AGENT] `∃≥k` holds when a duplicate-free list of `k` members of the domain satisfies the condition. `∃≤k` is the negation of `∃≥(k+1)`. Neither needs a cardinality library.
- [AGENT] Stability (def:atom-classes, def:stable-formulas) quantifies over valid states only, as the paper's "registry states" are valid by definition. Condition stability quantifies over every assignment, which is the paper's "for every `y`".

Accumulator layer (def:representation, def:accumulator-updates, sec:plain-comparison):

- [AGENT] `Accs` stores the three encoded sets. `Accs.update` is def:accumulator-updates (the honest values); `Accs.write u a p` is the stored values after update `u` proposes `p`: an issuance writes `I`, a revocation writes `A` and `R̃`.
- [USER] The checks are the paper's step check (3), consistency check (4) and revoked-subset-of-issued check (5), read as set relations, plus the proposed issuance check `e(I', g̃) = e(I, g̃^y · Q̃)`. The step and issuance checks compare the proposed values with the stored ones; (4) and (5) are checked on the stored values after the update. The paper does not say which update runs which check; the model runs each check on every update, and a check about values an update does not write is trivially true.

VDR layer (Compare-and-swap, versioned state):

- [AGENT] `Vdr` is the stored values plus the public log of accepted updates. The global version is the log's length. `history v` replays the first `v` log entries from `Σ₀`; this is the authenticated history. The group version of `S` is the number of logged updates of IDs in `S`. These satisfy def:global-version and def:group-version by construction.
- [AGENT] A `Tx` has a sender, an update, its proposed values and an optional guard (a formula and `provedAt`, the version of the state `Σ_g` it was proved against).
- [AGENT] `Vdr.Accepts` is def:accepted-update (commented out in the paper, lines 623–632) without its fresh-values condition, plus the single-writer check and the value checks. The guard must be closed, proved against a state of the history (`provedAt ≤ version`), and fresh by one of def:fresh-guard (a) stable, (b) all domains are groups with unchanged group versions, (c) unchanged global version. Enabledness is not a separate condition: the checks imply it (`ChecksExactSpec`).
- [AGENT] `Checks` switches each check on or off. The VDR is `Vdr.run`, with every check on; `Vdr.runWith k` with a check off is a mutation, used only by the necessity targets.
- [AGENT] Case (a) uses semantic stability. An implementation would decide it from the formula's structure (lem:closure), which accepts a subset of these guards. A stricter VDR's run equals this VDR's run on the transactions it accepted, so the safety targets should carry over; that argument is not part of this freeze.
- [AGENT] `Vdr.submit` decides acceptance classically. A rejected transaction changes nothing. `Vdr.runWith` folds `submit` over a list of transactions from the initial VDR, so every reachable VDR is a run of some list.
- [AGENT] Independent registries (S10) are a map from registry IDs to VDRs, each with its own issuer. `sysRun` routes each transaction to its registry.
- [AGENT] The running example's guard is `reservationGuard S`, that is `∀ x ∈ S. NotRevoked(x)`; `ReservationPolicy S txs` says every transaction revoking a member of `S` carries it.

## Frozen targets

Each target is a closed proposition in `Model.lean`. The proving phase proves `theorem <name> : <Spec>` with exactly the names below.

Paper lemmas, and two lemmas the paper lacks:

| Spec | Theorem | Paper | Statement |
|---|---|---|---|
| `StateOrderSpec` | `state_order` | lem:state-order | `⊑` is a partial order with least element `Σ₀`; steps and runs move up; every larger valid state is reachable. |
| `AtomClassesSpec` | `atom_classes` | lem:atom-classes | `Revoked`, `Issued` monotone and not antitone; `NotRevoked`, `NotIssued` antitone and not monotone. |
| `ClosureSpec` | `closure` | lem:closure | Parts (a)–(d) as stated. |
| `NarrowingSpec` | `narrowing` | lem:narrowing | As stated. |
| `GlobalVersionSpec` | `global_version` | lem:global-version | History states at versions `v, w` are equal iff `v = w`, and reachable from one another iff `v ≤ w`. |
| `GroupVersionSpec` | `group_version` | lem:group-version | Between two history versions. |
| `FreshGuardSpec` | `fresh_guard_sound` | lem:fresh-guard | A fresh guard holds in the current state. |
| `RepresentationSpec` | `representation` | lem:representation | The honest values of an enabled update represent the next state. |
| `ChecksExactSpec` | `checks_exact` | missing | Checks (3)–(5) and the issuance check pass exactly for the honest values of an enabled update. |
| `HonestUpdateSpec` | `honest_update` | missing | In every reachable VDR, the issuer's enabled unguarded update with the honest values is accepted. |

Design-level claims (`tab:design-claims`, plus the proposed S11):

| Claim | Spec | Theorem | What the target says |
|---|---|---|---|
| S1 Single writer | `S1SingleWriterSpec` | `s1_single_writer` | A transaction from anyone other than the issuer changes nothing. Holds by construction. |
| S2 Lifecycle discipline | `S2LifecycleSpec` | `s2_lifecycle` | In every reachable VDR, `A ⊆ I`, `R̃ ⊆ I`, `A ∪ R̃ = I`; the log has no repeated update; every logged revocation follows the issuance of the same ID; an accepted revocation revokes an active credential; an accepted issuance issues a fresh ID. |
| S3 Monotone growth | `S3MonotoneSpec` | `s3_monotone` | `I` and `R̃` only grow; leaving `A` means entering `R̃`; a revoked ID is never in `A` again. |
| S4 Public state and revocation log | `S4RevocationLogSpec` | `s4_revocation_log` | The ordered revocation log lists exactly `R̃`, each ID once, and only grows by appending. |
| S5 Log-bound updates | `S5LogBoundSpec` | `s5_log_bound` | Every logged update was enabled in the state its log prefix determines; the stored values represent the state the whole log determines; an update that fails a check changes nothing. |
| S6 Two-sided, exclusive status | `S6ExclusiveSpec` | `s6_exclusive` | No ID is in `R̃` at one point and in `A` at the same or a later point. |
| S7 Freshness by monotonicity | `S7FreshnessSpec` | `s7_freshness` | A stable closed formula true at any version of the history stays a fresh guard in every extension of the run; a formula that is not stable is, in some run, true at an earlier version and false in the current state. |
| S8 Atomic guarded updates | `S8GuardedUpdateSpec` | `s8_guarded_update` | (1) An accepted guarded update takes effect in a state where its guard holds. (2) Under `ReservationPolicy S`, at most one member of `S` is ever revoked, under arbitrary interleaving and arbitrary proof versions. |
| S10 Independent partitions | `S10PartitionsSpec` | `s10_partitions` | Each registry ends up exactly as if only the transactions addressed to it had been submitted. Holds by construction. |
| S11 Authenticated history (proposed) | `S11HistorySpec` | `s11_history` | Versions only grow; the state at every version stays the same as the log grows; the stored values encode the state at the current version. |

Necessity (each check carries a claim):

| Spec | Theorem | Check switched off | Claim that becomes false |
|---|---|---|---|
| `SenderCheckNeededSpec` | `sender_check_needed` | sender | S1 |
| `IssueCheckNeededSpec` | `issue_check_needed` | issuance (proposed) | S3: the issuer can drop IDs from `I` |
| `StepCheckNeededSpec` | `step_check_needed` | step (3) | S3: a revocation can drop IDs from `R̃` |
| `ConsistencyCheckNeededSpec` | `consistency_check_needed` | consistency (4) | S6 |
| `SubsetCheckNeededSpec` | `subset_check_needed` | revoked ⊆ issued (5) | S2: a never-issued ID can be revoked |
| `GuardCheckNeededSpec` | `guard_check_needed` | guard freshness | S8 |

Witnesses (non-vacuity, and the counterexamples behind the paper findings):

| Spec | Theorem | What it shows |
|---|---|---|
| `StaleStableGuardWitness` | `stale_stable_guard` | Case (a) accepts a guard proved against an earlier, different state. S8's literal wording is false. |
| `StaleVolatileGuardWitness` | `stale_volatile_guard` | Case (b) accepts a guard that is not stable, proved against an earlier, different state. S8's literal wording and S7's "must be proved against the current state" are false. |
| `AliceBobWitness` | `alice_bob` | Both reservations are acceptable against the same state; after Alice's, Bob's is rejected whatever values it carries, and his guard is false. |
| `UnguardedRaceWitness` | `unguarded_race` | Without the policy, two members of a group end up revoked. |
| `OneReservationWitness` | `one_reservation` | Under the policy, a member of the group can be revoked: the bound is reached. |
| `BothRejectedWitness` | `both_rejected` | Two reservations acceptable against the same state are both rejected after an issuance into the group, although the guard still holds: "exactly one" does not hold. |
| `StaleValuesWitness` | `stale_values` | The checks reject an enabled update whose values are the honest values of an earlier state, with no version check on values. |

## Claims the model cannot express

- S9 Hidden identifier, entirely. It is a confidentiality claim. A set-level model has no adversary, no knowledge and no presentation transcripts, so "known only to its issuer and its holder" and "proved in zero knowledge" have nothing to refer to.
- S1, in part. "Every other party can read the state, verify against it and prove from it" is availability (I5). That only the holder of the trapdoor `α` can compute new accumulator values is cryptography (I3). The target covers the VDR's sender check.
- S4, in part. "Public" and "anyone can read without asking" are availability. The example's privacy (the notary does not learn whose credential was revoked) is confidentiality. The target covers the structure of the revocation log.
- S5, in part. Re-running the pairing checks against the public log is ideal here. The target covers what the checks protect: the state is determined by the log, and failed updates have no effect.
- S6, in part. That nobody can forge contradictory proofs rests on the soundness of I2 and I3. With ideal proofs it reduces to the set disjointness the target states, which the consistency check carries.
- S8, the literal wording, which the witnesses refute; the target is the reading the design supports.
- S10, in part. "Each with its own secret" is cryptography. The target covers independence of state.
- Inherited claims I1–I7 are assumptions of this model, not targets.

## Paper findings

Observations for the author, each to be clarified in the body. The model does not depend on resolving them.

1. S8's wording ("takes effect only in the state on which its guard was evaluated") describes fresh-guard case (c) only; (a) and (b) accept guards proved against earlier states (`stale_stable_guard`, `stale_volatile_guard`). The design is right and the sentence is loose. The abstract's compare-and-swap sentence is equally loose and stays as submitted; the body says what the check compares.
2. S7's "must be proved against the current state" is false for case (b): a guard over groups whose versions did not change is accepted after unrelated updates (`stale_volatile_guard`). Its example holds only if Alice's group contains Bob's credential.
3. def:accepted-update and lem:fresh-values are commented out, so the live text has no acceptance rule.
4. The stated reason for def:fresh-values ("only the global version guarantees" fresh values) does not hold for revocations: the step and consistency checks tie the new `A` and `R̃` to the stored ones (`stale_values`). For issuance no check ties `I'` to the stored `I`; the model adds one (`issue_check_needed`). With it, the version serves guards and the authenticated history, not values.
5. The checks of sec:plain-comparison are not connected to def:accumulator-updates; `checks_exact` is the missing lemma. The list does not say which update runs which check.
6. S4 makes the ordered list of revoked identifiers public, and the revocation step check needs `y` in the clear. S9 says an identifier is known only to its issuer and holder. Both cannot hold after a revocation; S9 holds as unlinkability.
7. lem:closure covers quantifiers over conditions only, not `Q x ∈ D. Φ` with a formula body. The prose claim that the class of every formula follows from its structure relies on the fallback "otherwise treat it as volatile". A gap in coverage, not a false statement.

## False targets

If a target turns out false, keep it unchanged. Prove `theorem <name>_false : ¬ <Spec>` with a concrete counterexample in `Counterexamples.lean`, and propose a corrected statement in `PAPER-COVERAGE.md`. Never weaken a target, and never edit `Model.lean` or this file.

## Oracle and evidence

- [AGENT] Forbidden in proof files: `sorry`, `admit`, `native_decide`, `axiom` declarations, `unsafe`, `implemented_by`, `extern`, `debug.skipKernelTC`.
- [AGENT] Allowed axioms: `propext`, `Quot.sound`, `Classical.choice`. The model itself needs `Classical.choice`, because `Vdr.submit` decides acceptance classically.
- [USER] `Audit.lean` is part of the build. For each target it has `#check (<theorem> : <Spec>)` and `#guard_msgs in #print axioms <theorem>` with the expected axiom list, so the build fails if a theorem's axioms change. CI runs `lake build --wfail`.
- [AGENT] `THEOREMS.md` lists every target with its status (proved, false with counterexample, or open) and its axioms. `PAPER-COVERAGE.md` maps each paper lemma and claim to its theorem and disposition, including this file's list of claims the model cannot express.
- [USER] The final report maps every kernel-checked finding to a ready-to-paste `\atodo[inline]{…}` keyed to a LaTeX label of the chapter, so it merges with other review layers; findings that need judgment are listed separately. The run does not edit the paper.
- [USER] No file of this directory may match Sinka Tibor's Lean work ([argos-formal](https://github.com/snktibor/argos-formal), its pull requests, the reconstruction in `fabric-vdr-core`); `scripts/check-distinct.py` checks this before each commit.
