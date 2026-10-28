# Credential lifecycle model: frozen contract

Frozen before proof search, 2026-10-28. `Model.lean` holds the exact definitions and the named `*Spec` propositions; this file says what they mean, what they leave out, and what the proving phase must deliver. `frozen/spec.sha256` seals both files. Proof files import `Model` and never edit it.

Tags: [USER] marks a requirement from Martin's brief of 2026-10-28. [AGENT] marks an encoding or policy decision made while writing the model, open to his review.

## Source

- [`content/proposed-approach.tex` at 967fe4d](https://github.com/BlackLight54/TDK26-Kocsis-Kamilla/blob/967fe4df643ca52dea69c26bfc6db840068cf67d/content/proposed-approach.tex), SHA-256 `709d1ec825e4b197697677aaadeed39eecf92eea760bd519c42f1f1fea29ea62`.
- [USER] Sections in scope: `sec:credential-lifecycle`, the design-level claims table `tab:design-claims`, `sec:atomic-guarded-update` including Compare-and-swap, "Three accumulators: A, R̃, I", and "Versioned state and authenticated history". The query language sections and the Solidity code are out of scope.

## Scope

- [USER] Model the state at the level of sets. Accumulators and pairing checks are ideal sets. The cryptography is assumed, not proved.
- [USER] One `*Spec` per design-level claim the model can express, and a list of the claims it cannot express, with reasons.
- [USER] The model, not the Solidity contracts. No proof search that takes days. The build must run on a clean Ubuntu VM within 16 GB of memory (32 GB at most).
- [USER] Lean 4 with `Std` only, pinned toolchain, targets frozen before proof search and sealed by hash, CI that runs `lake build`.
- [AGENT] Toolchain `leanprover/lean4:v4.23.0`, the same release archive (SHA-256 `ecd028d6…22ba`) that Sinka Tibor's reconstruction pinned. `scripts/setup-toolchain.sh` installs it without elan.
- [AGENT] Besides the claim targets, each paper lemma in the sections above gets a frozen target. The lemmas carry "needs a proof" todos in the paper, and the claim proofs need them anyway. This tier can be dropped without touching the claim targets.

## What "ideal" means

These are the assumptions that replace the cryptography. None of them is proved here.

- [USER] Each accumulator is the set its holders can prove membership in: `A` is `Iss \ Rev`, `R̃` is `Rev`, `I` is `Iss` (def:representation with `acc` the identity).
- [AGENT] A proof of a formula against a state exists exactly when the formula holds there. This stands in for the soundness and completeness of BBS presentations, sigma protocols and accumulator witnesses (I1–I3).
- [AGENT] The on-chain pairing checks (step, consistency, revoked-subset-of-issued) decide their set relations exactly. Accordingly, an accepted update stores the update applied to the current stored values. The model has no transaction that carries values of its own.
- [AGENT] Versions identify states (anchored hashes, I4) and `Tx.sender` is the true sender (I6).
- [AGENT] The todo at def:representation says that with static add the value of `A` does not change on issuance. That is a statement about group elements. The set a holder can prove membership in is `Iss \ Rev` under both readings, so the todo does not change this model.

## Encoding

Registry layer (sec:atomic-guarded-update):

- [AGENT] Credential IDs are `Nat`. A set of IDs is a predicate `Nat → Prop`. `RegState` is a pair `(iss, rev)` without built-in invariants; `RegState.Valid` is def:registry-state (both sets finite, `rev ⊆ iss`). A set is finite when it has the members of some list.
- [AGENT] `Update`, `Enabled`, `apply`, `Step` and `Reach` follow def:updates and not:steps. `Reach` is the reflexive-transitive closure of `Step`.

Formula layer:

- [AGENT] Variables are `Nat`. Conditions and formulas follow def:conditions and def:formulas, with named variables and an assignment `Env`. `Formula.Closed` means every variable is bound. `Models σ Φ` evaluates under a fixed default assignment, which is irrelevant for closed formulas.
- [AGENT] A group and a presented set are lists of IDs; only membership matters. `Domain.presented` carries its set `P`, so a formula may mention more than one presented set. That generalizes the paper harmlessly.
- [AGENT] `∃≥k` holds when a duplicate-free list of `k` members of the domain satisfies the condition. `∃≤k` is the negation of `∃≥(k+1)`. Neither needs a cardinality library.
- [AGENT] Stability (def:atom-classes, def:stable-formulas) quantifies over valid states only, as the paper's "registry states" are valid by definition. Condition stability quantifies over every assignment, which is the paper's "for every `y`".

VDR layer (Compare-and-swap, three accumulators, versioned state):

- [AGENT] `Vdr` is the stored triple `(A, R̃, I)` plus the public log of accepted updates. The global version is the log's length. `history v` replays the first `v` log entries from `Σ₀`; this is the authenticated history. The group version of `S` is the number of logged updates of IDs in `S`. These satisfy def:global-version and def:group-version by construction.
- [AGENT] Accumulators are updated from their stored values (def:accumulator-updates applied incrementally), not recomputed from `(Iss, Rev)`. Hence lem:representation and the S2/S6 invariants say something about the stored values.
- [AGENT] A `Tx` has a sender, an update, `valuesAt` (the version of the state `Σ_v` its values were computed from) and an optional guard (a formula and `provedAt`, the version of the state `Σ_g` it was proved against).
- [AGENT] `Vdr.Accepts` is def:accepted-update, which the paper keeps inside `\begin{comment}` ([lines 602–611](https://github.com/BlackLight54/TDK26-Kocsis-Kamilla/blob/967fe4df643ca52dea69c26bfc6db840068cf67d/content/proposed-approach.tex#L602-L611)), plus the single-writer check and enabledness. The guard must be closed, proved against a state of the history (`provedAt ≤ version`), and fresh by one of def:fresh-guard (a) stable, (b) all domains are groups with unchanged group versions, (c) unchanged global version. The values must be fresh: `valuesAt = version` (def:fresh-values).
- [AGENT] Case (a) uses semantic stability. An implementation would decide it from the formula's structure (lem:closure), which accepts a subset of these guards. Whether the claim targets carry over to that stricter VDR is not part of this freeze.
- [AGENT] `Vdr.submit` decides acceptance classically. A rejected transaction changes nothing. `Vdr.run` folds `submit` over a list of transactions from the initial VDR, so every reachable VDR is `Vdr.run issuer txs` for some list.
- [AGENT] Independent registries (S10) are a map from registry IDs to VDRs, each with its own issuer. `sysRun` routes each transaction to its registry.
- [AGENT] The running example's guard is `reservationGuard S`, that is `∀ x ∈ S. NotRevoked(x)`.

## Frozen targets

Each target is a closed proposition in `Model.lean`. The proving phase proves `theorem <name> : <Spec>` with exactly the names below.

Paper lemmas:

| Spec | Theorem | Paper | Statement |
|---|---|---|---|
| `StateOrderSpec` | `state_order` | lem:state-order | `⊑` is a partial order with least element `Σ₀`; steps and runs move up; every larger valid state is reachable. |
| `AtomClassesSpec` | `atom_classes` | lem:atom-classes | `Revoked`, `Issued` monotone and not antitone; `NotRevoked`, `NotIssued` antitone and not monotone. |
| `ClosureSpec` | `closure` | lem:closure | Parts (a)–(d) as stated. |
| `NarrowingSpec` | `narrowing` | lem:narrowing | As stated. |
| `GlobalVersionSpec` | `global_version` | lem:global-version | History states at versions `v, w` are equal iff `v = w`, and reachable from one another iff `v ≤ w`. |
| `GroupVersionSpec` | `group_version` | lem:group-version | Between two history versions. |
| `FreshGuardSpec` | `fresh_guard_sound` | lem:fresh-guard | A fresh guard holds in the current state. |
| `RepresentationSpec` | `representation` | lem:representation | As stated. |

Design-level claims (`tab:design-claims`):

| Claim | Spec | Theorem | What the target says |
|---|---|---|---|
| S1 Single writer | `S1SingleWriterSpec` | `s1_single_writer` | A transaction from anyone other than the issuer changes nothing. True by the sender check; the content is that no other path changes the state. |
| S2 Lifecycle discipline | `S2LifecycleSpec` | `s2_lifecycle` | In every reachable VDR, `A ⊆ I`, `R̃ ⊆ I`, `A ∪ R̃ = I`; the log has no repeated update; every logged revocation follows the issuance of the same ID; an accepted revocation revokes an active credential. |
| S3 Monotone growth | `S3MonotoneSpec` | `s3_monotone` | `I` and `R̃` only grow; leaving `A` means entering `R̃`; a revoked ID is never in `A` again. |
| S4 Public state and revocation log | `S4RevocationLogSpec` | `s4_revocation_log` | The ordered revocation log lists exactly `R̃`, each ID once, and only grows by appending. |
| S5 Log-bound updates | `S5LogBoundSpec` | `s5_log_bound` | Every logged update was enabled in the state its log prefix determines; the stored values represent the state the whole log determines; a rejected transaction changes nothing. |
| S6 Two-sided, exclusive status | `S6ExclusiveSpec` | `s6_exclusive` | No ID is in `R̃` at one point and in `A` at the same or a later point. |
| S7 Freshness by monotonicity | `S7FreshnessSpec` | `s7_freshness` | A formula is stable iff, for all states `σ` reachable from `Σ₀` and `σ'` reachable from `σ`, truth at `σ` implies truth at `σ'`. The forward direction lets a stable statement be proved against any earlier authentic state; the backward direction says every other statement can be falsified later, so it must be proved against the current state. |
| S8 Atomic guarded updates | `S8GuardedUpdateSpec` | `s8_guarded_update` | (1) An accepted guarded update takes effect in a state where its guard holds. (2) Of two transactions whose values were computed at the same version, the second is rejected whenever the first was accepted, whatever comes between. (3) Running example: if every transaction revoking a member of `S` carries the guard `reservationGuard S`, at most one member of `S` is ever revoked, under arbitrary interleaving and arbitrary proof versions. |
| S10 Independent partitions | `S10PartitionsSpec` | `s10_partitions` | Each registry ends up exactly as if only the transactions addressed to it had been submitted. |

The model does not freeze two expressible statements from `sec:credential-lifecycle`, since neither is a design-level claim. The whole-registry comparisons (`A = I` iff nothing is revoked, `R̃ ≠ I` iff something is active) follow from the S2 invariants. The restriction of holder-presented domains to `∃` and `∃≥k` would need a model of the holder's whole wallet.

## Claims the model cannot express

- S9 Hidden identifier, entirely. It is a confidentiality claim. A set-level model has no adversary, no knowledge and no presentation transcripts, so "known only to its issuer and its holder" and "proved in zero knowledge" have nothing to refer to.
- S1, in part. "Every other party can read the state, verify against it and prove from it" is availability (I5). That only the holder of the trapdoor `α` can compute new accumulator values is cryptography (I3). The target covers the VDR's sender check.
- S4, in part. "Public" and "anyone can read without asking" are availability. The example's privacy (the notary does not learn whose credential was revoked) is confidentiality. The target covers the structure of the revocation log.
- S5, in part. Checking an update "against the public log" means re-running pairing checks, which are ideal here. The target covers what the checks protect: the state is determined by the log, and failed updates have no effect.
- S6, in part. That nobody can forge contradictory proofs rests on the soundness of I2 and I3. With ideal proofs it reduces to the set disjointness the target states.
- S8, the literal wording. "Takes effect only in the state on which its guard was evaluated" contradicts def:fresh-guard (a) and (b), which accept guards proved against older states. The target uses the weaker reading the design supports: the guard holds in the state where the update takes effect. Case (c) satisfies the literal wording.
- S10, in part. "Each with its own secret" is cryptography. The target covers independence of state.
- Inherited claims I1–I7 are assumptions of this model, not targets.

## Paper divergences found while encoding

These are observations for the authors. The model does not depend on resolving them.

1. S8's statement is stronger than the mechanism of Compare-and-swap; see above.
2. def:accepted-update and the soundness lemma for fresh values are commented out, so the live text has no acceptance rule. The model uses the commented-out definition as written.
3. S4 makes the ordered list of revoked identifiers public, and the revocation step check needs `y` in the clear. S9 says an identifier is known only to its issuer and holder. Both cannot hold after a revocation.
4. lem:closure covers quantifiers over conditions only, not `Q x ∈ D. Φ` with a formula body. The prose claim that the class of every formula follows from its structure therefore relies on the fallback "otherwise treat it as volatile". This is a gap in coverage, not a false statement.

## Non-vacuity and falsifiability

The proving phase must add kernel-checked witnesses in `Examples.lean`:

- an accepted unguarded issue and revocation, and a rejected transaction from a non-issuer;
- an accepted guarded update under each of fresh-guard cases (a), (b) and (c), where cases (a) and (b) have `provedAt < version` (the counterexample to S8's literal wording);
- Alice and Bob: two `reservationGuard` revocations of different members of `S`, proved at the same version. The first is accepted. The second is rejected, both with its original `valuesAt` and with `valuesAt` updated to the current version (then its stale guard rejects it);
- the same two revocations without guards, both accepted, leaving two members of `S` revoked (the policy hypothesis of S8 (3) is needed);
- a transaction with `valuesAt` below the current version, rejected;
- a formula that is not stable, falsified along a `Reach` chain from `Σ₀` (the backward direction of S7 has content).

If a target turns out false, keep it unchanged. Prove `theorem <name>_false : ¬ <Spec>` with a concrete counterexample in `Counterexamples.lean`, and propose a corrected statement in `PAPER-COVERAGE.md`. Never weaken a target, and never edit `Model.lean` or this file.

## Oracle and evidence

- [AGENT] Forbidden in proof files: `sorry`, `admit`, `native_decide`, `axiom` declarations, `unsafe`, `implemented_by`, `extern`, `debug.skipKernelTC`.
- [AGENT] Allowed axioms: `propext`, `Quot.sound`, `Classical.choice`. The model itself needs `Classical.choice`, because `Vdr.submit` decides acceptance classically. `#print axioms Lifecycle.Vdr.submit` reports exactly these three.
- [AGENT] `Audit.lean` checks each theorem against its spec (`#check (state_order : StateOrderSpec)`) and prints the axioms of every theorem.
- [AGENT] `THEOREMS.md` lists every target with its status (proved, false with counterexample, or open) and its axioms. `PAPER-COVERAGE.md` maps each paper lemma and claim to its theorem and disposition, including this file's list of claims the model cannot express.
- [AGENT] CI checks the seal (`sha256sum --check frozen/spec.sha256`) and runs `lake build`.
