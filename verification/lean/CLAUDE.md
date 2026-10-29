# Lean model of the credential lifecycle

A frozen Lean 4 model of the credential lifecycle in Kocsis Kamilla's TDK paper, and the targets to prove about it. `CONTRACT.md` defines the scope, the ideal-crypto assumptions, the target tables with theorem names, and the axiom policy. Read it before writing any proof.

`Model.lean` and `CONTRACT.md` are **sealed**: `frozen/spec.sha256` holds their hashes, and every proof file imports `Model` exactly as it is. A sealed target that looks wrong is a finding to report, with the target left as it stands.

## Build

```sh
bash scripts/setup-toolchain.sh                 # pinned Lean 4.23.0 into ./tools, hash-checked
export PATH="$PWD/tools/lean-4.23.0/bin:$PATH"  # fish: fish_add_path $PWD/tools/lean-4.23.0/bin
bash scripts/check.sh                           # seal, forbidden mechanisms, build, audit coverage
```

With elan installed, `lake build` alone picks up `lean-toolchain`. The project uses `Std` only and has no Lake dependencies. Proofs must keep the whole build within a 16 GB machine.

`scripts/check.sh` is the gate. It is **green** when it prints `check.sh: OK`. CI runs the same script.

## Steps

1. **Read.** Read `CONTRACT.md`, then `Model.lean`. Done when you can name the theorem for every target and say which lemmas each claim rests on.
2. **Prove.** Put helper lemmas and one `theorem <name> : <Spec>` per target in modules under `Lifecycle/` (`import Model`, `namespace Lifecycle`), names exactly as in the contract's tables, and add each module to `roots` in `lakefile.toml`. Keep modules under about 600 lines. The witness and necessity targets are theorems like the rest: build the concrete runs and prove each `Accepts` by unfolding. Done when every target is proved, proved false (step 3), or recorded as open in `THEOREMS.md`.
3. **Counterexample**, only for a false target: prove `theorem <name>_false : ¬ <Spec>` in `Counterexamples.lean` from a concrete instance, and propose the corrected statement in `PAPER-COVERAGE.md`. The sealed target stays as it is.
4. **Audit.** Create `Audit.lean`, a root in `lakefile.toml`, importing every module. For each target it has `#check (<name> : <Spec>)` and `#guard_msgs in #print axioms <name>` with the expected message in a doc comment above it. Done when `scripts/check.sh` is green.
5. **Distinctness.** Before each commit, run `python3 -I scripts/check-distinct.py <refs>` against Sinka Tibor's Lean work: a checkout of [argos-formal](https://github.com/snktibor/argos-formal) `main`, one of each of its pull-request heads, and the reconstruction in `fabric-vdr-core/verification/lean`. Reuse ideas, never text.
6. **Report.** Write `THEOREMS.md`: every target with its status (proved, false, open), its file and line, and its axioms. Write `PAPER-COVERAGE.md`: one row per paper lemma and per design-level claim S1–S11, giving the theorem and its disposition, plus the contract's list of claims the model cannot express. For each paper finding backed by a theorem, give a ready-to-paste `\atodo[inline]{…}` in English and the label of the chapter it goes after (`content/03-proposed-approach.tex`); list findings that need judgment separately. Done when every target and every claim has a row.

## Time box

The whole run is hours, not days. When a target has resisted for about an hour of attempts, record it as open in `THEOREMS.md`, with the furthest lemma reached and what blocks it, and move on. Return to open targets after the rest are done.

## Proof notes

- Order that follows the dependencies: validity of reachable registry states; `Vdr.runWith` facts (a `foldl`, so `List.foldl_append` splits runs; `Vdr.submit` unfolds with `if_pos`/`if_neg`); the invariant that under `Checks.all` the stored values represent `replay RegState.init c.log` (from `checks_exact`); `history` facts; then the paper lemmas; then the claims.
- `Vdr.submit` decides acceptance classically. Use `by_cases h : Vdr.Accepts k issuer c t` and `simp [Vdr.submit, h]`.
- `RegState`, `Accs` and `Vdr` have predicate fields. Equality goals need `funext` and `propext`; the `mk.injEq` simp lemmas reduce structure equality to field equality. `Models` respects pointwise-equal states; prove that once.
- `Models` uses the assignment `fun _ => 0`. Narrowing and the group-version lemma need a generalization to `Φ.Scoped bound` under any assignment that sends every variable of `bound` to an ID the updates do not touch; prove that first, by induction on the formula.
- `StateOrderSpec` (d) and the backward half of `S7FreshnessSpec` need runs that reach a given valid state: issue the missing members of `iss`, then revoke the missing members of `rev`, skipping IDs already present (lists may repeat). `honest_update` makes every such step accepted.
- `reservationGuard S` is not stable when `S` has a member: compare `Σ₀` with the state where that member is issued and revoked.

## Commits

Commit on this branch at each checkpoint (a group of targets proved, the audit, the reports), with `scripts/check.sh` green and the distinctness check passing at every commit. Push and open a pull request only when the brief that launched you says so.
