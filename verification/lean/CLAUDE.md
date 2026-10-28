# Lean model of the credential lifecycle

A frozen Lean 4 model of the credential lifecycle in Kocsis Kamilla's TDK paper, and the targets to prove about it. `CONTRACT.md` defines the scope, the ideal-crypto assumptions, the target list with theorem names, the required witnesses and the axiom policy. Read it before writing any proof.

`Model.lean` and `CONTRACT.md` are **sealed**: `frozen/spec.sha256` holds their hashes, and every proof file imports `Model` exactly as it is. A sealed target that looks wrong is a finding to report, with the target left as it stands.

## Build

```sh
bash scripts/setup-toolchain.sh                 # pinned Lean 4.23.0 into ./tools, hash-checked
export PATH="$PWD/tools/lean-4.23.0/bin:$PATH"  # fish: fish_add_path $PWD/tools/lean-4.23.0/bin
bash scripts/check.sh                           # seal, forbidden mechanisms, lake build, axioms
```

With elan installed, `lake build` alone picks up `lean-toolchain`. The project uses `Std` only and has no Lake dependencies. `lake build` of `Model` takes under a second and well under 1 GB of memory; proofs must keep the whole build within a 16 GB machine.

`scripts/check.sh` is the gate. It is **green** when it prints `check.sh: OK`. CI runs the same script.

## Steps

1. **Read.** Read `CONTRACT.md`, then `Model.lean`. Done when you can name the theorem for every `*Spec` and say which paper lemmas each claim target rests on.
2. **Prove.** Create `Proofs.lean` (`import Model`, `namespace Lifecycle`) with helper lemmas and one `theorem <name> : <Spec>` per target, names exactly as in the contract's tables. Add each new module to `roots` in `lakefile.toml`. Split into more modules when a file passes about 600 lines. Done when every target is proved, proved false (step 4), or recorded as open in `THEOREMS.md`.
3. **Witness.** Create `Examples.lean` with one kernel-checked theorem per bullet of the contract's "Non-vacuity and falsifiability" list. Done when every bullet has a named theorem.
4. **Counterexample**, only for a false target: prove `theorem <name>_false : ¬ <Spec>` in `Counterexamples.lean` from a concrete instance, and propose the corrected statement in `PAPER-COVERAGE.md`. The sealed target stays as it is.
5. **Audit.** Create `Audit.lean` importing every module, with `#check (<name> : <Spec>)` for each proved target and `#print axioms <name>` for every theorem in `Proofs`, `Examples` and `Counterexamples`. Done when `scripts/check.sh` is green.
6. **Report.** Write `THEOREMS.md`: every target with its status (proved, false, open), its file and line, and its axioms as printed by `Audit.lean`. Write `PAPER-COVERAGE.md`: one row per paper lemma and per design-level claim S1–S10, giving the theorem and its disposition, plus the contract's list of claims the model cannot express. Done when every target and every claim has a row.

## Time box

The whole run is hours, not days. When a target has resisted for about an hour of attempts, record it as open in `THEOREMS.md`, with the furthest lemma reached and what blocks it, and move on. Return to open targets after the rest are done.

## Proof notes

- Proving order that follows the dependencies: validity of reachable registry states; `Vdr.run` facts (it is a `foldl`, so `List.foldl_append` splits runs; `Vdr.submit` unfolds with `if_pos`/`if_neg`); the S5 invariant that the stored values represent `replay RegState.init c.log` and that `c.history c.version` is `c.reg`; then the paper lemmas; then the claims.
- `Vdr.submit` decides acceptance classically. Use `by_cases h : Vdr.Accepts issuer c t` and `simp [Vdr.submit, h]`.
- `RegState`, `Accs` and `Vdr` have predicate fields. Equality goals need `funext` and `propext`; the `mk.injEq` simp lemmas reduce structure equality to field equality.
- `Models` uses the assignment `fun _ => 0`. Narrowing and the group-version lemma need a generalization to `Φ.Scoped bound` under any assignment that sends every variable of `bound` to an ID the updates do not touch; prove that first, by induction on the formula.
- `StateOrderSpec` (d) needs the finiteness lists from `RegState.Valid`: issue the missing members of `σ'.iss`, then revoke the missing members of `σ'.rev`, skipping IDs already present (lists may repeat).

## Commits

Commit on this branch at each checkpoint (a group of targets proved, witnesses done, reports written), with `scripts/check.sh` green at every commit. Push and open a pull request only when the brief that launched you says so.
