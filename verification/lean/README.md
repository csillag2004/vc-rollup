# Lean model of the credential lifecycle

A frozen Lean 4 model of the credential lifecycle in Kocsis Kamilla's TDK paper, and the targets to prove about it. `CONTRACT.md` defines the scope, the ideal-crypto assumptions, the target tables with theorem names, and the axiom policy.

`Model.lean` and `CONTRACT.md` are **sealed**: `frozen/spec.sha256` holds their hashes, and every proof file imports `Model` exactly as it is. A sealed target that looks wrong is a finding to report, with the target left as it stands.

## Build

```sh
bash scripts/setup-toolchain.sh                 # pinned Lean 4.23.0 into ./tools, hash-checked
export PATH="$PWD/tools/lean-4.23.0/bin:$PATH"  # fish: fish_add_path $PWD/tools/lean-4.23.0/bin
bash scripts/check.sh                           # seal, forbidden mechanisms, build, audit coverage
```

With elan installed, `lake build` alone picks up `lean-toolchain`. The project uses `Std` only and has no Lake dependencies. The whole build fits in 16 GB of memory.

`scripts/check.sh` is the gate. It is **green** when it prints `check.sh: OK`. CI runs the same script.

## Reports

`THEOREMS.md` lists every target with its status, file, line and axioms. `PAPER-COVERAGE.md` maps each paper
lemma and design-level claim to its theorem. `Audit.lean` prints the axioms of every target; `check.sh` fails
if an expected message changes.

## Seal record

On 2026-10-31 two links in `CONTRACT.md` to the private paper repository were replaced by plain text naming
the same file, commit and lines. Nothing else changed, and `frozen/spec.sha256` was updated for it. The
original seal of `CONTRACT.md` was `b5b95fc29b2262d559ce39cef8a7308bb944c0504b2ba281d7546c1157c79c46`.
