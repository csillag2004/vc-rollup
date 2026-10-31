# vc-rollup

Companion artifact for *Joint anonymized issuance and revocation for complex verifiable credential chains* by Kocsis Csillag Kamilla (2026).

This prototype combines BBS credentials, a query language, three BLS12-381 accumulators and ledger-enforced public guards on an EVM with EIP-2537. Issuance publishes IDs; storage enforces lifecycle and group membership. The contract evaluates bound public guards at execution, and update policies cannot be removed or replaced. Private update guards are rejected because the existing proof construction is unsound against the accumulator trapdoor holder. See [the executable contract](design/ENFORCED-GUARDS.md).

## Setup

Clone recursively to obtain the Foundry dependencies. Use Node.js 26.7.0, Foundry 1.8.6 and just 1.58.0 as pinned in `mise.toml`, Rust 1.94.1 as pinned in `rust-toolchain.toml`, npm and Python 3.11 or newer with venv/pip support. Foundry must support the Prague hardfork. The `just lean` recipe installs the checksum-pinned Lean 4.23.0 toolchain locally; it needs curl, tar and zstd on Linux x86-64. On other platforms use elan with the pinned `verification/lean/lean-toolchain`. Run `just install` to install the locked dependencies. Set `EVALUATION_PYTHON` before installation if a specific Python interpreter is needed; plotting dependencies are isolated in `.venv-evaluation/`. The lockfile pins ethers 6.17.0 and Cucumber 13.3.0 alongside the cryptographic dependencies.

## Reproduce

Run commands from the repository root:

```sh
just build
just test
just evaluate
just benchmark
just robustness
just reproduce --smoke
just demo
just hygiene
just lean
```

`just reproduce --smoke` checks the reproduction path with a reduced workload; it does not establish full benchmark results. Evaluation and benchmark commands write CSV tables and mode-specific reports/provenance under `out/`. `just reproduce` assembles `report.md` and `provenance.json`; contract costs are in `gas.csv` (gas and calldata bytes), proof timings in `scalability.csv`, classification in `classification.csv`, and outcomes in `correctness.csv` and `robustness.csv`. The demo recording is `out/demo/demo.cast`. Use each run's provenance to identify its revision, environment and parameters. Timings depend on the host; compare outcomes and parameters before comparing numbers.

## Container

Build from the recursive checkout, then run the same recipes in the pinned environment:

```sh
docker build --build-arg ARTIFACT_REVISION=$(git rev-parse HEAD) -t vc-rollup-artifact .
docker run --rm -v "$PWD/out-container:/out" -e OUT=/out vc-rollup-artifact reproduce --smoke
```

Omit `--smoke` for full measurements. No container image or release tag has been published.

## What does not reproduce

The local recipes do not recreate historical OP Sepolia transactions, perform a deployment, or populate the separate thesis sources. Cryptographic keys, IDs and proof blinding use OS randomness. The formula sampler uses seed 2026; CPU timings and some encoded proof lengths vary between runs. Lean verifies an ideal model, not the Solidity implementation or the cryptographic assumptions.

## Results and release

The paper's evaluation chapter is still a skeleton, so this repository does not invent table numbers or a results tag. Current measurements must identify their source revision through provenance. Publication remains blocked by [historical key exposure](design/SECURITY-RELEASE.md); `just secrets --strict` is deliberately stricter than the CI baseline. A PR is not a release or a Zenodo deposit.

## Evaluation

The [written evaluation](results/evaluation/evaluation.md) states four research questions, interprets the correctness, classification, proof-cost and EVM results, and bounds the claims. Its figures and tables are derived from the recorded CSVs, with hashes checked first. `just reproduce` generates both measurements and evaluation; `just figures results/local out/evaluation` rebuilds the interpretation and figures from the committed run. Matplotlib and its dependencies are pinned in `scripts/evaluation-requirements.txt`.

## Recorded results

[Current local report](results/local/report.md), [provenance](results/local/provenance.json), and [demo recording](results/demo/demo.cast) identify the evaluated source revision and machine. Earlier reduced-design measurements are retained under [historical/reduced](results/historical/reduced/VALIDATION.md); their numbers and guarantees do not describe this ABI. Timings were taken on a shared development host without CPU isolation.

| Evidence | Recipe | Output |
|---|---|---|
| Reservation race and BDD correctness | `just evaluate` | `out/correctness.csv`, `out/bdd.json` |
| Bounded classification, 3,000 formulas per model | `just evaluate` | `out/classification.csv` |
| Proof scaling, groups of 4/16/64 and thresholds 1–4 | `just benchmark` | `out/scalability.csv` |
| Gas and calldata for public guarded updates | `just benchmark` | `out/gas.csv` |
| Invalid inputs, stale state and guard regressions | `just robustness` | `out/robustness.csv`, `out/guard-integration.tap` |
| Complete run and parameters | `just reproduce` | `out/report.md`, `out/provenance.json` |
| Recorded terminal demonstration | `just demo` | `out/demo/demo.cast`, captions and transcript |

See [validation and remaining release work](results/VALIDATION.md). Re-running a recipe overwrites its outputs; use `OUT` to keep separate runs.

## Evidence and scope

| Evidence | Implementation |
|---|---|
| Naive versus enforced-public-guard reservation race; stable loser proof | `offchain/eval/flat-reservation.ts` |
| Finite-state classification checks | `offchain/eval/classify-exhaustive.ts` |
| Proof time and size | `offchain/eval/bench.ts` |
| Contract gas and operation costs | `offchain/eval/gas.ts` |
| Contract and off-chain robustness | `test/`, `offchain/test/`, `offchain/features/` |
| Ideal set-model proofs | `verification/lean/` |

The race demonstrates prevention of a second reservation by current-state public guard evaluation, including raw issuer calls with fabricated proof bytes. The guarantee starts when the intended program is bound. The issuer still chooses the initial policy and can censor or order updates. Programs are executable semantics; query text is descriptive and clients check compilation correspondence. Empty public programs mean true. A newly created credential definition has its own policy and is not a substitute for the one a verifier accepted.

The [current claim-to-evidence map](design/CLAIM-EVIDENCE.md) separates contract enforcement, model assumptions and unsupported private guards. Private presentations remain available off-chain under their documented assumptions. Proof bytes emitted for public updates are audit data; they do not authorize the transition.

[Historical evaluation](design/EVALUATION.md) and [OP Sepolia evidence](design/OP-SEPOLIA-RUN.md) retain their provenance. No new deployment or live performance claim is made. [Thesis changes](design/THESIS-CHANGES.md) list required alignment without editing the paper.

## Contributions

The paper is by Kocsis Csillag Kamilla. The companion includes work by Kamilla and Martin Farkas. In particular, the Rust `qlc` front end was built by Martin with Claude, as recorded in [its original PR](https://github.com/csillag2004/vc-rollup/pull/2); it is not student-authored proof-generation code. The [Lean model PR](https://github.com/csillag2004/vc-rollup/pull/1) records the separate formalization effort. This artifact hardening was performed with GPT-6 Astra through the Codex harness in T3 Code. Repository authorship does not change the paper's authorship.

## Citation and license

Citation metadata is in [CITATION.cff](CITATION.cff). No DOI or release identifier is assigned here. Original repository code is offered under the [MIT license](LICENSE); vendored dependencies retain their own licenses, including those under `lib/`.
