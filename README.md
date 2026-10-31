# vc-rollup

Companion artifact for *Joint anonymized issuance and revocation for complex verifiable credential chains* by Kocsis Csillag Kamilla (2026).

This prototype combines BBS credentials, a query language, three BLS12-381 accumulators and atomic compare-and-swap (CAS) updates on an EVM with EIP-2537. The selected artifact uses hidden issuance, trusted issuer/updater checks and proof hashes. Its executable scope and trust assumptions are in [ARTIFACT-CONTRACT.md](design/ARTIFACT-CONTRACT.md).

## Setup

Clone recursively to obtain the Foundry dependencies. Use Node.js 26.7.0, Foundry 1.8.6 and just 1.58.0 as pinned in `mise.toml`, Rust 1.94.1 as pinned in `rust-toolchain.toml`, npm and Python 3. Foundry must support the Prague hardfork. The `just lean` recipe installs the checksum-pinned Lean 4.23.0 toolchain locally; it needs curl, tar and zstd on Linux x86-64. On other platforms use elan with the pinned `verification/lean/lean-toolchain`. Run `just install` to install the locked dependencies. The lockfile pins ethers 6.17.0 and Cucumber 13.3.0 alongside the cryptographic dependencies.

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

## Evidence and scope

| Evidence | Implementation |
|---|---|
| Naive versus CAS reservation race; stable loser proof | `offchain/eval/flat-reservation.ts` |
| Finite-state classification checks | `offchain/eval/classify-exhaustive.ts` |
| Proof time and size | `offchain/eval/bench.ts` |
| Contract gas and operation costs | `offchain/eval/gas.ts` |
| Contract and off-chain robustness | `test/`, `offchain/test/`, `offchain/features/` |
| Ideal set-model proofs | `verification/lean/` |

The race demonstrates prevention of a second reservation when the issuer verifies a true guard and declares the correct CAS policy. The contract does not evaluate the query or verify the guard proof. Pairing checks do not enforce all set relations against an issuer who knows the accumulator secret. Read the [trust boundary](design/ARTIFACT-CONTRACT.md) before interpreting the results.

[Historical evaluation](design/EVALUATION.md) and [OP Sepolia evidence](design/OP-SEPOLIA-RUN.md) are retained with their original provenance. Local reproduction does not redeploy contracts or establish current testnet performance. [Thesis changes](design/THESIS-CHANGES.md) identify claims that need alignment with this reduced design.

## Citation and license

Citation metadata is in [CITATION.cff](CITATION.cff). No DOI or release identifier is assigned here. Original repository code is offered under the [MIT license](LICENSE); vendored dependencies retain their own licenses, including those under `lib/`.
