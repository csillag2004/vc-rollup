# Validation record

Full local evidence and the terminal recording were generated from [source 622a9fe](https://github.com/csillag2004/vc-rollup/commit/622a9fe3012a5ce73d27cd97176846558fad929b) with a clean worktree. No OP Sepolia deployment or live measurements were performed.

| Check | Result |
|---|---|
| Solidity format, build and tests | PASS, 88 tests |
| TypeScript typecheck and unit tests | PASS, 16 tests |
| Rust front end | PASS, 62 tests |
| WebAssembly interface | PASS, parser/error cases and 2,000 repeated calls |
| Lean sealed specification, build and axiom audit | PASS, all 33 frozen targets; recursive forbidden-mechanism scan |
| Full local reproduction | PASS, 61.187 seconds, outputs under `local/` |
| BDD | PASS, 15 scenarios and 118 steps |
| Classification | PASS, 3,000 formulas in each of two models, zero bounded violations |
| Robustness | PASS, 17 named contract cases and actor integration |
| Demo recording | PASS, parsed asciinema v2 with monotonic timestamps; see `demo/` |
| Container | Build PASS at the recorded source; smoke reproduction PASS on its immediate predecessor before path normalization (45.44 seconds) |
| Source archive | PASS, fresh dependency recovery and Solidity/Rust build; both Lean seals preserved |
| Citation metadata | PASS, CFF 1.2 schema validation |
| npm dependency audit | PASS, zero reported vulnerabilities at validation time |
| Current-tree publication hygiene | PASS; two historical private-source-link warnings remain |
| Normal secrets scan | PASS with the three exact historical fingerprints baselined |
| Strict publication gates | BLOCKED: historical keys and private-source links |

The container smoke used [the implementation checkpoint](https://github.com/csillag2004/vc-rollup/commit/66f716aeb6d8491811e164e138c58a11918b478b). The following commit only normalizes checkout paths in recorded logs; the container image was rebuilt successfully after that change. Full native reproduction and the demo use the later revision shown above. No published image, results tag or DOI is claimed.

The formula sampler has a fixed seed. Crypto randomness is intentionally fresh, and wall-clock measurements were taken on a shared development host. Each proof case includes one warm-up and three paired generation/verification samples. Gas and calldata come from actual transaction receipts/input. These measurements are not L1 data fees or concurrency/load guarantees.

## Completion and release boundary

- DONE: inspect Markdown and all eight merged PRs; use the user-selected reduced design.
- DONE: validate guarded submissions, bind CAS dependencies, reject invalid history versions, and retain regression coverage.
- DONE: align the documentation and ideal-model limitations; preserve frozen seals and Rust front-end attribution.
- DONE: provide pinned native/container/archive setup, CI, machine-readable experiments and a recorded demo.
- DONE: run full local measurements and retain exact output hashes/provenance.
- DEFERRED by the selected scope: OP Sepolia redeployment and new live measurements.
- BLOCKED for publication: key remediation and coordinated history/private-reference cleanup. See [release status](../design/SECURITY-RELEASE.md). This does not prevent review of the PR.
- NOT PERFORMED: PR merge, release publication and Zenodo deposit.
