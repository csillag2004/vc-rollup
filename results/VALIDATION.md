# Validation record: ledger-enforced public guards

Full local measurements and the demo were generated from [source a2d0cf2](https://github.com/csillag2004/vc-rollup/commit/a2d0cf26823917e767e55532bd240819608fc29e), with a clean worktree. This is the `public-guards-v1` profile, not the earlier reduced implementation. No live deployment or paper-source edit was performed.

| Check | Result |
|---|---|
| Solidity format/build/tests | PASS, 109 tests across three suites, including two fuzz tests with 256 runs each |
| TypeScript typecheck/unit tests | PASS, 21 tests |
| Rust front end | PASS, 62 tests |
| WASM interface | PASS, parser/error cases and 2,000 repeated calls |
| Lean seals, build and axiom audit | PASS, frozen model unchanged, 33 audited targets |
| Full local reproduction | PASS, 118.267 seconds; [raw outputs and hashes](local/provenance.json) |
| BDD | PASS, 21 scenarios, 235 steps; private policy binding checked for rejection |
| Bounded classification | PASS, 3,000 sampled formulas in each of two models, zero observed violations |
| Required contract robustness | PASS, 24 cases, including raw issuer, policy locking, private rejection and cross-registry public guards |
| Actor integration | PASS, policy checks, raw false-guard rejection, private rejection and event proof/digest round-trip |
| Container | Build and smoke reproduction PASS at the measured source revision |
| Demo | PASS, actual asciinema v2 recording, monotonic timestamps, matching clean source revision |
| Current-tree hygiene | PASS, no errors; two historical private-source warnings remain |
| Baseline secrets scan | PASS; strict publication remains blocked by known historical exposures |

The full native run used a shared development host, including other validation workloads. Timing means/ranges are observations, not isolated latency estimates or evidence of monotonic scaling. The derived evaluation reports non-monotone timing series explicitly. Its renderer was subsequently corrected to derive those statements from the data; `evaluation/derivation.json` records the renderer and output hashes separately from the measurement revision.

The [evaluation](evaluation/evaluation.md) includes public-guard correctness, bounded classification, proof time/size, group creation cost, and controlled update costs. The three control paths restore the same snapshot before revoking the same ID. They compare full call cost including proof bytes/events, not a single opcode or a universal overhead. The action is unbound for those controls so the bare path remains callable; permanently bound paths are measured separately.

All committed raw-output hashes were verified before rendering. The renderer rejects reduced-design provenance. Its figures are standalone SVG/PNG; the new controlled-cost figure was visually inspected. The demo and raw result files retain the original revision and parameters. Earlier results are preserved under [historical/reduced](historical/reduced/VALIDATION.md).

## Completed scope and remaining work

- DONE: public issuance IDs, lifecycle storage checks, issued-only groups, validated public policy programs and atomic public guard evaluation.
- DONE: permanent nonzero update-policy bindings; private update guards rejected both at binding and execution, even on unbound actions.
- DONE: client ABI/compiler alignment, full proof-byte events, guard evidence retrieval, signed-header/message-role checks and collision-resistant public count semantics.
- DONE: adversarial tests, reproducible local evaluation, controlled gas comparisons, figures, demonstration and [current paper evidence map](../design/CLAIM-EVIDENCE.md).
- DEFERRED: private update guards. The existing status sigma proof accepts a trapdoor-forged witness; a regression demonstrates the counterexample. Sound private authorization requires a different ledger-membership construction. Off-chain presentations remain available with this limitation.
- DEFERRED: historical BBS key resolution across rotation, larger contention workloads and holder witness-refresh scaling.
- DEFERRED by authorization: OP Sepolia redeployment; preparation remains in [release status](../design/SECURITY-RELEASE.md).
- BLOCKED for publication: historical key remediation and private-source cleanup. This reviewable artifact is not a release or a Zenodo deposit.
- NOT PERFORMED: merge or paper changes.
