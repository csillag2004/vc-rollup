# Evaluation of the reduced credential-registry prototype

Full workload. This evaluation answers four questions about the implemented trusted-issuer/updater design. It combines functional scenarios, bounded semantic checks and measured proof/EVM costs under the documented trust assumptions.

## Method and provenance

Measurements come from [source revision 622a9fe](https://github.com/csillag2004/vc-rollup/commit/622a9fe3012a5ce73d27cd97176846558fad929b), run on 2026-10-31T17:10:38.555Z. The source worktree was clean. The machine was AMD Ryzen 9 7950X3D 16-Core Processor, 32 logical CPUs, 93.9 GiB RAM, Linux. Proof computations use one Node.js process; this was a shared host with no CPU isolation. Node v26.7.0, Foundry 1.8.6, solc 0.8.30 and the Prague hardfork were used. [Provenance and raw-output hashes](../local/reproduce-provenance.json) specify the exact environment.

Each proof case has one warm-up and three paired generation/verification samples. Tables report mean and observed minimum–maximum, not confidence intervals. Cryptographic keys, IDs and blinding are fresh OS randomness. Formula sampling uses seed 2026, depth at most four, and a universe of four IDs. Every comparable state pair is enumerated for each sampled formula; the formula space itself is not exhaustively enumerated.

## RQ1: Does atomic CAS prevent the demonstrated stale-guard race?

**Within the selected trust model, yes for the tested interleaving.** Alice and Bob obtain valid guards at the same state. The naive updater checks both and later revokes both credentials, yielding two reservations. With the policy bound to the action, Alice's update succeeds and Bob's update reverts with `StaleGroupVersion`. Bob's old presentation remains cryptographically valid but is no longer fresh. The stable "flat is taken" proof remains valid after a later issuance and revocation. A separate holder proof verifies signature, group membership and revoked status without naming the group member in the proof interface.

The result is a controlled sequential interleaving of a check/use race, not a throughput or many-client concurrency experiment. It does not establish end-to-end anonymity. The issuer is trusted to verify the proof and select a correct classification and bindings; CAS closes the freshness gap after that verification. A dishonest issuer can submit a hash without a valid guard in this reduced design.

The [correctness cases](../local/correctness.csv), [BDD outcomes](../local/bdd.json) and [reservation trace](../local/reservation.json) record the observations. Robustness evidence covers malformed accumulator updates, stale values, repeated revocation, invalid groups, policy mismatch, bypass attempts, guard-proof validation, CAS coverage and invalid history versions through the contract, actor and unit suites. [Robustness results](../local/robustness.csv) and [actor integration output](../local/guard-integration.tap) retain the run evidence. This is functional rejection coverage, not a denial-of-service assessment.

## RQ2: Is the classifier sound on the bounded sample, and how conservative is it?

**No classification violations were observed in 6,000 sampled formulas across the two models.** A stable verdict must never turn false along the enumerated state order; a co-stable verdict must never turn true; a state-independent verdict must not change.

- system model (domains hold issued IDs): 503/538 volatile verdicts (93.5%) are semantically stable or co-stable over the enumerated states.
- general model (groups of arbitrary IDs): 662/1130 volatile verdicts (58.6%) are semantically stable or co-stable over the enumerated states.

![Conservative volatile classifications](classification.svg)

These conservative verdicts can request stronger freshness checking than the bounded semantics require. They are not false soundness claims: the syntactic rule deliberately over-approximates volatility. The percentages describe this generator and finite state space, not a representative production workload or a measured transaction-rejection rate. [Raw classification counts](../local/classification.csv).

The separate Lean model provides ideal set-level proofs. Its exact-check and guard-truth premises are not enforced against a malicious issuer by the reduced Solidity implementation; no end-to-end compiler or cryptographic proof is inferred from those theorems.

## RQ3: How do proof costs change with the threshold and anchored group size?

**Both tested dimensions increase computation, while they affect proof size differently.** Requiring more active credentials adds credential and distinctness evidence. Hidden membership in a larger anchored group keeps the measured encoded proof size fixed while increasing the measured work.

![Proof generation and verification cost](proof-cost.svg)

Threshold cases:

| Active credentials k | Generate ms, mean (range) | Verify ms, mean (range) | Proof-element bytes |
|---:|---:|---:|---:|
| 1 | 74.1 (72.8–75.0) | 69.3 (68.1–70.4) | 1040 |
| 2 | 151.6 (151.0–152.7) | 142.5 (142.3–142.6) | 2224 |
| 3 | 242.2 (237.6–249.1) | 230.4 (228.6–233.5) | 3520 |
| 4 | 328.2 (327.4–329.1) | 314.6 (313.3–316.1) | 4960 |

Hidden group-member cases:

| Group size | Generate ms, mean (range) | Verify ms, mean (range) | Proof-element bytes |
|---:|---:|---:|---:|
| 4 | 110.8 (110.6–111.0) | 103.2 (102.9–103.6) | 1392 |
| 16 | 164.6 (163.2–166.5) | 129.0 (128.8–129.4) | 1392 |
| 64 | 376.6 (372.6–384.3) | 235.2 (234.2–236.6) | 1392 |

"Proof-element bytes" counts compressed group elements and encoded scalars, excluding JSON framing, identifiers, transport headers and fetched registry history. A public query can therefore have zero proof-element bytes while still requiring data and computation. The full table also measures active/revoked credentials, an OR with a simulated branch, same-holder evidence and aggregate receipts. [All paired timing samples](../local/scalability.csv).

Three samples on one shared host support a description of these runs, not a precise latency SLA or an asymptotic complexity claim. Setup, key generation, credential issuance and network history retrieval are outside the timed proof loops. The aggregate-receipt case receives an already computed witness; its generation time is not the cost of constructing that witness. The hidden-member fixtures keep one presented credential and two revocations, but registry history grows with the group, so this is an implementation scaling experiment rather than an isolated group-operation microbenchmark. Larger groups and thresholds beyond the tested range remain unmeasured.

## RQ4: What are the EVM execution and calldata costs?

**Group creation gets more expensive over the tested sizes.** It computes and checks a set-polynomial relation; a fixed number of pairing checks does not make total execution cost constant.

![Group-creation gas](group-gas.svg)

| Group size | Gas | Calldata bytes |
|---:|---:|---:|
| 2 | 427,247 | 5,892 |
| 4 | 514,283 | 5,956 |
| 8 | 688,574 | 6,084 |
| 16 | 1,052,640 | 6,340 |

Group creation uses SRS degree 16 for every size shown. Each row above is one transaction, not a repeated-run estimate. The measurements also include registry/SRS setup, 16 issuances and the update variants below.

| Operation | Variant | Gas | Calldata bytes |
|---|---|---:|---:|
| revoke | step + consistency + subset (3 pairing checks) | 661,065 | 772 |
| guardedRevoke | global CAS (policy lookup + registry versions) | 672,788 | 996 |
| guardedRevoke | group CAS (policy lookup + group version) | 684,393 | 964 |
| guardedRevoke | stable guard, no comparison | 660,406 | 964 |
| guardedIssueUpdate | group CAS + Schnorr + 2 pairing checks | 472,051 | 1,060 |

The update rows establish that each path executes and records its cost. They do **not** isolate CAS overhead: the operations occur at different storage states, and gas depends on zero/nonzero transitions and calldata contents. In particular, a lower measured cost for a stable guarded update than an unguarded update is not evidence that guarding saves gas. A controlled overhead experiment would reset to identical pre-state and vary only the policy/check path.

Calldata bytes include the selector and arguments. These are local Prague gas measurements, not OP Sepolia L1 data fees, currency costs, finality latency or throughput. [Per-transaction gas and calldata](../local/gas.csv).

## Reproduction and scope

`just reproduce` runs the measurements on a fresh local chain and derives this evaluation under `out/evaluation/`. `just figures results/local out/evaluation` derives the text and figures from the committed full run without rerunning the measurements. The renderer verifies every recorded output hash before interpreting the CSVs. Smoke output is marked as reduced and must not replace the full-workload evaluation.

The evidence supports the implemented conditional race-prevention mechanism, bounded classification checks and the measured proof/EVM costs. It does not support malicious-issuer safety, general classifier soundness from sampling alone, production throughput, full anonymity, or current public-testnet performance. The broader paper evaluation chapter and new live deployment are outside this companion-repository task.
