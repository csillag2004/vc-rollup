# Lifecycle model and contract tests

The Solidity tests exercise concrete counterparts of the sealed set-level model in
`verification/lean`. They recover the uncommitted tests written against the public
guard implementation at [506cd56](https://github.com/csillag2004/vc-rollup/commit/506cd569971dc8c363646dd79011ce82340d4c47),
validated against the enforced-public-guard implementation merged in
[PR 9](https://github.com/csillag2004/vc-rollup/pull/9).
The frozen Lean model and its proofs are unchanged.

Run from the repository root:

```sh
bash scripts/install-contract-deps.sh
forge test --match-contract StateRegistryTest
forge test --match-contract StateRegistryInvariantTest -vv
```

The normal `just test` and artifact CI include both files. Foundry runs the eight
invariant assertions together for 64 sequences of 32 calls. The handler exposes
13 actions over ten credential IDs, with real BLS12-381 precompiles and a known
issuer trapdoor. It maintains independent issuance/revocation logs and expected
accumulator values, checks each call's acceptance or rejection, and enables
`fail-on-revert` so a handler assertion cannot be silently discarded.

| Model target or witness | Concrete coverage |
| --- | --- |
| `unguarded_race`, `one_reservation` | Unit tests show two revocations without a policy and one successful reservation with a bound public policy. |
| `both_rejected` | Interleaving tests deliberately differ from the model: fixed groups contain already-issued IDs, and public predicates are evaluated at execution. An outside issuance or revocation leaves the first reservation admissible; the second fails with `GuardFalse`. |
| `stale_values` | Old issuance values fail the step check even without a version check. |
| `issue_check_needed`, `step_check_needed`, `consistency_check_needed` | Constructed updates drop an issued ID, drop a revoked ID, or add an extra revoked ID. The respective pairing check rejects each update. |
| S1, `checks_exact`, `honest_update` | The handler compares expected outcomes with actual results, including calls from a non-issuer, duplicates, stale values and forged accumulator inputs. |
| S2, S3, S4 | Revoked IDs were issued earlier; append-only logs agree with the handler and the encoded sets. |
| S5, S6 | Stored values match the handler's sets; status and issuance/revocation versions agree. |
| S8 | At most one member of the reservation group is revoked under the handler's policy. |
| S10 | A second registry evolves independently. |
| S11, `global_version`, `group_version` | State hashes remain fixed at previous versions; global versions count accepted updates; group versions count revoked members. |

## Boundaries

These are bounded randomized tests and concrete witnesses, not a proof that the
Solidity implementation refines the Lean model. The Lean model assumes ideal
cryptography; these tests use a small fixed ID universe and one known trapdoor.
They do not establish cryptographic soundness, privacy, or arbitrary-query safety.

The invariant handler voluntarily guards revocations of reservation-group members
and leaves other revocations unguarded. This matches the model's per-group
`ReservationPolicy` assumption; it does not prove mandatory policy enforcement
against an issuer who bypasses that handler. The existing direct-call tests and
the recovered bound-policy unit tests cover contract-enforced public guards.

No private clause is used here. Current contracts reject private update guards;
private presentations remain a separate off-chain feature. Public predicates are
evaluated against current state, so these tests do not claim to exercise private
proof verification or private-clause compare-and-swap. The model's ideal witness
checks must not be presented as proofs of those unsupported mechanisms.

## Consolidation validation

On 2026-10-31 the eight recovered unit tests passed against current public-guard
contracts without production changes. All eight invariant assertions passed over
64 sequences, 2,048 handler calls, with zero handler reverts. Original uncommitted
source files were preserved in their separate checkout.
