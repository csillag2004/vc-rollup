# Current paper claims and implementation evidence

This map covers the ledger-enforced public-guard revision described in [ENFORCED-GUARDS.md](ENFORCED-GUARDS.md). Historical Lean coverage is not a substitute for implementation evidence. Test names refer to `test/StateRegistry.t.sol` unless another file is named. The measured revision and output hashes are in `results/local/provenance.json`.

| Paper claim | Current mechanism and evidence | Boundary |
|---|---|---|
| Single writer | Issuer/DID-owner checks; `test_issueOnlyIssuer`, `testFuzz_nonIssuerCannotRevoke` | Issuer censorship, key compromise and ordering are not prevented. |
| Lifecycle discipline | Public ID storage; `test_issueTwiceReverts`, `test_revokeNotIssuedReverts`, `test_issuerWithAlphaCannotRevokeUnissued`, `test_revokeTwiceReverts` | Uniqueness is per registry. A valid BBS signature alone does not establish ledger issuance. |
| Monotone issued/revoked sets | Append-only issuance/revocation storage and unique transitions; tests above plus step/consistency failures | Lean's set theorem is separate from implementation tests; no refinement proof. |
| Public state and history | `Issued`, `Revoked`, `valuesHashAt`, `readHistory`; BDD and reservation run | Availability/finality depend on the chain and read path. IDs and timing are public. The current client resolves the latest DID BBS key; historical verification across key rotation is not implemented. |
| Log-bound accumulator updates | `test_issueWrongStepReverts`, `test_revokeWrongStepReverts`, `test_revokeInconsistentRtildeReverts`, `test_revokeStaleValuesReverts` | Cryptographic/precompile assumptions remain; set membership is enforced structurally. |
| Exclusive status | Storage cannot mark an ID both active and revoked under lifecycle definitions | The existing private sigma witness does not prove this against an issuer with alpha. `sigma.test.ts` has an accepting false-revoked counterexample. |
| Freshness | Public programs evaluated in transaction pre-state; `test_groupGuardIgnoresOutsideRevocation`; off-chain freshness tests | Presented freshness does not authorize updates. Stable proofs are tested on a separate fixture across later issuance/revocation. |
| Atomic guarded updates | `test_publicGuardEvaluatedOnChain`, `test_flatReservationRaceDecidedOnChain`, `test_issuerCannotReserveTwice`; raw-call integration | Holds for the supported public program. Private clauses fail closed. The state change itself must still satisfy lifecycle checks. |
| Presentation privacy | Off-chain BBS/sigma composition tests and hidden-member example | No end-to-end anonymity/unlinkability theorem; IDs, issuer knowledge, receipts and timing leak information. |
| Independent partitions | Registry-keyed storage and policy domain targets; `test_publicGuardedIssueAcrossRegistries` | Action policies bind at CredDef scope. Different registries can intentionally depend on one another through a guard. |
| Policy-enforced lifecycle | `test_unguardedUpdateRejectedWhenBound`, `test_wrongPolicyReverts`, `test_updatePolicyCannotBeRemovedOrReplaced` | The initial policy is selected by the issuer. Inspect the actual bound program, not its descriptive query string. Empty public program means true. |
| Guard evidence availability | `test_guardProofEmitted`, `test_guardDigestBindsProof`, client `verifyGuardProof` and event round-trip | Proof bytes are available but can be invalid. Public truth is checked without trusting them. |
| Private credential-chain update | `test_presentedPolicyCannotBindUpdates`, `test_presentedGuardCannotAuthorizeUnboundIssue`, `test_presentedGuardCannotAuthorizeUnboundRevoke` | NOT IMPLEMENTED: no sound on-chain private verifier against the trapdoor holder. Rejected rather than accepted retrospectively. |
| Query language/classification | TypeScript compiler tests, BDD class correspondence, Solidity malformed-program and class tests, bounded semantic sampling | No general compiler proof. qlc is a separate prototype; private/off-chain syntax exceeds the supported update subset. |

## What the evaluation establishes

The companion evaluation reports local functional outcomes, bounded classification checks, proof timing/size, and EVM gas/calldata. Adversarial tests call the contracts directly and include issuer-known-trapdoor inputs. They do not establish liveness, fair ordering, production throughput, private-proof security or current OP Sepolia performance. The frozen Lean model and seals are unchanged.
