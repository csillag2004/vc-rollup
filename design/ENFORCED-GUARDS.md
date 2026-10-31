# Ledger-enforced guards: implementation contract

Frozen 2026-10-31 following the user's approval to pursue the non-reduced implementation. Supersedes the reduced artifact contract for new runs; the older GUARDS.md and Lean seals remain unchanged.

## Enforced subset

Restore public issuance IDs, unique issuance, issued-before-revoke checks, issued-only fixed groups, public counters, and the validated postfix public guard evaluator from revision 15ba12f. Public clauses use Revoked/NotRevoked over fixed groups or registry Issued domains, with all/exists/at-least/at-most and conjunction/disjunction. The registered program, not descriptive query text, is the executable policy. Clients compile and compare the program with the query before use; contracts validate its structure and compute its class.

A bound Issue/Revoke policy is permanent: it cannot be replaced or removed (idempotent rebinding is allowed). Unbound actions remain deliberately unrestricted; readers must inspect binding before relying on enforcement. Creating a new credential definition does not change the policy of an existing one. A policy may be attached after earlier unrestricted activity, so the guarantee begins at binding, not retroactively.

Every guarded update evaluates public clauses against the current ledger state atomically. Wrong policies, false guards, unissued IDs and duplicate issuance fail even when the caller is the issuer holding alpha. Group/registry identity is part of the policy commitment. Empty public programs mean true.

## Private-proof boundary

Any nonempty presented program is rejected when binding an Issue/Revoke policy and when executing a guarded update, including an unbound one. Registration and off-chain presentation remain available for research and verification. Merely emitting proof bytes or comparing versions is not proof verification.

The existing sigma status witnesses are forgeable by the accumulator trapdoor holder. They cannot supply malicious-issuer-safe private update guards simply by moving their verifier on-chain. Private guard enforcement requires a separately designed, reviewed proof bound to authenticated ledger membership, policy, action and update. It is deferred, not claimed implemented. The paper's private lease guard is therefore not an executable update policy in this revision.

Guard proof bytes and their digest may be retained in events for audit, but are not a source of authority for the supported public-only policy. Public issuance and group/revocation IDs leak identifiers and timing; no full anonymity theorem is claimed.

## Validation and evidence

Adversarial contract tests must cover false public guards, direct raw calls, policy removal/replacement, unsupported presented clauses, forged quotient witnesses for unissued IDs, duplicate issuance, and group eligibility. Test public predicate semantics against reference counts. Run the actual client reservation race, proof retrieval, BDD, classification, proof benchmarks and measured gas/calldata on local Prague Anvil. Preserve earlier reduced-design evidence as historical; publish new provenance and a current claim-to-evidence map. Do not redeploy, rewrite history, or edit paper sources.
