# Local artifact results

Mode: reproduce (full). Generated 2026-10-31T17:10:38.555Z.

Scope: hidden issuance, trusted issuer/updater, off-chain proof verification and on-chain compare-and-swap.
These runs do not establish security against a malicious issuer or on-chain guard truth.

## Correctness

- naive_double_booking: PASS (two revoked group members).
- atomic_group_cas: PASS (StaleGroupVersion).
- stable_loser_proof: PASS (proof verifies).
- stable_loser_proof_after_updates: PASS (proof stays valid and fresh).
- hidden_member_credential: PASS (signature and revoked status verify).
- bdd: exists x in S. Revoked(x): PASS (3 steps).
- bdd: atleast 2 x in S. Revoked(x): PASS (3 steps).
- bdd: forall x in S. NotRevoked(x): PASS (3 steps).
- bdd: atmost 1 x in S. Revoked(x): PASS (3 steps).
- bdd: forall x in Issued. NotRevoked(x): PASS (3 steps).
- bdd: exists x in Issued. NotRevoked(x): PASS (3 steps).
- bdd: Without a bound policy the flat is booked twice: PASS (14 steps).
- bdd: With a bound policy the second booking is rejected: PASS (16 steps).
- bdd: A stale guard proof is valid but not fresh: PASS (12 steps).
- bdd: A bound policy cannot be bypassed: PASS (12 steps).
- bdd: The loser's proof stays valid after later updates: PASS (13 steps).
- bdd: Alice proves the reservation without revealing who she is: PASS (12 steps).
- bdd: A CredDef needs an existing schema: PASS (4 steps).
- bdd: The chain rejects a wrong revocation step: PASS (9 steps).
- bdd: A group witness must match the set: PASS (8 steps).

## Bounded classification

| Model | Verdict | Formulas | Violations | Volatile but semantically (co-)stable |
|---|---|---:|---:|---:|
| system model (domains hold issued IDs) | state-independent | 1294 | 0 | – |
| system model (domains hold issued IDs) | stable | 532 | 0 | – |
| system model (domains hold issued IDs) | co-stable | 636 | 0 | – |
| system model (domains hold issued IDs) | volatile | 538 | 0 | 503 |
| general model (groups of arbitrary IDs) | state-independent | 930 | 0 | – |
| general model (groups of arbitrary IDs) | stable | 447 | 0 | – |
| general model (groups of arbitrary IDs) | co-stable | 493 | 0 | – |
| general model (groups of arbitrary IDs) | volatile | 1130 | 0 | 662 |

Formulas are sampled with seed 2026; all comparable state pairs over four IDs are enumerated for each formula.
This is bounded evidence, not a proof of general classifier soundness.

## Off-chain proof cost

| Case | Rule | Prove (ms) | Verify (ms) | Mean size (bytes) |
|---|---|---:|---:|---:|
| one active credential | R-CRED-SIG + R-ATOM-NOTREVOKED | 73.6 | 68.7 | 1040 |
| one revoked credential | R-CRED-SIG + R-ATOM-REVOKED (G2) | 98.4 | 90.1 | 1184 |
| OR with a simulated branch | R-OR (CDS) | 114.8 | 110.8 | 1536 |
| at least 1 active | R-ATLEAST (k credentials + distinctness) | 74.1 | 69.3 | 1040 |
| at least 2 active | R-ATLEAST (k credentials + distinctness) | 151.6 | 142.5 | 2224 |
| at least 3 active | R-ATLEAST (k credentials + distinctness) | 242.2 | 230.4 | 3520 |
| at least 4 active | R-ATLEAST (k credentials + distinctness) | 328.2 | 314.6 | 4960 |
| same holder, two credentials | R-CRED-EQ | 111.2 | 103.9 | 1696 |
| hidden member of S, |S| = 4 | R-EXISTS (acc_S) + R-ATOM-NOTREVOKED | 110.8 | 103.2 | 1392 |
| ∀x∈T. NotRevoked, |T| = 3 | public evaluation + aggregate receipt | 0.2 | 40.3 | 48 |
| ∃x∈S. Revoked, |S| = 4 | public evaluation (loser's proof) | 0.2 | 0.0 | 0 |
| hidden member of S, |S| = 16 | R-EXISTS (acc_S) + R-ATOM-NOTREVOKED | 164.6 | 129.0 | 1392 |
| ∀x∈T. NotRevoked, |T| = 15 | public evaluation + aggregate receipt | 0.2 | 128.2 | 48 |
| ∃x∈S. Revoked, |S| = 16 | public evaluation (loser's proof) | 0.2 | 0.0 | 0 |
| hidden member of S, |S| = 64 | R-EXISTS (acc_S) + R-ATOM-NOTREVOKED | 376.6 | 235.2 | 1392 |
| ∀x∈T. NotRevoked, |T| = 63 | public evaluation + aggregate receipt | 0.3 | 479.0 | 48 |
| ∃x∈S. Revoked, |S| = 64 | public evaluation (loser's proof) | 0.2 | 0.0 | 0 |

Each case has one warm-up and three measured samples. CSV retains individual samples; table reports arithmetic means.
Proof sizes count encoded group elements and scalars, excluding JSON framing. Crypto randomness is not seeded; timings and some proof lengths vary.

## EVM cost

| Operation | Detail | Gas (median of runs) | Runs |
|---|---|---:|---:|
| setup | BBS key in DID document, schema, CredDef | 458445 | 1 |
| createRegistry + publishSrs | SRS degree 4 | 1933453 | 1 |
| createRegistry + publishSrs | SRS degree 8 | 2151343 | 1 |
| createRegistry + publishSrs | SRS degree 16 | 2639200 | 1 |
| issueUpdate | Schnorr + 2 pairing checks | 438916 | 16 |
| createGroup | |S| = 2 (on-chain [P_S]_2 + subset check) | 427247 | 1 |
| createGroup | |S| = 4 (on-chain [P_S]_2 + subset check) | 514283 | 1 |
| createGroup | |S| = 8 (on-chain [P_S]_2 + subset check) | 688574 | 1 |
| createGroup | |S| = 16 (on-chain [P_S]_2 + subset check) | 1052640 | 1 |
| revoke | step + consistency + subset (3 pairing checks) | 661065 | 1 |
| registerPolicy | co-stable, group CAS | 211483 | 1 |
| guardedRevoke | global CAS (policy lookup + registry versions) | 672788 | 1 |
| guardedRevoke | group CAS (policy lookup + group version) | 684393 | 1 |
| guardedRevoke | stable guard, no comparison | 660406 | 1 |
| guardedIssueUpdate | group CAS + Schnorr + 2 pairing checks | 472051 | 1 |

Gas rows record actual receipts on Prague. Setup rows may contain several transactions; the summary sums each operation.
Calldata bytes are measured from transaction input, including the function selector; they are not L1 data fees.

## Robustness

17 required Solidity rejection/freshness cases passed; actor guard integration passed.
See robustness.csv and guard-integration.tap for individual cases. These are functional rejection tests, not a denial-of-service study.

## Provenance

See reproduce-provenance.json for revision, tool versions, hardware, parameters and hashes of outputs.
The paper evaluation chapter is not yet populated; no paper table numbers or publication DOI are assigned by this run.
