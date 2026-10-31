# Local artifact results

Mode: reproduce (full). Generated 2026-10-31T19:12:30.916Z.

Scope: public issuance, structural lifecycle checks and atomic on-chain public guard evaluation.
Private presented update guards fail closed; private presentation security against a trapdoor holder is not claimed.

## Correctness

- naive_double_booking: PASS (two revoked group members).
- atomic_public_guard: PASS (GuardFalse).
- guard_proof_from_ledger: PASS (proof retrieved and verified).
- stable_loser_proof: PASS (proof verifies).
- stable_loser_proof_after_issuance: PASS (reservation proof stays valid and fresh).
- stable_proof_after_issue_and_revoke: PASS (separate fixture: both later transitions in proof registry).
- hidden_member_credential: PASS (signature and revoked status verify).
- bdd: exists x in S. Revoked(x): PASS (11 steps).
- bdd: atleast 2 x in S. Revoked(x): PASS (11 steps).
- bdd: forall x in S. NotRevoked(x): PASS (11 steps).
- bdd: atmost 1 x in S. Revoked(x): PASS (11 steps).
- bdd: forall x in Issued. NotRevoked(x): PASS (11 steps).
- bdd: exists x in Issued. NotRevoked(x): PASS (11 steps).
- bdd: exists x in Presented. Sig(x, "Interest") & Revoked(x): PASS (11 steps).
- bdd: exists x in Presented. Sig(x, "Interest") & Active(x): PASS (11 steps).
- bdd: (exists x in Presented. Sig(x, "Interest") & NotRevoked(x)) & atmost 1 y in Issued. NotRevoked(y): PASS (11 steps).
- bdd: A query that does not split as presented ∧ public stays off-chain: PASS (9 steps).
- bdd: A query that does not split as presented ∧ public stays off-chain: PASS (9 steps).
- bdd: Without a bound policy the flat is booked twice: PASS (14 steps).
- bdd: With a bound policy the contract rejects the second booking: PASS (17 steps).
- bdd: A stale guard proof is valid but not fresh: PASS (12 steps).
- bdd: A bound policy cannot be bypassed: PASS (12 steps).
- bdd: The issuer cannot reserve the flat twice: PASS (17 steps).
- bdd: The loser's proof stays valid after later updates: PASS (13 steps).
- bdd: Alice proves the reservation without revealing who she is: PASS (12 steps).
- bdd: A CredDef needs an existing schema: PASS (4 steps).
- bdd: The chain rejects a wrong revocation step: PASS (9 steps).
- bdd: A group holds issued credentials only: PASS (8 steps).

## Bounded classification

| Model | Verdict | Formulas | Violations | Volatile but semantically (co-)stable |
|---|---|---:|---:|---:|
| system model (domains hold issued IDs) | state-independent | 1709 | 0 | – |
| system model (domains hold issued IDs) | stable | 414 | 0 | – |
| system model (domains hold issued IDs) | co-stable | 483 | 0 | – |
| system model (domains hold issued IDs) | volatile | 394 | 0 | 359 |
| general model (groups of arbitrary IDs) | state-independent | 1163 | 0 | – |
| general model (groups of arbitrary IDs) | stable | 398 | 0 | – |
| general model (groups of arbitrary IDs) | co-stable | 435 | 0 | – |
| general model (groups of arbitrary IDs) | volatile | 1004 | 0 | 536 |

Formulas are sampled with seed 2026; all comparable state pairs over four IDs are enumerated for each formula.
This is bounded evidence, not a proof of general classifier soundness.

## Off-chain proof cost

| Case | Rule | Prove (ms) | Verify (ms) | Mean size (bytes) |
|---|---|---:|---:|---:|
| one active credential | R-CRED-SIG + R-ATOM-NOTREVOKED | 185.4 | 127.1 | 1040 |
| one revoked credential | R-CRED-SIG + R-ATOM-REVOKED (G2) | 237.2 | 202.4 | 1184 |
| OR with a simulated branch | R-OR (CDS) | 241.8 | 666.4 | 1536 |
| at least 1 active | R-ATLEAST (k credentials + distinctness) | 151.6 | 290.3 | 1040 |
| at least 2 active | R-ATLEAST (k credentials + distinctness) | 299.9 | 284.0 | 2224 |
| at least 3 active | R-ATLEAST (k credentials + distinctness) | 483.1 | 790.1 | 3520 |
| at least 4 active | R-ATLEAST (k credentials + distinctness) | 782.6 | 653.2 | 4960 |
| same holder, two credentials | R-CRED-EQ | 227.4 | 200.6 | 1696 |
| hidden member of S, |S| = 4 | R-EXISTS (acc_S) + R-ATOM-NOTREVOKED | 221.1 | 256.4 | 1392 |
| ∀x∈T. NotRevoked, |T| = 3 | public evaluation + aggregate receipt | 0.4 | 84.5 | 48 |
| ∃x∈S. Revoked, |S| = 4 | public evaluation (loser's proof) | 0.3 | 0.0 | 0 |
| hidden member of S, |S| = 16 | R-EXISTS (acc_S) + R-ATOM-NOTREVOKED | 313.2 | 270.4 | 1392 |
| ∀x∈T. NotRevoked, |T| = 15 | public evaluation + aggregate receipt | 0.8 | 321.4 | 48 |
| ∃x∈S. Revoked, |S| = 16 | public evaluation (loser's proof) | 0.4 | 0.0 | 0 |
| hidden member of S, |S| = 64 | R-EXISTS (acc_S) + R-ATOM-NOTREVOKED | 453.5 | 260.0 | 1392 |
| ∀x∈T. NotRevoked, |T| = 63 | public evaluation + aggregate receipt | 0.3 | 507.8 | 48 |
| ∃x∈S. Revoked, |S| = 64 | public evaluation (loser's proof) | 0.2 | 0.0 | 0 |

Each case has one warm-up and three measured samples. CSV retains individual samples; table reports arithmetic means.
Proof sizes count encoded group elements and scalars, excluding JSON framing. Crypto randomness is not seeded; timings and some proof lengths vary.

## EVM cost

| Operation | Detail | Gas (median of runs) | Runs |
|---|---|---:|---:|
| setup | BBS key in DID document, schema, CredDef | 458445 | 1 |
| createRegistry + publishSrs | SRS degree 4 | 1933500 | 1 |
| createRegistry + publishSrs | SRS degree 8 | 2151399 | 1 |
| createRegistry + publishSrs | SRS degree 16 | 2639313 | 1 |
| issueUpdate | public ID + 2 pairing checks | 497582 | 16 |
| createGroup | |S| = 2 (issued-ID storage checks) | 170581 | 1 |
| createGroup | |S| = 4 (issued-ID storage checks) | 221779 | 1 |
| createGroup | |S| = 8 (issued-ID storage checks) | 324199 | 1 |
| createGroup | |S| = 16 (issued-ID storage checks) | 529004 | 1 |
| registerPolicy | public group predicate | 267443 | 1 |
| revoke | control: bare update, identical pre-state | 662963 | 1 |
| guardedRevoke | control: public group guard, identical pre-state | 722655 | 1 |
| guardedRevoke | control: public registry guard, identical pre-state | 702148 | 1 |
| guardedRevoke | permanently bound public group guard | 722672 | 1 |
| guardedIssueUpdate | permanently bound public group guard + public ID | 559330 | 1 |

Gas rows record actual receipts on Prague. Setup rows may contain several transactions; the summary sums each operation.
Calldata bytes are measured from transaction input, including the function selector; they are not L1 data fees.

## Robustness

24 required Solidity enforcement cases passed; actor guard integration passed.
See robustness.csv and guard-integration.tap for individual cases. These are functional rejection tests, not a denial-of-service study.

## Provenance

See reproduce-provenance.json for revision, tool versions, hardware, parameters and hashes of outputs.
The paper evaluation chapter is not yet populated; no paper table numbers or publication DOI are assigned by this run.
