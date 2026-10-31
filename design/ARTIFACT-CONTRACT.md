# Submission artifact contract

Decision dated 2026-10-31: the user selected the reduced design in [PR 8](https://github.com/csillag2004/vc-rollup/pull/8) for this artifact. This document supersedes the guard-restoration proposal for submission scope. Frozen `GUARDS.md`, its hash and the Lean contract/seals remain historical records; they are not silently revised to describe this implementation.

## Implemented method

`StateRegistry` stores A, R̃, I and W_IR, authenticated historical values, revocation logs, groups and versions. Issuance hides y: a Schnorr proof links T = I^y to the issuance step, with pairing checks for the new values. Revocation reveals y, rejects repeated revocation using storage, and checks step, consistency and quotient relations with pairings. Group creation checks a polynomial accumulator subset relation against I.

`PolicyRegistry` stores the author's query, declared formula class, declared CAS mode and bindings. It checks that the chosen mode is strong enough for the declared class and binding kinds. It does not parse the query or recompute its class. The issuer binds policies to CredDef actions. A bound update must use the expected policy; its group or registry versions must match when the policy requires CAS. Stable/state-independent policies can use no comparison.

The off-chain compiler, prover and verifier implement the query semantics and proofs. The updater must verify a guard before submitting the update. The transaction carries `proofHash`, and the event commits to `keccak256(abi.encode(policyId, proofHash))`. Full guard proof bytes are not stored on the ledger. Later verification requires a separately retained proof and authenticated historical values.

## Trust boundary

The issuer/updater is trusted to issue fresh identifiers, maintain valid lifecycle sets, anchor groups containing issued IDs, verify guard proofs and select an honest query classification and bindings. The issuer holds α. It can compute quotient witnesses for relations that do not hold as sets, so pairing acceptance alone does not enforce these relations against that issuer. Hidden issuance prevents on-chain checks for duplicate issuance and for whether a later revoked identifier was issued. Storage still rejects a second revocation of the same visible identifier.

CAS prevents a verified guard from becoming stale before execution under the declared policy. It does not establish that the guard was true, that its classification is correct, or that the supplied hash names a valid proof. A dishonest updater can supply a hash without a valid guard; an incorrectly declared stable class can remove a needed comparison. These are outside this artifact's security claim.

Issuance hides y, but revocation and group membership publish identifiers. Timing, registry identity, versions and historical issuance receipts can leak correlations. No end-to-end anonymity or unlinkability theorem is claimed. BBS signatures use a library; composed presentations use the prototype's sigma protocol and are not interchangeable with an IETF BBS presentation verifier.

## Evidence contract

The local race compares two separately verified updates at the same state. The naive profile accepts both; the CAS profile accepts the first and rejects the second with `StaleGroupVersion`. A stable loser proof remains usable after later updates. This is a conditional concurrency guarantee under the trust boundary above.

Classification checks exhaustively enumerate state pairs for a finite universe and sampled formulas. They are bounded evidence. Benchmarks measure the implemented proof constructions and contract calls; a constant number of pairing checks does not imply constant gas, calldata or witness-refresh cost.

Lean proves properties of an ideal set model with exact relation checks and a guard-truth premise. Its results do not establish that the reduced contracts enforce those premises against the issuer. It does not prove cryptographic security, privacy, availability or compiler correctness. Historical coverage notes about public issued-ID storage and on-chain guard evaluation describe the stronger revision, not this artifact. Keep the sealed model unchanged and state this gap alongside any cited theorem.

Fresh output belongs in `out/` with the source revision, environment, parameters and observed results. Existing evaluation and OP Sepolia reports retain their historical status. The artifact makes no claim of a new testnet deployment, and smoke runs do not replace full measurements.
