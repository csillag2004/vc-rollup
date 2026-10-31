# Thesis alignment for the reduced artifact

The current artifact follows [ARTIFACT-CONTRACT.md](ARTIFACT-CONTRACT.md), selected on 2026-10-31. The paper's title is *Joint anonymized issuance and revocation for complex verifiable credential chains*. This checklist records required alignment; it does not change the student's text.

- Describe BBS signatures, the prototype's composed sigma presentations, BLS12-381 and EIP-2537. State OP Stack/Prague execution assumptions and distinguish signature compatibility from presentation compatibility.
- Use the static-add representation A = V0^(1/P_Rev(α)); issuance updates I and W_IR. Explain hidden-y issuance and its Schnorr step proof. Duplicate issuance and the issued status of a revoked ID rely on the trusted issuer.
- Describe groups as intended subsets of issued IDs. The pairing subset test does not enforce that relation against the issuer holding α. Revocation publishes identifiers and storage rejects repeated visible revocations.
- Describe policies as author-declared classes and CAS modes. Query semantics and guard proofs are checked off chain by the updater; the contract enforces policy binding and version comparisons. Remove claims of on-chain query evaluation, public issuance storage, compiler-checked on-chain classes or `GuardProof` events containing proof bytes.
- State that the ledger stores a proof commitment. Proof recovery requires separate retention. CAS establishes freshness conditional on a correctly verified and classified guard, not guard truth itself.
- Qualify privacy claims: issuance identifiers are hidden, while revocations and groups reveal identifiers; historical receipt versions and timing can leak information. Lean does not prove privacy or cryptographic security.
- Separate the ideal Lean model from implementation enforcement. Exact set-relation checks and guard truth are model premises that the reduced implementation entrusts to the issuer/updater. Cite the frozen model and this gap together.
- Populate the evaluation from recorded runs: naive/CAS race (`StaleGroupVersion`), bounded classification, proof cost, gas/calldata and robustness. Report revision, environment, parameters and repetitions. Keep historical OP Sepolia evidence separate. Do not transplant numbers from the stronger guard implementation.
- Treat witness-refresh scaling and larger concurrency stress as optional experiments unless separately commissioned. Mark unsupported claims and missing measurements explicitly.
