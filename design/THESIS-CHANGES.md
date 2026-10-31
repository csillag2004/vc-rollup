# Thesis alignment for ledger-enforced public guards

The current executable scope is [ENFORCED-GUARDS.md](ENFORCED-GUARDS.md). This checklist does not edit the student's paper. The earlier decision to use the reduced design has been superseded.

- Describe public issuance IDs, unique issuance and issued-before-revocation checks. Structural storage checks, rather than issuer-known-trapdoor quotient witnesses, enforce lifecycle and group membership.
- State the supported update language: public quantifiers/counting over fixed issued-only groups and registry Issued domains, combined by conjunction/disjunction. The registered validated program is authoritative. Descriptive query text is checked against it by clients, not parsed by Solidity.
- Explain that public guards are evaluated against the current state atomically. The second reservation fails with GuardFalse, not a stale version error. Off-chain freshness checks remain meaningful for presentations.
- State that a nonzero Issue/Revoke policy binding cannot be replaced or removed. This guarantee starts at binding. Initial policy selection, unrestricted prior actions, issuer censorship and transaction ordering remain outside the guarantee.
- Private Presented clauses cannot authorize an update, even with a stable class or a proof included in calldata. The paper's private lease-issuance guard is not implemented. The current sigma status relations are forgeable by the accumulator trapdoor holder; their regression counterexample explains the fail-closed boundary.
- GuardProof events retain proof bytes and update events commit to their digest. Public guard truth is established independently of those bytes. Emission is not proof verification and does not guarantee valid audit content from a malicious issuer.
- Qualify privacy: issuance, groups and revocation expose IDs and timing. Off-chain presentations aim to hide the selected credential under stated cryptographic/trust assumptions; no composition/privacy theorem is supplied by Lean.
- Use the current claim-to-evidence matrix for guarantees. Frozen Lean results prove an ideal set model; no Solidity refinement or compiler correctness theorem is claimed.
- Populate evaluation from the new provenance and local outputs. Preserve the old reduced-design results as historical and distinguish historical OP Sepolia evidence from the new ABI. Do not transplant old gas numbers or claim full private-guard support.
- Explain BBS signature-library reuse versus prototype sigma presentations, and separate Kamilla's implementation contributions from Martin's qlc/Lean work and AI assistance.
- Witness-refresh scaling, larger contention workloads and a sound private ledger-membership proof remain future work. Live redeployment requires separate approval.
