# Release status

The current artifact is prepared for review. A public release or Zenodo deposit waits until the three leaked keys below are rotated.

## Historical keys

The full-history gitleaks scan finds three private-key entries in `wallets.txt` (commits `7e41dd0` and `e37175d`). They are not Anvil test accounts. The file is gone from the tree, but the history is not rewritten, so the keys stay readable once the repository is public. The fix is to rotate them: new wallets, and nothing left on the old ones.

Until then the hygiene workflow's gitleaks step fails. After rotation, their fingerprints go into `.gitleaksignore` under a comment that says when they were rotated. The three entries already there are the public Anvil account-zero key used by the local test fixtures.

Run the scan locally with `just secrets`, and the publication gate with `just hygiene --publish`. Its history warnings include the private-paper links in earlier revisions of `verification/lean/CONTRACT.md` and `PAPER-COVERAGE.md`. The current `CONTRACT.md` names the paper source as plain text and is resealed; `verification/lean/README.md` records the original seal and the exact change.

## Testnet preparation

The checked-in OP Sepolia report is historical evidence for the reduced interface. No new deployment has been made. Before any separately approved live run:

1. Complete key remediation and use a newly provisioned funded signer. Do not reuse the deleted wallet file.
2. Check the intended network and EIP-2537 support; `script/Deploy.s.sol` probes the pairing precompile before deployment.
3. Review a non-broadcast simulation of the deployment script and its expected addresses/cost.
4. After approval, deploy and record the source revision, chain ID, addresses, transaction hashes, compiler settings and run outputs. Never include signer secrets in the repository or report.

The artifact's normal reproduction commands use a fresh local Anvil instance and require no live-network credentials.
