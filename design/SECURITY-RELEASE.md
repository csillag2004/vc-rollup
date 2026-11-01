# Release status

The current artifact is prepared for review. A public release or Zenodo deposit remains blocked by historical credential exposure.

## Historical keys

The full-history gitleaks scan found three private-key entries in `wallets.txt` that are not the standard Anvil test accounts. This revision removes the file. Deletion does not remove the keys from earlier commits or invalidate them.

The hygiene workflow scans the whole history with gitleaks and has no baseline for these keys, so it fails until the history is rewritten. The only allowlist entry, in `scripts/gitleaks.toml`, is the standard public Anvil account-zero key used by the local test fixtures.

Before publication, the owner must determine where the three keys were used, retire or rotate them, and decide how to handle affected assets or accounts. A coordinated history rewrite, including affected branches and tags, requires a separate decision. This repository does not rewrite shared history or transact on a live network.

Run both publication gates after remediation:

```sh
just secrets
just hygiene --strict
```

The strict hygiene gate also reports the private-paper links in earlier revisions of `verification/lean/CONTRACT.md` and `PAPER-COVERAGE.md`. The current `CONTRACT.md` names the paper source as plain text and is resealed; `verification/lean/README.md` records the original seal and the exact change.

## Testnet preparation

The checked-in OP Sepolia report is historical evidence for the reduced interface. No new deployment has been made. Before any separately approved live run:

1. Complete key remediation and use a newly provisioned funded signer. Do not reuse the deleted wallet file.
2. Check the intended network and EIP-2537 support; `script/Deploy.s.sol` probes the pairing precompile before deployment.
3. Review a non-broadcast simulation of the deployment script and its expected addresses/cost.
4. After approval, deploy and record the source revision, chain ID, addresses, transaction hashes, compiler settings and run outputs. Never include signer secrets in the repository or report.

The artifact's normal reproduction commands use a fresh local Anvil instance and require no live-network credentials.
