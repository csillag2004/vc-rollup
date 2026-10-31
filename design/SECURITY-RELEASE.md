# Release status

The current artifact is prepared for review. A public release or Zenodo deposit remains blocked by historical credential exposure.

## Historical keys

The full-history gitleaks scan found three private-key entries in `wallets.txt` that are not the standard Anvil test accounts. This revision removes the file. Deletion does not remove the keys from earlier commits or invalidate them.

`scripts/gitleaks-history-baseline.txt` records only the three historical finding fingerprints. Normal CI uses that narrow baseline so a new exposure still fails. The standard public Anvil account-zero key has a separate exact allowlist entry. Neither mechanism means that the exposed keys are safe.

Before publication, the owner must determine where the three keys were used, retire or rotate them, and decide how to handle affected assets or accounts. A coordinated history rewrite, including affected branches and tags, requires a separate decision. This PR does not rewrite shared history or transact on a live network.

Run both publication gates after remediation:

```sh
just secrets --strict
just hygiene --strict
```

The strict secrets gate deliberately ignores the historical baseline and currently fails. The strict hygiene gate also reports historical private-paper links. One citation inside the sealed Lean contract remains a documented source-record exception; changing it would invalidate the original seal. Any publication treatment of that record must preserve a verifiable original and identify the redaction explicitly.

## Testnet preparation

The checked-in OP Sepolia report is historical evidence for the reduced interface. No new deployment has been made. Before any separately approved live run:

1. Complete key remediation and use a newly provisioned funded signer. Do not reuse the deleted wallet file.
2. Check the intended network and EIP-2537 support; `script/Deploy.s.sol` probes the pairing precompile before deployment.
3. Review a non-broadcast simulation of the deployment script and its expected addresses/cost.
4. After approval, deploy and record the source revision, chain ID, addresses, transaction hashes, compiler settings and run outputs. Never include signer secrets in the repository or report.

The artifact's normal reproduction commands use a fresh local Anvil instance and require no live-network credentials.
