# Deployments

Historical evidence from 2026-10-29. These records describe the then-deployed CAS/hash-only interface. No redeployment or fresh testnet validation is claimed by this submission artifact. Local reproduction and its provenance are separate; see [ARTIFACT-CONTRACT.md](ARTIFACT-CONTRACT.md).

## OP Sepolia (chain id 11155420), 2026-10-29

Deployed with `script/Deploy.s.sol` from branch `tdk/full-implementation`; deployer
`0xb614843DBfFE34Fc8575B48af991D9eE7B8F3Ba1`. Transactions: `broadcast/Deploy.s.sol/11155420/run-latest.json`.

| Contract | Address | Gas |
|---|---|---:|
| EthereumDIDRegistry | `0xe18dAa42ff516Ad981d10f1b3E256E181E67a2A5` | 1,066,341 |
| SchemaRegistry | `0x0d56767A51cB0c5C4Be03D81c03e5cFD295F6A97` | 819,195 |
| CredDefRegistry | `0x55132dd145d17c29D7bC2FCF9f837a0604526363` | 555,498 |
| PolicyRegistry | `0xBD9c6664f467135bcF1ca49e17fd786Bc8623055` | 1,183,415 |
| StateRegistry | `0x3947002b50fC6da0E785Cf0D67E15355Cf4D47B5` | 4,714,013 |

Blocks 50735934–50735939; the deployment cost 0.0000125 ETH.

EIP-2537 on the live chain was checked with `eth_call` to the pairing precompile (`0x0f`):
`e(g, g̃)·e(−g, g̃) = 1` returns `1`, `e(g, g̃)·e(2g, g̃) = 1` returns `0`. (The script's own probe runs
in forge's local EVM, so it alone does not show that the chain has the precompile.)

Explorer: `https://sepolia-optimism.etherscan.io/address/<address>`. The contracts are not source-verified
(that needs `ETHERSCAN_API_KEY`: `forge verify-contract ... --chain 11155420`).

The flat reservation was run against these contracts: [`OP-SEPOLIA-RUN.md`](OP-SEPOLIA-RUN.md) (outcome, gas and
fees per operation, every transaction). Addresses for the off-chain client: `deployments/11155420.json`.
