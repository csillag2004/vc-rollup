# vc-rollup: TDK reference implementation

Credential query language over AnonCreds-v2-style credentials (BBS signatures) with a three-accumulator
registry (A, R̃, I) on an EVM chain with EIP-2537 (OP Stack), and atomic guarded updates by
compare-and-swap. See [`design/PLAN.md`](design/PLAN.md).

```shell
forge test                      # contracts (evm prague)
cd offchain && npm test         # off-chain library
```
