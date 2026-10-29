# vc-rollup: TDK reference implementation

A credential query language over AnonCreds-v2-style credentials (BBS signatures), a three-accumulator
registry (A, R̃, I) on an EVM chain with EIP-2537 (OP Stack), and atomic guarded updates by
compare-and-swap. Design and decisions: [`design/PLAN.md`](design/PLAN.md); results:
[`design/EVALUATION.md`](design/EVALUATION.md); what the thesis text needs: [`design/THESIS-CHANGES.md`](design/THESIS-CHANGES.md).

## Layout

| Path | What |
|---|---|
| `src/StateRegistry.sol` | A, R̃, I, W_IR, SRS, versions, groups; every update checked with pairings (verify on write) |
| `src/PolicyRegistry.sol` | policies (query + bindings), CredDef rules for issue / revoke / present |
| `src/lib/BLS.sol` | EIP-2537 wrappers |
| `offchain/src/crypto` | BLS12-381 helpers, accumulators, BBS (IETF draft), sigma framework (AND, CDS threshold), leaves |
| `offchain/src/ql` | parser, NNF, classification, compiler / prover / verifier, freshness, exhaustive check |
| `offchain/src/chain`, `offchain/src/actors` | ethers client (history from events) and issuer / holder / verifier |
| `offchain/eval` | flat reservation, classification, benchmarks, gas, report |
| `offchain/features` | BDD scenarios (cucumber-js): flat reservation, verify on write, classification |

## Running

```shell
cd offchain && npm install && cd ..
forge build                       # without a downloadable native solc: forge build --use ./tools/solc
forge test                        # 104 tests, real pairings via the Prague precompiles
cd offchain && npm test           # 16 off-chain tests
anvil --hardfork prague &         # local chain with EIP-2537
npm run demo                      # flat reservation end to end
npm run bdd                       # 21 Gherkin scenarios (offchain/features) on the local chain
npm run eval:classify             # exhaustive classification check, also against PolicyRegistry.classify on the local chain
npm run bdd:op-sepolia            # the same scenarios on OP Sepolia (deployed contracts, PRIVATE_KEY in .env)
npm run eval:report               # regenerates design/EVALUATION.md
```

Deployed on OP Sepolia: addresses in [`design/DEPLOYMENTS.md`](design/DEPLOYMENTS.md). That deployment predates
[`design/GUARDS.md`](design/GUARDS.md), and the off-chain code follows the new ABI, so `bdd:op-sepolia` and
`demo:op-sepolia` need a fresh deployment first. To deploy again (the script first probes the BLS12-381 pairing precompile):

```shell
forge script script/Deploy.s.sol --rpc-url op_sepolia --private-key $PRIVATE_KEY --broadcast
```
