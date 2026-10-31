set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

install:
    bash scripts/install-contract-deps.sh
    npm --prefix offchain ci

build:
    forge build --use ./tools/solc
    cargo build --locked --manifest-path qlc/Cargo.toml

test: build
    forge fmt --check
    forge test --use ./tools/solc -vv
    npm --prefix offchain test
    npm --prefix offchain run typecheck
    cargo test --locked --manifest-path qlc/Cargo.toml
    cargo build --locked --release --target wasm32-unknown-unknown --manifest-path qlc/Cargo.toml
    node qlc/tests/wasm_smoke.mjs

evaluate *args: build
    node scripts/run.mjs evaluate {{args}}

benchmark *args: build
    node scripts/run.mjs benchmark {{args}}

robustness *args: build
    node scripts/run.mjs robustness {{args}}

reproduce *args: build
    node scripts/run.mjs reproduce {{args}}

demo *args: build
    node scripts/run.mjs demo {{args}}

lean:
    bash scripts/lean.sh

hygiene *args:
    python3 scripts/hygiene.py {{args}}

# Known historical exposures remain a release blocker; --strict reports them.
secrets *args:
    bash scripts/secrets.sh {{args}}
