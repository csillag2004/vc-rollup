set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

install:
    bash scripts/install-contract-deps.sh
    npm --prefix offchain ci
    bash scripts/evaluation.sh --setup

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
    bash scripts/evaluation.sh "${OUT:-out}" "${OUT:-out}/evaluation"

demo *args: build
    node scripts/run.mjs demo {{args}}

lean:
    bash scripts/lean.sh

hygiene *args:
    python3 scripts/hygiene.py {{args}}

# Secrets in the whole history; fails until the leaked keys are removed from history.
secrets:
    docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:v8.30.0 git /repo --redact --config /repo/scripts/gitleaks.toml

# Interpret a hash-verified run and render its publication figures.
figures input="out" output="out/evaluation":
    bash scripts/evaluation.sh "{{input}}" "{{output}}"
