#!/usr/bin/env bash
# Baseline contains only fingerprints of three historical exposed keys, never values.
# --strict omits that baseline and remains a release gate until history is repaired.
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
args=()
case "${1:-}" in
  '') args+=(--gitleaks-ignore-path "$PWD/scripts/gitleaks-history-baseline.txt") ;;
  --strict) ;;
  *) echo 'Usage: scripts/secrets.sh [--strict]' >&2; exit 2 ;;
esac
git_common="$(git rev-parse --path-format=absolute --git-common-dir)"
docker run --rm -v "$PWD:$PWD:ro" -v "$git_common:$git_common:ro" \
  ghcr.io/gitleaks/gitleaks:v8.30.0 git "$PWD" --redact \
  --config "$PWD/scripts/gitleaks.toml" "${args[@]}"
