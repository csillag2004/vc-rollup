#!/usr/bin/env bash
# The gate for this directory: seal intact, no forbidden proof mechanisms, `lake build` green,
# no `sorry`, and (once Audit.lean exists) only whitelisted axioms. Exits non-zero on any failure.
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."

command -v lake >/dev/null || { echo "lake not on PATH; run scripts/setup-toolchain.sh and add tools/lean-4.23.0/bin to PATH" >&2; exit 1; }

sha256sum --check --strict frozen/spec.sha256

if grep -nE '\b(sorry|admit|native_decide|axiom|unsafe|implemented_by|extern)\b|debug\.skipKernelTC' -- *.lean; then
  echo "Forbidden proof mechanism in the lines above." >&2
  exit 1
fi

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
lake build 2>&1 | tee "$log"
if grep -q "declaration uses 'sorry'" "$log"; then
  echo "A declaration uses sorry." >&2
  exit 1
fi

if [[ -f Audit.lean ]]; then
  lake env lean Audit.lean 2>&1 | tee "$log"
  bad="$(grep -oE "depends on axioms: \[[^]]*\]" "$log" \
    | sed -E 's/.*\[(.*)\]/\1/' | tr ',' '\n' | tr -d ' ' \
    | grep -vxE 'propext|Quot\.sound|Classical\.choice|' | sort -u || true)"
  if [[ -n "$bad" ]]; then
    echo "Axioms outside the whitelist: $bad" >&2
    exit 1
  fi
fi
echo "check.sh: OK"
