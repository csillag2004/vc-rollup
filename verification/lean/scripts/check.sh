#!/usr/bin/env bash
# The gate for this directory. Fails unless: the seal holds; no proof file uses a forbidden
# mechanism; `lake build --wfail` is green (the build runs Audit.lean's #guard_msgs axiom
# checks); and, once Audit.lean exists, it checks every target of CONTRACT.md against its spec
# and expects only whitelisted axioms.
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."

command -v lake >/dev/null || {
  echo "lake not on PATH; run scripts/setup-toolchain.sh and add tools/lean-4.23.0/bin to PATH" >&2
  exit 1
}

sha256sum --check --strict frozen/spec.sha256

if grep -nE '\b(sorry|admit|native_decide|axiom|unsafe|implemented_by|extern)\b|debug\.skipKernelTC' \
  -- *.lean; then
  echo "Forbidden proof mechanism in the lines above." >&2
  exit 1
fi

lake build --wfail

if [[ -f Audit.lean ]]; then
  grep -qF '"Audit"' lakefile.toml || { echo "Audit is not a root in lakefile.toml" >&2; exit 1; }
  missing=0
  while IFS='|' read -r spec thm; do
    if ! grep -qF "#check ($thm : $spec)" Audit.lean; then
      echo "Audit.lean lacks: #check ($thm : $spec)" >&2
      missing=1
    fi
  done < <(grep -oE '^\|.*`[A-Za-z0-9]+(Spec|Witness)` \| `[a-z0-9_]+` \|' CONTRACT.md \
    | grep -oE '`[A-Za-z0-9]+(Spec|Witness)` \| `[a-z0-9_]+`' | tr -d '` ' )
  [[ $missing -eq 0 ]] || exit 1
  bad="$(grep -oE 'depends on axioms: \[[^]]*\]' Audit.lean \
    | sed -E 's/.*\[(.*)\]/\1/' | tr ',' '\n' | tr -d ' ' \
    | grep -vxE 'propext|Quot\.sound|Classical\.choice|' | sort -u || true)"
  if [[ -n "$bad" ]]; then
    echo "Axioms outside the whitelist: $bad" >&2
    exit 1
  fi
fi
echo "check.sh: OK"
