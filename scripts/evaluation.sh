#!/usr/bin/env bash
# Render an interpretation and figures from a completed, hash-verified local run.
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
venv=.venv-evaluation
if [[ ! -x "$venv/bin/python" ]]; then
  "${EVALUATION_PYTHON:-python3}" -m venv "$venv"
fi
if ! cmp -s scripts/evaluation-requirements.txt "$venv/requirements.txt"; then
  "$venv/bin/python" -m pip install --disable-pip-version-check -r scripts/evaluation-requirements.txt
  cp scripts/evaluation-requirements.txt "$venv/requirements.txt"
fi
[[ "${1:-}" != --setup ]] || exit 0
exec "$venv/bin/python" scripts/evaluation.py "${1:-out}" "${2:-out/evaluation}"
