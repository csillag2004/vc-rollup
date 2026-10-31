#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ -x verification/lean/tools/lean-4.23.0/bin/lake ]]; then
  export PATH="$PWD/verification/lean/tools/lean-4.23.0/bin:$PATH"
elif ! command -v lean >/dev/null || ! lean --version | grep -q 'version 4.23.0,'; then
  bash verification/lean/scripts/setup-toolchain.sh
  export PATH="$PWD/verification/lean/tools/lean-4.23.0/bin:$PATH"
fi
bash verification/lean/scripts/check.sh
