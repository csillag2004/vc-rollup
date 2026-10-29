#!/usr/bin/env bash
# Installs Lean 4.23.0 (linux-x86_64) under ./tools without elan and checks the release
# tarball against its pinned SHA-256. Rerunning reuses a verified download and install.
set -euo pipefail

lean_version=4.23.0
release="lean-$lean_version-linux"
pinned_sha=ecd028d6f642b61b451c8687aeeb24dd53789fbfdcb7d4adb8f5cf60eb2022ba
dest="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/tools"
tarball="$dest/$release.tar.zst"
prefix="$dest/lean-$lean_version"

if [[ "$(uname -s)/$(uname -m)" != Linux/x86_64 ]]; then
  echo "linux-x86_64 only; elsewhere use elan, which reads lean-toolchain" >&2
  exit 1
fi
for need in curl tar zstd sha256sum; do
  command -v "$need" >/dev/null || { echo "missing: $need" >&2; exit 1; }
done

mkdir -p "$dest"
if ! [[ -f "$tarball" ]]; then
  curl -fL --retry 3 -o "$tarball.part" \
    "https://github.com/leanprover/lean4/releases/download/v$lean_version/$release.tar.zst"
  mv -- "$tarball.part" "$tarball"
fi
if ! echo "$pinned_sha  $tarball" | sha256sum --check --quiet -; then
  echo "checksum mismatch for $tarball; delete it and rerun" >&2
  exit 1
fi

if ! [[ -x "$prefix/bin/lean" ]]; then
  [[ ! -e "$prefix" ]] || { echo "partial install at $prefix; delete it and rerun" >&2; exit 1; }
  scratch="$(mktemp -d "$dest/unpack.XXXXXX")"
  trap 'rm -rf -- "$scratch"' EXIT
  zstd -dc -- "$tarball" | tar -x -C "$scratch"
  mv -- "$scratch/$release" "$prefix"
fi

got="$("$prefix/bin/lean" --version)"
case "$got" in
  *"version $lean_version,"*) ;;
  *) echo "unexpected lean: $got" >&2; exit 1 ;;
esac
printf '%s\nPATH entry: %s\n' "$got" "$prefix/bin"
