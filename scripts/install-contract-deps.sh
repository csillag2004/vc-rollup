#!/usr/bin/env bash
# GitHub/Zenodo source archives omit Git submodule contents.
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
revision="$(node -p 'Object.entries(JSON.parse(require("fs").readFileSync("foundry.lock", "utf8"))).find(([name]) => name.endsWith("forge-std"))[1].tag.rev')"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid forge-std revision in foundry.lock' >&2; exit 1; }
dest=lib/forge-std
if [[ -e "$dest/.git" ]]; then
  actual="$(git -C "$dest" rev-parse HEAD)"
  [[ "$actual" == "$revision" ]] || { echo 'Existing forge-std revision differs from foundry.lock; refusing to replace it.' >&2; exit 1; }
  [[ -z "$(git -C "$dest" status --porcelain)" ]] || { echo 'Existing forge-std has local changes; refusing to replace it.' >&2; exit 1; }
  exit 0
fi
if [[ -d "$dest" ]] && [[ -n "$(ls -A "$dest")" ]]; then
  echo 'Existing forge-std has no Git metadata; move it aside before installing the pinned dependency.' >&2
  exit 1
fi
mkdir -p lib
scratch="$(mktemp -d lib/.forge-std.XXXXXX)"
trap 'rm -rf -- "$scratch"' EXIT
git init -q "$scratch"
git -C "$scratch" remote add origin https://github.com/foundry-rs/forge-std.git
git -C "$scratch" fetch --depth 1 origin "$revision"
git -C "$scratch" checkout --detach -q FETCH_HEAD
[[ "$(git -C "$scratch" rev-parse HEAD)" == "$revision" ]]
[[ ! -d "$dest" ]] || rmdir "$dest"
mv "$scratch" "$dest"
echo "Installed forge-std at $revision"
