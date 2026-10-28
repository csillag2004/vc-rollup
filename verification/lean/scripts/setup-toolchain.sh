#!/usr/bin/env bash
# Install the pinned Lean release into ./tools without elan, verifying the archive hash.
# Idempotent: an existing download or installation is checked and reused.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="4.23.0"
ARCHIVE_NAME="lean-${VERSION}-linux.tar.zst"
ARCHIVE_URL="https://github.com/leanprover/lean4/releases/download/v${VERSION}/${ARCHIVE_NAME}"
ARCHIVE_SHA256="ecd028d6f642b61b451c8687aeeb24dd53789fbfdcb7d4adb8f5cf60eb2022ba"
TOOLS_DIR="$ROOT/tools"
ARCHIVE_PATH="$TOOLS_DIR/$ARCHIVE_NAME"
INSTALL_DIR="$TOOLS_DIR/lean-${VERSION}"

if [[ "$(uname -sm)" != "Linux x86_64" ]]; then
  echo "This script installs the linux-x86_64 release; on other platforms use elan, which reads lean-toolchain." >&2
  exit 1
fi
for tool in curl tar zstd sha256sum; do
  command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done

mkdir -p "$TOOLS_DIR"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  curl --fail --location --retry 3 --output "$ARCHIVE_PATH.part" "$ARCHIVE_URL"
  mv "$ARCHIVE_PATH.part" "$ARCHIVE_PATH"
fi

actual="$(sha256sum "$ARCHIVE_PATH" | cut -d ' ' -f 1)"
if [[ "$actual" != "$ARCHIVE_SHA256" ]]; then
  echo "Archive checksum mismatch: expected $ARCHIVE_SHA256, got $actual" >&2
  exit 1
fi

if [[ ! -x "$INSTALL_DIR/bin/lean" ]]; then
  if [[ -e "$INSTALL_DIR" ]]; then
    echo "Incomplete installation at $INSTALL_DIR; remove it and rerun." >&2
    exit 1
  fi
  tmp="$(mktemp -d "$TOOLS_DIR/.extract.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  tar --zstd -xf "$ARCHIVE_PATH" -C "$tmp"
  mv "$tmp/lean-${VERSION}-linux" "$INSTALL_DIR"
fi

version_output="$("$INSTALL_DIR/bin/lean" --version)"
if [[ "$version_output" != *"version ${VERSION},"* ]]; then
  echo "Unexpected Lean version: $version_output" >&2
  exit 1
fi
echo "$version_output"
echo "Add to PATH: $INSTALL_DIR/bin"
