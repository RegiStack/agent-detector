#!/usr/bin/env bash
# Registack AIR — Internal Pre-Release. © Registack.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${1:-$ROOT_DIR/dist/cli/registack-agent-detector}"

mkdir -p "$OUT_DIR"

FILES=(
  "index.html"
  "README.md"
  "LICENSE.txt"
  "NOTICE.md"
  "SECURITY.md"
  "registack-agent-detector.py"
  "registack-agent-detector.ps1"
  "registack-air-import.py"
  "registack-air-import.ps1"
  "install-macos.sh"
  "install-linux.sh"
  "install-windows.ps1"
  "uninstall-macos.sh"
  "uninstall-linux.sh"
  "uninstall-windows.ps1"
)

for file in "${FILES[@]}"; do
  cp "$ROOT_DIR/$file" "$OUT_DIR/$file"
done

printf 'Publish tree assembled at %s\n' "$OUT_DIR"
