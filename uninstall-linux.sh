#!/usr/bin/env bash
# Registack AIR — Internal Pre-Release. © Registack.
set -euo pipefail

TARGET_DIR="${TARGET_DIR:-/usr/local/bin}"
BIN_NAME="registack-agent-detector"
POINTER_NAME=".registack-agent-detector-config"
TARGET_PATH="${TARGET_DIR}/${BIN_NAME}"
POINTER_PATH="${TARGET_DIR}/${POINTER_NAME}"

if [ -e "$TARGET_PATH" ]; then
  if rm -f "$TARGET_PATH" 2>/dev/null; then
    :
  else
    sudo rm -f "$TARGET_PATH"
  fi
fi

if [ -e "$POINTER_PATH" ]; then
  if rm -f "$POINTER_PATH" 2>/dev/null; then
    :
  else
    sudo rm -f "$POINTER_PATH"
  fi
fi

echo "Registack AIR Agent Detector uninstall complete."
