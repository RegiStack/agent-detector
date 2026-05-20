#!/usr/bin/env bash
# Registack AIR — Internal Pre-Release. © Registack.
set -euo pipefail

TARGET_DIR="${TARGET_DIR:-/usr/local/bin}"
BIN_NAME="registack-agent-detector"
IMPORTER_NAME="registack-air-import"
LINK_NAME="registack-air-link"
POINTER_NAME=".registack-agent-detector-config"
TARGET_PATH="${TARGET_DIR}/${BIN_NAME}"
IMPORTER_PATH="${TARGET_DIR}/${IMPORTER_NAME}"
LINK_PATH="${TARGET_DIR}/${LINK_NAME}"
POINTER_PATH="${TARGET_DIR}/${POINTER_NAME}"
DEFAULT_CONFIG_PATH="${REGISTACK_AGENT_DETECTOR_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/registack-agent-detector/config.json}"
CONFIG_PATH="$DEFAULT_CONFIG_PATH"

remove_path() {
  local target="$1"
  [ -n "$target" ] || return 0
  [ -e "$target" ] || return 0
  if [ -w "$target" ] || [ -w "$(dirname "$target")" ]; then
    rm -f "$target"
  else
    sudo rm -f "$target"
  fi
}

if [ -e "$POINTER_PATH" ]; then
  pointer_value="$(cat "$POINTER_PATH" 2>/dev/null || true)"
  if [ -n "$pointer_value" ]; then
    CONFIG_PATH="$pointer_value"
  fi
fi

remove_path "$TARGET_PATH"
remove_path "$IMPORTER_PATH"
remove_path "$LINK_PATH"
remove_path "$POINTER_PATH"
remove_path "$CONFIG_PATH"
remove_path "$(dirname "$CONFIG_PATH")/state.json"

echo "Registack AIR Agent Detector uninstall complete."
