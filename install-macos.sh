#!/usr/bin/env bash
# Registack AIR — Internal Pre-Release. © Registack.
set -euo pipefail

BASE_URL="${REGISTACK_AGENT_DETECTOR_BASE_URL:-https://www.registack.eu/cli/registack-agent-detector}"
TARGET_DIR="${TARGET_DIR:-/usr/local/bin}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/registack-agent-detector"
CONFIG_PATH="${REGISTACK_AGENT_DETECTOR_CONFIG:-$CONFIG_DIR/config.json}"
SCAN_CHOICE="${REGISTACK_AGENT_DETECTOR_SCAN_CHOICE:-}"
BIN_NAME="registack-agent-detector"
IMPORTER_NAME="registack-air-import"
LINK_NAME="registack-air-link"
POINTER_NAME=".registack-agent-detector-config"
TMP_FILE="$(mktemp)"
TMP_IMPORTER_FILE="$(mktemp)"
TMP_LINK_FILE="$(mktemp)"
PROMPT_FOR_SCAN_DIR=true
SELECTED_SCAN_DIR=""
PICKER_LABEL="Choose folder in Finder..."
declare -a CANDIDATE_PATHS

cleanup() {
  rm -f "$TMP_FILE"
  rm -f "$TMP_IMPORTER_FILE"
  rm -f "$TMP_LINK_FILE"
}
trap cleanup EXIT

usage() {
  cat <<EOF
Usage: install-macos.sh [--install-dir PATH] [--scan-choice NUMBER] [--base-url URL] [--config-path PATH] [--no-prompt]
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install-dir)
      TARGET_DIR="$2"
      shift 2
      ;;
    --scan-choice)
      SCAN_CHOICE="$2"
      shift 2
      ;;
    --base-url)
      BASE_URL="$2"
      shift 2
      ;;
    --config-path)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --no-prompt)
      PROMPT_FOR_SCAN_DIR=false
      shift 1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3.9+ is required but python3 was not found." >&2
  exit 1
fi

add_candidate() {
  local candidate="$1"
  local existing
  [ -n "$candidate" ] || return 0
  [ -d "$candidate" ] || return 0
  for existing in "${CANDIDATE_PATHS[@]:-}"; do
    [ "$existing" = "$candidate" ] && return 0
  done
  CANDIDATE_PATHS+=("$candidate")
}

build_candidates() {
  CANDIDATE_PATHS=()
  add_candidate "/"
  add_candidate "$HOME/Applications"
  add_candidate "/Applications"
  add_candidate "$HOME/.registack"
  add_candidate "$HOME/.codex"
  add_candidate "$HOME/.cursor"
  add_candidate "$HOME/.openclaw"
  add_candidate "$HOME/Documents"
  add_candidate "$HOME/Downloads"
  add_candidate "$HOME/Desktop"
  add_candidate "$HOME"
}

pick_scan_dir_with_picker() {
  local selected
  if ! command -v osascript >/dev/null 2>&1; then
    echo "Finder path selection requires osascript." >&2
    exit 1
  fi
  selected="$(osascript -e 'POSIX path of (choose folder with prompt "Select default detection path for Registack AIR Agent Detector")' 2>/dev/null || true)"
  selected="${selected%/}"
  if [ -z "$selected" ] || [ ! -d "$selected" ]; then
    echo "No folder selected." >&2
    exit 1
  fi
  SELECTED_SCAN_DIR="$selected"
}

pick_scan_dir() {
  local index max choice picker_choice
  build_candidates
  if [ "${#CANDIDATE_PATHS[@]}" -eq 0 ]; then
    echo "No predefined detection paths were found on this machine." >&2
    exit 1
  fi

  max="${#CANDIDATE_PATHS[@]}"
  picker_choice=$((max + 1))

  if [ -n "$SCAN_CHOICE" ]; then
    case "$SCAN_CHOICE" in
      ''|*[!0-9]*)
        echo "Invalid --scan-choice value: $SCAN_CHOICE" >&2
        exit 1
        ;;
    esac
    if [ "$SCAN_CHOICE" -lt 1 ] || [ "$SCAN_CHOICE" -gt "$picker_choice" ]; then
      echo "scan-choice out of range: $SCAN_CHOICE (valid: 1-$picker_choice)" >&2
      exit 1
    fi
    if [ "$SCAN_CHOICE" -eq "$picker_choice" ]; then
      pick_scan_dir_with_picker
      return
    fi
    SELECTED_SCAN_DIR="${CANDIDATE_PATHS[$((SCAN_CHOICE - 1))]}"
    return
  fi

  if [ "$PROMPT_FOR_SCAN_DIR" != true ]; then
    echo "Installation requires a detection-path selection. Re-run interactively or with --scan-choice NUMBER." >&2
    exit 1
  fi

  if [ ! -r /dev/tty ]; then
    echo "Interactive path selection is unavailable. Re-run with --scan-choice NUMBER." >&2
    exit 1
  fi

  echo "Select default detection path:" > /dev/tty
  index=1
  while [ "$index" -le "$max" ]; do
    printf '  [%d] %s\n' "$index" "${CANDIDATE_PATHS[$((index - 1))]}" > /dev/tty
    index=$((index + 1))
  done
  printf '  [%d] %s\n' "$picker_choice" "$PICKER_LABEL" > /dev/tty

  while true; do
    printf 'Choice [1-%d]: ' "$picker_choice" > /dev/tty
    IFS= read -r choice < /dev/tty || true
    case "$choice" in
      ''|*[!0-9]*)
        echo "Please select a number between 1 and $picker_choice." > /dev/tty
        ;;
      *)
        if [ "$choice" -eq "$picker_choice" ]; then
          pick_scan_dir_with_picker
          break
        fi
        if [ "$choice" -ge 1 ] && [ "$choice" -le "$max" ]; then
          SELECTED_SCAN_DIR="${CANDIDATE_PATHS[$((choice - 1))]}"
          break
        fi
        echo "Please select a number between 1 and $picker_choice." > /dev/tty
        ;;
    esac
  done
}

pick_scan_dir

config_json="$(python3 - "$SELECTED_SCAN_DIR" <<'PY'
import json
import sys

selected = sys.argv[1]
payload = {
    "scan_profile": "persistent_selected_path",
    "selected_primary_scan_dir": selected,
    "default_scan_dirs": [selected],
}
print(json.dumps(payload, indent=2))
PY
)"

write_pointer_file() {
  local pointer_path="${TARGET_DIR}/${POINTER_NAME}"
  if printf '%s\n' "$CONFIG_PATH" > "$pointer_path" 2>/dev/null; then
    return 0
  fi
  printf '%s\n' "$CONFIG_PATH" | sudo tee "$pointer_path" >/dev/null
}

fetch_artifact() {
  local artifact_name="$1"
  local destination="$2"
  case "$BASE_URL" in
    https://*|http://*)
      curl --http1.1 -fsSL "${BASE_URL}/${artifact_name}" -o "$destination"
      ;;
    file://*)
      python3 - "$BASE_URL" "$artifact_name" "$destination" <<'PY'
import shutil
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

base_url, artifact_name, destination = sys.argv[1:4]
parsed = urlparse(base_url)
if parsed.scheme != "file":
    raise SystemExit("unsupported file URL")
base_path = Path(unquote(parsed.path))
artifact_path = base_path / artifact_name
if not artifact_path.exists():
    raise SystemExit(f"missing artifact: {artifact_path}")
shutil.copyfile(artifact_path, destination)
PY
      ;;
    *)
      if [ -d "$BASE_URL" ]; then
        cp "$BASE_URL/${artifact_name}" "$destination"
      else
        echo "Unsupported base URL or path: $BASE_URL" >&2
        exit 1
      fi
      ;;
  esac
}

fetch_artifact "registack-agent-detector.py" "$TMP_FILE"
fetch_artifact "registack-air-import.py" "$TMP_IMPORTER_FILE"
fetch_artifact "registack-air-link.py" "$TMP_LINK_FILE"

if mkdir -p "$TARGET_DIR" 2>/dev/null \
  && install -m 0755 "$TMP_FILE" "${TARGET_DIR}/${BIN_NAME}" 2>/dev/null \
  && install -m 0755 "$TMP_IMPORTER_FILE" "${TARGET_DIR}/${IMPORTER_NAME}" 2>/dev/null \
  && install -m 0755 "$TMP_LINK_FILE" "${TARGET_DIR}/${LINK_NAME}" 2>/dev/null; then
  :
else
  sudo mkdir -p "$TARGET_DIR"
  sudo install -m 0755 "$TMP_FILE" "${TARGET_DIR}/${BIN_NAME}"
  sudo install -m 0755 "$TMP_IMPORTER_FILE" "${TARGET_DIR}/${IMPORTER_NAME}"
  sudo install -m 0755 "$TMP_LINK_FILE" "${TARGET_DIR}/${LINK_NAME}"
fi

mkdir -p "$(dirname "$CONFIG_PATH")"
printf '%s\n' "$config_json" > "$CONFIG_PATH"
write_pointer_file

"${TARGET_DIR}/${BIN_NAME}" --version >/dev/null
"${TARGET_DIR}/${IMPORTER_NAME}" --version >/dev/null
"${TARGET_DIR}/${LINK_NAME}" --version >/dev/null

echo "Registack AIR Agent Detector installed successfully at ${TARGET_DIR}/${BIN_NAME}"
echo "Registack AIR Importer installed successfully at ${TARGET_DIR}/${IMPORTER_NAME}"
echo "Registack AIR Link installed successfully at ${TARGET_DIR}/${LINK_NAME}"
echo "Primary detection path: ${SELECTED_SCAN_DIR}"
echo "Default scan profile: persistent selected path"
echo "Config: ${CONFIG_PATH}"
echo "Verify with: ${BIN_NAME} --version"
echo "Importer verify: ${IMPORTER_NAME} --version"
echo "AIR link verify: ${LINK_NAME} --version"
