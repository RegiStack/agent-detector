#!/usr/bin/env bash
# Registack AIR — Internal Pre-Release. © Registack.
set -euo pipefail

BASE_URL="${REGISTACK_AGENT_DETECTOR_BASE_URL:-https://registack.eu/cli/registack-agent-detector}"
TARGET_DIR="${TARGET_DIR:-/usr/local/bin}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/registack-agent-detector"
CONFIG_PATH="${REGISTACK_AGENT_DETECTOR_CONFIG:-$CONFIG_DIR/config.json}"
SCAN_CHOICE="${REGISTACK_AGENT_DETECTOR_SCAN_CHOICE:-}"
BIN_NAME="registack-agent-detector"
POINTER_NAME=".registack-agent-detector-config"
TMP_FILE="$(mktemp)"
PROMPT_FOR_SCAN_DIR=true
SELECTED_SCAN_DIR=""
declare -a CANDIDATE_PATHS

cleanup() {
  rm -f "$TMP_FILE"
}
trap cleanup EXIT

usage() {
  cat <<EOF
Usage: install-linux.sh [--install-dir PATH] [--scan-choice NUMBER] [--base-url URL] [--config-path PATH] [--no-prompt]
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
  add_candidate "$HOME/apps"
  add_candidate "$HOME/.registack"
  add_candidate "$HOME/Documents"
  add_candidate "$HOME/Downloads"
  add_candidate "/opt/apps"
  add_candidate "/srv"
  add_candidate "$HOME"
}

pick_scan_dir() {
  local index max choice
  build_candidates
  if [ "${#CANDIDATE_PATHS[@]}" -eq 0 ]; then
    echo "No predefined detection paths were found on this machine." >&2
    exit 1
  fi

  max="${#CANDIDATE_PATHS[@]}"

  if [ -n "$SCAN_CHOICE" ]; then
    case "$SCAN_CHOICE" in
      ''|*[!0-9]*)
        echo "Invalid --scan-choice value: $SCAN_CHOICE" >&2
        exit 1
        ;;
    esac
    if [ "$SCAN_CHOICE" -lt 1 ] || [ "$SCAN_CHOICE" -gt "$max" ]; then
      echo "scan-choice out of range: $SCAN_CHOICE (valid: 1-$max)" >&2
      exit 1
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

  while true; do
    printf 'Choice [1-%d]: ' "$max" > /dev/tty
    IFS= read -r choice < /dev/tty || true
    case "$choice" in
      ''|*[!0-9]*)
        echo "Please select a number between 1 and $max." > /dev/tty
        ;;
      *)
        if [ "$choice" -ge 1 ] && [ "$choice" -le "$max" ]; then
          SELECTED_SCAN_DIR="${CANDIDATE_PATHS[$((choice - 1))]}"
          break
        fi
        echo "Please select a number between 1 and $max." > /dev/tty
        ;;
    esac
  done
}

pick_scan_dir

escaped_item=$(printf '%s' "$SELECTED_SCAN_DIR" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')

curl -fsSL "${BASE_URL}/registack-agent-detector.py" -o "$TMP_FILE"

if mkdir -p "$TARGET_DIR" 2>/dev/null && install -m 0755 "$TMP_FILE" "${TARGET_DIR}/${BIN_NAME}" 2>/dev/null; then
  :
else
  sudo mkdir -p "$TARGET_DIR"
  sudo install -m 0755 "$TMP_FILE" "${TARGET_DIR}/${BIN_NAME}"
fi

mkdir -p "$(dirname "$CONFIG_PATH")"
cat > "$CONFIG_PATH" <<EOF
{
  "default_scan_dirs": [${escaped_item}]
}
EOF
printf '%s\n' "$CONFIG_PATH" > "${TARGET_DIR}/${POINTER_NAME}"

"${TARGET_DIR}/${BIN_NAME}" --version >/dev/null

echo "Registack AIR Agent Detector installed successfully at ${TARGET_DIR}/${BIN_NAME}"
echo "Selected detection path: ${SELECTED_SCAN_DIR}"
echo "Config: ${CONFIG_PATH}"
echo "Verify with: ${BIN_NAME} --version"
