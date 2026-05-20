#!/usr/bin/env bash
# Registack AIR — Internal Pre-Release. © Registack.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$ROOT_DIR/dist/cli/registack-agent-detector"
ENV_FILE="$ROOT_DIR/.lovable-publish.env"

LOVABLE_ROOT="${LOVABLE_PROJECT_ROOT:-}"
PUBLIC_ROOT="${LOVABLE_PUBLIC_ROOT:-}"
TARGET_ROOT="${LOVABLE_TARGET_DIR:-}"

usage() {
  cat <<'EOF'
Usage:
  bash publish-lovable.sh [--lovable-root PATH]
                          [--public-root PATH]
                          [--target-dir PATH]
                          [--no-build]
                          [--dry-run]
EOF
}

resolve_from_project_root() {
  local base="$1"
  printf '%s/public/cli/registack-agent-detector\n' "$base"
}

resolve_from_public_root() {
  local base="$1"
  printf '%s/cli/registack-agent-detector\n' "$base"
}

canonicalize_dir() {
  local path="$1"
  mkdir -p "$path"
  (
    cd "$path"
    pwd
  )
}

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  LOVABLE_ROOT="${LOVABLE_ROOT:-${LOVABLE_PROJECT_ROOT:-}}"
  PUBLIC_ROOT="${PUBLIC_ROOT:-${LOVABLE_PUBLIC_ROOT:-}}"
  TARGET_ROOT="${TARGET_ROOT:-${LOVABLE_TARGET_DIR:-}}"
fi

NO_BUILD=0
DRY_RUN=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --lovable-root)
      LOVABLE_ROOT="${2:-}"
      shift 2
      ;;
    --public-root)
      PUBLIC_ROOT="${2:-}"
      shift 2
      ;;
    --target-dir)
      TARGET_ROOT="${2:-}"
      shift 2
      ;;
    --no-build)
      NO_BUILD=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

selector_count=0
[ -n "$LOVABLE_ROOT" ] && selector_count=$((selector_count + 1))
[ -n "$PUBLIC_ROOT" ] && selector_count=$((selector_count + 1))
[ -n "$TARGET_ROOT" ] && selector_count=$((selector_count + 1))

if [ "$selector_count" -eq 0 ]; then
  printf 'No Lovable target configured.\n' >&2
  exit 2
fi

if [ "$selector_count" -gt 1 ]; then
  printf 'Configure exactly one of --lovable-root, --public-root, or --target-dir.\n' >&2
  exit 2
fi

if [ -n "$LOVABLE_ROOT" ]; then
  TARGET_DIR="$(resolve_from_project_root "$LOVABLE_ROOT")"
elif [ -n "$PUBLIC_ROOT" ]; then
  TARGET_DIR="$(resolve_from_public_root "$PUBLIC_ROOT")"
else
  TARGET_DIR="$TARGET_ROOT"
fi

if [ "$NO_BUILD" -eq 0 ]; then
  bash "$ROOT_DIR/assemble-publish-tree.sh" >/dev/null
fi

SOURCE_DIR="$(canonicalize_dir "$SOURCE_DIR")"
TARGET_DIR="$(canonicalize_dir "$TARGET_DIR")"

REQUIRED_FILES=(
  "index.html"
  "README.md"
  "LICENSE.txt"
  "NOTICE.md"
  "SECURITY.md"
  "registack-agent-detector.py"
  "registack-agent-detector.ps1"
  "registack-air-import.py"
  "registack-air-import.ps1"
  "registack-air-link.py"
  "registack-air-link.ps1"
  "install-macos.sh"
  "install-linux.sh"
  "install-windows.ps1"
  "uninstall-macos.sh"
  "uninstall-linux.sh"
  "uninstall-windows.ps1"
)

printf 'Source: %s\n' "$SOURCE_DIR"
printf 'Target: %s\n' "$TARGET_DIR"

if [ "$DRY_RUN" -eq 1 ]; then
  printf 'Dry run only. No files copied.\n'
  exit 0
fi

rsync -a --delete "$SOURCE_DIR/" "$TARGET_DIR/"

for file in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$TARGET_DIR/$file" ]; then
    printf 'Lovable target verification failed: %s\n' "$TARGET_DIR/$file" >&2
    exit 2
  fi
done

printf 'Lovable publish tree synced to %s\n' "$TARGET_DIR"
printf 'Next step: open Lovable and click Publish/Update.\n'
