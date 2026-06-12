#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION_FILE="$ROOT_DIR/version.txt"

usage() {
  echo "Usage: $0 <major|minor|patch|x.y.z>"
  echo ""
  echo "  major    Increment major version (x.0.0)"
  echo "  minor    Increment minor version (x.y.0)"
  echo "  patch    Increment patch version (x.y.z)"
  echo "  x.y.z    Set an explicit semantic version"
  exit 1
}

[[ $# -ne 1 ]] && usage

# Read current version from version.txt; fall back to Info.plist
if [[ -f "$VERSION_FILE" ]]; then
  CURRENT_VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"
else
  CURRENT_VERSION="$(defaults read "$ROOT_DIR/vmenu/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "")"
fi

if [[ -z "$CURRENT_VERSION" ]]; then
  echo "Error: could not determine current version." >&2
  exit 1
fi

# Parse current version — support both 2-part (1.27) and 3-part (1.27.0)
IFS='.' read -r -a PARTS <<< "$CURRENT_VERSION"
MAJOR="${PARTS[0]:-0}"
MINOR="${PARTS[1]:-0}"
PATCH="${PARTS[2]:-0}"

BUMP="$1"

case "$BUMP" in
  major)
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
    ;;
  minor)
    MINOR=$((MINOR + 1))
    PATCH=0
    ;;
  patch)
    PATCH=$((PATCH + 1))
    ;;
  [0-9]*.[0-9]*.[0-9]*)
    IFS='.' read -r MAJOR MINOR PATCH <<< "$BUMP"
    ;;
  *)
    echo "Error: unrecognised argument '$BUMP'." >&2
    usage
    ;;
esac

NEW_VERSION="$MAJOR.$MINOR.$PATCH"

echo "Bumping $CURRENT_VERSION → $NEW_VERSION"

# ── version.txt ─────────────────────────────────────────────────────────────
echo "$NEW_VERSION" > "$VERSION_FILE"

# ── Info.plist helper (PlistBuddy) ──────────────────────────────────────────
update_plist() {
  local plist="$1"
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $NEW_VERSION" "$plist"
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $NEW_VERSION" "$plist"
  echo "  Updated $plist"
}

update_plist "$ROOT_DIR/vmenu/Info.plist"
update_plist "$ROOT_DIR/vmenuhelper/Info.plist"

# The About box reads its version from Info.plist (stamped above), with a
# neutral "—" fallback, so there is no longer a hardcoded version literal in
# the Swift source to keep in sync here.

echo "Done. Version is now $NEW_VERSION"
