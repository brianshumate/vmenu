#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION_FILE="$ROOT_DIR/version.txt"

if [[ ! -f "$VERSION_FILE" ]]; then
  echo "Error: version.txt not found at $VERSION_FILE" >&2
  exit 1
fi

VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"

if [[ -z "$VERSION" ]]; then
  echo "Error: version.txt is empty." >&2
  exit 1
fi

TAG="v$VERSION"

if git -C "$ROOT_DIR" tag --list | grep -qxF "$TAG"; then
  echo "Error: tag $TAG already exists." >&2
  exit 1
fi

echo "Tagging release $TAG"
git -C "$ROOT_DIR" tag -a "$TAG" -m "Release $TAG"

echo "Pushing $TAG to origin"
git -C "$ROOT_DIR" push origin "$TAG"

echo "Done. Released $TAG"
