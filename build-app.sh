#!/bin/bash
# Build vmenu.app bundle for distribution.
#
# Usage:
#   ./build-app.sh                 # release build, ad-hoc signed
#   ./build-app.sh debug           # debug build, ad-hoc signed
#   ./build-app.sh release sign    # release build, Developer ID signed + notarisation-ready
#
# When "sign" is passed as $2 the script uses the first "Developer ID Application"
# identity found in your keychain. Override with CODESIGN_IDENTITY env var.
set -euo pipefail

CONFIGURATION="${1:-release}"
SIGN="${2:-}"
APP_NAME="vmenu"
APP_BUNDLE="${APP_NAME}.app"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${SCRIPT_DIR}/${APP_BUNDLE}"
ENTITLEMENTS="${SCRIPT_DIR}/vmenu/vmenu.entitlements"

# ── Build ────────────────────────────────────────────────────────────────────
echo "Building ${APP_NAME} (${CONFIGURATION})..."
swift build -c "${CONFIGURATION}"

BIN_PATH=$(swift build -c "${CONFIGURATION}" --show-bin-path)
BINARY="${BIN_PATH}/${APP_NAME}"

if [ ! -f "${BINARY}" ]; then
    echo "Error: Binary not found at ${BINARY}"
    exit 1
fi

# ── Assemble .app bundle ─────────────────────────────────────────────────────
echo "Creating ${APP_BUNDLE}..."
rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS"
mkdir -p "${APP_DIR}/Contents/Resources"

# Copy binary
cp "${BINARY}" "${APP_DIR}/Contents/MacOS/${APP_NAME}"

# Copy Info.plist
cp "${SCRIPT_DIR}/vmenu/Info.plist" "${APP_DIR}/Contents/Info.plist"

# PkgInfo — standard for all macOS .app bundles
printf 'APPL????' > "${APP_DIR}/Contents/PkgInfo"

# Copy icon
if [ -f "${SCRIPT_DIR}/vmenu/AppIcon.icns" ]; then
    cp "${SCRIPT_DIR}/vmenu/AppIcon.icns" "${APP_DIR}/Contents/Resources/AppIcon.icns"
    echo "Included app icon."
else
    echo "Warning: AppIcon.icns not found, app will use default icon."
fi

# ── Stamp version from git tag (if available) ────────────────────────────────
# When run in CI the tag is typically checked-out; locally we try to read it.
GIT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || true)
if [ -n "${GIT_VERSION}" ]; then
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${GIT_VERSION}" "${APP_DIR}/Contents/Info.plist"
    /usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${GIT_VERSION}" "${APP_DIR}/Contents/Info.plist"
    echo "Stamped version: ${GIT_VERSION}"
fi

# ── Code-sign ─────────────────────────────────────────────────────────────────
if [ "${SIGN}" = "sign" ]; then
    IDENTITY="${CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | grep 'Developer ID Application' | head -1 | awk -F'"' '{print $2}')}"
    if [ -z "${IDENTITY}" ]; then
        echo "Error: No Developer ID Application identity found. Set CODESIGN_IDENTITY."
        exit 1
    fi
    echo "Signing with: ${IDENTITY}"
    codesign --force --options runtime \
        --entitlements "${ENTITLEMENTS}" \
        --sign "${IDENTITY}" \
        --timestamp \
        "${APP_DIR}/Contents/MacOS/${APP_NAME}"
    codesign --force --options runtime \
        --entitlements "${ENTITLEMENTS}" \
        --sign "${IDENTITY}" \
        --timestamp \
        "${APP_DIR}"
    echo "Verifying signature..."
    codesign --verify --deep --strict --verbose=2 "${APP_DIR}"
else
    # Ad-hoc sign for local use (Gatekeeper will still prompt on first launch)
    codesign --force --deep --sign - "${APP_DIR}"
    echo "Ad-hoc signed (use './build-app.sh release sign' for distribution signing)."
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Built: ${APP_DIR}"
echo ""
echo "To install, copy to /Applications:"
echo "  cp -r ${APP_BUNDLE} /Applications/"
