#!/bin/bash
# Build vmenu.app bundle for distribution.
#
# The bundle contains:
#   Contents/MacOS/vmenu                                          — main app (sandboxed)
#   Contents/MacOS/com.brianshumate.vmenu.helper                  — XPC helper (unsandboxed)
#   Contents/Library/LaunchAgents/com.brianshumate.vmenu.helper.plist — helper agent plist
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
HELPER_NAME="com.brianshumate.vmenu.helper"
HELPER_SPM_TARGET="vmenu-helper"
APP_BUNDLE="${APP_NAME}.app"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${SCRIPT_DIR}/${APP_BUNDLE}"
ENTITLEMENTS="${SCRIPT_DIR}/vmenu/vmenu.entitlements"
HELPER_ENTITLEMENTS="${SCRIPT_DIR}/vmenuhelper/vmenuhelper.entitlements"

# ── Build ────────────────────────────────────────────────────────────────────
echo "Building ${APP_NAME} + helper (${CONFIGURATION})..."
swift build -c "${CONFIGURATION}"

BIN_PATH=$(swift build -c "${CONFIGURATION}" --show-bin-path)
BINARY="${BIN_PATH}/${APP_NAME}"
HELPER_BINARY="${BIN_PATH}/${HELPER_SPM_TARGET}"

if [ ! -f "${BINARY}" ]; then
    echo "Error: Main binary not found at ${BINARY}"
    exit 1
fi

if [ ! -f "${HELPER_BINARY}" ]; then
    echo "Error: Helper binary not found at ${HELPER_BINARY}"
    exit 1
fi

# ── Assemble .app bundle ─────────────────────────────────────────────────────
echo "Creating ${APP_BUNDLE}..."
rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS"
mkdir -p "${APP_DIR}/Contents/Resources"
mkdir -p "${APP_DIR}/Contents/Library/LaunchAgents"

# Copy main binary
cp "${BINARY}" "${APP_DIR}/Contents/MacOS/${APP_NAME}"

# Copy helper binary (renamed to match the Mach service name / bundle ID)
cp "${HELPER_BINARY}" "${APP_DIR}/Contents/MacOS/${HELPER_NAME}"

# Copy Info.plist
cp "${SCRIPT_DIR}/vmenu/Info.plist" "${APP_DIR}/Contents/Info.plist"

# Copy helper launchd plist into the bundle location SMAppService expects
cp "${SCRIPT_DIR}/vmenuhelper/${HELPER_NAME}.plist" \
   "${APP_DIR}/Contents/Library/LaunchAgents/${HELPER_NAME}.plist"

# PkgInfo — standard for all macOS .app bundles
printf 'APPL????' > "${APP_DIR}/Contents/PkgInfo"

# Copy icon (.icns for legacy support)
if [ -f "${SCRIPT_DIR}/vmenu/AppIcon.icns" ]; then
    cp "${SCRIPT_DIR}/vmenu/AppIcon.icns" "${APP_DIR}/Contents/Resources/AppIcon.icns"
    echo "Included app icon (.icns)."
else
    echo "Warning: AppIcon.icns not found, app will use default icon."
fi

# Copy asset catalog if present (for CFBundleIconName / modern icon support)
if [ -d "${SCRIPT_DIR}/vmenu/Assets.xcassets" ]; then
    cp -R "${SCRIPT_DIR}/vmenu/Assets.xcassets" "${APP_DIR}/Contents/Resources/Assets.xcassets"
    echo "Included asset catalog."
fi

# ── Stamp version from git tag (if available) ────────────────────────────────
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

    # Sign helper first (inner binary before outer bundle)
    echo "Signing helper..."
    codesign --force --options runtime \
        --entitlements "${HELPER_ENTITLEMENTS}" \
        --sign "${IDENTITY}" \
        --timestamp \
        "${APP_DIR}/Contents/MacOS/${HELPER_NAME}"

    # Sign main binary
    echo "Signing main binary..."
    codesign --force --options runtime \
        --entitlements "${ENTITLEMENTS}" \
        --sign "${IDENTITY}" \
        --timestamp \
        "${APP_DIR}/Contents/MacOS/${APP_NAME}"

    # Sign the bundle
    echo "Signing bundle..."
    codesign --force --options runtime \
        --entitlements "${ENTITLEMENTS}" \
        --sign "${IDENTITY}" \
        --timestamp \
        "${APP_DIR}"

    echo "Verifying signature..."
    codesign --verify --deep --strict --verbose=2 "${APP_DIR}"
else
    # Ad-hoc sign for local use
    # Sign helper first (inner before outer)
    codesign --force --sign - "${APP_DIR}/Contents/MacOS/${HELPER_NAME}"
    codesign --force --deep --sign - "${APP_DIR}"
    echo "Ad-hoc signed (use './build-app.sh release sign' for distribution signing)."
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Built: ${APP_DIR}"
echo ""
echo "Bundle contents:"
find "${APP_DIR}" -type f | sed "s|${APP_DIR}/||" | sort
echo ""
echo "To install, copy to /Applications:"
echo "  cp -r ${APP_BUNDLE} /Applications/"
