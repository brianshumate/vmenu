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

# ── App icon ─────────────────────────────────────────────────────────────────
# Generate AppIcon.icns from source SVG layers at build time.
# All sizes are rendered from vmenu/icon-layers/variants/default.svg so the
# .icns always matches the asset catalog default variant without manual upkeep.
ICON_SRC="${SCRIPT_DIR}/vmenu/icon-layers/variants/default.svg"
ICONSET_DIR="${SCRIPT_DIR}/vmenu/AppIcon.iconset"
ICNS_OUT="${APP_DIR}/Contents/Resources/AppIcon.icns"

if [ -f "${ICON_SRC}" ] && command -v rsvg-convert &>/dev/null && command -v iconutil &>/dev/null; then
    echo "Building AppIcon.icns from source SVG layers..."
    rm -rf "${ICONSET_DIR}"
    mkdir -p "${ICONSET_DIR}"

    _render_icon() {
        local name="$1" px="$2"
        rsvg-convert --width "${px}" --height "${px}" --keep-aspect-ratio \
            --output "${ICONSET_DIR}/${name}" "${ICON_SRC}"
        # Tag with sRGB profile
        sips --matchTo '/System/Library/ColorSync/Profiles/sRGB Profile.icc' \
            "${ICONSET_DIR}/${name}" --out "${ICONSET_DIR}/${name}" 2>/dev/null || true
    }

    _render_icon "icon_16x16.png"      16
    _render_icon "icon_16x16@2x.png"   32
    _render_icon "icon_32x32.png"      32
    _render_icon "icon_32x32@2x.png"   64
    _render_icon "icon_128x128.png"    128
    _render_icon "icon_128x128@2x.png" 256
    _render_icon "icon_256x256.png"    256
    _render_icon "icon_256x256@2x.png" 512
    _render_icon "icon_512x512.png"    512
    _render_icon "icon_512x512@2x.png" 1024

    iconutil --convert icns --output "${ICNS_OUT}" "${ICONSET_DIR}"
    rm -rf "${ICONSET_DIR}"
    echo "Included app icon (.icns, built from SVG layers)."
elif [ -f "${SCRIPT_DIR}/vmenu/AppIcon.icns" ]; then
    # Fallback: use pre-built .icns if rsvg-convert / iconutil are unavailable
    cp "${SCRIPT_DIR}/vmenu/AppIcon.icns" "${ICNS_OUT}"
    echo "Included app icon (.icns, pre-built fallback — install rsvg-convert for source-derived builds)."
else
    echo "Warning: AppIcon.icns not found and rsvg-convert unavailable. App will use default icon."
fi

# Copy asset catalog (CFBundleIconName / appearance-variant icon support)
if [ -d "${SCRIPT_DIR}/vmenu/Assets.xcassets" ]; then
    cp -R "${SCRIPT_DIR}/vmenu/Assets.xcassets" "${APP_DIR}/Contents/Resources/Assets.xcassets"
    echo "Included asset catalog (default + dark + clear + tinted variants)."
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
