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
# Two complementary steps, run in order so the final .icns always has all sizes:
#
# Step 1 — Assets.car (CFBundleIconName / adaptive-icon variants)
#   Compile Assets.xcassets with actool so macOS can load the appearance-aware
#   variants (default, dark, high-contrast) at runtime.
#   A raw .xcassets directory is NOT read by the OS — only a compiled .car works.
#   actool also emits its own AppIcon.icns, which is replaced in Step 2.
#   Falls back to copying the raw catalog if xcrun/actool is unavailable.
#
# Step 2 — AppIcon.icns (CFBundleIconFile)
#   Generate a full-resolution .icns from the source SVG at build time so the
#   Finder/Dock icon always matches the source without manual upkeep.
#   All ten canonical macOS sizes are rendered from default.svg.
#   Running after actool ensures our version (10 sizes) is not overwritten by
#   actool's minimal single-slot output.
#   Falls back to the pre-built vmenu/AppIcon.icns when rsvg-convert is absent.
ICON_SRC="${SCRIPT_DIR}/vmenu/icon-layers/variants/default.svg"
ICONSET_DIR="${SCRIPT_DIR}/vmenu/AppIcon.iconset"
ICNS_OUT="${APP_DIR}/Contents/Resources/AppIcon.icns"
XCASSETS_SRC="${SCRIPT_DIR}/vmenu/Assets.xcassets"
ACTOOL_PARTIAL_PLIST="${APP_DIR}/Contents/Resources/actool-partial.plist"

# Step 1: compile asset catalog with actool → Assets.car + appearance-variant icons.
# macOS requires a compiled .car file to honour CFBundleIconName and load adaptive
# icon variants (dark, high-contrast).  Copying the raw .xcassets directory does
# nothing — the OS never reads uncompiled asset catalogs at runtime.
if [ -d "${XCASSETS_SRC}" ] && command -v xcrun &>/dev/null && xcrun actool --version &>/dev/null 2>&1; then
    echo "Compiling asset catalog with actool..."
    xcrun actool \
        --output-format human-readable-text \
        --notices \
        --warnings \
        --platform macosx \
        --minimum-deployment-target 26.0 \
        --target-device mac \
        --app-icon AppIcon \
        --output-partial-info-plist "${ACTOOL_PARTIAL_PLIST}" \
        --compile "${APP_DIR}/Contents/Resources" \
        "${XCASSETS_SRC}" 2>&1 | grep -v "^$" || true
    # Remove the temporary partial plist — Info.plist already declares the keys.
    rm -f "${ACTOOL_PARTIAL_PLIST}"
    echo "Compiled asset catalog (Assets.car, adaptive icon variants included)."
elif [ -d "${XCASSETS_SRC}" ]; then
    # actool unavailable — copy the raw catalog as a last resort.
    # CFBundleIconName will not resolve appearance variants, but the .icns
    # (CFBundleIconFile) still provides the Finder/Dock icon.
    cp -R "${XCASSETS_SRC}" "${APP_DIR}/Contents/Resources/Assets.xcassets"
    echo "Warning: actool unavailable — copied raw asset catalog (install Xcode Command Line Tools for compiled .car support)."
fi

# Step 2: build AppIcon.icns (runs after actool to overwrite actool's minimal output).
# actool only generates sizes it can derive from the single 1024×1024 asset catalog
# entry; our rsvg-convert path produces all ten canonical sizes from the source SVG.
if [ -f "${ICON_SRC}" ] && command -v rsvg-convert &>/dev/null && command -v iconutil &>/dev/null; then
    echo "Building AppIcon.icns from source SVG layers..."
    rm -rf "${ICONSET_DIR}"
    mkdir -p "${ICONSET_DIR}"

    _render_icon() {
        local name="$1" px="$2"
        rsvg-convert --width "${px}" --height "${px}" --keep-aspect-ratio \
            --output "${ICONSET_DIR}/${name}" "${ICON_SRC}"
        # Tag with sRGB colour profile so Finder renders colours correctly.
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
    # Fallback: use pre-built .icns if rsvg-convert / iconutil are unavailable.
    cp "${SCRIPT_DIR}/vmenu/AppIcon.icns" "${ICNS_OUT}"
    echo "Included app icon (.icns, pre-built fallback — install rsvg-convert for source-derived builds)."
else
    echo "Warning: AppIcon.icns not found and rsvg-convert unavailable. App will use default icon."
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
    # Use explicit identifier to match the Mach service name for XPC lookup
    echo "Signing helper with identifier ${HELPER_NAME}..."
    HELPER_PARENT_CONSTRAINT="${SCRIPT_DIR}/vmenuhelper/launch-constraint-parent.plist"
    if [ -f "${HELPER_PARENT_CONSTRAINT}" ]; then
        echo "  (applying parent launch constraint for macOS 26 compatibility)"
        codesign --force --options runtime \
            --identifier "${HELPER_NAME}" \
            --entitlements "${HELPER_ENTITLEMENTS}" \
            --launch-constraint-parent "${HELPER_PARENT_CONSTRAINT}" \
            --sign "${IDENTITY}" \
            --timestamp \
            "${APP_DIR}/Contents/MacOS/${HELPER_NAME}"
    else
        codesign --force --options runtime \
            --identifier "${HELPER_NAME}" \
            --entitlements "${HELPER_ENTITLEMENTS}" \
            --sign "${IDENTITY}" \
            --timestamp \
            "${APP_DIR}/Contents/MacOS/${HELPER_NAME}"
    fi

    # Sign main binary with explicit identifier
    echo "Signing main binary..."
    codesign --force --options runtime \
        --identifier "com.brianshumate.vmenu" \
        --entitlements "${ENTITLEMENTS}" \
        --sign "${IDENTITY}" \
        --timestamp \
        "${APP_DIR}/Contents/MacOS/${APP_NAME}"

    # Sign the bundle (don't use --deep to avoid re-signing nested components)
    echo "Signing bundle..."
    codesign --force --options runtime \
        --identifier "com.brianshumate.vmenu" \
        --entitlements "${ENTITLEMENTS}" \
        --sign "${IDENTITY}" \
        --timestamp \
        "${APP_DIR}"

    echo "Verifying signatures..."
    codesign --verify --deep --strict --verbose=2 "${APP_DIR}"
    echo "  Helper identifier: $(codesign -dv "${APP_DIR}/Contents/MacOS/${HELPER_NAME}" 2>&1 | grep 'Identifier=' | cut -d= -f2)"
    echo "  Main app identifier: $(codesign -dv "${APP_DIR}/Contents/MacOS/${APP_NAME}" 2>&1 | grep 'Identifier=' | cut -d= -f2)"
else
    # Ad-hoc sign for local use
    # On macOS 26 (Tahoe), launch constraints require:
    #   1. Explicit bundle identifier matching the Mach service name
    #   2. Entitlements applied even for ad-hoc signing
    #   3. The helper must be signed with its own identifier, not inherit from parent
    #   4. Do NOT use --deep on the bundle as it re-signs nested components with wrong identifiers

    echo "Signing helper with identifier ${HELPER_NAME}..."
    # On macOS 26 (Tahoe), ad-hoc signed helpers launched by launchd via SMAppService
    # must NOT have launch constraints applied - the constraints cause immediate
    # SIGKILL with "Launch Constraint Violation". Launch constraints are only
    # meaningful for Developer ID signed binaries.
    #
    # For ad-hoc signing, we rely on:
    # 1. The app being in /Applications (satisfies Gatekeeper path rules)
    # 2. The helper having the correct bundle identifier matching the Mach service
    # 3. SMAppService registering the helper with launchd properly
    codesign --force \
        --identifier "${HELPER_NAME}" \
        --entitlements "${HELPER_ENTITLEMENTS}" \
        --sign - \
        "${APP_DIR}/Contents/MacOS/${HELPER_NAME}"

    echo "Signing main app binary..."
    codesign --force \
        --identifier "com.brianshumate.vmenu" \
        --entitlements "${ENTITLEMENTS}" \
        --sign - \
        "${APP_DIR}/Contents/MacOS/${APP_NAME}"

    echo "Signing bundle (without re-signing nested components)..."
    # Sign the bundle itself - codesign will seal the already-signed nested components
    codesign --force \
        --identifier "com.brianshumate.vmenu" \
        --entitlements "${ENTITLEMENTS}" \
        --sign - \
        "${APP_DIR}"

    echo "Verifying signatures..."
    echo "  Helper identifier: $(codesign -dv "${APP_DIR}/Contents/MacOS/${HELPER_NAME}" 2>&1 | grep 'Identifier=' | cut -d= -f2)"
    echo "  Main app identifier: $(codesign -dv "${APP_DIR}/Contents/MacOS/${APP_NAME}" 2>&1 | grep 'Identifier=' | cut -d= -f2)"
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
