#!/bin/bash
# Build vmenu.app bundle with proper icon
set -euo pipefail

CONFIGURATION="${1:-release}"
APP_NAME="vmenu"
APP_BUNDLE="${APP_NAME}.app"

echo "Building ${APP_NAME} (${CONFIGURATION})..."
swift build -c "${CONFIGURATION}"

BIN_PATH=$(swift build -c "${CONFIGURATION}" --show-bin-path)
BINARY="${BIN_PATH}/${APP_NAME}"

if [ ! -f "${BINARY}" ]; then
    echo "Error: Binary not found at ${BINARY}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${SCRIPT_DIR}/${APP_BUNDLE}"

echo "Creating ${APP_BUNDLE}..."
rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS"
mkdir -p "${APP_DIR}/Contents/Resources"

# Copy binary
cp "${BINARY}" "${APP_DIR}/Contents/MacOS/${APP_NAME}"

# Copy Info.plist
cp "${SCRIPT_DIR}/vmenu/Info.plist" "${APP_DIR}/Contents/Info.plist"

# Copy icon
if [ -f "${SCRIPT_DIR}/vmenu/AppIcon.icns" ]; then
    cp "${SCRIPT_DIR}/vmenu/AppIcon.icns" "${APP_DIR}/Contents/Resources/AppIcon.icns"
    echo "Included app icon."
else
    echo "Warning: AppIcon.icns not found, app will use default icon."
fi

echo ""
echo "Built: ${APP_DIR}"
echo ""
echo "To install, copy to /Applications:"
echo "  cp -r ${APP_BUNDLE} /Applications/"
