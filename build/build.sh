#!/bin/bash
# Build SSO Watcher.dmg containing SSO Watcher.app + Install ChmodBPF.pkg.
#
# Prerequisites:
#   - Xcode Command Line Tools (`xcode-select --install`)
#   - A python venv at .venv (start.command bootstraps it)
#
# Optional signing (for shipping to real users):
#   DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)" \
#   DEVELOPER_ID_INSTALLER="Developer ID Installer: Your Name (TEAMID)" \
#     ./build/build.sh

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)

VENV_PY="$ROOT/.venv/bin/python3"
VENV_PIP="$ROOT/.venv/bin/pip"

[ -x "$VENV_PY" ] || { echo "!! no .venv here — run start.command once to bootstrap it"; exit 1; }

echo ">>> Installing py2app in venv (if needed)..."
"$VENV_PIP" install -q py2app

echo ">>> Cleaning old build artifacts..."
rm -rf build/build build/dist dist
rm -rf "$ROOT/build/pkgroot" "$ROOT/build/pkgscripts" "$ROOT/build/dmgroot"
mkdir -p dist

echo ">>> Building SSO Watcher.app with py2app..."
(cd build && "$VENV_PY" setup.py py2app --dist-dir "$ROOT/dist" --bdist-base "$ROOT/build/build")

APP="$ROOT/dist/SSO Watcher.app"
[ -d "$APP" ] || { echo "!! .app not produced — check py2app output above"; exit 1; }

echo ">>> Signing SSO Watcher.app..."
if [ -n "${DEVELOPER_ID:-}" ]; then
    codesign --deep --force --sign "$DEVELOPER_ID" --options runtime "$APP"
    echo "   signed with $DEVELOPER_ID"
else
    codesign --deep --force --sign - "$APP"
    echo "   ad-hoc signed (Gatekeeper warns on first launch until you set DEVELOPER_ID)"
fi

echo ">>> Assembling Install ChmodBPF.pkg..."
PKGROOT="build/pkgroot"
PKGSCR="build/pkgscripts"
rm -rf "$PKGROOT" "$PKGSCR"

mkdir -p "$PKGROOT/Library/LaunchDaemons"
mkdir -p "$PKGROOT/Library/Application Support/SSO Watcher/ChmodBPF"
cp build/chmodbpf/org.sso-watcher.ChmodBPF.plist "$PKGROOT/Library/LaunchDaemons/"
cp build/chmodbpf/ChmodBPF                        "$PKGROOT/Library/Application Support/SSO Watcher/ChmodBPF/"
chmod +x "$PKGROOT/Library/Application Support/SSO Watcher/ChmodBPF/ChmodBPF"

mkdir -p "$PKGSCR"
cp build/chmodbpf/postinstall "$PKGSCR/postinstall"
chmod +x "$PKGSCR/postinstall"

pkgbuild \
    --root "$PKGROOT" \
    --scripts "$PKGSCR" \
    --identifier "com.sso-watcher.ChmodBPF.pkg" \
    --version "0.1.0" \
    --install-location "/" \
    "dist/Install ChmodBPF.pkg"

if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
    echo ">>> Signing pkg with $DEVELOPER_ID_INSTALLER"
    productsign --sign "$DEVELOPER_ID_INSTALLER" \
        "dist/Install ChmodBPF.pkg" "dist/Install ChmodBPF-signed.pkg"
    mv "dist/Install ChmodBPF-signed.pkg" "dist/Install ChmodBPF.pkg"
fi

echo ">>> Assembling SSO Watcher.dmg..."
DMGROOT="build/dmgroot"
rm -rf "$DMGROOT"
mkdir -p "$DMGROOT"
cp -R "$APP"                       "$DMGROOT/"
cp    "dist/Install ChmodBPF.pkg"  "$DMGROOT/"
ln -s /Applications                 "$DMGROOT/Applications"

hdiutil create -ov -format UDZO \
    -volname "SSO Watcher" \
    -srcfolder "$DMGROOT" \
    "dist/SSO Watcher.dmg"

echo ""
echo "==============================================="
echo "  Built:  dist/SSO Watcher.dmg"
echo "==============================================="
echo ""
echo "First-time install on a Mac:"
echo "  1. Double-click SSO Watcher.dmg"
echo "  2. Double-click 'Install ChmodBPF.pkg' — needs admin password"
echo "  3. Drag SSO Watcher.app to Applications"
echo "  4. Log out and back in (so group membership takes effect)"
echo "  5. Launch from Applications — no password prompt this time"
echo ""
