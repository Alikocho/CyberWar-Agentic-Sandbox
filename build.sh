#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberWar Sandbox — Mac / Linux Build Script
# ─────────────────────────────────────────────────────────────────────────────
# Requires: Python 3.10+
# Usage:    bash build.sh
#
# Output (macOS):
#   dist/CyberWarSandbox.app          ← double-click to run, no terminal needed
#   dist/CyberWarSandbox.app.zip      ← ready to share / AirDrop
#
# Output (Linux):
#   dist/CyberWarSandbox/             ← run ./dist/CyberWarSandbox/CyberWarSandbox
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/.venv-build"
DIST_DIR="$PROJECT_DIR/dist"
IS_MAC=false
[[ "$(uname -s)" == "Darwin" ]] && IS_MAC=true

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   CyberWar Sandbox — Build               ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# ── 1. Python check ──────────────────────────────────────────────────────────
PY=$(command -v python3 || command -v python || true)
if [[ -z "$PY" ]]; then
  echo "❌  Python 3 not found. Install from https://python.org" && exit 1
fi
PY_VER=$("$PY" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "  ✓ Python $PY_VER  →  $PY"

# ── 2. Tkinter check (macOS) ─────────────────────────────────────────────────
if $IS_MAC; then
  if ! "$PY" -c "import tkinter" 2>/dev/null; then
    echo ""
    echo "  ⚠  Tkinter not found. The launcher window won't appear,"
    echo "     but the browser will still open automatically."
    echo "     To fix: install Python from python.org (includes Tkinter),"
    echo "     or via Homebrew:  brew install python-tk"
    echo ""
  else
    echo "  ✓ Tkinter available"
  fi
fi

# ── 3. Virtual environment ───────────────────────────────────────────────────
echo "  → Creating virtual environment ..."
"$PY" -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "  → Installing dependencies ..."
pip install --quiet --upgrade pip
pip install --quiet -r "$PROJECT_DIR/requirements.txt"

# ── 4. Clean previous build ──────────────────────────────────────────────────
rm -rf "$DIST_DIR" "$PROJECT_DIR/build"
echo "  ✓ Cleaned previous build artefacts"

# ── 5. Run PyInstaller ───────────────────────────────────────────────────────
echo "  → Running PyInstaller ..."
cd "$PROJECT_DIR"
pyinstaller cyberwar.spec --noconfirm

# ── 6. Post-process & package ────────────────────────────────────────────────
if $IS_MAC; then
  APP="$DIST_DIR/CyberWarSandbox.app"
  ZIP="$DIST_DIR/CyberWarSandbox.zip"

  # Remove quarantine flag so macOS doesn't block the unsigned app
  xattr -cr "$APP" 2>/dev/null || true

  echo "  → Creating zip for distribution ..."
  cd "$DIST_DIR"
  zip -r CyberWarSandbox.zip CyberWarSandbox.app -x "*.DS_Store"

  echo ""
  echo "  ╔════════════════════════════════════════════════════════╗"
  echo "  ║  ✅  macOS build complete!                             ║"
  echo "  ╠════════════════════════════════════════════════════════╣"
  echo "  ║  App  →  dist/CyberWarSandbox.app                     ║"
  echo "  ║  Zip  →  dist/CyberWarSandbox.zip  (share / AirDrop)  ║"
  echo "  ║                                                          ║"
  echo "  ║  Double-click the .app to launch.                      ║"
  echo "  ║  Your browser will open automatically.                 ║"
  echo "  ║                                                          ║"
  echo "  ║  First launch:  right-click → Open  (Gatekeeper)       ║"
  echo "  ╚════════════════════════════════════════════════════════╝"
else
  echo ""
  echo "  ╔════════════════════════════════════════════════════╗"
  echo "  ║  ✅  Linux build complete!                         ║"
  echo "  ╠════════════════════════════════════════════════════╣"
  echo "  ║  Run:  ./dist/CyberWarSandbox/CyberWarSandbox      ║"
  echo "  ║  Then open: http://localhost:5000                  ║"
  echo "  ╚════════════════════════════════════════════════════╝"
fi
echo ""

deactivate
