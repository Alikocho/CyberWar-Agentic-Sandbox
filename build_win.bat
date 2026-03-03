@echo off
:: ─────────────────────────────────────────────────────────────────────────────
:: CyberWar Sandbox — Windows Build Script
:: ─────────────────────────────────────────────────────────────────────────────
:: Requires: Python 3.10+  (must be on PATH, "Add to PATH" checked at install)
:: Usage:    Double-click build_win.bat
::
:: Output:
::   dist\CyberWarSandbox\CyberWarSandbox.exe   ← no console window
::   dist\CyberWarSandbox.zip                   ← ready to share
::
:: What the .exe does:
::   - Starts the web server silently in the background
::   - Opens your default browser automatically
::   - Shows a system-tray icon (right-click → Open / Quit)
:: ─────────────────────────────────────────────────────────────────────────────
setlocal enabledelayedexpansion
title CyberWar Sandbox — Windows Build
cd /d "%~dp0"

echo.
echo   ╔══════════════════════════════════════════╗
echo   ║  CyberWar Sandbox — Windows Build        ║
echo   ╚══════════════════════════════════════════╝
echo.

:: ── 1. Python check ──────────────────────────────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
  echo   ERROR: Python not found on PATH.
  echo   Download from https://python.org and check "Add Python to PATH".
  pause & exit /b 1
)
python --version
echo   Python found.

:: ── 2. Virtual environment ───────────────────────────────────────────────────
echo.
echo   ^→ Creating virtual environment in .venv-build ...
python -m venv .venv-build
call .venv-build\Scripts\activate.bat

:: ── 3. Dependencies ──────────────────────────────────────────────────────────
echo   ^→ Installing dependencies ...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

:: pystray + Pillow power the system-tray icon (no-console experience)
echo   ^→ Installing tray-icon dependencies (pystray, Pillow) ...
python -m pip install --quiet pystray pillow

:: ── 4. Clean previous build ──────────────────────────────────────────────────
if exist dist  rmdir /s /q dist
if exist build rmdir /s /q build
echo   Cleaned previous build artefacts.

:: ── 5. Run PyInstaller ───────────────────────────────────────────────────────
echo   ^→ Running PyInstaller (this takes a minute) ...
pyinstaller cyberwar.spec --noconfirm

:: ── 6. Zip with PowerShell ───────────────────────────────────────────────────
echo   ^→ Creating zip archive ...
powershell -NoProfile -Command ^
  "Compress-Archive -Path 'dist\CyberWarSandbox' -DestinationPath 'dist\CyberWarSandbox_Windows.zip' -Force"

:: ── 7. Done ──────────────────────────────────────────────────────────────────
echo.
echo   ╔════════════════════════════════════════════════════════════╗
echo   ║  Build complete!                                            ║
echo   ╠════════════════════════════════════════════════════════════╣
echo   ║  Exe  →  dist\CyberWarSandbox\CyberWarSandbox.exe          ║
echo   ║  Zip  →  dist\CyberWarSandbox_Windows.zip  (share / send)  ║
echo   ║                                                              ║
echo   ║  Double-click the .exe to launch.                          ║
echo   ║  Your browser opens automatically.                         ║
echo   ║  Look for the CyberWar icon in the system tray (^) to quit.║
echo   ╚════════════════════════════════════════════════════════════╝
echo.

call .venv-build\Scripts\deactivate.bat
pause
