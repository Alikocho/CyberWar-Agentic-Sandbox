# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for CyberWar Sandbox
#
# Mac:     dist/CyberWarSandbox.app  — double-click, no terminal, Tkinter status window
# Windows: dist/CyberWarSandbox/CyberWarSandbox.exe  — no console, system-tray icon
#
# Build:
#   Mac / Linux:  bash build.sh
#   Windows:      build_win.bat

import sys
from pathlib import Path

HERE   = Path(SPECPATH)
IS_MAC = sys.platform == 'darwin'
IS_WIN = sys.platform == 'win32'

block_cipher = None

# Choose the right launcher per platform
if IS_MAC:
    ENTRY = str(HERE / 'launcher.py')
elif IS_WIN:
    ENTRY = str(HERE / 'launcher_win.py')
else:
    ENTRY = str(HERE / 'app.py')      # Linux: plain Flask server

a = Analysis(
    [ENTRY],
    pathex=[str(HERE)],
    binaries=[],
    datas=[
        (str(HERE / 'templates'),                 'templates'),
        (str(HERE / 'cyberwar_ui_template.html'),  '.'),
        (str(HERE / 'env'),                        'env'),
        (str(HERE / 'engine'),                     'engine'),
        (str(HERE / 'agents'),                     'agents'),
        (str(HERE / 'scenarios'),                  'scenarios'),
        (str(HERE / 'rl'),                         'rl'),
    ],
    hiddenimports=[
        'flask',
        'flask.templating',
        'jinja2',
        'jinja2.ext',
        'werkzeug',
        'werkzeug.serving',
        'werkzeug.debug',
        # Project packages
        'env',
        'env.network',
        'env.actions',
        'env.observation',
        'engine',
        'engine.engine',
        'agents',
        'agents.agents',
        'agents.claude_agent',
        'agents.human_agent',
        'scenarios',
        'scenarios.scenarios',
        'rl',
        'rl.ppo_agent',
        # GUI / tray
        'tkinter',
        'tkinter.font',
        'pystray',
        'PIL',
        'PIL.Image',
        'PIL.ImageDraw',
        # Stdlib
        'webbrowser',
        'threading',
        'socket',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['matplotlib', 'cv2', 'PyQt5', 'wx'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='CyberWarSandbox',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    # windowed=True → no black console window on Windows/Mac
    console=False,
    icon=str(HERE / 'icon.ico') if (IS_WIN and (HERE / 'icon.ico').exists()) else str(HERE / 'icon.icns') if (IS_MAC and (HERE / 'icon.icns').exists()) else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='CyberWarSandbox',
)

# ── Mac only: wrap into a proper .app bundle ─────────────────────────────────
if IS_MAC:
    app = BUNDLE(
        coll,
        name='CyberWarSandbox.app',
        icon=str(HERE / 'icon.icns') if (HERE / 'icon.icns').exists() else None,
        bundle_identifier='com.cyberwar.sandbox',
        info_plist={
            'CFBundleName':               'CyberWar Sandbox',
            'CFBundleDisplayName':        'CyberWar Sandbox',
            'CFBundleVersion':            '1.0.0',
            'CFBundleShortVersionString': '1.0',
            'CFBundleIdentifier':         'com.cyberwar.sandbox',
            'LSUIElement':                False,
            'NSHighResolutionCapable':    True,
            'NSRequiresAquaSystemAppearance': False,
        },
    )
