# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Gullwing desktop app.
# Run from the repo root:  pyinstaller packaging/gullwing.spec

import os
import sys
from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT, BUNDLE

block_cipher = None

# This spec lives in packaging/ — resolve paths from the repo root so it works
# no matter what the current working directory is.
ROOT = os.path.dirname(os.path.abspath(SPECPATH))

a = Analysis(
    [os.path.join(ROOT, 'gullwing_ui.py')],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=[
        'exposure_checker',
        'exposure_checker._core',
        'exposure_checker._cli',
        'exposure_checker._notify',
        'exposure_checker._remediate',
        'exposure_checker._report',
        'exposure_checker._schedule',
        'exposure_checker._storage',
        'exposure_checker.checks.security',
        'exposure_checker.checks.performance',
        'exposure_checker.checks.cleaner',
        'exposure_checker.checks.portscan',
        'exposure_checker.checks.benchmark',
        'exposure_checker.checks.overclock',
        'tkinter',
        'tkinter.ttk',
        'cryptography',
        'gullwing_splash',
        'pygame',
        'numpy',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Gullwing',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# macOS .app bundle
app = BUNDLE(
    exe,
    name='Gullwing.app',
    icon=None,
    bundle_identifier='com.gullwing.app',
    info_plist={
        'CFBundleShortVersionString': '1.0.8',
        'CFBundleVersion': '1.0.8',
        'NSHighResolutionCapable': True,
        'NSRequiresAquaSystemAppearance': False,
    },
)
