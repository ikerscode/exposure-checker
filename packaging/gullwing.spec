# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Gullwing desktop app.
# Run from the repo root:  pyinstaller packaging/gullwing.spec

import os
import sys
from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT, BUNDLE

# This spec lives in packaging/ — resolve paths from the repo root so it works
# no matter what the current working directory is.
ROOT = os.path.dirname(os.path.abspath(SPECPATH))

# Single source of truth for the version: read it textually from _core.py so the
# bundle metadata can't drift from exposure_checker.__version__. Read, don't
# import, to avoid import side effects at spec-exec time.
import re
with open(os.path.join(ROOT, 'exposure_checker', '_core.py')) as _vf:
    _VERSION = re.search(r'__version__\s*=\s*["\']([^"\']+)', _vf.read()).group(1)

_ASSETS_SRC = os.path.join(ROOT, 'exposure_checker', 'gui', 'assets')
_ASSETS_DEST = os.path.join('exposure_checker', 'gui', 'assets')

_ICO_PATH  = os.path.join(_ASSETS_SRC, 'icons', 'icon.ico')
_ICNS_PATH = os.path.join(_ASSETS_SRC, 'icons', 'icon.icns')

a = Analysis(
    [os.path.join(ROOT, 'exposure_checker', 'gui', 'app.py')],
    pathex=[ROOT],
    binaries=[],
    datas=[
        (_ASSETS_SRC, _ASSETS_DEST),
    ],
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
        'exposure_checker.gui',
        'exposure_checker.gui.app',
        'exposure_checker.gui.splash',
        'pygame',
        'numpy',
        'customtkinter',
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        'PIL.ImageDraw',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

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
    icon=_ICO_PATH if os.path.isfile(_ICO_PATH) else None,
)

# macOS .app bundle
app = BUNDLE(
    exe,
    name='Gullwing.app',
    icon=_ICNS_PATH if os.path.isfile(_ICNS_PATH) else None,
    bundle_identifier='com.gullwing.app',
    info_plist={
        'CFBundleShortVersionString': _VERSION,
        'CFBundleVersion': _VERSION,
        'NSHighResolutionCapable': True,
        'NSRequiresAquaSystemAppearance': False,
    },
)
