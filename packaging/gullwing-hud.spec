# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the Gullwing HUD (webview UI).
# Run from the repo root:  pyinstaller packaging/gullwing-hud.spec
#
# Produces a single "Gullwing" executable that opens the HUD in a Qt WebEngine
# window. Qt is bundled (PySide6) so end users need no system packages.

import os
import re
from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT, BUNDLE
from PyInstaller.utils.hooks import collect_all

ROOT = os.path.dirname(os.path.abspath(SPECPATH))

# Single source of truth for the version (read, don't import).
with open(os.path.join(ROOT, 'exposure_checker', '_core.py')) as _vf:
    _VERSION = re.search(r'__version__\s*=\s*["\']([^"\']+)', _vf.read()).group(1)

_WEBUI_SRC  = os.path.join(ROOT, 'exposure_checker', 'webui', 'assets')
_WEBUI_DEST = os.path.join('exposure_checker', 'webui', 'assets')
_ICO_PATH   = os.path.join(ROOT, 'exposure_checker', 'gui', 'assets', 'icons', 'icon.ico')
_ICNS_PATH  = os.path.join(ROOT, 'exposure_checker', 'gui', 'assets', 'icons', 'icon.icns')

datas = [(_WEBUI_SRC, _WEBUI_DEST)]
binaries = []
hiddenimports = [
    'exposure_checker', 'exposure_checker._core', 'exposure_checker._cli',
    'exposure_checker._notify', 'exposure_checker._remediate', 'exposure_checker._report',
    'exposure_checker._schedule', 'exposure_checker._storage', 'exposure_checker._elevate',
    'exposure_checker._session',
    'exposure_checker.webui', 'exposure_checker.webui.app', 'exposure_checker.webui.bridge',
    'exposure_checker.checks.security', 'exposure_checker.checks.performance',
    'exposure_checker.checks.cleaner', 'exposure_checker.checks.portscan',
    'exposure_checker.checks.benchmark', 'exposure_checker.checks.overclock',
    'cryptography', 'psutil',
    # Qt WebEngine backend — the hooks-contrib PySide6 hook bundles the WebEngine
    # runtime (QtWebEngineProcess, resources, locales) when these are imported.
    'PySide6.QtCore', 'PySide6.QtGui', 'PySide6.QtWidgets',
    'PySide6.QtWebEngineWidgets', 'PySide6.QtWebEngineCore', 'PySide6.QtWebChannel',
    'PySide6.QtNetwork', 'PySide6.QtPrintSupport',
]

# pywebview ships JS shims + a qt platform module; qtpy is its Qt abstraction.
for _pkg in ('webview', 'qtpy'):
    _d, _b, _h = collect_all(_pkg)
    datas += _d; binaries += _b; hiddenimports += _h

a = Analysis(
    [os.path.join(ROOT, 'exposure_checker', 'webui', 'app.py')],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Trim modules the HUD never uses (the classic Tkinter UI, the pygame splash,
    # and unused Qt modules) to keep the already-large WebEngine bundle down.
    excludes=['tkinter', 'customtkinter', 'pygame', 'numpy', 'PIL',
              'PyQt5', 'PyQt6',
              'PySide6.Qt3DCore', 'PySide6.QtQuick3D', 'PySide6.QtMultimedia',
              'PySide6.QtCharts', 'PySide6.QtDataVisualization', 'PySide6.QtSql'],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

_CODESIGN_IDENTITY = os.environ.get('GULLWING_CODESIGN_IDENTITY') or None
_ENTITLEMENTS = os.environ.get('GULLWING_ENTITLEMENTS') or None

# onedir mode (COLLECT below): the reliable layout for Qt WebEngine across all
# three platforms — the WebEngine helper process, resources and locales sit next
# to the executable instead of being unpacked from a single file at runtime
# (onefile breaks WebEngine's helper lookup and macOS notarization).
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Gullwing',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                       # UPX corrupts Qt's WebEngine binaries
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=_CODESIGN_IDENTITY,
    entitlements_file=_ENTITLEMENTS,
    icon=_ICO_PATH if os.path.isfile(_ICO_PATH) else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='Gullwing',
)

# macOS .app bundle (wraps the onedir tree)
app = BUNDLE(
    coll,
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
