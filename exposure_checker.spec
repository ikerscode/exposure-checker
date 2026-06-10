# PyInstaller spec — builds the Exposure Checker desktop app.
# Usage:  pyinstaller exposure_checker.spec
#
# Outputs (in dist/):
#   macOS   →  "Exposure Checker.app"  (then packaged as .dmg by CI)
#   Windows →  "Exposure Checker.exe"
#   Linux   →  "exposure-checker"
import sys

block_cipher = None

a = Analysis(
    ["exposure_checker_ui.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        "cryptography",
        "cryptography.hazmat.backends",
        "cryptography.hazmat.backends.openssl",
        "cryptography.x509",
        "tkinter",
        "tkinter.ttk",
        "tkinter.filedialog",
        "tkinter.messagebox",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
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
    name="Exposure Checker" if sys.platform != "linux" else "exposure-checker",
    debug=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    console=False,      # no terminal window — GUI only
    argv_emulation=False,
)

# macOS: wrap the executable in a proper .app bundle
if sys.platform == "darwin":
    app = BUNDLE(
        exe,
        name="Exposure Checker.app",
        bundle_identifier="com.exposurechecker.app",
        info_plist={
            "CFBundleName":               "Exposure Checker",
            "CFBundleDisplayName":        "Exposure Checker",
            "CFBundleShortVersionString": "1.0.0",
            "NSHighResolutionCapable":    True,
            "NSRequiresAquaSystemAppearance": False,  # allow dark mode
        },
    )
