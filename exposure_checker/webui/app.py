#!/usr/bin/env python3
"""Gullwing — HUD (webview front-end).

    gullwing-hud                              # installed entry point
    python -m exposure_checker.webui.app      # from the repo root

Loads the local HUD (HTML/CSS/JS) in a pywebview window backed by Qt WebEngine
and exposes Gullwing's real logic through :class:`exposure_checker.webui.bridge.Bridge`.
No network, no telemetry — the page is served from disk under a strict CSP and
pywebview makes no outbound calls of its own.

The classic Tkinter UI (``gullwing-ui``) is untouched and remains available.
"""

import os
import platform
import shutil
import subprocess
import sys

import exposure_checker as ec

_OS = platform.system()  # "Linux" | "Darwin" | "Windows"


def _asset(rel: str) -> str:
    """Resolve a path under webui/assets/, PyInstaller-aware."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base = os.path.join(sys._MEIPASS, "exposure_checker", "webui", "assets")
    else:
        base = os.path.join(os.path.dirname(__file__), "assets")
    return os.path.join(base, rel)


def _ensure_admin() -> None:
    """Best-effort elevation at launch on Windows/macOS.

    Mirrors the Tkinter app's behaviour so admin-only scans see what they need.
    Linux scans run fine as a regular user and fixes self-elevate via pkexec, so
    Linux is left alone. If elevation is declined we proceed anyway — individual
    fixes still prompt for elevation per batch — rather than blocking the user.
    """
    try:
        from exposure_checker._elevate import _is_root
        if _is_root():
            return
    except Exception:
        return

    if _OS == "Windows":
        try:
            import ctypes
            if getattr(sys, "frozen", False):
                exe, params = sys.argv[0], " ".join(f'"{a}"' for a in sys.argv[1:])
            else:
                exe, params = sys.executable, " ".join(f'"{a}"' for a in sys.argv)
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            if ret > 32:
                sys.exit(0)
        except Exception:
            pass
    elif _OS == "Darwin":
        try:
            import shlex
            if getattr(sys, "frozen", False):
                safe = " ".join(shlex.quote(a) for a in sys.argv)
            else:
                safe = shlex.quote(sys.executable) + " " + " ".join(shlex.quote(a) for a in sys.argv)
            script = f'do shell script "{safe} &" with administrator privileges'
            r = subprocess.run(["osascript", "-e", script], capture_output=True)
            if r.returncode == 0:
                sys.exit(0)
        except Exception:
            pass
    # Either elevation isn't available or the user declined — continue unelevated.


def main():
    if "--smoke" in sys.argv:
        import webview                                          # noqa: F401
        import qtpy                                             # noqa: F401
        # Importing the WebEngine modules proves PyInstaller bundled the Qt
        # WebEngine runtime — without this, a frozen build missing WebEngine
        # would still pass a plain import check but fail to open a window.
        from PySide6 import QtWebEngineWidgets, QtWebEngineCore  # noqa: F401
        from exposure_checker.webui.bridge import Bridge        # noqa: F401
        from exposure_checker import _elevate, _session, _notify, _report  # noqa: F401
        Bridge()  # construct it — exercises psutil priming + imports
        print(f"gullwing-hud {ec.__version__} smoke ok")
        raise SystemExit(0)

    # When re-invoked with a CLI subcommand (e.g. by a scheduled scan), defer to
    # the scanner's command-line handler instead of opening the window.
    _CLI = {"headless", "schedule", "diff", "remediate"}
    argv = sys.argv[1:]
    if argv and (argv[0] in _CLI or argv[0].startswith("-")):
        ec.main()
        return

    if _OS != "Linux":
        _ensure_admin()

    # QtWebEngine's sandbox needs a setuid helper that isn't present in many
    # packaged / containerised Linux environments; disabling it keeps rendering
    # working. The renderer still loads only local files under the page CSP.
    os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")

    import webview
    from exposure_checker.webui.bridge import Bridge

    bridge = Bridge()
    webview.create_window(
        "Gullwing",
        url=_asset("index.html"),
        js_api=bridge,
        width=1280, height=820, min_size=(1024, 680),
        background_color="#03070A",
        text_select=False,
    )
    # gui='qt' selects the PySide6/QtWebEngine backend (pip-installable on all
    # three platforms, so no end-user system packages are required).
    webview.start(gui="qt")


if __name__ == "__main__":
    main()
