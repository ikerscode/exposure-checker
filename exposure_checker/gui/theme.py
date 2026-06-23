"""
Gullwing design system — color tokens, type scale, font loading, helpers.

Usage:
    import exposure_checker.gui.theme as T

    T.load_fonts()           # call once after tk.Tk() is created
    bg = T.BG                # "#0B0E16"
    font = T.font_ui(10)     # ("Space Grotesk", 10)
    pill_bg = T.tint_hex(T.BG, T.SEV_CRITICAL, 0.13)
"""

from __future__ import annotations
import os
import sys

# ── Color tokens ───────────────────────────────────────────────────────────────

# Backgrounds
BG            = "#0B0E16"
SURFACE       = "#141A28"
SURFACE_RAISED = "#1D2538"

# Borders / dividers
BORDER        = "#2A3346"

# Text
TEXT          = "#E8EDF5"
TEXT_MUTED    = "#9AA6BC"
TEXT_DIM      = "#5E6B82"

# Brand
ACCENT        = "#F6A93B"   # gold
DATA          = "#37D4C3"   # teal

# Severity
SEV_CRITICAL  = "#F23645"
SEV_HIGH      = "#FF6B5C"
SEV_MEDIUM    = "#E8C547"
SEV_REVIEW    = "#4DA3FF"
SEV_INFO      = "#8B97AD"

# Status
OK            = "#3FB950"   # green
ERR           = "#F23645"

# ── Backward-compatible C dict (drop-in for the old inline dict) ───────────────

C: dict = {
    "bg":         BG,
    "panel":      SURFACE,
    "input":      SURFACE_RAISED,
    "border":     BORDER,
    "text":       TEXT,
    "muted":      TEXT_MUTED,
    "accent":     ACCENT,
    "accent2":    "#D4861A",  # darker gold for pressed state
    "neon":       DATA,       # teal replaces old purple in accent bar
    "CRITICAL":   SEV_CRITICAL,
    "HIGH":       SEV_HIGH,
    "MEDIUM":     SEV_MEDIUM,
    "REVIEW":     SEV_REVIEW,
    "INFO":       SEV_INFO,
    "ok":         OK,
    "err":        ERR,
    "cmd":        DATA,
    "hdr":        ACCENT,     # section-header label colour
    "hdr_bg":     BG,
    "log_bg":     "#070A12",
    "radar_bg":   "#030e0b",
    "radar_grid": "#081d15",
    "pill":       SURFACE,
    "scan_glow":  DATA,
}

# ── Type scale (4-px grid) ─────────────────────────────────────────────────────

# Font family names (resolved after load_fonts(); fall back to system fonts)
_UI_FAMILY   = "Space Grotesk"
_BODY_FAMILY = "IBM Plex Sans"
_MONO_FAMILY = "JetBrains Mono"
_SYSTEM      = "TkDefaultFont"
_SYSTEM_MONO = "TkFixedFont"

# Whether bundled fonts have been loaded successfully
_fonts_loaded: bool = False


def font_ui(size: int, weight: str = "normal") -> tuple:
    """Interface font — Space Grotesk → system fallback."""
    fam = _UI_FAMILY if _fonts_loaded else _SYSTEM
    return (fam, size, weight) if weight != "normal" else (fam, size)


def font_body(size: int) -> tuple:
    """Body / prose font — IBM Plex Sans → system fallback."""
    fam = _BODY_FAMILY if _fonts_loaded else _SYSTEM
    return (fam, size)


def font_mono(size: int) -> tuple:
    """Monospace font — JetBrains Mono → system fallback."""
    fam = _MONO_FAMILY if _fonts_loaded else _SYSTEM_MONO
    return (fam, size)


# ── Corner radius constants (px) ──────────────────────────────────────────────

RADIUS_PILL   = 6
RADIUS_BUTTON = 10
RADIUS_CARD   = 10
RADIUS_MODAL  = 16

# ── Helpers ────────────────────────────────────────────────────────────────────

def tint_hex(base: str, color: str, alpha: float) -> str:
    """Blend *color* over *base* at *alpha* (0–1). Returns a hex color string."""
    def _parse(h: str):
        h = h.lstrip("#")
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)

    br, bg, bb = _parse(base)
    cr, cg, cb = _parse(color)
    r = round(br * (1 - alpha) + cr * alpha)
    g = round(bg * (1 - alpha) + cg * alpha)
    b = round(bb * (1 - alpha) + cb * alpha)
    return f"#{r:02x}{g:02x}{b:02x}"


def round_rect(canvas, x1, y1, x2, y2, radius, **kwargs):
    """Draw a filled rounded rectangle on a Tkinter Canvas; return the item id.

    Implemented as a smoothed polygon: the corner points are listed three-per-
    corner and ``smooth=True`` rounds them into arcs. Accepts the usual
    create_polygon kwargs (``fill``, ``outline``, ``width``, ``tags``, …) so
    callers can pass e.g. ``fill=T.SURFACE, outline=T.BORDER``.
    """
    r = max(0, min(radius, (x2 - x1) / 2, (y2 - y1) / 2))
    points = [
        x1 + r, y1,
        x2 - r, y1,
        x2,     y1,
        x2,     y1 + r,
        x2,     y2 - r,
        x2,     y2,
        x2 - r, y2,
        x1 + r, y2,
        x1,     y2,
        x1,     y2 - r,
        x1,     y1 + r,
        x1,     y1,
    ]
    return canvas.create_polygon(points, smooth=True, **kwargs)


def _asset_path(rel: str) -> str:
    """Resolve a path relative to gui/assets/, PyInstaller-aware."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base = os.path.join(sys._MEIPASS, "exposure_checker", "gui", "assets")
    else:
        base = os.path.join(os.path.dirname(__file__), "assets")
    return os.path.join(base, rel)


# ── Font loading ───────────────────────────────────────────────────────────────

def load_fonts() -> None:
    """Load bundled OFL fonts via customtkinter.FontManager.

    Silently degrades to system fonts when:
    - customtkinter is not installed
    - font files are missing (frozen build without updated datas)
    - the platform's font subsystem rejects the font (e.g. some macOS builds)
    """
    global _fonts_loaded
    if _fonts_loaded:
        return

    font_files = [
        "fonts/SpaceGrotesk-Regular.ttf",
        "fonts/SpaceGrotesk-Bold.ttf",
        "fonts/JetBrainsMono-Regular.ttf",
        "fonts/IBMPlexSans-Regular.ttf",
    ]

    try:
        import customtkinter as ctk
    except ImportError:
        return

    any_loaded = False
    for rel in font_files:
        path = _asset_path(rel)
        if not os.path.isfile(path):
            continue
        try:
            ok = ctk.FontManager.load_font(path)
            if ok:
                any_loaded = True
        except Exception:
            pass

    if any_loaded:
        _fonts_loaded = True
