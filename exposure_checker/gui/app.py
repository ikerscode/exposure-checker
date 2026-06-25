#!/usr/bin/env python3
"""
Gullwing — desktop interface.

    gullwing-ui                          # installed entry point
    python -m exposure_checker.gui.app   # from the repo root
"""
import datetime
import json
import math
import os
import platform
import queue
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser

_UI_OS = platform.system()  # "Linux" | "Darwin" | "Windows"

import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, ttk

import exposure_checker as ec
from exposure_checker.gui import theme as T


def _sev_pill(parent, text, bg, fg):
    """A small rounded severity badge (Canvas) — the rounded replacement for the
    rectangular padded Label. Returns the Canvas; caller packs it. Colors are
    passed through unchanged; the text is rendered uppercase."""
    text = str(text).upper()
    pad_x, pad_y = 7, 3
    fnt = tkfont.Font(font=T.font_ui(7, "bold"))
    w = fnt.measure(text) + 2 * pad_x
    h = fnt.metrics("linespace") + 2 * pad_y
    cv = tk.Canvas(parent, width=w, height=h, bg=parent["bg"],
                   highlightthickness=0, bd=0)
    T.round_rect(cv, 0, 0, w, h, radius=T.RADIUS_PILL, fill=bg, outline="")
    cv.create_text(w / 2, h / 2, text=text, fill=fg,
                   font=T.font_ui(7, "bold"), anchor="center")
    return cv


class RoundButton(tk.Canvas):
    """A rounded-rect button drawn on a Canvas, with hover and disabled states.

    Intentionally accepts the ttk-style ``configure(state=…, text=…, style=…)``
    calls the app already makes on its hero buttons, so existing call sites work
    unchanged (``style`` is ignored; ``state``/``text`` drive a redraw)."""

    def __init__(self, parent, text="", command=None, bg=None, fg="#060a0f",
                 hover=None, font=None, padx=20, pady=9, state=tk.NORMAL, **kw):
        self._text    = text
        self._command = command
        self._bg      = bg or C["accent"]
        self._fg      = fg
        self._hover   = hover or T.tint_hex(self._bg, "#ffffff", 0.14)
        self._font    = font or T.font_ui(10, "bold")
        self._enabled = (str(state) == str(tk.NORMAL))
        self._hovering = False
        try:
            cbg = parent["bg"]
        except tk.TclError:
            cbg = C["bg"]
        fnt = tkfont.Font(font=self._font)
        w = fnt.measure(text or "M") + 2 * padx
        h = fnt.metrics("linespace") + 2 * pady
        super().__init__(parent, width=w, height=h, bg=cbg,
                         highlightthickness=0, bd=0, **kw)
        self.bind("<Configure>", lambda _e: self._redraw())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self._redraw()

    def _fill(self):
        if not self._enabled:
            return C["input"]
        return self._hover if self._hovering else self._bg

    def _redraw(self):
        self.delete("all")
        w = self.winfo_width() or int(self["width"])
        h = self.winfo_height() or int(self["height"])
        T.round_rect(self, 1, 1, w - 1, h - 1, radius=T.RADIUS_BUTTON,
                     fill=self._fill(), outline="")
        self.create_text(w / 2, h / 2, text=self._text,
                         fill=self._fg if self._enabled else C["muted"],
                         font=self._font, anchor="center")
        super().configure(cursor="hand2" if self._enabled else "")

    def _on_enter(self, _e):
        self._hovering = True
        if self._enabled:
            self._redraw()

    def _on_leave(self, _e):
        self._hovering = False
        if self._enabled:
            self._redraw()

    def _on_click(self, _e):
        if self._enabled and self._command:
            self._command()

    def configure(self, cnf=None, **kw):
        redraw = False
        if "state" in kw:
            self._enabled = (str(kw.pop("state")) == str(tk.NORMAL))
            redraw = True
        if "text" in kw:
            self._text = kw.pop("text")
            redraw = True
        kw.pop("style", None)   # RoundButton carries its own colors
        result = super().configure(cnf, **kw) if (cnf is not None or kw) else None
        if redraw:
            self._redraw()
        return result

    config = configure


def _enable_windows_dpi_awareness():
    """Tell Windows this process is DPI-aware so Tk renders crisp on HiDPI /
    scaled displays instead of being bitmap-stretched (blurry)."""
    if _UI_OS != "Windows":
        return
    try:
        import ctypes
        # PER_MONITOR_AWARE_V2 (-4); falls back to system-DPI aware on older OS.
        try:
            ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        except (AttributeError, OSError):
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PER_MONITOR
            except (AttributeError, OSError):
                ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


_enable_windows_dpi_awareness()

# ── Palette (design system) ───────────────────────────────────────────────────

C = T.C

_SEV_ORDER   = ["CRITICAL", "HIGH", "MEDIUM", "REVIEW", "INFO"]
_GRADE_COLOR = {
    "A": T.OK,         "B": T.DATA,
    "C": T.SEV_MEDIUM, "D": T.SEV_HIGH, "F": T.SEV_CRITICAL, "—": T.TEXT_DIM,
}
_GRADE_LABEL = {
    "A": "EXCELLENT", "B": "GOOD",
    "C": "FAIR",      "D": "POOR", "F": "CRITICAL",
}


def _ago(ts: float) -> str:
    diff = (datetime.datetime.now() - datetime.datetime.fromtimestamp(ts)).total_seconds()
    if diff < 120:   return "just now"
    if diff < 3600:  return f"{int(diff / 60)}m ago"
    if diff < 86400: return f"{int(diff / 3600)}h ago"
    return f"{int(diff / 86400)}d ago"


# ── TTK dark theme ─────────────────────────────────────────────────────────────

def _configure_style(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    bg, panel, border, text, muted, accent, inp = (
        C["bg"], C["panel"], C["border"], C["text"],
        C["muted"], C["accent"], C["input"],
    )
    s.configure(".", background=bg, foreground=text, bordercolor=border,
                 focuscolor=accent, insertcolor=text,
                 selectbackground="#1f3a5c", selectforeground=text)

    s.configure("TButton", background=inp, foreground=text,
                 bordercolor=border, padding=(12, 6), relief="flat",
                 font=T.font_ui(9))
    s.map("TButton",
          background=[("active", "#2d333b"), ("pressed", border)],
          relief=[("pressed", "flat"), ("active", "flat")])
    # Drop clam's dotted focus ring (the Button.focus element) for all *.TButton
    # variants — derived styles inherit this layout.
    s.layout("TButton", [
        ("Button.border", {"sticky": "nswe", "border": "1", "children": [
            ("Button.padding", {"sticky": "nswe", "children": [
                ("Button.label", {"sticky": "nswe"})
            ]})
        ]})
    ])

    s.configure("Accent.TButton", background=accent, foreground="#060a0f",
                 bordercolor=accent, font=T.font_ui(10, "bold"),
                 padding=(20, 8))
    s.map("Accent.TButton",
          background=[("active", "#0099b8"), ("pressed", "#0077a8")],
          foreground=[("active", "#060a0f")])

    s.configure("Fix.TButton", background="#1e3a28", foreground="#3fb950",
                 bordercolor="#2ea043", padding=(14, 6),
                 font=T.font_ui(9, "bold"))
    s.map("Fix.TButton",
          background=[("active", "#2a4d36"), ("pressed", "#1a3020"),
                      ("disabled", "#111a14")],
          foreground=[("disabled", "#2a4830")],
          bordercolor=[("active", "#3fb950"), ("disabled", "#1e2e21")])

    s.configure("Dim.TButton", background=panel, foreground=muted,
                 bordercolor=border, padding=(12, 6))
    s.map("Dim.TButton",
          background=[("active", inp), ("disabled", panel)],
          foreground=[("disabled", C["INFO"])])

    s.configure("Revert.TButton", background="#2d1a10", foreground="#e3733a",
                 bordercolor="#6a3820", padding=(14, 6),
                 font=T.font_ui(9, "bold"))
    s.map("Revert.TButton",
          background=[("active", "#3d2518"), ("disabled", "#1a1008")],
          foreground=[("disabled", "#4a2818")],
          bordercolor=[("disabled", "#3a2010")])

    s.configure("Treeview", background=panel, foreground=text,
                 fieldbackground=panel, bordercolor=border, rowheight=30)
    s.configure("Treeview.Heading", background=C["input"], foreground=muted,
                 bordercolor=border, font=T.font_ui(9, "bold"),
                 padding=(8, 8))
    s.map("Treeview",
          background=[("selected", "#1f3a5c")],
          foreground=[("selected", text)])

    s.configure("TEntry", fieldbackground=inp, foreground=text,
                 bordercolor=border, padding=7)
    s.map("TEntry", bordercolor=[("focus", accent)])

    s.configure("TFrame",       background=bg)
    s.configure("Panel.TFrame", background=panel)
    s.configure("TLabel",       background=bg, foreground=text)
    s.configure("TCheckbutton", background=bg, foreground=text)
    s.map("TCheckbutton", background=[("active", bg)])

    s.configure("TScrollbar", background=panel, troughcolor=bg,
                 bordercolor=bg, arrowcolor=muted, relief="flat")
    s.map("TScrollbar", background=[("active", inp)])

    s.configure("TNotebook", background=bg, tabmargins=(0, 4, 0, 0))
    s.configure("TNotebook.Tab", background=panel, foreground=muted,
                 padding=(14, 9), font=T.font_ui(10, "bold"))
    s.map("TNotebook.Tab",
          background=[("selected", bg)],
          foreground=[("selected", text)])

    # Hidden-tab notebook style (tabs replaced by left nav rail)
    s.layout("NoTabs.TNotebook.Tab", [])
    s.configure("NoTabs.TNotebook", background=bg, tabmargins=[0, 0, 0, 0])


# ── CenterStage ────────────────────────────────────────────────────────────────

class CenterStage(tk.Canvas):
    """idle diamond → radar sweep (scanning) → animated score ring (results)."""

    def __init__(self, parent, size=200, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=C["panel"], highlightthickness=0, **kw)
        self._s   = size
        self._cx  = self._cy = size // 2
        self._r   = size // 2 - 12
        self._rw  = 15

        self._mode        = "idle"
        self._angle       = 90.0
        self._score       = 0
        self._target      = 0
        self._grade       = "—"
        self._sub         = ""
        self._anim        = None
        self._gull_phase  = 0.0   # for radar seagull animation
        self._draw_idle()

    # public ──────────────────────────────────────────────────────────────────

    def start_scan(self):
        self._cancel()
        self._mode  = "scanning"
        self._angle = 90.0
        self._sub   = ""
        self._spin()

    def update_check(self, name):
        self._sub = name[:28]

    def show_score(self, score, grade):
        self._cancel()
        self._mode   = "score"
        self._target = score
        self._grade  = grade
        self._score  = 0
        self._count_up()

    def reset(self):
        self._cancel()
        self._mode = "idle"
        self._draw_idle()

    # animation ───────────────────────────────────────────────────────────────

    def _cancel(self):
        if self._anim:
            self.after_cancel(self._anim)
            self._anim = None

    def _spin(self):
        if self._mode != "scanning":
            return
        self._angle      = (self._angle - 3) % 360
        self._gull_phase = (self._gull_phase + 0.018) % 1.0
        self._draw_radar()
        self._anim = self.after(28, self._spin)

    def _count_up(self):
        if self._score < self._target:
            self._score = min(self._score + 2, self._target)
            self._draw_score()
            self._anim = self.after(10, self._count_up)
        else:
            self._score = self._target
            self._draw_score()

    # draw ────────────────────────────────────────────────────────────────────

    def _draw_idle(self):
        self.delete("all")
        cx, cy, r = self._cx, self._cy, self._r
        self.create_arc(cx-r, cy-r, cx+r, cy+r, start=0, extent=359.9,
                        style=tk.ARC, outline=C["border"], width=self._rw)
        self.create_text(cx, cy - 8,  text="◆", fill=C["border"],
                         font=T.font_ui(26), anchor="center")
        self.create_text(cx, cy + 18, text="PRESS SCAN", fill=C["muted"],
                         font=T.font_ui(9), anchor="center")

    def _draw_radar(self):
        self.delete("all")
        cx, cy, r = self._cx, self._cy, self._r
        self.create_oval(cx-r, cy-r, cx+r, cy+r,
                         fill=C["radar_bg"], outline=C["border"], width=1)
        for ratio in (0.33, 0.66, 1.0):
            rr = int(r * ratio)
            self.create_oval(cx-rr, cy-rr, cx+rr, cy+rr,
                             outline=C["radar_grid"], width=1, fill="")
        self.create_line(cx-r, cy, cx+r, cy, fill=C["radar_grid"])
        self.create_line(cx, cy-r, cx, cy+r, fill=C["radar_grid"])

        trail = 80
        for i in range(trail, 0, -4):
            a = self._angle - i
            t = (i / trail) ** 0.6
            ri = int(t * 0x58); gi = int(t * 0xa6); bi = int(t * 0xff)
            self.create_arc(cx-r, cy-r, cx+r, cy+r, start=a, extent=4.5,
                            style=tk.ARC,
                            outline=f"#{ri:02x}{gi:02x}{bi:02x}", width=4)
        self.create_arc(cx-r, cy-r, cx+r, cy+r,
                        start=self._angle - 2, extent=4,
                        style=tk.ARC, outline=C["accent"], width=5)
        rad = math.radians(self._angle)
        lx = cx + r * math.cos(rad)
        ly = cy - r * math.sin(rad)
        self.create_line(cx, cy, lx, ly, fill=C["accent"], width=1)
        self.create_oval(cx-3, cy-3, cx+3, cy+3, fill=C["accent"], outline="")

        # Locked / skin-locked seagull mascot in radar centre
        gull_flap = math.sin(self._gull_phase * 2 * math.pi)
        # Ghost glow layer (slightly bigger, dimmer) for depth
        _draw_gull_icon(self, cx, cy, flap=gull_flap, scale=1.35,
                        body="#1a4a3a", wing="#1a4a3a",
                        beak="#1a4a3a", eye="#1a4a3a")
        # Main silhouette — muted teal, clearly visible against radar dark
        _draw_gull_icon(self, cx, cy, flap=gull_flap, scale=1.15,
                        body="#4a9080", wing="#3a7060",
                        beak="#4a9080", eye="#4a9080")

        if self._sub:
            self.create_text(cx, cy + r + 16, text=self._sub, fill=C["muted"],
                             font=T.font_mono(8), anchor="center")

    def _draw_score(self):
        self.delete("all")
        cx, cy, r, rw = self._cx, self._cy, self._r, self._rw
        color = _GRADE_COLOR.get(self._grade, C["muted"])
        self.create_arc(cx-r, cy-r, cx+r, cy+r, start=0, extent=359.9,
                        style=tk.ARC, outline=C["border"], width=rw)
        if self._score > 0:
            sweep = self._score / 100 * 359.9
            self.create_arc(cx-r, cy-r, cx+r, cy+r,
                            start=90, extent=-sweep,
                            style=tk.ARC, outline=color, width=rw)
            # Fake rounded caps: a filled dot at each end of the swept arc
            # (create_arc uses square caps Tkinter cannot round).
            cap_r = rw / 2
            for theta in (90.0, 90.0 - sweep):
                rad = math.radians(theta)
                px = cx + r * math.cos(rad)
                py = cy - r * math.sin(rad)
                self.create_oval(px - cap_r, py - cap_r, px + cap_r, py + cap_r,
                                 fill=color, outline="")
        self.create_text(cx, cy - 16,
                         text=self._grade if self._grade != "—" else "?",
                         fill=color,
                         font=T.font_ui(44, "bold"), anchor="center")
        self.create_text(cx, cy + 24, text=f"{self._score}/100",
                         fill=C["muted"], font=T.font_mono(11),
                         anchor="center")
        if self._score == self._target and self._grade in _GRADE_LABEL:
            self.create_text(cx, cy + r + 16,
                             text=_GRADE_LABEL[self._grade], fill=color,
                             font=T.font_ui(9, "bold"), anchor="center")


# ── Severity bar row ───────────────────────────────────────────────────────────

class _SparklineWidget(tk.Canvas):
    """Mini score-trend sparkline — shows last N scans as a line+dot chart."""

    _H  = 40
    _W  = 210
    _PAD = 6

    def __init__(self, parent, tab_name: str):
        super().__init__(parent, width=self._W, height=self._H,
                         bg=C["panel"], highlightthickness=0)
        self._tab = tab_name
        self._history: list = []
        self.refresh()

    def refresh(self):
        self._history = ec.load_scan_history(self._tab, n=20)
        self._redraw()

    def push(self, score: int, grade: str):
        """Add the latest scan point without touching disk (already saved)."""
        self._history = ec.load_scan_history(self._tab, n=20)
        self._redraw()

    def _redraw(self):
        self.delete("all")
        data = self._history
        if len(data) < 2:
            if data:
                self.create_text(
                    self._W // 2, self._H // 2,
                    text=f"{data[-1]['score']}/100",
                    fill=C["muted"], font=T.font_ui(8))
            else:
                self.create_text(
                    self._W // 2, self._H // 2,
                    text="No history yet",
                    fill=C["INFO"], font=T.font_ui(8))
            return

        scores  = [d["score"] for d in data]
        lo, hi  = min(scores), max(scores)
        rng     = max(hi - lo, 10)
        p       = self._PAD
        w, h    = self._W, self._H

        def _x(i):
            return p + int(i / (len(data) - 1) * (w - 2 * p))

        def _y(s):
            return (h - p) - int((s - lo) / rng * (h - 2 * p))

        pts = [(_x(i), _y(s)) for i, s in enumerate(scores)]

        # Gradient fill under the line
        for i in range(len(pts) - 1):
            x0, y0 = pts[i]
            x1, y1 = pts[i + 1]
            self.create_polygon(
                x0, y0, x1, y1, x1, h - p, x0, h - p,
                fill=C["input"], outline="")

        # Line
        for i in range(len(pts) - 1):
            self.create_line(pts[i], pts[i + 1],
                             fill=C["accent"], width=1, smooth=False)

        # Dots — last one larger + grade colour
        for i, (x, y) in enumerate(pts):
            grade = data[i].get("grade", "—")
            col   = _GRADE_COLOR.get(grade, C["muted"])
            r     = 4 if i == len(pts) - 1 else 2
            self.create_oval(x - r, y - r, x + r, y + r,
                             fill=col, outline="")

        # Latest score annotation
        lx, ly = pts[-1]
        lbl = f"{scores[-1]}"
        self.create_text(lx - 3, ly - 7, text=lbl,
                         fill=C["text"], font=T.font_ui(7),
                         anchor="s")


class _AcceptRiskDialog(tk.Toplevel):
    """Modal: let user accept a finding as a known/acceptable risk."""

    def __init__(self, parent, check: str, label: str, on_accept=None, on_remove=None):
        super().__init__(parent)
        self.title("Accept risk")
        self.resizable(False, False)
        self.configure(bg=C["panel"])
        self.grab_set()
        self.transient(parent)

        self._check  = check
        self._label  = label
        self._on_accept = on_accept
        self._on_remove = on_remove
        already = ec.is_accepted_risk(check, label)

        pad = dict(padx=18, pady=6)

        tk.Label(self, text="Finding", bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(8, "bold"), anchor="w").pack(
            fill=tk.X, padx=18, pady=(14, 0))
        tk.Label(self, text=label, bg=C["panel"], fg=C["text"],
                 font=T.font_ui(10, "bold"),
                 wraplength=340, justify=tk.LEFT, anchor="w").pack(
            fill=tk.X, **pad)

        tk.Frame(self, bg=C["border"], height=1).pack(fill=tk.X, padx=18)

        if already:
            info     = ec.load_accepted_risks().get(ec._risk_key(check, label), {})
            note     = info.get("note", "")
            ts       = info.get("ts", 0)
            when     = datetime.datetime.fromtimestamp(ts).strftime("%d %b %Y") if ts else "?"
            note_sfx = f' — "{note}"' if note else ""
            tk.Label(self,
                     text=f"Accepted on {when}{note_sfx}",
                     bg=C["panel"], fg=C["ok"],
                     font=T.font_ui(9)).pack(**pad)
            ttk.Button(self, text="Remove acceptance",
                       command=self._remove).pack(padx=18, pady=(0, 14), anchor="e")
        else:
            tk.Label(self,
                     text="Mark this finding as an accepted risk.\n"
                          "It will still appear but won't count toward the score.",
                     bg=C["panel"], fg=C["muted"],
                     font=T.font_ui(9),
                     justify=tk.LEFT).pack(**pad)
            tk.Label(self, text="Note (optional)", bg=C["panel"], fg=C["muted"],
                     font=T.font_ui(8, "bold"), anchor="w").pack(
                fill=tk.X, padx=18)
            self._note_var = tk.StringVar()
            ttk.Entry(self, textvariable=self._note_var, width=42).pack(
                padx=18, pady=(4, 10))
            bf = tk.Frame(self, bg=C["panel"])
            bf.pack(fill=tk.X, padx=18, pady=(0, 14))
            ttk.Button(bf, text="Cancel",
                       command=self.destroy).pack(side=tk.LEFT)
            ttk.Button(bf, text="Accept risk",
                       style="Accent.TButton",
                       command=self._accept).pack(side=tk.RIGHT)

        self.update_idletasks()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        w, h   = self.winfo_reqwidth(), self.winfo_reqheight()
        self.geometry(f"{w}x{h}+{px + (pw - w)//2}+{py + (ph - h)//2}")

    def _accept(self):
        note = getattr(self, "_note_var", tk.StringVar()).get().strip()
        ec.save_accepted_risk(self._check, self._label, note)
        if self._on_accept:
            self._on_accept()
        self.destroy()

    def _remove(self):
        ec.remove_accepted_risk(self._check, self._label)
        if self._on_remove:
            self._on_remove()
        self.destroy()


class _ScheduleDialog(tk.Toplevel):
    """Modal: configure headless scheduled scans via crontab."""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Schedule scans")
        self.resizable(False, False)
        self.configure(bg=C["panel"])
        self.grab_set()
        self.transient(parent)

        sched = ec.load_schedule()
        self._enabled  = tk.BooleanVar(value=sched.get("enabled", False))
        self._hour_var = tk.StringVar(value=str(sched.get("hour", 9)).zfill(2))
        self._min_var  = tk.StringVar(value=str(sched.get("minute", 0)).zfill(2))
        self._tabs = {
            "security":  tk.BooleanVar(value="security"  in sched.get("tabs", ["security"])),
            "antivirus": tk.BooleanVar(value="antivirus" in sched.get("tabs", [])),
            "cleaner":   tk.BooleanVar(value="cleaner"   in sched.get("tabs", [])),
        }

        pad = dict(padx=20, pady=6)

        tk.Label(self, text="Scheduled scans",
                 bg=C["panel"], fg=C["text"],
                 font=T.font_ui(13, "bold")).pack(padx=20, pady=(16, 4), anchor="w")
        tk.Label(self,
                 text="Runs silently in the background and sends a\n"
                      "desktop notification if new issues are found.",
                 bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(9), justify=tk.LEFT).pack(padx=20, anchor="w")

        tk.Frame(self, bg=C["border"], height=1).pack(fill=tk.X, padx=20, pady=10)

        en_f = tk.Frame(self, bg=C["panel"])
        en_f.pack(fill=tk.X, **pad)
        ttk.Checkbutton(en_f, text="Enable scheduled scan",
                        variable=self._enabled).pack(anchor="w")

        time_f = tk.Frame(self, bg=C["panel"])
        time_f.pack(fill=tk.X, padx=20, pady=(4, 0))
        tk.Label(time_f, text="Daily at", bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(9)).pack(side=tk.LEFT)
        ttk.Spinbox(time_f, from_=0, to=23, width=3, format="%02.0f",
                    textvariable=self._hour_var).pack(side=tk.LEFT, padx=(8, 2))
        tk.Label(time_f, text=":", bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(9, "bold")).pack(side=tk.LEFT)
        ttk.Spinbox(time_f, from_=0, to=59, width=3, format="%02.0f",
                    textvariable=self._min_var).pack(side=tk.LEFT, padx=(2, 0))

        tk.Label(self, text="Tabs to scan",
                 bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(8, "bold")).pack(padx=20, pady=(12, 2), anchor="w")
        for key, label in (("security", "Security"), ("antivirus", "Antivirus"),
                            ("cleaner", "Cleaner")):
            ttk.Checkbutton(self, text=label,
                            variable=self._tabs[key]).pack(padx=32, anchor="w")

        # Status of current cron
        cron_jobs = ec._read_ec_cron_jobs()
        status_txt = f"Active: {cron_jobs[0]}" if cron_jobs else "Not scheduled"
        tk.Label(self, text=status_txt,
                 bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(7),
                 wraplength=340).pack(padx=20, pady=(8, 0), anchor="w")

        tk.Frame(self, bg=C["border"], height=1).pack(fill=tk.X, padx=20, pady=12)

        bf = tk.Frame(self, bg=C["panel"])
        bf.pack(fill=tk.X, padx=20, pady=(0, 16))
        ttk.Button(bf, text="Cancel", command=self.destroy).pack(side=tk.LEFT)
        ttk.Button(bf, text="Save", style="Accent.TButton",
                   command=self._save).pack(side=tk.RIGHT)

        self.update_idletasks()
        pw = parent.winfo_width(); ph = parent.winfo_height()
        px = parent.winfo_rootx(); py = parent.winfo_rooty()
        w  = self.winfo_reqwidth(); h = self.winfo_reqheight()
        self.geometry(f"{w}x{h}+{px+(pw-w)//2}+{py+(ph-h)//2}")

    def _save(self):
        tabs = [k for k, v in self._tabs.items() if v.get()]
        if not tabs:
            tabs = ["security"]
        sched = {
            "enabled": self._enabled.get(),
            "hour":    int(self._hour_var.get()),
            "minute":  int(self._min_var.get()),
            "tabs":    tabs,
        }
        ec.save_schedule(sched)
        ok, err = ec.install_schedule(sched)
        if not err:
            messagebox.showinfo(
                "Saved",
                ("Scheduled scan enabled — runs daily at "
                 f"{sched['hour']:02d}:{sched['minute']:02d}.")
                if sched["enabled"] else "Scheduled scan disabled.")
        else:
            messagebox.showerror("Schedule error", err)
        self.destroy()


class _SevRow(tk.Frame):
    _BAR_W = 68

    def __init__(self, parent, severity):
        super().__init__(parent, bg=C["panel"])
        self._sev = severity
        dot = tk.Canvas(self, width=10, height=10, bg=C["panel"],
                        highlightthickness=0)
        dot.create_oval(2, 2, 8, 8, fill=C[severity], outline="")
        dot.pack(side=tk.LEFT, padx=(0, 5))
        tk.Label(self, text=severity, bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(9), width=8, anchor="w").pack(side=tk.LEFT)
        self._bar = tk.Canvas(self, width=self._BAR_W, height=5,
                              bg=C["input"], highlightthickness=0)
        self._bar.pack(side=tk.LEFT, padx=(2, 4))
        self._fill = self._bar.create_rectangle(0, 0, 0, 5,
                                                fill=C[severity], outline="")
        self._lbl = tk.Label(self, text="0", bg=C["panel"], fg=C["muted"],
                             font=T.font_ui(9, "bold"), width=3,
                             anchor="e")
        self._lbl.pack(side=tk.LEFT)

    def update(self, count, max_count):
        color = C[self._sev] if count > 0 else C["muted"]
        self._lbl.configure(text=str(count), fg=color)
        px = int(count / max(max_count, 1) * self._BAR_W)
        self._bar.coords(self._fill, 0, 0, px, 5)

    def reset(self):
        self._lbl.configure(text="0", fg=C["muted"])
        self._bar.coords(self._fill, 0, 0, 0, 5)


# ── UIReporter ─────────────────────────────────────────────────────────────────

class _UIReporter(ec._Reporter):
    def __init__(self, ui_queue):
        super().__init__(json_mode=True)
        self._q = ui_queue

    def begin(self, title, subtitle=None):
        super().begin(title, subtitle)
        self._q.put(("status", title))

    def finding(self, severity, label, why, fix, fix_cmds=None, **extra):
        super().finding(severity, label, why, fix, fix_cmds=fix_cmds, **extra)
        record = {
            "check":    self._cur["check"] if self._cur else "",
            "severity": severity,
            "label":    label,
            "why":      why,
            "fix":      fix,
            "fix_cmds": fix_cmds or [],
        }
        record.update(extra)   # pass revertable=False and other metadata to the UI
        self._q.put(("finding", record))


# ── Privilege / batch-fix helpers ─────────────────────────────────────────────

def _is_root():
    if _UI_OS == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _elevation_available() -> bool:
    """True if we can ask for elevated privileges on this platform."""
    if _UI_OS == "Linux":
        return bool(shutil.which("pkexec"))
    if _UI_OS == "Darwin":
        return bool(shutil.which("osascript"))
    if _UI_OS == "Windows":
        return bool(shutil.which("powershell"))
    return False


def _ensure_admin() -> None:
    """Re-launch the GUI with admin privileges if not already elevated.

    On success the elevated process takes over and this one exits.
    If the user declines or no elevation tool is available, shows an
    error dialog and exits.  CLI subcommands bypass this entirely.
    """
    if _is_root():
        return

    if _UI_OS == "Windows":
        import ctypes
        if getattr(sys, "frozen", False):
            exe, params = sys.argv[0], " ".join(f'"{a}"' for a in sys.argv[1:])
        else:
            exe    = sys.executable
            params = " ".join(f'"{a}"' for a in sys.argv)
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        if ret > 32:
            sys.exit(0)

    elif _UI_OS == "Darwin":
        if getattr(sys, "frozen", False):
            safe = " ".join(shlex.quote(a) for a in sys.argv)
        else:
            safe = shlex.quote(sys.executable) + " " + " ".join(shlex.quote(a) for a in sys.argv)
        script = f'do shell script "{safe} &" with administrator privileges'
        r = subprocess.run(["osascript", "-e", script], capture_output=True)
        if r.returncode == 0:
            sys.exit(0)

    elif _UI_OS == "Linux":
        pkexec = shutil.which("pkexec")
        if pkexec:
            # pkexec strips DISPLAY/WAYLAND_DISPLAY so Tkinter can't open a window.
            # Pass them explicitly via `env` so the elevated process can find the screen.
            script = os.path.abspath(__file__)
            env_vars = []
            for var in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR",
                        "DBUS_SESSION_BUS_ADDRESS"):
                val = os.environ.get(var)
                if val:
                    env_vars.append(f"{var}={val}")
            env_cmd = [pkexec, "env"] + env_vars + [sys.executable, script] + sys.argv[1:]
            os.execvp(pkexec, env_cmd)

    _tmp = tk.Tk()
    _tmp.withdraw()
    if _UI_OS == "Windows":
        how = "Right-click the app → 'Run as administrator'."
    elif _UI_OS == "Darwin":
        how = "Launch from a terminal with: sudo gullwing-ui"
    else:
        how = "Launch with: pkexec gullwing-ui  or  sudo gullwing-ui"
    messagebox.showerror(
        "Administrator Required",
        "Gullwing needs administrator privileges to scan your system.\n\n"
        + how,
        parent=_tmp,
    )
    _tmp.destroy()
    sys.exit(1)


_FIRST_RUN_FLAG = os.path.join(
    os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
    "exposure-checker", "first_run_done",
)


def _batch_fix_elevated(findings):
    """Collect ALL fix_cmds and run them with a SINGLE elevation prompt.
    Returns list of (cmd, returncode, output) or None if no escalation tool."""
    cmds = [cmd for f in findings for cmd in f.get("fix_cmds", [])]
    if not cmds:
        return []

    if _is_root():
        results = []
        for cmd in cmds:
            rc, out = ec._run_fix_cmd(cmd)
            results.append((cmd, rc, out))
        return results

    if _UI_OS == "Darwin":
        return _batch_fix_macos(cmds)
    if _UI_OS == "Windows":
        return _batch_fix_windows(cmds)
    return _batch_fix_linux(cmds)


def _batch_fix_linux(cmds):
    """Single pkexec prompt for all fixes on Linux."""
    pkexec = shutil.which("pkexec")
    if not pkexec:
        return None

    lines = ["#!/bin/bash"]
    for i, cmd in enumerate(cmds):
        lines.append(f'printf "\\n##ECCMD{i}##\\n"')
        lines.append(f'{{ {cmd}; }} 2>&1')
        lines.append(f'printf "##ECEXIT{i}:%d##\\n" "$?"')

    fd, spath = tempfile.mkstemp(suffix=".sh", prefix="ec-fix-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(spath, 0o700)
        result = subprocess.run([pkexec, "bash", spath],
                                capture_output=True, text=True, timeout=120)
        return _parse_batch_output(cmds, result.stdout)
    except subprocess.TimeoutExpired:
        return [(c, 1, "timed out") for c in cmds]
    except OSError as exc:
        return [(c, 1, str(exc)) for c in cmds]
    finally:
        try:
            os.unlink(spath)
        except OSError:
            pass


def _batch_fix_macos(cmds):
    """Single osascript administrator prompt for ALL fixes on macOS.

    Previously each command spawned its own `do shell script ... with
    administrator privileges` → one password dialog *per fix*. Now all
    commands run inside one marker-tagged shell script behind one prompt.
    """
    lines = []
    for i, cmd in enumerate(cmds):
        lines.append(f'printf "\\n##ECCMD{i}##\\n"')
        lines.append(f'{{ {cmd}; }} 2>&1')
        lines.append(f'printf "##ECEXIT{i}:%d##\\n" "$?"')
    fd, spath = tempfile.mkstemp(suffix=".sh", prefix="ec-fix-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(spath, 0o700)
        safe = spath.replace("\\", "\\\\").replace('"', '\\"')
        script = f'do shell script "/bin/bash \\"{safe}\\"" with administrator privileges'
        r = subprocess.run(["osascript", "-e", script],
                           capture_output=True, text=True, errors="replace",
                           timeout=max(120, 60 * len(cmds)))
        if r.returncode != 0 and "##ECCMD" not in r.stdout:
            # User cancelled the auth dialog or osascript failed outright
            msg = r.stderr.strip() or "authorization cancelled"
            return [(c, 1, msg) for c in cmds]
        return _parse_batch_output(cmds, r.stdout)
    except subprocess.TimeoutExpired:
        return [(c, 1, "timed out") for c in cmds]
    except OSError as exc:
        return [(c, 1, str(exc)) for c in cmds]
    finally:
        try:
            os.unlink(spath)
        except OSError:
            pass


def _batch_fix_windows(cmds):
    """Single UAC prompt for ALL fixes on Windows.

    Each command is wrapped in try/catch with $ErrorActionPreference='Stop'
    so cmdlet failures are caught. Output is written via Out-File -Encoding
    ASCII to guarantee no BOM — PS5.1 Add-Content -Encoding UTF8 writes a
    BOM on new files which breaks marker parsing.
    """
    no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    fd, script_path = tempfile.mkstemp(suffix=".ps1", prefix="ec-fix-")
    out_path = script_path + ".out"
    # Both paths come from tempfile.mkstemp() so they can't contain quotes, but
    # quote anyway so the escaping invariant has no exceptions. ps_out fills a
    # simple '{}' slot (ec._ps_quote wraps + escapes); ps_scr is embedded inside
    # a nested \"...\" Start-Process argument below, so it keeps an inline escape.
    ps_scr = script_path.replace("'", "''")  # PS single-quote escape (nested)

    lines = [f"$__f = {ec._ps_quote(out_path)}"]
    for i, cmd in enumerate(cmds):
        lines += [
            f'"##ECCMD{i}##" | Out-File -Append -Encoding ASCII -FilePath $__f',
            f"$__c = 0",
            f"try {{",
            f"    $ErrorActionPreference = 'Stop'",
            f"    & {{ {cmd} }} 2>&1 | Out-String -Stream"
            f" | Out-File -Append -Encoding ASCII -FilePath $__f",
            f"    if ($LASTEXITCODE) {{ $__c = $LASTEXITCODE }}",
            f"}} catch {{",
            f"    $ErrorActionPreference = 'Continue'",
            f'    "Error: $_" | Out-File -Append -Encoding ASCII -FilePath $__f',
            f"    $__c = 1",
            f"}}",
            f"$ErrorActionPreference = 'Continue'",
            f'"##ECEXIT{i}:$__c##" | Out-File -Append -Encoding ASCII -FilePath $__f',
        ]
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig") as fh:
            fh.write("\n".join(lines) + "\n")
        runner = (
            f"Start-Process powershell.exe "
            f"-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"{ps_scr}\"' "
            f"-Verb RunAs -WindowStyle Hidden -Wait"
        )
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", runner],
            capture_output=True, text=True, errors="replace",
            timeout=max(120, 60 * len(cmds)), creationflags=no_window,
        )
        if "denied" in (r.stderr or "").lower() or "cancel" in (r.stderr or "").lower():
            return [(c, 1, "UAC prompt declined") for c in cmds]
        try:
            with open(out_path, encoding="ascii", errors="replace") as fh:
                stdout = fh.read()
        except OSError:
            stdout = ""
        if "##ECCMD" not in stdout:
            return [(c, 1, (r.stderr or "elevation failed").strip()) for c in cmds]
        return _parse_batch_output(cmds, stdout)
    except subprocess.TimeoutExpired:
        return [(c, 1, "timed out") for c in cmds]
    except OSError as exc:
        return [(c, 1, str(exc)) for c in cmds]
    finally:
        for p in (script_path, out_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def _parse_batch_output(cmds, stdout):
    """Parse marker-tagged output from the batch-fix script."""
    outputs: dict = {}
    exits:   dict = {}
    cur_idx        = None
    cur_out:  list = []

    for line in stdout.splitlines():
        m = re.match(r"##ECCMD(\d+)##", line.strip())
        if m:
            if cur_idx is not None:
                outputs[cur_idx] = "\n".join(cur_out).strip()
            cur_idx = int(m.group(1))
            cur_out = []
            continue
        m = re.match(r"##ECEXIT(\d+):(\d+)##", line.strip())
        if m:
            i, rc = int(m.group(1)), int(m.group(2))
            exits[i] = rc
            if cur_idx is not None:
                outputs[cur_idx] = "\n".join(cur_out).strip()
                cur_idx = None
                cur_out = []
            continue
        if cur_idx is not None:
            cur_out.append(line)

    return [(cmd, exits.get(i, 1), outputs.get(i, ""))
            for i, cmd in enumerate(cmds)]


def _assemble_preview_cmds(findings, force_sudo=None) -> str:
    """The commands that will run, one per line — sudo-prefixed on POSIX when
    elevation applies. Shared by the confirm dialog and the denied dialog so the
    preview always matches what is actually executed."""
    all_cmds = [cmd for f in findings for cmd in f.get("fix_cmds", [])]
    if _UI_OS == "Windows":
        return "\n".join(all_cmds)
    use_sudo = (not _is_root()) if force_sudo is None else force_sudo
    if use_sudo:
        return "\n".join(f"sudo {c}" for c in all_cmds)
    return "\n".join(all_cmds)


def _confirm_fix_dialog(parent, findings) -> bool:
    """Modal preview shown before any fix runs. Lists the actual commands in a
    read-only monospace box and states whether the changes can be reverted.
    Returns True to apply, False on Cancel or window close."""
    n        = len(findings)
    n_cmd    = sum(len(f.get("fix_cmds", [])) for f in findings)
    cmds_txt = _assemble_preview_cmds(findings)
    top      = parent.winfo_toplevel()
    result   = {"ok": False}

    dlg = tk.Toplevel(parent)
    dlg.title("Apply fixes")
    dlg.configure(bg=C["panel"])
    dlg.resizable(False, False)
    dlg.transient(top)

    tk.Label(dlg, text=f"Apply {n} fix{'es' if n != 1 else ''}",
             bg=C["panel"], fg=C["text"],
             font=T.font_ui(13, "bold")).pack(padx=20, pady=(16, 2), anchor="w")
    tk.Label(dlg, text=f"These {n_cmd} command(s) will run on your machine:",
             bg=C["panel"], fg=C["muted"],
             font=T.font_ui(9)).pack(padx=20, anchor="w")

    # Read-only, scrollable, monospace command preview
    tf = tk.Frame(dlg, bg=C["panel"])
    tf.pack(fill=tk.BOTH, expand=True, padx=20, pady=(6, 8))
    txt = tk.Text(tf, height=min(max(n_cmd, 3), 12), width=66,
                  bg=C["log_bg"], fg=C["cmd"], font=T.font_mono(9),
                  relief=tk.FLAT, wrap=tk.NONE, padx=8, pady=6)
    sb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=txt.yview)
    txt.configure(yscrollcommand=sb.set)
    txt.insert("1.0", cmds_txt)
    txt.configure(state=tk.DISABLED)
    sb.pack(side=tk.RIGHT, fill=tk.Y)
    txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Reversibility status
    non_rev = [f.get("label", "?") for f in findings if f.get("revertable") is False]
    if non_rev:
        rev_text, rev_fg = "⚠ Cannot be undone: " + ", ".join(non_rev), C["HIGH"]
    else:
        rev_text, rev_fg = ("↩  Changes are snapshotted and can be reverted "
                            "this session.", C["ok"])
    tk.Label(dlg, text=rev_text, bg=C["panel"], fg=rev_fg,
             font=T.font_ui(9), wraplength=470, justify=tk.LEFT).pack(
        padx=20, anchor="w")

    if not _is_root() and _UI_OS != "Windows":
        tk.Label(dlg, text="You will be asked for your password once for all fixes.",
                 bg=C["panel"], fg=C["muted"], font=T.font_ui(8)).pack(
            padx=20, anchor="w", pady=(2, 0))

    bf = tk.Frame(dlg, bg=C["panel"])
    bf.pack(padx=20, pady=(10, 16), anchor="e")

    def _apply():
        result["ok"] = True
        dlg.destroy()

    def _cancel():
        result["ok"] = False
        dlg.destroy()

    ttk.Button(bf, text=f"Apply {n} fix{'es' if n != 1 else ''}",
               style="Accent.TButton", command=_apply).pack(side=tk.RIGHT)
    ttk.Button(bf, text="Cancel", command=_cancel).pack(side=tk.RIGHT, padx=(0, 8))
    dlg.protocol("WM_DELETE_WINDOW", _cancel)

    dlg.grab_set()
    top.wait_window(dlg)
    return result["ok"]


def _show_fix_denied_dialog(root, findings):
    all_cmds = [cmd for f in findings for cmd in f.get("fix_cmds", [])]
    if not all_cmds:
        return
    dlg = tk.Toplevel(root)
    dlg.title("Admin Access Required")
    dlg.configure(bg=C["panel"])
    dlg.resizable(False, False)
    dlg.transient(root)

    tk.Label(dlg, text="Admin Access Required",
             bg=C["panel"], fg=C["text"],
             font=T.font_ui(12, "bold")).pack(pady=(18, 4), padx=20)
    if _UI_OS == "Windows":
        run_hint = "Run these commands in an elevated (Administrator) PowerShell."
    else:
        run_hint = "Run these commands in a terminal, or launch\ngullwing-ui with sudo to auto-apply."
    cmds_text = _assemble_preview_cmds(findings, force_sudo=True)
    tk.Label(dlg, text=run_hint,
             bg=C["panel"], fg=C["muted"],
             justify=tk.CENTER).pack(pady=(0, 10), padx=20)
    txt = tk.Text(dlg, height=min(len(all_cmds) + 1, 10), width=58,
                  bg=C["log_bg"], fg=C["cmd"], font=("TkFixedFont", 9),
                  relief=tk.FLAT, wrap=tk.NONE, padx=8, pady=6)
    txt.insert("1.0", cmds_text)
    txt.configure(state=tk.DISABLED)
    txt.pack(fill=tk.X, padx=20, pady=(0, 8))

    bf = tk.Frame(dlg, bg=C["panel"])
    bf.pack(pady=(0, 18), padx=20)

    def _copy():
        dlg.clipboard_clear()
        dlg.clipboard_append(cmds_text)
        dlg.update()
        copy_btn.configure(text="Copied ✓")

    copy_btn = ttk.Button(bf, text="Copy Commands", command=_copy)
    copy_btn.pack(side=tk.LEFT, padx=(0, 8))
    ttk.Button(bf, text="Close", command=dlg.destroy).pack(side=tk.LEFT)


# ── Session tracker ────────────────────────────────────────────────────────────

class _SessionTracker:
    """Captures pre-fix snapshots so everything applied this session can be reverted.

    On first successful before_fix() call the snapshot is also written to
    ~/.local/share/gullwing/sessions/<ts>/ so that an incomplete session
    (app killed mid-fix) is detectable on next launch.  mark_complete() is
    called when the user finishes a revert, adding a 'completed' sentinel.
    """

    def __init__(self):
        self._snaps:      list = []   # [(label, snap_dict)]
        self._session_ts: str  = ""   # set on first successful before_fix

    def before_fix(self, label: str) -> bool:
        """Capture pre-fix state. Returns True on success, False if snapshot failed.
        The caller MUST abort the fix if this returns False."""
        try:
            snap = ec.take_snapshot(label=f"before: {label}")
        except Exception:
            return False
        files      = snap.get("files", {})
        captured   = any(v is not None for v in files.values())
        has_net    = bool(snap.get("ufw_status") or snap.get("ufw_rules"))
        has_sysctl = any(v is not None for v in snap.get("sysctl_prev", {}).values())

        if captured or has_net or has_sysctl:
            # Real state captured — record it so the fix can be reverted.
            self._snaps.append((label, snap))
            # Persist to disk on the first snap in this session so an abrupt
            # kill leaves a recoverable manifest.
            if not self._session_ts:
                import datetime as _dt
                self._session_ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            ec.write_session_manifest(self._session_ts, label, snap)
            return True

        # On Linux/macOS the captured files ARE what the fixes edit, so if they
        # exist on disk but came back as None (present but unreadable, e.g.
        # permission denied) a later revert would fail — abort to protect the
        # user's config. On Windows the captured hosts file is unrelated to the
        # registry/service fixes being applied, so an unreadable hosts file must
        # never block a fix.
        if _UI_OS != "Windows" and any(v is None for v in files.values()):
            return False

        # Nothing on this system to snapshot (e.g. Windows fixes are registry/
        # service changes the snapshot system doesn't track). The fix isn't
        # revertable, but there's nothing to protect — let it proceed instead
        # of blocking the user outright.
        return True

    @property
    def has_changes(self):
        return bool(self._snaps)

    def earliest_snap(self):
        return self._snaps[0][1] if self._snaps else None

    def summary_lines(self):
        lines = []
        for label, snap in self._snaps:
            ts = snap.get("timestamp", "?")[:19].replace("T", " ")
            lines.append(f"[{ts}]  {label}")
        return lines

    def clear(self):
        """Clear in-memory state and mark the on-disk session as completed."""
        if self._session_ts:
            ec.mark_session_complete(self._session_ts)
            self._session_ts = ""
        self._snaps.clear()


# ── FindingsPane ───────────────────────────────────────────────────────────────

class _FindingsPane:
    """Scrollable card list for findings — replaces the old Treeview."""

    _STRIPE = {
        "CRITICAL": "#f25757", "HIGH": "#f5922e",
        "MEDIUM":   "#e8c13a", "REVIEW": "#6b7786", "INFO": "#3d4a5c",
    }
    _SEV_CAP = {
        "CRITICAL": "Critical", "HIGH": "High",
        "MEDIUM":   "Medium",   "REVIEW": "Review", "INFO": "Info",
    }

    def __init__(self, parent, on_fix_one=None):
        self._on_fix_one = on_fix_one
        self._findings: list = []
        self._cards:    list = []
        self._selected: dict = {}   # idx → BooleanVar (unused currently but kept for API)
        self._parent = parent
        self._info_findings: list = []   # INFO-severity findings buffered out of the card list
        self._info_toggle   = None       # outer Frame for the collapsible INFO section

        # Alert banner — packed before the scroll canvas when there are C/H findings
        self._alert_frame   = tk.Frame(parent, bg=C["panel"],
                                       highlightthickness=1,
                                       highlightbackground=C["border"])
        self._alert_visible = False

        self._outer = tk.Frame(parent, bg=C["bg"])
        self._outer.pack(fill=tk.BOTH, expand=True)

        self._canvas = tk.Canvas(self._outer, bg=C["bg"],
                                  highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(self._outer, orient=tk.VERTICAL,
                              command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._inner = tk.Frame(self._canvas, bg=C["bg"])
        self._win_id = self._canvas.create_window(
            0, 0, window=self._inner, anchor="nw")
        self._inner.bind("<Configure>", self._on_inner_cfg)
        self._canvas.bind("<Configure>", self._on_canvas_cfg)
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self._canvas.bind(seq, self._on_scroll)

        # Empty state overlay
        self._empty_f   = tk.Frame(self._canvas, bg=C["bg"])
        self._empty_win = self._canvas.create_window(
            0, 0, window=self._empty_f, anchor="center")
        self._build_empty_state()
        self._set_empty(True)

    def _build_empty_state(self):
        f = self._empty_f
        gull_c = tk.Canvas(f, width=86, height=56, bg=C["bg"],
                            highlightthickness=0)
        gull_c.pack(pady=(0, 8))
        # Draw a dim ghost gull — actual _draw_gull_icon defined later in module
        _draw_gull_icon(gull_c, 43, 28, flap=0.0, scale=0.82,
                        body=C["input"], wing=C["border"],
                        beak=C["input"], eye=C["border"])
        tk.Label(f, text="Nothing found yet",
                 bg=C["bg"], fg=C["muted"],
                 font=T.font_ui(14, "bold")).pack()
        tk.Label(f, text="Press Scan now to analyse this machine",
                 bg=C["bg"], fg=C["INFO"],
                 font=T.font_ui(10)).pack(pady=(6, 0))

    def _set_empty(self, visible: bool):
        state_cards = "hidden" if visible else "normal"
        state_empty = "normal" if visible else "hidden"
        self._canvas.itemconfigure(self._win_id,    state=state_cards)
        self._canvas.itemconfigure(self._empty_win, state=state_empty)

    def _on_inner_cfg(self, _e=None):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_cfg(self, event):
        self._canvas.itemconfigure(self._win_id, width=event.width)
        self._canvas.coords(self._empty_win,
                             event.width // 2, event.height // 2)

    def _on_scroll(self, event):
        if event.num == 4:                       # X11 wheel up
            self._canvas.yview_scroll(-1, "units")
        elif event.num == 5:                     # X11 wheel down
            self._canvas.yview_scroll(1, "units")
        elif _UI_OS == "Darwin":
            # macOS reports small deltas (±1..3 per trackpad event);
            # int(delta/60) truncated to 0 → scrolling was completely dead.
            self._canvas.yview_scroll(-int(event.delta), "units")
        else:                                    # Windows: multiples of ±120
            step = int(-event.delta / 120) or (-1 if event.delta > 0 else 1)
            self._canvas.yview_scroll(step, "units")

    # ── Public API ────────────────────────────────────────────────────────────

    def add_finding(self, f: dict):
        if f.get("severity") == "INFO":
            self._info_findings.append(f)
            return                      # INFO cards are shown only under the collapsed toggle
        idx = len(self._findings)
        self._findings.append(f)
        if f.get("fix_cmds"):
            self._selected[idx] = tk.BooleanVar(value=False)
        self._build_card(f)
        self._set_empty(False)

    def flush_info_group(self):
        """Called when a scan completes: sort visible cards by severity, then
        append a collapsed toggle for any buffered INFO findings."""
        self._sort_visible_cards()
        if self._info_findings:
            self._build_info_toggle()
        if self._findings or self._info_findings:
            self._set_empty(False)

    def _sort_visible_cards(self):
        """Re-order non-INFO cards: CRITICAL first, then HIGH, MEDIUM, REVIEW."""
        if len(self._findings) <= 1:
            return
        _ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "REVIEW": 3}
        paired = list(zip(self._findings, self._cards))
        paired.sort(key=lambda x: _ORDER.get(x[0].get("severity", ""), 99))
        for _, card in paired:
            card.pack_forget()
        self._findings = [p[0] for p in paired]
        self._cards    = [p[1] for p in paired]
        for card in self._cards:
            card.pack(fill=tk.X, padx=12, pady=(8, 0))

    def _build_info_toggle(self):
        """Build the collapsible INFO section at the bottom of the card list."""
        n = len(self._info_findings)
        outer = tk.Frame(self._inner, bg=C["bg"])
        outer.pack(fill=tk.X, padx=12, pady=(14, 8))
        self._info_toggle = outer

        hdr = tk.Frame(outer, bg=C["bg"])
        hdr.pack(fill=tk.X)
        lbl_txt = f"▶  Show {n} informational item{'s' if n != 1 else ''}"
        self._info_btn = tk.Label(hdr, text=lbl_txt, bg=C["bg"], fg=C["muted"],
                                  font=T.font_ui(9), cursor="hand2")
        self._info_btn.pack(side=tk.LEFT)
        tk.Frame(hdr, bg=C["border"], height=1).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0), pady=6)

        self._info_body     = tk.Frame(outer, bg=C["bg"])
        self._info_expanded = False
        for f in self._info_findings:
            self._build_info_card(f, self._info_body)

        self._info_btn.bind("<Button-1>", self._toggle_info)
        self._info_btn.bind("<Enter>",
            lambda _e: self._info_btn.configure(fg=C["accent"]))
        self._info_btn.bind("<Leave>",
            lambda _e: self._info_btn.configure(fg=C["muted"]))
        self._bind_scroll(outer)

    def _build_info_card(self, f: dict, parent: tk.Frame):
        """Compact card for an INFO finding (no Fix button; ⋯ still allows Accept Risk)."""
        accepted  = f.get("_accepted", False)
        stripe    = self._STRIPE["INFO"]
        card_bg   = C["bg"]
        card = tk.Frame(parent, bg=card_bg,
                        highlightthickness=1, highlightbackground=C["border"])
        card.pack(fill=tk.X, pady=(4, 0))

        tk.Frame(card, bg=stripe, width=4).pack(side=tk.LEFT, fill=tk.Y)

        right_f = tk.Frame(card, bg=card_bg)
        right_f.pack(side=tk.RIGHT, padx=(4, 8), pady=7)
        ttk.Button(right_f, text="⋯", style="Dim.TButton", width=2,
                   command=lambda _f=f: self._open_info_overflow(_f)).pack()

        body = tk.Frame(card, bg=card_bg)
        body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 8), pady=7)

        top = tk.Frame(body, bg=card_bg)
        top.pack(fill=tk.X)
        _sev_pill(top, "INFO", stripe, "#060a0f").pack(side=tk.LEFT)
        if f.get("check"):
            tk.Label(top, text=f"  {f['check']}", bg=card_bg, fg=C["muted"],
                     font=T.font_ui(8)).pack(side=tk.LEFT)
        if accepted:
            tk.Label(top, text="  Accepted risk", bg=card_bg, fg=C["ok"],
                     font=T.font_ui(7, "bold")).pack(side=tk.LEFT)

        title_fg = C["muted"] if accepted else C["text"]
        tk.Label(body, text=f.get("label", ""), bg=card_bg, fg=title_fg,
                 font=T.font_ui(10, "bold"),
                 anchor="w", wraplength=500, justify=tk.LEFT).pack(
            fill=tk.X, pady=(4, 0))
        if f.get("why") and not accepted:
            tk.Label(body, text=f["why"], bg=card_bg, fg=C["muted"],
                     font=T.font_ui(9), anchor="w",
                     wraplength=500, justify=tk.LEFT).pack(fill=tk.X, pady=(2, 0))
        self._bind_scroll(card)
        return card

    def _open_info_overflow(self, f: dict):
        """Accept-risk dialog for INFO findings (card rebuild omitted; re-scan to reflect)."""
        root = self._inner.winfo_toplevel()
        _AcceptRiskDialog(root, f.get("check", ""), f.get("label", ""))

    def _toggle_info(self, _e=None):
        self._info_expanded = not self._info_expanded
        n = len(self._info_findings)
        if self._info_expanded:
            self._info_btn.configure(
                text=f"▼  Hide {n} informational item{'s' if n != 1 else ''}")
            self._info_body.pack(fill=tk.X, pady=(6, 0))
        else:
            self._info_btn.configure(
                text=f"▶  Show {n} informational item{'s' if n != 1 else ''}")
            self._info_body.pack_forget()
        self._inner.update_idletasks()
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def clear(self):
        self.hide_alert()
        for card in self._cards:
            card.destroy()
        self._cards.clear()
        self._findings.clear()
        self._selected.clear()
        self._info_findings.clear()
        if self._info_toggle and self._info_toggle.winfo_exists():
            self._info_toggle.destroy()
        self._info_toggle = None
        self._set_empty(True)
        self._canvas.yview_moveto(0)

    def scroll_to_top(self):
        self._canvas.yview_moveto(0.0)

    def show_alert(self, finding: dict) -> None:
        """Pin a plain-English headline card for the worst finding above the list."""
        sev   = finding.get("severity", "HIGH")
        col   = self._STRIPE.get(sev, C["HIGH"])
        label = finding.get("label", "")
        why   = finding.get("why", "")

        for w in self._alert_frame.winfo_children():
            w.destroy()

        stripe = tk.Frame(self._alert_frame, bg=col, width=5)
        stripe.pack(side=tk.LEFT, fill=tk.Y)
        stripe.pack_propagate(False)

        body = tk.Frame(self._alert_frame, bg=C["panel"])
        body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=9)

        top_row = tk.Frame(body, bg=C["panel"])
        top_row.pack(fill=tk.X)
        _sev_pill(top_row, self._SEV_CAP.get(sev, sev), col, "#ffffff").pack(
            side=tk.LEFT, padx=(0, 8))
        tk.Label(top_row, text=label,
                 bg=C["panel"], fg=C["text"],
                 font=T.font_ui(9, "bold"),
                 anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)

        if why:
            tk.Label(body, text=why,
                     bg=C["panel"], fg=C["muted"],
                     font=T.font_ui(8),
                     anchor="w", wraplength=520,
                     justify=tk.LEFT).pack(fill=tk.X, pady=(3, 0))

        if finding.get("fix_cmds") and self._on_fix_one:
            fix_col = tk.Frame(self._alert_frame, bg=C["panel"])
            fix_col.pack(side=tk.RIGHT, padx=12)
            ttk.Button(fix_col, text="Fix it →",
                       style="Accent.TButton",
                       command=lambda f=finding: self._on_fix_one(f)).pack(pady=10)

        if not self._alert_visible:
            self._alert_frame.pack(fill=tk.X, before=self._outer, pady=(0, 6))
            self._alert_visible = True

    def hide_alert(self) -> None:
        if self._alert_visible:
            self._alert_frame.pack_forget()
            self._alert_visible = False

    def get_fixable(self) -> list:
        return [f for f in self._findings
                if f.get("fix_cmds") and not f.get("_accepted")]

    def get_selected(self) -> list:
        """Currently unused — selection is per-card via Fix this button."""
        return []

    def mark_fixed(self, finding: dict):
        btn = finding.get("_fix_btn")
        if btn:
            try:
                btn.configure(state=tk.DISABLED, text="Fixed ✓")
            except tk.TclError:
                pass

    def set_fix_btn_state(self, enabled: bool):
        st = tk.NORMAL if enabled else tk.DISABLED
        for f in self._findings:
            btn = f.get("_fix_btn")
            if btn:
                try:
                    btn.configure(state=st)
                except tk.TclError:
                    pass

    # ── Card builder ──────────────────────────────────────────────────────────

    def _build_card(self, f: dict):
        card = tk.Canvas(self._inner, bg=C["bg"], highlightthickness=0, bd=0)
        card.pack(fill=tk.X, padx=12, pady=(8, 0))
        self._cards.append(card)
        self._render_card(card, f)

    def _render_card(self, card: tk.Canvas, f: dict):
        """Build the finding's content frame and embed it in `card` (a Canvas)
        over a rounded-rect background. The stripe, label, why-text and the
        Fix / ⋯ buttons are unchanged and stay clickable inside the content frame."""
        accepted = f.get("_accepted", False)
        sev      = f.get("severity", "REVIEW")
        stripe   = self._STRIPE.get(sev, C["muted"]) if not accepted else C["border"]
        sev_cap  = self._SEV_CAP.get(sev, sev.title())
        card_bg  = C["panel"] if not accepted else C["bg"]

        # Content frame is card_bg so its rectangular fill blends with the rounded
        # background; the corners reveal the parent surface (the Canvas bg).
        content = tk.Frame(card, bg=card_bg)

        tk.Frame(content, bg=stripe, width=4).pack(side=tk.LEFT, fill=tk.Y)

        body = tk.Frame(content, bg=card_bg)
        body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 8), pady=9)

        # Severity badge + check name row
        top = tk.Frame(body, bg=card_bg)
        top.pack(fill=tk.X)
        badge_bg = stripe if not accepted else C["input"]
        badge_fg = "#060a0f" if not accepted else C["muted"]
        _sev_pill(top, sev_cap, badge_bg, badge_fg).pack(side=tk.LEFT)
        check_txt = f.get("check", "")
        if check_txt:
            tk.Label(top, text=f"  {check_txt}",
                     bg=card_bg, fg=C["muted"],
                     font=T.font_ui(8)).pack(side=tk.LEFT)
        if accepted:
            tk.Label(top, text="  Accepted risk",
                     bg=card_bg, fg=C["ok"],
                     font=T.font_ui(7, "bold")).pack(side=tk.LEFT)
        elif f.get("revertable") is False:
            tk.Label(top, text="  Cannot be undone",
                     bg=card_bg, fg=C["muted"],
                     font=T.font_ui(7)).pack(side=tk.LEFT)

        title_fg = C["muted"] if accepted else C["text"]
        tk.Label(body, text=f.get("label", ""),
                 bg=card_bg, fg=title_fg,
                 font=T.font_ui(10, "bold"),
                 anchor="w", wraplength=500,
                 justify=tk.LEFT).pack(fill=tk.X, pady=(5, 2))

        why = f.get("why", "")
        if why and not accepted:
            tk.Label(body, text=why,
                     bg=card_bg, fg=C["muted"],
                     font=T.font_ui(9),
                     anchor="w", wraplength=500,
                     justify=tk.LEFT).pack(fill=tk.X)

        # Right-side action column
        right_f = tk.Frame(content, bg=card_bg)
        right_f.pack(side=tk.RIGHT, padx=(4, 8), pady=9)

        if f.get("fix_cmds") and self._on_fix_one and not accepted:
            btn = ttk.Button(right_f, text="Fix this →",
                              style="Fix.TButton",
                              command=lambda _f=f: self._on_fix_one(_f))
            btn.pack(pady=(0, 4))
            f["_fix_btn"] = btn

        # ⋯ overflow button → accept/unaccept risk
        overflow = ttk.Button(
            right_f, text="⋯", style="Dim.TButton", width=2,
            command=lambda _f=f, _c=card: self._open_overflow(_f, _c))
        overflow.pack()

        self._embed_rounded_card(card, content, card_bg)
        self._bind_scroll(card)

    def _embed_rounded_card(self, card: tk.Canvas, content: tk.Frame, card_bg: str):
        """Place `content` on `card` over a rounded-rect background sized to fit it.
        The canvas height tracks the content height; the rounded rect is redrawn on
        resize so corners stay crisp."""
        pad = 4   # inset so the rounded corners reveal the parent surface behind
        cid = card.create_window(pad, pad, window=content, anchor="nw")

        def _redraw(w, h):
            if w < 2 or h < 2:
                return
            card.delete("cardbg")
            T.round_rect(card, 1, 1, w - 1, h - 1, radius=T.RADIUS_CARD,
                         fill=card_bg, outline=C["border"], tags="cardbg")
            card.tag_lower("cardbg")

        def _on_canvas_cfg(e):
            card.itemconfigure(cid, width=e.width - 2 * pad)
            _redraw(e.width, card.winfo_height())

        def _on_content_cfg(e):
            h = e.height + 2 * pad
            if card.winfo_height() != h:
                card.configure(height=h)
            _redraw(card.winfo_width(), h)

        card.bind("<Configure>", _on_canvas_cfg)
        content.bind("<Configure>", _on_content_cfg)

    def _open_overflow(self, f: dict, card: tk.Frame):
        check = f.get("check", "")
        label = f.get("label", "")
        root  = card.winfo_toplevel()

        def _on_change():
            # Refresh the card's accepted state and rebuild it
            f["_accepted"] = ec.is_accepted_risk(check, label)
            idx = self._findings.index(f) if f in self._findings else -1
            if idx >= 0 and idx < len(self._cards):
                old = self._cards[idx]
                old.destroy()
                # Rebuild card in place
                placeholder = tk.Frame(self._inner, bg=C["bg"], height=0)
                placeholder.pack(fill=tk.X, padx=12)
                self._cards[idx] = placeholder
                self._build_card_at(f, idx)
                placeholder.destroy()

        _AcceptRiskDialog(root, check, label,
                          on_accept=_on_change, on_remove=_on_change)

    def _build_card_at(self, f: dict, idx: int):
        """Rebuild a single card at a specific index position."""
        cards_before = self._cards[:idx]
        card = tk.Canvas(self._inner, bg=C["bg"], highlightthickness=0, bd=0)
        # Pack after the card before us so position is preserved.
        if cards_before and cards_before[-1].winfo_exists():
            card.pack(fill=tk.X, padx=12, pady=(8, 0), after=cards_before[-1])
        else:
            card.pack(fill=tk.X, padx=12, pady=(8, 0))
        self._cards[idx] = card
        self._render_card(card, f)

    def _bind_scroll(self, widget):
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            widget.bind(seq, self._on_scroll)
        for child in widget.winfo_children():
            self._bind_scroll(child)


# ── ScanTab ────────────────────────────────────────────────────────────────────

_TAB_ICONS = {
    "Security": "◈", "Antivirus": "⊛", "Performance": "◉",
    "Protection": "◇", "Cleaner": "⊙",
}


class ScanTab:
    """One notebook tab: CenterStage + severity bars + findings cards + fix flow."""

    def __init__(self, notebook, title, score_label, app, run_fn,
                 session_tracker=None, revertable=True):
        self._title       = title
        self._score_label = score_label
        self.app          = app
        self._run_fn      = run_fn
        self._tracker     = session_tracker if revertable else None
        self._revertable  = revertable

        self._q:             queue.Queue = queue.Queue()
        self._findings:      list        = []
        self._reporter_data: dict        = {}
        self._scanning:      bool        = False
        self._last_html:     str         = ""
        self._post_fix_scan: bool        = False

        self.frame = ttk.Frame(notebook)
        icon   = _TAB_ICONS.get(title, "")
        tab_t  = f"  {icon}  {title}  " if icon else f"  {title}  "
        notebook.add(self.frame, text=tab_t)
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        main = tk.Frame(self.frame, bg=C["bg"])
        main.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        # ── Left panel ────────────────────────────────────────────────────────
        left = tk.Frame(main, bg=C["panel"], width=240)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left.pack_propagate(False)

        # Buttons pinned to bottom first so they're never clipped
        fix_f = tk.Frame(left, bg=C["panel"])
        fix_f.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(4, 10))

        tk.Frame(left, bg=C["border"], height=1).pack(
            side=tk.BOTTOM, fill=tk.X, padx=10)

        self._btn_fix_all = ttk.Button(fix_f, text="Fix all issues (0)",
                                       style="Fix.TButton",
                                       command=self._fix_all,
                                       state=tk.DISABLED)
        self._btn_fix_all.pack(fill=tk.X, pady=(0, 6))

        self._btn_scan = RoundButton(fix_f, text="▶  Scan now",
                                     bg=C["accent"], fg="#060a0f",
                                     command=self.start_scan)
        self._btn_scan.pack(fill=tk.X)

        # Score label + gauge (top of left panel)
        tk.Label(left, text=self._score_label,
                 bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(8, "bold")).pack(pady=(10, 4))

        self._stage = CenterStage(left, size=174)
        self._stage.pack(padx=12)

        self._coaching_lbl = tk.Label(left, text="",
                                       bg=C["panel"], fg=C["accent"],
                                       font=T.font_ui(8),
                                       wraplength=210, justify=tk.CENTER)
        self._coaching_lbl.pack(pady=(4, 0))

        # Score trend sparkline
        self._sparkline = _SparklineWidget(left, self._title)
        self._sparkline.pack(pady=(6, 0), padx=14)

        tk.Frame(left, bg=C["border"], height=1).pack(
            fill=tk.X, padx=12, pady=(10, 6))

        sev_f = tk.Frame(left, bg=C["panel"])
        sev_f.pack(fill=tk.X, padx=10)
        self._sev_rows: dict = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "REVIEW"):
            row = _SevRow(sev_f, sev)
            row.pack(fill=tk.X, pady=2)
            self._sev_rows[sev] = row

        # Compliance profile selector
        tk.Frame(left, bg=C["border"], height=1).pack(
            fill=tk.X, padx=12, pady=(8, 4))
        comp_f = tk.Frame(left, bg=C["panel"])
        comp_f.pack(fill=tk.X, padx=10, pady=(0, 6))
        tk.Label(comp_f, text="Compliance", bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(7, "bold")).pack(anchor="w")
        self._compliance_var = tk.StringVar(value="General")
        comp_cb = ttk.Combobox(comp_f, textvariable=self._compliance_var,
                                values=ec.COMPLIANCE_PROFILES,
                                state="readonly", width=20)
        comp_cb.pack(fill=tk.X, pady=(2, 0))
        self._compliance_lbl = tk.Label(comp_f, text="",
                                         bg=C["panel"], fg=C["accent"],
                                         font=T.font_ui(7),
                                         wraplength=200)
        self._compliance_lbl.pack(anchor="w", pady=(2, 0))

        # ── Right: findings cards ──────────────────────────────────────────────
        right = tk.Frame(main, bg=C["bg"])
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._pane = _FindingsPane(right, on_fix_one=self._fix_one)

    # ── Scan ──────────────────────────────────────────────────────────────────

    def start_scan(self):
        if self._scanning:
            return
        self._clear_results()
        self._scanning = True
        self._btn_scan.configure(state=tk.DISABLED)
        self.app._progress.start(10)
        self._stage.start_scan()
        self.app._set_status(f"Scanning {self._title}…")
        self.app._log_append(f"\n── {self._title} scan ──\n", "hdr")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        reporter = _UIReporter(self._q)
        try:
            self._run_fn(reporter)
            self._reporter_data = reporter._data
        except Exception as exc:
            self._q.put(("log", (f"Scan error: {exc}\n", "err")))
        finally:
            self._q.put(("done_scan", None))

    # ── Fix ───────────────────────────────────────────────────────────────────

    def _fix_all(self):
        to_fix = self._pane.get_fixable()
        if to_fix:
            self._confirm_and_fix(to_fix)

    def _fix_one(self, finding: dict):
        if finding.get("fix_cmds"):
            self._confirm_and_fix([finding])

    def _confirm_and_fix(self, findings):
        if not _is_root() and not _elevation_available():
            _show_fix_denied_dialog(self.app.root, findings)
            return

        # Pre-flight: warn if disk is critically low
        disk_warn = ec._remediate._check_disk_space(min_mb=50)
        if disk_warn:
            if not messagebox.askyesno(
                "Low disk space",
                f"⚠  {disk_warn}\n\nSome fixes write to disk and may fail. Continue anyway?",
                parent=self.frame,
            ):
                return

        # Show the real commands + reversibility status before anything runs.
        if not _confirm_fix_dialog(self.frame, findings):
            return

        if self._tracker:
            if not self._tracker.before_fix(self._title):
                messagebox.showerror(
                    "Snapshot failed",
                    "Could not capture the current system state before applying fixes.\n\n"
                    "The fix has been aborted to protect your configuration.\n"
                    "This may happen if the app lacks read access to system files.",
                    parent=self.frame,
                )
                return
            self.app._refresh_revert_btn()

        self.app.set_gull_fixing(True)
        self._pane.set_fix_btn_state(False)
        self._btn_fix_all.configure(state=tk.DISABLED, style="Dim.TButton",
                                    text="Fixing…")
        self._btn_scan.configure(state=tk.DISABLED)
        self.app._progress.start(10)
        self.app._set_status("Gull is on it — applying fixes…")
        threading.Thread(target=self._fix_worker, args=(findings,),
                         daemon=True).start()

    def _fix_worker(self, findings):
        try:
            self._fix_worker_inner(findings)
        except Exception as exc:
            self._q.put(("log", (f"  ✗ Internal error: {exc}\n", "err")))
            self._q.put(("done_fix", False))

    def _fix_worker_inner(self, findings):
        self._q.put(("log", ("\n── Applying fixes ──\n", "hdr")))
        results = _batch_fix_elevated(findings)

        if results is None:
            self._q.put(("log",
                         ("  ✗ No admin tool available. Use 'Copy Commands'.\n",
                          "err")))
            self._q.put(("done_fix", False))
            return

        cmd_idx = 0
        failed  = 0
        for finding in findings:
            cmds  = finding.get("fix_cmds", [])
            n     = len(cmds)
            batch = results[cmd_idx:cmd_idx + n]
            cmd_idx += n
            all_ok = all(rc == 0 for _, rc, _ in batch)
            label  = finding.get("label", "Unknown issue")
            if all_ok:
                self._q.put(("log",       (f"  ✓  {label}\n", "ok")))
                self._q.put(("mark_fixed", finding))
            else:
                failed += 1
                self._q.put(("log", (f"  ✗  {label}\n", "err")))
                for _, rc, out in batch:
                    if rc != 0:
                        raw = out.strip()[:200] if out.strip() else f"(exit code {rc})"
                        if "122" in raw or "quota exceeded" in raw.lower():
                            raw = "disk quota exceeded — free up disk space before applying fixes"
                        elif "no space left" in raw.lower():
                            raw = "no space left on device — free up disk space before applying fixes"
                        self._q.put(("log", (f"      {raw}\n", "muted")))

        self._q.put(("done_fix", failed == 0))

    # ── Queue consumer ─────────────────────────────────────────────────────────

    def poll(self):
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "status":
                    self.app._set_status(payload)
                    if self._scanning:
                        self._stage.update_check(payload)
                elif kind == "finding":
                    self._add_row(payload)
                    sev    = payload["severity"]
                    tag    = sev.lower() if sev in ("CRITICAL", "HIGH") else "muted"
                    bullet = "●" if sev in ("CRITICAL", "HIGH") else "·"
                    self.app._log_append(
                        f"  {bullet} {sev.title()}: {payload['label']}\n", tag)
                elif kind == "log":
                    self.app._log_append(*payload)
                elif kind == "mark_fixed":
                    self._pane.mark_fixed(payload)
                elif kind == "done_scan":
                    self._finish_scan()
                elif kind == "done_fix":
                    self._finish_fix(payload)
        except queue.Empty:
            pass

    # ── Findings helpers ──────────────────────────────────────────────────────

    def _add_row(self, f: dict):
        f["_accepted"] = ec.is_accepted_risk(f.get("check", ""), f.get("label", ""))
        self._findings.append(f)
        self._pane.add_finding(f)
        self._refresh_btns()

    def _clear_results(self):
        self._findings.clear()
        self._reporter_data = {}
        self._last_html     = ""
        self._pane.clear()
        self._coaching_lbl.configure(text="")
        self._compliance_lbl.configure(text="")
        for row in self._sev_rows.values():
            row.reset()
        self._refresh_btns()

    def _refresh_btns(self):
        fixable = self._pane.get_fixable()
        n_fix   = len(fixable)
        self._btn_fix_all.configure(
            text=f"Fix all issues ({n_fix})",
            state=tk.NORMAL if fixable else tk.DISABLED,
            style="Fix.TButton" if fixable else "Dim.TButton",
        )

    def _update_score_panel(self):
        counts: dict = {}
        for f in self._findings:
            s = f.get("severity", "")
            counts[s] = counts.get(s, 0) + 1
        max_c = max(counts.values(), default=1)
        for sev, row in self._sev_rows.items():
            row.update(counts.get(sev, 0), max_c)
        if self._reporter_data:
            score, grade = ec._compute_score(self._reporter_data)
            self._stage.show_score(score, grade)
            return score, grade
        return 0, "—"

    # ── Finish callbacks ──────────────────────────────────────────────────────

    def _finish_scan(self):
        self._scanning = False
        self.app._progress.stop()
        self._btn_scan.configure(state=tk.NORMAL)

        score, grade = self._update_score_panel()
        # Guarantee the radar sweep stops even when a scan errored or produced no
        # report data — otherwise _update_score_panel never calls show_score and
        # the radar spins forever on that tab.
        if not self._reporter_data:
            self._stage.reset()
        n = len(self._findings)
        counts: dict = {}
        for f in self._findings:
            s = f.get("severity", "")
            counts[s] = counts.get(s, 0) + 1
        parts = [f"{counts[s]} {s}"
                 for s in ("CRITICAL", "HIGH", "MEDIUM") if counts.get(s)]
        detail = " · ".join(parts) if parts else "no issues found"
        lbl    = _GRADE_LABEL.get(grade, "")
        self.app._set_status(
            f"{self._title}  —  {lbl}  {score}/100 {grade}"
            f"  ·  {n} finding(s)  ({detail})")
        self._refresh_btns()

        # Grade coaching line
        c_crit = counts.get("CRITICAL", 0)
        c_high = counts.get("HIGH", 0)
        if grade == "A":
            coaching = "All clear. Outstanding."
        elif grade == "B":
            coaching = "Good shape — fix critical issues for A."
        elif c_crit > 0:
            s = "s" if c_crit > 1 else ""
            coaching = f"Fix {c_crit} critical issue{s} to reach B."
        elif c_high > 0:
            s = "s" if c_high > 1 else ""
            coaching = f"Fix {c_high} high issue{s} to improve."
        else:
            coaching = "Address medium issues to reach A."
        self._coaching_lbl.configure(text=coaching)

        worst = next(
            (f for sev in ("CRITICAL", "HIGH")
             for f in self._findings
             if f.get("severity") == sev and not f.get("_accepted")),
            None,
        )
        if worst:
            self._pane.show_alert(worst)
            self._pane.scroll_to_top()
        else:
            self._pane.hide_alert()

        # Save history + refresh sparkline
        ec.save_scan_history(self._title, score, grade, counts)
        self._sparkline.push(score, grade)
        self.app._refresh_last_scan_badge()

        # Compliance score
        profile = self._compliance_var.get()
        passing, total, pct = ec.compliance_score(self._reporter_data, profile)
        if pct is not None:
            col = C["ok"] if pct >= 80 else (C["MEDIUM"] if pct >= 50 else C["err"])
            self._compliance_lbl.configure(
                text=f"{pct}% compliant  ({passing}/{total} checks passing)",
                fg=col)
        else:
            self._compliance_lbl.configure(text="")

        # Pre-generate HTML for "Open Report"
        if self._reporter_data:
            try:
                fd, path = tempfile.mkstemp(suffix=".html", prefix="ec-")
                os.close(fd)
                tmp = ec._Reporter(json_mode=True)
                tmp._data = self._reporter_data
                tmp.write_to(path)
                self._last_html = path
            except Exception:
                pass

        # Sort visible cards, collapse INFO noise, refresh Overview counts.
        # Never auto-navigate — the user picks their own tab.
        self._pane.flush_info_group()
        if hasattr(self.app, "_tab_overview"):
            self.app._tab_overview.refresh()
        self._post_fix_scan = False

    def _finish_fix(self, success: bool):
        self.app.set_gull_fixing(False)
        self.app._progress.stop()
        self._btn_scan.configure(state=tk.NORMAL)
        self._pane.set_fix_btn_state(True)
        self._refresh_btns()
        # Always rescan after a fix attempt so the UI reflects the new state —
        # even if some commands failed, others may have succeeded.
        if success:
            self.app._set_status("Fixes applied — rescanning all tabs in 2s…")
            self.app._log_append("\nFixes applied. Rescanning all tabs…\n", "ok")
        else:
            self.app._set_status("Some fixes failed — rescanning all tabs in 2s…")
            self.app._log_append(
                "\nSome fixes failed. Rescanning all tabs to refresh state…\n", "err")
        self.app._note_windows_revert_scope()
        self.frame.after(2000, self.app._rescan_populated_tabs)

    # ── Report helpers ─────────────────────────────────────────────────────────

    def open_report(self):
        if not self._reporter_data:
            messagebox.showinfo("No report", "Run a scan first.")
            return
        if self._last_html and os.path.exists(self._last_html):
            import pathlib
            webbrowser.open(pathlib.Path(self._last_html).resolve().as_uri())
        else:
            messagebox.showinfo("Not ready", "Report not yet generated.")

    def save_report(self):
        if not self._reporter_data:
            messagebox.showinfo("No report", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"),
                       ("JSON report", "*.json"),
                       ("All files",   "*.*")],
            initialfile=f"report-{self._title.lower()}.html",
        )
        if not path:
            return
        tmp = ec._Reporter(json_mode=True)
        tmp._data = self._reporter_data
        err = tmp.write_to(path)
        if err:
            messagebox.showerror("Save failed", err)
        else:
            self.app._set_status(f"Saved → {path}")


# ── Overview tab ───────────────────────────────────────────────────────────────

class OverviewTab:
    """First notebook tab: cross-tab Safety / Speed summary with one-click Fix recommended.

    Safety column  — Security, Protection, Antivirus scan tabs.
    Speed column   — Performance, Cleaner scan tabs.
    INFO findings are excluded from all counts (they are presentation-noise).
    Each count badge is a clickable label that selects the relevant ScanTab.
    "Fix recommended" collects every CRITICAL/HIGH fix_cmd from all scan tabs
    and runs them via _batch_fix_elevated in a single elevation prompt.
    """

    # (tab-attr-name, display-name, column)
    _TAB_COLS = [
        ("_tab_security",     "Security",    "safety"),
        ("_tab_protection",   "Protection",  "safety"),
        ("_tab_antivirus",    "Antivirus",   "safety"),
        ("_tab_performance",  "Performance", "speed"),
        ("_tab_cleaner",      "Cleaner",     "speed"),
    ]

    def __init__(self, notebook, app):
        self._nb  = notebook
        self._app = app
        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text="  ◈  Overview  ")
        self._build()

    def _build(self):
        outer = tk.Frame(self.frame, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)

        hdr = tk.Frame(outer, bg=C["bg"])
        hdr.pack(fill=tk.X, pady=(0, 14))
        tk.Label(hdr, text="System Overview",
                 bg=C["bg"], fg=C["text"],
                 font=T.font_ui(14, "bold")).pack(side=tk.LEFT)
        self._hint = tk.Label(hdr,
                              text="Run a scan on any tab to see results here.",
                              bg=C["bg"], fg=C["muted"],
                              font=T.font_ui(9))
        self._hint.pack(side=tk.RIGHT)

        cols = tk.Frame(outer, bg=C["bg"])
        cols.pack(fill=tk.BOTH, expand=True)

        self._safety_body = self._make_column(cols, "Safety",  side=tk.LEFT,  padx=(0, 8))
        self._speed_body  = self._make_column(cols, "Speed",   side=tk.LEFT,  padx=(8, 0))

        fix_row = tk.Frame(outer, bg=C["bg"])
        fix_row.pack(pady=(18, 0), anchor="w")
        self._btn_fix = RoundButton(fix_row,
                                    text="Fix recommended  (0 issues)",
                                    bg=C["ok"], fg="#060a0f",
                                    state=tk.DISABLED,
                                    command=self._fix_recommended)
        self._btn_fix.pack(side=tk.LEFT)

    def _make_column(self, parent, title, side, padx):
        col = tk.Frame(parent, bg=C["panel"],
                       highlightthickness=1, highlightbackground=C["border"])
        col.pack(side=side, fill=tk.BOTH, expand=True, padx=padx)
        tk.Label(col, text=title.upper(),
                 bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(9, "bold"),
                 padx=14, pady=10).pack(anchor="w")
        tk.Frame(col, bg=C["border"], height=1).pack(fill=tk.X, padx=12)
        body = tk.Frame(col, bg=C["panel"])
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)
        return body

    def refresh(self):
        """Rebuild counts from live ScanTab findings. Called after every scan."""
        for w in self._safety_body.winfo_children():
            w.destroy()
        for w in self._speed_body.winfo_children():
            w.destroy()

        total_fixable = 0
        has_any_data  = False

        for attr, display_name, col in self._TAB_COLS:
            tab = getattr(self._app, attr, None)
            if tab is None:
                continue
            body = self._safety_body if col == "safety" else self._speed_body
            findings = getattr(tab, "_findings", [])
            if findings:
                has_any_data = True
            ch = sum(1 for f in findings
                     if f.get("severity") in ("CRITICAL", "HIGH")
                     and not f.get("_accepted"))
            mr = sum(1 for f in findings
                     if f.get("severity") in ("MEDIUM", "REVIEW"))
            fix = sum(1 for f in findings
                      if f.get("severity") in ("CRITICAL", "HIGH")
                      and f.get("fix_cmds") and not f.get("_accepted"))
            total_fixable += fix
            self._build_tab_row(body, tab, display_name, ch, mr)

        noun = "issue" if total_fixable == 1 else "issues"
        if total_fixable > 0:
            self._btn_fix.configure(
                text=f"Fix recommended  ({total_fixable} {noun})",
                state=tk.NORMAL, style="Fix.TButton")
        else:
            self._btn_fix.configure(
                text="Fix recommended  (0 issues)",
                state=tk.DISABLED, style="Dim.TButton")

        self._hint.configure(
            text="" if has_any_data
            else "Run a scan on any tab to see results here.")

    def _build_tab_row(self, parent, tab, name, ch, mr):
        row = tk.Frame(parent, bg=C["panel"])
        row.pack(fill=tk.X, pady=3)

        tk.Label(row, text=name, bg=C["panel"], fg=C["text"],
                 font=T.font_ui(9), width=13, anchor="w").pack(side=tk.LEFT)

        # CRITICAL / HIGH count — recommended fixes
        if ch > 0:
            ch_col = C["CRITICAL"]
            ch_txt = f"⚠ {ch} recommended"
            ch_cur = "hand2"
        else:
            ch_col = C["muted"]
            ch_txt = "0 recommended"
            ch_cur = ""
        ch_lbl = tk.Label(row, text=ch_txt, bg=C["panel"], fg=ch_col,
                          font=T.font_ui(8, "bold" if ch > 0 else "normal"),
                          padx=6, pady=3, cursor=ch_cur)
        ch_lbl.pack(side=tk.LEFT, padx=(4, 2))
        if ch > 0:
            ch_lbl.bind("<Button-1>", lambda _e, t=tab: self._nb.select(t.frame))
            ch_lbl.bind("<Enter>",    lambda _e, w=ch_lbl: w.configure(fg=C["accent"]))
            ch_lbl.bind("<Leave>",    lambda _e, w=ch_lbl, c=ch_col: w.configure(fg=c))

        # MEDIUM / REVIEW count — worth a look
        if mr > 0:
            mr_col = C["MEDIUM"]
            mr_txt = f"{mr} to review"
            mr_cur = "hand2"
        else:
            mr_col = C["muted"]
            mr_txt = "0 to review"
            mr_cur = ""
        mr_lbl = tk.Label(row, text=mr_txt, bg=C["panel"], fg=mr_col,
                          font=T.font_ui(8),
                          padx=6, pady=3, cursor=mr_cur)
        mr_lbl.pack(side=tk.LEFT, padx=2)
        if mr > 0:
            mr_lbl.bind("<Button-1>", lambda _e, t=tab: self._nb.select(t.frame))
            mr_lbl.bind("<Enter>",    lambda _e, w=mr_lbl: w.configure(fg=C["accent"]))
            mr_lbl.bind("<Leave>",    lambda _e, w=mr_lbl, c=mr_col: w.configure(fg=c))

    # ── Fix recommended ───────────────────────────────────────────────────────

    def _fix_recommended(self):
        all_fixable = []
        for attr, _, _ in self._TAB_COLS:
            tab = getattr(self._app, attr, None)
            if tab is None:
                continue
            for f in getattr(tab, "_findings", []):
                if (f.get("severity") in ("CRITICAL", "HIGH")
                        and f.get("fix_cmds")
                        and not f.get("_accepted")):
                    all_fixable.append(f)

        if not all_fixable:
            return

        if not _is_root() and not _elevation_available():
            _show_fix_denied_dialog(self._app.root, all_fixable)
            return

        disk_warn = ec._remediate._check_disk_space(min_mb=50)
        if disk_warn:
            if not messagebox.askyesno(
                "Low disk space",
                f"⚠  {disk_warn}\n\nSome fixes write to disk and may fail. Continue anyway?",
                parent=self.frame,
            ):
                return

        # Show the real commands + reversibility status before anything runs.
        if not _confirm_fix_dialog(self.frame, all_fixable):
            return

        if not self._app._tracker.before_fix("Overview"):
            messagebox.showerror(
                "Snapshot failed",
                "Could not capture the current system state before applying fixes.\n\n"
                "The fix has been aborted to protect your configuration.\n"
                "This may happen if the app lacks read access to system files.",
                parent=self.frame,
            )
            return
        self._app._refresh_revert_btn()
        self._app.set_gull_fixing(True)
        self._btn_fix.configure(state=tk.DISABLED, text="Fixing…", style="Dim.TButton")
        self._app._progress.start(10)
        self._app._set_status("Gull is on it — applying recommended fixes…")
        threading.Thread(target=self._fix_worker, args=(all_fixable,),
                         daemon=True).start()

    def _fix_worker(self, findings):
        try:
            results = _batch_fix_elevated(findings)
            self.frame.after(0, lambda: self._finish_fix(findings, results))
        except Exception as exc:
            self.frame.after(0, lambda: self._finish_fix(findings, None, str(exc)))

    def _finish_fix(self, findings, results, err=None):
        self._app.set_gull_fixing(False)
        self._app._progress.stop()

        if err or results is None:
            self._app._log_append(
                f"\n  ✗ Overview fix error: {err or 'no admin tool available'}\n", "err")
            self._app._set_status("Fix failed — check Scan activity.")
            self.refresh()
            return

        self._app._log_append("\n── Overview: recommended fixes ──\n", "hdr")
        failed = 0
        idx    = 0
        for f in findings:
            n     = len(f.get("fix_cmds", []))
            batch = results[idx: idx + n]
            idx  += n
            ok    = all(rc == 0 for _, rc, _ in batch)
            if not ok:
                failed += 1
            icon, tag = ("✓", "ok") if ok else ("✗", "err")
            self._app._log_append(f"  {icon}  {f.get('label', '')}\n", tag)

        if failed == 0:
            self._app._set_status("Recommended fixes applied — rescanning in 2s…")
            self._app._log_append("\nFixes applied. Rescanning now…\n", "ok")
            self.frame.after(2000, self._rescan_tabs_with_data)
        else:
            self._app._set_status("Some fixes failed — check Scan activity.")
        self._app._note_windows_revert_scope()
        self.refresh()

    def _rescan_tabs_with_data(self):
        self._app._rescan_populated_tabs()


# ── Snapshots tab ──────────────────────────────────────────────────────────────

class SnapshotsTab:
    """4th notebook tab: save / restore / delete system state snapshots."""

    def __init__(self, notebook, app):
        self.app   = app
        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text="  ⊞  Snapshots  ")
        self._build()

    def _build(self):
        outer = tk.Frame(self.frame, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)

        # Top controls
        ctrl = tk.Frame(outer, bg=C["bg"])
        ctrl.pack(fill=tk.X, pady=(0, 10))
        tk.Label(ctrl, text="SYSTEM SNAPSHOTS", bg=C["bg"], fg=C["muted"],
                 font=T.font_ui(8, "bold")).pack(side=tk.LEFT)
        tk.Label(ctrl,
                 text="Save a point-in-time backup of system config. "
                      "Restore any snapshot to roll back changes.",
                 bg=C["bg"], fg=C["INFO"],
                 font=T.font_ui(8)).pack(side=tk.LEFT, padx=(12, 0))

        # Buttons
        btn_f = tk.Frame(outer, bg=C["bg"])
        btn_f.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(btn_f, text="📸  Save Snapshot Now",
                   style="Accent.TButton",
                   command=self._save_snap).pack(side=tk.LEFT, padx=(0, 8))
        self._btn_restore = ttk.Button(btn_f, text="Restore Selected",
                                       state=tk.DISABLED,
                                       command=self._restore_snap)
        self._btn_restore.pack(side=tk.LEFT, padx=(0, 4))
        self._btn_delete = ttk.Button(btn_f, text="Delete",
                                      state=tk.DISABLED,
                                      command=self._delete_snap)
        self._btn_delete.pack(side=tk.LEFT)

        # Treeview
        cols = ("timestamp", "host", "label", "path")
        self._tree = ttk.Treeview(outer, columns=cols, show="headings",
                                   selectmode="browse")
        self._tree.heading("timestamp", text="DATE / TIME")
        self._tree.heading("host",      text="HOST")
        self._tree.heading("label",     text="LABEL")
        self._tree.heading("path",      text="FILE")
        self._tree.column("timestamp", width=160, stretch=False)
        self._tree.column("host",      width=130, stretch=False)
        self._tree.column("label",     width=220)
        self._tree.column("path",      width=999)
        vsb = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        self._snap_map: dict = {}  # iid → (fpath, snap)
        self._refresh()

    def _refresh(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._snap_map.clear()
        for fpath, snap in ec.list_snapshots():
            ts  = snap.get("timestamp", "")[:19].replace("T", " ")
            host = snap.get("hostname", "?")
            lbl  = snap.get("label", "")
            iid = self._tree.insert("", tk.END,
                                     values=(ts, host, lbl, fpath))
            self._snap_map[iid] = (fpath, snap)
        self._on_select(None)

    def _on_select(self, _event):
        sel = self._tree.selection()
        active = bool(sel)
        self._btn_restore.configure(state=tk.NORMAL if active else tk.DISABLED)
        self._btn_delete.configure(state=tk.NORMAL if active else tk.DISABLED)

    def _save_snap(self):
        label = ""
        dlg = tk.Toplevel(self.app.root)
        dlg.title("Save Snapshot")
        dlg.configure(bg=C["panel"])
        dlg.resizable(False, False)
        dlg.transient(self.app.root)
        dlg.grab_set()
        tk.Label(dlg, text="Snapshot label (optional):",
                 bg=C["panel"], fg=C["text"]).pack(padx=20, pady=(16, 4))
        var = tk.StringVar(value=f"Manual {datetime.datetime.now().strftime('%d %b %H:%M')}")
        ent = ttk.Entry(dlg, textvariable=var, width=36)
        ent.pack(padx=20, pady=(0, 12))
        ent.select_range(0, tk.END)
        ent.focus_set()

        def _ok():
            nonlocal label
            label = var.get().strip()
            dlg.destroy()

        bf = tk.Frame(dlg, bg=C["panel"])
        bf.pack(pady=(0, 16))
        ttk.Button(bf, text="Save", style="Accent.TButton",
                   command=_ok).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(bf, text="Cancel", command=dlg.destroy).pack(side=tk.LEFT)
        dlg.bind("<Return>", lambda _: _ok())
        self.app.root.wait_window(dlg)

        if label is None:
            return
        snap  = ec.take_snapshot(label=label)
        fpath = ec.save_snapshot(snap)
        self.app._set_status(f"Snapshot saved → {fpath}")
        self._refresh()

    def _restore_snap(self):
        sel = self._tree.selection()
        if not sel:
            return
        fpath, snap = self._snap_map[sel[0]]
        ts  = snap.get("timestamp", "")[:19].replace("T", " ")
        lbl = snap.get("label", "")
        if not messagebox.askyesno(
            "Restore Snapshot",
            f"Restore snapshot from {ts}?\n\"{lbl}\"\n\n"
            "This will overwrite current SSH config and firewall rules. "
            "You may be prompted for your password.",
        ):
            return

        self.app._set_status("Restoring snapshot…")
        self.app._progress.start(10)

        def _worker():
            results = ec.restore_snapshot(snap)
            self.frame.after(0, lambda: self._finish_restore(results))

        threading.Thread(target=_worker, daemon=True).start()

    def _finish_restore(self, results):
        self.app._progress.stop()
        ok_n   = sum(1 for _, s, _ in results if s)
        fail_n = sum(1 for _, s, _ in results if not s)
        self.app._log_append("\n── Snapshot restore ──\n", "hdr")
        for action, success, detail in results:
            tag  = "ok" if success else "err"
            icon = "✓" if success else "✗"
            self.app._log_append(f"  {icon} {action}"
                                  + (f": {detail}" if detail else "") + "\n", tag)
        self.app._set_status(
            f"Restore complete — {ok_n} ok, {fail_n} failed")

    def _delete_snap(self):
        sel = self._tree.selection()
        if not sel:
            return
        fpath, snap = self._snap_map[sel[0]]
        if not messagebox.askyesno("Delete Snapshot",
                                    f"Delete snapshot?\n{fpath}"):
            return
        ec.delete_snapshot(fpath)
        self._refresh()
        self.app._set_status("Snapshot deleted.")


# ── Benchmark Tab ──────────────────────────────────────────────────────────────

class BenchmarkTab:
    """Animated medieval village flythrough + hardware benchmark."""

    _TIERS = [
        (90, "S", "#ffd700"), (75, "A", "#00e87a"), (60, "B", "#00d4ff"),
        (45, "C", "#ffcc00"), (30, "D", "#ff8822"), (0,  "F", "#ff4455"),
    ]

    def __init__(self, nb, app):
        self.frame = ttk.Frame(nb)
        nb.add(self.frame, text="Benchmark")
        self._app  = app
        self._t    = 0.0
        self._running     = False
        self._bench_start = 0.0
        self._frame_count = 0
        self._results: dict = {}
        self._build()
        self._anim_tick()

    def _build(self):
        outer = tk.Frame(self.frame, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)

        self._canvas = tk.Canvas(outer, bg="#05080f", highlightthickness=0, height=300)
        self._canvas.pack(fill=tk.X)

        # ── control bar ────────────────────────────────────────────────────────
        ctrl = tk.Frame(outer, bg=C["panel"])
        ctrl.pack(fill=tk.X)
        self._status_lbl = tk.Label(ctrl, text="Press  ▶ RUN  to start  (~12 s)",
                                    bg=C["panel"], fg=C["muted"],
                                    font=T.font_ui(9))
        self._status_lbl.pack(side=tk.LEFT, padx=12, pady=8)
        self._run_btn = tk.Button(ctrl, text="▶  RUN BENCHMARK",
                                  bg=C["accent"], fg=C["bg"],
                                  font=T.font_ui(10, "bold"),
                                  relief=tk.FLAT, padx=14, pady=5,
                                  cursor="hand2", command=self._start)
        self._run_btn.pack(side=tk.RIGHT, padx=12, pady=6)

        # progress strip
        self._prog = tk.Canvas(outer, bg=C["border"], height=3, highlightthickness=0)
        self._prog.pack(fill=tk.X)

        # ── result cards ────────────────────────────────────────────────────────
        grid = tk.Frame(outer, bg=C["bg"])
        grid.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        metrics = [
            ("cpu_hash",   "CPU Hash",    "SHA-256 throughput"),
            ("cpu_float",  "CPU Float",   "Trig Mop/s"),
            ("memory",     "Memory BW",   "Read/write bandwidth"),
            ("disk",       "Disk Write",  "Sequential MB/s"),
            ("render_fps", "Render FPS",  "Canvas frames/s"),
        ]
        self._result_vars: dict = {}
        for i, (key, label, desc) in enumerate(metrics):
            col, row = i % 2, i // 2
            card = tk.Frame(grid, bg=C["panel"],
                            highlightthickness=1, highlightbackground=C["border"])
            card.grid(row=row, column=col, padx=4, pady=3, sticky="ew")
            grid.grid_columnconfigure(col, weight=1)
            tk.Label(card, text=label, bg=C["panel"], fg=C["text"],
                     font=T.font_ui(9, "bold")).pack(anchor="w", padx=8, pady=(5,0))
            tk.Label(card, text=desc, bg=C["panel"], fg=C["muted"],
                     font=T.font_ui(7)).pack(anchor="w", padx=8)
            vf = tk.Frame(card, bg=C["panel"])
            vf.pack(fill=tk.X, padx=8, pady=(1,6))
            val_v  = tk.StringVar(value="—")
            tier_v = tk.StringVar(value="")
            tk.Label(vf, textvariable=val_v, bg=C["panel"], fg=C["accent"],
                     font=("TkFixedFont", 11, "bold")).pack(side=tk.LEFT)
            tl = tk.Label(vf, textvariable=tier_v, bg=C["panel"],
                          font=T.font_ui(11, "bold"))
            tl.pack(side=tk.RIGHT)
            self._result_vars[key] = (val_v, tier_v, tl)

        total_card = tk.Frame(grid, bg=C["panel"],
                              highlightthickness=1, highlightbackground=C["border"])
        total_card.grid(row=3, column=0, columnspan=2, padx=4, pady=3, sticky="ew")
        self._grade_lbl  = tk.Label(total_card, text="—", bg=C["panel"],
                                    fg=C["muted"], font=T.font_ui(30, "bold"))
        self._grade_lbl.pack(side=tk.LEFT, padx=14, pady=6)
        sf = tk.Frame(total_card, bg=C["panel"])
        sf.pack(side=tk.LEFT, pady=6)
        tk.Label(sf, text="OVERALL", bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(7)).pack(anchor="w")
        self._score_lbl = tk.Label(sf, text="—", bg=C["panel"], fg=C["text"],
                                   font=T.font_ui(11, "bold"))
        self._score_lbl.pack(anchor="w")

    def _tier(self, score):
        for min_s, label, color in self._TIERS:
            if score >= min_s:
                return label, color
        return "F", "#ff4455"

    def _start(self):
        if self._running:
            return
        self._running     = True
        self._frame_count = 0
        self._bench_start = time.time()
        self._results     = {}
        self._run_btn.configure(state=tk.DISABLED, text="Running…")
        self._status_lbl.configure(text="Benchmarking…", fg=C["accent"])
        for _, (vv, tv, tl) in self._result_vars.items():
            vv.set("…"); tv.set("")
        self._grade_lbl.configure(text="…", fg=C["muted"])
        self._score_lbl.configure(text="…")
        threading.Thread(target=self._bench_thread, daemon=True).start()

    def _post(self, key, text, score):
        label, color = self._tier(score)
        def _up():
            if key in self._result_vars:
                vv, tv, tl = self._result_vars[key]
                vv.set(text)
                tv.set(f"  {label}")
                tl.configure(fg=color)
            self._results[key] = score
            self._update_total()
        self.frame.after(0, _up)

    def _update_total(self):
        if not self._results:
            return
        avg = sum(self._results.values()) / len(self._results)
        label, color = self._tier(avg)
        self._grade_lbl.configure(text=label, fg=color)
        self._score_lbl.configure(text=f"Score  {avg:.0f} / 100")

    def _bench_thread(self):
        import hashlib, tempfile

        def upd(msg):
            self.frame.after(0, lambda: self._status_lbl.configure(text=msg))

        # CPU hash (~3 s)
        upd("CPU hash benchmark…")
        t0 = time.time(); n = 0; chunk = b"x" * 4096
        while time.time() - t0 < 3.0:
            hashlib.sha256(chunk).digest(); n += 1
        rate = n * 4096 / 3.0 / 1e6
        self._post("cpu_hash", f"{rate:.0f} MB/s", min(100, int(rate / 12)))

        # CPU float (~2 s)
        upd("CPU float benchmark…")
        t0 = time.time(); n = 0
        while time.time() - t0 < 2.0:
            for j in range(500):
                math.sin(n * 0.001) * math.cos(n * 0.002)
            n += 500
        rate_m = n / 2.0 / 1e6
        self._post("cpu_float", f"{rate_m:.1f} Mop/s", min(100, int(rate_m / 2)))

        # Memory (~2 s)
        upd("Memory bandwidth benchmark…")
        buf = bytearray(64 * 1024 * 1024)
        t0 = time.time(); nb = 0
        while time.time() - t0 < 2.0:
            memoryview(buf)[0] = 1; _ = memoryview(buf)[-1]
            nb += len(buf)
        rate_gb = nb / (time.time() - t0) / 1e9
        self._post("memory", f"{rate_gb:.1f} GB/s", min(100, int(rate_gb / 0.3)))

        # Disk (~2 s)
        upd("Disk write benchmark…")
        total_b = 0; t_total = 0.001
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".gwbench") as f:
                fname = f.name; chunk_d = b"G" * (256 * 1024)
                t0 = time.time()
                while time.time() - t0 < 2.0:
                    f.write(chunk_d); total_b += len(chunk_d)
                t_total = time.time() - t0
            os.unlink(fname)
        except OSError:
            pass
        rate_mb = total_b / t_total / 1e6
        self._post("disk", f"{rate_mb:.0f} MB/s", min(100, int(rate_mb / 5)))

        # Render FPS (frames we drew while benchmarking)
        elapsed = time.time() - self._bench_start
        fps = self._frame_count / max(elapsed, 1)
        self._post("render_fps", f"{fps:.1f} FPS", min(100, int(fps / 0.55)))

        def _done():
            self._running = False
            self._run_btn.configure(state=tk.NORMAL, text="▶  RUN BENCHMARK")
            self._status_lbl.configure(text="Benchmark complete.", fg=C["ok"])
            self._prog.delete("all")
        self.frame.after(0, _done)

    # ── Village scene ─────────────────────────────────────────────────────────

    def _anim_tick(self):
        try:
            self._draw_village(self._t)
            self._t += 0.016
            if self._running:
                self._frame_count += 1
                elapsed = time.time() - self._bench_start
                frac = min(1.0, elapsed / 11.0)
                w = self._prog.winfo_width() or 800
                self._prog.delete("all")
                self._prog.create_rectangle(0, 0, int(w * frac), 3,
                                            fill=C["accent"], outline="")
        except Exception:
            pass
        self.frame.after(33, self._anim_tick)

    def _draw_village(self, t):
        c = self._canvas
        W = c.winfo_width()  or 800
        H = c.winfo_height() or 300
        c.delete("all")

        # Sky gradient bands
        sky = ["#05080f","#06091a","#070b22","#090e2a","#0b1132"]
        bh  = (H * 0.65) / len(sky)
        for i, col in enumerate(sky):
            c.create_rectangle(0, i*bh, W, (i+1)*bh, fill=col, outline="")

        # Stars
        rng = random.Random(42)
        for _ in range(90):
            sx = rng.randint(0, W); sy = rng.randint(0, int(H * 0.58))
            tw = 0.5 + 0.5 * math.sin(t * 2.1 + sx * 0.13)
            br = int(100 + 155 * tw)
            br2 = min(255, br + 30)
            c.create_oval(sx-1, sy-1, sx+1, sy+1,
                          fill=f"#{br:02x}{br:02x}{br2:02x}", outline="")

        # Moon
        mx, my = W * 0.82, H * 0.13
        for r, col in [(34,"#110e08"),(28,"#1a1608")]:
            c.create_oval(mx-r, my-r, mx+r, my+r, fill="", outline=col, width=4)
        c.create_oval(mx-22, my-22, mx+22, my+22, fill="#e8e0c8", outline="")
        c.create_oval(mx+4,  my-7,  mx+11, my,    fill="#d0c8b0", outline="")
        c.create_oval(mx-8,  my+4,  mx+1,  my+11, fill="#d8d0b8", outline="")

        horiz_y = H * 0.60

        # Ground
        c.create_rectangle(0, horiz_y, W, H, fill="#050a05", outline="")

        # Distant hills layer 1
        off1 = (t * 5) % W
        for ox in (-W, 0, W):
            pts = []
            for xi in range(0, W+20, 18):
                hx = xi + ox - off1
                hy = horiz_y - 42 - 26*math.sin((xi+ox)*0.007+1.3)
                pts += [hx, hy]
            pts += [W+ox, horiz_y, ox-W, horiz_y]
            if len(pts) >= 6:
                c.create_polygon(pts, fill="#090f07", outline="")

        # Distant hills layer 2
        off2 = (t * 9) % W
        for ox in (-W, 0, W):
            pts = []
            for xi in range(0, W+20, 18):
                hx = xi + ox - off2
                hy = horiz_y - 18 - 12*math.sin((xi+ox)*0.012+2.9)
                pts += [hx, hy]
            pts += [W+ox, horiz_y, ox-W, horiz_y]
            if len(pts) >= 6:
                c.create_polygon(pts, fill="#070c05", outline="")

        c.create_line(0, horiz_y, W, horiz_y, fill="#1a3020", width=1)

        # Castle
        cx = W // 2
        cy = int(horiz_y)
        c.create_rectangle(cx-28, cy-88, cx+28, cy, fill="#040904", outline="")
        for bx in range(cx-28, cx+20, 11):
            c.create_rectangle(bx, cy-97, bx+7, cy-88, fill="#040904", outline="")
        for sx in (-44, 44):
            c.create_rectangle(cx+sx-13, cy-62, cx+sx+13, cy, fill="#040904", outline="")
            for bx in range(cx+sx-13, cx+sx+7, 9):
                c.create_rectangle(bx, cy-70, bx+6, cy-62, fill="#040904", outline="")
        for wx, wy in ((cx-9, cy-62), (cx+9, cy-62), (cx-9, cy-38)):
            c.create_rectangle(wx-3, wy-5, wx+3, wy+5, fill="#ffcc44", outline="")
            c.create_oval(wx-9, wy-11, wx+9, wy+11, fill="", outline="#331e00", width=7)

        # Moving buildings
        boff = (t * 16) % (W * 2)
        rng2 = random.Random(13)
        for i in range(14):
            bx = int((i * 130 - boff) % (W * 2) - 60)
            bw = rng2.randint(26, 48); bh2 = rng2.randint(32, 68)
            by = int(horiz_y) - bh2
            c.create_rectangle(bx, by, bx+bw, int(horiz_y), fill="#050a04", outline="")
            rp = [bx-4, by, bx+bw//2, by-15, bx+bw+4, by]
            c.create_polygon(rp, fill="#040803", outline="")
            for wxi in range(2):
                for wyi in range(2):
                    wx2 = bx+5+wxi*14; wy2 = by+7+wyi*15
                    wc  = "#bb7700" if rng2.random() > 0.35 else "#0a1207"
                    c.create_rectangle(wx2, wy2, wx2+6, wy2+8, fill=wc, outline="")

        # Road (one-point perspective)
        vpx, vpy = W//2, int(horiz_y)
        near_hw = int(W * 0.18)
        c.create_polygon(vpx-3, vpy, vpx+3, vpy,
                          vpx+near_hw, H, vpx-near_hw, H,
                          fill="#0b160a", outline="")
        # Road dashes
        for i in range(8):
            frac = ((i/8) + (t*0.38) % (1/8)*8) % 1.0
            p = frac**2
            dy = vpy + (H-vpy)*p
            dw = max(2, int(7*p)); dh = max(2, int(16*p))
            c.create_rectangle(vpx-dw//2, dy-dh//2, vpx+dw//2, dy+dh//2,
                                fill="#1a3318", outline="")

        # Foreground trees
        toff = (t * 32) % 260
        for side in (-1, 1):
            for i in range(5):
                tx = W//2 + side*(int(W*0.28) + i*68 - int(toff))
                ty = int(horiz_y) + 4
                th = 55 + (i%3)*18
                c.create_rectangle(tx-3, ty, tx+3, ty+18, fill="#180c00", outline="")
                c.create_polygon(tx, ty-th, tx-16, ty, tx+16, ty,
                                  fill="#021201", outline="")
                c.create_polygon(tx, ty-th-8, tx-11, ty-int(th*0.38),
                                  tx+11, ty-int(th*0.38), fill="#031402", outline="")

        # Torches
        for tx, ty in ((W//2-75, int(horiz_y)-4), (W//2+75, int(horiz_y)-4)):
            fl  = 0.7 + 0.3*math.sin(t*8.4 + tx*0.11)
            fl2 = 0.7 + 0.3*math.sin(t*6.8 + tx*0.21 + 1.1)
            c.create_rectangle(tx-2, ty-18, tx+2, ty+8, fill="#2a1800", outline="")
            for r, col in ((int(20*fl),"#180700"), (int(14*fl),"#380f00"),
                           (int(9*fl2),"#bb3800"), (int(5*fl2),"#ff8800")):
                c.create_oval(tx-r, ty-18-r, tx+r, ty-18+r, fill=col, outline="")

        # Mist
        for i, fc in enumerate(("#06100a","#071208","#091407","#0b1608")):
            fy = int(horiz_y) - 3 + i*3
            c.create_rectangle(0, fy, W, fy+4, fill=fc, outline="")

        # Seagulls flying through the scene
        for gi in range(3):
            gx = (W * (0.2 + gi*0.3) + t * (28 + gi*9)) % (W + 80) - 40
            gy = H * (0.18 + gi*0.09)
            gfl = math.sin(t*5.1 + gi*2.1) - 0.25*math.sin(2*(t*5.1+gi*2.1))
            _draw_gull_icon(c, gx, gy, flap=gfl, scale=0.25+gi*0.06,
                            body="#cce0ee", wing="#aac8dc")

        # HUD
        if self._running:
            elapsed = time.time() - self._bench_start
            fps_live = self._frame_count / max(elapsed, 0.1)
            c.create_text(8, 8, anchor="nw",
                          text=f"FPS {fps_live:.0f}   {elapsed:.1f}s / 11s",
                          fill=C["accent"], font=("TkFixedFont", 9))
        elif not self._results:
            c.create_text(W//2, H//2-14, text="GULLWING BENCHMARK",
                          fill=C["accent"], font=T.font_ui(17, "bold"))
            c.create_text(W//2, H//2+12, text="Press  ▶ RUN BENCHMARK  to begin",
                          fill=C["muted"], font=T.font_ui(10))


# ── Overclock Tab ──────────────────────────────────────────────────────────────

class OverclockTab:
    """Live hardware monitor + overclocking advisory panel."""

    _RISK = (
        "⚠  OVERCLOCKING RISK: Increasing clock speeds or voltages beyond factory\n"
        "   specifications can permanently damage hardware, void warranties, cause\n"
        "   data loss, and reduce component lifespan. Only proceed if you understand\n"
        "   the risks fully. Gullwing never modifies clocks or voltages automatically."
    )

    def __init__(self, nb, app):
        self.frame = ttk.Frame(nb)
        nb.add(self.frame, text="Overclock")
        self._app              = app
        self._poll_id          = None
        self._advisory         = []
        self._meter_vals: dict = {}       # key → current float | None
        self._oc_t             = 0.0      # animation clock
        self._last_adv_key     = None     # fingerprint of last rendered advisory
        self._build()
        self._oc_anim_tick()
        self._poll()

    def _build(self):
        outer = tk.Frame(self.frame, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)

        # Risk banner
        banner = tk.Frame(outer, bg="#3a0808")
        banner.pack(fill=tk.X, padx=0, pady=0)
        tk.Label(banner, text=self._RISK,
                 bg="#3a0808", fg="#ff9090",
                 font=T.font_ui(8),
                 justify=tk.LEFT).pack(anchor="w", padx=12, pady=8)

        # Main two-column layout
        cols = tk.Frame(outer, bg=C["bg"])
        cols.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        # Left: live monitor
        left = tk.Frame(cols, bg=C["bg"])
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,6))

        hdr_l = tk.Frame(left, bg=C["panel"])
        hdr_l.pack(fill=tk.X, pady=(0,4))
        tk.Label(hdr_l, text="  LIVE MONITOR",
                 bg=C["panel"], fg=C["accent"],
                 font=T.font_ui(9, "bold")).pack(side=tk.LEFT, pady=6)
        self._refresh_btn = tk.Button(hdr_l, text="⟳ Refresh",
                                      bg=C["panel"], fg=C["muted"],
                                      font=T.font_ui(8),
                                      relief=tk.FLAT, cursor="hand2",
                                      command=self._poll)
        self._refresh_btn.pack(side=tk.RIGHT, padx=8)

        self._meters_frame = tk.Frame(left, bg=C["bg"])
        self._meters_frame.pack(fill=tk.BOTH, expand=True)

        # Define meters
        self._meter_defs = [
            ("cpu_freq",   "CPU Frequency",  "MHz",  5000, C["accent"]),
            ("cpu_temp",   "CPU Temp",        "°C",   110,  C["HIGH"]),
            ("gpu_freq",   "GPU Core Clock",  "MHz",  3000, C["neon"]),
            ("gpu_temp",   "GPU Temp",        "°C",   110,  C["HIGH"]),
            ("ram_freq",   "RAM Speed",       "MHz",  8000, C["ok"]),
            ("fan_rpm",    "Fan Speed",       "RPM",  3000, C["MEDIUM"]),
        ]
        self._meter_labels: dict = {}
        self._meter_bars:   dict = {}

        for key, label, unit, max_val, color in self._meter_defs:
            row = tk.Frame(self._meters_frame, bg=C["panel"],
                           highlightthickness=1, highlightbackground=C["border"])
            row.pack(fill=tk.X, pady=2)

            name_lbl = tk.Label(row, text=label, bg=C["panel"], fg=C["muted"],
                                 font=T.font_ui(8), width=16, anchor="w")
            name_lbl.pack(side=tk.LEFT, padx=(8,0), pady=5)

            bar_frame = tk.Frame(row, bg=C["bg"], height=14)
            bar_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=4, padx=6)
            bar_cnv = tk.Canvas(bar_frame, bg=C["bg"], height=14,
                                highlightthickness=0)
            bar_cnv.pack(fill=tk.X, expand=True)

            val_lbl = tk.Label(row, text="—", bg=C["panel"], fg=color,
                               font=("TkFixedFont", 9, "bold"), width=12, anchor="e")
            val_lbl.pack(side=tk.RIGHT, padx=8, pady=5)

            self._meter_labels[key] = (val_lbl, color, max_val)
            self._meter_bars[key]   = (bar_cnv, color)

        # Right: advisory panel
        right = tk.Frame(cols, bg=C["bg"], width=260)
        right.pack(side=tk.RIGHT, fill=tk.BOTH)
        right.pack_propagate(False)

        tk.Label(right, text="OC ADVISORY",
                 bg=C["bg"], fg=C["accent"],
                 font=T.font_ui(9, "bold")).pack(anchor="w", pady=(0,4))

        adv_outer = tk.Frame(right, bg=C["bg"],
                             highlightthickness=1, highlightbackground=C["border"])
        adv_outer.pack(fill=tk.BOTH, expand=True)

        self._adv_canvas = tk.Canvas(adv_outer, bg=C["bg"],
                                     highlightthickness=0)
        adv_sb = ttk.Scrollbar(adv_outer, orient=tk.VERTICAL,
                               command=self._adv_canvas.yview)
        self._adv_canvas.configure(yscrollcommand=adv_sb.set)
        adv_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._adv_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._adv_inner = tk.Frame(self._adv_canvas, bg=C["bg"])
        self._adv_win   = self._adv_canvas.create_window(
            (0, 0), window=self._adv_inner, anchor="nw")
        self._adv_inner.bind("<Configure>", self._on_adv_resize)
        self._adv_canvas.bind("<Configure>", self._on_adv_canvas_resize)

        # Placeholder until advisory loads
        self._adv_status = tk.Label(self._adv_inner,
                                    text="Click  ⟳ Refresh  to load advisory…",
                                    bg=C["bg"], fg=C["muted"],
                                    font=T.font_ui(8),
                                    wraplength=220, justify=tk.LEFT)
        self._adv_status.pack(anchor="w", padx=8, pady=8)

    def _on_adv_resize(self, _e):
        self._adv_canvas.configure(
            scrollregion=self._adv_canvas.bbox("all"))

    def _on_adv_canvas_resize(self, e):
        self._adv_canvas.itemconfigure(self._adv_win, width=e.width)

    @staticmethod
    def _hex_to_rgb(hexcol):
        return int(hexcol[1:3], 16), int(hexcol[3:5], 16), int(hexcol[5:7], 16)

    def _update_meter(self, key, value):
        if key not in self._meter_labels:
            return
        val_lbl, color, max_val = self._meter_labels[key]
        self._meter_vals[key] = value
        if value is None:
            val_lbl.configure(text="N/A", fg=C["muted"])
            return
        unit = {"cpu_freq":"MHz","cpu_temp":"°C","gpu_freq":"MHz",
                "gpu_temp":"°C","ram_freq":"MHz","fan_rpm":"RPM"}[key]
        disp_color = color
        if "temp" in key and value >= 90:
            disp_color = C["CRITICAL"]
        elif "temp" in key and value >= 75:
            disp_color = C["HIGH"]
        val_lbl.configure(text=f"{value:.0f} {unit}", fg=disp_color)

    def _oc_anim_tick(self):
        """30 fps glow-bar animation for the live monitor."""
        try:
            if not self.frame.winfo_exists():
                return
        except Exception:
            return
        self._oc_t = (self._oc_t + 0.055) % (2 * math.pi)
        pulse = 0.80 + 0.20 * math.sin(self._oc_t)
        for key, (val_lbl, color, max_val) in self._meter_labels.items():
            bar_cnv, bar_color = self._meter_bars[key]
            w = bar_cnv.winfo_width()
            if w < 2:
                continue
            current_val = self._meter_vals.get(key)
            bar_cnv.delete("all")
            # Track background
            bar_cnv.create_rectangle(0, 0, w, 14, fill="#050d18", outline="")
            if current_val is None:
                continue
            frac = max(0.0, min(1.0, current_val / max_val))
            filled = int(w * frac)
            if filled < 1:
                continue
            try:
                r, g, b = self._hex_to_rgb(bar_color)
            except Exception:
                continue
            # Outer glow (dim, wide)
            gr = min(255, int(r * 0.25))
            gg = min(255, int(g * 0.25))
            gb = min(255, int(b * 0.25))
            bar_cnv.create_rectangle(0, 0, filled, 14,
                                     fill=f"#{gr:02x}{gg:02x}{gb:02x}", outline="")
            # Main bar with pulse
            mr = min(255, int(r * pulse))
            mg = min(255, int(g * pulse))
            mb = min(255, int(b * pulse))
            bar_cnv.create_rectangle(0, 3, filled, 11,
                                     fill=f"#{mr:02x}{mg:02x}{mb:02x}", outline="")
            # Top shine
            sr = min(255, int(r * 1.5 * pulse))
            sg = min(255, int(g * 1.5 * pulse))
            sb = min(255, int(b * 1.5 * pulse))
            bar_cnv.create_rectangle(0, 3, filled, 5,
                                     fill=f"#{sr:02x}{sg:02x}{sb:02x}", outline="")
            # Leading-edge glow dot
            if filled > 4:
                tr = min(255, int(r * 2.0))
                tg = min(255, int(g * 2.0))
                tb = min(255, int(b * 2.0))
                bar_cnv.create_rectangle(
                    max(0, filled - 5), 1, min(w, filled + 2), 13,
                    fill=f"#{tr:02x}{tg:02x}{tb:02x}", outline=""
                )
        self.frame.after(33, self._oc_anim_tick)

    def _read_hardware(self):
        """Read live hardware metrics. Returns dict key→float|None."""
        vals: dict = {k: None for k, *_ in self._meter_defs}

        # CPU frequency
        try:
            if _UI_OS == "Linux":
                freq_total = 0.0; n_cores = 0
                for p in os.scandir("/sys/devices/system/cpu"):
                    if not p.name.startswith("cpu") or not p.name[3:].isdigit():
                        continue
                    freq_f = os.path.join(p.path, "cpufreq", "scaling_cur_freq")
                    try:
                        with open(freq_f) as fh:
                            freq_total += int(fh.read()) / 1000
                        n_cores += 1
                    except OSError:
                        pass
                if n_cores:
                    vals["cpu_freq"] = freq_total / n_cores
            elif _UI_OS == "Windows":
                out, rc = ec._ps(
                    "(Get-CimInstance Win32_Processor).CurrentClockSpeed")
                if rc == 0 and out.strip().isdigit():
                    vals["cpu_freq"] = float(out.strip())
            elif _UI_OS == "Darwin":
                out = subprocess.check_output(
                    ["sysctl", "-n", "hw.cpufrequency"],
                    timeout=3).decode().strip()
                if out.isdigit():
                    vals["cpu_freq"] = float(out) / 1e6
        except Exception:
            pass

        # CPU temperature
        try:
            if _UI_OS == "Linux":
                for tz in sorted(os.listdir("/sys/class/thermal")):
                    tp = f"/sys/class/thermal/{tz}/temp"
                    try:
                        with open(tp) as fh:
                            vals["cpu_temp"] = int(fh.read()) / 1000.0
                        break
                    except OSError:
                        pass
            elif _UI_OS == "Darwin":
                pass  # requires sudo / SMC access
        except Exception:
            pass

        # GPU (NVIDIA first, then AMD)
        try:
            out = subprocess.check_output(
                ["nvidia-smi",
                 "--query-gpu=clocks.gr,temperature.gpu",
                 "--format=csv,noheader,nounits"],
                timeout=4, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).decode().strip()
            parts = [p.strip() for p in out.split(",")]
            if len(parts) >= 2:
                vals["gpu_freq"] = float(parts[0])
                vals["gpu_temp"] = float(parts[1])
        except Exception:
            pass

        if vals["gpu_freq"] is None:
            try:
                if _UI_OS == "Linux":
                    for card in sorted(os.listdir("/sys/class/drm")):
                        freq_f = f"/sys/class/drm/{card}/device/pp_dpm_sclk"
                        if not os.path.exists(freq_f):
                            continue
                        with open(freq_f) as fh:
                            for line in reversed(fh.read().splitlines()):
                                if "*" in line:
                                    m = re.search(r"(\d+)Mhz", line)
                                    if m:
                                        vals["gpu_freq"] = float(m.group(1))
                                    break
                        break
            except Exception:
                pass

        if vals["gpu_temp"] is None:
            try:
                if _UI_OS == "Linux":
                    import glob as _glob
                    for tf in _glob.glob("/sys/class/hwmon/hwmon*/temp1_input"):
                        try:
                            with open(tf) as fh:
                                t_val = int(fh.read()) / 1000.0
                            name_f = os.path.join(os.path.dirname(tf), "name")
                            name = open(name_f).read().strip() if os.path.exists(name_f) else ""
                            if "amdgpu" in name or "nouveau" in name:
                                vals["gpu_temp"] = t_val
                                break
                        except OSError:
                            pass
            except Exception:
                pass

        # RAM speed
        try:
            if _UI_OS == "Linux":
                out = subprocess.check_output(
                    ["dmidecode", "--type", "17"],
                    timeout=4, stderr=subprocess.DEVNULL).decode()
                speeds = re.findall(r"Speed:\s+(\d+)\s+MT/s", out)
                if speeds:
                    vals["ram_freq"] = float(max(int(s) for s in speeds))
            elif _UI_OS == "Windows":
                out, rc = ec._ps(
                    "(Get-CimInstance Win32_PhysicalMemory).Speed | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum")
                if rc == 0 and out.strip().isdigit():
                    vals["ram_freq"] = float(out.strip())
        except Exception:
            pass

        # Fan speed
        try:
            if _UI_OS == "Linux":
                import glob as _glob
                for ff in _glob.glob("/sys/class/hwmon/hwmon*/fan1_input"):
                    try:
                        with open(ff) as fh:
                            vals["fan_rpm"] = float(fh.read().strip())
                        break
                    except OSError:
                        pass
        except Exception:
            pass

        return vals

    def _run_advisory(self):
        """Run check_overclock and return findings."""
        reporter = ec._Reporter()
        try:
            ec.check_overclock(reporter)
        except Exception:
            pass
        findings = []
        for chk in reporter._data.get("checks", []):
            for f in chk.get("findings", []):
                findings.append(f)
        return findings

    def _poll(self):
        """Read hardware and advisory in background, update UI."""
        def _bg():
            hw   = self._read_hardware()
            adv  = self._run_advisory()
            self.frame.after(0, lambda: self._apply(hw, adv))
        threading.Thread(target=_bg, daemon=True).start()
        # re-poll every 3 s
        self._poll_id = self.frame.after(3000, self._poll)

    def _apply(self, hw, findings):
        for key, val in hw.items():
            self._update_meter(key, val)
        # Only re-render advisory when findings actually change
        adv_key = tuple((f.get("label",""), f.get("severity","")) for f in findings)
        if adv_key != self._last_adv_key:
            self._last_adv_key = adv_key
            self._render_advisory(findings)

    def _render_advisory(self, findings):
        for w in self._adv_inner.winfo_children():
            w.destroy()

        if not findings:
            tk.Label(self._adv_inner,
                     text="No overclocking advisories for this system.",
                     bg=C["bg"], fg=C["ok"],
                     font=T.font_ui(8),
                     wraplength=220, justify=tk.LEFT).pack(anchor="w", padx=8, pady=8)
            return

        sev_colors = {
            "CRITICAL": C["CRITICAL"], "HIGH": C["HIGH"],
            "MEDIUM": C["MEDIUM"], "REVIEW": C["muted"],
            "INFO": C["accent"],
        }

        for f in findings:
            sev   = f.get("severity", "INFO")
            label = f.get("label", "")
            why   = f.get("why", "")
            fix   = f.get("fix", "")
            color = sev_colors.get(sev, C["muted"])

            card = tk.Frame(self._adv_inner, bg=C["panel"],
                            highlightthickness=1, highlightbackground=color)
            card.pack(fill=tk.X, padx=4, pady=3)

            hf = tk.Frame(card, bg=C["panel"])
            hf.pack(fill=tk.X, padx=6, pady=(5,0))
            tk.Label(hf, text=sev, bg=C["panel"], fg=color,
                     font=T.font_ui(7, "bold")).pack(side=tk.LEFT)
            tk.Label(hf, text=label, bg=C["panel"], fg=C["text"],
                     font=T.font_ui(8, "bold"),
                     wraplength=190, justify=tk.LEFT).pack(anchor="w", padx=(4,0))

            if why:
                tk.Label(card, text=why, bg=C["panel"], fg=C["muted"],
                         font=T.font_ui(7),
                         wraplength=210, justify=tk.LEFT).pack(anchor="w", padx=6, pady=(2,0))
            if fix:
                tk.Label(card, text=fix, bg=C["panel"], fg=C["accent"],
                         font=T.font_ui(7),
                         wraplength=210, justify=tk.LEFT).pack(anchor="w", padx=6, pady=(1,4))
            else:
                card.pack_configure(pady=(3,3))
                tk.Frame(card, bg=C["panel"], height=4).pack()


# ── Main application ───────────────────────────────────────────────────────────

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Gullwing")
        root.minsize(900, 600)
        root.configure(bg=C["bg"])
        root.resizable(True, True)
        _configure_style(root)
        self._build()
        self._refresh_last_scan_badge()
        self._poll()
        # Check for sessions that were interrupted before the app last exited.
        # Defer so the window is fully rendered before the dialog appears.
        root.after(800, self._check_incomplete_sessions)

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        r = self.root
        self._tracker = _SessionTracker()

        # ── Header (frame-based) ──────────────────────────────────────────────
        HDR_H = 68
        hdr = tk.Frame(r, bg=C["bg"], height=HDR_H)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Frame(hdr, bg=C["border"], height=1).pack(side=tk.TOP, fill=tk.X)
        tk.Frame(hdr, bg=C["accent"], height=2).pack(side=tk.BOTTOM, fill=tk.X)

        # Right: version + privilege pill (packed first to anchor it right)
        priv    = "ADMIN" if _is_root() else "STANDARD"
        priv_fg = C["ok"] if _is_root() else C["muted"]
        pill = tk.Frame(hdr, bg=C["pill"], highlightthickness=1,
                        highlightbackground=C["border"])
        tk.Label(pill, text=f"v{ec.__version__}", bg=C["pill"], fg=C["muted"],
                 font=T.font_ui(8), padx=6, pady=2).pack(side=tk.LEFT)
        tk.Label(pill, text="•", bg=C["pill"], fg=C["border"],
                 font=T.font_ui(8)).pack(side=tk.LEFT)
        tk.Label(pill, text=priv, bg=C["pill"], fg=priv_fg,
                 font=T.font_ui(8, "bold"), padx=6, pady=2).pack(side=tk.LEFT)
        pill.pack(side=tk.RIGHT, padx=14)

        # Left: icon mark + title
        left_hdr = tk.Frame(hdr, bg=C["bg"])
        left_hdr.pack(side=tk.LEFT, fill=tk.Y, padx=(16, 0))

        # Gull icon (icon-header.png → diamond polygon fallback)
        _icon_loaded = False
        try:
            from PIL import Image as _PilImage, ImageTk as _ImageTk
            _ico_path = T._asset_path("icons/icon-header.png")
            if os.path.isfile(_ico_path):
                _pil    = _PilImage.open(_ico_path).convert("RGBA")
                _tk_img = _ImageTk.PhotoImage(_pil)
                _ico_lbl = tk.Label(left_hdr, image=_tk_img, bg=C["bg"])
                _ico_lbl.image = _tk_img
                _ico_lbl.pack(side=tk.LEFT, padx=(0, 10), pady=14)
                _icon_loaded = True
        except Exception:
            pass
        if not _icon_loaded:
            _logo = tk.Canvas(left_hdr, width=32, height=32,
                              bg=C["bg"], highlightthickness=0)
            _logo.create_polygon(16, 1, 31, 16, 16, 31, 1, 16,
                                 fill=C["accent"], outline="")
            _logo.create_polygon(16, 8, 24, 16, 16, 24, 8, 16,
                                 fill=C["neon"], outline="")
            _logo.pack(side=tk.LEFT, padx=(0, 10), pady=14)

        # Title
        title_f = tk.Frame(left_hdr, bg=C["bg"])
        title_f.pack(side=tk.LEFT, fill=tk.Y, pady=14)
        title_row = tk.Frame(title_f, bg=C["bg"])
        title_row.pack(anchor="w")
        tk.Label(title_row, text="GULLWING",
                 bg=C["bg"], fg=C["text"],
                 font=T.font_ui(13, "bold")).pack(side=tk.LEFT)
        tk.Label(title_row, text=f"  v{ec.__version__}",
                 bg=C["bg"], fg=C["accent"],
                 font=T.font_ui(9, "bold")).pack(side=tk.LEFT)
        tk.Label(title_f, text="Tune it. Lock it. Send it.",
                 bg=C["bg"], fg=C["muted"],
                 font=T.font_ui(7)).pack(anchor="w")

        # Animated seagull mascot
        GULL_W, GULL_H = 100, 64
        self._hdr_gull = tk.Canvas(hdr, width=GULL_W, height=GULL_H,
                                    bg=C["bg"], highlightthickness=0)
        self._hdr_gull.pack(side=tk.LEFT, padx=16)
        self._hdr_gull_phase  = 0.0
        self._gull_boost_until = 0
        self._gull_click_times: list = []
        self._konami_seq: list = []
        self._hdr_gull.bind("<Button-1>",        lambda _e: self._gull_check_in())
        self._hdr_gull.bind("<Double-Button-1>", lambda _e: self._gull_summon_golden())
        self._hdr_gull.bind("<Button-3>",        self._gull_right_click)
        self._hdr_gull.bind("<Enter>",  lambda _e: self._hdr_gull.configure(cursor="hand2"))
        self._hdr_gull.bind("<Leave>",  lambda _e: self._hdr_gull.configure(cursor=""))
        self._animate_hdr_gull()

        # Konami code listener
        self.root.bind("<Key>", self._konami_check)

        # Ambient seagull state
        self._ambient_tops: list = []
        self._schedule_ambient_gull()

        # ── Target / TLS bar ──────────────────────────────────────────────────
        ctrl = tk.Frame(r, bg=C["bg"])
        ctrl.pack(fill=tk.X, padx=16, pady=(6, 4))

        tk.Label(ctrl, text="Target", bg=C["bg"], fg=C["muted"],
                 font=T.font_ui(8, "bold")).grid(
            row=0, column=0, sticky="w")
        tk.Label(ctrl, text="TLS host (optional)", bg=C["bg"], fg=C["muted"],
                 font=T.font_ui(8, "bold")).grid(
            row=0, column=2, sticky="w", padx=(16, 0))

        self._var_target = tk.StringVar(value="127.0.0.1")
        self._var_tls    = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._var_target, width=26).grid(
            row=1, column=0, sticky="ew")
        ttk.Entry(ctrl, textvariable=self._var_tls, width=26).grid(
            row=1, column=2, sticky="ew", padx=(16, 0))
        ctrl.grid_columnconfigure(0, weight=1)
        ctrl.grid_columnconfigure(2, weight=1)

        # ── Tab content: nav rail (left) + notebook (right) ─────────────────
        _nb_area = tk.Frame(r, bg=C["bg"])
        _nb_area.pack(fill=tk.BOTH, expand=True, pady=(6, 0))

        self._nav_rail = tk.Frame(_nb_area, bg=T.SURFACE, width=92)
        self._nav_rail.pack(side=tk.LEFT, fill=tk.Y, padx=(16, 0))
        self._nav_rail.pack_propagate(False)

        self._nb = ttk.Notebook(_nb_area, style="NoTabs.TNotebook")
        self._nb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 16))

        self._tab_overview = OverviewTab(self._nb, self)

        self._tab_security  = ScanTab(
            self._nb, "Security",  "Security score", self, self._run_security,
            session_tracker=self._tracker)
        self._tab_antivirus = ScanTab(
            self._nb, "Antivirus", "Threat status",  self, self._run_antivirus,
            session_tracker=self._tracker)
        self._tab_performance = ScanTab(
            self._nb, "Performance", "Boost status", self, self._run_performance,
            session_tracker=self._tracker)
        self._tab_protection = ScanTab(
            self._nb, "Protection", "Shield status", self, self._run_protection,
            session_tracker=self._tracker)
        self._tab_cleaner   = ScanTab(
            self._nb, "Cleaner",   "Clean status",   self, self._run_cleaner,
            session_tracker=self._tracker, revertable=False)
        self._tab_benchmark = BenchmarkTab(self._nb, self)
        self._tab_overclock = OverclockTab(self._nb, self)
        self._tab_snapshots = SnapshotsTab(self._nb, self)

        # Populate nav rail now that all tab frames exist
        self._populate_nav_rail()
        self._nb.bind("<<NotebookTabChanged>>", self._update_nav_rail)

        # Start on the Security tab — the Overview is a place users navigate to,
        # not the default landing tab.
        self._nb.select(self._tab_security.frame)

        # ── Scan activity log ──────────────────────────────────────────────────
        log_hdr = tk.Frame(r, bg=C["bg"])
        log_hdr.pack(fill=tk.X, padx=16, pady=(6, 2))

        # Gull mascot + SCAN ACTIVITY label inline
        log_gull = tk.Canvas(log_hdr, width=22, height=16, bg=C["bg"],
                              highlightthickness=0)
        log_gull.pack(side=tk.LEFT, padx=(0, 4))
        _draw_gull_icon(log_gull, 11, 8, flap=0.1, scale=0.32)
        tk.Label(log_hdr, text="Scan activity",
                 bg=C["bg"], fg=C["muted"],
                 font=T.font_ui(8, "bold")).pack(side=tk.LEFT)

        log_outer = tk.Frame(r, bg=C["log_bg"], bd=0,
                              highlightthickness=1,
                              highlightbackground=C["border"])
        log_outer.pack(fill=tk.X, padx=16, pady=(0, 4))

        self._log = tk.Text(log_outer, height=4, state=tk.DISABLED,
                            font=("TkFixedFont", 9),
                            bg=C["log_bg"], fg=C["text"],
                            relief=tk.FLAT, wrap=tk.WORD, padx=10, pady=6)
        self._log.tag_configure("ok",       foreground=C["ok"])
        self._log.tag_configure("err",      foreground=C["err"])
        self._log.tag_configure("cmd",      foreground=C["cmd"])
        self._log.tag_configure("hdr",      foreground=C["hdr"])
        self._log.tag_configure("muted",    foreground=C["muted"])
        self._log.tag_configure("neon",     foreground=C["neon"])
        self._log.tag_configure("critical", foreground=C["CRITICAL"])
        self._log.tag_configure("high",     foreground=C["HIGH"])
        log_sb = ttk.Scrollbar(log_outer, orient=tk.VERTICAL,
                               command=self._log.yview)
        self._log.configure(yscrollcommand=log_sb.set)
        self._log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_sb.pack(side=tk.RIGHT, fill=tk.Y)

        # Bottom action bar
        br = tk.Frame(r, bg=C["bg"])
        br.pack(fill=tk.X, padx=16, pady=(0, 8))
        ttk.Button(br, text="Open Report",
                   command=self._open_report).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(br, text="Save Report…",
                   command=self._save_report).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(br, text="Export PDF",
                   command=self._export_pdf).pack(side=tk.LEFT, padx=(0, 4))
        tk.Frame(br, bg=C["border"], width=1).pack(
            side=tk.LEFT, fill=tk.Y, pady=2, padx=6)
        ttk.Button(br, text="Save Baseline",
                   command=self._save_baseline).pack(side=tk.LEFT, padx=(6, 4))
        ttk.Button(br, text="Diff vs File…",
                   command=self._diff).pack(side=tk.LEFT)
        tk.Frame(br, bg=C["border"], width=1).pack(
            side=tk.LEFT, fill=tk.Y, pady=2, padx=6)
        self._btn_revert = RoundButton(br, text="↩  Revert Session",
                                       bg="#e3733a", fg="#1a0e06",
                                       state=tk.DISABLED,
                                       command=self._revert_session)
        self._btn_revert.pack(side=tk.LEFT, padx=(6, 0))
        # Schedule and settings (pinned right)
        ttk.Button(br, text="⏱  Schedule",
                   command=lambda: _ScheduleDialog(self.root)).pack(
            side=tk.RIGHT, padx=(0, 0))

        # ── Status bar ────────────────────────────────────────────────────────
        # thin accent separator above status bar
        tk.Frame(r, bg=C["border"], height=1).pack(fill=tk.X, side=tk.BOTTOM)
        sb = tk.Frame(r, bg=C["panel"], height=30)
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        sb.pack_propagate(False)

        # Tiny static seagull in status bar
        sb_gull = tk.Canvas(sb, width=26, height=20, bg=C["panel"],
                             highlightthickness=0)
        sb_gull.pack(side=tk.LEFT, padx=(10, 4), pady=5)
        _draw_gull_icon(sb_gull, 13, 10, flap=0.3, scale=0.38)

        self._var_status = tk.StringVar(
            value="Ready — select a tab and press Scan")
        tk.Label(sb, textvariable=self._var_status,
                 bg=C["panel"], fg=C["muted"],
                 font=T.font_ui(9), anchor=tk.W).pack(
            side=tk.LEFT, fill=tk.X, expand=True, pady=7)
        self._progress = ttk.Progressbar(sb, mode="indeterminate", length=90)
        self._progress.pack(side=tk.RIGHT, padx=10, pady=7)
        tk.Frame(sb, bg=C["border"], width=1).pack(
            side=tk.RIGHT, fill=tk.Y, pady=5)
        self._last_scan_lbl = tk.Label(
            sb, text="", bg=C["panel"], fg=C["muted"],
            font=T.font_ui(8), padx=10)
        self._last_scan_lbl.pack(side=tk.RIGHT, pady=7)

    # ── Nav rail ──────────────────────────────────────────────────────────────

    def _populate_nav_rail(self):
        _NAV_ITEMS = [
            ("◈", "Overview",    lambda: self._tab_overview.frame),
            ("🔒", "Security",   lambda: self._tab_security.frame),
            ("🛡", "Antivirus",  lambda: self._tab_antivirus.frame),
            ("⚡", "Performance", lambda: self._tab_performance.frame),
            ("🔐", "Protection", lambda: self._tab_protection.frame),
            ("🧹", "Cleaner",    lambda: self._tab_cleaner.frame),
            ("📊", "Benchmark",  lambda: self._tab_benchmark.frame),
            ("🔧", "Overclock",  lambda: self._tab_overclock.frame),
            ("⊞", "Snapshots",  lambda: self._tab_snapshots.frame),
        ]
        self._nav_btns: dict = {}   # frame widget → nav button label

        # Thin top padding
        tk.Frame(self._nav_rail, bg=T.SURFACE, height=8).pack(fill=tk.X)

        for icon, label, frame_fn in _NAV_ITEMS:
            frame = frame_fn()
            btn = tk.Label(
                self._nav_rail,
                text=f"{icon}\n{label}",
                bg=T.SURFACE, fg=T.TEXT_MUTED,
                font=T.font_ui(8),
                cursor="hand2", anchor="center",
                justify=tk.CENTER,
                pady=6,
            )
            btn.pack(fill=tk.X, padx=4, pady=1)
            btn.bind("<Button-1>",  lambda _e, f=frame: self._nb.select(f))
            btn.bind("<Enter>",     lambda _e, b=btn: b.configure(fg=T.TEXT))
            btn.bind("<Leave>",     lambda _e, b=btn: self._refresh_nav_btn(b))
            self._nav_btns[str(frame)] = btn

        # Thin bottom rule
        tk.Frame(self._nav_rail, bg=T.BORDER, height=1).pack(
            fill=tk.X, padx=4, pady=(4, 0))

        self._update_nav_rail()

    def _refresh_nav_btn(self, btn: tk.Label):
        """Restore a nav button to its correct active/muted state."""
        selected = self._nb.select()
        is_active = any(
            str(f) == selected and b is btn
            for f, b in self._nav_btns.items()
        )
        btn.configure(
            fg=T.ACCENT if is_active else T.TEXT_MUTED,
            bg=T.BG    if is_active else T.SURFACE,
        )

    def _update_nav_rail(self, _event=None):
        """Sync nav rail highlight to the currently selected notebook tab."""
        selected = self._nb.select()
        for frame_id, btn in self._nav_btns.items():
            if frame_id == selected:
                btn.configure(fg=T.ACCENT, bg=T.BG,
                               font=T.font_ui(8, "bold"))
            else:
                btn.configure(fg=T.TEXT_MUTED, bg=T.SURFACE,
                               font=T.font_ui(8))

    # ── Seagull animation ─────────────────────────────────────────────────────

    def _animate_hdr_gull(self):
        try:
            if self.root.state() == "iconic" or not self.root.winfo_ismapped():
                self.root.after(300, self._animate_hdr_gull)
                return
        except Exception:
            pass
        c = self._hdr_gull
        c.delete("all")
        # Realistic flap: ~2.5 Hz, asymmetric sine for natural wing beat
        t = self._hdr_gull_phase
        flap = math.sin(t) - 0.25 * math.sin(2 * t)
        boosted = getattr(self, "_gull_boost_until", 0) > 0
        if getattr(self, "_gull_fixing", False) or boosted:
            _draw_gull_icon(c, 46, 32, flap=flap, scale=1.01,
                            body="#f0c060", wing="#d4a040",
                            beak="#e07010", eye="#3a2000")
            self._hdr_gull_phase = (self._hdr_gull_phase + 0.19) % (2 * math.pi)
            if boosted:
                self._gull_boost_until -= 1
        else:
            _draw_gull_icon(c, 46, 32, flap=flap, scale=1.01)
            self._hdr_gull_phase = (self._hdr_gull_phase + 0.10) % (2 * math.pi)
        self.root.after(40, self._animate_hdr_gull)

    def set_gull_fixing(self, fixing: bool):
        self._gull_fixing = fixing

    def _note_windows_revert_scope(self):
        """After fixes apply on Windows, state plainly what Revert can't undo.

        The snapshot layer only captures the hosts file on Windows; the bulk of
        Windows fixes are registry/service changes it can't roll back. Say so
        once per session rather than letting the Revert button imply otherwise.
        """
        if _UI_OS != "Windows" or getattr(self, "_win_revert_noted", False):
            return
        self._win_revert_noted = True
        self._log_append(
            "\nNote: Windows registry and service changes can't be undone by "
            "Revert Session — only firewall/hosts edits are snapshotted. "
            "Use System Restore for a full rollback.\n", "muted")

    # ── Quips & easter eggs ───────────────────────────────────────────────────

    _GULL_QUIPS = [
        "All checks are local — no cloud, no phone-home.",
        "Squawk! Ready to scan, optimize, and protect.",
        "Just a seagull keeping your rig safe.",
        "100% offline. Your data stays yours.",
        "Need a scan? Hit the button. I'll be here.",
        "Optimize first, game later. Or, you know, now.",
        "Venice was nice but this machine needs work.",
        "No APIs. No secrets. Just local checks.",
        "Click Scan — I'll watch the radar.",
        "Privacy guaranteed. The gull has seen nothing.",
        "Your frames aren't going to drop themselves.",
        "I've seen worse rigs. Not many, but some.",
        "Latency is the enemy. I know its address.",
        "Every fix applied is a frame per second gained.",
        "Gaming PC? More like waiting PC — until now.",
        "I don't sleep. I scan.",
        "Your GPU called. It said thank you.",
        "Zero telemetry. The gull does not gossip.",
        "They said get a real antivirus. I said squawk.",
        "Frame drops are a choice. A bad one.",
        "PCIe ASPM disabled. You're welcome.",
        "Three monitors? Respect. Also, check your VRAM.",
        "I have seen the registry. It was dark there.",
        "Secure Boot on. Sleep schedule: nonexistent.",
    ]
    _GULL_FACTS = [
        "Seagulls can drink both fresh and salt water — a special gland removes the salt.",
        "Herring gulls can recognise individual human faces.",
        "Gulls drop shellfish from height onto rocks to crack them open.",
        "Some seagulls live up to 30 years in the wild.",
        "Seagulls use the thermals rising off warm tarmac to soar without flapping.",
        "A group of seagulls is called a colony, or more poetically, a screech.",
        "Gulls communicate through specific calls — over 30 distinct vocalisations.",
    ]
    _KONAMI = ("Up","Up","Down","Down","Left","Right","Left","Right","b","a")
    _gull_quip_idx = 0

    def _konami_check(self, event):
        self._konami_seq.append(event.keysym)
        if len(self._konami_seq) > len(self._KONAMI):
            self._konami_seq = self._konami_seq[-len(self._KONAMI):]
        if tuple(self._konami_seq) == self._KONAMI:
            self._konami_seq = []
            self._set_status("KONAMI ACTIVATED — the skies darken with gulls!")
            self._log_append("  ★ Konami code! Flock inbound.\n", "neon")
            for i in range(8):
                self.root.after(i * 320, self._launch_ambient_gull)

    def _gull_check_in(self):
        now = time.time()
        self._gull_boost_until = 80
        # Rapid-click easter egg: 5 clicks within 2 seconds → summon flock
        self._gull_click_times = [t for t in self._gull_click_times if now - t < 2.0]
        self._gull_click_times.append(now)
        if len(self._gull_click_times) >= 5:
            self._gull_click_times = []
            self._set_status("RAPID CLICK — flock inbound!")
            self._log_append("  ★ Rapid-click easter egg: flock inbound!\n", "neon")
            for i in range(6):
                self.root.after(i * 280, self._launch_ambient_gull)
            return
        quip = self._GULL_QUIPS[self.__class__._gull_quip_idx % len(self._GULL_QUIPS)]
        self.__class__._gull_quip_idx += 1
        self._set_status(quip)
        self._log_append(f"  ✦ {quip}\n", "muted")
        self._launch_ambient_gull()

    def _gull_summon_golden(self):
        """Double-click → special golden gull + surprise quip."""
        self._gull_boost_until = 120
        self._set_status("✦ A golden gull appears… legend says it brings frame drops to your enemies.")
        self._log_append("  ★ Golden gull summoned via double-click!\n", "neon")
        self._launch_ambient_gull(golden=True)

    def _gull_right_click(self, event):
        fact = random.choice(self._GULL_FACTS)
        menu = tk.Menu(self.root, tearoff=0,
                       bg=C["panel"], fg=C["text"],
                       activebackground=C["accent"], activeforeground=C["bg"],
                       font=T.font_ui(9))
        menu.add_command(label=f"Gull fact: {fact}", state="disabled",
                         foreground=C["muted"])
        menu.add_separator()
        menu.add_command(label="Summon ambient gull",
                         command=self._launch_ambient_gull)
        menu.add_command(label="Summon golden gull ✦",
                         command=self._gull_summon_golden)
        menu.add_command(label="FLOCK MODE (8 gulls)",
                         command=lambda: [
                             self._launch_ambient_gull()
                             for _ in range(8)
                         ])
        menu.post(event.x_root, event.y_root)

    # ── Ambient seagulls ──────────────────────────────────────────────────────

    # Near-black transparency key used for Toplevel-based gulls.
    # Windows: this exact colour becomes invisible via -transparentcolor.
    # macOS: whole Toplevel is transparent via -transparent.
    # Linux: window alpha set to 0.92 so this near-black bg almost disappears
    #        against the dark panel surfaces.
    _GULL_TRANS = "#010203"

    def _schedule_ambient_gull(self):
        """Schedule the next ambient gull crossing (every 20–50 s)."""
        try:
            delay = random.randint(20_000, 50_000)
            self.root.after(delay, self._launch_ambient_gull)
        except Exception:
            pass

    def _launch_ambient_gull(self, golden: bool = False):
        """Float a seagull across the window in a transparent Toplevel overlay."""
        def _start():
            try:
                w = self.root.winfo_width()
                h = self.root.winfo_height()
                if w < 200 or h < 100:
                    self._schedule_ambient_gull()
                    return

                # 10 % larger than previous range (0.28–0.48 → 0.31–0.53)
                scale  = random.uniform(0.31, 0.53)
                speed  = random.uniform(2.2, 4.0)
                ltr    = random.random() > 0.5
                cw     = int(66 * scale + 10)
                ch     = int(44 * scale + 10)

                rx = self.root.winfo_rootx()
                ry = self.root.winfo_rooty()
                y  = random.randint(int(h * 0.08), int(h * 0.55))

                start_x = -cw if ltr else w + cw
                end_x   =  w + cw if ltr else -cw

                # ── Transparent Toplevel (no black box) ────────────────────
                top = tk.Toplevel(self.root)
                top.overrideredirect(True)
                top.configure(bg=self._GULL_TRANS)
                # Do NOT set -topmost: that makes gulls float over every other
                # app on the screen.  As a child of self.root, this Toplevel
                # already stacks above the app window naturally.
                try:
                    if _UI_OS == "Windows":
                        top.attributes("-transparentcolor", self._GULL_TRANS)
                    elif _UI_OS == "Darwin":
                        top.attributes("-transparent", True)
                        top.configure(bg="systemTransparent")
                    else:
                        # Linux: whole-window alpha makes near-black bg nearly invisible
                        top.attributes("-alpha", 0.92)
                except Exception:
                    pass
                top.geometry(f"{cw}x{ch}+{rx + int(start_x)}+{ry + y}")

                cnv = tk.Canvas(top, width=cw, height=ch,
                                bg=self._GULL_TRANS, highlightthickness=0)
                cnv.place(x=0, y=0)

                # Colour scheme: golden for easter egg, natural white for normal
                b_col  = "#f5d060" if golden else "white"
                wg_col = "#d4a820" if golden else "#cce0ee"
                bk_col = "#c07010" if golden else "#e8a020"

                state = {"x": float(start_x), "flap_t": random.uniform(0, 6.28)}

                def _tick():
                    try:
                        # Hide when app is minimised so gulls don't linger
                        # on the taskbar / desktop.
                        try:
                            hidden = (self.root.state() == "iconic" or
                                      not self.root.winfo_ismapped())
                            if hidden:
                                top.withdraw()
                                self.root.after(300, _tick)
                                return
                            else:
                                top.deiconify()
                        except Exception:
                            pass

                        state["x"] += speed if ltr else -speed
                        # Realistic wing beat: ~3 Hz asymmetric sine
                        state["flap_t"] = (state["flap_t"] + 0.22) % (2 * math.pi)
                        t = state["flap_t"]
                        flap = math.sin(t) - 0.28 * math.sin(2 * t)

                        if (ltr and state["x"] > end_x) or \
                           (not ltr and state["x"] < end_x):
                            top.destroy()
                            self._schedule_ambient_gull()
                            return

                        top.geometry(f"{cw}x{ch}+{rx + int(state['x'])}+{ry + y}")
                        cnv.delete("all")
                        _draw_gull_icon(cnv, cw // 2, ch // 2, flap=flap,
                                        scale=scale, body=b_col, wing=wg_col,
                                        beak=bk_col, flipped=not ltr)
                        self.root.after(36, _tick)
                    except Exception:
                        try:
                            top.destroy()
                        except Exception:
                            pass
                        self._schedule_ambient_gull()

                self.root.after(36, _tick)
            except Exception:
                self._schedule_ambient_gull()

        _start()

    # ── Scan runners ──────────────────────────────────────────────────────────

    def _run_security(self, reporter):
        target   = self._var_target.get().strip() or "127.0.0.1"
        tls_host = self._var_tls.get().strip() or None

        # SSH remote scan if target is user@host
        if "@" in target:
            ec.run_remote_scan(target, reporter)
            return

        ip, display = ec.resolve_target(target)
        ec.run_port_scan(reporter, ip, display, 1.0)
        ec.audit_ssh(reporter)
        ec.check_firewall(reporter)
        ec.check_listeners(reporter)
        ec.check_world_writable(reporter)
        ec.check_suid(reporter)
        ec.check_cron(reporter)
        ec.check_packages(reporter)
        ec.check_kernel_hardening(reporter)
        ec.check_sensitive_perms(reporter)
        ec.check_user_accounts(reporter)
        ec.check_docker_socket(reporter)
        if tls_host:
            ec.check_tls(reporter, tls_host)

    def _run_antivirus(self, reporter):
        ec.check_auth_log(reporter)
        ec.check_malware(reporter)

    def _run_performance(self, reporter):
        ec.check_startup(reporter)
        ec.check_power_settings(reporter)
        ec.check_gpu_settings(reporter)
        ec.check_network_perf(reporter)
        ec.check_memory_perf(reporter)
        ec.check_system_resources(reporter)

    def _run_protection(self, reporter):
        ec.check_protection_hardening(reporter)

    def _run_cleaner(self, reporter):
        ec.check_system_cleaner(reporter)
        ec.check_startup(reporter)

    # ── Shared helpers ────────────────────────────────────────────────────────

    def _rescan_populated_tabs(self):
        """Rescan every ScanTab that already has findings (post-fix rescan).

        Sets _post_fix_scan so each tab stays on its own page when done instead
        of jumping to the Overview tab.
        """
        for tab in (self._tab_security, self._tab_antivirus,
                    self._tab_performance, self._tab_protection,
                    self._tab_cleaner):
            if getattr(tab, "_findings", []):
                # Clear any stuck scanning flag so start_scan can't early-return.
                tab._scanning = False
                tab._post_fix_scan = True
                tab.start_scan()

    def _get_active_tab(self) -> ScanTab:
        for tab in (self._tab_security, self._tab_antivirus,
                    self._tab_performance, self._tab_protection,
                    self._tab_cleaner):
            try:
                if tab.frame.winfo_ismapped():
                    return tab
            except Exception:
                pass
        return self._tab_security

    def _refresh_revert_btn(self):
        state = tk.NORMAL if self._tracker.has_changes else tk.DISABLED
        self._btn_revert.configure(state=state)

    def _revert_session(self):
        snap = self._tracker.earliest_snap()
        if not snap:
            return
        lines = self._tracker.summary_lines()
        detail = "\n".join(f"  • {l}" for l in lines)
        if not messagebox.askyesno(
            "Revert Session Changes",
            f"Revert all changes made this session?\n\n{detail}\n\n"
            "This will restore SSH config and firewall rules to the state "
            "they were in before any fixes were applied.",
        ):
            return
        self._set_status("Reverting session…")
        self._progress.start(10)

        def _worker():
            results = ec.restore_snapshot(snap)
            self.root.after(0, lambda: self._finish_revert(results))

        threading.Thread(target=_worker, daemon=True).start()

    def _finish_revert(self, results):
        self._progress.stop()
        ok_n   = sum(1 for _, s, _ in results if s)
        fail_n = sum(1 for _, s, _ in results if not s)
        self._log_append("\n── Session revert ──\n", "hdr")
        for action, success, detail in results:
            tag  = "ok" if success else "err"
            icon = "✓" if success else "✗"
            self._log_append(f"  {icon} {action}"
                              + (f": {detail}" if detail else "") + "\n", tag)
        self._tracker.clear()
        self._refresh_revert_btn()
        self._set_status(
            f"Session reverted — {ok_n} ok, {fail_n} failed. Rescanning in 3s…"
        )
        self.root.after(3000, self._tab_security.start_scan)

    def _check_incomplete_sessions(self):
        """On launch, surface any sessions that were interrupted mid-fix."""
        sessions = ec.find_incomplete_sessions()
        if not sessions:
            return
        # Use the earliest incomplete session for the revert candidate.
        session_ts, manifest = sessions[0]
        snap  = manifest.get("snap", {})
        label = manifest.get("label", session_ts)
        ts_human = session_ts[:8] + " " + session_ts[9:11] + ":" + session_ts[11:13]
        if not messagebox.askyesno(
            "Incomplete session detected",
            f"Gullwing was closed while fixes were still in progress.\n\n"
            f"Session:  {ts_human}\n"
            f"Last fix: {label}\n\n"
            "Would you like to revert the changes from that session now?\n\n"
            "Choose No to leave the changes in place (they will not be offered again).",
            parent=self.root,
        ):
            # User declined — mark it complete so it won't reappear.
            ec.mark_session_complete(session_ts)
            return
        self._set_status("Reverting interrupted session…")
        self._progress.start(10)

        def _worker():
            results = ec.restore_snapshot(snap)
            ec.mark_session_complete(session_ts)
            self.root.after(0, lambda: self._finish_revert(results))

        threading.Thread(target=_worker, daemon=True).start()

    def _refresh_last_scan_badge(self) -> None:
        """Update the status-bar 'Last scan' pill from on-disk history."""
        best_ts, best_grade = 0.0, None
        for tab_name in ("security", "antivirus", "cleaner"):
            hist = ec.load_scan_history(tab_name, n=1)
            if hist and hist[-1]["ts"] > best_ts:
                best_ts   = hist[-1]["ts"]
                best_grade = hist[-1]["grade"]
        if best_grade is None:
            self._last_scan_lbl.configure(text="No scan yet", fg=C["muted"])
        else:
            col = _GRADE_COLOR.get(best_grade, C["muted"])
            self._last_scan_lbl.configure(
                text=f"Last scan: {_ago(best_ts)}  ·  {best_grade}",
                fg=col,
            )
            self.root.title(
                f"Gullwing  ·  Grade {best_grade}  ·  Gull"
            )

    def _log_append(self, text: str, tag: str = ""):
        self._log.configure(state=tk.NORMAL)
        self._log.insert(tk.END, text, tag)
        self._log.see(tk.END)
        self._log.configure(state=tk.DISABLED)

    def _set_status(self, msg: str):
        self._var_status.set(msg.rstrip("."))

    # ── Reports / baseline / diff ─────────────────────────────────────────────

    def _open_report(self):
        self._get_active_tab().open_report()

    def _save_report(self):
        self._get_active_tab().save_report()

    def _export_pdf(self):
        tab = self._get_active_tab()
        if not tab._reporter_data:
            messagebox.showinfo("No report", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF report", "*.pdf"), ("All files", "*.*")],
            initialfile=f"report-{tab._title.lower()}.pdf",
        )
        if not path:
            return
        self._set_status("Generating PDF…")
        self._progress.start(10)

        def _worker():
            err = ec.generate_pdf_report(tab._reporter_data, path)
            self.root.after(0, lambda: self._finish_pdf(path, err))

        threading.Thread(target=_worker, daemon=True).start()

    def _finish_pdf(self, path: str, err: str):
        self._progress.stop()
        if err:
            messagebox.showerror("PDF export failed", err)
            self._set_status("PDF export failed.")
        else:
            self._set_status(f"PDF saved → {path}")
            if messagebox.askyesno("PDF saved", f"Saved to:\n{path}\n\nOpen it now?"):
                webbrowser.open(f"file://{path}")

    def _save_baseline(self):
        tab = self._get_active_tab()
        if not tab._reporter_data:
            messagebox.showinfo("No report", "Run a scan first.")
            return
        err = ec._save_baseline(ec._DEFAULT_BASELINE, tab._reporter_data)
        if err:
            messagebox.showerror("Baseline save failed", err)
        else:
            self._set_status(f"Baseline saved → {ec._DEFAULT_BASELINE}")

    def _diff(self):
        tab = self._get_active_tab()
        if not tab._reporter_data:
            messagebox.showinfo("No report", "Run a scan first.")
            return
        path = filedialog.askopenfilename(
            title="Select baseline / before report",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        b_data, err = ec._load_report(path)
        if err:
            messagebox.showerror("Load failed", err)
            return
        diff   = ec.diff_reports(b_data, tab._reporter_data)
        n_new  = len(diff["new"])
        n_res  = len(diff["resolved"])
        n_chg  = len(diff["changed"])
        self._log_append(
            f"\n── Diff vs {os.path.basename(path)} "
            f"({n_new} new · {n_res} resolved · {n_chg} changed)\n", "hdr")
        for check, label, sev in diff["new"]:
            self._log_append(f"  [NEW/{sev}] {check} / {label}\n", "err")
        for check, label, sev in diff["resolved"]:
            self._log_append(f"  [FIXED]    {check} / {label}\n", "ok")
        for check, label, bv, av in diff["changed"]:
            self._log_append(
                f"  [CHANGED]  {check} / {label}: {bv} → {av}\n", "cmd")
        self._set_status(
            f"Diff — {n_new} new · {n_res} resolved · {n_chg} changed")

    # ── Poll loop ─────────────────────────────────────────────────────────────

    def _poll(self):
        for tab in (self._tab_security, self._tab_antivirus,
                    self._tab_performance, self._tab_protection,
                    self._tab_cleaner):
            tab.poll()
        self.root.after(40, self._poll)


# ── Seagull drawing helper ─────────────────────────────────────────────────────

def _draw_gull_icon(cnv, cx, cy, flap=0.0, scale=1.0,
                    body="white", wing="#cce0ee",
                    beak="#e8a020", eye="#1a1a2a",
                    flipped=False):
    """Draw a realistic seagull on cnv centered at (cx, cy).
    flap in [-1,+1]: +1 = wings up, -1 = wings down.
    flipped=True mirrors the gull to face left (for right-to-left flight).
    """
    s = scale
    m = -1 if flipped else 1   # x mirror multiplier

    # Asymmetric wing displacement: far wing gets full travel, near wing foreshortened
    wy_far  = int(flap * 16 * s)
    wy_near = int(flap * 10 * s)

    # Dark primary feather tips
    tip_col = "#28364a" if body in ("white", "#e8edf4", "#f2f5fa", "#edf2fa") else "#1a2030"

    # ── Far wing ─────────────────────────────────────────────────────────────
    cnv.create_polygon(
        cx,                   cy - int(2 * s),
        cx - m*int(9 * s),   cy + wy_far // 2,
        cx - m*int(25 * s),  cy + wy_far,
        cx - m*int(20 * s),  cy + wy_far + int(5 * s),
        cx - m*int(7 * s),   cy + int(3 * s),
        smooth=True, fill=wing, outline="",
    )
    # Far wing primary tip band
    cnv.create_polygon(
        cx - m*int(22 * s), cy + wy_far,
        cx - m*int(25 * s), cy + wy_far,
        cx - m*int(20 * s), cy + wy_far + int(5 * s),
        cx - m*int(17 * s), cy + wy_far + int(4 * s),
        fill=tip_col, outline="",
    )

    # ── Near wing ─────────────────────────────────────────────────────────────
    cnv.create_polygon(
        cx,                   cy - int(2 * s),
        cx + m*int(5 * s),   cy + wy_near // 2,
        cx + m*int(16 * s),  cy + wy_near,
        cx + m*int(12 * s),  cy + wy_near + int(4 * s),
        cx + m*int(4 * s),   cy + int(2 * s),
        smooth=True, fill=wing, outline="",
    )
    # Near wing primary tip band
    cnv.create_polygon(
        cx + m*int(13 * s), cy + wy_near,
        cx + m*int(16 * s), cy + wy_near,
        cx + m*int(12 * s), cy + wy_near + int(4 * s),
        cx + m*int(9 * s),  cy + wy_near + int(3 * s),
        fill=tip_col, outline="",
    )

    # ── Body ─────────────────────────────────────────────────────────────────
    cnv.create_oval(cx - int(12 * s), cy - int(4 * s),
                    cx + int(12 * s), cy + int(5 * s),
                    fill=body, outline="")

    # ── Head ─────────────────────────────────────────────────────────────────
    cnv.create_oval(cx + m*int(8 * s),  cy - int(9 * s),
                    cx + m*int(18 * s), cy + int(1 * s),
                    fill=body, outline="")

    # ── Beak ─────────────────────────────────────────────────────────────────
    cnv.create_polygon(
        cx + m*int(16 * s), cy - int(5 * s),
        cx + m*int(24 * s), cy - int(4 * s),
        cx + m*int(16 * s), cy - int(2 * s),
        fill=beak, outline="",
    )
    # Beak tip accent (darker)
    cnv.create_polygon(
        cx + m*int(21 * s), cy - int(5 * s),
        cx + m*int(24 * s), cy - int(4 * s),
        cx + m*int(21 * s), cy - int(3 * s),
        fill="#b05810", outline="",
    )

    # ── Eye ──────────────────────────────────────────────────────────────────
    cnv.create_oval(cx + m*int(12 * s), cy - int(7 * s),
                    cx + m*int(15 * s), cy - int(4 * s),
                    fill=eye, outline="")
    # Eye highlight
    cnv.create_oval(cx + m*int(12 * s), cy - int(7 * s),
                    cx + m*int(13 * s), cy - int(6 * s),
                    fill="#ffffff", outline="")

    # ── Tail (forked) ────────────────────────────────────────────────────────
    cnv.create_polygon(
        cx - m*int(12 * s), cy,
        cx - m*int(20 * s), cy - int(5 * s),
        cx - m*int(22 * s), cy - int(2 * s),
        cx - m*int(19 * s), cy + int(5 * s),
        cx - m*int(17 * s), cy + int(2 * s),
        fill=body, outline="",
    )


# ── Venice splash animation ─────────────────────────────────────────────────────

class VeniceSplash:
    """Third-person flythrough: the camera follows a seagull gliding down a
    Venetian canal at dusk — one-point perspective, scrolling facades, lit
    windows reflected in the water."""

    W, H = 680, 380
    _DURATION = 6.8   # seconds total — longer to feel premium
    _FADE_IN  = 0.40
    _FADE_OUT = 0.55
    _TICK_MS  = 30    # ~33 fps

    _SKY_STOPS = [
        (0.00, "#0a0e30"),   # deep midnight blue at zenith
        (0.22, "#1a1658"),   # rich indigo
        (0.43, "#4a1e5a"),   # warm violet
        (0.60, "#8a2840"),   # crimson-purple
        (0.74, "#c84030"),   # rich vermillion
        (0.86, "#e06020"),   # burnt orange
        (0.94, "#f09030"),   # warm amber
        (1.00, "#ffc050"),   # golden at horizon
    ]

    # Camera / projection
    _F        = 240.0   # focal length (px)
    _CANAL_HW = 2.6     # canal half-width (world units)
    _CAM_H    = 1.6     # camera height above water
    _NEAR     = 0.9
    _FAR      = 34.0
    _SPEED    = 6.5     # world units / second forward

    def __init__(self, root):
        self._root  = root
        self._alive = True
        self._t     = 0.0
        self._z_cam = 0.0

        win = tk.Toplevel(root)
        win.overrideredirect(True)
        win.configure(bg="#06021a")
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        win.geometry(
            f"{self.W}x{self.H}+{(sw - self.W)//2}+{(sh - self.H)//2}"
        )
        self._win = win

        self._cnv = tk.Canvas(win, width=self.W, height=self.H,
                               bg="#06021a", highlightthickness=0)
        self._cnv.pack()

        try:
            win.attributes("-alpha", 0.0)
            self._can_alpha = True
        except Exception:
            self._can_alpha = False

        self._hz = int(self.H * 0.46)           # horizon line
        self._rng = random.Random(42)
        self._segments = self._gen_segments()
        self._draw_sky()
        self._tick()

    # ── Static sky (drawn once) ───────────────────────────────────────────────

    @staticmethod
    def _lerp(stops, frac):
        for i in range(len(stops) - 1):
            y0, c0 = stops[i]
            y1, c1 = stops[i + 1]
            if y0 <= frac <= y1:
                t = (frac - y0) / (y1 - y0) if y1 > y0 else 0.0
                r = int(int(c0[1:3], 16) + t * (int(c1[1:3], 16) - int(c0[1:3], 16)))
                g = int(int(c0[3:5], 16) + t * (int(c1[3:5], 16) - int(c0[3:5], 16)))
                b = int(int(c0[5:7], 16) + t * (int(c1[5:7], 16) - int(c0[5:7], 16)))
                return f"#{r:02x}{g:02x}{b:02x}"
        return stops[-1][1]

    @staticmethod
    def _shade(hexcol, k):
        """Darken/brighten a #rrggbb colour by factor k."""
        r = max(0, min(255, int(int(hexcol[1:3], 16) * k)))
        g = max(0, min(255, int(int(hexcol[3:5], 16) * k)))
        b = max(0, min(255, int(int(hexcol[5:7], 16) * k)))
        return f"#{r:02x}{g:02x}{b:02x}"

    def _draw_sky(self):
        cnv, w, hz = self._cnv, self.W, self._hz
        bands = 50
        for i in range(bands):
            y0 = int(i / bands * hz)
            y1 = int((i + 1) / bands * hz) + 1
            cnv.create_rectangle(0, y0, w, y1, outline="",
                                 fill=self._lerp(self._SKY_STOPS, i / bands))
        rng = random.Random(7)
        for _ in range(38):
            sx = rng.randint(0, w)
            sy = rng.randint(0, int(hz * 0.45))
            b  = rng.randint(155, 225)
            cnv.create_oval(sx - 1, sy - 1, sx + 1, sy + 1, outline="",
                            fill=f"#{b:02x}{b:02x}{min(b+25,255):02x}")
        # Sun glow at the vanishing point — warm and prominent
        vx = w // 2
        for gr, col in ((62, "#4a1c08"), (44, "#903818"), (28, "#d06018"),
                        (14, "#f09030"), (7, "#ffe070")):
            cnv.create_oval(vx - gr, hz - gr // 2 - 6,
                            vx + gr, hz + gr // 2 - 6,
                            fill=col, outline="")
        # Water base — deep Venice canal blue-green
        cnv.create_rectangle(0, hz, w, self.H, fill="#091c2e", outline="")
        # Sun path on water — amber streak toward the camera
        for i in range(10):
            sy0 = hz + 4 + i * max(1, (self.H - hz - 10) // 10)
            sy1 = sy0 + max(1, (self.H - hz - 10) // 10) + 2
            alpha = 1.0 - i * 0.09
            hw_streak = max(1, int(28 * alpha * alpha))
            cnv.create_rectangle(vx - hw_streak, sy0, vx + hw_streak, sy1,
                                 fill=self._shade("#d86018", alpha), outline="")

    # ── World generation ──────────────────────────────────────────────────────

    # Venetian plaster palette — terracotta, ochre, dusty rose, warm neutrals
    _FACADE_COLS = [
        "#c8703a", "#d49040", "#be5838", "#c89828",
        "#c86858", "#a86030", "#d0a038", "#b86848", "#cc8060",
    ]
    _STONE_COL = "#c8b890"   # pale limestone at waterline

    def _gen_segment(self, z0):
        rng = self._rng
        _pole_schemes = [
            ("#1a3a8a", "#f0f0f8"),   # blue / white
            ("#c03020", "#f0f0f8"),   # red / white
            ("#1a3a8a", "#c03020"),   # blue / red
            ("#246020", "#f0d030"),   # green / gold
            ("#1a3a8a", "#f0e030"),   # blue / gold
        ]
        return {
            "z0": z0,
            "len":     rng.uniform(2.8, 5.0),
            "lh":      rng.uniform(3.6, 5.4),
            "rh":      rng.uniform(3.6, 5.4),
            "lc":      rng.choice(self._FACADE_COLS),
            "rc":      rng.choice(self._FACADE_COLS),
            "lwin":    rng.randint(2, 3),
            "rwin":    rng.randint(2, 3),
            "lncols":  rng.randint(3, 5),
            "rncols":  rng.randint(3, 5),
            "pole":      rng.random() < 0.55,
            "pole_side": rng.choice((-1, 1)),
            "pole_cols": rng.choice(_pole_schemes),
            "arch":      rng.random() < 0.22,
            "chimney":   rng.random() < 0.50,
            "chim_off":  rng.uniform(0.2, 0.8),
            "balcony":   rng.random() < 0.42,
            "boat":      rng.random() < 0.24,
            "boat_side": rng.choice((-1, 1)),
        }

    def _gen_segments(self):
        segs, z = [], self._NEAR
        while z < self._FAR + 6:
            s = self._gen_segment(z)
            segs.append(s)
            z += s["len"]
        return segs

    # ── Projection helpers ────────────────────────────────────────────────────

    def _proj(self, x, y, z):
        """World (x right, y up from water, z forward) → screen."""
        s = self._F / z
        sx = self.W / 2 + x * s
        sy = self._hz - (y - self._CAM_H) * s
        return sx, sy, s

    # ── Per-frame scene ───────────────────────────────────────────────────────

    def _draw_scene(self):
        cnv = self._cnv
        cnv.delete("scene")
        zc = self._z_cam

        # Recycle segments that passed the camera; extend the far end
        while self._segments and self._segments[0]["z0"] + self._segments[0]["len"] - zc < self._NEAR:
            self._segments.pop(0)
        far_end = self._segments[-1]["z0"] + self._segments[-1]["len"] if self._segments else zc + self._NEAR
        while far_end - zc < self._FAR:
            s = self._gen_segment(far_end)
            self._segments.append(s)
            far_end += s["len"]

        hw = self._CANAL_HW
        # Far → near so close facades paint over distant ones
        for seg in reversed(self._segments):
            z0 = max(seg["z0"] - zc, self._NEAR)
            z1 = max(seg["z0"] + seg["len"] - zc, self._NEAR + 0.01)
            if z0 >= self._FAR:
                continue
            z1 = min(z1, self._FAR)
            fog = max(0.22, 1.0 - (z0 / self._FAR) * 0.9)

            for side, height, fac_col, nrows, ncols in (
                (-1, seg["lh"], seg["lc"], seg["lwin"], seg["lncols"]),
                (+1, seg["rh"], seg["rc"], seg["rwin"], seg["rncols"]),
            ):
                x = side * hw
                bx0, by0, _ = self._proj(x, 0,      z0)
                bx1, by1, _ = self._proj(x, 0,      z1)
                tx0, ty0, _ = self._proj(x, height, z0)
                tx1, ty1, _ = self._proj(x, height, z1)
                fc = self._shade(fac_col, fog)

                # Main plaster facade
                cnv.create_polygon(bx0, by0, bx1, by1, tx1, ty1, tx0, ty0,
                                   fill=fc, outline=self._shade(fc, 0.72),
                                   tags="scene")

                # Pale limestone base band at waterline
                sbx0, sby0, _ = self._proj(x, 0.45, z0)
                sbx1, sby1, _ = self._proj(x, 0.45, z1)
                cnv.create_polygon(bx0, by0, bx1, by1, sbx1, sby1, sbx0, sby0,
                                   fill=self._shade(self._STONE_COL, fog * 0.88),
                                   outline="", tags="scene")

                # Rooftop cornice line
                cnv.create_line(tx0, ty0, tx1, ty1,
                                fill=self._shade(fac_col, fog * 0.50),
                                width=2, tags="scene")

                # Arched windows in a grid
                if z0 < 22:
                    for ri in range(nrows):
                        wy = height * (0.33 + 0.26 * ri / max(1, nrows))
                        for ci in range(ncols):
                            wz = z0 + (z1 - z0) * ((ci + 0.5) / ncols)
                            wpx, wpys, ws = self._proj(x, wy, wz)
                            wr = max(1, int(ws * 0.10))
                            warm = "#ffce6a" if (ri + ci) % 2 == 0 else "#ffb040"
                            wc = self._shade(warm, fog * 1.15)
                            # Window body
                            cnv.create_rectangle(
                                wpx - wr, wpys - int(wr * 1.0),
                                wpx + wr, wpys + int(wr * 0.7),
                                fill=wc, outline="", tags="scene")
                            # Gothic arched top
                            cnv.create_oval(
                                wpx - wr, wpys - int(wr * 1.8),
                                wpx + wr, wpys - int(wr * 0.2),
                                fill=wc, outline="", tags="scene")
                            # Water reflection — vertical amber smear
                            if fog > 0.45 and ws > 8 and wpys < self._hz:
                                rfl_y = self._hz + (self._hz - wpys) * 0.45
                                rfl_len = max(1, int(wr * 2.0))
                                cnv.create_line(wpx, rfl_y, wpx, rfl_y + rfl_len,
                                                fill=self._shade("#b05820", fog * 0.55),
                                                width=max(1, wr), tags="scene")

                # Small wrought-iron balcony rail on nearer facades
                if seg["balcony"] and z0 < 18:
                    bz = z0 + (z1 - z0) * 0.52
                    by_world = height * 0.48
                    bx, bys, bs = self._proj(x, by_world, bz)
                    bw = max(4, int(bs * 0.34))
                    rail_y = bys + max(2, int(bs * 0.10))
                    rail_c = self._shade("#161b22", max(0.35, fog))
                    cnv.create_line(bx - bw, rail_y, bx + bw, rail_y,
                                    fill=rail_c, width=max(1, int(bs * 0.018)),
                                    tags="scene")
                    for rk in range(5):
                        rx = bx - bw + (2 * bw) * rk / 4
                        cnv.create_line(rx, rail_y - max(2, int(bs * 0.10)),
                                        rx, rail_y + max(1, int(bs * 0.04)),
                                        fill=rail_c, tags="scene")

                # Chimney pots on rooftop
                if seg["chimney"] and z0 < 16:
                    chz = z0 + (z1 - z0) * seg["chim_off"]
                    chx_w, chys, chs = self._proj(x, height, chz)
                    ch_off = int(chs * 0.5 * (-side))
                    ch_h   = max(2, int(chs * 0.28))
                    ch_w   = max(1, int(chs * 0.09))
                    chx_s  = int(chx_w) + ch_off
                    cnv.create_rectangle(chx_s - ch_w, chys - ch_h,
                                         chx_s + ch_w, chys,
                                         fill=self._shade("#4a2810", fog),
                                         outline="", tags="scene")
                    cnv.create_oval(chx_s - ch_w - 1, chys - ch_h - ch_w,
                                    chx_s + ch_w + 1, chys - ch_h + ch_w,
                                    fill=self._shade("#2a1406", fog),
                                    outline="", tags="scene")

            # A low moored boat/gondola silhouette gives the canal scale.
            if seg["boat"] and z0 < 18:
                bx = seg["boat_side"] * (hw - 0.92)
                bz = z0 + (z1 - z0) * 0.58
                sx, sy, bs = self._proj(bx, 0.05, bz)
                bw = max(5, int(bs * 0.42))
                bh = max(2, int(bs * 0.10))
                boat_c = self._shade("#100b10", max(0.38, 1 - bz / 18))
                cnv.create_polygon(
                    sx - bw, sy - bh,
                    sx + bw, sy - bh,
                    sx + int(bw * 0.70), sy + bh,
                    sx - int(bw * 0.70), sy + bh,
                    fill=boat_c, outline="", tags="scene")
                cnv.create_line(sx - int(bw * 0.40), sy - bh,
                                sx - int(bw * 0.18), sy - bh * 5,
                                fill=boat_c, width=max(1, int(bs * 0.018)),
                                tags="scene")

            # Striped mooring pole (palo da ormeggio)
            if seg["pole"] and z0 < 16:
                ppx = seg["pole_side"] * (hw - 0.35)
                ppz = (z0 + z1) / 2
                px0, py0, ps = self._proj(ppx, 0,   ppz)
                px1, py1, _  = self._proj(ppx, 2.0, ppz)
                pwx  = max(1, int(ps * 0.07))
                fade = max(0.4, 1.0 - ppz / 20)
                pc1, pc2 = seg["pole_cols"]
                for bi in range(5):
                    bt  = bi / 5
                    bt2 = (bi + 1) / 5
                    py_top = py0 + (py1 - py0) * bt
                    py_bot = py0 + (py1 - py0) * bt2
                    pc = self._shade(pc1 if bi % 2 == 0 else pc2, fade)
                    cnv.create_line(px0, py_top, px0, py_bot,
                                    fill=pc, width=pwx * 2, tags="scene")
                cnv.create_oval(px0 - pwx*2, py1 - pwx*2,
                                px0 + pwx*2, py1 + pwx*2,
                                fill=self._shade("#2a3850", fade),
                                outline="", tags="scene")

            # Bridge arch spanning the canal
            if seg["arch"] and self._NEAR + 3 < z0 < 20:
                az = (z0 + z1) / 2
                fogc = self._shade("#241620", max(0.35, 1 - az / 22))
                deck_h, rise = 2.2, 1.5
                steps = 14
                top_pts, bot_pts = [], []
                for k in range(steps + 1):
                    u  = k / steps
                    wx = (-1 + 2 * u) * hw
                    wy = deck_h + math.sin(u * math.pi) * rise
                    sx, sy, _ = self._proj(wx, wy, az)
                    top_pts.append((sx, sy))
                    sx2, sy2, _ = self._proj(wx, wy - 0.45, az)
                    bot_pts.append((sx2, sy2))
                band = top_pts + list(reversed(bot_pts))
                flat = [c for p in band for c in p]
                cnv.create_polygon(*flat, fill=fogc,
                                   outline=self._shade(fogc, 1.3),
                                   smooth=True, tags="scene")
                for u in (0.42, 0.5, 0.58):
                    wx  = (-1 + 2 * u) * hw
                    wy  = deck_h + math.sin(u * math.pi) * rise
                    rx0, ry0, _ = self._proj(wx, wy,        az)
                    rx1, ry1, _ = self._proj(wx, wy + 0.35, az)
                    cnv.create_line(rx0, ry0, rx1, ry1,
                                    fill=self._shade("#2e1f2a", max(0.4, 1 - az / 22)),
                                    tags="scene")

        # Canal waterline edges converging on the vanishing point
        for side in (-1, 1):
            el_x0, el_y0, _ = self._proj(side * hw, 0, self._NEAR)
            el_x1, el_y1, _ = self._proj(side * hw, 0, self._FAR)
            cnv.create_line(el_x0, el_y0, el_x1, el_y1,
                            fill="#1a3048", width=2, tags="scene")

        # Water shimmer — warm amber near sun path, cooler blue elsewhere
        for i in range(12):
            wz_s = self._NEAR + ((i * 1.4 + (zc * 1.2 % 1.4))) * 1.9
            if wz_s >= self._FAR:
                continue
            wsx, wsy, ws_s = self._proj(0, 0, wz_s)
            whalf = ws_s * (0.45 + (i % 4) * 0.20)
            if abs(wsx - self.W / 2) / self.W < 0.12:
                shim_c = self._shade("#c05812", max(0.25, ws_s / 28))
            else:
                shim_c = self._shade("#1c3a58", max(0.25, ws_s / 28))
            cnv.create_line(wsx - whalf, wsy, wsx + whalf, wsy,
                            fill=shim_c, tags="scene")

    def _draw_single_gull(self, cnv, cx, cy, t, freq=3.2, scale=1.0,
                          alpha=1.0, tag="gull"):
        """Draw one back-view seagull; alpha dims colours for distant gulls."""
        flap = math.sin(t * freq * 2 * math.pi)
        span  = int(46 * scale)
        sweep = (16 + flap * 14) * scale
        dim = lambda c: self._shade(c, alpha)
        body_c = dim("#f2f5fa")
        wing_c = dim("#dde4ee")
        tip_c  = dim("#2a3140")
        for side in (-1, 1):
            cnv.create_polygon(
                cx, cy,
                cx + side * span * 0.45, cy - sweep * 0.7,
                cx + side * span,        cy - sweep,
                cx + side * span * 0.92, cy - sweep + 5 * scale,
                cx + side * span * 0.4,  cy + 4 * scale,
                fill=wing_c, outline="", smooth=True, tags=tag)
            cnv.create_polygon(
                cx + side * span * 0.78, cy - sweep + scale,
                cx + side * span,        cy - sweep,
                cx + side * span * 0.92, cy - sweep + 5 * scale,
                fill=tip_c, outline="", tags=tag)
        r = int(6 * scale)
        cnv.create_oval(cx - r, cy - int(4 * scale),
                        cx + r, cy + int(10 * scale),
                        fill=body_c, outline="", tags=tag)
        cnv.create_polygon(
            cx - int(4 * scale), cy + int(8 * scale),
            cx + int(4 * scale), cy + int(8 * scale),
            cx, cy + int(16 * scale),
            fill=wing_c, outline="", tags=tag)
        cnv.create_oval(cx - int(3 * scale), cy - int(9 * scale),
                        cx + int(3 * scale), cy - int(3 * scale),
                        fill=body_c, outline="", tags=tag)

    def _draw_gull_back(self, t):
        """Lead gull + two escort gulls in loose V-formation + water shadow."""
        cnv = self._cnv
        cnv.delete("gull")

        # Lead gull (close, main character)
        cx = self.W / 2 + math.sin(t * 0.9) * 26
        cy = self._hz - 38 + math.sin(t * 1.7) * 10
        self._draw_single_gull(cnv, cx, cy, t, freq=3.2, scale=1.0, alpha=1.0)

        # Left escort (farther away, smaller, dimmer, slightly different phase)
        ex1 = cx - 68 + math.sin(t * 0.7 + 1.1) * 14
        ey1 = cy - 18 + math.sin(t * 1.3 + 0.4) * 7
        self._draw_single_gull(cnv, ex1, ey1, t + 0.15, freq=2.9,
                               scale=0.62, alpha=0.58, tag="gull")

        # Right escort (even farther)
        ex2 = cx + 84 + math.sin(t * 0.6 + 2.2) * 10
        ey2 = cy - 28 + math.sin(t * 1.1 + 1.0) * 6
        self._draw_single_gull(cnv, ex2, ey2, t + 0.28, freq=3.1,
                               scale=0.46, alpha=0.38, tag="gull")


    def _draw_titles(self):
        cnv = self._cnv
        cnv.delete("title")
        ty = self.H - 72
        progress = max(0.0, min(1.0, self._t / max(0.1, self._DURATION)))
        stages = [
            (0.00, "Detecting platform and loading base configuration…"),
            (0.10, "Indexing port risk database — 1 024 known services…"),
            (0.22, "Locating cron, launchd, and Task Scheduler entries…"),
            (0.35, "Compiling kernel hardening rule-set — 34 sysctl checks…"),
            (0.47, "Mapping SUID/SGID binary search paths…"),
            (0.58, "Registering GPU, power, and NIC probe routines…"),
            (0.70, "Loading 90+ performance and security checks across 7 modules…"),
            (0.82, "Building protection hardening baseline…"),
            (0.92, "All systems ready — launching Gullwing…"),
        ]
        stage = stages[0][1]
        for threshold, label in reversed(stages):
            if progress >= threshold:
                stage = label
                break
        # Drop shadow
        cnv.create_text(self.W // 2 + 1, ty + 1, text="GULLWING",
                        fill="#020508", font=T.font_ui(22, "bold"),
                        anchor="center", tags="title")
        cnv.create_text(self.W // 2, ty, text="GULLWING",
                        fill="#e6edf3", font=T.font_ui(22, "bold"),
                        anchor="center", tags="title")
        cnv.create_text(self.W // 2, ty + 28,
                        text="Scan  ·  Optimize  ·  Protect  ·  Clean — on the machine you own",
                        fill="#8fa0b4", font=T.font_ui(10),
                        anchor="center", tags="title")
        # Progress bar — wider, with a glow fill
        bar_w, bar_h = 280, 6
        bx0 = self.W // 2 - bar_w // 2
        by0 = ty + 46
        filled = int(bar_w * progress)
        cnv.create_rectangle(bx0, by0, bx0 + bar_w, by0 + bar_h,
                             fill="#0d1824", outline="#1e3050", tags="title")
        if filled > 0:
            # Glow: slightly wider, dimmer rectangle behind
            cnv.create_rectangle(bx0, by0 - 1,
                                 bx0 + filled, by0 + bar_h + 1,
                                 fill="#006888", outline="", tags="title")
            cnv.create_rectangle(bx0, by0,
                                 bx0 + filled, by0 + bar_h,
                                 fill="#00b4d8", outline="", tags="title")
        pct = int(progress * 100)
        cnv.create_text(self.W // 2, ty + 62,
                        text=f"{stage}   {pct}%   v{ec.__version__}",
                        fill="#5a6a7a", font=T.font_ui(8),
                        anchor="center", tags="title")

    # ── Animation loop ────────────────────────────────────────────────────────

    def _tick(self):
        if not self._alive:
            return
        t  = self._t
        dt = self._TICK_MS / 1000.0

        if self._can_alpha:
            if t < self._FADE_IN:
                self._win.attributes("-alpha", t / self._FADE_IN)
            elif t > self._DURATION - self._FADE_OUT:
                remaining = self._DURATION - t
                self._win.attributes("-alpha", max(0.0, remaining / self._FADE_OUT))

        if t >= self._DURATION:
            self._alive = False
            self._win.destroy()
            return

        # Ease the camera in, cruise, ease out
        ease = min(1.0, t / 0.7) * min(1.0, max(0.15, (self._DURATION - t) / 0.8))
        self._z_cam += self._SPEED * ease * dt

        try:
            self._draw_scene()
            self._draw_gull_back(t)
            self._draw_titles()
        except tk.TclError:
            self._alive = False
            return

        self._t += dt
        self._win.after(self._TICK_MS, self._tick)

    def wait_done(self, callback):
        """Poll until the animation finishes, then call callback."""
        if not self._alive:
            callback()
        else:
            # Must schedule on root, not _win — _win.destroy() cancels its own afters
            self._root.after(80, lambda: self.wait_done(callback))


def _first_run_wizard(root: tk.Tk, app) -> None:
    """On first launch: ask Quick Scan or Full Audit and kick it off."""
    if os.path.exists(_FIRST_RUN_FLAG):
        return
    try:
        os.makedirs(os.path.dirname(_FIRST_RUN_FLAG), exist_ok=True)
        open(_FIRST_RUN_FLAG, "w").close()
    except Exception:
        pass

    dlg = tk.Toplevel(root)
    dlg.title("Welcome to Gullwing")
    dlg.configure(bg=C["bg"])
    dlg.resizable(False, False)
    dlg.transient(root)
    dlg.grab_set()

    dlg.update_idletasks()
    w, h = 420, 260
    rx = root.winfo_rootx() + (root.winfo_width()  - w) // 2
    ry = root.winfo_rooty() + (root.winfo_height() - h) // 2
    dlg.geometry(f"{w}x{h}+{rx}+{ry}")

    tk.Label(dlg, text="Welcome",
             bg=C["bg"], fg=C["accent"],
             font=T.font_ui(18, "bold")).pack(pady=(28, 4))
    tk.Label(dlg, text="Choose how to start your first scan:",
             bg=C["bg"], fg=C["text"],
             font=T.font_ui(10)).pack(pady=(0, 22))

    choice = [None]

    def _pick(val):
        choice[0] = val
        dlg.destroy()

    btn_f = tk.Frame(dlg, bg=C["bg"])
    btn_f.pack()
    ttk.Button(btn_f, text="Quick Scan\nSecurity only  (~30 s)",
               style="Accent.TButton",
               command=lambda: _pick("quick")).pack(
        side=tk.LEFT, padx=14, ipadx=14, ipady=8)
    ttk.Button(btn_f, text="Full Audit\nSecurity + AV + Boost + Cleaner",
               command=lambda: _pick("full")).pack(
        side=tk.LEFT, padx=14, ipadx=14, ipady=8)

    tk.Label(dlg, text="You can re-run any scan from its tab at any time.",
             bg=C["bg"], fg=C["muted"],
             font=T.font_ui(8)).pack(pady=(20, 0))

    root.wait_window(dlg)

    if choice[0] == "quick":
        root.after(150, app._tab_security.start_scan)
    elif choice[0] == "full":
        root.after(150, app._tab_security.start_scan)
        root.after(300, app._tab_antivirus.start_scan)
        root.after(450, app._tab_performance.start_scan)
        root.after(600, app._tab_protection.start_scan)
        root.after(750, app._tab_cleaner.start_scan)


def _show_splash(root):
    splash = VeniceSplash(root)
    return splash


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    if "--smoke" in sys.argv:
        from exposure_checker import _core, _remediate, _storage, _report, _schedule, _notify, _cli
        from exposure_checker.checks import (
            security, performance, cleaner, portscan, benchmark, overclock,
        )
        from exposure_checker.gui import splash
        print(f"gullwing {ec.__version__} smoke ok")
        raise SystemExit(0)

    # When the frozen app is re-invoked by a scheduled scan (or run from a
    # terminal with CLI args), delegate to the scanner's command-line handler
    # instead of opening the GUI. Without this, `exposure-checker headless`
    # would silently launch the window and the scheduled scan would never run.
    _CLI_SUBCOMMANDS = {"headless", "schedule", "diff", "remediate"}
    argv = sys.argv[1:]
    if argv and (argv[0] in _CLI_SUBCOMMANDS or argv[0].startswith("-")):
        ec.main()
        return

    # Windows/macOS need root at launch; Linux scans work as a regular user
    # and fixes handle their own elevation via pkexec when needed.
    if _UI_OS != "Linux":
        _ensure_admin()

    # High-fidelity pygame splash (real raster renderer). Runs fully and closes
    # its own window *before* Tk is created. Falls back to the Tk splash below
    # if pygame is not installed or anything goes wrong.
    used_pygame_splash = False
    _splash_err = ""
    try:
        from exposure_checker.gui import splash as gullwing_splash
        used_pygame_splash = gullwing_splash.run_splash(version=ec.__version__)
    except Exception as _e:
        used_pygame_splash = False
        _splash_err = repr(_e)

    # Diagnostic breadcrumb: records which interpreter launched the app and
    # whether the cinematic splash ran. Lets us tell a system-python launch
    # (old Tk splash) from a venv launch at a glance. Best-effort; never fatal.
    try:
        import datetime as _dt
        with open(os.path.join(tempfile.gettempdir(), "gullwing_launch.log"),
                  "a") as _lg:
            _lg.write(
                f"{_dt.datetime.now():%Y-%m-%d %H:%M:%S}  "
                f"python={sys.executable}  cinematic_splash={used_pygame_splash}"
                + (f"  err={_splash_err}" if _splash_err else "") + "\n")
    except Exception:
        pass

    root = tk.Tk()
    root.withdraw()
    T.load_fonts()
    # On HiDPI Windows, sync Tk's logical scaling to the real DPI so fonts and
    # canvas geometry match the crispness we enabled at process level.
    if _UI_OS == "Windows":
        try:
            import ctypes
            dpi = ctypes.windll.user32.GetDpiForSystem()
            if dpi and dpi != 96:
                root.tk.call("tk", "scaling", dpi / 72.0)
        except Exception:
            pass
    app_built = [False]
    app_ref   = [None]

    def _show_main():
        if not app_built[0]:
            app_built[0] = True
            app_ref[0] = App(root)
            root.after(200, lambda: _first_run_wizard(root, app_ref[0]))
        root.deiconify()
        root.lift()

    if used_pygame_splash:
        # The pygame splash already played; go straight to the app.
        _show_main()
    else:
        try:
            splash = _show_splash(root)
            splash.wait_done(_show_main)
        except Exception:
            _show_main()

    root.mainloop()


if __name__ == "__main__":
    main()
