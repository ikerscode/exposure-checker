#!/usr/bin/env python3
"""
Exposure Checker — desktop interface.

    exposure-checker-ui
    python3 exposure_checker_ui.py
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
import webbrowser

_UI_OS = platform.system()  # "Linux" | "Darwin" | "Windows"

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exposure_checker as ec

# ── Palette ────────────────────────────────────────────────────────────────────

C = {
    "bg":         "#0a0e14",   # deeper, more premium than #0d1117
    "panel":      "#131920",
    "input":      "#1c2430",
    "border":     "#252d3a",
    "text":       "#e8edf4",
    "muted":      "#6b7786",
    "accent":     "#00b4d8",   # ocean cyan — not GitHub blue
    "accent2":    "#0077a8",   # darker accent for pressed states
    "CRITICAL":   "#f25757",
    "HIGH":       "#f5922e",
    "MEDIUM":     "#e8c13a",
    "REVIEW":     "#6b7786",
    "INFO":       "#3d4a5c",
    "ok":         "#34c96a",
    "err":        "#f25757",
    "cmd":        "#60b8d4",
    "hdr":        "#b892f5",
    "log_bg":     "#060a0f",
    "radar_bg":   "#05100d",
    "radar_grid": "#0b2419",
}

_SEV_ORDER   = ["CRITICAL", "HIGH", "MEDIUM", "REVIEW", "INFO"]
_GRADE_COLOR = {
    "A": "#34c96a", "B": "#00b4d8",
    "C": "#e8c13a", "D": "#f5922e", "F": "#f25757", "—": "#6b7786",
}
_GRADE_LABEL = {
    "A": "EXCELLENT", "B": "GOOD",
    "C": "FAIR",      "D": "POOR", "F": "CRITICAL",
}


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
                 font=("TkDefaultFont", 9))
    s.map("TButton",
          background=[("active", "#2d333b"), ("pressed", border)],
          relief=[("pressed", "flat"), ("active", "flat")])

    s.configure("Accent.TButton", background=accent, foreground="#060a0f",
                 bordercolor=accent, font=("TkDefaultFont", 10, "bold"),
                 padding=(20, 8))
    s.map("Accent.TButton",
          background=[("active", "#0099b8"), ("pressed", "#0077a8")],
          foreground=[("active", "#060a0f")])

    s.configure("Fix.TButton", background="#1e3a28", foreground="#3fb950",
                 bordercolor="#2ea043", padding=(14, 6),
                 font=("TkDefaultFont", 9, "bold"))
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
                 font=("TkDefaultFont", 9, "bold"))
    s.map("Revert.TButton",
          background=[("active", "#3d2518"), ("disabled", "#1a1008")],
          foreground=[("disabled", "#4a2818")],
          bordercolor=[("disabled", "#3a2010")])

    s.configure("Treeview", background=panel, foreground=text,
                 fieldbackground=panel, bordercolor=border, rowheight=30)
    s.configure("Treeview.Heading", background=C["input"], foreground=muted,
                 bordercolor=border, font=("TkDefaultFont", 9, "bold"),
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
                 padding=(20, 9), font=("TkDefaultFont", 10, "bold"))
    s.map("TNotebook.Tab",
          background=[("selected", bg)],
          foreground=[("selected", text)])


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
                         font=("TkDefaultFont", 26), anchor="center")
        self.create_text(cx, cy + 18, text="PRESS SCAN", fill=C["muted"],
                         font=("TkDefaultFont", 9), anchor="center")

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
                             font=("TkFixedFont", 8), anchor="center")

    def _draw_score(self):
        self.delete("all")
        cx, cy, r, rw = self._cx, self._cy, self._r, self._rw
        color = _GRADE_COLOR.get(self._grade, C["muted"])
        self.create_arc(cx-r, cy-r, cx+r, cy+r, start=0, extent=359.9,
                        style=tk.ARC, outline=C["border"], width=rw)
        if self._score > 0:
            self.create_arc(cx-r, cy-r, cx+r, cy+r,
                            start=90, extent=-(self._score / 100 * 359.9),
                            style=tk.ARC, outline=color, width=rw)
        self.create_text(cx, cy - 16,
                         text=self._grade if self._grade != "—" else "?",
                         fill=color,
                         font=("TkDefaultFont", 44, "bold"), anchor="center")
        self.create_text(cx, cy + 24, text=f"{self._score}/100",
                         fill=C["muted"], font=("TkDefaultFont", 11),
                         anchor="center")
        if self._score == self._target and self._grade in _GRADE_LABEL:
            self.create_text(cx, cy + r + 16,
                             text=_GRADE_LABEL[self._grade], fill=color,
                             font=("TkDefaultFont", 9, "bold"), anchor="center")


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
                    fill=C["muted"], font=("TkDefaultFont", 8))
            else:
                self.create_text(
                    self._W // 2, self._H // 2,
                    text="No history yet",
                    fill=C["INFO"], font=("TkDefaultFont", 8))
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
                         fill=C["text"], font=("TkDefaultFont", 7),
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
                 font=("TkDefaultFont", 8, "bold"), anchor="w").pack(
            fill=tk.X, padx=18, pady=(14, 0))
        tk.Label(self, text=label, bg=C["panel"], fg=C["text"],
                 font=("TkDefaultFont", 10, "bold"),
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
                     font=("TkDefaultFont", 9)).pack(**pad)
            ttk.Button(self, text="Remove acceptance",
                       command=self._remove).pack(padx=18, pady=(0, 14), anchor="e")
        else:
            tk.Label(self,
                     text="Mark this finding as an accepted risk.\n"
                          "It will still appear but won't count toward the score.",
                     bg=C["panel"], fg=C["muted"],
                     font=("TkDefaultFont", 9),
                     justify=tk.LEFT).pack(**pad)
            tk.Label(self, text="Note (optional)", bg=C["panel"], fg=C["muted"],
                     font=("TkDefaultFont", 8, "bold"), anchor="w").pack(
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
                 font=("TkDefaultFont", 13, "bold")).pack(padx=20, pady=(16, 4), anchor="w")
        tk.Label(self,
                 text="Runs silently in the background and sends a\n"
                      "desktop notification if new issues are found.",
                 bg=C["panel"], fg=C["muted"],
                 font=("TkDefaultFont", 9), justify=tk.LEFT).pack(padx=20, anchor="w")

        tk.Frame(self, bg=C["border"], height=1).pack(fill=tk.X, padx=20, pady=10)

        en_f = tk.Frame(self, bg=C["panel"])
        en_f.pack(fill=tk.X, **pad)
        ttk.Checkbutton(en_f, text="Enable scheduled scan",
                        variable=self._enabled).pack(anchor="w")

        time_f = tk.Frame(self, bg=C["panel"])
        time_f.pack(fill=tk.X, padx=20, pady=(4, 0))
        tk.Label(time_f, text="Daily at", bg=C["panel"], fg=C["muted"],
                 font=("TkDefaultFont", 9)).pack(side=tk.LEFT)
        ttk.Spinbox(time_f, from_=0, to=23, width=3, format="%02.0f",
                    textvariable=self._hour_var).pack(side=tk.LEFT, padx=(8, 2))
        tk.Label(time_f, text=":", bg=C["panel"], fg=C["muted"],
                 font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)
        ttk.Spinbox(time_f, from_=0, to=59, width=3, format="%02.0f",
                    textvariable=self._min_var).pack(side=tk.LEFT, padx=(2, 0))

        tk.Label(self, text="Tabs to scan",
                 bg=C["panel"], fg=C["muted"],
                 font=("TkDefaultFont", 8, "bold")).pack(padx=20, pady=(12, 2), anchor="w")
        for key, label in (("security", "Security"), ("antivirus", "Antivirus"),
                            ("cleaner", "Cleaner")):
            ttk.Checkbutton(self, text=label,
                            variable=self._tabs[key]).pack(padx=32, anchor="w")

        # Status of current cron
        cron_jobs = ec._read_ec_cron_jobs()
        status_txt = f"Active: {cron_jobs[0]}" if cron_jobs else "Not scheduled"
        tk.Label(self, text=status_txt,
                 bg=C["panel"], fg=C["muted"],
                 font=("TkDefaultFont", 7),
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
                 font=("TkDefaultFont", 9), width=8, anchor="w").pack(side=tk.LEFT)
        self._bar = tk.Canvas(self, width=self._BAR_W, height=5,
                              bg=C["input"], highlightthickness=0)
        self._bar.pack(side=tk.LEFT, padx=(2, 4))
        self._fill = self._bar.create_rectangle(0, 0, 0, 5,
                                                fill=C[severity], outline="")
        self._lbl = tk.Label(self, text="0", bg=C["panel"], fg=C["muted"],
                             font=("TkDefaultFont", 9, "bold"), width=3,
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
        self._q.put(("finding", {
            "check":    self._cur["check"] if self._cur else "",
            "severity": severity,
            "label":    label,
            "why":      why,
            "fix":      fix,
            "fix_cmds": fix_cmds or [],
        }))


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
    """Single osascript administrator prompt for all fixes on macOS."""
    results = []
    for i, cmd in enumerate(cmds):
        safe = cmd.replace("\\", "\\\\").replace('"', '\\"')
        script = f'do shell script "{safe}" with administrator privileges'
        try:
            r = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True, text=True, timeout=120,
            )
            results.append((cmd, r.returncode, (r.stdout + r.stderr).strip()))
        except subprocess.TimeoutExpired:
            results.append((cmd, 1, "timed out"))
        except OSError as exc:
            results.append((cmd, 1, str(exc)))
    return results


def _batch_fix_windows(cmds):
    """Run each fix command elevated via PowerShell Start-Process on Windows."""
    results = []
    for cmd in cmds:
        safe = cmd.replace("'", "''")
        ps = (
            f"$p = Start-Process powershell.exe "
            f"-ArgumentList '-Command','{safe}' "
            f"-Verb RunAs -Wait -PassThru; $p.ExitCode"
        )
        try:
            r = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=120,
            )
            rc_s = r.stdout.strip()
            rc = int(rc_s) if rc_s.lstrip("-").isdigit() else r.returncode
            results.append((cmd, rc, r.stderr.strip()))
        except subprocess.TimeoutExpired:
            results.append((cmd, 1, "timed out"))
        except OSError as exc:
            results.append((cmd, 1, str(exc)))
    return results


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
             font=("TkDefaultFont", 12, "bold")).pack(pady=(18, 4), padx=20)
    tk.Label(dlg,
             text="Run these commands in a terminal, or launch\n"
                  "exposure-checker-ui with sudo to auto-apply.",
             bg=C["panel"], fg=C["muted"],
             justify=tk.CENTER).pack(pady=(0, 10), padx=20)

    cmds_text = "\n".join(f"sudo {c}" for c in all_cmds)
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
    """Captures pre-fix snapshots so everything applied this session can be reverted."""

    def __init__(self):
        self._snaps: list = []  # [(label, snap_dict)]

    def before_fix(self, label: str):
        snap = ec.take_snapshot(label=f"before: {label}")
        self._snaps.append((label, snap))

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
                 font=("TkDefaultFont", 14, "bold")).pack()
        tk.Label(f, text="Press Scan now to analyse this machine",
                 bg=C["bg"], fg=C["INFO"],
                 font=("TkDefaultFont", 10)).pack(pady=(6, 0))

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
        if event.num == 4:
            self._canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            self._canvas.yview_scroll(1, "units")
        else:
            self._canvas.yview_scroll(int(-event.delta / 60), "units")

    # ── Public API ────────────────────────────────────────────────────────────

    def add_finding(self, f: dict):
        idx = len(self._findings)
        self._findings.append(f)
        if f.get("fix_cmds"):
            self._selected[idx] = tk.BooleanVar(value=False)
        self._build_card(f)
        self._set_empty(False)

    def clear(self):
        for card in self._cards:
            card.destroy()
        self._cards.clear()
        self._findings.clear()
        self._selected.clear()
        self._set_empty(True)
        self._canvas.yview_moveto(0)

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
        accepted = f.get("_accepted", False)
        sev      = f.get("severity", "REVIEW")
        stripe   = self._STRIPE.get(sev, C["muted"]) if not accepted else C["border"]
        sev_cap  = self._SEV_CAP.get(sev, sev.title())
        card_bg  = C["panel"] if not accepted else C["bg"]

        card = tk.Frame(self._inner, bg=card_bg,
                        highlightthickness=1,
                        highlightbackground=C["border"])
        card.pack(fill=tk.X, padx=12, pady=(8, 0))
        self._cards.append(card)

        tk.Frame(card, bg=stripe, width=4).pack(side=tk.LEFT, fill=tk.Y)

        body = tk.Frame(card, bg=card_bg)
        body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 8), pady=9)

        # Severity badge + check name row
        top = tk.Frame(body, bg=card_bg)
        top.pack(fill=tk.X)
        badge_bg = stripe if not accepted else C["input"]
        badge_fg = "#060a0f" if not accepted else C["muted"]
        tk.Label(top, text=sev_cap.upper(),
                 bg=badge_bg, fg=badge_fg,
                 font=("TkDefaultFont", 7, "bold"),
                 padx=6, pady=2).pack(side=tk.LEFT)
        check_txt = f.get("check", "")
        if check_txt:
            tk.Label(top, text=f"  {check_txt}",
                     bg=card_bg, fg=C["muted"],
                     font=("TkDefaultFont", 8)).pack(side=tk.LEFT)
        if accepted:
            tk.Label(top, text="  Accepted risk",
                     bg=card_bg, fg=C["ok"],
                     font=("TkDefaultFont", 7, "bold")).pack(side=tk.LEFT)

        title_fg = C["muted"] if accepted else C["text"]
        tk.Label(body, text=f.get("label", ""),
                 bg=card_bg, fg=title_fg,
                 font=("TkDefaultFont", 10, "bold"),
                 anchor="w", wraplength=500,
                 justify=tk.LEFT).pack(fill=tk.X, pady=(5, 2))

        why = f.get("why", "")
        if why and not accepted:
            tk.Label(body, text=why,
                     bg=card_bg, fg=C["muted"],
                     font=("TkDefaultFont", 9),
                     anchor="w", wraplength=500,
                     justify=tk.LEFT).pack(fill=tk.X)

        # Right-side action column
        right_f = tk.Frame(card, bg=card_bg)
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

        self._bind_scroll(card)

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
        # Save packing position by temporarily recording neighbor
        cards_before = self._cards[:idx]
        cards_after  = self._cards[idx + 1:]
        # Destroy old placeholder and rebuild
        accepted = f.get("_accepted", False)
        sev      = f.get("severity", "REVIEW")
        stripe   = self._STRIPE.get(sev, C["muted"]) if not accepted else C["border"]
        sev_cap  = self._SEV_CAP.get(sev, sev.title())
        card_bg  = C["panel"] if not accepted else C["bg"]

        card = tk.Frame(self._inner, bg=card_bg,
                        highlightthickness=1,
                        highlightbackground=C["border"])
        # Pack after the card before us
        if cards_before and cards_before[-1].winfo_exists():
            card.pack(fill=tk.X, padx=12, pady=(8, 0),
                      after=cards_before[-1])
        else:
            card.pack(fill=tk.X, padx=12, pady=(8, 0))
        self._cards[idx] = card

        tk.Frame(card, bg=stripe, width=4).pack(side=tk.LEFT, fill=tk.Y)
        body = tk.Frame(card, bg=card_bg)
        body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 8), pady=9)
        top = tk.Frame(body, bg=card_bg)
        top.pack(fill=tk.X)
        badge_bg = stripe if not accepted else C["input"]
        badge_fg = "#060a0f" if not accepted else C["muted"]
        tk.Label(top, text=sev_cap.upper(), bg=badge_bg, fg=badge_fg,
                 font=("TkDefaultFont", 7, "bold"), padx=6, pady=2).pack(side=tk.LEFT)
        check_txt = f.get("check", "")
        if check_txt:
            tk.Label(top, text=f"  {check_txt}", bg=card_bg, fg=C["muted"],
                     font=("TkDefaultFont", 8)).pack(side=tk.LEFT)
        if accepted:
            tk.Label(top, text="  Accepted risk", bg=card_bg, fg=C["ok"],
                     font=("TkDefaultFont", 7, "bold")).pack(side=tk.LEFT)
        title_fg = C["muted"] if accepted else C["text"]
        tk.Label(body, text=f.get("label", ""), bg=card_bg, fg=title_fg,
                 font=("TkDefaultFont", 10, "bold"),
                 anchor="w", wraplength=500, justify=tk.LEFT).pack(
            fill=tk.X, pady=(5, 2))
        why = f.get("why", "")
        if why and not accepted:
            tk.Label(body, text=why, bg=card_bg, fg=C["muted"],
                     font=("TkDefaultFont", 9),
                     anchor="w", wraplength=500, justify=tk.LEFT).pack(fill=tk.X)
        right_f = tk.Frame(card, bg=card_bg)
        right_f.pack(side=tk.RIGHT, padx=(4, 8), pady=9)
        if f.get("fix_cmds") and self._on_fix_one and not accepted:
            btn = ttk.Button(right_f, text="Fix this →", style="Fix.TButton",
                              command=lambda _f=f: self._on_fix_one(_f))
            btn.pack(pady=(0, 4))
            f["_fix_btn"] = btn
        overflow = ttk.Button(
            right_f, text="⋯", style="Dim.TButton", width=2,
            command=lambda _f=f, _c=card: self._open_overflow(_f, _c))
        overflow.pack()
        self._bind_scroll(card)

    def _bind_scroll(self, widget):
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            widget.bind(seq, self._on_scroll)
        for child in widget.winfo_children():
            self._bind_scroll(child)


# ── ScanTab ────────────────────────────────────────────────────────────────────

_TAB_ICONS = {"Security": "◈", "Antivirus": "⊛", "Cleaner": "⊙"}


class ScanTab:
    """One notebook tab: CenterStage + severity bars + findings cards + fix flow."""

    def __init__(self, notebook, title, score_label, app, run_fn,
                 session_tracker=None):
        self._title       = title
        self._score_label = score_label
        self.app          = app
        self._run_fn      = run_fn
        self._tracker     = session_tracker

        self._q:             queue.Queue = queue.Queue()
        self._findings:      list        = []
        self._reporter_data: dict        = {}
        self._scanning:      bool        = False
        self._last_html:     str         = ""

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

        self._btn_scan = ttk.Button(fix_f, text="▶  Scan now",
                                    style="Accent.TButton",
                                    command=self.start_scan)
        self._btn_scan.pack(fill=tk.X)

        # Score label + gauge (top of left panel)
        tk.Label(left, text=self._score_label,
                 bg=C["panel"], fg=C["muted"],
                 font=("TkDefaultFont", 8, "bold")).pack(pady=(10, 4))

        self._stage = CenterStage(left, size=174)
        self._stage.pack(padx=12)

        self._coaching_lbl = tk.Label(left, text="",
                                       bg=C["panel"], fg=C["accent"],
                                       font=("TkDefaultFont", 8),
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
                 font=("TkDefaultFont", 7, "bold")).pack(anchor="w")
        self._compliance_var = tk.StringVar(value="General")
        comp_cb = ttk.Combobox(comp_f, textvariable=self._compliance_var,
                                values=ec.COMPLIANCE_PROFILES,
                                state="readonly", width=20)
        comp_cb.pack(fill=tk.X, pady=(2, 0))
        self._compliance_lbl = tk.Label(comp_f, text="",
                                         bg=C["panel"], fg=C["accent"],
                                         font=("TkDefaultFont", 7),
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
        n_cmd = sum(len(f.get("fix_cmds", [])) for f in findings)
        if not _is_root() and not _elevation_available():
            _show_fix_denied_dialog(self.app.root, findings)
            return

        sudo_note = (
            "" if _is_root()
            else "\n\nYou will be asked for your password once for all fixes."
        )
        noun = "issue" if len(findings) == 1 else "issues"
        if not messagebox.askyesno(
            "Apply fixes",
            f"Fix {len(findings)} {noun} ({n_cmd} command(s))?{sudo_note}",
        ):
            return

        if self._tracker:
            self._tracker.before_fix(self._title)
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
                    if rc != 0 and out:
                        self._q.put(("log",
                                     (f"      {out.strip()[:120]}\n", "muted")))

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

        # Save history + refresh sparkline
        ec.save_scan_history(self._title, score, grade, counts)
        self._sparkline.push(score, grade)

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

    def _finish_fix(self, success: bool):
        self.app.set_gull_fixing(False)
        self.app._progress.stop()
        self._btn_scan.configure(state=tk.NORMAL)
        self._pane.set_fix_btn_state(True)
        self._refresh_btns()
        if success:
            self.app._set_status("Fixes applied — rescanning in 2s…")
            self.app._log_append("\nFixes applied. Rescanning now…\n", "ok")
            self.frame.after(2000, self.start_scan)
        else:
            self.app._set_status("Some fixes failed — check Scan activity.")

    # ── Report helpers ─────────────────────────────────────────────────────────

    def open_report(self):
        if not self._reporter_data:
            messagebox.showinfo("No report", "Run a scan first.")
            return
        if self._last_html and os.path.exists(self._last_html):
            webbrowser.open(f"file://{self._last_html}")
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
                 font=("TkDefaultFont", 8, "bold")).pack(side=tk.LEFT)
        tk.Label(ctrl,
                 text="Save a point-in-time backup of system config. "
                      "Restore any snapshot to roll back changes.",
                 bg=C["bg"], fg=C["INFO"],
                 font=("TkDefaultFont", 8)).pack(side=tk.LEFT, padx=(12, 0))

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


# ── Main application ───────────────────────────────────────────────────────────

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Exposure Checker  ·  Gull")
        root.minsize(900, 600)
        root.configure(bg=C["bg"])
        root.resizable(True, True)
        _configure_style(root)
        self._build()
        self._poll()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        r = self.root
        self._tracker = _SessionTracker()

        # ── Header ────────────────────────────────────────────────────────────
        HDR_H = 64
        hdr_canvas = tk.Canvas(r, height=HDR_H, bg="#0d1117",
                                highlightthickness=0)
        hdr_canvas.pack(fill=tk.X)

        def _paint_hdr(event=None):
            w = hdr_canvas.winfo_width()
            if w < 2:
                return
            hdr_canvas.delete("bg")
            # Subtle left→right gradient: dark navy to slightly bluer
            steps = 32
            for i in range(steps):
                x0 = int(i / steps * w)
                x1 = int((i + 1) / steps * w) + 1
                t  = i / steps
                rr = int(0x0d + t * 4)
                gg = int(0x11 + t * 8)
                bb = int(0x17 + t * 20)
                hdr_canvas.create_rectangle(x0, 0, x1, HDR_H,
                    fill=f"#{rr:02x}{gg:02x}{bb:02x}", outline="", tags="bg")
            # Accent line at bottom
            hdr_canvas.create_rectangle(0, HDR_H - 2, w, HDR_H,
                fill=C["accent"], outline="", tags="bg")

        hdr_canvas.bind("<Configure>", _paint_hdr)
        hdr_canvas.after(10, _paint_hdr)

        # Diamond logo
        logo = tk.Canvas(hdr_canvas, width=28, height=28,
                         bg="#0d1117", highlightthickness=0)
        hdr_canvas.create_window(18, HDR_H // 2, window=logo, anchor="w")
        logo.create_polygon(14, 1, 27, 14, 14, 27, 1, 14,
                            fill=C["accent"], outline="")

        # Title block
        title_f = tk.Frame(hdr_canvas, bg="#0d1117")
        hdr_canvas.create_window(56, HDR_H // 2, window=title_f, anchor="w")
        tk.Label(title_f, text="Exposure Checker",
                 bg="#0d1117", fg=C["text"],
                 font=("TkDefaultFont", 14, "bold")).pack(anchor="w")
        tk.Label(title_f, text="Security scanner for systems you own",
                 bg="#0d1117", fg=C["muted"],
                 font=("TkDefaultFont", 8)).pack(anchor="w")

        # Animated seagull mascot (right of title)
        GULL_W, GULL_H = 90, 58
        self._hdr_gull = tk.Canvas(hdr_canvas, width=GULL_W, height=GULL_H,
                                    bg="#0d1117", highlightthickness=0)
        hdr_canvas.create_window(310, HDR_H // 2,
                                  window=self._hdr_gull, anchor="w")
        self._hdr_gull_phase = 0.0
        self._animate_hdr_gull()

        # Version / admin label (pinned right via a separate window)
        root_note = "  ADMIN" if _is_root() else f"  {_UI_OS}"
        ver_lbl = tk.Label(hdr_canvas,
                           text=f"v{ec.__version__}{root_note}",
                           bg="#0d1117", fg=C["muted"],
                           font=("TkDefaultFont", 8))
        self._hdr_ver_win = hdr_canvas.create_window(
            9999, HDR_H // 2, window=ver_lbl, anchor="e")

        def _pin_ver(event=None):
            hdr_canvas.coords(self._hdr_ver_win,
                               hdr_canvas.winfo_width() - 14, HDR_H // 2)

        hdr_canvas.bind("<Configure>",
                         lambda e: (_paint_hdr(e), _pin_ver(e)))
        hdr_canvas.after(20, _pin_ver)

        # ── Target / TLS bar ──────────────────────────────────────────────────
        ctrl = tk.Frame(r, bg=C["bg"])
        ctrl.pack(fill=tk.X, padx=16, pady=(6, 4))

        tk.Label(ctrl, text="Target", bg=C["bg"], fg=C["muted"],
                 font=("TkDefaultFont", 8, "bold")).grid(
            row=0, column=0, sticky="w")
        tk.Label(ctrl, text="TLS host (optional)", bg=C["bg"], fg=C["muted"],
                 font=("TkDefaultFont", 8, "bold")).grid(
            row=0, column=2, sticky="w", padx=(16, 0))

        self._var_target = tk.StringVar(value="127.0.0.1")
        self._var_tls    = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._var_target, width=26).grid(
            row=1, column=0, sticky="ew")
        ttk.Entry(ctrl, textvariable=self._var_tls, width=26).grid(
            row=1, column=2, sticky="ew", padx=(16, 0))
        ctrl.grid_columnconfigure(0, weight=1)
        ctrl.grid_columnconfigure(2, weight=1)

        # Notebook with 4 tabs
        self._nb = ttk.Notebook(r)
        self._nb.pack(fill=tk.BOTH, expand=True, padx=16, pady=(6, 0))

        self._tab_security  = ScanTab(
            self._nb, "Security",  "Security score", self, self._run_security,
            session_tracker=self._tracker)
        self._tab_antivirus = ScanTab(
            self._nb, "Antivirus", "Threat status",  self, self._run_antivirus,
            session_tracker=self._tracker)
        self._tab_cleaner   = ScanTab(
            self._nb, "Cleaner",   "Clean status",   self, self._run_cleaner,
            session_tracker=self._tracker)
        self._tab_snapshots = SnapshotsTab(self._nb, self)

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
                 font=("TkDefaultFont", 8, "bold")).pack(side=tk.LEFT)

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
        self._btn_revert = ttk.Button(br, text="↩  Revert Session",
                                       style="Revert.TButton",
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
                 font=("TkDefaultFont", 9), anchor=tk.W).pack(
            side=tk.LEFT, fill=tk.X, expand=True, pady=7)
        self._progress = ttk.Progressbar(sb, mode="indeterminate", length=90)
        self._progress.pack(side=tk.RIGHT, padx=10, pady=7)

    # ── Seagull animation ─────────────────────────────────────────────────────

    def _animate_hdr_gull(self):
        c = self._hdr_gull
        c.delete("all")
        flap = math.sin(self._hdr_gull_phase * 2 * math.pi)
        # Fixing mode: gull turns warm amber and flaps faster
        if getattr(self, "_gull_fixing", False):
            _draw_gull_icon(c, 44, 30, flap=flap, scale=0.92,
                            body="#f0c060", wing="#d4a040",
                            beak="#e07010", eye="#3a2000")
            self._hdr_gull_phase = (self._hdr_gull_phase + 0.038) % 1.0
        else:
            _draw_gull_icon(c, 44, 30, flap=flap, scale=0.92)
            self._hdr_gull_phase = (self._hdr_gull_phase + 0.013) % 1.0
        self.root.after(45, self._animate_hdr_gull)

    def set_gull_fixing(self, fixing: bool):
        """Switch seagull mascot into/out of fix mode."""
        self._gull_fixing = fixing

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

    def _run_cleaner(self, reporter):
        ec.check_system_cleaner(reporter)

    # ── Shared helpers ────────────────────────────────────────────────────────

    def _get_active_tab(self) -> ScanTab:
        for tab in (self._tab_security, self._tab_antivirus, self._tab_cleaner):
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
        for tab in (self._tab_security, self._tab_antivirus, self._tab_cleaner):
            tab.poll()
        self.root.after(40, self._poll)


# ── Seagull drawing helper ─────────────────────────────────────────────────────

def _draw_gull_icon(cnv, cx, cy, flap=0.0, scale=1.0,
                    body="white", wing="#cce0ee",
                    beak="#e8a020", eye="#1a1a2a"):
    """Draw a seagull on `cnv` centered at (cx, cy).
    flap in [-1,1]: -1 wings down, +1 wings up.
    Pass body/wing/beak/eye to override colours (use for monochrome styles)."""
    s  = scale
    wy = int(flap * 14 * s)

    # Left wing
    cnv.create_polygon(
        cx,              cy - int(2*s),
        cx - int(8*s),  cy + wy // 2,
        cx - int(22*s), cy + wy,
        cx - int(18*s), cy + wy + int(4*s),
        cx - int(6*s),  cy + int(2*s),
        smooth=True, fill=wing, outline="",
    )
    # Right wing (foreshortened)
    wy2 = int(flap * 8 * s)
    cnv.create_polygon(
        cx,              cy - int(2*s),
        cx + int(5*s),  cy + wy2 // 2,
        cx + int(14*s), cy + wy2,
        cx + int(11*s), cy + wy2 + int(3*s),
        cx + int(3*s),  cy + int(2*s),
        smooth=True, fill=wing, outline="",
    )
    # Body
    cnv.create_oval(cx - int(11*s), cy - int(4*s),
                    cx + int(11*s), cy + int(4*s),
                    fill=body, outline="")
    # Head
    cnv.create_oval(cx + int(7*s), cy - int(8*s),
                    cx + int(16*s), cy,
                    fill=body, outline="")
    # Beak
    cnv.create_polygon(cx + int(14*s), cy - int(5*s),
                       cx + int(22*s), cy - int(4*s),
                       cx + int(14*s), cy - int(2*s),
                       fill=beak, outline="")
    # Eye
    cnv.create_oval(cx + int(11*s), cy - int(6*s),
                    cx + int(14*s), cy - int(3*s),
                    fill=eye, outline="")
    # Tail
    cnv.create_polygon(cx - int(11*s), cy,
                       cx - int(18*s), cy - int(4*s),
                       cx - int(18*s), cy + int(4*s),
                       fill=body, outline="")


# ── Venice splash animation ─────────────────────────────────────────────────────

class VeniceSplash:
    """Animated startup splash: seagull flies over a Venice dusk skyline."""

    W, H = 580, 310
    _DURATION = 3.2   # seconds total
    _FADE_IN  = 0.35
    _FADE_OUT = 0.45
    _TICK_MS  = 40    # ~25 fps

    _SKY_STOPS = [
        (0.00, "#06021a"),
        (0.25, "#150c38"),
        (0.50, "#4a1640"),
        (0.68, "#b03030"),
        (0.80, "#d86028"),
        (0.90, "#f0a020"),
        (1.00, "#ffc840"),
    ]

    def __init__(self, root):
        self._root  = root
        self._alive = True
        self._t     = 0.0

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

        self._draw_background()
        self._tick()

    @staticmethod
    def _lerp(stops, frac):
        for i in range(len(stops) - 1):
            y0, c0 = stops[i]
            y1, c1 = stops[i + 1]
            if y0 <= frac <= y1:
                t  = (frac - y0) / (y1 - y0) if y1 > y0 else 0.0
                r  = int(int(c0[1:3], 16) + t * (int(c1[1:3], 16) - int(c0[1:3], 16)))
                g  = int(int(c0[3:5], 16) + t * (int(c1[3:5], 16) - int(c0[3:5], 16)))
                b  = int(int(c0[5:7], 16) + t * (int(c1[5:7], 16) - int(c0[5:7], 16)))
                return f"#{r:02x}{g:02x}{b:02x}"
        return stops[-1][1]

    def _draw_background(self):
        cnv  = self._cnv
        w, h = self.W, self.H
        gy   = int(h * 0.62)   # horizon y

        # Sky gradient
        bands = 48
        for i in range(bands):
            y0    = int(i / bands * gy)
            y1    = int((i + 1) / bands * gy) + 1
            color = self._lerp(self._SKY_STOPS, i / bands)
            cnv.create_rectangle(0, y0, w, y1, fill=color, outline=color)

        # Stars
        rng = random.Random(7)
        for _ in range(70):
            sx = rng.randint(0, w)
            sy = rng.randint(0, int(gy * 0.55))
            b  = rng.randint(140, 240)
            cnv.create_oval(sx - 1, sy - 1, sx + 1, sy + 1,
                            fill=f"#{b:02x}{b:02x}{min(b+30,255):02x}",
                            outline="")

        # Moon
        mx, my, mr = w - 80, 52, 20
        for gr in (30, 25, 20):
            frac = (gr - 20) / 12
            gc   = int(255 * (1 - frac * 0.88))
            cnv.create_oval(mx - gr, my - gr, mx + gr, my + gr,
                            fill=f"#{gc:02x}{min(gc+18,255):02x}{gc:02x}",
                            outline="")
        cnv.create_oval(mx - mr, my - mr, mx + mr, my + mr,
                        fill="#fff8d0", outline="")

        # Horizon glow bands
        for gi in range(22):
            yr = gy - gi * 2
            t  = gi / 22
            r  = int(240 - t * 200)
            g  = int(100 - t * 80)
            b2 = int(20  - t * 14)
            cnv.create_rectangle(0, yr, w, yr + 2,
                                  fill=f"#{r:02x}{g:02x}{b2:02x}", outline="")

        # Water
        cnv.create_rectangle(0, gy, w, h, fill="#040e1e", outline="")

        # Water shimmer
        for i in range(10):
            wy2 = gy + 8 + i * 13
            for xi in range(0, w, rng.randint(35, 55)):
                cnv.create_line(xi, wy2, xi + rng.randint(8, 22), wy2,
                                fill="#162848", width=1)

        # ── Building silhouettes ─────────────────────────────────────────────
        col_far  = "#0c0e14"   # far buildings
        col_near = "#080a10"   # near buildings

        def rect(x1, y1, x2, y2, col=col_near):
            cnv.create_rectangle(x1, y1, x2, y2, fill=col, outline=col)
        def poly(*pts, col=col_near):
            cnv.create_polygon(*pts, fill=col, outline=col)

        # Far skyline layer
        for (x1, y1, x2) in [
            (0, 52, 70), (65, 38, 150), (145, 58, 230),
            (225, 28, 315), (310, 48, 390), (385, 42, 465), (460, 52, 580),
        ]:
            rect(x1, y1, x2, gy, col=col_far)

        # Campanile (tall bell tower, left)
        tx = 60
        ty = gy - 168
        rect(tx - 11, ty, tx + 11, gy)
        rect(tx - 14, ty - 8, tx + 14, ty)
        rect(tx - 9,  ty - 26, tx + 9, ty - 8)
        poly(tx - 14, ty - 8, tx, ty - 50, tx + 14, ty - 8)
        rect(tx - 3,  ty - 50, tx + 3, ty - 62)  # lantern
        poly(tx - 4, ty - 62, tx + 4, ty - 62, tx, ty - 74)

        # Dome church (Santa Maria style)
        dx, db = 155, gy - 58
        poly(95, db, 95, gy, 215, gy, 215, db,
             200, db - 18, 185, db - 32, 155, db - 52,
             125, db - 32, 110, db - 18, col=col_near)
        # Drum + dome
        cnv.create_arc(112, db - 96, 198, db - 8,
                       start=0, extent=180, fill=col_near, outline=col_near)
        rect(148, db - 96, 162, db - 108)
        poly(147, db - 108, 163, db - 108, 155, db - 124)
        # Side belfries
        for bx in (102, 206):
            rect(bx - 6, db - 30, bx + 6, db)
            poly(bx - 6, db - 30, bx, db - 42, bx + 6, db - 30)

        # Arched bridge (Rialto style)
        bx0, bx1 = 240, 340
        bxm = (bx0 + bx1) // 2
        arch_h = 40
        poly(bx0, gy, bx0, gy - 14, bx0 + 8, gy - 20,
             bx0 + 20, gy - 30, bxm, gy - arch_h - 4,
             bx1 - 20, gy - 30, bx1 - 8, gy - 20,
             bx1, gy - 14, bx1, gy, col=col_near)
        # Arch opening
        cnv.create_arc(bx0 + 18, gy - arch_h * 2 + 6,
                       bx1 - 18, gy - 8,
                       start=0, extent=180, fill="#040e1e", outline="")
        # Railings
        for ri in range(6):
            rx = bx0 + 28 + ri * 14
            rect(rx, gy - arch_h - 12, rx + 3, gy - arch_h - 20)

        # Right cluster buildings
        rect(350, gy - 88, 430, gy)
        rect(360, gy - 110, 410, gy - 88)
        poly(360, gy - 110, 385, gy - 132, 410, gy - 110)
        # Tall window arch on right cluster
        cnv.create_arc(370, gy - 106, 400, gy - 82,
                       start=0, extent=180, fill="#06101e", outline="")

        # Second tower (right)
        tx2 = 490
        ty2 = gy - 140
        rect(tx2 - 9, ty2, tx2 + 9, gy)
        rect(tx2 - 12, ty2 - 8, tx2 + 12, ty2)
        rect(tx2 - 7,  ty2 - 22, tx2 + 7, ty2 - 8)
        poly(tx2 - 12, ty2 - 8, tx2, ty2 - 40, tx2 + 12, ty2 - 8)
        rect(tx2 - 2, ty2 - 40, tx2 + 2, ty2 - 50)

        # Far right small buildings
        rect(430, gy - 60, 470, gy)
        rect(540, gy - 72, 580, gy)

        # Gondola poles in water
        pole_col = "#0d1c38"
        for px in (35, 110, 195, 295, 375, 450, 525):
            cnv.create_rectangle(px - 2, gy, px + 2, gy + 65,
                                 fill=pole_col, outline=pole_col)
            # Small ball finial
            cnv.create_oval(px - 4, gy - 4, px + 4, gy + 4,
                            fill=pole_col, outline="")

        # Gondola silhouette (bottom-left water)
        gx, ghy = 30, gy + 50
        poly(gx, ghy, gx + 70, ghy, gx + 80, ghy - 6,
             gx + 65, ghy - 10, gx + 5, ghy - 10, gx - 10, ghy - 5)
        # Gondolier
        rect(gx + 50, ghy - 28, gx + 56, ghy - 10)
        poly(gx + 47, ghy - 28, gx + 59, ghy - 28,
             gx + 55, ghy - 36, gx + 51, ghy - 36)

        # Text overlay (placed in water area so it doesn't cover buildings)
        ty_txt = gy + 28
        cnv.create_text(w // 2, ty_txt,
                        text="EXPOSURE CHECKER",
                        fill="#e6edf3",
                        font=("TkDefaultFont", 20, "bold"),
                        anchor="center")
        cnv.create_text(w // 2, ty_txt + 26,
                        text="Security scanner for systems you own",
                        fill="#7d8590",
                        font=("TkDefaultFont", 10),
                        anchor="center")
        cnv.create_text(w // 2, ty_txt + 48,
                        text=f"v{ec.__version__}",
                        fill="#4a5566",
                        font=("TkDefaultFont", 8),
                        anchor="center")

    def _tick(self):
        if not self._alive:
            return
        t  = self._t
        dt = self._TICK_MS / 1000.0

        # Alpha fade
        if self._can_alpha:
            if t < self._FADE_IN:
                self._win.attributes("-alpha", t / self._FADE_IN)
            elif t > self._DURATION - self._FADE_OUT:
                remaining = self._DURATION - t
                self._win.attributes(
                    "-alpha", max(0.0, remaining / self._FADE_OUT)
                )

        if t >= self._DURATION:
            self._alive = False
            self._win.destroy()
            return

        # Seagull position
        gull_progress = max(0.0, (t - 0.2) / (self._DURATION - 0.6))
        gull_x = -55 + gull_progress * (self.W + 110)
        gull_y = (int(self.H * 0.28)
                  + int(math.sin(gull_progress * math.pi * 1.8) * 22)
                  + int(math.sin(gull_progress * math.pi * 6) * 6))
        flap   = math.sin(t * 3.5 * 2 * math.pi)  # 3.5 Hz

        self._cnv.delete("gull")
        _draw_gull_icon(self._cnv, int(gull_x), gull_y, flap=flap,
                        scale=1.0)

        self._t += dt
        self._win.after(self._TICK_MS, self._tick)

    def wait_done(self, callback):
        """Poll until the animation finishes, then call callback."""
        if not self._alive:
            callback()
        else:
            # Must schedule on root, not _win — _win.destroy() cancels its own afters
            self._root.after(80, lambda: self.wait_done(callback))


def _show_splash(root):
    splash = VeniceSplash(root)
    return splash


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    root.withdraw()
    app_built = [False]

    def _show_main():
        if not app_built[0]:
            app_built[0] = True
            App(root)
        root.deiconify()
        root.lift()

    try:
        splash = _show_splash(root)
        splash.wait_done(_show_main)
    except Exception:
        _show_main()

    root.mainloop()


if __name__ == "__main__":
    main()
