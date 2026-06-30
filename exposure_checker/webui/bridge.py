"""The JS↔Python bridge for the Gullwing HUD.

A single :class:`Bridge` instance is handed to pywebview as ``js_api``; every
public method is callable from the front-end as ``pywebview.api.<method>(...)``
and returns JSON-serializable data. The bridge does the *real* work by reusing
Gullwing's existing logic — it never reimplements a scan, a score, or a fix:

  * scans            → :func:`exposure_checker.scan_to_report`
  * scoring          → :func:`exposure_checker._report._compute_score` + ``_SCORE_WEIGHTS``
  * elevated fixes   → :mod:`exposure_checker._elevate`
  * snapshot/revert  → :class:`exposure_checker._session._SessionTracker` + ``restore_snapshot``
  * live sensors     → ``psutil`` (counters only — no network calls)

Security invariant carried over from the Tkinter UI and the ``remediate`` work:
the front-end never supplies commands to run. ``scan()`` registers each finding
server-side keyed by a stable id; ``apply_fix``/``clean``/``confirm_fix`` accept
only those ids and execute the ``fix_cmds`` produced by Gullwing's own scan.
"""

import hashlib
import os
import platform
import re
import time

import exposure_checker as ec
from exposure_checker._notify import scan_to_report
from exposure_checker._elevate import (
    _is_root, _elevation_available, _batch_fix_elevated, _assemble_preview_cmds,
)
from exposure_checker._session import _SessionTracker

_OS = platform.system()

# HUD module id → the Gullwing scan tabs that feed it. benchmark/overclock are
# handled by their own methods (they're advisory and slow, not finding tabs).
_MODULE_TABS = {
    "home": ["security", "antivirus", "performance", "protection", "cleaner"],
    "perf": ["performance"],
    "sec":  ["security", "antivirus", "protection"],
    "clean": ["cleaner"],
}

# README S–F grade scale (distinct from _compute_score's A–F). Numeric score stays
# canonical from _compute_score; this only drives the big letter + its color.
_GRADE_BANDS = [
    ("S", 92, "#5BF5E4"), ("A", 82, "#7CFFB0"), ("B", 70, "#FFB23E"),
    ("C", 55, "#FFD23E"), ("D", 40, "#FF8A3D"), ("F", 0, "#FF4D5E"),
]

# Benchmark tier → representative 0–100 score (tiers come from checks/benchmark.py).
_TIER_SCORE = {"S": 98, "A": 88, "B": 76, "C": 62, "D": 48, "F": 32}
_TIER_RE = re.compile(r":\s*([SABCDF])\s*\(")
_MB_RE = re.compile(r"([\d,]+(?:\.\d+)?)\s*MB")


def _hud_grade(score: int) -> dict:
    for letter, lo, color in _GRADE_BANDS:
        if score >= lo:
            return {"letter": letter, "color": color}
    return {"letter": "F", "color": "#FF4D5E"}


def _fid(f: dict) -> str:
    """Stable id for a finding (label + its commands)."""
    key = (f.get("label", "") + "|" + "\n".join(f.get("fix_cmds") or [])).encode("utf-8")
    return hashlib.sha1(key).hexdigest()[:12]


def _map_finding(f: dict, cat: str) -> dict:
    """Translate a Gullwing finding into the prototype's card shape."""
    cmds = f.get("fix_cmds") or []
    sev = f.get("severity", "INFO")
    return {
        "id": _fid(f),
        "cat": cat,
        "sev": sev,
        "title": f.get("label", ""),
        "desc": f.get("why", ""),
        "fix": f.get("fix", ""),
        "command": cmds[0] if cmds else "",
        "commands": cmds,
        "points": ec._SCORE_WEIGHTS.get(sev, 0) if cmds else 0,
        "revertable": f.get("revertable", True),
        "fixable": bool(cmds),
        "fixed": False,
        # Parsed reclaimable size (GB) — meaningful for cleaner findings, 0 for
        # the rest; the front-end only reads it in the Disk Cleaner module.
        "_gb": round(_parse_mb(f.get("label", "")) / 1024.0, 2),
    }


def _count_sev(findings: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "REVIEW": 0, "INFO": 0}
    for f in findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    return counts


def _parse_mb(label: str):
    m = _MB_RE.search(label or "")
    if not m:
        return 0.0
    try:
        return float(m.group(1).replace(",", ""))
    except ValueError:
        return 0.0


class Bridge:
    """The pywebview ``js_api`` object. One instance per app run."""

    def __init__(self):
        self._tracker = _SessionTracker()
        self._registry: dict = {}     # id -> original finding dict (with fix_cmds)
        self._net_base = None         # (bytes_recv, bytes_sent, monotonic) for throughput
        try:
            import psutil
            psutil.cpu_percent(interval=None)   # prime the first delta
            io = psutil.net_io_counters()
            self._net_base = (io.bytes_recv, io.bytes_sent, time.monotonic())
        except Exception:
            pass

    # ── meta ────────────────────────────────────────────────────────────────
    def app_info(self) -> dict:
        try:
            n_incomplete = len(ec.find_incomplete_sessions())
        except Exception:
            n_incomplete = 0
        return {
            "version": ec.__version__,
            "os": _OS,
            "is_root": _is_root(),
            "elevation": _elevation_available(),
            "incomplete_sessions": n_incomplete,
        }

    # ── scanning ────────────────────────────────────────────────────────────
    def scan(self, module: str) -> dict:
        """Run the scan tabs behind a HUD module; register findings; return cards."""
        tabs = _MODULE_TABS.get(module, [])
        merged = {"checks": []}
        findings = []
        for tab in tabs:
            try:
                data = scan_to_report(tab)
            except Exception:
                continue
            merged["checks"].extend(data.get("checks", []))
            for chk in data.get("checks", []):
                for raw in chk.get("findings", []):
                    mapped = _map_finding(raw, tab)
                    self._registry[mapped["id"]] = raw
                    findings.append(mapped)
        score, _grade_af = ec._compute_score(merged)
        grade = _hud_grade(score)
        return {
            "module": module,
            "score": score,
            "grade": grade["letter"],
            "gradeColor": grade["color"],
            "findings": findings,
            "counts": _count_sev(findings),
        }

    # ── live sensors (psutil counters only — no network calls) ───────────────
    def live_sensors(self) -> dict:
        out = {"cpu": None, "temp": None, "ram": None, "ram_total": None,
               "disk": None, "disk_free": None, "net": None, "vpn": False}
        try:
            import psutil
        except Exception:
            return out
        try:
            out["cpu"] = round(psutil.cpu_percent(interval=None))
        except Exception:
            pass
        try:
            vm = psutil.virtual_memory()
            out["ram"] = round(vm.used / (1024 ** 3), 1)
            out["ram_total"] = round(vm.total / (1024 ** 3), 1)
        except Exception:
            pass
        try:
            du = psutil.disk_usage(os.path.expanduser("~"))
            out["disk"] = round(du.percent)
            out["disk_free"] = round(du.free / (1024 ** 3))
        except Exception:
            pass
        out["temp"] = self._read_temp(psutil)
        out["net"] = self._net_throughput(psutil)
        out["vpn"] = self._detect_vpn(psutil)
        return out

    def _read_temp(self, psutil):
        """Best-effort package temperature in °C (Linux/FreeBSD only)."""
        fn = getattr(psutil, "sensors_temperatures", None)
        if not fn:
            return None
        try:
            temps = fn()
        except Exception:
            return None
        for key in ("coretemp", "k10temp", "zenpower", "acpitz", "cpu_thermal"):
            if temps.get(key):
                return round(temps[key][0].current)
        for entries in temps.values():
            if entries:
                try:
                    return round(entries[0].current)
                except Exception:
                    continue
        return None

    def _net_throughput(self, psutil):
        """Download throughput in KB/s since the last poll (reads counters only)."""
        try:
            io = psutil.net_io_counters()
            now = time.monotonic()
        except Exception:
            return None
        if not self._net_base:
            self._net_base = (io.bytes_recv, io.bytes_sent, now)
            return 0
        prev_recv, _prev_sent, prev_t = self._net_base
        dt = max(0.001, now - prev_t)
        kbps = max(0.0, (io.bytes_recv - prev_recv) / 1024.0 / dt)
        self._net_base = (io.bytes_recv, io.bytes_sent, now)
        return round(kbps)

    def _detect_vpn(self, psutil):
        """True if a VPN-style interface is up (interface names only — no calls)."""
        try:
            names = psutil.net_if_stats()
        except Exception:
            return False
        for name, stats in names.items():
            low = name.lower()
            if getattr(stats, "isup", False) and (
                low.startswith(("tun", "tap", "wg", "ppp", "utun")) or "vpn" in low
            ):
                return True
        return False

    # ── fix confirmation + application ───────────────────────────────────────
    def _resolve(self, ids: list) -> list:
        return [self._registry[i] for i in (ids or []) if i in self._registry]

    def confirm_fix(self, ids: list) -> dict:
        """Data for the front-end confirmation modal (the exact commands shown)."""
        findings = self._resolve(ids)
        preview = _assemble_preview_cmds(findings) if findings else ""
        non_rev = [f.get("label", "?") for f in findings
                   if f.get("revertable", True) is False]
        return {
            "count": len(findings),
            "commands": preview.split("\n") if preview else [],
            "revertable": not bool(non_rev),
            "non_revertable": non_rev,
            "is_root": _is_root(),
            "elevation": _elevation_available(),
        }

    def apply_fix(self, ids: list) -> dict:
        """Snapshot, then run the selected findings' fixes under one elevation prompt."""
        findings = self._resolve(ids)
        if not findings:
            return {"ok": False, "reason": "no matching findings"}
        if not _is_root() and not _elevation_available():
            return {"ok": False, "denied": True,
                    "preview": _assemble_preview_cmds(findings),
                    "reason": "no elevation tool available"}
        label = (findings[0].get("label", "fix") if len(findings) == 1
                 else f"{len(findings)} fixes")
        if not self._tracker.before_fix(label):
            return {"ok": False,
                    "reason": "could not capture the current system state — fix aborted"}
        results = _batch_fix_elevated(findings)
        if results is None:
            return {"ok": False, "denied": True,
                    "preview": _assemble_preview_cmds(findings)}
        wrapped = self._wrap_results(results, [_fid(f) for f in findings])
        wrapped["can_revert"] = self._tracker.has_changes
        return wrapped

    def revert_session(self) -> dict:
        """Undo everything fixed this session by restoring the earliest snapshot."""
        snap = self._tracker.earliest_snap()
        if not snap:
            return {"ok": False, "reason": "nothing to revert"}
        try:
            results = ec.restore_snapshot(snap)
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}
        self._tracker.clear()
        out = [{"action": a, "ok": bool(ok), "detail": (d or "")[:200]}
               for a, ok, d in results]
        return {"ok": all(r["ok"] for r in out) if out else True, "results": out}

    # ── disk cleaner ──────────────────────────────────────────────────────────
    def clean(self, ids: list) -> dict:
        """Run the selected cleaner findings' fixes. Not snapshot-tracked (cleaning
        deletes temp files and is intentionally not revertable)."""
        findings = self._resolve(ids)
        if not findings:
            return {"ok": False, "reason": "nothing selected"}
        if not _is_root() and not _elevation_available():
            return {"ok": False, "denied": True,
                    "preview": _assemble_preview_cmds(findings)}
        results = _batch_fix_elevated(findings)
        if results is None:
            return {"ok": False, "denied": True,
                    "preview": _assemble_preview_cmds(findings)}
        wrapped = self._wrap_results(results, [_fid(f) for f in findings])
        reclaimed_mb = 0.0
        for f in findings:
            reclaimed_mb += _parse_mb(f.get("label", ""))
        wrapped["reclaimed_gb"] = round(reclaimed_mb / 1024.0, 1)
        return wrapped

    # ── benchmark (real CPU/memory/disk; GPU not benchmarked) ────────────────
    def benchmark(self) -> dict:
        try:
            data = scan_to_report("benchmark")
        except Exception:
            return {"cpu": None, "gpu": None, "mem": None, "disk": None,
                    "index": None, "cards": []}
        subs: dict = {}
        cards = []
        for chk in data.get("checks", []):
            for f in chk.get("findings", []):
                label = f.get("label", "")
                m = _TIER_RE.search(label)
                tier = m.group(1) if m else None
                score = _TIER_SCORE.get(tier)
                low = label.lower()
                if "hash" in low or "float" in low:
                    name, sub = "PROCESSOR", "cpu"
                elif "memory" in low:
                    name, sub = "MEMORY", "mem"
                elif "disk" in low:
                    name, sub = "STORAGE", "disk"
                else:
                    name, sub = label.split(":")[0].upper()[:16], None
                cards.append({"name": name, "score": score, "tier": tier,
                              "note": (f.get("why", "") or "")[:180]})
                if sub and score is not None:
                    subs.setdefault(sub, []).append(score)

        def _avg(vals):
            return round(sum(vals) / len(vals)) if vals else None
        cpu, mem, disk = _avg(subs.get("cpu")), _avg(subs.get("mem")), _avg(subs.get("disk"))
        avail = [v for v in (cpu, mem, disk) if v is not None]
        index = round(sum(avail) / len(avail)) if avail else None
        # GPU is intentionally None — Gullwing has no GPU benchmark; the card shows
        # "not benchmarked" rather than a fabricated number.
        return {"cpu": cpu, "gpu": None, "mem": mem, "disk": disk,
                "index": index, "cards": cards}

    # ── overclock advisor (advisory only — never applies anything) ───────────
    def overclock(self) -> dict:
        try:
            data = scan_to_report("overclock")
        except Exception:
            return {"headroom": None, "cards": []}
        cards = []
        headroom = None
        # Require a literal "+" so an incidental "66% of max" can't be misread as
        # headroom; only an explicit "+N%" advisory counts.
        pct = re.compile(r"\+\s*(\d{1,2})\s*%")
        for chk in data.get("checks", []):
            for f in chk.get("findings", []):
                label = f.get("label", "")
                cards.append({
                    "sev": f.get("severity", "INFO"),
                    "title": label,
                    "desc": (f.get("why", "") or "")[:220],
                    "fix": (f.get("fix", "") or "")[:220],
                })
                if headroom is None:
                    m = pct.search(label)
                    if m:
                        headroom = f"+{m.group(1)}%"
        return {"headroom": headroom, "cards": cards, "advisory": True}

    # ── crash recovery ───────────────────────────────────────────────────────
    def incomplete_sessions(self) -> list:
        try:
            return [{"ts": ts, "label": m.get("label", ts)}
                    for ts, m in ec.find_incomplete_sessions()]
        except Exception:
            return []

    def recover_session(self, ts: str) -> dict:
        try:
            sessions = {t: m for t, m in ec.find_incomplete_sessions()}
        except Exception:
            return {"ok": False, "reason": "could not list sessions"}
        m = sessions.get(ts)
        if not m:
            return {"ok": False, "reason": "session not found"}
        try:
            results = ec.restore_snapshot(m.get("snap", {}))
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}
        ec.mark_session_complete(ts)
        out = [{"action": a, "ok": bool(ok), "detail": (d or "")[:200]}
               for a, ok, d in results]
        return {"ok": all(r["ok"] for r in out) if out else True, "results": out}

    def dismiss_session(self, ts: str) -> dict:
        try:
            ec.mark_session_complete(ts)
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}

    # ── helpers ───────────────────────────────────────────────────────────────
    def _wrap_results(self, results: list, ids: list) -> dict:
        out = []
        for cmd, rc, o in results:
            out.append({"cmd": cmd, "rc": rc, "ok": rc == 0, "out": (o or "")[:400]})
        ok_all = all(r["ok"] for r in out) if out else True
        return {"ok": ok_all, "results": out, "fixed": ids if ok_all else []}
