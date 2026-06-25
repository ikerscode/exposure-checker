"""Persistent storage: scan history, accepted risks, compliance profiles, snapshots."""

import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

from ._core import _OS, _ps, _DEFAULT_BASELINE, _SMTP_CONFIG_PATH, _SCHEDULE_FILE, _Reporter
from ._remediate import _run_fix_cmd

def _data_dir() -> str:
    """Per-OS application data directory for snapshots, history, sessions.

    Recovery state (revert manifests) must live where each OS expects it:
    Windows %APPDATA%, macOS ~/Library/Application Support, Linux XDG.
    """
    if _OS == "Windows":
        base = os.environ.get("APPDATA") or os.path.expanduser(r"~\AppData\Roaming")
    elif _OS == "Darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "gullwing")


_EC_DATA_DIR = _data_dir()
_HISTORY_DIR  = os.path.join(_EC_DATA_DIR, "history")
_SNAPSHOT_DIR = os.path.join(_EC_DATA_DIR, "snapshots")
_SESSION_DIR  = os.path.join(_EC_DATA_DIR, "sessions")
_ACCEPTED_FILE = os.path.join(_EC_DATA_DIR, "accepted_risks.json")

_SESSION_TTL_DAYS = 7

def _snapshot_files_for_os():
    """Config files worth capturing before a fix, per platform.

    The revert system can only restore files it captured, so this list is
    OS-specific: Linux fixes edit sshd/ufw/sysctl; Windows has none of those
    paths (its fixes are registry/service changes the snapshot can't track),
    so we capture only the hosts file it actually has.
    """
    if _OS == "Windows":
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        return [os.path.join(sysroot, "System32", "drivers", "etc", "hosts")]
    if _OS == "Darwin":
        return [
            "/etc/ssh/sshd_config",
            "/etc/hosts",
            "/etc/pf.conf",
        ]
    return [
        "/etc/ssh/sshd_config",
        "/etc/ufw/user.rules",
        "/etc/ufw/user6.rules",
        "/etc/sysctl.conf",
        "/etc/sysctl.d/99-hardening.conf",  # our drop-in: capture prior content
        "/etc/hosts",
    ]

_SNAPSHOT_CAPTURED_FILES = _snapshot_files_for_os()

def save_scan_history(tab: str, score: int, grade: str, counts: dict) -> None:
    d = os.path.join(_HISTORY_DIR, tab.lower())
    os.makedirs(d, exist_ok=True)
    rec = {"ts": int(time.time()), "score": score, "grade": grade, "counts": counts}
    with open(os.path.join(d, f"{rec['ts']}.json"), "w") as fh:
        json.dump(rec, fh)
    files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
    for old in files[:-50]:
        try:
            os.unlink(os.path.join(d, old))
        except OSError:
            pass


def load_scan_history(tab: str, n: int = 30) -> list:
    """Return list of {ts, score, grade, counts} dicts, oldest-first."""
    d = os.path.join(_HISTORY_DIR, tab.lower())
    if not os.path.isdir(d):
        return []
    files = sorted(f for f in os.listdir(d) if f.endswith(".json"))[-n:]
    out = []
    for fname in files:
        try:
            with open(os.path.join(d, fname)) as fh:
                out.append(json.load(fh))
        except Exception:
            pass
    return out


# ── Accepted risks ────────────────────────────────────────────────────────────

def _risk_key(check: str, label: str) -> str:
    return f"{check}||{label}"


def load_accepted_risks() -> dict:
    """Return {key: {check, label, note, ts}} dict."""
    try:
        with open(_ACCEPTED_FILE) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def save_accepted_risk(check: str, label: str, note: str = "") -> None:
    risks = load_accepted_risks()
    risks[_risk_key(check, label)] = {
        "check": check, "label": label,
        "note": note, "ts": int(time.time()),
    }
    os.makedirs(_EC_DATA_DIR, exist_ok=True)
    with open(_ACCEPTED_FILE, "w") as fh:
        json.dump(risks, fh, indent=2)


def remove_accepted_risk(check: str, label: str) -> None:
    risks = load_accepted_risks()
    key = _risk_key(check, label)
    if key in risks:
        del risks[key]
        with open(_ACCEPTED_FILE, "w") as fh:
            json.dump(risks, fh, indent=2)


def is_accepted_risk(check: str, label: str) -> bool:
    return _risk_key(check, label) in load_accepted_risks()


# ── Compliance profiles ───────────────────────────────────────────────────────

COMPLIANCE_PROFILES = [
    "General",
    "CIS Level 1",
    "HIPAA Basics",
    "PCI-DSS Lite",
]

# CLI slug → internal profile name
_PROFILE_MAP = {
    "cis-l1":  "CIS Level 1",
    "hipaa":   "HIPAA Basics",
    "pci-dss": "PCI-DSS Lite",
}

# CLI slug → argparse flags that must be enabled for full coverage
_PROFILE_CHECKS = {
    "cis-l1":  ["ssh_audit", "check_firewall", "check_world_writable",
                 "check_suid", "check_kernel", "check_listeners", "check_packages"],
    "hipaa":   ["ssh_audit", "check_firewall", "check_auth", "check_packages",
                 "check_listeners", "check_sensitive_perms"],
    "pci-dss": ["ssh_audit", "check_firewall", "check_listeners", "check_packages"],
}

_COMPLIANCE_REQUIRED: dict = {
    "CIS Level 1": {
        "ssh":             "CRITICAL",
        "firewall":        "CRITICAL",
        "world-writable":  "HIGH",
        "suid":            "HIGH",
        "kernel":          "HIGH",
        "listeners":       "HIGH",
        "packages":        "MEDIUM",
    },
    "HIPAA Basics": {
        "ssh":             "CRITICAL",
        "firewall":        "CRITICAL",
        "auth":            "HIGH",
        "packages":        "HIGH",
        "listeners":       "HIGH",
        "sensitive-perms": "HIGH",
    },
    "PCI-DSS Lite": {
        "ssh":             "CRITICAL",
        "firewall":        "CRITICAL",
        "port":            "CRITICAL",
        "packages":        "HIGH",
        "tls":             "HIGH",
        "listeners":       "HIGH",
    },
}


def compliance_score(reporter_data: dict, profile: str) -> tuple:
    """Return (passing, total, pct) or (0, 0, None) for General/unknown."""
    required = _COMPLIANCE_REQUIRED.get(profile)
    if not required:
        return (0, 0, None)
    sev_rank  = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "REVIEW": 1, "INFO": 0}
    findings  = [f for chk in reporter_data.get("checks", [])
                 for f in chk.get("findings", [])]
    failing: set = set()
    for f in findings:
        chk_name = f.get("check", "").lower()
        sev      = f.get("severity", "INFO")
        for req_key, min_sev in required.items():
            if req_key in chk_name and sev_rank.get(sev, 0) >= sev_rank.get(min_sev, 0):
                failing.add(req_key)
    total   = len(required)
    passing = total - len(failing)
    pct     = int(100 * passing / total) if total else 100
    return (passing, total, pct)


# ── Headless scan + desktop notification ──────────────────────────────────────

def take_snapshot(label=""):
    """Capture current system state. Returns the snapshot dict."""
    import socket as _socket
    import datetime as _dt
    snap = {
        "version": 1,
        "label": label,
        "hostname": _socket.gethostname(),
        "timestamp": _dt.datetime.now().isoformat(),
        "files": {},
        "ufw_status": "",
        "ufw_rules": "",
        "suid_files": [],
        "world_writable": [],
    }
    for path in _SNAPSHOT_CAPTURED_FILES:
        try:
            with open(path) as fh:
                snap["files"][path] = fh.read()
        except FileNotFoundError:
            # Not present on this system — nothing to capture, not a failure.
            # Leaving it out of the dict lets before_fix() tell "no state to
            # back up here" apart from "exists but unreadable" (a perms issue).
            pass
        except OSError:
            snap["files"][path] = None

    ufw = shutil.which("ufw")
    if ufw:
        try:
            r = subprocess.run([ufw, "status", "verbose"],
                               capture_output=True, text=True, timeout=10)
            snap["ufw_status"] = r.stdout
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            r = subprocess.run([ufw, "show", "added"],
                               capture_output=True, text=True, timeout=10)
            snap["ufw_rules"] = r.stdout
        except (OSError, subprocess.TimeoutExpired):
            pass

    # Linux: record the prior runtime value of every kernel-hardening sysctl key
    # so Revert Session can put them back (the fix now writes a drop-in + applies
    # at runtime). An unreadable/absent key is recorded as None.
    if _OS == "Linux":
        prev = {}
        try:
            from .checks.security import _SYSCTL_RULES, _read_sysctl
            for rule in _SYSCTL_RULES:
                key = rule[0]
                val, err = _read_sysctl(key)
                prev[key] = None if err else val
        except Exception:
            prev = {}
        snap["sysctl_prev"] = prev
        snap["sysctl_dropin_existed"] = os.path.exists("/etc/sysctl.d/99-hardening.conf")

    return snap


def save_snapshot(snap):
    """Write snapshot to disk. Returns the file path."""
    import datetime as _dt
    os.makedirs(_SNAPSHOT_DIR, exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    label_slug = "".join(c if c.isalnum() else "_" for c in snap.get("label", ""))[:32]
    fname = f"snap_{ts}_{label_slug}.json" if label_slug else f"snap_{ts}.json"
    fpath = os.path.join(_SNAPSHOT_DIR, fname)
    import json as _json
    with open(fpath, "w") as fh:
        _json.dump(snap, fh, indent=2)
    return fpath


def list_snapshots():
    """Return list of (filepath, snap_dict) sorted newest-first."""
    import json as _json
    if not os.path.isdir(_SNAPSHOT_DIR):
        return []
    results = []
    for fname in sorted(os.listdir(_SNAPSHOT_DIR), reverse=True):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(_SNAPSHOT_DIR, fname)
        try:
            with open(fpath) as fh:
                snap = _json.load(fh)
            results.append((fpath, snap))
        except (OSError, ValueError):
            pass
    return results


def delete_snapshot(fpath):
    """Delete a snapshot file."""
    try:
        os.unlink(fpath)
        return True
    except OSError:
        return False


def restore_snapshot(snap):
    """Apply a snapshot, restoring captured files and UFW state.
    Returns list of (action, success, detail) tuples."""
    results = []
    for path, content in snap.get("files", {}).items():
        if content is None:
            continue
        try:
            with open(path, "w") as fh:
                fh.write(content)
            results.append((f"restore {path}", True, ""))
        except OSError as e:
            results.append((f"restore {path}", False, str(e)))

    if "/etc/ssh/sshd_config" in snap.get("files", {}):
        if _OS == "Windows":
            sshd_cmd = "Restart-Service sshd -ErrorAction SilentlyContinue"
        elif _OS == "Darwin":
            sshd_cmd = "launchctl kickstart -k system/com.openssh.sshd 2>/dev/null || true"
        else:
            sshd_cmd = (
                "systemctl reload-or-restart ssh 2>/dev/null "
                "|| systemctl reload-or-restart sshd 2>/dev/null || true"
            )
        rc, out = _run_fix_cmd(sshd_cmd)
        results.append(("reload sshd", rc == 0, out.strip()[:120]))

    ufw_rules = snap.get("ufw_rules", "")
    ufw_status = snap.get("ufw_status", "")
    ufw = shutil.which("ufw")
    if ufw and ufw_rules:
        rc, out = _run_fix_cmd("ufw --force reset")
        results.append(("ufw reset", rc == 0, out.strip()[:120]))
        for rule_line in ufw_rules.splitlines():
            rule_line = rule_line.strip()
            if rule_line.startswith("ufw "):
                rc, out = _run_fix_cmd(rule_line)
                results.append((rule_line, rc == 0, out.strip()[:120]))
        if "Status: active" in ufw_status:
            rc, out = _run_fix_cmd("ufw --force enable")
            results.append(("ufw enable", rc == 0, out.strip()[:120]))
        else:
            rc, out = _run_fix_cmd("ufw disable")
            results.append(("ufw disable", rc == 0, out.strip()[:120]))

    # Restore kernel (sysctl) parameters to their captured prior runtime values,
    # then reconcile our hardening drop-in.
    sysctl_prev = snap.get("sysctl_prev", {})
    if sysctl_prev:
        for key, prior in sysctl_prev.items():
            if prior is None:
                continue
            rc, out = _run_fix_cmd(
                f"sysctl -w {shlex.quote(key)}={shlex.quote(prior)}")
            results.append((f"sysctl {key}={prior}", rc == 0, out.strip()[:120]))

        dropin = "/etc/sysctl.d/99-hardening.conf"
        if not snap.get("sysctl_dropin_existed", False):
            # Gullwing created the drop-in — remove it so nothing persists.
            try:
                if os.path.exists(dropin):
                    os.unlink(dropin)
                results.append((f"remove {dropin}", True, ""))
            except OSError as e:
                results.append((f"remove {dropin}", False, str(e)))
        # If the drop-in pre-existed, its prior content was captured in
        # snap["files"] and already rewritten by the file-restore loop above.

        rc, out = _run_fix_cmd("sysctl --system 2>/dev/null || true")
        results.append(("sysctl --system", rc == 0, out.strip()[:120]))

    return results


# ── Session manifest (disk-persistent revert state) ───────────────────────────

def write_session_manifest(session_ts: str, label: str, snap: dict) -> bool:
    """Persist a pre-fix snapshot to disk under sessions/<session_ts>/.

    Written atomically (tmp file → rename) so a kill mid-write never leaves a
    corrupt manifest.  Returns True on success.
    """
    import tempfile as _tempfile
    d = os.path.join(_SESSION_DIR, session_ts)
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        return False
    manifest = {"session_ts": session_ts, "label": label, "snap": snap}
    dest = os.path.join(d, "manifest.json")
    tmp  = dest + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, default=str)
        os.replace(tmp, dest)   # atomic on POSIX; best-effort on Windows
        return True
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


def mark_session_complete(session_ts: str) -> None:
    """Write a 'completed' sentinel so the session is not surfaced on next launch."""
    d = os.path.join(_SESSION_DIR, session_ts)
    try:
        with open(os.path.join(d, "completed"), "w") as fh:
            fh.write("")
    except OSError:
        pass


def find_incomplete_sessions() -> list:
    """Return [(session_ts, manifest_dict)] for sessions that:
      - have a manifest.json but no 'completed' marker
      - are less than _SESSION_TTL_DAYS old

    Older or corrupt dirs are silently skipped (not deleted — safety first).
    """
    if not os.path.isdir(_SESSION_DIR):
        return []
    cutoff = time.time() - _SESSION_TTL_DAYS * 86400
    results = []
    try:
        entries = sorted(os.scandir(_SESSION_DIR), key=lambda e: e.name)
    except OSError:
        return []
    for entry in entries:
        if not entry.is_dir():
            continue
        if os.path.exists(os.path.join(entry.path, "completed")):
            continue
        manifest_path = os.path.join(entry.path, "manifest.json")
        if not os.path.exists(manifest_path):
            continue
        try:
            if os.path.getmtime(manifest_path) < cutoff:
                continue
            with open(manifest_path, encoding="utf-8") as fh:
                manifest = json.load(fh)
            results.append((entry.name, manifest))
        except (OSError, json.JSONDecodeError):
            pass
    return results


# ── Remediation ───────────────────────────────────────────────────────────────

