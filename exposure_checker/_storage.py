"""Persistent storage: scan history, accepted risks, compliance profiles, snapshots."""

import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time

from ._core import _OS, _ps, _DEFAULT_BASELINE, _SMTP_CONFIG_PATH, _SCHEDULE_FILE, _Reporter
from ._remediate import _run_fix_cmd

_EC_DATA_DIR = os.path.join(
    os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"),
    "gullwing",
)
_HISTORY_DIR = os.path.join(_EC_DATA_DIR, "history")
_SNAPSHOT_DIR = os.path.join(_EC_DATA_DIR, "snapshots")
_ACCEPTED_FILE = os.path.join(_EC_DATA_DIR, "accepted_risks.json")

_SNAPSHOT_CAPTURED_FILES = [
    "/etc/ssh/sshd_config",
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
    "/etc/sysctl.conf",
    "/etc/hosts",
]

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

    return results


# ── Remediation ───────────────────────────────────────────────────────────────

