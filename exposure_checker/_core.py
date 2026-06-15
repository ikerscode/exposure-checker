"""Core utilities: OS helpers, PowerShell runner, constants, and Reporter."""

import concurrent.futures  # noqa: F401 – re-exported for checks that use it
import datetime
import ipaddress            # noqa: F401 – used by portscan, re-exported
import json
import os
import re                   # noqa: F401 – used by security checks
import shlex
import shutil               # noqa: F401 – used by checks
import socket               # noqa: F401 – used by portscan
import ssl                  # noqa: F401 – used by TLS check
import subprocess
import sys
import time                 # noqa: F401 – used by checks
import platform

try:
    from cryptography import x509 as _cx509
    _CRYPTO_OK = True
except ImportError:
    _cx509 = None
    _CRYPTO_OK = False


__version__ = "1.0.7"

_OS = platform.system()  # "Linux" | "Darwin" | "Windows"

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if _OS == "Windows" else 0


# ── PowerShell / shell helpers ─────────────────────────────────────────────────

def _ps(cmd: str, timeout: int = 30) -> tuple:
    """Run a PowerShell command. Returns (stdout_str, returncode)."""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, errors="replace",
            timeout=timeout, creationflags=_NO_WINDOW,
        )
        return r.stdout, r.returncode
    except (OSError, subprocess.TimeoutExpired):
        return "", 1


def _ps_quote(value) -> str:
    """PowerShell single-quoted string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _shell_quote(value) -> str:
    """POSIX shell string literal."""
    return shlex.quote(str(value))


def _truncate(value, limit=180) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text[: limit - 1] + "..." if len(text) > limit else text


def _self_invocation() -> list:
    """argv prefix to re-launch this program (cron / launchd / Task Scheduler).

    Uses ``python -m exposure_checker`` so it works regardless of CWD and
    survives the package reorganisation.  For PyInstaller frozen builds the
    executable re-launches itself directly.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "exposure_checker"]


# ── Risk database ──────────────────────────────────────────────────────────────

# port -> (service, severity, why it matters, how to fix)
RISKY_PORTS = {
    21:    ("FTP", "HIGH", "File transfer, usually unencrypted - credentials sent in clear text.",
            "Disable FTP; use SFTP/SCP over SSH instead."),
    23:    ("Telnet", "CRITICAL", "Remote login with NO encryption - passwords travel in plain text.",
            "Disable telnet entirely and use SSH."),
    25:    ("SMTP", "MEDIUM", "Mail server. If open to the internet it can be abused as an open relay.",
            "Restrict to known hosts / require auth, or firewall it."),
    53:    ("DNS", "MEDIUM", "DNS server. An open resolver can be abused in amplification attacks.",
            "Disable public recursion or firewall to trusted clients."),
    80:    ("HTTP", "INFO", "An (unencrypted) web service is running. Fine if intended.",
            "Serve over HTTPS; make sure it isn't an unprotected admin panel."),
    110:   ("POP3", "MEDIUM", "Legacy mail retrieval, often plaintext.",
            "Use encrypted POP3S/IMAPS, or disable."),
    135:   ("MS-RPC", "HIGH", "Windows RPC - a frequent target for remote exploits.",
            "Never expose to the internet; firewall to the local network only."),
    139:   ("NetBIOS", "HIGH", "Legacy Windows sharing - leaks info, historically wormable.",
            "Disable NetBIOS over TCP/IP; firewall it."),
    445:   ("SMB", "HIGH", "Windows file sharing - the EternalBlue/WannaCry port.",
            "Block 445 at the firewall; never expose SMB to the internet."),
    1433:  ("MS-SQL", "HIGH", "Microsoft SQL Server exposed to the network.",
            "Bind to localhost or firewall to app servers; require strong auth."),
    2375:  ("Docker API (plain)", "CRITICAL",
            "Unencrypted, UNAUTHENTICATED Docker API = full root on the host.",
            "Never expose this. Use the local socket; if remote, use TLS (2376) with client certs."),
    2376:  ("Docker API (TLS)", "HIGH", "Docker API over TLS - still remote root if certs leak.",
            "Restrict to trusted clients; protect the client certificates."),
    3000:  ("Dev/app panel (3000)", "MEDIUM",
            "Common dev server / dashboard (Grafana, Node apps).",
            "Ensure it requires auth and isn't reachable beyond localhost/LAN."),
    3306:  ("MySQL/MariaDB", "HIGH", "Database exposed to the network.",
            "Bind to 127.0.0.1 or firewall to app servers; require strong auth."),
    3389:  ("RDP", "HIGH",
            "Windows Remote Desktop - a top brute-force / ransomware entry point.",
            "Don't expose to the internet; use a VPN, enable NLA + strong passwords + MFA."),
    5000:  ("Dev/app panel (5000)", "MEDIUM", "Common dev server (Flask etc.).",
            "Make sure it isn't a debug server exposed in production."),
    5432:  ("PostgreSQL", "HIGH", "Database exposed to the network.",
            "Bind to 127.0.0.1 or firewall to app servers; require strong auth."),
    5900:  ("VNC", "HIGH", "Remote desktop, frequently weak or no authentication.",
            "Tunnel over SSH/VPN; never expose VNC directly; set a strong password."),
    6379:  ("Redis", "CRITICAL", "Redis often has NO auth by default - open means data theft / RCE.",
            "Bind to 127.0.0.1, set 'requirepass', and firewall it."),
    8080:  ("HTTP-alt / panel (8080)", "MEDIUM", "Common alternate web / admin panel port.",
            "Require auth; don't expose admin interfaces to the network."),
    8081:  ("Admin panel (8081)", "MEDIUM", "Common admin/management interface port.",
            "Require auth; restrict to localhost/LAN."),
    9000:  ("Portainer / panel (9000)", "MEDIUM",
            "Often Portainer (Docker management) or other dashboards.",
            "Require strong auth; don't expose container management to the network."),
    9090:  ("Prometheus / panel (9090)", "MEDIUM",
            "Often Prometheus or an admin dashboard - frequently no auth.",
            "Put behind auth / a reverse proxy; restrict to localhost/LAN."),
    9200:  ("Elasticsearch", "CRITICAL",
            "Elasticsearch often has no auth by default - open = full data access.",
            "Enable security, bind to localhost, and firewall it."),
    11211: ("Memcached", "HIGH", "No auth by default; abused for huge amplification attacks.",
            "Bind to 127.0.0.1 and firewall it."),
    27017: ("MongoDB", "CRITICAL",
            "MongoDB historically shipped with no auth - open = full data access.",
            "Enable auth, bind to 127.0.0.1, and firewall it."),
}

SPECIAL = {
    22:  ("SSH", "REVIEW", "SSH is fine IF it's key-only. Password auth invites brute-forcing.",
          "Set 'PasswordAuthentication no', use keys, consider fail2ban."),
    443: ("HTTPS", "INFO",
          "Encrypted web service - good. Just confirm it isn't an exposed admin panel.",
          "Keep TLS current; protect any admin UI behind auth."),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "REVIEW": 3, "INFO": 4}

_SCORE_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "REVIEW": 1, "INFO": 0}

# ── XDG-based config / data paths ─────────────────────────────────────────────

_DEFAULT_BASELINE = os.path.join(
    os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"),
    "exposure-checker", "baseline.json",
)

_SMTP_CONFIG_PATH = os.path.join(
    os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
    "exposure-checker", "config.ini",
)
_SCHEDULE_FILE = os.path.join(
    os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
    "exposure-checker", "schedule.json",
)


# ── Reporter ───────────────────────────────────────────────────────────────────

class _Reporter:
    """Routes findings to human-readable stdout or a JSON structure (--json).

    Each check calls begin() once, then any combination of finding() / ok() /
    error() / info(), then end().  dump_json() flushes the accumulated data.
    """

    def __init__(self, json_mode=False):
        self._json = json_mode
        self._data = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "checks": [],
        }
        self._cur = None

    @property
    def json_mode(self):
        return self._json

    def begin(self, title, subtitle=None):
        entry = {"check": title, "subtitle": subtitle, "error": None, "findings": []}
        self._data["checks"].append(entry)
        self._cur = entry
        if not self._json:
            print()
            print("-" * 66)
            print(f"  {title}")
            if subtitle:
                print(f"  {subtitle}")
            print("-" * 66)

    def end(self, summary=None):
        if not self._json:
            print()
            if summary:
                print("-" * 66)
                print(f"  {summary}")
            print("-" * 66)

    def finding(self, severity, label, why, fix, fix_cmds=None, **extra):
        record = {"severity": severity, "label": label, "why": why, "fix": fix,
                  "fix_cmds": fix_cmds or []}
        record.update(extra)
        if self._cur is not None:
            self._cur["findings"].append(record)
        if not self._json:
            print(f"\n  [{severity}] {label}")
            print(f"      why : {why}")
            print(f"      fix : {fix}")

    def ok(self, msg):
        if not self._json:
            print(f"\n[+] {msg.rstrip('.')}.")

    def info(self, msg):
        if not self._json:
            print(f"[*] {msg}")

    def error(self, msg):
        if self._cur is not None:
            self._cur["error"] = msg
        if not self._json:
            print(f"\n[!] {msg.rstrip('.')}.")

    def dump_json(self):
        if self._json:
            print(json.dumps(self._data, indent=2, default=str))

    def write_to(self, path):
        """Serialise the report to *path*. Auto-detects .html extension."""
        try:
            if path.lower().endswith(".html"):
                from ._report import _render_html
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(_render_html(self._data))
            else:
                with open(path, "w") as fh:
                    json.dump(self._data, fh, indent=2, default=str)
            return None
        except OSError as e:
            return str(e)

    def findings_at_or_above(self, severity):
        threshold = SEVERITY_ORDER.get(severity.upper(), 9)
        return [
            f
            for check in self._data["checks"]
            for f in check.get("findings", [])
            if SEVERITY_ORDER.get(f.get("severity", ""), 9) <= threshold
        ]
